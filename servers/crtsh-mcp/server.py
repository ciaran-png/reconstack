#!/usr/bin/env python3
"""
Certificate Transparency (crt.sh) MCP Server - Infrastructure Discovery Tool
Find hidden subdomains, track SSL certificate timelines, expose infrastructure connections!
"""

import asyncio
import json
import logging
import os
import sys
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from urllib.parse import quote

import httpx
from mcp.server import Server, NotificationOptions
from mcp.server.models import InitializationOptions
import mcp.server.stdio
import mcp.types as types

# Configure logging for our certificate reconnaissance
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("crtsh-mcp")

class CrtShClient:
    """Client for interacting with the crt.sh Certificate Transparency API"""
    
    def __init__(self):
        """Initialize the crt.sh client - NO API KEY NEEDED!"""
        self.base_url = "https://crt.sh"
        self.client = httpx.AsyncClient(timeout=60.0)  # Longer timeout for large queries
    
    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()
    
    def parse_date(self, date_str: str) -> str:
        """Parse PostgreSQL timestamp to readable format"""
        try:
            if 'T' in date_str:
                dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
            return date_str
        except:
            return date_str
    
    def extract_domains(self, name_value: str) -> List[str]:
        """Extract unique domains from certificate name value"""
        domains = set()
        
        # Split by newlines and spaces
        parts = name_value.replace('\n', ' ').split()
        
        for part in parts:
            # Clean up the domain
            domain = part.strip().lower()
            
            # Remove wildcards but keep the domain
            if domain.startswith('*.'):
                domain = domain[2:]
            
            # Basic validation
            if domain and '.' in domain and not domain.startswith('.'):
                domains.add(domain)
        
        return sorted(list(domains))
    
    async def search_certificates(self, query: str, 
                                 wildcard: bool = True,
                                 include_expired: bool = True,
                                 deduplicate: bool = True) -> Dict[str, Any]:
        """
        Search for certificates
        
        Args:
            query: Domain to search (e.g., "example.com" or "%.example.com" for wildcards)
            wildcard: Include wildcard certificates
            include_expired: Include expired certificates
            deduplicate: Remove duplicate entries
        """
        try:
            # Format query for wildcard search
            if wildcard and not query.startswith('%'):
                search_query = f"%.{query}"
            else:
                search_query = query
            
            # Parameters for the API
            params = {
                "q": search_query,
                "output": "json"
            }
            
            if not include_expired:
                params["exclude"] = "expired"
            
            logger.info(f"Searching crt.sh for: {search_query}")
            
            response = await self.client.get(
                f"{self.base_url}/",
                params=params
            )
            
            if response.status_code == 200:
                try:
                    certificates = response.json()
                    
                    # Process and enhance the data
                    processed_certs = []
                    seen_ids = set()
                    all_domains = set()
                    
                    for cert in certificates:
                        # Deduplicate by certificate ID if requested
                        cert_id = cert.get('id')
                        if deduplicate and cert_id in seen_ids:
                            continue
                        seen_ids.add(cert_id)
                        
                        # Extract domains from name_value
                        name_value = cert.get('name_value', '')
                        domains = self.extract_domains(name_value)
                        all_domains.update(domains)
                        
                        # Parse dates
                        cert['entry_timestamp_formatted'] = self.parse_date(cert.get('entry_timestamp', ''))
                        cert['not_before_formatted'] = self.parse_date(cert.get('not_before', ''))
                        cert['not_after_formatted'] = self.parse_date(cert.get('not_after', ''))
                        
                        # Add extracted domains
                        cert['domains'] = domains
                        
                        # Check if expired
                        try:
                            not_after = cert.get('not_after', '')
                            if not_after:
                                expiry = datetime.fromisoformat(not_after.replace('Z', '+00:00'))
                                cert['is_expired'] = expiry < datetime.now(timezone.utc)
                            else:
                                cert['is_expired'] = None
                        except:
                            cert['is_expired'] = None
                        
                        # Add certificate URL
                        cert['crtsh_url'] = f"https://crt.sh/?id={cert_id}"
                        
                        processed_certs.append(cert)
                    
                    # Sort by entry timestamp (most recent first)
                    processed_certs.sort(
                        key=lambda x: x.get('entry_timestamp', ''),
                        reverse=True
                    )
                    
                    return {
                        "success": True,
                        "data": {
                            "query": query,
                            "total_certificates": len(processed_certs),
                            "unique_domains": len(all_domains),
                            "domains_found": sorted(list(all_domains)),
                            "certificates": processed_certs
                        }
                    }
                    
                except json.JSONDecodeError:
                    # Sometimes crt.sh returns HTML on error
                    return {
                        "success": False,
                        "error": "Invalid response from crt.sh (might be rate limited)"
                    }
            else:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code} from crt.sh"
                }
                
        except httpx.TimeoutException:
            return {
                "success": False,
                "error": "Request timed out - try a more specific query"
            }
        except Exception as e:
            logger.error(f"Error searching certificates: {e}")
            return {"success": False, "error": str(e)}
    
    async def get_certificate_details(self, cert_id: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific certificate
        
        Args:
            cert_id: Certificate ID from crt.sh
        """
        try:
            # Get certificate details
            response = await self.client.get(
                f"{self.base_url}/",
                params={
                    "id": cert_id,
                    "output": "json"
                }
            )
            
            if response.status_code == 200:
                cert_data = response.json()
                
                # The response is usually an array with one item
                if isinstance(cert_data, list) and cert_data:
                    cert = cert_data[0]
                    
                    # Extract and process details
                    cert['entry_timestamp_formatted'] = self.parse_date(cert.get('entry_timestamp', ''))
                    cert['not_before_formatted'] = self.parse_date(cert.get('not_before', ''))
                    cert['not_after_formatted'] = self.parse_date(cert.get('not_after', ''))
                    cert['domains'] = self.extract_domains(cert.get('name_value', ''))
                    cert['crtsh_url'] = f"https://crt.sh/?id={cert_id}"
                    
                    return {
                        "success": True,
                        "data": cert
                    }
                else:
                    return {
                        "success": False,
                        "error": "Certificate not found"
                    }
            else:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}"
                }
                
        except Exception as e:
            logger.error(f"Error getting certificate details: {e}")
            return {"success": False, "error": str(e)}
    
    async def find_subdomains(self, domain: str) -> Dict[str, Any]:
        """
        Find all subdomains for a domain using certificate transparency
        
        Args:
            domain: Base domain to find subdomains for
        """
        try:
            # Search for all certificates for this domain and subdomains
            result = await self.search_certificates(domain, wildcard=True, deduplicate=True)
            
            if result.get("success"):
                data = result.get("data", {})
                all_domains = set(data.get("domains_found", []))
                
                # Filter to only subdomains of the target domain
                subdomains = set()
                base_domain = domain.lower().strip()
                
                for d in all_domains:
                    d_lower = d.lower().strip()
                    # Check if it's a subdomain (not the base domain itself)
                    if d_lower.endswith(f".{base_domain}") or d_lower == base_domain:
                        subdomains.add(d)
                
                # Organize subdomains by level
                organized = {
                    "base": base_domain,
                    "www": [],
                    "api": [],
                    "mail": [],
                    "admin": [],
                    "test/dev": [],
                    "other": []
                }
                
                for subdomain in sorted(subdomains):
                    if subdomain == base_domain:
                        continue
                    elif subdomain.startswith("www."):
                        organized["www"].append(subdomain)
                    elif "api" in subdomain:
                        organized["api"].append(subdomain)
                    elif "mail" in subdomain or "mx" in subdomain or "smtp" in subdomain:
                        organized["mail"].append(subdomain)
                    elif "admin" in subdomain or "panel" in subdomain or "portal" in subdomain:
                        organized["admin"].append(subdomain)
                    elif any(x in subdomain for x in ["test", "dev", "staging", "demo", "sandbox"]):
                        organized["test/dev"].append(subdomain)
                    else:
                        organized["other"].append(subdomain)
                
                return {
                    "success": True,
                    "data": {
                        "domain": domain,
                        "total_subdomains": len(subdomains),
                        "subdomains": sorted(list(subdomains)),
                        "organized": organized,
                        "certificates_analyzed": data.get("total_certificates", 0)
                    }
                }
            else:
                return result
                
        except Exception as e:
            logger.error(f"Error finding subdomains: {e}")
            return {"success": False, "error": str(e)}
    
    async def certificate_timeline(self, domain: str) -> Dict[str, Any]:
        """
        Get a timeline of certificate issuance for a domain
        
        Args:
            domain: Domain to analyze
        """
        try:
            # Get all certificates
            result = await self.search_certificates(domain, wildcard=True, include_expired=True)
            
            if result.get("success"):
                data = result.get("data", {})
                certificates = data.get("certificates", [])
                
                # Group by year and month
                timeline = {}
                issuer_stats = {}
                
                for cert in certificates:
                    # Parse the timestamp
                    timestamp = cert.get('entry_timestamp', '')
                    if timestamp:
                        try:
                            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                            year_month = dt.strftime('%Y-%m')
                            year = dt.strftime('%Y')
                            
                            if year not in timeline:
                                timeline[year] = {}
                            if year_month not in timeline[year]:
                                timeline[year][year_month] = []
                            
                            timeline[year][year_month].append({
                                "date": cert.get('entry_timestamp_formatted'),
                                "issuer": cert.get('issuer_name', 'Unknown'),
                                "domains": cert.get('domains', []),
                                "expired": cert.get('is_expired', False),
                                "cert_id": cert.get('id'),
                                "url": cert.get('crtsh_url')
                            })
                            
                            # Track issuer statistics
                            issuer = cert.get('issuer_name', 'Unknown')
                            if issuer not in issuer_stats:
                                issuer_stats[issuer] = 0
                            issuer_stats[issuer] += 1
                            
                        except Exception as e:
                            logger.error(f"Error parsing timestamp {timestamp}: {e}")
                
                # Calculate statistics
                total_certs = len(certificates)
                active_certs = sum(1 for c in certificates if not c.get('is_expired', True))
                expired_certs = total_certs - active_certs
                
                # Find first and last certificate
                first_cert = None
                last_cert = None
                if certificates:
                    sorted_certs = sorted(certificates, key=lambda x: x.get('entry_timestamp', ''))
                    if sorted_certs:
                        first_cert = {
                            "date": sorted_certs[0].get('entry_timestamp_formatted'),
                            "issuer": sorted_certs[0].get('issuer_name'),
                            "domains": sorted_certs[0].get('domains', [])
                        }
                        last_cert = {
                            "date": sorted_certs[-1].get('entry_timestamp_formatted'),
                            "issuer": sorted_certs[-1].get('issuer_name'),
                            "domains": sorted_certs[-1].get('domains', [])
                        }
                
                return {
                    "success": True,
                    "data": {
                        "domain": domain,
                        "total_certificates": total_certs,
                        "active_certificates": active_certs,
                        "expired_certificates": expired_certs,
                        "timeline": timeline,
                        "issuer_statistics": issuer_stats,
                        "first_certificate": first_cert,
                        "last_certificate": last_cert
                    }
                }
            else:
                return result
                
        except Exception as e:
            logger.error(f"Error building timeline: {e}")
            return {"success": False, "error": str(e)}
    
    async def find_related_domains(self, domain: str) -> Dict[str, Any]:
        """
        Find related domains that appear on the same certificates
        
        Args:
            domain: Domain to find relationships for
        """
        try:
            # Get all certificates for this domain
            result = await self.search_certificates(domain, wildcard=True)
            
            if result.get("success"):
                data = result.get("data", {})
                certificates = data.get("certificates", [])
                
                # Track related domains and their co-occurrences
                related = {}
                target_domain = domain.lower()
                
                for cert in certificates:
                    domains_on_cert = cert.get('domains', [])
                    
                    # Find certificates that have multiple domains
                    if len(domains_on_cert) > 1:
                        for d in domains_on_cert:
                            d_lower = d.lower()
                            # Skip the target domain itself
                            if d_lower == target_domain or d_lower.endswith(f".{target_domain}"):
                                continue
                            
                            if d not in related:
                                related[d] = {
                                    "count": 0,
                                    "certificates": [],
                                    "issuers": set()
                                }
                            
                            related[d]["count"] += 1
                            related[d]["certificates"].append({
                                "cert_id": cert.get('id'),
                                "date": cert.get('entry_timestamp_formatted'),
                                "issuer": cert.get('issuer_name')
                            })
                            related[d]["issuers"].add(cert.get('issuer_name', 'Unknown'))
                
                # Convert sets to lists for JSON serialization
                for domain_info in related.values():
                    domain_info["issuers"] = sorted(list(domain_info["issuers"]))
                
                # Sort by co-occurrence count
                sorted_related = dict(sorted(
                    related.items(),
                    key=lambda x: x[1]["count"],
                    reverse=True
                ))
                
                return {
                    "success": True,
                    "data": {
                        "domain": domain,
                        "total_related_domains": len(related),
                        "certificates_analyzed": len(certificates),
                        "related_domains": sorted_related
                    }
                }
            else:
                return result
                
        except Exception as e:
            logger.error(f"Error finding related domains: {e}")
            return {"success": False, "error": str(e)}

# Initialize the MCP server
app = Server("crtsh-mcp")
logger.info("Initializing Certificate Transparency MCP Server - Infrastructure discovery ready!")

# Global client instance
crtsh_client: Optional[CrtShClient] = None

@app.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List available Certificate Transparency tools - TRIMMED for efficiency"""
    return [
        types.Tool(
            name="crtsh_search",
            description="Search certificate transparency logs for a domain. Finds all SSL certificates issued.",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Domain to search (e.g., 'example.com')"
                    },
                    "wildcard": {
                        "type": "boolean",
                        "description": "Include wildcard/subdomain certificates (default: true)",
                        "default": True
                    },
                    "include_expired": {
                        "type": "boolean",
                        "description": "Include expired certificates (default: true)",
                        "default": True
                    }
                },
                "required": ["domain"]
            }
        ),
        types.Tool(
            name="crtsh_subdomains",
            description="Find ALL subdomains for a domain using certificate transparency. Discovers hidden infrastructure!",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Base domain to find subdomains for (e.g., 'example.com')"
                    }
                },
                "required": ["domain"]
            }
        ),
        # DISABLED: crtsh_timeline, crtsh_related, crtsh_certificate
    ]

@app.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """Execute Certificate Transparency tools"""
    
    global crtsh_client
    
    # Initialize client if needed (no API key required!)
    if crtsh_client is None:
        crtsh_client = CrtShClient()
    
    try:
        if name == "crtsh_search":
            domain = arguments.get("domain")
            if not domain:
                return [types.TextContent(type="text", text="❌ Domain is required!")]
            
            wildcard = arguments.get("wildcard", True)
            include_expired = arguments.get("include_expired", True)
            
            logger.info(f"Searching certificates for: {domain}")
            result = await crtsh_client.search_certificates(domain, wildcard, include_expired)
            
            if result.get("success"):
                data = result.get("data", {})
                certs = data.get("certificates", [])
                
                response_text = f"""🔐 **Certificate Transparency Search Results**

**Domain:** {data.get('query')}
**Total Certificates:** {data.get('total_certificates', 0)}
**Unique Domains Found:** {data.get('unique_domains', 0)}

**Discovered Domains:**
"""
                
                # List unique domains found
                domains = data.get("domains_found", [])
                for d in domains[:30]:  # Limit to 30 domains
                    response_text += f"  - {d}\n"
                
                if len(domains) > 30:
                    response_text += f"  ... and {len(domains) - 30} more\n"
                
                # Show recent certificates
                response_text += "\n**Recent Certificates:**\n"
                for cert in certs[:10]:  # Show 10 most recent
                    response_text += f"""
**Certificate ID:** {cert.get('id')}
  Logged: {cert.get('entry_timestamp_formatted')}
  Issuer: {cert.get('issuer_name')}
  Valid: {cert.get('not_before_formatted')} to {cert.get('not_after_formatted')}
  Expired: {cert.get('is_expired', 'Unknown')}
  Domains: {', '.join(cert.get('domains', [])[:3])}
  [View]({cert.get('crtsh_url')})
"""
            else:
                response_text = f"❌ Search failed: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "crtsh_subdomains":
            domain = arguments.get("domain")
            if not domain:
                return [types.TextContent(type="text", text="❌ Domain is required!")]
            
            logger.info(f"Finding subdomains for: {domain}")
            result = await crtsh_client.find_subdomains(domain)
            
            if result.get("success"):
                data = result.get("data", {})
                organized = data.get("organized", {})
                
                response_text = f"""🌐 **Subdomain Discovery via Certificate Transparency**

**Domain:** {data.get('domain')}
**Total Subdomains Found:** {data.get('total_subdomains', 0)}
**Certificates Analyzed:** {data.get('certificates_analyzed', 0)}

**Discovered Subdomains by Category:**
"""
                
                # Show organized subdomains
                if organized.get("www"):
                    response_text += f"\n**WWW ({len(organized['www'])}):**\n"
                    for sub in organized["www"][:10]:
                        response_text += f"  - {sub}\n"
                
                if organized.get("api"):
                    response_text += f"\n**API ({len(organized['api'])}):**\n"
                    for sub in organized["api"][:10]:
                        response_text += f"  - {sub}\n"
                
                if organized.get("mail"):
                    response_text += f"\n**Mail ({len(organized['mail'])}):**\n"
                    for sub in organized["mail"][:10]:
                        response_text += f"  - {sub}\n"
                
                if organized.get("admin"):
                    response_text += f"\n**Admin/Portal ({len(organized['admin'])}):**\n"
                    for sub in organized["admin"][:10]:
                        response_text += f"  - {sub}\n"
                
                if organized.get("test/dev"):
                    response_text += f"\n**Test/Dev ({len(organized['test/dev'])}):**\n"
                    for sub in organized["test/dev"][:10]:
                        response_text += f"  - {sub}\n"
                
                if organized.get("other"):
                    response_text += f"\n**Other ({len(organized['other'])}):**\n"
                    for sub in organized["other"][:20]:
                        response_text += f"  - {sub}\n"
                
                response_text += "\n💡 **Tip:** These subdomains were found via SSL certificates and may reveal hidden infrastructure!"
            else:
                response_text = f"❌ Subdomain discovery failed: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "crtsh_timeline":
            domain = arguments.get("domain")
            if not domain:
                return [types.TextContent(type="text", text="❌ Domain is required!")]
            
            logger.info(f"Building certificate timeline for: {domain}")
            result = await crtsh_client.certificate_timeline(domain)
            
            if result.get("success"):
                data = result.get("data", {})
                timeline = data.get("timeline", {})
                
                response_text = f"""📊 **Certificate Timeline Analysis**

**Domain:** {data.get('domain')}
**Total Certificates:** {data.get('total_certificates', 0)}
**Active:** {data.get('active_certificates', 0)} | **Expired:** {data.get('expired_certificates', 0)}

"""
                
                if data.get("first_certificate"):
                    first = data["first_certificate"]
                    response_text += f"""**First Certificate:**
  Date: {first.get('date')}
  Issuer: {first.get('issuer')}

"""
                
                if data.get("last_certificate"):
                    last = data["last_certificate"]
                    response_text += f"""**Most Recent Certificate:**
  Date: {last.get('date')}
  Issuer: {last.get('issuer')}

"""
                
                # Show timeline by year
                response_text += "**Certificate Issuance Timeline:**\n"
                for year in sorted(timeline.keys(), reverse=True)[:5]:  # Last 5 years
                    year_data = timeline[year]
                    total_year = sum(len(certs) for certs in year_data.values())
                    response_text += f"\n**{year}:** {total_year} certificates\n"
                    
                    for month in sorted(year_data.keys(), reverse=True)[:3]:  # Last 3 months
                        certs = year_data[month]
                        response_text += f"  {month}: {len(certs)} cert(s)\n"
                
                # Show issuer statistics
                if data.get("issuer_statistics"):
                    response_text += "\n**Certificate Authorities Used:**\n"
                    for issuer, count in sorted(data["issuer_statistics"].items(), key=lambda x: x[1], reverse=True)[:5]:
                        response_text += f"  - {issuer}: {count} certificates\n"
            else:
                response_text = f"❌ Timeline analysis failed: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "crtsh_related":
            domain = arguments.get("domain")
            if not domain:
                return [types.TextContent(type="text", text="❌ Domain is required!")]
            
            logger.info(f"Finding related domains for: {domain}")
            result = await crtsh_client.find_related_domains(domain)
            
            if result.get("success"):
                data = result.get("data", {})
                related = data.get("related_domains", {})
                
                response_text = f"""🔗 **Related Domains Analysis**

**Target Domain:** {data.get('domain')}
**Related Domains Found:** {data.get('total_related_domains', 0)}
**Certificates Analyzed:** {data.get('certificates_analyzed', 0)}

**Domains Sharing Certificates:**
"""
                
                if related:
                    for related_domain, info in list(related.items())[:20]:  # Top 20
                        response_text += f"""
**{related_domain}**
  Shared Certificates: {info['count']}
  Certificate Authorities: {', '.join(info['issuers'])}
"""
                        # Show first certificate where they appeared together
                        if info['certificates']:
                            first_cert = info['certificates'][0]
                            response_text += f"  First Seen Together: {first_cert['date']}\n"
                else:
                    response_text += "\nNo related domains found on shared certificates."
                
                response_text += "\n💡 **Note:** Domains on the same certificate often indicate shared infrastructure or ownership!"
            else:
                response_text = f"❌ Related domains analysis failed: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "crtsh_certificate":
            cert_id = arguments.get("cert_id")
            if not cert_id:
                return [types.TextContent(type="text", text="❌ Certificate ID is required!")]
            
            logger.info(f"Getting certificate details for ID: {cert_id}")
            result = await crtsh_client.get_certificate_details(cert_id)
            
            if result.get("success"):
                cert = result.get("data", {})
                
                response_text = f"""🔐 **Certificate Details**

**Certificate ID:** {cert.get('id')}
**URL:** {cert.get('crtsh_url')}

**Timing:**
  Logged: {cert.get('entry_timestamp_formatted')}
  Valid From: {cert.get('not_before_formatted')}
  Valid Until: {cert.get('not_after_formatted')}

**Issuer:** {cert.get('issuer_name')}

**Domains Covered:**
"""
                for domain in cert.get('domains', []):
                    response_text += f"  - {domain}\n"
                
                response_text += f"""
**Serial Number:** {cert.get('serial_number', 'N/A')}
"""
            else:
                response_text = f"❌ Failed to get certificate: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        else:
            return [types.TextContent(
                type="text",
                text=f"❌ Unknown tool: {name}"
            )]
    
    except Exception as e:
        logger.error(f"Error executing tool {name}: {e}", exc_info=True)
        return [types.TextContent(
            type="text",
            text=f"❌ Error executing {name}: {str(e)}"
        )]

async def main():
    """Main entry point for the Certificate Transparency MCP server"""
    global crtsh_client
    logger.info("Starting Certificate Transparency MCP Server...")
    logger.info("NO API KEY REQUIRED - Using public crt.sh service!")
    
    try:
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            await app.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="crtsh-mcp",
                    server_version="1.0.0",
                    capabilities=app.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )
    finally:
        # Cleanup
        if crtsh_client:
            await crtsh_client.close()
            crtsh_client = None

if __name__ == "__main__":
    asyncio.run(main())