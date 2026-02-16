#!/usr/bin/env python3
"""
VirusTotal MCP Server - Cyber Intelligence Tool
Comprehensive domain, IP, URL, and file analysis via the VirusTotal API v3.
"""

import asyncio
import json
import logging
import os
import sys
import base64
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from enum import Enum

import httpx
import vt
from mcp.server import Server, NotificationOptions
from mcp.server.models import InitializationOptions
import mcp.server.stdio
import mcp.types as types

# Configure logging for our intelligence operations
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("virustotal-mcp")

class VTClient:
    """Enhanced VirusTotal client for comprehensive threat intelligence"""
    
    def __init__(self, api_key: str):
        """Initialize the VirusTotal client"""
        self.api_key = api_key
        self.client = None
        self._api_key = api_key
        
    async def _ensure_client(self):
        """Ensure client is initialized and open"""
        if self.client is None:
            self.client = vt.Client(self._api_key)
        return self.client
        
    async def close(self):
        """Close the client connection"""
        if self.client:
            try:
                await self.client.close_async()
            except RuntimeError:
                # Already in event loop, just close the session directly
                if hasattr(self.client, '_http_client'):
                    await self.client._http_client.close()
            self.client = None
    
    # Domain Analysis
    async def get_domain(self, domain: str) -> Dict[str, Any]:
        """Get comprehensive domain information including passive DNS"""
        try:
            client = await self._ensure_client()
            domain_obj = await client.get_object_async(f"/domains/{domain}")
            return {"success": True, "data": domain_obj.to_dict()}
        except Exception as e:
            logger.error(f"Error getting domain {domain}: {e}")
            return {"success": False, "error": str(e)}
    
    async def get_domain_dns_resolutions(self, domain: str, limit: int = 40) -> Dict[str, Any]:
        """Get passive DNS resolutions for a domain"""
        try:
            client = await self._ensure_client()
            resolutions = []
            iterator = client.iterator(f"/domains/{domain}/resolutions", limit=limit)
            async for resolution in iterator:
                resolutions.append(resolution.to_dict())
            return {"success": True, "data": resolutions}
        except Exception as e:
            logger.error(f"Error getting DNS resolutions for {domain}: {e}")
            return {"success": False, "error": str(e)}
    
    async def get_domain_subdomains(self, domain: str, limit: int = 40) -> Dict[str, Any]:
        """Get subdomains for a domain"""
        try:
            client = await self._ensure_client()
            subdomains = []
            iterator = client.iterator(f"/domains/{domain}/subdomains", limit=limit)
            async for subdomain in iterator:
                subdomains.append(subdomain.to_dict())
            return {"success": True, "data": subdomains}
        except Exception as e:
            logger.error(f"Error getting subdomains for {domain}: {e}")
            return {"success": False, "error": str(e)}
    
    async def get_domain_siblings(self, domain: str, limit: int = 40) -> Dict[str, Any]:
        """Get sibling domains (same parent domain)"""
        try:
            client = await self._ensure_client()
            siblings = []
            iterator = client.iterator(f"/domains/{domain}/siblings", limit=limit)
            async for sibling in iterator:
                siblings.append(sibling.to_dict())
            return {"success": True, "data": siblings}
        except Exception as e:
            logger.error(f"Error getting siblings for {domain}: {e}")
            return {"success": False, "error": str(e)}
    
    async def get_domain_communicating_files(self, domain: str, limit: int = 20) -> Dict[str, Any]:
        """Get files that communicate with this domain"""
        try:
            client = await self._ensure_client()
            files = []
            iterator = client.iterator(f"/domains/{domain}/communicating_files", limit=limit)
            async for file in iterator:
                files.append(file.to_dict())
            return {"success": True, "data": files}
        except Exception as e:
            logger.error(f"Error getting communicating files for {domain}: {e}")
            return {"success": False, "error": str(e)}
    
    async def get_domain_referrer_files(self, domain: str, limit: int = 20) -> Dict[str, Any]:
        """Get files that contain this domain"""
        try:
            client = await self._ensure_client()
            files = []
            iterator = client.iterator(f"/domains/{domain}/referrer_files", limit=limit)
            async for file in iterator:
                files.append(file.to_dict())
            return {"success": True, "data": files}
        except Exception as e:
            logger.error(f"Error getting referrer files for {domain}: {e}")
            return {"success": False, "error": str(e)}
    
    # IP Analysis
    async def get_ip(self, ip: str) -> Dict[str, Any]:
        """Get comprehensive IP information"""
        try:
            client = await self._ensure_client()
            ip_obj = await client.get_object_async(f"/ip_addresses/{ip}")
            return {"success": True, "data": ip_obj.to_dict()}
        except Exception as e:
            logger.error(f"Error getting IP {ip}: {e}")
            return {"success": False, "error": str(e)}
    
    async def get_ip_dns_resolutions(self, ip: str, limit: int = 40) -> Dict[str, Any]:
        """Get reverse DNS resolutions for an IP"""
        try:
            client = await self._ensure_client()
            resolutions = []
            iterator = client.iterator(f"/ip_addresses/{ip}/resolutions", limit=limit)
            async for resolution in iterator:
                resolutions.append(resolution.to_dict())
            return {"success": True, "data": resolutions}
        except Exception as e:
            logger.error(f"Error getting DNS resolutions for IP {ip}: {e}")
            return {"success": False, "error": str(e)}
    
    async def get_ip_communicating_files(self, ip: str, limit: int = 20) -> Dict[str, Any]:
        """Get files that communicate with this IP"""
        try:
            client = await self._ensure_client()
            files = []
            iterator = client.iterator(f"/ip_addresses/{ip}/communicating_files", limit=limit)
            async for file in iterator:
                files.append(file.to_dict())
            return {"success": True, "data": files}
        except Exception as e:
            logger.error(f"Error getting communicating files for IP {ip}: {e}")
            return {"success": False, "error": str(e)}
    
    # URL Analysis
    async def scan_url(self, url: str) -> Dict[str, Any]:
        """Submit a URL for scanning"""
        try:
            client = await self._ensure_client()
            url_id = vt.url_id(url)
            analysis = await client.scan_url_async(url)
            return {
                "success": True,
                "data": {
                    "id": analysis.id,
                    "url": url,
                    "url_id": url_id,
                    "message": "URL submitted for analysis"
                }
            }
        except Exception as e:
            logger.error(f"Error scanning URL {url}: {e}")
            return {"success": False, "error": str(e)}
    
    async def get_url(self, url: str) -> Dict[str, Any]:
        """Get URL analysis report"""
        try:
            client = await self._ensure_client()
            url_id = vt.url_id(url)
            url_obj = await client.get_object_async(f"/urls/{url_id}")
            return {"success": True, "data": url_obj.to_dict()}
        except Exception as e:
            logger.error(f"Error getting URL {url}: {e}")
            return {"success": False, "error": str(e)}
    
    # File Analysis
    async def get_file(self, file_hash: str) -> Dict[str, Any]:
        """Get file analysis report by hash (MD5, SHA1, or SHA256)"""
        try:
            client = await self._ensure_client()
            file_obj = await client.get_object_async(f"/files/{file_hash}")
            return {"success": True, "data": file_obj.to_dict()}
        except Exception as e:
            logger.error(f"Error getting file {file_hash}: {e}")
            return {"success": False, "error": str(e)}
    
    async def get_file_behaviour(self, file_hash: str) -> Dict[str, Any]:
        """Get file behaviour report from sandbox analysis"""
        try:
            client = await self._ensure_client()
            # Get behaviour reports
            behaviours = []
            iterator = client.iterator(f"/files/{file_hash}/behaviours", limit=10)
            async for behaviour in iterator:
                behaviours.append(behaviour.to_dict())
            return {"success": True, "data": behaviours}
        except Exception as e:
            logger.error(f"Error getting file behaviour for {file_hash}: {e}")
            return {"success": False, "error": str(e)}
    
    async def get_file_contacted_domains(self, file_hash: str, limit: int = 20) -> Dict[str, Any]:
        """Get domains contacted by a file"""
        try:
            client = await self._ensure_client()
            domains = []
            iterator = client.iterator(f"/files/{file_hash}/contacted_domains", limit=limit)
            async for domain in iterator:
                domains.append(domain.to_dict())
            return {"success": True, "data": domains}
        except Exception as e:
            logger.error(f"Error getting contacted domains for {file_hash}: {e}")
            return {"success": False, "error": str(e)}
    
    # Comments
    async def get_comments(self, object_type: str, object_id: str, limit: int = 20) -> Dict[str, Any]:
        """Get community comments for an object (domain, ip, file, url)"""
        try:
            client = await self._ensure_client()
            # Determine the correct endpoint
            if object_type == "domain":
                endpoint = f"/domains/{object_id}/comments"
            elif object_type == "ip":
                endpoint = f"/ip_addresses/{object_id}/comments"
            elif object_type == "file":
                endpoint = f"/files/{object_id}/comments"
            elif object_type == "url":
                url_id = vt.url_id(object_id)
                endpoint = f"/urls/{url_id}/comments"
            else:
                return {"success": False, "error": f"Invalid object type: {object_type}"}
            
            comments = []
            iterator = client.iterator(endpoint, limit=limit)
            async for comment in iterator:
                comments.append(comment.to_dict())
            return {"success": True, "data": comments}
        except Exception as e:
            logger.error(f"Error getting comments for {object_type} {object_id}: {e}")
            return {"success": False, "error": str(e)}
    
    # Search
    async def search(self, query: str, limit: int = 20) -> Dict[str, Any]:
        """Search VirusTotal intelligence (requires premium for advanced queries)"""
        try:
            client = await self._ensure_client()
            results = []
            iterator = client.iterator("/intelligence/search", params={"query": query}, limit=limit)
            async for result in iterator:
                results.append(result.to_dict())
            return {"success": True, "data": results}
        except Exception as e:
            # Fallback to basic file search if intelligence search fails
            try:
                client = await self._ensure_client()
                results = []
                iterator = client.iterator("/files", params={"query": query}, limit=limit)
                async for result in iterator:
                    results.append(result.to_dict())
                return {"success": True, "data": results, "note": "Using basic search (premium required for intelligence search)"}
            except Exception as e2:
                logger.error(f"Error searching: {e2}")
                return {"success": False, "error": str(e2)}
    
    # API quota
    async def get_api_usage(self) -> Dict[str, Any]:
        """Get API quota and usage information"""
        try:
            # Use httpx for this endpoint as vt-py doesn't have built-in support
            async with httpx.AsyncClient() as http_client:
                response = await http_client.get(
                    "https://www.virustotal.com/api/v3/users/current",
                    headers={"x-apikey": self.api_key}
                )
                if response.status_code == 200:
                    return {"success": True, "data": response.json()["data"]}
                else:
                    return {"success": False, "error": f"HTTP {response.status_code}"}
        except Exception as e:
            logger.error(f"Error getting API usage: {e}")
            return {"success": False, "error": str(e)}

# Initialize the MCP server
app = Server("virustotal-mcp")
logger.info("Initializing VirusTotal MCP Server - Cyber intelligence ready!")

# Global client instance
vt_client: Optional[VTClient] = None

def get_api_key() -> Optional[str]:
    """Get API key from environment variable"""
    api_key = os.getenv("VT_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        logger.warning("No VT_API_KEY or VIRUSTOTAL_API_KEY found in environment!")
    return api_key

def format_domain_report(data: Dict) -> str:
    """Format domain analysis for display"""
    attrs = data.get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    
    result = f"""🌐 **Domain Analysis: {data.get('id')}**

**Categories:** {', '.join(attrs.get('categories', {}).values()) if attrs.get('categories') else 'None'}
**Creation Date:** {attrs.get('creation_date', 'Unknown')}
**Last Update:** {attrs.get('last_modification_date', 'Unknown')}

**Reputation:**
🟢 Clean: {stats.get('harmless', 0)}
🔴 Malicious: {stats.get('malicious', 0)}
🟡 Suspicious: {stats.get('suspicious', 0)}
⚪ Undetected: {stats.get('undetected', 0)}

**WHOIS Info:**
Registrar: {attrs.get('registrar', 'Unknown')}

**DNS Records:**
"""
    
    # Add DNS records if available
    dns_records = attrs.get('last_dns_records', [])
    for record in dns_records[:10]:
        result += f"  - {record.get('type')}: {record.get('value')}\n"
    
    return result

def format_ip_report(data: Dict) -> str:
    """Format IP analysis for display"""
    attrs = data.get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    
    result = f"""🖥️ **IP Analysis: {data.get('id')}**

**Network:** {attrs.get('network', 'Unknown')}
**Country:** {attrs.get('country', 'Unknown')}
**AS Owner:** {attrs.get('as_owner', 'Unknown')}
**ASN:** {attrs.get('asn', 'Unknown')}

**Reputation:**
🟢 Clean: {stats.get('harmless', 0)}
🔴 Malicious: {stats.get('malicious', 0)}
🟡 Suspicious: {stats.get('suspicious', 0)}
⚪ Undetected: {stats.get('undetected', 0)}
"""
    
    return result

@app.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List available VirusTotal tools - TRIMMED for efficiency"""
    return [
        # Domain Analysis - CORE
        types.Tool(
            name="vt_domain",
            description="Get comprehensive domain analysis including reputation, DNS records, WHOIS, and categories",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Domain to analyze (e.g., 'example.com')"
                    }
                },
                "required": ["domain"]
            }
        ),
        types.Tool(
            name="vt_domain_dns",
            description="Get passive DNS resolutions - see when domain pointed to different IPs (historical DNS)",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Domain to get DNS history for"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum results to return (default: 40)",
                        "default": 40
                    }
                },
                "required": ["domain"]
            }
        ),
        types.Tool(
            name="vt_domain_subdomains",
            description="Find all subdomains of a domain",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Parent domain to find subdomains for"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum results (default: 40)",
                        "default": 40
                    }
                },
                "required": ["domain"]
            }
        ),
        
        # IP Analysis - CORE
        types.Tool(
            name="vt_ip",
            description="Get comprehensive IP analysis including reputation, network info, and location",
            inputSchema={
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "IP address to analyze (e.g., '8.8.8.8')"
                    }
                },
                "required": ["ip"]
            }
        ),
        types.Tool(
            name="vt_ip_dns",
            description="Get reverse DNS resolutions - see what domains pointed to this IP (historical)",
            inputSchema={
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "IP address to get DNS history for"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum results (default: 40)",
                        "default": 40
                    }
                },
                "required": ["ip"]
            }
        ),
        
        # URL Analysis - CORE
        types.Tool(
            name="vt_url",
            description="Get URL analysis report",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL to get report for"
                    }
                },
                "required": ["url"]
            }
        ),
        
        # File Analysis - CORE
        types.Tool(
            name="vt_file",
            description="Get file analysis report by hash (MD5, SHA1, or SHA256)",
            inputSchema={
                "type": "object",
                "properties": {
                    "hash": {
                        "type": "string",
                        "description": "File hash (MD5, SHA1, or SHA256)"
                    }
                },
                "required": ["hash"]
            }
        ),
        
        # Search - CORE
        types.Tool(
            name="vt_search",
            description="Search VirusTotal (basic search, premium required for advanced)",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query (e.g., 'tag:ransomware', 'behavior:creates_mutex')"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum results (default: 20)",
                        "default": 20
                    }
                },
                "required": ["query"]
            }
        ),
        # DISABLED: vt_domain_siblings, vt_domain_communicating_files, vt_domain_referrer_files,
        # vt_ip_communicating_files, vt_scan_url, vt_file_behaviour, vt_file_contacted_domains,
        # vt_comments, vt_api_usage
    ]

@app.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """Execute VirusTotal tools"""
    
    global vt_client
    
    # Initialize client if needed
    if vt_client is None:
        api_key = get_api_key()
        if not api_key:
            return [types.TextContent(
                type="text",
                text="❌ VT_API_KEY or VIRUSTOTAL_API_KEY not found in environment! Set it to use this tool."
            )]
        vt_client = VTClient(api_key)
    
    try:
        # Domain Analysis
        if name == "vt_domain":
            domain = arguments.get("domain")
            if not domain:
                return [types.TextContent(type="text", text="❌ Domain is required!")]
            
            logger.info(f"Analyzing domain: {domain}")
            result = await vt_client.get_domain(domain)
            
            if result.get("success"):
                response_text = format_domain_report(result.get("data", {}))
            else:
                response_text = f"❌ Domain analysis failed: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "vt_domain_dns":
            domain = arguments.get("domain")
            limit = arguments.get("limit", 40)
            
            if not domain:
                return [types.TextContent(type="text", text="❌ Domain is required!")]
            
            logger.info(f"Getting passive DNS for domain: {domain}")
            result = await vt_client.get_domain_dns_resolutions(domain, limit)
            
            if result.get("success"):
                resolutions = result.get("data", [])
                response_text = f"🔍 **Passive DNS for {domain}**\n\n"
                response_text += f"Found {len(resolutions)} historical DNS resolutions:\n\n"
                
                for res in resolutions:
                    attrs = res.get("attributes", {})
                    response_text += f"**IP:** {attrs.get('ip_address')}\n"
                    response_text += f"  Date: {attrs.get('date', 'Unknown')}\n"
                    response_text += f"  Resolver: {attrs.get('resolver', 'Unknown')}\n\n"
            else:
                response_text = f"❌ Failed to get DNS resolutions: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "vt_domain_subdomains":
            domain = arguments.get("domain")
            limit = arguments.get("limit", 40)
            
            if not domain:
                return [types.TextContent(type="text", text="❌ Domain is required!")]
            
            logger.info(f"Getting subdomains for: {domain}")
            result = await vt_client.get_domain_subdomains(domain, limit)
            
            if result.get("success"):
                subdomains = result.get("data", [])
                response_text = f"🌐 **Subdomains of {domain}**\n\n"
                response_text += f"Found {len(subdomains)} subdomains:\n\n"
                
                for sub in subdomains:
                    response_text += f"  - {sub.get('id', 'Unknown')}\n"
            else:
                response_text = f"❌ Failed to get subdomains: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "vt_domain_siblings":
            domain = arguments.get("domain")
            limit = arguments.get("limit", 40)
            
            if not domain:
                return [types.TextContent(type="text", text="❌ Domain is required!")]
            
            logger.info(f"Getting sibling domains for: {domain}")
            result = await vt_client.get_domain_siblings(domain, limit)
            
            if result.get("success"):
                siblings = result.get("data", [])
                response_text = f"🔗 **Sibling Domains of {domain}**\n\n"
                response_text += f"Found {len(siblings)} sibling domains:\n\n"
                
                for sib in siblings:
                    response_text += f"  - {sib.get('id', 'Unknown')}\n"
            else:
                response_text = f"❌ Failed to get siblings: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "vt_domain_communicating_files":
            domain = arguments.get("domain")
            limit = arguments.get("limit", 20)
            
            if not domain:
                return [types.TextContent(type="text", text="❌ Domain is required!")]
            
            logger.info(f"Getting communicating files for: {domain}")
            result = await vt_client.get_domain_communicating_files(domain, limit)
            
            if result.get("success"):
                files = result.get("data", [])
                response_text = f"🦠 **Files Communicating with {domain}**\n\n"
                response_text += f"Found {len(files)} files/malware:\n\n"
                
                for file in files:
                    attrs = file.get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    response_text += f"**SHA256:** {file.get('id', 'Unknown')[:16]}...\n"
                    response_text += f"  Names: {', '.join(attrs.get('names', ['Unknown'])[:3])}\n"
                    response_text += f"  Type: {attrs.get('type_description', 'Unknown')}\n"
                    response_text += f"  Detections: 🔴 {stats.get('malicious', 0)} / {sum(stats.values())}\n\n"
            else:
                response_text = f"❌ Failed to get communicating files: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "vt_domain_referrer_files":
            domain = arguments.get("domain")
            limit = arguments.get("limit", 20)
            
            if not domain:
                return [types.TextContent(type="text", text="❌ Domain is required!")]
            
            logger.info(f"Getting referrer files for: {domain}")
            result = await vt_client.get_domain_referrer_files(domain, limit)
            
            if result.get("success"):
                files = result.get("data", [])
                response_text = f"📄 **Files Referencing {domain}**\n\n"
                response_text += f"Found {len(files)} files containing this domain:\n\n"
                
                for file in files:
                    attrs = file.get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    response_text += f"**SHA256:** {file.get('id', 'Unknown')[:16]}...\n"
                    response_text += f"  Names: {', '.join(attrs.get('names', ['Unknown'])[:3])}\n"
                    response_text += f"  Type: {attrs.get('type_description', 'Unknown')}\n"
                    response_text += f"  Detections: 🔴 {stats.get('malicious', 0)} / {sum(stats.values())}\n\n"
            else:
                response_text = f"❌ Failed to get referrer files: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        # IP Analysis
        elif name == "vt_ip":
            ip = arguments.get("ip")
            if not ip:
                return [types.TextContent(type="text", text="❌ IP is required!")]
            
            logger.info(f"Analyzing IP: {ip}")
            result = await vt_client.get_ip(ip)
            
            if result.get("success"):
                response_text = format_ip_report(result.get("data", {}))
            else:
                response_text = f"❌ IP analysis failed: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "vt_ip_dns":
            ip = arguments.get("ip")
            limit = arguments.get("limit", 40)
            
            if not ip:
                return [types.TextContent(type="text", text="❌ IP is required!")]
            
            logger.info(f"Getting reverse DNS for IP: {ip}")
            result = await vt_client.get_ip_dns_resolutions(ip, limit)
            
            if result.get("success"):
                resolutions = result.get("data", [])
                response_text = f"🔍 **Reverse DNS for {ip}**\n\n"
                response_text += f"Found {len(resolutions)} domains that resolved to this IP:\n\n"
                
                for res in resolutions:
                    attrs = res.get("attributes", {})
                    response_text += f"**Domain:** {attrs.get('host_name')}\n"
                    response_text += f"  Date: {attrs.get('date', 'Unknown')}\n"
                    response_text += f"  Resolver: {attrs.get('resolver', 'Unknown')}\n\n"
            else:
                response_text = f"❌ Failed to get reverse DNS: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "vt_ip_communicating_files":
            ip = arguments.get("ip")
            limit = arguments.get("limit", 20)
            
            if not ip:
                return [types.TextContent(type="text", text="❌ IP is required!")]
            
            logger.info(f"Getting communicating files for IP: {ip}")
            result = await vt_client.get_ip_communicating_files(ip, limit)
            
            if result.get("success"):
                files = result.get("data", [])
                response_text = f"🦠 **Files Communicating with {ip}**\n\n"
                response_text += f"Found {len(files)} files/malware:\n\n"
                
                for file in files:
                    attrs = file.get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    response_text += f"**SHA256:** {file.get('id', 'Unknown')[:16]}...\n"
                    response_text += f"  Names: {', '.join(attrs.get('names', ['Unknown'])[:3])}\n"
                    response_text += f"  Detections: 🔴 {stats.get('malicious', 0)} / {sum(stats.values())}\n\n"
            else:
                response_text = f"❌ Failed to get communicating files: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        # URL Analysis
        elif name == "vt_scan_url":
            url = arguments.get("url")
            if not url:
                return [types.TextContent(type="text", text="❌ URL is required!")]
            
            logger.info(f"Scanning URL: {url}")
            result = await vt_client.scan_url(url)
            
            if result.get("success"):
                data = result.get("data", {})
                response_text = f"""⚡ **URL Submitted for Scanning**

**URL:** {data.get('url')}
**Analysis ID:** {data.get('id')}
**URL ID:** {data.get('url_id')}

Check results in a moment with vt_url tool."""
            else:
                response_text = f"❌ URL scan failed: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "vt_url":
            url = arguments.get("url")
            if not url:
                return [types.TextContent(type="text", text="❌ URL is required!")]
            
            logger.info(f"Getting URL report: {url}")
            result = await vt_client.get_url(url)
            
            if result.get("success"):
                data = result.get("data", {})
                attrs = data.get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                
                response_text = f"""🔗 **URL Analysis: {url}**

**Last Analysis:** {attrs.get('last_analysis_date', 'Unknown')}

**Detection Results:**
🟢 Clean: {stats.get('harmless', 0)}
🔴 Malicious: {stats.get('malicious', 0)}
🟡 Suspicious: {stats.get('suspicious', 0)}
⚪ Undetected: {stats.get('undetected', 0)}

**Categories:** {', '.join(attrs.get('categories', {}).values()) if attrs.get('categories') else 'None'}
**Title:** {attrs.get('title', 'N/A')}
**Final URL:** {attrs.get('last_final_url', 'N/A')}
"""
            else:
                response_text = f"❌ URL report failed: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        # File Analysis
        elif name == "vt_file":
            hash_value = arguments.get("hash")
            if not hash_value:
                return [types.TextContent(type="text", text="❌ File hash is required!")]
            
            logger.info(f"Getting file report: {hash_value}")
            result = await vt_client.get_file(hash_value)
            
            if result.get("success"):
                data = result.get("data", {})
                attrs = data.get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                
                response_text = f"""📁 **File Analysis**

**SHA256:** {data.get('id', 'Unknown')[:32]}...
**Names:** {', '.join(attrs.get('names', ['Unknown'])[:5])}
**Type:** {attrs.get('type_description', 'Unknown')}
**Size:** {attrs.get('size', 0):,} bytes

**Detection Results:**
🟢 Clean: {stats.get('harmless', 0)}
🔴 Malicious: {stats.get('malicious', 0)}
🟡 Suspicious: {stats.get('suspicious', 0)}
⚪ Undetected: {stats.get('undetected', 0)}

**Tags:** {', '.join(attrs.get('tags', ['None']))}
**First Seen:** {attrs.get('first_submission_date', 'Unknown')}
"""
            else:
                response_text = f"❌ File report failed: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "vt_file_behaviour":
            hash_value = arguments.get("hash")
            if not hash_value:
                return [types.TextContent(type="text", text="❌ File hash is required!")]
            
            logger.info(f"Getting file behaviour: {hash_value}")
            result = await vt_client.get_file_behaviour(hash_value)
            
            if result.get("success"):
                behaviours = result.get("data", [])
                response_text = f"🔬 **File Behaviour Analysis**\n\n"
                
                if behaviours:
                    for idx, behaviour in enumerate(behaviours[:3], 1):
                        attrs = behaviour.get("attributes", {})
                        response_text += f"**Sandbox {idx}:**\n"
                        response_text += f"  Platform: {attrs.get('sandbox_name', 'Unknown')}\n"
                        
                        # Show some interesting behaviors
                        if attrs.get('processes_tree'):
                            response_text += "  Process Activity: Yes\n"
                        if attrs.get('files_dropped'):
                            response_text += f"  Files Dropped: {len(attrs['files_dropped'])}\n"
                        if attrs.get('registry_keys_set'):
                            response_text += f"  Registry Keys: {len(attrs['registry_keys_set'])}\n"
                        if attrs.get('dns_lookups'):
                            response_text += f"  DNS Lookups: {len(attrs['dns_lookups'])}\n"
                        response_text += "\n"
                else:
                    response_text += "No sandbox analysis available for this file."
            else:
                response_text = f"❌ Behaviour analysis failed: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "vt_file_contacted_domains":
            hash_value = arguments.get("hash")
            limit = arguments.get("limit", 20)
            
            if not hash_value:
                return [types.TextContent(type="text", text="❌ File hash is required!")]
            
            logger.info(f"Getting contacted domains for file: {hash_value}")
            result = await vt_client.get_file_contacted_domains(hash_value, limit)
            
            if result.get("success"):
                domains = result.get("data", [])
                response_text = f"🌐 **Domains Contacted by File**\n\n"
                response_text += f"Found {len(domains)} contacted domains:\n\n"
                
                for domain in domains:
                    response_text += f"  - {domain.get('id', 'Unknown')}\n"
            else:
                response_text = f"❌ Failed to get contacted domains: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        # Comments
        elif name == "vt_comments":
            object_type = arguments.get("object_type")
            object_id = arguments.get("object_id")
            limit = arguments.get("limit", 20)
            
            if not object_type or not object_id:
                return [types.TextContent(type="text", text="❌ Object type and ID are required!")]
            
            logger.info(f"Getting comments for {object_type}: {object_id}")
            result = await vt_client.get_comments(object_type, object_id, limit)
            
            if result.get("success"):
                comments = result.get("data", [])
                response_text = f"💬 **Community Comments for {object_type}: {object_id}**\n\n"
                
                if comments:
                    for comment in comments:
                        attrs = comment.get("attributes", {})
                        response_text += f"**Date:** {attrs.get('date', 'Unknown')}\n"
                        response_text += f"**Votes:** 👍 {attrs.get('votes', {}).get('positive', 0)} / 👎 {attrs.get('votes', {}).get('negative', 0)}\n"
                        response_text += f"**Comment:** {attrs.get('text', 'N/A')}\n\n"
                else:
                    response_text += "No community comments found."
            else:
                response_text = f"❌ Failed to get comments: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        # Search
        elif name == "vt_search":
            query = arguments.get("query")
            limit = arguments.get("limit", 20)
            
            if not query:
                return [types.TextContent(type="text", text="❌ Search query is required!")]
            
            logger.info(f"Searching VirusTotal: {query}")
            result = await vt_client.search(query, limit)
            
            if result.get("success"):
                results = result.get("data", [])
                note = result.get("note", "")
                
                response_text = f"🔍 **VirusTotal Search: {query}**\n\n"
                if note:
                    response_text += f"_{note}_\n\n"
                response_text += f"Found {len(results)} results:\n\n"
                
                for res in results[:10]:
                    attrs = res.get("attributes", {})
                    response_text += f"**{res.get('type', 'Unknown')}:** {res.get('id', 'Unknown')[:32]}...\n"
                    if attrs.get('names'):
                        response_text += f"  Names: {', '.join(attrs['names'][:3])}\n"
                    response_text += "\n"
            else:
                response_text = f"❌ Search failed: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        # API Usage
        elif name == "vt_api_usage":
            logger.info("Getting API usage")
            result = await vt_client.get_api_usage()
            
            if result.get("success"):
                data = result.get("data", {})
                attrs = data.get("attributes", {})
                quotas = attrs.get("quotas", {})
                
                response_text = "📊 **VirusTotal API Usage**\n\n"
                
                for quota_name, quota_info in quotas.items():
                    used = quota_info.get("used", 0)
                    allowed = quota_info.get("allowed", 0)
                    response_text += f"**{quota_name}:**\n"
                    response_text += f"  Used: {used} / {allowed}\n"
                    response_text += f"  Remaining: {allowed - used}\n\n"
            else:
                response_text = f"❌ Failed to get API usage: {result.get('error')}"
            
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
    """Main entry point for the VirusTotal MCP server"""
    global vt_client
    logger.info("Starting VirusTotal MCP Server...")
    
    # Check for API key
    if not get_api_key():
        logger.warning("⚠️  VT_API_KEY or VIRUSTOTAL_API_KEY not set in environment!")
        logger.warning("Set it before using the tools: export VT_API_KEY='your_key_here'")
    
    try:
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            await app.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="virustotal-mcp",
                    server_version="1.0.1",
                    capabilities=app.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )
    finally:
        # Cleanup
        if vt_client:
            await vt_client.close()
            vt_client = None

if __name__ == "__main__":
    asyncio.run(main())