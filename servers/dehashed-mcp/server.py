#!/usr/bin/env python3
"""
DeHashed MCP Server - Breach Intelligence & WHOIS Investigation Tool
Find leaked credentials, map domain ownership, expose hidden connections!
"""

import asyncio
import json
import logging
import os
import sys
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from enum import Enum

import httpx
from mcp.server import Server, NotificationOptions
from mcp.server.models import InitializationOptions
import mcp.server.stdio
import mcp.types as types

# Configure logging for our breach intelligence operations
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("dehashed-mcp")

class DeHashedClient:
    """Client for interacting with the DeHashed API"""
    
    def __init__(self, api_key: str):
        """Initialize the DeHashed client"""
        self.api_key = api_key
        self.base_url = "https://api.dehashed.com/v2"
        self.headers = {
            "Dehashed-Api-Key": api_key,
            "Content-Type": "application/json"
        }
        self.client = httpx.AsyncClient(timeout=30.0)
        self.search_balance = None
        self.whois_credits = None
    
    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()
    
    # Core Search Functions
    async def search(self, query: str, page: int = 1, size: int = 100, 
                    regex: bool = False, wildcard: bool = False, 
                    de_dupe: bool = True) -> Dict[str, Any]:
        """
        Search for breach data
        
        Args:
            query: Search query (email, username, phone, name, IP, domain, etc.)
            page: Page number for pagination
            size: Results per page (max 10000)
            regex: Use regex matching
            wildcard: Use wildcard matching
            de_dupe: Remove duplicate results
        """
        try:
            # Validate parameters
            if regex and wildcard:
                return {"success": False, "error": "Cannot use both regex and wildcard"}
            
            if page * size > 10000:
                return {"success": False, "error": "Maximum pagination depth is 10,000"}
            
            response = await self.client.post(
                f"{self.base_url}/search",
                headers=self.headers,
                json={
                    "query": query,
                    "page": page,
                    "size": size,
                    "regex": regex,
                    "wildcard": wildcard,
                    "de_dupe": de_dupe
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                # Store balance for tracking
                if "balance" in data:
                    self.search_balance = data["balance"]
                return {"success": True, "data": data}
            else:
                error_data = response.json() if response.text else {}
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}",
                    "details": error_data
                }
                
        except Exception as e:
            logger.error(f"Error searching: {e}")
            return {"success": False, "error": str(e)}
    
    async def password_search(self, password: str) -> Dict[str, Any]:
        """
        Check if a password has been leaked (FREE - doesn't use credits)
        
        Args:
            password: Plain text password to check
        """
        try:
            # Hash the password with SHA-256
            sha256_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
            
            response = await self.client.post(
                f"{self.base_url}/search-password",
                headers=self.headers,
                json={
                    "sha256_hashed_password": sha256_hash
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                return {"success": True, "data": data}
            else:
                return {"success": False, "error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            logger.error(f"Error checking password: {e}")
            return {"success": False, "error": str(e)}
    
    # WHOIS Functions
    async def whois_search(self, search_type: str, **kwargs) -> Dict[str, Any]:
        """
        Perform various WHOIS searches
        
        Args:
            search_type: Type of WHOIS search
            **kwargs: Additional parameters based on search type
        """
        try:
            json_data = {"search_type": search_type}
            
            # Add parameters based on search type
            if search_type in ["whois", "whois-history", "reverse-ip", "reverse-mx", 
                              "reverse-ns", "subdomain-scan"]:
                # Correct parameter for WHOIS/history is 'domain', but reverse-ip uses 'ip_address', etc.
                # However, the endpoint expects 'domain' for all these except 'reverse-ip' which might be flexible or require 'domain' field.
                # Let's check docs or behavior.
                # Standard search uses 'query', but whois/search endpoint uses specific fields.
                # Actually, for whois-history, parameter is just 'domain'.
                if kwargs.get("domain"):
                    json_data["domain"] = kwargs.get("domain")
                elif kwargs.get("ip_address"):
                    json_data["domain"] = kwargs.get("ip_address")
                elif kwargs.get("mx_server"):
                    json_data["domain"] = kwargs.get("mx_server")
                elif kwargs.get("ns_server"):
                    json_data["domain"] = kwargs.get("ns_server")
            
            if search_type == "reverse-whois":
                if "include" in kwargs:
                    json_data["include"] = kwargs["include"]
                if "exclude" in kwargs:
                    json_data["exclude"] = kwargs["exclude"]
                if "reverse_type" in kwargs:
                    json_data["reverse_type"] = kwargs["reverse_type"]
            
            response = await self.client.post(
                f"{self.base_url}/whois/search",
                headers=self.headers,
                json=json_data
            )
            
            if response.status_code == 200:
                data = response.json()
                return {"success": True, "data": data}
            else:
                # Parse the API error message for better reporting
                error_msg = f"HTTP {response.status_code}"
                error_details = {}
                try:
                    error_details = response.json() if response.text else {}
                    if "error" in error_details:
                        error_msg = error_details["error"]
                except:
                    error_details = {"raw": response.text}
                
                logger.error(f"WHOIS API error for {search_type}: {error_msg} - {error_details}")
                return {
                    "success": False,
                    "error": error_msg,
                    "details": error_details,
                    "search_type": search_type
                }
                
        except Exception as e:
            logger.error(f"Error in WHOIS search: {e}")
            return {"success": False, "error": str(e)}
    
    async def whois(self, domain: str) -> Dict[str, Any]:
        """Get current WHOIS information for a domain"""
        return await self.whois_search("whois", domain=domain)
    
    async def whois_history(self, domain: str) -> Dict[str, Any]:
        """Get historical WHOIS information (costs 25 credits!)"""
        return await self.whois_search("whois-history", domain=domain)
    
    async def reverse_whois(self, include: List[str] = None, exclude: List[str] = None, 
                           reverse_type: str = "current") -> Dict[str, Any]:
        """Find all domains by registrant info"""
        if not include and not exclude:
            return {"success": False, "error": "Must provide either include or exclude terms"}
        
        return await self.whois_search(
            "reverse-whois",
            include=include or [],
            exclude=exclude or [],
            reverse_type=reverse_type
        )
    
    async def reverse_ip(self, ip_address: str) -> Dict[str, Any]:
        """Find all domains on an IP"""
        return await self.whois_search("reverse-ip", domain=ip_address)
    
    async def reverse_mx(self, mx_server: str) -> Dict[str, Any]:
        """Find all domains using an MX server"""
        return await self.whois_search("reverse-mx", domain=mx_server)
    
    async def reverse_ns(self, ns_server: str) -> Dict[str, Any]:
        """Find all domains using a nameserver"""
        return await self.whois_search("reverse-ns", domain=ns_server)
    
    async def subdomain_scan(self, domain: str) -> Dict[str, Any]:
        """Find subdomains for a domain"""
        return await self.whois_search("subdomain-scan", domain=domain)
    
    async def get_credits(self) -> Dict[str, Any]:
        """Get WHOIS credits and search balance"""
        try:
            # Get WHOIS credits
            response = await self.client.get(
                f"{self.base_url}/whois/credits",
                headers={"Dehashed-Api-Key": self.api_key}
            )
            
            whois_credits = 0
            if response.status_code == 200:
                data = response.json()
                whois_credits = data.get("whois_credits", 0)
                self.whois_credits = whois_credits
            
            return {
                "success": True,
                "data": {
                    "search_balance": self.search_balance or "Unknown (run a search to check)",
                    "whois_credits": whois_credits
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting credits: {e}")
            return {"success": False, "error": str(e)}

# Initialize the MCP server
app = Server("dehashed-mcp")
logger.info("Initializing DeHashed MCP Server - Breach intelligence ready!")

# Global client instance
dehashed_client: Optional[DeHashedClient] = None

def get_api_key() -> Optional[str]:
    """Get API key from environment variable"""
    api_key = os.getenv("DEHASHED_API_KEY")
    if not api_key:
        logger.warning("No DEHASHED_API_KEY found in environment!")
    return api_key

def format_breach_result(entry: Dict) -> str:
    """Format a breach entry for display"""
    result = []
    
    # Add all available fields
    if entry.get("email"):
        result.append(f"📧 **Email:** {', '.join(entry['email'])}")
    if entry.get("username"):
        result.append(f"👤 **Username:** {', '.join(entry['username'])}")
    if entry.get("password"):
        result.append(f"🔑 **Password:** {', '.join(entry['password'][:3]) if len(entry['password']) > 3 else entry['password']}")
    if entry.get("hashed_password"):
        result.append(f"🔐 **Hash:** {entry['hashed_password'][0][:20]}..." if entry['hashed_password'] else "N/A")
    if entry.get("name"):
        result.append(f"📝 **Name:** {', '.join(entry['name'])}")
    if entry.get("phone"):
        result.append(f"📱 **Phone:** {', '.join(entry['phone'])}")
    if entry.get("address"):
        result.append(f"🏠 **Address:** {entry['address'][0][:50]}...")
    if entry.get("ip_address"):
        result.append(f"🌐 **IP:** {', '.join(entry['ip_address'])}")
    if entry.get("company"):
        result.append(f"🏢 **Company:** {', '.join(entry['company'])}")
    if entry.get("database_name"):
        result.append(f"💾 **Source:** {entry['database_name']}")
    
    return "\n".join(result)

@app.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List available DeHashed tools - TRIMMED for efficiency"""
    return [
        # Core Search - ESSENTIAL
        types.Tool(
            name="dehashed_search",
            description="Search breach databases for emails, usernames, phones, names, IPs, domains. Find leaked credentials and PII.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query (e.g., 'email:user@example.com' or 'domain:example.com')"
                    },
                    "page": {
                        "type": "integer",
                        "description": "Page number (default: 1)",
                        "default": 1
                    },
                    "size": {
                        "type": "integer",
                        "description": "Results per page (max 10000, default: 100)",
                        "default": 100
                    },
                    "de_dupe": {
                        "type": "boolean",
                        "description": "Remove duplicates (default: true)",
                        "default": True
                    },
                    "wildcard": {
                        "type": "boolean",
                        "description": "Use wildcard matching",
                        "default": False
                    }
                },
                "required": ["query"]
            }
        ),
        types.Tool(
            name="dehashed_credits",
            description="Check remaining search and WHOIS credits",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        # DISABLED (expensive WHOIS features - use Shodan/VT for DNS/domain intel instead):
        # dehashed_password_check, dehashed_whois, dehashed_whois_history, dehashed_reverse_whois,
        # dehashed_reverse_mx, dehashed_reverse_ns, dehashed_reverse_ip, dehashed_subdomain_scan
    ]

@app.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """Execute DeHashed tools"""
    
    global dehashed_client
    
    # Initialize client if needed
    if dehashed_client is None:
        api_key = get_api_key()
        if not api_key:
            return [types.TextContent(
                type="text",
                text="❌ DEHASHED_API_KEY not found in environment! Set it to use this tool."
            )]
        dehashed_client = DeHashedClient(api_key)
    
    try:
        # Search Functions
        if name == "dehashed_search":
            query = arguments.get("query")
            if not query:
                return [types.TextContent(type="text", text="❌ Query is required!")]
            
            page = arguments.get("page", 1)
            size = arguments.get("size", 100)
            de_dupe = arguments.get("de_dupe", True)
            wildcard = arguments.get("wildcard", False)
            
            logger.info(f"Searching DeHashed for: {query}")
            result = await dehashed_client.search(query, page, size, wildcard=wildcard, de_dupe=de_dupe)
            
            if result.get("success"):
                data = result.get("data", {})
                entries = data.get("entries", [])
                total = data.get("total", 0)
                balance = data.get("balance", "Unknown")
                
                response_text = f"""🔍 **DeHashed Breach Search Results**

**Query:** `{query}`
**Total Results:** {total:,}
**Results on this page:** {len(entries)}
**Credits Remaining:** {balance}
**Time:** {data.get('took', 'N/A')}

"""
                
                if entries:
                    response_text += "**🚨 Leaked Data Found:**\n\n"
                    for i, entry in enumerate(entries[:20], 1):  # Limit to 20 results
                        response_text += f"**Result {i}:**\n"
                        response_text += format_breach_result(entry)
                        response_text += "\n\n"
                else:
                    response_text += "✅ No breach data found for this query."
                
                if total > len(entries):
                    response_text += f"\n_Showing {len(entries)} of {total} total results. Use pagination to see more._"
            else:
                response_text = f"❌ Search failed: {result.get('error')}\n{result.get('details', {})}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "dehashed_password_check":
            password = arguments.get("password")
            if not password:
                return [types.TextContent(type="text", text="❌ Password is required!")]
            
            logger.info("Checking if password has been leaked...")
            result = await dehashed_client.password_search(password)
            
            if result.get("success"):
                data = result.get("data", {})
                found = data.get("results_found", 0)
                
                if found > 0:
                    response_text = f"""🚨 **PASSWORD COMPROMISED!**

This password appears in **{found:,}** breach records!
⚠️ Do NOT use this password - it has been leaked!"""
                else:
                    response_text = """✅ **Password Not Found in Breaches**

This password does not appear in known breach databases.
(But still use unique, strong passwords!)"""
            else:
                response_text = f"❌ Password check failed: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        # WHOIS Functions
        elif name == "dehashed_whois":
            domain = arguments.get("domain")
            if not domain:
                return [types.TextContent(type="text", text="❌ Domain is required!")]
            
            logger.info(f"Getting WHOIS for: {domain}")
            result = await dehashed_client.whois(domain)
            
            if result.get("success"):
                data = result.get("data", {})
                response_text = f"""🌐 **WHOIS Information for {domain}**

{json.dumps(data, indent=2)}
"""
            else:
                response_text = f"❌ WHOIS lookup failed: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "dehashed_whois_history":
            domain = arguments.get("domain")
            if not domain:
                return [types.TextContent(type="text", text="❌ Domain is required!")]
            
            # First check available credits
            logger.info(f"Getting WHOIS history for: {domain}")
            credits_result = await dehashed_client.get_credits()
            whois_credits = credits_result.get("data", {}).get("whois_credits", 0) if credits_result.get("success") else 0
            
            response_text = f"⚠️ **WARNING: This costs 25 WHOIS credits!**\n"
            response_text += f"💳 **Available credits: {whois_credits}**\n\n"
            
            if whois_credits < 25:
                response_text += f"❌ **INSUFFICIENT CREDITS!** You need 25 WHOIS credits but only have {whois_credits}.\n"
                response_text += "Purchase more credits at https://dehashed.com to use this feature."
                return [types.TextContent(type="text", text=response_text)]
            
            result = await dehashed_client.whois_history(domain)
            
            if result.get("success"):
                data = result.get("data", {})
                response_text += f"""📚 **WHOIS History for {domain}**

{json.dumps(data, indent=2)}
"""
            else:
                error_msg = result.get("error", "Unknown error")
                error_details = result.get("details", {})
                response_text += f"❌ **WHOIS history failed:** {error_msg}\n"
                if error_details:
                    response_text += f"Details: {json.dumps(error_details)}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "dehashed_reverse_whois":
            include = arguments.get("include", [])
            exclude = arguments.get("exclude", [])
            reverse_type = arguments.get("reverse_type", "current")
            
            if not include and not exclude:
                return [types.TextContent(type="text", text="❌ Must provide either include or exclude terms!")]
            
            logger.info(f"Reverse WHOIS search - Include: {include}, Exclude: {exclude}")
            result = await dehashed_client.reverse_whois(include, exclude, reverse_type)
            
            if result.get("success"):
                data = result.get("data", {})
                response_text = f"""🔍 **Reverse WHOIS Results**

**Search Type:** {reverse_type}
**Include Terms:** {', '.join(include) if include else 'None'}
**Exclude Terms:** {', '.join(exclude) if exclude else 'None'}

**Results:**
{json.dumps(data, indent=2)}
"""
            else:
                response_text = f"❌ Reverse WHOIS failed: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "dehashed_reverse_mx":
            mx_server = arguments.get("mx_server")
            if not mx_server:
                return [types.TextContent(type="text", text="❌ MX server is required!")]
            
            logger.info(f"Finding domains using MX: {mx_server}")
            result = await dehashed_client.reverse_mx(mx_server)
            
            if result.get("success"):
                data = result.get("data", {})
                response_text = f"""📧 **Domains Using MX Server: {mx_server}**

{json.dumps(data, indent=2)}
"""
            else:
                response_text = f"❌ Reverse MX failed: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "dehashed_reverse_ns":
            ns_server = arguments.get("ns_server")
            if not ns_server:
                return [types.TextContent(type="text", text="❌ NS server is required!")]
            
            logger.info(f"Finding domains using NS: {ns_server}")
            result = await dehashed_client.reverse_ns(ns_server)
            
            if result.get("success"):
                data = result.get("data", {})
                response_text = f"""🌐 **Domains Using Nameserver: {ns_server}**

{json.dumps(data, indent=2)}
"""
            else:
                response_text = f"❌ Reverse NS failed: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "dehashed_reverse_ip":
            ip_address = arguments.get("ip_address")
            if not ip_address:
                return [types.TextContent(type="text", text="❌ IP address is required!")]
            
            logger.info(f"Finding domains on IP: {ip_address}")
            result = await dehashed_client.reverse_ip(ip_address)
            
            if result.get("success"):
                data = result.get("data", {})
                response_text = f"""🖥️ **Domains on IP {ip_address}**

{json.dumps(data, indent=2)}
"""
            else:
                response_text = f"❌ Reverse IP failed: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "dehashed_subdomain_scan":
            domain = arguments.get("domain")
            if not domain:
                return [types.TextContent(type="text", text="❌ Domain is required!")]
            
            logger.info(f"Scanning subdomains for: {domain}")
            result = await dehashed_client.subdomain_scan(domain)
            
            if result.get("success"):
                data = result.get("data", {})
                response_text = f"""🔍 **Subdomains for {domain}**

{json.dumps(data, indent=2)}
"""
            else:
                response_text = f"❌ Subdomain scan failed: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "dehashed_credits":
            logger.info("Checking DeHashed credits...")
            result = await dehashed_client.get_credits()
            
            if result.get("success"):
                data = result.get("data", {})
                response_text = f"""💳 **DeHashed Credit Balance**

**Search Credits:** {data.get('search_balance', 'Unknown')}
**WHOIS Credits:** {data.get('whois_credits', 0)}

_Note: Search balance updates after running a search_"""
            else:
                response_text = f"❌ Failed to get credits: {result.get('error')}"
            
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
    """Main entry point for the DeHashed MCP server"""
    global dehashed_client
    logger.info("Starting DeHashed MCP Server...")
    
    # Check for API key
    if not get_api_key():
        logger.warning("⚠️  DEHASHED_API_KEY not set in environment!")
        logger.warning("Set it before using: export DEHASHED_API_KEY='your_key_here'")
    
    try:
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            await app.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="dehashed-mcp",
                    server_version="1.0.0",
                    capabilities=app.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )
    finally:
        # Cleanup
        if dehashed_client:
            await dehashed_client.close()
            dehashed_client = None

if __name__ == "__main__":
    asyncio.run(main())