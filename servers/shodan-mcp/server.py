#!/usr/bin/env python3
"""
Shodan MCP Server - Cyber Reconnaissance Tool
The all-seeing eye of the internet - exposing vulnerable systems worldwide!
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from enum import Enum

import httpx
from mcp.server import Server, NotificationOptions
from mcp.server.models import InitializationOptions
import mcp.server.stdio
import mcp.types as types

# Configure logging for our cyber operations
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("shodan-mcp")

class ShodanClient:
    """Client for interacting with the Shodan API"""
    
    def __init__(self, api_key: str):
        """Initialize the Shodan client with API key"""
        self.api_key = api_key
        self.base_url = "https://api.shodan.io"
        self.stream_url = "https://stream.shodan.io"
        self.trends_url = "https://trends.shodan.io"
        self.client = httpx.AsyncClient(timeout=30.0)
        
    async def _make_request(self, method: str, endpoint: str, params: Optional[Dict] = None, 
                          json_data: Optional[Dict] = None, base_url: Optional[str] = None) -> Dict[str, Any]:
        """Make a request to the Shodan API"""
        try:
            url = (base_url or self.base_url) + endpoint
            
            # Add API key to params
            if params is None:
                params = {}
            params['key'] = self.api_key
            
            response = await self.client.request(
                method=method,
                url=url,
                params=params,
                json=json_data
            )
            
            # Check for errors
            if response.status_code != 200:
                error_data = {}
                try:
                    error_data = response.json()
                except:
                    error_data = {"error": response.text}
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}",
                    "details": error_data
                }
            
            return {"success": True, "data": response.json()}
            
        except httpx.HTTPError as e:
            logger.error(f"HTTP error: {e}")
            return {
                "success": False,
                "error": str(e)
            }
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    # Search Methods
    async def search(self, query: str, facets: Optional[str] = None, page: int = 1, 
                    minify: bool = True) -> Dict[str, Any]:
        """Search Shodan using the query syntax"""
        params = {
            'query': query,
            'page': page,
            'minify': minify
        }
        if facets:
            params['facets'] = facets
        return await self._make_request('GET', '/shodan/host/search', params)
    
    async def count(self, query: str, facets: Optional[str] = None) -> Dict[str, Any]:
        """Get total results for a search query"""
        params = {'query': query}
        if facets:
            params['facets'] = facets
        return await self._make_request('GET', '/shodan/host/count', params)
    
    async def host(self, ip: str, history: bool = False, minify: bool = True) -> Dict[str, Any]:
        """Get all services for a specific IP"""
        params = {
            'history': history,
            'minify': minify
        }
        return await self._make_request('GET', f'/shodan/host/{ip}', params)
    
    async def search_facets(self) -> Dict[str, Any]:
        """Get list of search facets"""
        return await self._make_request('GET', '/shodan/host/search/facets')
    
    async def search_filters(self) -> Dict[str, Any]:
        """Get list of search filters"""
        return await self._make_request('GET', '/shodan/host/search/filters')
    
    # DNS Methods
    async def dns_domain(self, domain: str, page: int = 1) -> Dict[str, Any]:
        """Get all subdomains and DNS records for a domain"""
        params = {'page': page}
        return await self._make_request('GET', f'/dns/domain/{domain}', params)
    
    async def dns_resolve(self, hostnames: List[str]) -> Dict[str, Any]:
        """Resolve hostnames to IPs"""
        params = {'hostnames': ','.join(hostnames)}
        return await self._make_request('GET', '/dns/resolve', params)
    
    async def dns_reverse(self, ips: List[str]) -> Dict[str, Any]:
        """Get hostnames for IPs"""
        params = {'ips': ','.join(ips)}
        return await self._make_request('GET', '/dns/reverse', params)
    
    # Scanning Methods
    async def scan(self, ips: List[str], force: bool = False) -> Dict[str, Any]:
        """Request on-demand scan of IPs"""
        json_data = {'ips': ips}
        if force:
            json_data['force'] = force
        return await self._make_request('POST', '/shodan/scan', json_data=json_data)
    
    async def scan_internet(self, port: int, protocol: str) -> Dict[str, Any]:
        """Request scan of the entire Internet for a specific port"""
        json_data = {
            'port': port,
            'protocol': protocol
        }
        return await self._make_request('POST', '/shodan/scan/internet', json_data=json_data)
    
    async def scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get status of a scan"""
        return await self._make_request('GET', f'/shodan/scan/{scan_id}')
    
    async def scans(self) -> Dict[str, Any]:
        """Get list of all scans"""
        return await self._make_request('GET', '/shodan/scans')
    
    # Alert Methods
    async def alert_create(self, name: str, filters: Dict[str, Any], 
                          expires: Optional[int] = None) -> Dict[str, Any]:
        """Create a new network alert"""
        json_data = {
            'name': name,
            'filters': filters
        }
        if expires:
            json_data['expires'] = expires
        return await self._make_request('POST', '/shodan/alert', json_data=json_data)
    
    async def alert_info(self, alert_id: str) -> Dict[str, Any]:
        """Get information about an alert"""
        return await self._make_request('GET', f'/shodan/alert/{alert_id}/info')
    
    async def alert_delete(self, alert_id: str) -> Dict[str, Any]:
        """Delete an alert"""
        return await self._make_request('DELETE', f'/shodan/alert/{alert_id}')
    
    async def alerts(self) -> Dict[str, Any]:
        """Get all alerts"""
        return await self._make_request('GET', '/shodan/alert/info')
    
    # Query Methods
    async def queries(self, page: int = 1, sort: str = "timestamp", order: str = "desc") -> Dict[str, Any]:
        """Get saved search queries"""
        params = {
            'page': page,
            'sort': sort,
            'order': order
        }
        return await self._make_request('GET', '/shodan/query', params)
    
    async def query_search(self, query: str, page: int = 1) -> Dict[str, Any]:
        """Search saved queries"""
        params = {
            'query': query,
            'page': page
        }
        return await self._make_request('GET', '/shodan/query/search', params)
    
    async def query_tags(self, size: int = 10) -> Dict[str, Any]:
        """Get popular tags for saved queries"""
        params = {'size': size}
        return await self._make_request('GET', '/shodan/query/tags', params)
    
    # Utility Methods
    async def my_ip(self) -> Dict[str, Any]:
        """Get your current IP"""
        return await self._make_request('GET', '/tools/myip')
    
    async def http_headers(self) -> Dict[str, Any]:
        """Get HTTP headers your client sends"""
        return await self._make_request('GET', '/tools/httpheaders')
    
    async def api_info(self) -> Dict[str, Any]:
        """Get API plan information"""
        return await self._make_request('GET', '/api-info')
    
    # Account Methods
    async def account_profile(self) -> Dict[str, Any]:
        """Get account profile"""
        return await self._make_request('GET', '/account/profile')
    
    # Data Methods
    async def data(self) -> Dict[str, Any]:
        """Get list of available datasets"""
        return await self._make_request('GET', '/shodan/data')
    
    async def ports(self) -> Dict[str, Any]:
        """Get list of ports Shodan crawls"""
        return await self._make_request('GET', '/shodan/ports')
    
    async def protocols(self) -> Dict[str, Any]:
        """Get list of protocols Shodan crawls"""
        return await self._make_request('GET', '/shodan/protocols')
    
    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()

# Initialize the MCP server
app = Server("shodan-mcp")
logger.info("Initializing Shodan MCP Server - Cyber reconnaissance ready!")

# Global client instance
shodan_client: Optional[ShodanClient] = None

def get_api_key() -> Optional[str]:
    """Get API key from environment variable"""
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        logger.warning("No SHODAN_API_KEY found in environment!")
    return api_key

def format_host_result(host_data: Dict) -> str:
    """Format host information for display"""
    result = f"""**IP:** {host_data.get('ip_str')}
**Organization:** {host_data.get('org', 'N/A')}
**OS:** {host_data.get('os', 'N/A')}
**Country:** {host_data.get('country_name', 'N/A')} ({host_data.get('country_code', 'N/A')})
**City:** {host_data.get('city', 'N/A')}
**ISP:** {host_data.get('isp', 'N/A')}
**Last Update:** {host_data.get('last_update', 'N/A')}

**Open Ports:** {', '.join(map(str, host_data.get('ports', [])))}

**Hostnames:** {', '.join(host_data.get('hostnames', ['None']))}

**Vulnerabilities:** {', '.join(host_data.get('vulns', ['None detected']))}
"""
    
    # Add service banners
    data_items = host_data.get('data', [])
    if data_items:
        result += "\n**Services:**\n"
        for service in data_items[:5]:  # Limit to first 5 services
            result += f"""
📍 **Port {service.get('port')}/{service.get('transport', 'tcp')}**
   Product: {service.get('product', 'Unknown')}
   Version: {service.get('version', 'N/A')}
   Banner: {service.get('data', '')[:100]}...
"""
    
    return result

@app.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List available Shodan tools - TRIMMED for efficiency"""
    return [
        # Search Tools - CORE
        types.Tool(
            name="shodan_search",
            description="Search Shodan for devices using query syntax. Examples: 'apache', 'port:22', 'country:US', 'org:Microsoft'",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Shodan search query (e.g., 'apache', 'port:22 country:US', 'webcam', 'mongodb')"
                    },
                    "page": {
                        "type": "integer",
                        "description": "Results page number (default: 1)",
                        "default": 1
                    },
                    "facets": {
                        "type": "string",
                        "description": "Comma-separated list of facets (e.g., 'country,org')"
                    }
                },
                "required": ["query"]
            }
        ),
        types.Tool(
            name="shodan_host",
            description="Get detailed information about a specific IP address",
            inputSchema={
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "IP address to lookup (e.g., '8.8.8.8')"
                    },
                    "history": {
                        "type": "boolean",
                        "description": "Include historical banners (default: false)",
                        "default": False
                    }
                },
                "required": ["ip"]
            }
        ),
        
        # DNS Tools - CORE
        types.Tool(
            name="shodan_dns_domain",
            description="Get all subdomains and DNS records for a domain",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Domain to lookup (e.g., 'google.com')"
                    },
                    "page": {
                        "type": "integer",
                        "description": "Page number for results",
                        "default": 1
                    }
                },
                "required": ["domain"]
            }
        ),
        types.Tool(
            name="shodan_dns_resolve",
            description="Resolve hostnames to IP addresses",
            inputSchema={
                "type": "object",
                "properties": {
                    "hostnames": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of hostnames to resolve (e.g., ['google.com', 'bing.com'])"
                    }
                },
                "required": ["hostnames"]
            }
        ),
        types.Tool(
            name="shodan_dns_reverse",
            description="Get hostnames for IP addresses (reverse DNS)",
            inputSchema={
                "type": "object",
                "properties": {
                    "ips": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of IPs to reverse lookup"
                    }
                },
                "required": ["ips"]
            }
        ),
        
        # Utility - API Info only
        types.Tool(
            name="shodan_api_info",
            description="Get information about your API plan and usage",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        # DISABLED: shodan_count, shodan_scan, shodan_scan_status, shodan_alerts, 
        # shodan_alert_create, shodan_queries, shodan_query_tags, shodan_my_ip,
        # shodan_ports, shodan_protocols, shodan_search_filters, shodan_search_facets
    ]

@app.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """Execute Shodan tools for cyber reconnaissance"""
    
    global shodan_client
    
    # Initialize client if needed
    if shodan_client is None:
        api_key = get_api_key()
        if not api_key:
            return [types.TextContent(
                type="text",
                text="❌ SHODAN_API_KEY not found in environment! Set it to use this tool."
            )]
        shodan_client = ShodanClient(api_key)
    
    try:
        # Search Tools
        if name == "shodan_search":
            query = arguments.get("query")
            page = arguments.get("page", 1)
            facets = arguments.get("facets")
            
            if not query:
                return [types.TextContent(type="text", text="❌ Query is required!")]
            
            logger.info(f"Searching Shodan for: {query}")
            result = await shodan_client.search(query, facets, page)
            
            if result.get("success"):
                data = result.get("data", {})
                matches = data.get("matches", [])
                total = data.get("total", 0)
                
                response_text = f"""🔍 **Shodan Search Results**

**Query:** `{query}`
**Total Results:** {total:,}
**Page:** {page}
**Results on this page:** {len(matches)}

"""
                if facets and data.get('facets'):
                    response_text += "**Facet Analysis:**\n"
                    for facet_name, facet_data in data['facets'].items():
                        response_text += f"\n{facet_name}:\n"
                        for item in facet_data[:5]:
                            response_text += f"  - {item['value']}: {item['count']:,}\n"
                
                response_text += "\n**Results:**\n"
                
                for match in matches[:10]:  # Limit to 10 results
                    response_text += f"""
🖥️ **{match.get('ip_str')}:{match.get('port')}**
   Organization: {match.get('org', 'N/A')}
   Location: {match.get('location', {}).get('city', 'Unknown')}, {match.get('location', {}).get('country_name', 'Unknown')}
   OS: {match.get('os', 'N/A')}
   Product: {match.get('product', 'N/A')}
   Hostnames: {', '.join(match.get('hostnames', ['None']))}
"""
            else:
                response_text = f"❌ Search failed: {result.get('error')}\n{result.get('details', {})}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "shodan_count":
            query = arguments.get("query")
            facets = arguments.get("facets")
            
            if not query:
                return [types.TextContent(type="text", text="❌ Query is required!")]
            
            logger.info(f"Counting results for: {query}")
            result = await shodan_client.count(query, facets)
            
            if result.get("success"):
                data = result.get("data", {})
                total = data.get("total", 0)
                
                response_text = f"""📊 **Shodan Count Results**

**Query:** `{query}`
**Total Results:** {total:,}
"""
                
                if facets and data.get('facets'):
                    response_text += "\n**Breakdown by Facets:**\n"
                    for facet_name, facet_data in data['facets'].items():
                        response_text += f"\n**{facet_name}:**\n"
                        for item in facet_data[:10]:
                            response_text += f"  - {item['value']}: {item['count']:,}\n"
            else:
                response_text = f"❌ Count failed: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "shodan_host":
            ip = arguments.get("ip")
            history = arguments.get("history", False)
            
            if not ip:
                return [types.TextContent(type="text", text="❌ IP address is required!")]
            
            logger.info(f"Looking up host: {ip}")
            result = await shodan_client.host(ip, history)
            
            if result.get("success"):
                data = result.get("data", {})
                response_text = f"🖥️ **Host Information**\n\n{format_host_result(data)}"
            else:
                response_text = f"❌ Host lookup failed: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        # DNS Tools
        elif name == "shodan_dns_domain":
            domain = arguments.get("domain")
            page = arguments.get("page", 1)
            
            if not domain:
                return [types.TextContent(type="text", text="❌ Domain is required!")]
            
            logger.info(f"Looking up DNS for domain: {domain}")
            result = await shodan_client.dns_domain(domain, page)
            
            if result.get("success"):
                data = result.get("data", {})
                subdomains = data.get("subdomains", [])
                dns_records = data.get("data", [])
                
                response_text = f"""🌐 **DNS Information for {domain}**

**Subdomains Found:** {len(subdomains)}
**DNS Records:** {len(dns_records)}

**Subdomains:**
"""
                for subdomain in subdomains[:20]:
                    response_text += f"  - {subdomain}.{domain}\n"
                
                if dns_records:
                    response_text += "\n**DNS Records:**\n"
                    for record in dns_records[:10]:
                        response_text += f"  - {record.get('subdomain', '')}.{domain} → {record.get('value', 'N/A')} ({record.get('type', 'A')})\n"
            else:
                response_text = f"❌ DNS lookup failed: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "shodan_dns_resolve":
            hostnames = arguments.get("hostnames", [])
            
            if not hostnames:
                return [types.TextContent(type="text", text="❌ Hostnames are required!")]
            
            logger.info(f"Resolving hostnames: {hostnames}")
            result = await shodan_client.dns_resolve(hostnames)
            
            if result.get("success"):
                data = result.get("data", {})
                response_text = "🌐 **DNS Resolution Results**\n\n"
                
                for hostname, ip in data.items():
                    if ip:
                        response_text += f"✅ {hostname} → {ip}\n"
                    else:
                        response_text += f"❌ {hostname} → Could not resolve\n"
            else:
                response_text = f"❌ DNS resolution failed: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "shodan_dns_reverse":
            ips = arguments.get("ips", [])
            
            if not ips:
                return [types.TextContent(type="text", text="❌ IPs are required!")]
            
            logger.info(f"Reverse DNS lookup for: {ips}")
            result = await shodan_client.dns_reverse(ips)
            
            if result.get("success"):
                data = result.get("data", {})
                response_text = "🌐 **Reverse DNS Results**\n\n"
                
                for ip, hostnames in data.items():
                    if hostnames:
                        response_text += f"✅ {ip} → {', '.join(hostnames)}\n"
                    else:
                        response_text += f"❌ {ip} → No hostnames found\n"
            else:
                response_text = f"❌ Reverse DNS failed: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        # Scanning Tools
        elif name == "shodan_scan":
            ips = arguments.get("ips", [])
            force = arguments.get("force", False)
            
            if not ips:
                return [types.TextContent(type="text", text="❌ IPs are required!")]
            
            if len(ips) > 100:
                return [types.TextContent(type="text", text="❌ Maximum 100 IPs per scan!")]
            
            logger.info(f"Requesting scan for {len(ips)} IPs")
            result = await shodan_client.scan(ips, force)
            
            if result.get("success"):
                data = result.get("data", {})
                response_text = f"""⚡ **Scan Request Submitted**

**Scan ID:** {data.get('id')}
**Credits Used:** {data.get('credits', len(ips))}
**Status:** {data.get('status', 'SUBMITTED')}
**IPs Queued:** {len(ips)}

Use scan_status with the ID to check progress."""
            else:
                response_text = f"❌ Scan request failed: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "shodan_scan_status":
            scan_id = arguments.get("scan_id")
            
            if not scan_id:
                return [types.TextContent(type="text", text="❌ Scan ID is required!")]
            
            logger.info(f"Checking scan status: {scan_id}")
            result = await shodan_client.scan_status(scan_id)
            
            if result.get("success"):
                data = result.get("data", {})
                response_text = f"""📊 **Scan Status**

**Scan ID:** {scan_id}
**Status:** {data.get('status', 'UNKNOWN')}
**Created:** {data.get('created', 'N/A')}
**Size:** {data.get('size', 0)} IPs
**Completed:** {data.get('count', 0)} IPs"""
            else:
                response_text = f"❌ Status check failed: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        # Alert Management
        elif name == "shodan_alerts":
            logger.info("Getting all alerts")
            result = await shodan_client.alerts()
            
            if result.get("success"):
                alerts = result.get("data", [])
                response_text = f"🚨 **Network Alerts ({len(alerts)} total)**\n\n"
                
                for alert in alerts:
                    response_text += f"""**{alert.get('name')}**
  ID: {alert.get('id')}
  Created: {alert.get('created')}
  IP Ranges: {', '.join(alert.get('filters', {}).get('ip', []))}
  
"""
            else:
                response_text = f"❌ Failed to get alerts: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "shodan_alert_create":
            name_arg = arguments.get("name")
            ip_ranges = arguments.get("ip_ranges", [])
            
            if not name_arg or not ip_ranges:
                return [types.TextContent(type="text", text="❌ Name and IP ranges are required!")]
            
            logger.info(f"Creating alert: {name_arg}")
            filters = {"ip": ip_ranges}
            result = await shodan_client.alert_create(name_arg, filters)
            
            if result.get("success"):
                data = result.get("data", {})
                response_text = f"""✅ **Alert Created Successfully**

**Name:** {data.get('name')}
**ID:** {data.get('id')}
**IP Ranges:** {', '.join(ip_ranges)}"""
            else:
                response_text = f"❌ Alert creation failed: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        # Query Directory
        elif name == "shodan_queries":
            page = arguments.get("page", 1)
            
            logger.info("Getting saved queries")
            result = await shodan_client.queries(page)
            
            if result.get("success"):
                data = result.get("data", {})
                queries_list = data.get("matches", [])
                total = data.get("total", 0)
                
                response_text = f"""📚 **Saved Queries Directory**

**Total Queries:** {total}
**Page:** {page}

"""
                for query in queries_list[:10]:
                    response_text += f"""**{query.get('title')}**
  Query: `{query.get('query')}`
  Description: {query.get('description', 'N/A')[:100]}...
  Tags: {', '.join(query.get('tags', []))}
  Votes: {query.get('votes', 0)}
  
"""
            else:
                response_text = f"❌ Failed to get queries: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "shodan_query_tags":
            size = arguments.get("size", 20)
            
            logger.info("Getting popular query tags")
            result = await shodan_client.query_tags(size)
            
            if result.get("success"):
                data = result.get("data", {})
                tags = data.get("matches", [])
                
                response_text = "🏷️ **Popular Query Tags**\n\n"
                
                for tag in tags:
                    response_text += f"  - **{tag.get('value')}**: {tag.get('count'):,} queries\n"
            else:
                response_text = f"❌ Failed to get tags: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        # Utility Tools
        elif name == "shodan_my_ip":
            logger.info("Getting current IP")
            result = await shodan_client.my_ip()
            
            if result.get("success"):
                ip = result.get("data", {})
                response_text = f"🌐 **Your Current IP:** {ip}"
            else:
                response_text = f"❌ Failed to get IP: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "shodan_api_info":
            logger.info("Getting API info")
            result = await shodan_client.api_info()
            
            if result.get("success"):
                data = result.get("data", {})
                response_text = f"""📊 **Shodan API Information**

**Plan:** {data.get('plan', 'N/A')}
**Query Credits:** {data.get('query_credits', 0):,}
**Query Credits Used:** {data.get('query_credits_used', 0):,}
**Scan Credits:** {data.get('scan_credits', 0):,}
**Scan Credits Used:** {data.get('scan_credits_used', 0):,}
**Monitored IPs:** {data.get('monitored_ips', 0):,}
**Usage Limits:**
  - Queries/month: {data.get('usage_limits', {}).get('query_credits', 'N/A')}
  - Scans/month: {data.get('usage_limits', {}).get('scan_credits', 'N/A')}
  - Monitored IPs: {data.get('usage_limits', {}).get('monitored_ips', 'N/A')}"""
            else:
                response_text = f"❌ Failed to get API info: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "shodan_ports":
            logger.info("Getting crawled ports list")
            result = await shodan_client.ports()
            
            if result.get("success"):
                ports = result.get("data", [])
                response_text = f"🔌 **Ports Crawled by Shodan ({len(ports)} total)**\n\n"
                response_text += "Most common ports:\n"
                # Group into chunks for better display
                for i in range(0, min(50, len(ports)), 10):
                    response_text += f"  {', '.join(map(str, ports[i:i+10]))}\n"
            else:
                response_text = f"❌ Failed to get ports: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "shodan_protocols":
            logger.info("Getting crawled protocols")
            result = await shodan_client.protocols()
            
            if result.get("success"):
                protocols = result.get("data", {})
                response_text = "📡 **Protocols Crawled by Shodan**\n\n"
                
                for protocol, description in protocols.items():
                    response_text += f"  - **{protocol}**: {description}\n"
            else:
                response_text = f"❌ Failed to get protocols: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "shodan_search_filters":
            logger.info("Getting search filters")
            result = await shodan_client.search_filters()
            
            if result.get("success"):
                filters = result.get("data", [])
                response_text = "🔍 **Available Search Filters**\n\n"
                
                for filter_item in filters:
                    response_text += f"**{filter_item.get('name')}**\n"
                    response_text += f"  Description: {filter_item.get('description')}\n"
                    response_text += f"  Example: `{filter_item.get('example')}`\n\n"
            else:
                response_text = f"❌ Failed to get filters: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "shodan_search_facets":
            logger.info("Getting search facets")
            result = await shodan_client.search_facets()
            
            if result.get("success"):
                facets = result.get("data", [])
                response_text = "📊 **Available Search Facets**\n\n"
                response_text += "Use these for statistical breakdowns in searches:\n\n"
                
                for facet in facets:
                    response_text += f"**{facet.get('name')}**\n"
                    response_text += f"  Description: {facet.get('description')}\n\n"
            else:
                response_text = f"❌ Failed to get facets: {result.get('error')}"
            
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
    """Main entry point for the Shodan MCP server"""
    logger.info("Starting Shodan MCP Server...")
    
    # Check for API key
    if not get_api_key():
        logger.warning("⚠️  SHODAN_API_KEY not set in environment!")
        logger.warning("Set it before using the tools: export SHODAN_API_KEY='your_key_here'")
    
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="shodan-mcp",
                server_version="1.0.0",
                capabilities=app.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )
    
    # Cleanup
    if shodan_client:
        await shodan_client.close()

if __name__ == "__main__":
    asyncio.run(main())