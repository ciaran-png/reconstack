#!/usr/bin/env python3
"""
Wayback Machine CDX API MCP Server - Historical Intelligence Tool
Track infrastructure changes, discover deleted content, and build timeline evidence!
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from urllib.parse import quote, urlencode
import re

import httpx
from mcp.server import Server, NotificationOptions
from mcp.server.models import InitializationOptions
import mcp.server.stdio
import mcp.types as types

# Configure logging for our historical reconnaissance
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("wayback-mcp")

class WaybackClient:
    """Client for interacting with the Wayback Machine CDX API"""
    
    def __init__(self):
        """Initialize the Wayback client"""
        self.base_url = "https://web.archive.org"
        self.cdx_url = f"{self.base_url}/cdx/search/cdx"
        self.client = httpx.AsyncClient(timeout=30.0)
    
    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()
    
    def parse_timestamp(self, timestamp: str) -> str:
        """Convert Wayback timestamp (YYYYMMDDhhmmss) to readable format"""
        try:
            if len(timestamp) >= 8:
                year = timestamp[0:4]
                month = timestamp[4:6]
                day = timestamp[6:8]
                if len(timestamp) >= 14:
                    hour = timestamp[8:10]
                    minute = timestamp[10:12]
                    second = timestamp[12:14]
                    return f"{year}-{month}-{day} {hour}:{minute}:{second}"
                return f"{year}-{month}-{day}"
        except:
            return timestamp
    
    def build_wayback_url(self, timestamp: str, original_url: str) -> str:
        """Build the Wayback Machine URL for a specific snapshot"""
        return f"https://web.archive.org/web/{timestamp}/{original_url}"
    
    async def search_url(self, url: str, 
                        from_date: Optional[str] = None,
                        to_date: Optional[str] = None,
                        limit: int = 100,
                        match_type: str = "exact",
                        collapse: Optional[str] = None,
                        filter_field: Optional[str] = None,
                        filter_value: Optional[str] = None) -> Dict[str, Any]:
        """
        Search for all archived versions of a URL
        
        Args:
            url: The URL to search for
            from_date: Start date (YYYYMMDD format)
            to_date: End date (YYYYMMDD format)
            limit: Maximum results to return
            match_type: "exact", "prefix", "host", or "domain"
            collapse: Field to collapse on (e.g., "timestamp:6" for monthly)
            filter_field: Field to filter (statuscode, mimetype, etc.)
            filter_value: Value to filter for
        """
        try:
            params = {
                "url": url,
                "output": "json",
                "limit": str(limit)
            }
            
            # Set match type
            if match_type == "prefix":
                params["matchType"] = "prefix"
            elif match_type == "host":
                params["matchType"] = "host"
            elif match_type == "domain":
                params["matchType"] = "domain"
            # exact is default, no param needed
            
            if from_date:
                params["from"] = from_date
            if to_date:
                params["to"] = to_date
            if collapse:
                params["collapse"] = collapse
            if filter_field and filter_value:
                params["filter"] = f"{filter_field}:{filter_value}"
            
            response = await self.client.get(self.cdx_url, params=params)
            response.raise_for_status()
            
            # Parse the JSON response
            data = response.json()
            
            # CDX returns array of arrays, first row is headers
            if data and len(data) > 0:
                headers = data[0]
                results = []
                
                for row in data[1:]:
                    # Create a dict from headers and values
                    item = {}
                    for i, header in enumerate(headers):
                        if i < len(row):
                            item[header] = row[i]
                    
                    # Add formatted timestamp and Wayback URL
                    if "timestamp" in item:
                        item["formatted_date"] = self.parse_timestamp(item["timestamp"])
                        item["wayback_url"] = self.build_wayback_url(item["timestamp"], item.get("original", url))
                    
                    results.append(item)
                
                return {
                    "success": True,
                    "data": {
                        "url": url,
                        "total_results": len(results),
                        "results": results
                    }
                }
            else:
                return {
                    "success": True,
                    "data": {
                        "url": url,
                        "total_results": 0,
                        "results": []
                    }
                }
                
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return {
                    "success": True,
                    "data": {
                        "url": url,
                        "total_results": 0,
                        "results": [],
                        "message": "No archived versions found"
                    }
                }
            logger.error(f"HTTP error searching for {url}: {e}")
            return {"success": False, "error": str(e)}
        except Exception as e:
            logger.error(f"Error searching for {url}: {e}")
            return {"success": False, "error": str(e)}
    
    async def get_domain_urls(self, domain: str, 
                             from_date: Optional[str] = None,
                             to_date: Optional[str] = None,
                             limit: int = 500) -> Dict[str, Any]:
        """Get all unique URLs archived from a domain"""
        try:
            params = {
                "url": f"{domain}/*",
                "matchType": "prefix",
                "output": "json",
                "collapse": "urlkey",  # Get unique URLs only
                "limit": str(limit),
                "fl": "original,timestamp,urlkey"  # Only get needed fields
            }
            
            if from_date:
                params["from"] = from_date
            if to_date:
                params["to"] = to_date
            
            response = await self.client.get(self.cdx_url, params=params)
            response.raise_for_status()
            
            data = response.json()
            
            if data and len(data) > 0:
                headers = data[0]
                urls = []
                
                for row in data[1:]:
                    item = {}
                    for i, header in enumerate(headers):
                        if i < len(row):
                            item[header] = row[i]
                    
                    if "timestamp" in item:
                        item["formatted_date"] = self.parse_timestamp(item["timestamp"])
                    
                    urls.append(item)
                
                return {
                    "success": True,
                    "data": {
                        "domain": domain,
                        "total_urls": len(urls),
                        "urls": urls
                    }
                }
            else:
                return {
                    "success": True,
                    "data": {
                        "domain": domain,
                        "total_urls": 0,
                        "urls": []
                    }
                }
                
        except Exception as e:
            logger.error(f"Error getting domain URLs for {domain}: {e}")
            return {"success": False, "error": str(e)}
    
    async def get_timeline(self, url: str, collapse: str = "timestamp:6") -> Dict[str, Any]:
        """
        Get a timeline of changes for a URL
        
        Args:
            url: The URL to analyze
            collapse: Grouping (timestamp:6 for monthly, timestamp:4 for yearly)
        """
        try:
            params = {
                "url": url,
                "output": "json",
                "collapse": collapse,
                "fl": "timestamp,statuscode,mimetype,digest"
            }
            
            response = await self.client.get(self.cdx_url, params=params)
            response.raise_for_status()
            
            data = response.json()
            
            if data and len(data) > 0:
                headers = data[0]
                timeline = []
                
                for row in data[1:]:
                    item = {}
                    for i, header in enumerate(headers):
                        if i < len(row):
                            item[header] = row[i]
                    
                    if "timestamp" in item:
                        item["formatted_date"] = self.parse_timestamp(item["timestamp"])
                        item["wayback_url"] = self.build_wayback_url(item["timestamp"], url)
                    
                    timeline.append(item)
                
                # Analyze changes
                changes = []
                prev_digest = None
                for item in timeline:
                    if prev_digest and item.get("digest") != prev_digest:
                        changes.append({
                            "date": item.get("formatted_date"),
                            "type": "content_changed",
                            "wayback_url": item.get("wayback_url")
                        })
                    prev_digest = item.get("digest")
                
                return {
                    "success": True,
                    "data": {
                        "url": url,
                        "total_snapshots": len(timeline),
                        "timeline": timeline,
                        "changes_detected": len(changes),
                        "changes": changes
                    }
                }
            else:
                return {
                    "success": True,
                    "data": {
                        "url": url,
                        "total_snapshots": 0,
                        "timeline": []
                    }
                }
                
        except Exception as e:
            logger.error(f"Error getting timeline for {url}: {e}")
            return {"success": False, "error": str(e)}
    
    async def check_availability(self, url: str, timestamp: Optional[str] = None) -> Dict[str, Any]:
        """
        Check if a URL is available in the Wayback Machine
        
        Args:
            url: The URL to check
            timestamp: Specific timestamp to check (optional)
        """
        try:
            if timestamp:
                # Check specific timestamp
                availability_url = f"{self.base_url}/wayback/available?url={quote(url)}&timestamp={timestamp}"
            else:
                # Check latest available
                availability_url = f"{self.base_url}/wayback/available?url={quote(url)}"
            
            response = await self.client.get(availability_url)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get("archived_snapshots", {}).get("closest"):
                snapshot = data["archived_snapshots"]["closest"]
                return {
                    "success": True,
                    "data": {
                        "url": url,
                        "available": snapshot.get("available", False),
                        "timestamp": snapshot.get("timestamp"),
                        "formatted_date": self.parse_timestamp(snapshot.get("timestamp", "")),
                        "wayback_url": snapshot.get("url"),
                        "status": snapshot.get("status")
                    }
                }
            else:
                return {
                    "success": True,
                    "data": {
                        "url": url,
                        "available": False,
                        "message": "No archived versions found"
                    }
                }
                
        except Exception as e:
            logger.error(f"Error checking availability for {url}: {e}")
            return {"success": False, "error": str(e)}
    
    async def compare_snapshots(self, url: str, 
                               timestamp1: str, 
                               timestamp2: str) -> Dict[str, Any]:
        """
        Compare two snapshots of a URL
        
        Args:
            url: The URL to compare
            timestamp1: First timestamp (YYYYMMDDHHMMSS)
            timestamp2: Second timestamp (YYYYMMDDHHMMSS)
        """
        try:
            # Get both snapshots
            params1 = {
                "url": url,
                "output": "json",
                "from": timestamp1,
                "to": timestamp1,
                "limit": "1"
            }
            
            params2 = {
                "url": url,
                "output": "json",
                "from": timestamp2,
                "to": timestamp2,
                "limit": "1"
            }
            
            response1 = await self.client.get(self.cdx_url, params=params1)
            response2 = await self.client.get(self.cdx_url, params=params2)
            
            data1 = response1.json() if response1.status_code == 200 else []
            data2 = response2.json() if response2.status_code == 200 else []
            
            snapshot1 = None
            snapshot2 = None
            
            if data1 and len(data1) > 1:
                headers = data1[0]
                row = data1[1]
                snapshot1 = {headers[i]: row[i] for i in range(min(len(headers), len(row)))}
                snapshot1["formatted_date"] = self.parse_timestamp(snapshot1.get("timestamp", ""))
                snapshot1["wayback_url"] = self.build_wayback_url(snapshot1.get("timestamp", ""), url)
            
            if data2 and len(data2) > 1:
                headers = data2[0]
                row = data2[1]
                snapshot2 = {headers[i]: row[i] for i in range(min(len(headers), len(row)))}
                snapshot2["formatted_date"] = self.parse_timestamp(snapshot2.get("timestamp", ""))
                snapshot2["wayback_url"] = self.build_wayback_url(snapshot2.get("timestamp", ""), url)
            
            # Compare the snapshots
            differences = []
            if snapshot1 and snapshot2:
                # Compare digest (content hash)
                if snapshot1.get("digest") != snapshot2.get("digest"):
                    differences.append("Content changed")
                
                # Compare status code
                if snapshot1.get("statuscode") != snapshot2.get("statuscode"):
                    differences.append(f"Status code changed: {snapshot1.get('statuscode')} → {snapshot2.get('statuscode')}")
                
                # Compare MIME type
                if snapshot1.get("mimetype") != snapshot2.get("mimetype"):
                    differences.append(f"MIME type changed: {snapshot1.get('mimetype')} → {snapshot2.get('mimetype')}")
            
            return {
                "success": True,
                "data": {
                    "url": url,
                    "snapshot1": snapshot1,
                    "snapshot2": snapshot2,
                    "differences": differences,
                    "content_changed": snapshot1.get("digest") != snapshot2.get("digest") if snapshot1 and snapshot2 else None
                }
            }
                
        except Exception as e:
            logger.error(f"Error comparing snapshots for {url}: {e}")
            return {"success": False, "error": str(e)}
    
    async def find_infrastructure_changes(self, domain: str, 
                                         from_date: Optional[str] = None,
                                         to_date: Optional[str] = None) -> Dict[str, Any]:
        """
        Find when a domain's infrastructure changed (useful for tracking hosting moves)
        Looks for changes in status codes and redirects
        """
        try:
            # Get all snapshots with status codes
            params = {
                "url": domain,
                "matchType": "host",
                "output": "json",
                "fl": "timestamp,original,statuscode,redirect",
                "limit": "1000"
            }
            
            if from_date:
                params["from"] = from_date
            if to_date:
                params["to"] = to_date
            
            response = await self.client.get(self.cdx_url, params=params)
            response.raise_for_status()
            
            data = response.json()
            
            if data and len(data) > 0:
                headers = data[0]
                snapshots = []
                
                for row in data[1:]:
                    item = {}
                    for i, header in enumerate(headers):
                        if i < len(row):
                            item[header] = row[i]
                    
                    if "timestamp" in item:
                        item["formatted_date"] = self.parse_timestamp(item["timestamp"])
                    
                    snapshots.append(item)
                
                # Analyze for infrastructure changes
                changes = []
                prev_redirect = None
                prev_status = None
                
                for snapshot in snapshots:
                    redirect = snapshot.get("redirect", "")
                    status = snapshot.get("statuscode", "")
                    
                    # Check for redirect changes (could indicate hosting move)
                    if prev_redirect is not None and redirect != prev_redirect:
                        change_type = "redirect_added" if redirect and not prev_redirect else "redirect_removed" if not redirect and prev_redirect else "redirect_changed"
                        changes.append({
                            "date": snapshot.get("formatted_date"),
                            "type": change_type,
                            "from_redirect": prev_redirect,
                            "to_redirect": redirect,
                            "url": snapshot.get("original"),
                            "wayback_url": self.build_wayback_url(snapshot.get("timestamp", ""), snapshot.get("original", domain))
                        })
                    
                    # Check for major status code changes
                    if prev_status and status != prev_status:
                        if (prev_status.startswith("2") and not status.startswith("2")) or \
                           (not prev_status.startswith("2") and status.startswith("2")):
                            changes.append({
                                "date": snapshot.get("formatted_date"),
                                "type": "status_changed",
                                "from_status": prev_status,
                                "to_status": status,
                                "url": snapshot.get("original"),
                                "wayback_url": self.build_wayback_url(snapshot.get("timestamp", ""), snapshot.get("original", domain))
                            })
                    
                    prev_redirect = redirect
                    prev_status = status
                
                return {
                    "success": True,
                    "data": {
                        "domain": domain,
                        "total_snapshots": len(snapshots),
                        "infrastructure_changes": len(changes),
                        "changes": changes,
                        "first_snapshot": snapshots[0] if snapshots else None,
                        "last_snapshot": snapshots[-1] if snapshots else None
                    }
                }
            else:
                return {
                    "success": True,
                    "data": {
                        "domain": domain,
                        "total_snapshots": 0,
                        "infrastructure_changes": 0,
                        "changes": []
                    }
                }
                
        except Exception as e:
            logger.error(f"Error finding infrastructure changes for {domain}: {e}")
            return {"success": False, "error": str(e)}

# Initialize the MCP server
app = Server("wayback-mcp")
logger.info("Initializing Wayback Machine MCP Server - Historical intelligence ready!")

# Global client instance
wayback_client: Optional[WaybackClient] = None

@app.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List available Wayback Machine tools - TRIMMED for efficiency"""
    return [
        types.Tool(
            name="wayback_search",
            description="Search for all archived versions of a URL. Find when content was captured.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL to search for (e.g., 'example.com' or 'https://example.com/page')"
                    },
                    "from_date": {
                        "type": "string",
                        "description": "Start date in YYYYMMDD format (e.g., '20200101')"
                    },
                    "to_date": {
                        "type": "string",
                        "description": "End date in YYYYMMDD format (e.g., '20231231')"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum results to return (default: 100)",
                        "default": 100
                    },
                    "match_type": {
                        "type": "string",
                        "enum": ["exact", "prefix", "host", "domain"],
                        "description": "Match type: exact URL, prefix, host, or entire domain",
                        "default": "exact"
                    }
                },
                "required": ["url"]
            }
        ),
        types.Tool(
            name="wayback_domain_urls",
            description="Get all unique URLs archived from a domain. Discover all pages that were captured.",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Domain to search (e.g., 'example.com')"
                    },
                    "from_date": {
                        "type": "string",
                        "description": "Start date in YYYYMMDD format"
                    },
                    "to_date": {
                        "type": "string",
                        "description": "End date in YYYYMMDD format"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum URLs to return (default: 500)",
                        "default": 500
                    }
                },
                "required": ["domain"]
            }
        ),
        # DISABLED: wayback_timeline, wayback_infrastructure_changes, 
        # wayback_check_availability, wayback_compare_snapshots
    ]

@app.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """Execute Wayback Machine tools"""
    
    global wayback_client
    
    # Initialize client if needed
    if wayback_client is None:
        wayback_client = WaybackClient()
    
    try:
        if name == "wayback_search":
            url = arguments.get("url")
            if not url:
                return [types.TextContent(type="text", text="❌ URL is required!")]
            
            from_date = arguments.get("from_date")
            to_date = arguments.get("to_date")
            limit = arguments.get("limit", 100)
            match_type = arguments.get("match_type", "exact")
            
            logger.info(f"Searching Wayback Machine for: {url}")
            result = await wayback_client.search_url(url, from_date, to_date, limit, match_type)
            
            if result.get("success"):
                data = result.get("data", {})
                results = data.get("results", [])
                
                response_text = f"""📚 **Wayback Machine Search Results**

**URL:** {data.get('url')}
**Total Snapshots:** {data.get('total_results', 0)}
**Date Range:** {from_date or 'earliest'} to {to_date or 'latest'}

**Archived Snapshots:**
"""
                
                # Group by year for better readability
                by_year = {}
                for r in results:
                    year = r.get("formatted_date", "Unknown")[:4]
                    if year not in by_year:
                        by_year[year] = []
                    by_year[year].append(r)
                
                for year in sorted(by_year.keys(), reverse=True)[:10]:  # Last 10 years
                    response_text += f"\n**{year}:** {len(by_year[year])} snapshots\n"
                    for snapshot in by_year[year][:3]:  # Show first 3 per year
                        response_text += f"  - {snapshot.get('formatted_date')}: "
                        response_text += f"[View]({snapshot.get('wayback_url')})\n"
                        if snapshot.get('statuscode'):
                            response_text += f"    Status: {snapshot.get('statuscode')}\n"
                
                if data.get("message"):
                    response_text += f"\n_{data['message']}_"
            else:
                response_text = f"❌ Search failed: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "wayback_timeline":
            url = arguments.get("url")
            if not url:
                return [types.TextContent(type="text", text="❌ URL is required!")]
            
            collapse = arguments.get("collapse", "timestamp:6")
            
            logger.info(f"Getting timeline for: {url}")
            result = await wayback_client.get_timeline(url, collapse)
            
            if result.get("success"):
                data = result.get("data", {})
                timeline = data.get("timeline", [])
                changes = data.get("changes", [])
                
                response_text = f"""📊 **Wayback Machine Timeline Analysis**

**URL:** {data.get('url')}
**Total Snapshots:** {data.get('total_snapshots', 0)}
**Changes Detected:** {data.get('changes_detected', 0)}

**Timeline:**
"""
                
                for item in timeline[:20]:  # Show first 20 periods
                    response_text += f"\n**{item.get('formatted_date')}**\n"
                    response_text += f"  Status: {item.get('statuscode', 'Unknown')}\n"
                    response_text += f"  [View Snapshot]({item.get('wayback_url')})\n"
                
                if changes:
                    response_text += "\n**🔄 Content Changes Detected:**\n"
                    for change in changes[:10]:
                        response_text += f"  - {change.get('date')}: {change.get('type')}\n"
                        response_text += f"    [View]({change.get('wayback_url')})\n"
            else:
                response_text = f"❌ Timeline analysis failed: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "wayback_domain_urls":
            domain = arguments.get("domain")
            if not domain:
                return [types.TextContent(type="text", text="❌ Domain is required!")]
            
            from_date = arguments.get("from_date")
            to_date = arguments.get("to_date")
            limit = arguments.get("limit", 500)
            
            logger.info(f"Getting URLs for domain: {domain}")
            result = await wayback_client.get_domain_urls(domain, from_date, to_date, limit)
            
            if result.get("success"):
                data = result.get("data", {})
                urls = data.get("urls", [])
                
                response_text = f"""🌐 **Domain Archive Analysis**

**Domain:** {data.get('domain')}
**Unique URLs Found:** {data.get('total_urls', 0)}

**Archived URLs:**
"""
                
                # Group URLs by path structure
                by_path = {}
                for url_item in urls:
                    original = url_item.get("original", "")
                    # Extract path
                    if "/" in original:
                        path = original.split("/", 3)[-1] if original.count("/") > 2 else "/"
                        path_root = path.split("/")[0] if "/" in path else path
                        if path_root not in by_path:
                            by_path[path_root] = []
                        by_path[path_root].append(url_item)
                
                for path_root in sorted(by_path.keys())[:20]:
                    response_text += f"\n**/{path_root}/** ({len(by_path[path_root])} URLs)\n"
                    for item in by_path[path_root][:3]:
                        response_text += f"  - {item.get('original', 'Unknown')}\n"
                        response_text += f"    Last seen: {item.get('formatted_date', 'Unknown')}\n"
            else:
                response_text = f"❌ Domain analysis failed: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "wayback_infrastructure_changes":
            domain = arguments.get("domain")
            if not domain:
                return [types.TextContent(type="text", text="❌ Domain is required!")]
            
            from_date = arguments.get("from_date")
            to_date = arguments.get("to_date")
            
            logger.info(f"Finding infrastructure changes for: {domain}")
            result = await wayback_client.find_infrastructure_changes(domain, from_date, to_date)
            
            if result.get("success"):
                data = result.get("data", {})
                changes = data.get("changes", [])
                
                response_text = f"""🔍 **Infrastructure Change Analysis**

**Domain:** {data.get('domain')}
**Total Snapshots Analyzed:** {data.get('total_snapshots', 0)}
**Infrastructure Changes Found:** {data.get('infrastructure_changes', 0)}

"""
                
                if data.get("first_snapshot"):
                    first = data["first_snapshot"]
                    response_text += f"**First Capture:** {first.get('formatted_date', 'Unknown')}\n"
                
                if data.get("last_snapshot"):
                    last = data["last_snapshot"]
                    response_text += f"**Last Capture:** {last.get('formatted_date', 'Unknown')}\n"
                
                if changes:
                    response_text += "\n**🚨 Infrastructure Changes Detected:**\n\n"
                    for change in changes:
                        response_text += f"**{change.get('date')}**\n"
                        response_text += f"  Type: {change.get('type')}\n"
                        
                        if change.get('type') == 'redirect_changed' or change.get('type') == 'redirect_added':
                            response_text += f"  From: {change.get('from_redirect', 'None')}\n"
                            response_text += f"  To: {change.get('to_redirect', 'None')}\n"
                            response_text += "  ⚠️ **Possible hosting/infrastructure change!**\n"
                        
                        if change.get('type') == 'status_changed':
                            response_text += f"  Status: {change.get('from_status')} → {change.get('to_status')}\n"
                        
                        response_text += f"  [View Snapshot]({change.get('wayback_url')})\n\n"
                else:
                    response_text += "\n✅ No major infrastructure changes detected in archived snapshots."
            else:
                response_text = f"❌ Infrastructure analysis failed: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "wayback_check_availability":
            url = arguments.get("url")
            if not url:
                return [types.TextContent(type="text", text="❌ URL is required!")]
            
            timestamp = arguments.get("timestamp")
            
            logger.info(f"Checking availability for: {url}")
            result = await wayback_client.check_availability(url, timestamp)
            
            if result.get("success"):
                data = result.get("data", {})
                
                if data.get("available"):
                    response_text = f"""✅ **URL Available in Wayback Machine**

**URL:** {data.get('url')}
**Available:** Yes
**Closest Snapshot:** {data.get('formatted_date')}
**Status:** {data.get('status')}

**View Snapshot:** {data.get('wayback_url')}
"""
                else:
                    response_text = f"""❌ **URL Not Available**

**URL:** {data.get('url')}
**Available:** No
**Message:** {data.get('message', 'No archived versions found')}
"""
            else:
                response_text = f"❌ Availability check failed: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "wayback_compare_snapshots":
            url = arguments.get("url")
            timestamp1 = arguments.get("timestamp1")
            timestamp2 = arguments.get("timestamp2")
            
            if not url or not timestamp1 or not timestamp2:
                return [types.TextContent(type="text", text="❌ URL and both timestamps are required!")]
            
            logger.info(f"Comparing snapshots for: {url}")
            result = await wayback_client.compare_snapshots(url, timestamp1, timestamp2)
            
            if result.get("success"):
                data = result.get("data", {})
                snapshot1 = data.get("snapshot1")
                snapshot2 = data.get("snapshot2")
                differences = data.get("differences", [])
                
                response_text = f"""🔄 **Snapshot Comparison**

**URL:** {data.get('url')}

**Snapshot 1:** {snapshot1.get('formatted_date') if snapshot1 else 'Not found'}
  Status: {snapshot1.get('statuscode', 'N/A') if snapshot1 else 'N/A'}
  [View]({snapshot1.get('wayback_url')}) if snapshot1 else '')

**Snapshot 2:** {snapshot2.get('formatted_date') if snapshot2 else 'Not found'}
  Status: {snapshot2.get('statuscode', 'N/A') if snapshot2 else 'N/A'}
  [View]({snapshot2.get('wayback_url') if snapshot2 else ''})

**Differences Found:** {len(differences)}
"""
                
                if differences:
                    response_text += "\n**Changes:**\n"
                    for diff in differences:
                        response_text += f"  - {diff}\n"
                
                if data.get("content_changed") is not None:
                    response_text += f"\n**Content Changed:** {'Yes' if data['content_changed'] else 'No'}"
            else:
                response_text = f"❌ Comparison failed: {result.get('error')}"
            
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
    """Main entry point for the Wayback Machine MCP server"""
    global wayback_client
    logger.info("Starting Wayback Machine MCP Server...")
    logger.info("No API key required - using public CDX API")
    
    try:
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            await app.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="wayback-mcp",
                    server_version="1.0.0",
                    capabilities=app.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )
    finally:
        # Cleanup
        if wayback_client:
            await wayback_client.close()
            wayback_client = None

if __name__ == "__main__":
    asyncio.run(main())