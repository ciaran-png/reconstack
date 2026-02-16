#!/usr/bin/env python3
"""
Sherlockeye MCP Server - OSINT Tool for Username Investigation
Multi-platform username, email, phone, and digital footprint search via the Sherlockeye API.
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from enum import Enum

import httpx
from mcp.server import Server, NotificationOptions
from mcp.server.models import InitializationOptions
import mcp.server.stdio
import mcp.types as types

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("sherlockeye-mcp")

class SearchType(Enum):
    """Valid search types for Sherlockeye OSINT platform"""
    USERNAME = "username"
    EMAIL = "email"
    PHONE = "phone"
    ADDRESS = "address"
    NAME = "name"
    DOMAIN = "domain"
    IP = "ip"
    BITCOIN = "bitcoin"
    ETHEREUM = "ethereum"
    # Additional types that might be supported
    SOCIAL = "social"
    COMPANY = "company"
    WEBSITE = "website"

class SherlockeyeClient:
    """Client for interacting with the Sherlockeye API"""
    
    def __init__(self, api_key: str):
        """Initialize the Sherlockeye client with API key"""
        self.api_key = api_key
        self.base_url = "https://api.sherlockeye.io"
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        self.client = httpx.AsyncClient(timeout=30.0)
        
    async def submit_search(self, search_type: str, value: str) -> Dict[str, Any]:
        """Submit a new search request"""
        try:
            response = await self.client.post(
                f"{self.base_url}/search",
                headers=self.headers,
                json={
                    "type": search_type,
                    "value": value
                }
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error submitting search: {e}")
            if hasattr(e, 'response') and e.response is not None:
                error_data = e.response.json() if e.response.text else {}
                return {
                    "success": False,
                    "error": str(e),
                    "details": error_data
                }
            return {
                "success": False,
                "error": str(e)
            }
    
    async def get_results(self, search_id: str) -> Dict[str, Any]:
        """Get results for a search ID"""
        try:
            response = await self.client.get(
                f"{self.base_url}/get/{search_id}",
                headers={"Authorization": f"Bearer {self.api_key}"}
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error getting results: {e}")
            if hasattr(e, 'response') and e.response is not None:
                error_data = e.response.json() if e.response.text else {}
                return {
                    "success": False,
                    "error": str(e),
                    "details": error_data
                }
            return {
                "success": False,
                "error": str(e)
            }
    
    async def delete_search(self, search_id: str) -> Dict[str, Any]:
        """Delete a search by ID"""
        try:
            response = await self.client.delete(
                f"{self.base_url}/delete/{search_id}",
                headers={"Authorization": f"Bearer {self.api_key}"}
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error deleting search: {e}")
            if hasattr(e, 'response') and e.response is not None:
                error_data = e.response.json() if e.response.text else {}
                return {
                    "success": False,
                    "error": str(e),
                    "details": error_data
                }
            return {
                "success": False,
                "error": str(e)
            }
    
    async def check_balance(self) -> Dict[str, Any]:
        """Check API usage balance"""
        try:
            response = await self.client.get(
                f"{self.base_url}/balance",
                headers={"Authorization": f"Bearer {self.api_key}"}
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error checking balance: {e}")
            if hasattr(e, 'response') and e.response is not None:
                error_data = e.response.json() if e.response.text else {}
                return {
                    "success": False,
                    "error": str(e),
                    "details": error_data
                }
            return {
                "success": False,
                "error": str(e)
            }
    
    async def register_blockchain(self, search_id: str) -> Dict[str, Any]:
        """Register search in blockchain for immutable evidence"""
        try:
            response = await self.client.post(
                f"{self.base_url}/blockchain/{search_id}",
                headers={"Authorization": f"Bearer {self.api_key}"}
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error registering in blockchain: {e}")
            if hasattr(e, 'response') and e.response is not None:
                error_data = e.response.json() if e.response.text else {}
                return {
                    "success": False,
                    "error": str(e),
                    "details": error_data
                }
            return {
                "success": False,
                "error": str(e)
            }
    
    async def search_and_wait(self, search_type: str, value: str, max_wait: int = 30) -> Dict[str, Any]:
        """Submit search and wait for results - convenience method"""
        # Submit the search
        submit_result = await self.submit_search(search_type, value)
        if not submit_result.get("success"):
            return submit_result
        
        search_id = submit_result.get("searchId")
        if not search_id:
            return {
                "success": False,
                "error": "No searchId returned from submission"
            }
        
        # Poll for results
        start_time = datetime.now()
        while (datetime.now() - start_time).seconds < max_wait:
            result = await self.get_results(search_id)
            
            if result.get("success") and result.get("data", {}).get("isComplete"):
                return result
            
            # Wait a bit before checking again
            await asyncio.sleep(2)
        
        # If we're here, we timed out
        return {
            "success": False,
            "error": f"Search timed out after {max_wait} seconds",
            "searchId": search_id
        }
    
    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()

# Initialize the MCP server
app = Server("sherlockeye-mcp")
logger.info("Initializing Sherlockeye MCP Server - OSINT weapon ready!")

# Global client instance
sherlockeye_client: Optional[SherlockeyeClient] = None

def get_api_key() -> Optional[str]:
    """Get API key from environment variable"""
    api_key = os.getenv("SHERLOCKEYE_API_KEY")
    if not api_key:
        logger.warning("No SHERLOCKEYE_API_KEY found in environment!")
    return api_key

@app.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List all available Sherlockeye tools"""
    return [
        types.Tool(
            name="sherlockeye_search",
            description="Submit a search to Sherlockeye OSINT platform for username, email, phone, address, name, domain, IP, or crypto addresses. Returns a search ID for tracking.",
            inputSchema={
                "type": "object",
                "properties": {
                    "value": {
                        "type": "string",
                        "description": "The value to search for (username, email, phone number, address, name, domain, IP, bitcoin/ethereum address, etc.)"
                    },
                    "search_type": {
                        "type": "string",
                        "description": "Type of search to perform",
                        "enum": ["username", "email", "phone", "address", "name", "domain", "ip", "bitcoin", "ethereum", "social", "company", "website"],
                        "default": "username"
                    }
                },
                "required": ["value", "search_type"]
            }
        ),
        types.Tool(
            name="sherlockeye_get_results",
            description="Get search results by search ID. Check if search is complete and retrieve all found accounts.",
            inputSchema={
                "type": "object",
                "properties": {
                    "search_id": {
                        "type": "string",
                        "description": "The search ID returned from sherlockeye_search"
                    }
                },
                "required": ["search_id"]
            }
        ),
        types.Tool(
            name="sherlockeye_quick_search",
            description="Submit search and wait for results in one operation. Supports username, email, phone, address, name, domain, IP, crypto addresses, and more.",
            inputSchema={
                "type": "object",
                "properties": {
                    "value": {
                        "type": "string",
                        "description": "The value to search for (username, email, phone, address, etc.)"
                    },
                    "search_type": {
                        "type": "string",
                        "description": "Type of search to perform",
                        "enum": ["username", "email", "phone", "address", "name", "domain", "ip", "bitcoin", "ethereum", "social", "company", "website"],
                        "default": "username"
                    },
                    "max_wait": {
                        "type": "integer",
                        "description": "Maximum seconds to wait for results (default: 30)",
                        "default": 30
                    }
                },
                "required": ["value"]
            }
        ),
        types.Tool(
            name="sherlockeye_delete",
            description="Delete a search by ID to clean up after investigation.",
            inputSchema={
                "type": "object",
                "properties": {
                    "search_id": {
                        "type": "string",
                        "description": "The search ID to delete"
                    }
                },
                "required": ["search_id"]
            }
        ),
        types.Tool(
            name="sherlockeye_balance",
            description="Check your Sherlockeye API usage balance and limits.",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        types.Tool(
            name="sherlockeye_blockchain",
            description="Register search results in blockchain for immutable evidence trail.",
            inputSchema={
                "type": "object",
                "properties": {
                    "search_id": {
                        "type": "string",
                        "description": "The search ID to register in blockchain"
                    }
                },
                "required": ["search_id"]
            }
        )
    ]

@app.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """Execute Sherlockeye tools for our OSINT operations"""
    
    global sherlockeye_client
    
    # Initialize client if needed
    if sherlockeye_client is None:
        api_key = get_api_key()
        if not api_key:
            return [types.TextContent(
                type="text",
                text="❌ SHERLOCKEYE_API_KEY not found in environment! Set it to use this tool."
            )]
        sherlockeye_client = SherlockeyeClient(api_key)
    
    try:
        if name == "sherlockeye_search":
            value = arguments.get("value")
            search_type = arguments.get("search_type", "username")
            
            if not value:
                return [types.TextContent(
                    type="text",
                    text="❌ Search value is required!"
                )]
            
            logger.info(f"Initiating {search_type} search for: {value}")
            result = await sherlockeye_client.submit_search(search_type, value)
            
            if result.get("success"):
                response_text = f"""✅ **Search Submitted Successfully!**

**Search ID:** `{result.get('searchId')}`
**Type:** {result.get('type')}
**Target:** {result.get('value')}
**Timestamp:** {result.get('timestamp')}

Use the search ID to retrieve results with `sherlockeye_get_results`."""
            else:
                response_text = f"""❌ **Search Failed**

**Error:** {result.get('error', 'Unknown error')}
{json.dumps(result.get('details', {}), indent=2) if result.get('details') else ''}"""
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "sherlockeye_get_results":
            search_id = arguments.get("search_id")
            
            if not search_id:
                return [types.TextContent(
                    type="text",
                    text="❌ Search ID is required!"
                )]
            
            logger.info(f"Getting results for search: {search_id}")
            result = await sherlockeye_client.get_results(search_id)
            
            if result.get("success"):
                data = result.get("data", {})
                results = data.get("results", [])
                is_complete = data.get("isComplete", False)
                
                response_text = f"""{'✅' if is_complete else '⏳'} **Search Results**

**Search ID:** {data.get('searchId')}
**Query:** {data.get('query')}
**Status:** {'Complete' if is_complete else 'In Progress'}
**Results Found:** {len(results)}
**Timestamp:** {data.get('timestamp')}

**Found Accounts:**
"""
                
                if results:
                    for r in results:
                        tags = ', '.join(r.get('tag', []))
                        response_text += f"""
🔍 **{r.get('source')}**
   - Name: {r.get('name')}
   - URL: {r.get('url')}
   - Tags: {tags}
   - Date: {r.get('date')}
"""
                else:
                    response_text += "\nNo results found yet. The search may still be in progress."
            else:
                response_text = f"""❌ **Failed to Get Results**

**Error:** {result.get('error', 'Unknown error')}
{json.dumps(result.get('details', {}), indent=2) if result.get('details') else ''}"""
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "sherlockeye_quick_search":
            value = arguments.get("value")
            search_type = arguments.get("search_type", "username")
            max_wait = arguments.get("max_wait", 30)
            
            if not value:
                return [types.TextContent(
                    type="text",
                    text="❌ Search value is required!"
                )]
            
            logger.info(f"Quick {search_type} search for: {value} (max wait: {max_wait}s)")
            result = await sherlockeye_client.search_and_wait(search_type, value, max_wait)
            
            if result.get("success"):
                data = result.get("data", {})
                results = data.get("results", [])
                
                response_text = f"""✅ **Quick Search Complete!**

**Search Type:** {search_type}
**Target:** {value}
**Results Found:** {len(results)}

**Found Accounts:**
"""
                
                if results:
                    for r in results:
                        tags = ', '.join(r.get('tag', []))
                        response_text += f"""
🔍 **{r.get('source')}**
   - Name: {r.get('name')}
   - URL: {r.get('url')}
   - Tags: {tags}
"""
                else:
                    response_text += "\nNo accounts found for this username."
            else:
                response_text = f"""❌ **Quick Search Failed**

**Error:** {result.get('error', 'Unknown error')}
{f"**Search ID:** {result.get('searchId')}" if result.get('searchId') else ''}"""
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "sherlockeye_delete":
            search_id = arguments.get("search_id")
            
            if not search_id:
                return [types.TextContent(
                    type="text",
                    text="❌ Search ID is required for deletion!"
                )]
            
            logger.info(f"Deleting search: {search_id}")
            result = await sherlockeye_client.delete_search(search_id)
            
            if result.get("success"):
                response_text = f"""✅ **Search Deleted Successfully**

**Search ID:** {result.get('searchId')}
**Message:** {result.get('message')}"""
            else:
                response_text = f"""❌ **Failed to Delete Search**

**Error:** {result.get('error', 'Unknown error')}"""
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "sherlockeye_balance":
            logger.info("Checking API balance")
            result = await sherlockeye_client.check_balance()
            
            if result.get("success"):
                data = result.get("data", {})
                counts = data.get("searchCounts", {})
                limits = data.get("searchLimits", {})
                
                response_text = f"""✅ **API Balance Status**

**Standard Searches:**
- Used: {counts.get('standard', 0)} / {limits.get('standard', 0)}
- Remaining: {limits.get('standard', 0) - counts.get('standard', 0)}

**Premium Searches:**
- Used: {counts.get('premium', 0)} / {limits.get('premium', 0)}
- Remaining: {limits.get('premium', 0) - counts.get('premium', 0)}"""
            else:
                response_text = f"""❌ **Failed to Check Balance**

**Error:** {result.get('error', 'Unknown error')}"""
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "sherlockeye_blockchain":
            search_id = arguments.get("search_id")
            
            if not search_id:
                return [types.TextContent(
                    type="text",
                    text="❌ Search ID is required for blockchain registration!"
                )]
            
            logger.info(f"Registering search in blockchain: {search_id}")
            result = await sherlockeye_client.register_blockchain(search_id)
            
            if result.get("success"):
                data = result.get("data", {})
                response_text = f"""✅ **Blockchain Registration Successful!**

**Search ID:** {data.get('searchId')}
**Signature:** `{data.get('signature')}`
**Registration Date:** {data.get('registrationDate')}
**Explorer URL:** {data.get('explorer')}

This search is now immutably recorded in the blockchain for evidence purposes!"""
            else:
                response_text = f"""❌ **Failed to Register in Blockchain**

**Error:** {result.get('error', 'Unknown error')}"""
            
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
    """Main entry point for the OSINT MCP server"""
    logger.info("Starting Sherlockeye MCP Server...")
    
    # Check for API key
    if not get_api_key():
        logger.warning("⚠️  SHERLOCKEYE_API_KEY not set in environment!")
        logger.warning("Set it before using the tools: export SHERLOCKEYE_API_KEY='your_key_here'")
    
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="sherlockeye-mcp",
                server_version="1.0.0",
                capabilities=app.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )
    
    # Cleanup
    if sherlockeye_client:
        await sherlockeye_client.close()

if __name__ == "__main__":
    asyncio.run(main())