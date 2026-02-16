#!/usr/bin/env python3
"""
OpenCorporates MCP Server - Corporate Registry Search
Search global corporate registries. Free tier: 500 requests/month.
"""

import asyncio
import json
import logging
import os
from typing import Any, Dict, List, Optional
from urllib.parse import quote

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
logger = logging.getLogger("opencorporates-mcp")


class OpenCorporatesClient:
    """Client for OpenCorporates API"""
    
    def __init__(self, api_token: Optional[str] = None):
        self.api_token = api_token or os.environ.get("OPENCORPORATES_API_KEY")
        self.base_url = "https://api.opencorporates.com/v0.4"
        self.client = httpx.AsyncClient(timeout=30.0)
    
    async def close(self):
        await self.client.aclose()
    
    def _add_auth(self, params: Dict) -> Dict:
        """Add API token if available"""
        if self.api_token:
            params["api_token"] = self.api_token
        return params
    
    async def search_companies(self, query: str, jurisdiction_code: Optional[str] = None,
                              per_page: int = 30, page: int = 1) -> Dict[str, Any]:
        """Search for companies by name"""
        try:
            params = self._add_auth({
                "q": query,
                "per_page": per_page,
                "page": page
            })
            
            if jurisdiction_code:
                params["jurisdiction_code"] = jurisdiction_code
            
            response = await self.client.get(
                f"{self.base_url}/companies/search",
                params=params
            )
            
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            elif response.status_code == 401:
                return {"success": False, "error": "API authentication failed or rate limit exceeded"}
            else:
                return {"success": False, "error": f"HTTP {response.status_code}: {response.text[:200]}"}
                
        except Exception as e:
            logger.error(f"Error searching companies: {e}")
            return {"success": False, "error": str(e)}
    
    async def get_company(self, jurisdiction_code: str, company_number: str) -> Dict[str, Any]:
        """Get detailed company information"""
        try:
            params = self._add_auth({})
            
            response = await self.client.get(
                f"{self.base_url}/companies/{jurisdiction_code}/{company_number}",
                params=params
            )
            
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            elif response.status_code == 404:
                return {"success": False, "error": "Company not found"}
            else:
                return {"success": False, "error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def search_officers(self, query: str, jurisdiction_code: Optional[str] = None,
                             per_page: int = 30) -> Dict[str, Any]:
        """Search for company officers/directors"""
        try:
            params = self._add_auth({
                "q": query,
                "per_page": per_page
            })
            
            if jurisdiction_code:
                params["jurisdiction_code"] = jurisdiction_code
            
            response = await self.client.get(
                f"{self.base_url}/officers/search",
                params=params
            )
            
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            else:
                return {"success": False, "error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def get_company_officers(self, jurisdiction_code: str, company_number: str) -> Dict[str, Any]:
        """Get officers for a specific company"""
        try:
            params = self._add_auth({})
            
            response = await self.client.get(
                f"{self.base_url}/companies/{jurisdiction_code}/{company_number}/officers",
                params=params
            )
            
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            else:
                return {"success": False, "error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def get_company_filings(self, jurisdiction_code: str, company_number: str) -> Dict[str, Any]:
        """Get filings for a specific company"""
        try:
            params = self._add_auth({})
            
            response = await self.client.get(
                f"{self.base_url}/companies/{jurisdiction_code}/{company_number}/filings",
                params=params
            )
            
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            else:
                return {"success": False, "error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}


def format_company(company: Dict) -> str:
    """Format company data for display"""
    c = company.get("company", company)
    
    name = c.get("name", "Unknown")
    number = c.get("company_number", "N/A")
    jurisdiction = c.get("jurisdiction_code", "N/A")
    status = c.get("current_status", "Unknown")
    company_type = c.get("company_type", "Unknown")
    incorporation_date = c.get("incorporation_date", "Unknown")
    dissolution_date = c.get("dissolution_date")
    registered_address = c.get("registered_address_in_full", "N/A")
    
    result = f"""
**{name}**
  Number: `{number}` | Jurisdiction: `{jurisdiction.upper()}`
  Status: {status}
  Type: {company_type}
  Incorporated: {incorporation_date}"""
    
    if dissolution_date:
        result += f"\n  Dissolved: {dissolution_date}"
    
    if registered_address and registered_address != "N/A":
        result += f"\n  Address: {registered_address}"
    
    # Add link
    opencorp_url = c.get("opencorporates_url", "")
    if opencorp_url:
        result += f"\n  [View on OpenCorporates]({opencorp_url})"
    
    return result


def format_officer(officer: Dict) -> str:
    """Format officer data for display"""
    o = officer.get("officer", officer)
    
    name = o.get("name", "Unknown")
    position = o.get("position", "Unknown")
    start_date = o.get("start_date", "Unknown")
    end_date = o.get("end_date")
    
    # Company info
    company = o.get("company", {})
    company_name = company.get("name", "Unknown Company")
    company_number = company.get("company_number", "")
    jurisdiction = company.get("jurisdiction_code", "")
    
    result = f"""
**{name}**
  Position: {position}
  Company: {company_name}"""
    
    if company_number:
        result += f" ({jurisdiction.upper()}/{company_number})"
    
    result += f"\n  Start: {start_date}"
    if end_date:
        result += f" | End: {end_date}"
    
    return result


# Initialize MCP server
app = Server("opencorporates-mcp")
logger.info("Initializing OpenCorporates MCP Server")

# Global client
oc_client: Optional[OpenCorporatesClient] = None


def get_client() -> OpenCorporatesClient:
    global oc_client
    if oc_client is None:
        oc_client = OpenCorporatesClient()
    return oc_client


@app.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List available corporate intelligence tools"""
    return [
        types.Tool(
            name="opencorp_search_company",
            description="Search global corporate registries for companies by name. Returns company info, status, addresses, and registration details.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Company name to search for"
                    },
                    "jurisdiction": {
                        "type": "string",
                        "description": "Optional: Jurisdiction code (e.g., 'us_de' for Delaware, 'gb' for UK, 'il' for Israel)"
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum results (default: 20)",
                        "default": 20
                    }
                },
                "required": ["query"]
            }
        ),
        types.Tool(
            name="opencorp_get_company",
            description="Get detailed information about a specific company using jurisdiction code and company number.",
            inputSchema={
                "type": "object",
                "properties": {
                    "jurisdiction": {
                        "type": "string",
                        "description": "Jurisdiction code (e.g., 'us_de', 'gb', 'il')"
                    },
                    "company_number": {
                        "type": "string",
                        "description": "Company registration number"
                    }
                },
                "required": ["jurisdiction", "company_number"]
            }
        ),
        types.Tool(
            name="opencorp_search_officers",
            description="Search for company officers/directors by name. Find all companies where a person serves as director.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Officer/director name to search"
                    },
                    "jurisdiction": {
                        "type": "string",
                        "description": "Optional: Limit to specific jurisdiction"
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum results (default: 30)",
                        "default": 30
                    }
                },
                "required": ["name"]
            }
        ),
        types.Tool(
            name="opencorp_company_officers",
            description="Get all officers/directors for a specific company.",
            inputSchema={
                "type": "object",
                "properties": {
                    "jurisdiction": {
                        "type": "string",
                        "description": "Jurisdiction code"
                    },
                    "company_number": {
                        "type": "string",
                        "description": "Company registration number"
                    }
                },
                "required": ["jurisdiction", "company_number"]
            }
        ),
        types.Tool(
            name="opencorp_company_filings",
            description="Get filing history for a specific company.",
            inputSchema={
                "type": "object",
                "properties": {
                    "jurisdiction": {
                        "type": "string",
                        "description": "Jurisdiction code"
                    },
                    "company_number": {
                        "type": "string",
                        "description": "Company registration number"
                    }
                },
                "required": ["jurisdiction", "company_number"]
            }
        ),
        types.Tool(
            name="opencorp_company_network",
            description="Find companies connected through shared officers/directors. OSINT gold for mapping corporate networks.",
            inputSchema={
                "type": "object",
                "properties": {
                    "jurisdiction": {
                        "type": "string",
                        "description": "Jurisdiction code of the starting company"
                    },
                    "company_number": {
                        "type": "string",
                        "description": "Company registration number"
                    }
                },
                "required": ["jurisdiction", "company_number"]
            }
        )
    ]


@app.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """Execute OpenCorporates tools"""
    
    client = get_client()
    
    try:
        if name == "opencorp_search_company":
            query = arguments.get("query", "").strip()
            jurisdiction = arguments.get("jurisdiction", "").strip().lower()
            max_results = arguments.get("max_results", 20)
            
            if not query:
                return [types.TextContent(type="text", text="❌ Company name query is required!")]
            
            logger.info(f"Searching companies: {query}")
            
            result = await client.search_companies(query, jurisdiction if jurisdiction else None, per_page=max_results)
            
            if not result.get("success"):
                return [types.TextContent(type="text", text=f"❌ Search failed: {result.get('error')}")]
            
            data = result.get("data", {}).get("results", {})
            companies = data.get("companies", [])
            total = data.get("total_count", 0)
            
            response_text = f"""🏢 **OpenCorporates Company Search**

**Query:** `{query}`"""
            
            if jurisdiction:
                response_text += f"\n**Jurisdiction:** `{jurisdiction.upper()}`"
            
            response_text += f"""
**Total Matches:** {total}
**Results Shown:** {len(companies)}

**Companies Found:**
"""
            
            if companies:
                for company_data in companies[:20]:
                    response_text += format_company(company_data)
                    response_text += "\n"
            else:
                response_text += "\n**No companies found matching this query.**"
            
            response_text += "\n\n💡 *Free tier: 500 requests/month. Use specific jurisdiction codes to narrow results.*"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "opencorp_get_company":
            jurisdiction = arguments.get("jurisdiction", "").strip().lower()
            company_number = arguments.get("company_number", "").strip()
            
            if not jurisdiction or not company_number:
                return [types.TextContent(type="text", text="❌ Both jurisdiction and company_number are required!")]
            
            logger.info(f"Getting company: {jurisdiction}/{company_number}")
            
            result = await client.get_company(jurisdiction, company_number)
            
            if not result.get("success"):
                return [types.TextContent(type="text", text=f"❌ Lookup failed: {result.get('error')}")]
            
            company = result.get("data", {}).get("results", {}).get("company", {})
            
            response_text = f"""🏢 **Company Details**

**{company.get('name', 'Unknown')}**

**Registration:**
  Number: `{company.get('company_number', 'N/A')}`
  Jurisdiction: `{company.get('jurisdiction_code', 'N/A').upper()}`
  Type: {company.get('company_type', 'Unknown')}
  Status: {company.get('current_status', 'Unknown')}

**Dates:**
  Incorporated: {company.get('incorporation_date', 'Unknown')}"""
            
            if company.get('dissolution_date'):
                response_text += f"\n  Dissolved: {company.get('dissolution_date')}"
            
            response_text += f"""

**Registered Address:**
  {company.get('registered_address_in_full', 'Not available')}

"""
            
            # Additional data if available
            if company.get('agent_name'):
                response_text += f"**Registered Agent:** {company.get('agent_name')}\n"
            
            if company.get('agent_address'):
                response_text += f"  Address: {company.get('agent_address')}\n"
            
            if company.get('previous_names'):
                response_text += "\n**Previous Names:**\n"
                for prev in company.get('previous_names', [])[:5]:
                    response_text += f"  - {prev.get('company_name')} (until {prev.get('end_date', 'N/A')})\n"
            
            if company.get('opencorporates_url'):
                response_text += f"\n[View Full Profile]({company.get('opencorporates_url')})"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "opencorp_search_officers":
            name_query = arguments.get("name", "").strip()
            jurisdiction = arguments.get("jurisdiction", "").strip().lower()
            max_results = arguments.get("max_results", 30)
            
            if not name_query:
                return [types.TextContent(type="text", text="❌ Officer name is required!")]
            
            logger.info(f"Searching officers: {name_query}")
            
            result = await client.search_officers(name_query, jurisdiction if jurisdiction else None, per_page=max_results)
            
            if not result.get("success"):
                return [types.TextContent(type="text", text=f"❌ Search failed: {result.get('error')}")]
            
            data = result.get("data", {}).get("results", {})
            officers = data.get("officers", [])
            total = data.get("total_count", 0)
            
            response_text = f"""👤 **OpenCorporates Officer Search**

**Query:** `{name_query}`
**Total Matches:** {total}
**Results Shown:** {len(officers)}

**Officers Found:**
"""
            
            if officers:
                for officer_data in officers[:25]:
                    response_text += format_officer(officer_data)
                    response_text += "\n"
            else:
                response_text += "\n**No officers found matching this name.**"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "opencorp_company_officers":
            jurisdiction = arguments.get("jurisdiction", "").strip().lower()
            company_number = arguments.get("company_number", "").strip()
            
            if not jurisdiction or not company_number:
                return [types.TextContent(type="text", text="❌ Both jurisdiction and company_number are required!")]
            
            logger.info(f"Getting officers for: {jurisdiction}/{company_number}")
            
            result = await client.get_company_officers(jurisdiction, company_number)
            
            if not result.get("success"):
                return [types.TextContent(type="text", text=f"❌ Lookup failed: {result.get('error')}")]
            
            data = result.get("data", {}).get("results", {})
            officers = data.get("officers", [])
            
            response_text = f"""👥 **Company Officers**

**Company:** {jurisdiction.upper()}/{company_number}
**Total Officers:** {len(officers)}

**Current & Past Officers:**
"""
            
            if officers:
                # Separate current and past
                current = []
                past = []
                
                for o in officers:
                    officer = o.get("officer", o)
                    if officer.get("end_date"):
                        past.append(officer)
                    else:
                        current.append(officer)
                
                if current:
                    response_text += "\n**Current:**\n"
                    for o in current:
                        response_text += f"  - **{o.get('name')}** - {o.get('position', 'Unknown')} (since {o.get('start_date', 'Unknown')})\n"
                
                if past:
                    response_text += "\n**Former:**\n"
                    for o in past[:10]:
                        response_text += f"  - {o.get('name')} - {o.get('position', 'Unknown')} ({o.get('start_date', '?')} to {o.get('end_date', '?')})\n"
            else:
                response_text += "\n**No officers on record.**"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "opencorp_company_filings":
            jurisdiction = arguments.get("jurisdiction", "").strip().lower()
            company_number = arguments.get("company_number", "").strip()
            
            if not jurisdiction or not company_number:
                return [types.TextContent(type="text", text="❌ Both jurisdiction and company_number are required!")]
            
            logger.info(f"Getting filings for: {jurisdiction}/{company_number}")
            
            result = await client.get_company_filings(jurisdiction, company_number)
            
            if not result.get("success"):
                return [types.TextContent(type="text", text=f"❌ Lookup failed: {result.get('error')}")]
            
            data = result.get("data", {}).get("results", {})
            filings = data.get("filings", [])
            
            response_text = f"""📄 **Company Filings**

**Company:** {jurisdiction.upper()}/{company_number}
**Total Filings:** {len(filings)}

**Recent Filings:**
"""
            
            if filings:
                for f in filings[:20]:
                    filing = f.get("filing", f)
                    response_text += f"""
  **{filing.get('title', 'Unknown Filing')}**
    Date: {filing.get('date', 'Unknown')}
    Type: {filing.get('filing_type', 'N/A')}
"""
                    if filing.get('opencorporates_url'):
                        response_text += f"    [View]({filing.get('opencorporates_url')})\n"
            else:
                response_text += "\n**No filings on record.**"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "opencorp_company_network":
            jurisdiction = arguments.get("jurisdiction", "").strip().lower()
            company_number = arguments.get("company_number", "").strip()
            
            if not jurisdiction or not company_number:
                return [types.TextContent(type="text", text="❌ Both jurisdiction and company_number are required!")]
            
            logger.info(f"Mapping network for: {jurisdiction}/{company_number}")
            
            # First get company details
            company_result = await client.get_company(jurisdiction, company_number)
            company_name = "Unknown Company"
            if company_result.get("success"):
                company_name = company_result.get("data", {}).get("results", {}).get("company", {}).get("name", "Unknown")
            
            # Get officers
            officers_result = await client.get_company_officers(jurisdiction, company_number)
            
            if not officers_result.get("success"):
                return [types.TextContent(type="text", text=f"❌ Failed to get officers: {officers_result.get('error')}")]
            
            officers = officers_result.get("data", {}).get("results", {}).get("officers", [])
            
            response_text = f"""🕸️ **Corporate Network Analysis**

**Starting Company:** {company_name}
**ID:** {jurisdiction.upper()}/{company_number}
**Officers Found:** {len(officers)}

"""
            
            # For each officer, find their other companies
            connections = {}
            
            for o in officers[:5]:  # Limit to avoid rate limits
                officer = o.get("officer", o)
                officer_name = officer.get("name", "")
                
                if not officer_name:
                    continue
                
                # Search for this officer's other positions
                await asyncio.sleep(1)  # Rate limit protection
                search_result = await client.search_officers(officer_name, per_page=20)
                
                if search_result.get("success"):
                    other_officers = search_result.get("data", {}).get("results", {}).get("officers", [])
                    
                    other_companies = []
                    for other in other_officers:
                        other_o = other.get("officer", other)
                        other_company = other_o.get("company", {})
                        other_company_name = other_company.get("name", "")
                        
                        # Skip the original company
                        if other_company_name and other_company_name.lower() != company_name.lower():
                            other_companies.append({
                                "name": other_company_name,
                                "number": other_company.get("company_number", ""),
                                "jurisdiction": other_company.get("jurisdiction_code", ""),
                                "position": other_o.get("position", "Unknown")
                            })
                    
                    if other_companies:
                        connections[officer_name] = other_companies
            
            if connections:
                response_text += "**Connected Companies via Shared Officers:**\n"
                
                for officer_name, companies in connections.items():
                    response_text += f"\n**{officer_name}** also serves at:\n"
                    for comp in companies[:5]:
                        response_text += f"  - {comp['name']}"
                        if comp['jurisdiction'] and comp['number']:
                            response_text += f" ({comp['jurisdiction'].upper()}/{comp['number']})"
                        response_text += f" as {comp['position']}\n"
                
                # Count unique connected companies
                all_connected = set()
                for comps in connections.values():
                    for c in comps:
                        all_connected.add(c['name'])
                
                response_text += f"\n**Summary:** {len(connections)} officers connect to {len(all_connected)} other companies."
            else:
                response_text += "**No network connections found through officers.**"
            
            return [types.TextContent(type="text", text=response_text)]
        
        else:
            return [types.TextContent(type="text", text=f"❌ Unknown tool: {name}")]
    
    except Exception as e:
        logger.error(f"Error executing tool {name}: {e}", exc_info=True)
        return [types.TextContent(type="text", text=f"❌ Error: {str(e)}")]


async def main():
    """Main entry point"""
    global oc_client
    
    logger.info("Starting OpenCorporates MCP Server...")
    logger.info("Free tier: 500 requests/month")
    
    if os.environ.get("OPENCORPORATES_API_KEY"):
        logger.info("API key found - authenticated access enabled")
    else:
        logger.info("No API key - using free tier")
    
    try:
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            await app.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="opencorporates-mcp",
                    server_version="1.0.0",
                    capabilities=app.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )
    finally:
        if oc_client:
            await oc_client.close()


if __name__ == "__main__":
    asyncio.run(main())
