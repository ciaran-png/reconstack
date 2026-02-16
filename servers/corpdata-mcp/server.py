#!/usr/bin/env python3
"""
Corporate Data MCP Server - FREE Corporate Registry Search
Aggregates multiple FREE corporate data sources:
- SEC EDGAR (US public companies)
- ProPublica Nonprofit Explorer (US nonprofits with 990s)
- Companies House (UK companies - has free API tier)

No API keys required!
"""

import asyncio
import json
import logging
import os
import re
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urljoin

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
logger = logging.getLogger("corpdata-mcp")


class CorporateDataClient:
    """Aggregated client for multiple FREE corporate data APIs"""
    
    def __init__(self):
        self.client = httpx.AsyncClient(
            timeout=30.0,
            headers={"User-Agent": "OSINT-Dashboard/1.0 (corpdata-mcp)"}
        )
        
        # SEC EDGAR base URLs
        self.sec_base = "https://data.sec.gov"
        self.sec_search = "https://efts.sec.gov/LATEST/search-index"
        
        # ProPublica Nonprofit Explorer
        self.propublica_base = "https://projects.propublica.org/nonprofits/api/v2"
        
        # Companies House UK (free tier: 600 requests/5min)
        self.uk_base = "https://api.company-information.service.gov.uk"
        self.uk_api_key = os.environ.get("COMPANIES_HOUSE_API_KEY")  # Optional
    
    async def close(self):
        await self.client.aclose()
    
    # ==================== SEC EDGAR (US Public Companies) ====================
    
    async def sec_search_companies(self, query: str) -> Dict[str, Any]:
        """Search SEC EDGAR for companies by name"""
        try:
            # Use SEC's full-text search API
            url = f"https://efts.sec.gov/LATEST/search-index?q={quote(query)}&dateRange=custom&startdt=2020-01-01&enddt=2030-01-01&forms=10-K,10-Q,8-K"
            
            response = await self.client.get(url)
            
            if response.status_code == 200:
                data = response.json()
                return {"success": True, "data": data}
            else:
                # Fallback: try to search by company name via full-text
                return {"success": False, "error": f"SEC search returned {response.status_code}"}
                
        except Exception as e:
            logger.error(f"SEC search error: {e}")
            return {"success": False, "error": str(e)}
    
    async def sec_get_company(self, cik: str) -> Dict[str, Any]:
        """Get company details from SEC by CIK number"""
        try:
            # Normalize CIK to 10 digits
            cik_padded = cik.zfill(10)
            
            url = f"{self.sec_base}/submissions/CIK{cik_padded}.json"
            
            response = await self.client.get(url)
            
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            elif response.status_code == 404:
                return {"success": False, "error": "CIK not found"}
            else:
                return {"success": False, "error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def sec_get_filings(self, cik: str, form_type: Optional[str] = None) -> Dict[str, Any]:
        """Get recent filings for a company"""
        result = await self.sec_get_company(cik)
        
        if not result.get("success"):
            return result
        
        data = result.get("data", {})
        filings_data = data.get("filings", {}).get("recent", {})
        
        filings = []
        forms = filings_data.get("form", [])
        dates = filings_data.get("filingDate", [])
        accessions = filings_data.get("accessionNumber", [])
        descriptions = filings_data.get("primaryDocDescription", [])
        
        for i in range(min(50, len(forms))):
            filing = {
                "form": forms[i] if i < len(forms) else "",
                "date": dates[i] if i < len(dates) else "",
                "accession": accessions[i] if i < len(accessions) else "",
                "description": descriptions[i] if i < len(descriptions) else ""
            }
            
            if form_type and filing["form"] != form_type:
                continue
            
            filings.append(filing)
        
        return {"success": True, "data": {"company": data.get("name"), "cik": cik, "filings": filings[:20]}}
    
    # ==================== ProPublica (US Nonprofits) ====================
    
    async def propublica_search(self, query: str, state: Optional[str] = None) -> Dict[str, Any]:
        """Search ProPublica Nonprofit Explorer"""
        try:
            url = f"{self.propublica_base}/search.json?q={quote(query)}"
            if state:
                url += f"&state%5Bid%5D={state.upper()}"
            
            response = await self.client.get(url)
            
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            else:
                return {"success": False, "error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def propublica_get_org(self, ein: str) -> Dict[str, Any]:
        """Get nonprofit details by EIN"""
        try:
            # Remove dashes from EIN
            ein_clean = ein.replace("-", "")
            
            url = f"{self.propublica_base}/organizations/{ein_clean}.json"
            
            response = await self.client.get(url)
            
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            elif response.status_code == 404:
                return {"success": False, "error": "EIN not found"}
            else:
                return {"success": False, "error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def propublica_get_990(self, ein: str) -> Dict[str, Any]:
        """Get 990 filings for a nonprofit"""
        result = await self.propublica_get_org(ein)
        
        if not result.get("success"):
            return result
        
        data = result.get("data", {})
        org = data.get("organization", {})
        filings = data.get("filings_with_data", [])
        
        return {
            "success": True,
            "data": {
                "organization": org,
                "filings": filings[:10]  # Last 10 990s
            }
        }
    
    # ==================== Companies House UK (Free Tier) ====================
    
    async def uk_search_companies(self, query: str) -> Dict[str, Any]:
        """Search UK Companies House (free tier: 600 requests/5min)"""
        try:
            # Basic search works without auth
            url = f"{self.uk_base}/search/companies?q={quote(query)}"
            
            headers = {}
            if self.uk_api_key:
                headers["Authorization"] = f"Basic {self.uk_api_key}"
            
            response = await self.client.get(url, headers=headers)
            
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            elif response.status_code == 401:
                return {"success": False, "error": "UK Companies House requires API key for this query"}
            else:
                return {"success": False, "error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def uk_get_company(self, company_number: str) -> Dict[str, Any]:
        """Get UK company details by company number"""
        try:
            url = f"{self.uk_base}/company/{company_number}"
            
            headers = {}
            if self.uk_api_key:
                headers["Authorization"] = f"Basic {self.uk_api_key}"
            
            response = await self.client.get(url, headers=headers)
            
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            elif response.status_code == 404:
                return {"success": False, "error": "Company not found"}
            else:
                return {"success": False, "error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def uk_get_officers(self, company_number: str) -> Dict[str, Any]:
        """Get officers/directors for UK company"""
        try:
            url = f"{self.uk_base}/company/{company_number}/officers"
            
            headers = {}
            if self.uk_api_key:
                headers["Authorization"] = f"Basic {self.uk_api_key}"
            
            response = await self.client.get(url, headers=headers)
            
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            else:
                return {"success": False, "error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}


# Initialize MCP server
app = Server("corpdata-mcp")
logger.info("Initializing Corporate Data MCP Server (FREE sources)")

# Global client
client: Optional[CorporateDataClient] = None


def get_client() -> CorporateDataClient:
    global client
    if client is None:
        client = CorporateDataClient()
    return client


@app.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List available corporate data tools - TRIMMED for efficiency (US nonprofits focus)"""
    return [
        # ProPublica Nonprofit Tools - CORE for investigation
        types.Tool(
            name="nonprofit_search",
            description="Search ProPublica for US nonprofits by name. Returns EINs, states, latest financials. FREE.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Nonprofit name to search (e.g., 'Red Cross', 'Habitat for Humanity')"
                    },
                    "state": {
                        "type": "string",
                        "description": "Optional 2-letter state code filter (e.g., 'NY', 'CA')"
                    }
                },
                "required": ["query"]
            }
        ),
        types.Tool(
            name="nonprofit_details",
            description="Get detailed nonprofit info by EIN. Includes mission, financials, address.",
            inputSchema={
                "type": "object",
                "properties": {
                    "ein": {
                        "type": "string",
                        "description": "Employer Identification Number (e.g., '11-2623719' or '112623719')"
                    }
                },
                "required": ["ein"]
            }
        ),
        types.Tool(
            name="nonprofit_990",
            description="Get IRS Form 990 filings for a nonprofit. Shows revenue, expenses, officers, grants.",
            inputSchema={
                "type": "object",
                "properties": {
                    "ein": {
                        "type": "string",
                        "description": "Employer Identification Number"
                    }
                },
                "required": ["ein"]
            }
        ),
        # DISABLED: SEC tools (sec_search, sec_company, sec_filings)
        # DISABLED: UK Companies House tools (uk_search, uk_company, uk_officers)
        # Re-enable if needed for public company or UK investigations
    ]


@app.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """Execute corporate data tools"""
    
    corp_client = get_client()
    
    try:
        # ==================== SEC EDGAR ====================
        if name == "sec_search":
            query = arguments.get("query", "").strip()
            
            if not query:
                return [types.TextContent(type="text", text="❌ Search query is required!")]
            
            logger.info(f"SEC search: {query}")
            
            # Get company by searching for their CIK via the company tickers file
            # This is a workaround since SEC's search API is inconsistent
            try:
                ticker_url = "https://www.sec.gov/files/company_tickers.json"
                response = await corp_client.client.get(ticker_url)
                
                if response.status_code == 200:
                    tickers = response.json()
                    matches = []
                    
                    query_lower = query.lower()
                    for key, company in tickers.items():
                        company_name = company.get("title", "").lower()
                        ticker = company.get("ticker", "").lower()
                        
                        if query_lower in company_name or query_lower == ticker:
                            matches.append({
                                "cik": str(company.get("cik_str")),
                                "name": company.get("title"),
                                "ticker": company.get("ticker")
                            })
                    
                    if matches:
                        response_text = f"""🏛️ **SEC EDGAR Company Search**

**Query:** `{query}`
**Matches Found:** {len(matches)}

**Results:**
"""
                        for m in matches[:15]:
                            response_text += f"""
**{m['name']}**
  Ticker: `{m['ticker']}`
  CIK: `{m['cik']}`
  SEC Link: https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={m['cik']}
"""
                        
                        return [types.TextContent(type="text", text=response_text)]
                    else:
                        return [types.TextContent(type="text", text=f"No SEC-registered companies found matching '{query}'")]
                        
            except Exception as e:
                return [types.TextContent(type="text", text=f"❌ SEC search error: {e}")]
        
        elif name == "sec_company":
            cik = arguments.get("cik", "").strip()
            
            if not cik:
                return [types.TextContent(type="text", text="❌ CIK number is required!")]
            
            logger.info(f"SEC company lookup: {cik}")
            result = await corp_client.sec_get_company(cik)
            
            if not result.get("success"):
                return [types.TextContent(type="text", text=f"❌ {result.get('error')}")]
            
            data = result.get("data", {})
            
            response_text = f"""🏛️ **SEC Company Details**

**Name:** {data.get('name', 'N/A')}
**CIK:** {data.get('cik', 'N/A')}
**Ticker(s):** {', '.join(data.get('tickers', [])) or 'N/A'}
**Exchange(s):** {', '.join(data.get('exchanges', [])) or 'N/A'}

**Industry:**
  SIC Code: {data.get('sic', 'N/A')} - {data.get('sicDescription', 'N/A')}
  Category: {data.get('category', 'N/A')}

**Location:**
  State of Incorporation: {data.get('stateOfIncorporation', 'N/A')}
  Fiscal Year End: {data.get('fiscalYearEnd', 'N/A')}

**Addresses:**
"""
            
            for addr_type in ['business', 'mailing']:
                addr = data.get('addresses', {}).get(addr_type, {})
                if addr:
                    response_text += f"""
  **{addr_type.title()} Address:**
    {addr.get('street1', '')}
    {addr.get('street2', '')}
    {addr.get('city', '')}, {addr.get('state', '')} {addr.get('zipCode', '')}
"""
            
            # Recent filings summary
            filings = data.get('filings', {}).get('recent', {})
            if filings:
                forms = filings.get('form', [])[:5]
                dates = filings.get('filingDate', [])[:5]
                
                response_text += "\n**Recent Filings:**\n"
                for i, form in enumerate(forms):
                    date = dates[i] if i < len(dates) else ""
                    response_text += f"  - {form} ({date})\n"
            
            response_text += f"\n🔗 [View on SEC]({f'https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={cik}'})"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "sec_filings":
            cik = arguments.get("cik", "").strip()
            form_type = arguments.get("form_type", "").strip()
            
            if not cik:
                return [types.TextContent(type="text", text="❌ CIK number is required!")]
            
            logger.info(f"SEC filings for CIK {cik}")
            result = await corp_client.sec_get_filings(cik, form_type if form_type else None)
            
            if not result.get("success"):
                return [types.TextContent(type="text", text=f"❌ {result.get('error')}")]
            
            data = result.get("data", {})
            filings = data.get("filings", [])
            
            response_text = f"""📄 **SEC Filings**

**Company:** {data.get('company', 'N/A')}
**CIK:** {data.get('cik', 'N/A')}
{f"**Filter:** {form_type}" if form_type else ""}
**Showing:** {len(filings)} filings

**Filings:**
"""
            
            for filing in filings:
                accession = filing.get('accession', '').replace('-', '')
                cik_padded = cik.zfill(10)
                doc_url = f"https://www.sec.gov/Archives/edgar/data/{cik_padded}/{accession}"
                
                response_text += f"""
**{filing.get('form', 'N/A')}** - {filing.get('date', 'N/A')}
  {filing.get('description', 'N/A')}
  [View Filing]({doc_url})
"""
            
            return [types.TextContent(type="text", text=response_text)]
        
        # ==================== ProPublica Nonprofits ====================
        elif name == "nonprofit_search":
            query = arguments.get("query", "").strip()
            state = arguments.get("state", "").strip()
            
            if not query:
                return [types.TextContent(type="text", text="❌ Search query is required!")]
            
            logger.info(f"Nonprofit search: {query}")
            result = await corp_client.propublica_search(query, state if state else None)
            
            if not result.get("success"):
                return [types.TextContent(type="text", text=f"❌ {result.get('error')}")]
            
            data = result.get("data", {})
            orgs = data.get("organizations", [])
            
            response_text = f"""🏢 **ProPublica Nonprofit Search**

**Query:** `{query}`
{f"**State:** {state}" if state else ""}
**Results Found:** {data.get('total_results', len(orgs))}

**Organizations:**
"""
            
            for org in orgs[:15]:
                ein = str(org.get('ein', ''))
                ein_formatted = f"{ein[:2]}-{ein[2:]}" if len(ein) > 2 else ein
                
                response_text += f"""
**{org.get('name', 'N/A')}**
  EIN: `{ein_formatted}`
  State: {org.get('state', 'N/A')}
  City: {org.get('city', 'N/A')}
  Total Revenue: ${org.get('income_amount', 0):,.0f}
  Total Assets: ${org.get('asset_amount', 0):,.0f}
"""
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "nonprofit_details":
            ein = arguments.get("ein", "").strip().replace("-", "")
            
            if not ein:
                return [types.TextContent(type="text", text="❌ EIN is required!")]
            
            logger.info(f"Nonprofit details: {ein}")
            result = await corp_client.propublica_get_org(ein)
            
            if not result.get("success"):
                return [types.TextContent(type="text", text=f"❌ {result.get('error')}")]
            
            data = result.get("data", {})
            org = data.get("organization", {})
            
            ein_formatted = f"{ein[:2]}-{ein[2:]}" if len(ein) > 2 else ein
            
            response_text = f"""🏢 **Nonprofit Details**

**Name:** {org.get('name', 'N/A')}
**EIN:** `{ein_formatted}`
**Subsection Code:** {org.get('subsection_code', 'N/A')}
**NTEE Code:** {org.get('ntee_code', 'N/A')}

**Location:**
  {org.get('address', 'N/A')}
  {org.get('city', '')}, {org.get('state', '')} {org.get('zipcode', '')}

**Financials (Latest):**
  Total Revenue: ${org.get('income_amount', 0):,.0f}
  Total Assets: ${org.get('asset_amount', 0):,.0f}
  Tax Period: {org.get('tax_period', 'N/A')}

**Classification:**
  Ruling Date: {org.get('ruling_date', 'N/A')}
  Deductibility Code: {org.get('deductibility_code', 'N/A')}
  Foundation Code: {org.get('foundation_code', 'N/A')}

🔗 [View on ProPublica](https://projects.propublica.org/nonprofits/organizations/{ein})
"""
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "nonprofit_990":
            ein = arguments.get("ein", "").strip().replace("-", "")
            
            if not ein:
                return [types.TextContent(type="text", text="❌ EIN is required!")]
            
            logger.info(f"Nonprofit 990s: {ein}")
            result = await corp_client.propublica_get_990(ein)
            
            if not result.get("success"):
                return [types.TextContent(type="text", text=f"❌ {result.get('error')}")]
            
            data = result.get("data", {})
            org = data.get("organization", {})
            filings = data.get("filings", [])
            
            response_text = f"""📋 **Form 990 Filings**

**Organization:** {org.get('name', 'N/A')}
**EIN:** {ein}
**Filings Found:** {len(filings)}

**Recent 990 Filings:**
"""
            
            for filing in filings:
                response_text += f"""
**Tax Period: {filing.get('tax_prd_yr', 'N/A')}**
  Form Type: {filing.get('formtype', 'N/A')}
  Total Revenue: ${filing.get('totrevenue', 0):,.0f}
  Total Expenses: ${filing.get('totfuncexpns', 0):,.0f}
  Net Assets: ${filing.get('totassetsend', 0):,.0f}
  Total Liabilities: ${filing.get('totliabend', 0):,.0f}
"""
                if filing.get('pdf_url'):
                    response_text += f"  [Download PDF]({filing['pdf_url']})\n"
            
            return [types.TextContent(type="text", text=response_text)]
        
        # ==================== UK Companies House ====================
        elif name == "uk_search":
            query = arguments.get("query", "").strip()
            
            if not query:
                return [types.TextContent(type="text", text="❌ Search query is required!")]
            
            logger.info(f"UK Companies search: {query}")
            result = await corp_client.uk_search_companies(query)
            
            if not result.get("success"):
                return [types.TextContent(type="text", text=f"❌ {result.get('error')}")]
            
            data = result.get("data", {})
            items = data.get("items", [])
            
            response_text = f"""🇬🇧 **UK Companies House Search**

**Query:** `{query}`
**Results Found:** {data.get('total_results', len(items))}

**Companies:**
"""
            
            for company in items[:15]:
                response_text += f"""
**{company.get('title', 'N/A')}**
  Company Number: `{company.get('company_number', 'N/A')}`
  Status: {company.get('company_status', 'N/A')}
  Type: {company.get('company_type', 'N/A')}
  Address: {company.get('address_snippet', 'N/A')}
  Incorporated: {company.get('date_of_creation', 'N/A')}
"""
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "uk_company":
            company_number = arguments.get("company_number", "").strip()
            
            if not company_number:
                return [types.TextContent(type="text", text="❌ Company number is required!")]
            
            logger.info(f"UK company lookup: {company_number}")
            result = await corp_client.uk_get_company(company_number)
            
            if not result.get("success"):
                return [types.TextContent(type="text", text=f"❌ {result.get('error')}")]
            
            data = result.get("data", {})
            
            response_text = f"""🇬🇧 **UK Company Details**

**Name:** {data.get('company_name', 'N/A')}
**Company Number:** `{data.get('company_number', 'N/A')}`
**Status:** {data.get('company_status', 'N/A')}
**Type:** {data.get('type', 'N/A')}

**Dates:**
  Incorporated: {data.get('date_of_creation', 'N/A')}
  Last Accounts: {data.get('accounts', {}).get('last_accounts', {}).get('made_up_to', 'N/A')}
  Next Accounts Due: {data.get('accounts', {}).get('next_due', 'N/A')}

**Registered Office:**
"""
            
            addr = data.get('registered_office_address', {})
            if addr:
                response_text += f"""  {addr.get('address_line_1', '')}
  {addr.get('address_line_2', '')}
  {addr.get('locality', '')}
  {addr.get('postal_code', '')}
"""
            
            response_text += f"""
**SIC Codes:** {', '.join(data.get('sic_codes', [])) or 'N/A'}

🔗 [View on Companies House](https://find-and-update.company-information.service.gov.uk/company/{company_number})
"""
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "uk_officers":
            company_number = arguments.get("company_number", "").strip()
            
            if not company_number:
                return [types.TextContent(type="text", text="❌ Company number is required!")]
            
            logger.info(f"UK officers lookup: {company_number}")
            result = await corp_client.uk_get_officers(company_number)
            
            if not result.get("success"):
                return [types.TextContent(type="text", text=f"❌ {result.get('error')}")]
            
            data = result.get("data", {})
            items = data.get("items", [])
            
            response_text = f"""👔 **UK Company Officers**

**Company Number:** `{company_number}`
**Officers Found:** {len(items)}

**Officers:**
"""
            
            for officer in items[:20]:
                response_text += f"""
**{officer.get('name', 'N/A')}**
  Role: {officer.get('officer_role', 'N/A')}
  Appointed: {officer.get('appointed_on', 'N/A')}
  Resigned: {officer.get('resigned_on', 'Still Active')}
  Nationality: {officer.get('nationality', 'N/A')}
"""
            
            return [types.TextContent(type="text", text=response_text)]
        
        else:
            return [types.TextContent(type="text", text=f"❌ Unknown tool: {name}")]
    
    except Exception as e:
        logger.error(f"Error executing tool {name}: {e}", exc_info=True)
        return [types.TextContent(type="text", text=f"❌ Error: {str(e)}")]


async def main():
    """Main entry point"""
    global client
    
    logger.info("Starting Corporate Data MCP Server (FREE sources)...")
    logger.info("Sources: SEC EDGAR, ProPublica Nonprofit Explorer, UK Companies House")
    
    try:
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            await app.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="corpdata-mcp",
                    server_version="1.0.0",
                    capabilities=app.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )
    finally:
        if client:
            await client.close()


if __name__ == "__main__":
    asyncio.run(main())
