import os
import json
from enum import Enum
from typing import List, Optional, Dict, Any
from mcp.server.fastmcp import FastMCP
from googleapiclient.discovery import build
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize FastMCP Server
mcp = FastMCP("google-dork-mcp")

# --- Configuration ---
API_KEY = os.getenv("GOOGLE_API_KEY")
CSE_ID = os.getenv("GOOGLE_CSE_ID") or os.getenv("GOOGLE_CX")

if not API_KEY or not CSE_ID:
    raise ValueError("GOOGLE_API_KEY and GOOGLE_CSE_ID (or GOOGLE_CX) must be set in .env")

# --- Strategy Definitions ---
class DorkStrategy(str, Enum):
    EXPOSED_ENV = "filetype:env OR filetype:env.backup OR filetype:env.bak"
    CONFIG_FILES = "filetype:xml OR filetype:conf OR filetype:cnf OR filetype:reg OR filetype:inf OR filetype:rdp OR filetype:cfg"
    DATABASE_FILES = "filetype:sql OR filetype:db OR filetype:dbf OR filetype:mdb"
    LOG_FILES = "filetype:log OR filetype:txt intext:password OR intext:username"
    BACKUP_FILES = "filetype:bkf OR filetype:bkp OR filetype:bak OR filetype:old OR filetype:backup"
    LOGIN_PAGES = "inurl:login OR inurl:admin OR inurl:cpanel OR intitle:\"login\""
    SQL_ERRORS = "intext:\"sql syntax near\" OR intext:\"syntax error has occurred\" OR intext:\"incorrect syntax near\""
    PUBLICly_EXPOSED_DOCS = "site:docs.google.com OR site:drive.google.com"
    S3_BUCKETS = "site:s3.amazonaws.com OR site:blob.core.windows.net"

# --- Helper Functions ---

def _google_search(query: str, num_results: int = 10) -> List[Dict[str, Any]]:
    """
    Executes a search against the Google Custom Search JSON API.
    Handles pagination if num_results > 10.
    """
    service = build("customsearch", "v1", developerKey=API_KEY)
    results = []
    
    # Google API returns max 10 results per page.
    # We loop to fetch more if requested, up to 30 (to save quota).
    max_fetch = min(num_results, 30) 
    
    for start_index in range(1, max_fetch + 1, 10):
        try:
            res = service.cse().list(
                q=query,
                cx=CSE_ID,
                num=min(10, max_fetch - start_index + 1), # Fetch remaining or 10
                start=start_index
            ).execute()
            
            items = res.get("items", [])
            if not items:
                break
                
            for item in items:
                results.append({
                    "title": item.get("title"),
                    "link": item.get("link"),
                    "snippet": item.get("snippet"),
                    "displayLink": item.get("displayLink")
                })
                
        except Exception as e:
            return [{"error": str(e)}]
            
    return results

# --- Tools ---

@mcp.tool()
def run_dork_scan(target_domain: str, strategy: DorkStrategy, num_results: int = 10) -> str:
    """
    Scans a specific target domain using a pre-defined sophisticated dork strategy.
    
    Args:
        target_domain: The domain to scan (e.g., "nasa.gov", "tesla.com").
        strategy: The type of vulnerability or asset to look for.
        num_results: Number of results to return (default 10).
    """
    # Construct the advanced query
    # We combine "site:" operator with the strategy's specific dork pattern.
    full_query = f"site:{target_domain} ({strategy.value})"
    
    results = _google_search(full_query, num_results)
    
    if not results:
        return f"No results found for strategy {strategy.name} on {target_domain}."
    
    # Format results for Claude
    formatted_output = f"### Dork Scan Results: {strategy.name} on {target_domain}\n"
    formatted_output += f"**Query Executed:** `{full_query}`\n\n"
    
    for i, res in enumerate(results, 1):
        formatted_output += f"{i}. [{res['title']}]({res['link']})\n"
        formatted_output += f"   > {res.get('snippet', 'No snippet')}\n\n"
        
    return formatted_output

@mcp.tool()
def raw_advanced_search(query: str, num_results: int = 10) -> str:
    """
    Executes a raw, custom Google Dork query. Use this for bespoke, highly specific searches
    that don't fit into standard strategies.
    
    Args:
        query: The full Google Dork query string (e.g., 'site:github.com "API_KEY"').
        num_results: Number of results to return.
    """
    results = _google_search(query, num_results)
    
    if not results:
        return f"No results found for query: {query}"
        
    formatted_output = f"### Raw Dork Results\n"
    formatted_output += f"**Query:** `{query}`\n\n"
    
    for i, res in enumerate(results, 1):
        if "error" in res:
             return f"Error executing search: {res['error']}"
        formatted_output += f"{i}. [{res['title']}]({res['link']})\n"
        formatted_output += f"   > {res.get('snippet', 'No snippet')}\n\n"
        
    return formatted_output

if __name__ == "__main__":
    mcp.run()
