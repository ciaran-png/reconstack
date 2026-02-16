#!/usr/bin/env python3
"""
GitDorker MCP Server - GitHub Dorking Tool
Advanced GitHub code search using dork queries to find sensitive data.
Uses GitHub's code search API directly.
"""

import asyncio
import json
import logging
import os
import re
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
logger = logging.getLogger("gitdorker-mcp")

# Preset dork categories for common sensitive data searches
DORK_PRESETS = {
    "api_keys": [
        "api_key",
        "apikey",
        "api_secret",
        "access_token",
        "auth_token",
        "client_secret",
    ],
    "aws": [
        "AKIA",  # AWS Access Key ID prefix
        "aws_secret_access_key",
        "aws_access_key_id",
        "s3.amazonaws.com",
    ],
    "database": [
        "password",
        "passwd",
        "pwd",
        "DB_PASSWORD",
        "DATABASE_URL",
        "MONGO_URI",
        "mysql://",
        "postgres://",
    ],
    "private_keys": [
        "BEGIN RSA PRIVATE KEY",
        "BEGIN OPENSSH PRIVATE KEY",
        "BEGIN PGP PRIVATE KEY",
        "BEGIN EC PRIVATE KEY",
    ],
    "config_files": [
        "filename:.env",
        "filename:.npmrc",
        "filename:config.json",
        "filename:settings.py",
        "filename:wp-config.php",
        "filename:application.yml",
    ],
    "oauth": [
        "client_id",
        "client_secret", 
        "oauth_token",
        "refresh_token",
    ],
    "smtp": [
        "smtp_password",
        "mail_password",
        "email_password",
        "sendgrid",
        "mailgun",
    ],
    "firebase": [
        "firebase",
        "firebaseConfig",
        "apiKey.*firebase",
    ],
    "stripe": [
        "sk_live_",
        "pk_live_",
        "stripe_secret",
    ],
    "slack": [
        "xoxb-",
        "xoxp-",
        "slack_token",
        "slack_webhook",
    ]
}


class GitHubDorker:
    """GitHub code search client for dorking"""
    
    def __init__(self, token: Optional[str] = None):
        self.token = token or os.environ.get("GITHUB_TOKEN")
        self.base_url = "https://api.github.com"
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "GitDorker-MCP/1.0"
        }
        if self.token:
            self.headers["Authorization"] = f"token {self.token}"
        
        self.client = httpx.AsyncClient(timeout=30.0, headers=self.headers)
    
    async def close(self):
        await self.client.aclose()
    
    async def search_code(self, query: str, per_page: int = 30, page: int = 1) -> Dict[str, Any]:
        """Search GitHub code with a query"""
        try:
            params = {
                "q": query,
                "per_page": min(per_page, 100),
                "page": page
            }
            
            response = await self.client.get(
                f"{self.base_url}/search/code",
                params=params
            )
            
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            elif response.status_code == 401:
                return {"success": False, "error": "Invalid or missing GitHub token"}
            elif response.status_code == 403:
                # Rate limit or abuse detection
                remaining = response.headers.get("X-RateLimit-Remaining", "0")
                reset_time = response.headers.get("X-RateLimit-Reset", "")
                return {
                    "success": False, 
                    "error": f"Rate limited. Remaining: {remaining}. Try again later."
                }
            elif response.status_code == 422:
                return {"success": False, "error": "Invalid search query syntax"}
            else:
                return {"success": False, "error": f"HTTP {response.status_code}: {response.text[:200]}"}
                
        except Exception as e:
            logger.error(f"Error searching GitHub: {e}")
            return {"success": False, "error": str(e)}
    
    async def search_repos(self, query: str, per_page: int = 10) -> Dict[str, Any]:
        """Search GitHub repositories"""
        try:
            params = {
                "q": query,
                "per_page": per_page
            }
            
            response = await self.client.get(
                f"{self.base_url}/search/repositories",
                params=params
            )
            
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            else:
                return {"success": False, "error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def build_target_query(self, dork: str, target: str, target_type: str = "org") -> str:
        """Build a search query targeting a specific org or user"""
        if target_type == "org":
            return f"{dork} org:{target}"
        elif target_type == "user":
            return f"{dork} user:{target}"
        elif target_type == "repo":
            return f"{dork} repo:{target}"
        else:
            return f"{dork} {target}"


# Initialize MCP server
app = Server("gitdorker-mcp")
logger.info("Initializing GitDorker MCP Server")

# Global client
dorker: Optional[GitHubDorker] = None


def get_dorker() -> GitHubDorker:
    global dorker
    if dorker is None:
        dorker = GitHubDorker()
    return dorker


@app.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List available GitHub dorking tools - TRIMMED for efficiency"""
    return [
        types.Tool(
            name="gitdorker_search",
            description="Search GitHub code with a custom dork query. Can target specific orgs/users. Requires GITHUB_TOKEN env var.",
            inputSchema={
                "type": "object",
                "properties": {
                    "dork": {
                        "type": "string",
                        "description": "Search query/dork (e.g., 'password', 'api_key', 'filename:.env')"
                    },
                    "target": {
                        "type": "string",
                        "description": "Target organization, user, or repo name"
                    },
                    "target_type": {
                        "type": "string",
                        "enum": ["org", "user", "repo"],
                        "description": "Type of target (org, user, or repo)",
                        "default": "org"
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum results to return (default: 30, max: 100)",
                        "default": 30
                    }
                },
                "required": ["dork"]
            }
        ),
        types.Tool(
            name="gitdorker_preset",
            description="Run preset dork categories (api_keys, aws, database, private_keys, config_files, oauth, smtp, firebase, stripe, slack) against a target.",
            inputSchema={
                "type": "object",
                "properties": {
                    "preset": {
                        "type": "string",
                        "enum": list(DORK_PRESETS.keys()),
                        "description": "Preset category to search for"
                    },
                    "target": {
                        "type": "string",
                        "description": "Target organization or user"
                    },
                    "target_type": {
                        "type": "string",
                        "enum": ["org", "user"],
                        "description": "Type of target",
                        "default": "org"
                    }
                },
                "required": ["preset", "target"]
            }
        ),
        # DISABLED: gitdorker_full_scan (too slow, hits rate limits)
        # DISABLED: gitdorker_list_presets (not essential)
    ]


@app.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """Execute GitDorker tools"""
    
    client = get_dorker()
    
    try:
        if name == "gitdorker_search":
            dork = arguments.get("dork", "").strip()
            target = arguments.get("target", "").strip()
            target_type = arguments.get("target_type", "org")
            max_results = min(arguments.get("max_results", 30), 100)
            
            if not dork:
                return [types.TextContent(type="text", text="❌ Dork query is required!")]
            
            # Build query
            if target:
                query = client.build_target_query(dork, target, target_type)
            else:
                query = dork
            
            logger.info(f"Running GitHub dork: {query}")
            
            result = await client.search_code(query, per_page=max_results)
            
            if not result.get("success"):
                error = result.get("error", "Unknown error")
                if "token" in error.lower():
                    error += "\n\n💡 Set GITHUB_TOKEN environment variable for authenticated searches."
                return [types.TextContent(type="text", text=f"❌ Search failed: {error}")]
            
            data = result.get("data", {})
            items = data.get("items", [])
            total = data.get("total_count", 0)
            
            response_text = f"""🔍 **GitHub Dork Search Results**

**Query:** `{query}`
**Total Matches:** {total}
**Results Shown:** {len(items)}

"""
            
            if items:
                response_text += "**Findings:**\n"
                
                for item in items[:30]:
                    repo = item.get("repository", {})
                    repo_name = repo.get("full_name", "Unknown")
                    file_path = item.get("path", "Unknown")
                    html_url = item.get("html_url", "")
                    
                    # Try to get a preview of the match
                    text_matches = item.get("text_matches", [])
                    preview = ""
                    if text_matches:
                        for match in text_matches[:1]:
                            fragment = match.get("fragment", "")
                            if fragment:
                                # Truncate and clean
                                preview = fragment[:150].replace('\n', ' ')
                                break
                    
                    response_text += f"""
**📄 {file_path}**
  Repo: [{repo_name}]({repo.get('html_url', '')})
  [View File]({html_url})
"""
                    if preview:
                        response_text += f"  Preview: `{preview}...`\n"
            else:
                response_text += "**✅ No matches found for this query.**"
            
            if not client.token:
                response_text += "\n\n⚠️ **Note:** Running without GITHUB_TOKEN. Rate limits are strict. Set token for better results."
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "gitdorker_preset":
            preset = arguments.get("preset", "").strip()
            target = arguments.get("target", "").strip()
            target_type = arguments.get("target_type", "org")
            
            if not preset or preset not in DORK_PRESETS:
                return [types.TextContent(type="text", text=f"❌ Invalid preset. Available: {', '.join(DORK_PRESETS.keys())}")]
            
            if not target:
                return [types.TextContent(type="text", text="❌ Target is required!")]
            
            dorks = DORK_PRESETS[preset]
            
            response_text = f"""🎯 **GitDorker Preset Scan: {preset}**

**Target:** {target} ({target_type})
**Dorks in preset:** {len(dorks)}

**Results:**
"""
            
            all_findings = []
            
            for dork in dorks:
                query = client.build_target_query(dork, target, target_type)
                logger.info(f"Running dork: {query}")
                
                result = await client.search_code(query, per_page=10)
                
                if result.get("success"):
                    data = result.get("data", {})
                    items = data.get("items", [])
                    total = data.get("total_count", 0)
                    
                    if total > 0:
                        response_text += f"\n**`{dork}`**: {total} matches\n"
                        for item in items[:3]:
                            file_path = item.get("path", "")
                            repo = item.get("repository", {}).get("full_name", "")
                            response_text += f"  - {repo}/{file_path}\n"
                        if total > 3:
                            response_text += f"  ... and {total - 3} more\n"
                        
                        all_findings.extend(items)
                else:
                    response_text += f"\n**`{dork}`**: ⚠️ {result.get('error', 'Error')}\n"
                
                # Rate limit protection
                await asyncio.sleep(2)
            
            if not all_findings:
                response_text += "\n**✅ No sensitive data found with these dorks.**"
            else:
                response_text += f"\n**Total unique findings:** {len(all_findings)}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "gitdorker_full_scan":
            target = arguments.get("target", "").strip()
            target_type = arguments.get("target_type", "org")
            
            if not target:
                return [types.TextContent(type="text", text="❌ Target is required!")]
            
            response_text = f"""🔥 **GitDorker Full Scan**

**Target:** {target} ({target_type})
**Running all {len(DORK_PRESETS)} preset categories...**

"""
            
            total_findings = 0
            findings_by_category = {}
            
            for preset_name, dorks in DORK_PRESETS.items():
                category_findings = 0
                
                for dork in dorks[:3]:  # Limit to 3 per category to avoid rate limits
                    query = client.build_target_query(dork, target, target_type)
                    result = await client.search_code(query, per_page=5)
                    
                    if result.get("success"):
                        total = result.get("data", {}).get("total_count", 0)
                        category_findings += total
                    
                    await asyncio.sleep(2)  # Rate limit protection
                
                findings_by_category[preset_name] = category_findings
                total_findings += category_findings
                
                if category_findings > 0:
                    response_text += f"**{preset_name}**: ⚠️ {category_findings} potential findings\n"
                else:
                    response_text += f"**{preset_name}**: ✅ Clean\n"
            
            response_text += f"""
---
**Summary:**
  Total potential exposures: {total_findings}
  Categories with findings: {sum(1 for v in findings_by_category.values() if v > 0)}
  
💡 Use `gitdorker_preset` for detailed results on specific categories.
"""
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "gitdorker_list_presets":
            response_text = "📋 **Available GitDorker Presets**\n\n"
            
            for preset_name, dorks in DORK_PRESETS.items():
                response_text += f"**{preset_name}:**\n"
                for dork in dorks:
                    response_text += f"  - `{dork}`\n"
                response_text += "\n"
            
            return [types.TextContent(type="text", text=response_text)]
        
        else:
            return [types.TextContent(type="text", text=f"❌ Unknown tool: {name}")]
    
    except Exception as e:
        logger.error(f"Error executing tool {name}: {e}", exc_info=True)
        return [types.TextContent(type="text", text=f"❌ Error: {str(e)}")]


async def main():
    """Main entry point"""
    global dorker
    
    logger.info("Starting GitDorker MCP Server...")
    
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        logger.info("GitHub token found - authenticated searches enabled")
    else:
        logger.warning("No GITHUB_TOKEN found - running with strict rate limits")
    
    try:
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            await app.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="gitdorker-mcp",
                    server_version="1.0.0",
                    capabilities=app.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )
    finally:
        if dorker:
            await dorker.close()


if __name__ == "__main__":
    asyncio.run(main())
