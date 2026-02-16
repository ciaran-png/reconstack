#!/usr/bin/env python3
"""
Social Analyzer MCP Server
Wraps 'maigret' to perform deep username reconnaissance across 3000+ sites.
"""

import asyncio
import logging
import json
import os
import shutil
import subprocess
import tempfile
import glob
from typing import Any, Dict, List, Optional
from pathlib import Path

from mcp.server import Server, NotificationOptions
from mcp.server.models import InitializationOptions
import mcp.server.stdio
import mcp.types as types

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("social-analyzer-mcp")

# Initialize MCP server
app = Server("social-analyzer-mcp")

def check_maigret_installed() -> bool:
    """Check if maigret is installed and in PATH"""
    # Check multiple possible locations
    if shutil.which("maigret"):
        return True
    # Also check common pip install locations
    possible_paths = [
        "/Library/Frameworks/Python.framework/Versions/3.11/bin/maigret",
        os.path.expanduser("~/.local/bin/maigret"),
        "/usr/local/bin/maigret"
    ]
    for path in possible_paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            return True
    return False

def get_maigret_path() -> str:
    """Get the full path to maigret executable"""
    if shutil.which("maigret"):
        return shutil.which("maigret")
    possible_paths = [
        "/Library/Frameworks/Python.framework/Versions/3.11/bin/maigret",
        os.path.expanduser("~/.local/bin/maigret"),
        "/usr/local/bin/maigret"
    ]
    for path in possible_paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            return path
    return "maigret"  # fallback

@app.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List available social analysis tools - TRIMMED for efficiency"""
    return [
        types.Tool(
            name="social_analyzer_search",
            description="Deep scan a username across 3000+ websites using Maigret. Returns found profiles and metadata. This process can take a few minutes.",
            inputSchema={
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "The username to investigate"
                    },
                    "limit_sites": {
                        "type": "integer",
                        "description": "Limit to top N sites (default: 500, set to 0 for all)",
                        "default": 500
                    },
                    "tags": {
                        "type": "string",
                        "description": "Filter by site tags (e.g., 'photo,coding,dating')",
                    }
                },
                "required": ["username"]
            }
        ),
        # DISABLED: check_status (not essential)
    ]

@app.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """Execute social analysis tools"""
    
    if name == "check_status":
        installed = check_maigret_installed()
        maigret_path = get_maigret_path() if installed else "Not found"
        return [types.TextContent(
            type="text", 
            text=f"Maigret installed: {'✅ Yes' if installed else '❌ No'}\nPath: {maigret_path}\n\nTo install: `pip install maigret`"
        )]
    
    elif name == "social_analyzer_search" or name == "analyze_username":  # Support both names
        if not check_maigret_installed():
            return [types.TextContent(type="text", text="❌ Maigret is not installed. Please install it with `pip install maigret`")]
        
        maigret_path = get_maigret_path()
        username = arguments.get("username", "").strip()
        limit = arguments.get("limit_sites", 500)
        pdf = arguments.get("pdf_report", False)
        tags = arguments.get("tags", "")
        
        if not username:
            return [types.TextContent(type="text", text="❌ Username is required")]
        
        # Create temp directory for reports
        with tempfile.TemporaryDirectory() as tmpdir:
            # Build command - output to our temp directory
            json_output_file = os.path.join(tmpdir, f"{username}.json")
            cmd = [
                maigret_path, username,
                "--json", "ndjson",  # Use ndjson format for easier parsing
                "--folderoutput", tmpdir,
                "--no-progressbar",
                "--timeout", "10"  # Limit per-site timeout
            ]
            
            if limit > 0:
                cmd.extend(["--top-sites", str(limit)])
            
            if tags:
                cmd.extend(["--tags", tags])
                
            if pdf:
                cmd.append("--pdf")
                
            logger.info(f"Running Maigret: {' '.join(cmd)}")
            
            try:
                # Maigret can be slow, set a generous timeout (5 minutes)
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                try:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(),
                        timeout=300  # 5 minute timeout
                    )
                except asyncio.TimeoutError:
                    process.kill()
                    return [types.TextContent(type="text", text=f"⏱️ Maigret timed out after 5 minutes for '{username}'. Try with fewer sites using limit_sites parameter.")]
                
                output = stdout.decode()
                err_output = stderr.decode()
                
                logger.info(f"Maigret exit code: {process.returncode}")
                if err_output:
                    logger.warning(f"Maigret stderr: {err_output[:500]}")
                
                report_text = f"🔍 **Username Analysis: {username}**\n\n"
                
                # Look for JSON files in the temp directory
                json_files = glob.glob(os.path.join(tmpdir, "*.json"))
                found_accounts = []
                
                for jf in json_files:
                    try:
                        with open(jf, 'r') as f:
                            content = f.read()
                            # Handle NDJSON (one JSON object per line)
                            for line in content.strip().split('\n'):
                                if line.strip():
                                    try:
                                        entry = json.loads(line)
                                        if isinstance(entry, dict):
                                            # Check if this is a found account
                                            if entry.get('status') and 'claimed' in str(entry.get('status', '')).lower():
                                                found_accounts.append(entry)
                                            elif entry.get('url_user') and entry.get('exists'):
                                                found_accounts.append(entry)
                                    except json.JSONDecodeError:
                                        continue
                    except Exception as e:
                        logger.error(f"Error reading JSON file {jf}: {e}")
                
                # Also try to parse stdout for additional data
                try:
                    for line in output.strip().split('\n'):
                        if line.strip().startswith('{'):
                            try:
                                entry = json.loads(line)
                                if isinstance(entry, dict) and entry.get('url_user'):
                                    found_accounts.append(entry)
                            except:
                                continue
                except:
                    pass
                
                # Deduplicate by URL
                seen_urls = set()
                unique_accounts = []
                for acc in found_accounts:
                    url = acc.get('url_user') or acc.get('url') or acc.get('link')
                    if url and url not in seen_urls:
                        seen_urls.add(url)
                        unique_accounts.append(acc)
                
                if unique_accounts:
                    report_text += f"✅ **Found {len(unique_accounts)} accounts:**\n\n"
                    for account in unique_accounts[:50]:  # Limit display
                        site_name = account.get('site_name') or account.get('sitename') or account.get('site') or 'Unknown'
                        url = account.get('url_user') or account.get('url') or account.get('link') or ''
                        report_text += f"- **{site_name}**: {url}\n"
                    
                    if len(unique_accounts) > 50:
                        report_text += f"\n_...and {len(unique_accounts) - 50} more accounts_\n"
                else:
                    report_text += "❌ **No accounts found** for this username.\n"
                    if output:
                        report_text += f"\n_Raw output sample:_\n```\n{output[:1000]}\n```"
                
                # Add exit info
                if process.returncode != 0:
                    report_text += f"\n\n⚠️ Process exited with code {process.returncode}"
                    if err_output:
                        report_text += f"\nStderr: {err_output[:500]}"
                
                return [types.TextContent(type="text", text=report_text)]
                
            except Exception as e:
                logger.error(f"Error running Maigret: {e}", exc_info=True)
                return [types.TextContent(type="text", text=f"❌ Error running Maigret: {str(e)}")]
            
    else:
        return [types.TextContent(type="text", text=f"❌ Unknown tool: {name}")]

async def main():
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="social-analyzer-mcp",
                server_version="1.0.0",
                capabilities=app.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )

if __name__ == "__main__":
    asyncio.run(main())
