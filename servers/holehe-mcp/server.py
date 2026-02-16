#!/usr/bin/env python3
"""
Holehe MCP Server - Email Account Discovery Tool
Checks if an email is registered on 100+ websites without triggering login alerts.
"""

import asyncio
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional

from mcp.server import Server, NotificationOptions
from mcp.server.models import InitializationOptions
import mcp.server.stdio
import mcp.types as types

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("holehe-mcp")


async def check_email_holehe(email: str) -> Dict[str, Any]:
    """
    Run holehe check on an email address.
    Returns dict with platforms where email is registered.
    """
    try:
        import httpx
        from holehe.core import get_functions, import_submodules
        import holehe.modules
        
        # holehe uses httpx internally
        client = httpx.AsyncClient(timeout=30.0)
        
        # Get all modules using correct holehe API
        modules = import_submodules(holehe.modules)
        websites = get_functions(modules)
        
        # Run checks
        results = {
            "email": email,
            "registered": [],
            "not_registered": [],
            "rate_limited": [],
            "errors": [],
            "total_checked": 0
        }
        
        out = []
        
        # Create tasks for all websites
        async def check_site(func):
            try:
                await func(email, client, out)
            except Exception as e:
                logger.debug(f"Error checking {func.__name__}: {e}")
        
        # Run all checks concurrently with semaphore to limit connections
        sem = asyncio.Semaphore(20)
        
        async def bounded_check(func):
            async with sem:
                await check_site(func)
        
        tasks = [bounded_check(func) for func in websites]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        await client.aclose()
        
        # Process results
        for item in out:
            results["total_checked"] += 1
            
            if item.get("exists") == True:
                results["registered"].append({
                    "platform": item.get("name"),
                    "url": item.get("url", ""),
                    "domain": item.get("domain", ""),
                    "method": item.get("method", "")
                })
            elif item.get("exists") == False:
                results["not_registered"].append(item.get("name"))
            elif item.get("rateLimit"):
                results["rate_limited"].append(item.get("name"))
            else:
                results["errors"].append(item.get("name"))
        
        return {"success": True, "data": results}
        
    except ImportError as e:
        return {"success": False, "error": f"Holehe not installed. Run: pip install holehe. Error: {e}"}
    except Exception as e:
        logger.error(f"Error running holehe: {e}")
        return {"success": False, "error": str(e)}


# Initialize MCP server
app = Server("holehe-mcp")
logger.info("Initializing Holehe Email OSINT MCP Server")


@app.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List available email OSINT tools - TRIMMED for efficiency"""
    return [
        types.Tool(
            name="holehe_check",
            description="Check if an email address is registered on 100+ websites (social media, services, etc.) without triggering login alerts. OSINT gold for identity mapping.",
            inputSchema={
                "type": "object",
                "properties": {
                    "email": {
                        "type": "string",
                        "description": "Email address to check (e.g., 'john.doe@gmail.com')"
                    }
                },
                "required": ["email"]
            }
        ),
        # DISABLED: holehe_check_batch (rarely needed, hits rate limits)
    ]


@app.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """Execute Holehe email OSINT tools"""
    
    try:
        if name == "holehe_check":
            email = arguments.get("email", "").strip()
            
            if not email or "@" not in email:
                return [types.TextContent(type="text", text="❌ Valid email address is required!")]
            
            logger.info(f"Checking email: {email}")
            result = await check_email_holehe(email)
            
            if result.get("success"):
                data = result.get("data", {})
                registered = data.get("registered", [])
                
                response_text = f"""📧 **Holehe Email Account Discovery**

**Email:** `{data.get('email')}`
**Platforms Checked:** {data.get('total_checked', 0)}
**Accounts Found:** {len(registered)}
**Rate Limited:** {len(data.get('rate_limited', []))}

"""
                
                if registered:
                    response_text += "**✅ Registered Accounts Found:**\n"
                    
                    # Group by category
                    social = []
                    email_providers = []
                    other = []
                    
                    for platform in registered:
                        name_lower = platform['platform'].lower()
                        if any(x in name_lower for x in ['twitter', 'instagram', 'facebook', 'tiktok', 'snapchat', 'linkedin', 'pinterest', 'reddit', 'tumblr']):
                            social.append(platform)
                        elif any(x in name_lower for x in ['gmail', 'yahoo', 'outlook', 'proton', 'mail']):
                            email_providers.append(platform)
                        else:
                            other.append(platform)
                    
                    if social:
                        response_text += "\n**Social Media:**\n"
                        for p in social:
                            response_text += f"  - **{p['platform']}**"
                            if p.get('url'):
                                response_text += f" ({p['url']})"
                            response_text += "\n"
                    
                    if email_providers:
                        response_text += "\n**Email Providers:**\n"
                        for p in email_providers:
                            response_text += f"  - **{p['platform']}**\n"
                    
                    if other:
                        response_text += "\n**Other Services:**\n"
                        for p in other:
                            response_text += f"  - **{p['platform']}**"
                            if p.get('domain'):
                                response_text += f" ({p['domain']})"
                            response_text += "\n"
                else:
                    response_text += "**No registered accounts found on checked platforms.**\n"
                
                if data.get('rate_limited'):
                    response_text += f"\n⚠️ **Rate Limited Sites:** {', '.join(data['rate_limited'][:10])}"
                    if len(data['rate_limited']) > 10:
                        response_text += f" ... and {len(data['rate_limited']) - 10} more"
                
                response_text += "\n\n💡 **Note:** This checks registration status without triggering login alerts."
                
            else:
                response_text = f"❌ Holehe check failed: {result.get('error')}"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "holehe_check_batch":
            emails = arguments.get("emails", [])
            
            if not emails:
                return [types.TextContent(type="text", text="❌ At least one email address is required!")]
            
            # Limit to 5 emails to avoid excessive rate limiting
            emails = emails[:5]
            
            response_text = f"""📧 **Holehe Batch Email Check**

**Emails to check:** {len(emails)}

"""
            
            all_results = []
            for email in emails:
                email = email.strip()
                if "@" not in email:
                    response_text += f"\n❌ **{email}**: Invalid email format\n"
                    continue
                
                logger.info(f"Batch checking email: {email}")
                result = await check_email_holehe(email)
                
                if result.get("success"):
                    data = result.get("data", {})
                    registered = data.get("registered", [])
                    
                    response_text += f"\n**{email}:** "
                    if registered:
                        platform_names = [p['platform'] for p in registered]
                        response_text += f"{len(registered)} accounts found\n"
                        response_text += f"  Platforms: {', '.join(platform_names[:10])}"
                        if len(platform_names) > 10:
                            response_text += f" +{len(platform_names) - 10} more"
                        response_text += "\n"
                    else:
                        response_text += "No accounts found\n"
                else:
                    response_text += f"\n❌ **{email}**: {result.get('error')}\n"
                
                # Small delay between emails
                await asyncio.sleep(2)
            
            return [types.TextContent(type="text", text=response_text)]
        
        else:
            return [types.TextContent(type="text", text=f"❌ Unknown tool: {name}")]
    
    except Exception as e:
        logger.error(f"Error executing tool {name}: {e}", exc_info=True)
        return [types.TextContent(type="text", text=f"❌ Error: {str(e)}")]


async def main():
    """Main entry point"""
    logger.info("Starting Holehe Email OSINT MCP Server...")
    
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="holehe-mcp",
                server_version="1.0.0",
                capabilities=app.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())
