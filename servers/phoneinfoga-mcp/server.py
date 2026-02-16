#!/usr/bin/env python3
"""
PhoneInfoga MCP Server - Phone Number Intelligence Tool
Phone number reconnaissance: carrier, line type, location, formatting.
Wraps the phoneinfoga CLI tool.
"""

import asyncio
import json
import logging
import os
import subprocess
import shutil
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
logger = logging.getLogger("phoneinfoga-mcp")


def find_phoneinfoga() -> Optional[str]:
    """Find the phoneinfoga binary"""
    # Check common locations
    locations = [
        shutil.which("phoneinfoga"),
        "/usr/local/bin/phoneinfoga",
        "/opt/homebrew/bin/phoneinfoga",
        os.path.expanduser("~/go/bin/phoneinfoga"),
    ]
    
    for loc in locations:
        if loc and os.path.isfile(loc):
            return loc
    
    return None


def run_phoneinfoga(args: List[str], timeout: int = 60) -> Dict[str, Any]:
    """Run phoneinfoga CLI command"""
    binary = find_phoneinfoga()
    
    if not binary:
        return {
            "success": False,
            "error": "phoneinfoga not found. Install with: brew install phoneinfoga OR go install github.com/sundowndev/phoneinfoga/v2@latest"
        }
    
    try:
        result = subprocess.run(
            [binary] + args,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        }
    
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"Command timed out after {timeout} seconds"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def parse_scan_output(output: str) -> Dict[str, Any]:
    """Parse phoneinfoga scan output into structured data"""
    result = {
        "raw_number": "",
        "international_format": "",
        "local_format": "",
        "e164_format": "",
        "country": "",
        "country_code": "",
        "carrier": "",
        "line_type": "",
        "valid": False,
        "possible": False,
        "scanners": {}
    }
    
    lines = output.strip().split('\n')
    current_scanner = None
    
    for line in lines:
        line = line.strip()
        
        # Basic info parsing
        if "International format:" in line:
            result["international_format"] = line.split(":")[-1].strip()
        elif "Local format:" in line:
            result["local_format"] = line.split(":")[-1].strip()
        elif "E164 format:" in line:
            result["e164_format"] = line.split(":")[-1].strip()
        elif "Country:" in line:
            result["country"] = line.split(":")[-1].strip()
        elif "Country code:" in line or "Dialing code:" in line:
            result["country_code"] = line.split(":")[-1].strip()
        elif "Carrier:" in line:
            result["carrier"] = line.split(":")[-1].strip()
        elif "Line type:" in line or "Type:" in line:
            result["line_type"] = line.split(":")[-1].strip()
        elif "Valid:" in line:
            result["valid"] = "true" in line.lower() or "yes" in line.lower()
        elif "Possible:" in line:
            result["possible"] = "true" in line.lower() or "yes" in line.lower()
        
        # Scanner detection
        elif "Running scanner" in line or "[scanner]" in line.lower():
            scanner_name = line.split()[-1].strip('[]')
            current_scanner = scanner_name
            result["scanners"][current_scanner] = {"results": [], "status": "running"}
        elif current_scanner and line and not line.startswith("─"):
            if "scanners" in result and current_scanner in result["scanners"]:
                result["scanners"][current_scanner]["results"].append(line)
    
    return result


# Initialize MCP server
app = Server("phoneinfoga-mcp")
logger.info("Initializing PhoneInfoga MCP Server")


@app.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List available phone OSINT tools - TRIMMED for efficiency"""
    return [
        types.Tool(
            name="phoneinfoga_scan",
            description="Scan a phone number for carrier info, location, line type, and run OSINT scanners. Include country code (e.g., +1 for US, +972 for Israel).",
            inputSchema={
                "type": "object",
                "properties": {
                    "number": {
                        "type": "string",
                        "description": "Phone number with country code (e.g., '+14155552671', '+972501234567')"
                    }
                },
                "required": ["number"]
            }
        ),
        # DISABLED: phoneinfoga_validate (scan includes validation)
        # DISABLED: phoneinfoga_batch (rarely needed)
    ]


@app.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """Execute PhoneInfoga tools"""
    
    try:
        if name == "phoneinfoga_scan":
            number = arguments.get("number", "").strip()
            
            if not number:
                return [types.TextContent(type="text", text="❌ Phone number is required!")]
            
            # Ensure number starts with +
            if not number.startswith("+"):
                number = "+" + number
            
            logger.info(f"Scanning phone number: {number}")
            
            # Run phoneinfoga scan
            result = run_phoneinfoga(["scan", "-n", number])
            
            if not result.get("success"):
                # Check if it's just that the binary isn't found
                if "not found" in result.get("error", ""):
                    return [types.TextContent(type="text", text=f"❌ {result.get('error')}")]
                
                # Try to parse any output we got
                output = result.get("stdout", "") + result.get("stderr", "")
                if output:
                    parsed = parse_scan_output(output)
                else:
                    return [types.TextContent(type="text", text=f"❌ Scan failed: {result.get('error', 'Unknown error')}")]
            else:
                output = result.get("stdout", "")
                parsed = parse_scan_output(output)
            
            # Build response
            response_text = f"""📱 **PhoneInfoga Scan Results**

**Number:** `{number}`

**Validation:**
  Valid: {'✅ Yes' if parsed.get('valid') else '❌ No'}
  Possible: {'✅ Yes' if parsed.get('possible') else '❌ No'}

**Formatting:**
  International: `{parsed.get('international_format', 'N/A')}`
  Local: `{parsed.get('local_format', 'N/A')}`
  E.164: `{parsed.get('e164_format', 'N/A')}`

**Location:**
  Country: {parsed.get('country', 'Unknown')}
  Country Code: {parsed.get('country_code', 'Unknown')}

**Carrier Info:**
  Carrier: {parsed.get('carrier', 'Unknown')}
  Line Type: {parsed.get('line_type', 'Unknown')}

"""
            
            # Add scanner results if any
            if parsed.get("scanners"):
                response_text += "**Scanner Results:**\n"
                for scanner, data in parsed["scanners"].items():
                    response_text += f"\n*{scanner}:*\n"
                    for line in data.get("results", [])[:10]:
                        response_text += f"  {line}\n"
            
            # Add raw output for debugging
            if output and len(output) < 2000:
                response_text += f"\n**Raw Output:**\n```\n{output[:2000]}\n```"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "phoneinfoga_validate":
            number = arguments.get("number", "").strip()
            country = arguments.get("country_code", "").strip().upper()
            
            if not number:
                return [types.TextContent(type="text", text="❌ Phone number is required!")]
            
            # Build validation using Google's libphonenumber via phoneinfoga
            args = ["scan", "-n", number]
            
            logger.info(f"Validating phone number: {number}")
            result = run_phoneinfoga(args)
            
            output = result.get("stdout", "") + result.get("stderr", "")
            parsed = parse_scan_output(output)
            
            response_text = f"""📱 **Phone Number Validation**

**Input:** `{number}`
**Valid:** {'✅ Yes' if parsed.get('valid') else '❌ No'}
**Possible:** {'✅ Yes' if parsed.get('possible') else '❌ No'}

**Formatted:**
  International: `{parsed.get('international_format', 'N/A')}`
  Local: `{parsed.get('local_format', 'N/A')}`
  E.164: `{parsed.get('e164_format', 'N/A')}`

**Details:**
  Country: {parsed.get('country', 'Unknown')}
  Line Type: {parsed.get('line_type', 'Unknown')}
"""
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "phoneinfoga_batch":
            numbers = arguments.get("numbers", [])
            
            if not numbers:
                return [types.TextContent(type="text", text="❌ At least one phone number is required!")]
            
            # Limit to 5 numbers
            numbers = numbers[:5]
            
            response_text = f"""📱 **PhoneInfoga Batch Scan**

**Numbers to scan:** {len(numbers)}

"""
            
            for number in numbers:
                number = number.strip()
                if not number.startswith("+"):
                    number = "+" + number
                
                logger.info(f"Batch scanning: {number}")
                result = run_phoneinfoga(["scan", "-n", number])
                
                output = result.get("stdout", "") + result.get("stderr", "")
                parsed = parse_scan_output(output)
                
                response_text += f"""
**{number}:**
  Valid: {'✅' if parsed.get('valid') else '❌'}
  Country: {parsed.get('country', 'Unknown')}
  Carrier: {parsed.get('carrier', 'Unknown')}
  Type: {parsed.get('line_type', 'Unknown')}
"""
                
                # Small delay between scans
                await asyncio.sleep(1)
            
            return [types.TextContent(type="text", text=response_text)]
        
        else:
            return [types.TextContent(type="text", text=f"❌ Unknown tool: {name}")]
    
    except Exception as e:
        logger.error(f"Error executing tool {name}: {e}", exc_info=True)
        return [types.TextContent(type="text", text=f"❌ Error: {str(e)}")]


async def main():
    """Main entry point"""
    logger.info("Starting PhoneInfoga MCP Server...")
    
    # Check if phoneinfoga is available
    binary = find_phoneinfoga()
    if binary:
        logger.info(f"Found phoneinfoga at: {binary}")
    else:
        logger.warning("phoneinfoga not found! Install with: brew install phoneinfoga")
    
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="phoneinfoga-mcp",
                server_version="1.0.0",
                capabilities=app.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())
