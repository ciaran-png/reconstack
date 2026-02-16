#!/usr/bin/env python3
"""
ExifTool MCP Server - Document Metadata Extractor
Extract metadata from any file type (PDFs, images, Office docs).
Wraps the exiftool CLI.
"""

import asyncio
import json
import logging
import os
import subprocess
import shutil
import tempfile
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

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
logger = logging.getLogger("exiftool-mcp")


def find_exiftool() -> Optional[str]:
    """Find the exiftool binary"""
    locations = [
        shutil.which("exiftool"),
        "/usr/local/bin/exiftool",
        "/opt/homebrew/bin/exiftool",
        "/usr/bin/exiftool",
    ]
    
    for loc in locations:
        if loc and os.path.isfile(loc):
            return loc
    
    return None


def run_exiftool(args: List[str], timeout: int = 60) -> Dict[str, Any]:
    """Run exiftool CLI command"""
    binary = find_exiftool()
    
    if not binary:
        return {
            "success": False,
            "error": "exiftool not found. Install with: brew install exiftool"
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


def parse_exiftool_json(output: str) -> List[Dict[str, Any]]:
    """Parse exiftool JSON output"""
    try:
        data = json.loads(output)
        if isinstance(data, list):
            return data
        return [data]
    except json.JSONDecodeError:
        return []


def format_metadata(metadata: Dict[str, Any], interesting_only: bool = True) -> str:
    """Format metadata for display"""
    result = ""
    
    # Interesting fields for OSINT
    interesting_fields = {
        # Document Info
        "FileName": "File Name",
        "FileType": "File Type",
        "FileSize": "File Size",
        "CreateDate": "Created",
        "ModifyDate": "Modified",
        "FileModifyDate": "File Modified",
        
        # Author/Creator
        "Author": "Author",
        "Creator": "Creator",
        "LastModifiedBy": "Last Modified By",
        "Company": "Company",
        "Manager": "Manager",
        
        # Software
        "Software": "Software",
        "Producer": "Producer",
        "Application": "Application",
        "CreatorTool": "Creator Tool",
        "PDFProducer": "PDF Producer",
        
        # Location/GPS
        "GPSLatitude": "GPS Latitude",
        "GPSLongitude": "GPS Longitude",
        "GPSPosition": "GPS Position",
        "GPSAltitude": "GPS Altitude",
        "City": "City",
        "Country": "Country",
        "State": "State",
        
        # Camera/Device
        "Make": "Camera Make",
        "Model": "Camera Model",
        "SerialNumber": "Serial Number",
        "LensModel": "Lens",
        
        # Technical
        "Title": "Title",
        "Subject": "Subject",
        "Keywords": "Keywords",
        "Description": "Description",
        "Comment": "Comment",
        
        # Email/Office
        "Emails": "Emails Found",
        "UserName": "Username",
        "ComputerName": "Computer Name",
        "RevisionNumber": "Revision Number",
        "TotalEditTime": "Total Edit Time",
        
        # PDF specific
        "PDFVersion": "PDF Version",
        "PageCount": "Page Count",
        "Linearized": "Linearized",
        
        # XMP
        "XMPToolkit": "XMP Toolkit",
        "CreatorWorkURL": "Creator URL",
        "CreatorWorkEmail": "Creator Email",
    }
    
    # Basic file info
    basic = []
    author_info = []
    software_info = []
    location_info = []
    other_interesting = []
    
    for key, label in interesting_fields.items():
        if key in metadata:
            value = metadata[key]
            if value and str(value).strip():
                item = f"  {label}: {value}"
                
                if key in ["FileName", "FileType", "FileSize", "CreateDate", "ModifyDate"]:
                    basic.append(item)
                elif key in ["Author", "Creator", "LastModifiedBy", "Company", "Manager", "UserName", "ComputerName"]:
                    author_info.append(item)
                elif key in ["Software", "Producer", "Application", "CreatorTool", "PDFProducer", "XMPToolkit"]:
                    software_info.append(item)
                elif "GPS" in key or key in ["City", "Country", "State"]:
                    location_info.append(item)
                else:
                    other_interesting.append(item)
    
    if basic:
        result += "**File Info:**\n" + "\n".join(basic) + "\n\n"
    
    if author_info:
        result += "**Author/Creator Info (OSINT Gold!):**\n" + "\n".join(author_info) + "\n\n"
    
    if software_info:
        result += "**Software Used:**\n" + "\n".join(software_info) + "\n\n"
    
    if location_info:
        result += "**📍 Location Data:**\n" + "\n".join(location_info) + "\n\n"
    
    if other_interesting:
        result += "**Other Metadata:**\n" + "\n".join(other_interesting) + "\n\n"
    
    if not interesting_only:
        # Include all remaining fields
        remaining = []
        for key, value in metadata.items():
            if key not in interesting_fields and value and str(value).strip():
                # Skip some noisy fields
                if key.startswith("File") and key not in interesting_fields:
                    continue
                if key.startswith("Source"):
                    continue
                if key.startswith("Directory"):
                    continue
                remaining.append(f"  {key}: {value}")
        
        if remaining:
            result += "**All Other Fields:**\n" + "\n".join(remaining[:50]) + "\n"
            if len(remaining) > 50:
                result += f"  ... and {len(remaining) - 50} more fields\n"
    
    return result


async def download_file(url: str, timeout: int = 60) -> Optional[str]:
    """Download a file from URL to temp directory"""
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            response = await client.get(url)
            
            if response.status_code != 200:
                return None
            
            # Get filename from URL or content-disposition
            filename = os.path.basename(urlparse(url).path) or "downloaded_file"
            
            # Create temp file
            temp_dir = tempfile.mkdtemp()
            temp_path = os.path.join(temp_dir, filename)
            
            with open(temp_path, "wb") as f:
                f.write(response.content)
            
            return temp_path
    
    except Exception as e:
        logger.error(f"Error downloading file: {e}")
        return None


# Initialize MCP server
app = Server("exiftool-mcp")
logger.info("Initializing ExifTool MCP Server")


@app.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List available metadata extraction tools - TRIMMED for efficiency"""
    return [
        types.Tool(
            name="exiftool_extract",
            description="Extract metadata from a local file. Reveals author names, software versions, GPS coordinates, timestamps, and more.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the file to analyze"
                    },
                    "all_fields": {
                        "type": "boolean",
                        "description": "Show all metadata fields (not just interesting ones)",
                        "default": False
                    }
                },
                "required": ["file_path"]
            }
        ),
        # DISABLED: exiftool_extract_url, exiftool_batch, exiftool_gps
        # Use download_and_extract_pdf for URLs, or download first then use exiftool_extract
    ]


@app.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """Execute ExifTool tools"""
    
    try:
        if name == "exiftool_extract":
            file_path = arguments.get("file_path", "").strip()
            all_fields = arguments.get("all_fields", False)
            
            if not file_path:
                return [types.TextContent(type="text", text="❌ File path is required!")]
            
            if not os.path.exists(file_path):
                return [types.TextContent(type="text", text=f"❌ File not found: {file_path}")]
            
            logger.info(f"Extracting metadata from: {file_path}")
            
            # Run exiftool with JSON output
            result = run_exiftool(["-json", "-a", "-G1", file_path])
            
            if not result.get("success"):
                return [types.TextContent(type="text", text=f"❌ Extraction failed: {result.get('error', result.get('stderr', 'Unknown error'))}")]
            
            metadata_list = parse_exiftool_json(result.get("stdout", ""))
            
            if not metadata_list:
                return [types.TextContent(type="text", text="❌ Could not parse metadata output")]
            
            metadata = metadata_list[0]
            
            response_text = f"""📄 **Document Metadata Extraction**

**File:** `{os.path.basename(file_path)}`

{format_metadata(metadata, interesting_only=not all_fields)}"""
            
            # OSINT highlights
            osint_finds = []
            if metadata.get("Author"):
                osint_finds.append(f"Author: {metadata['Author']}")
            if metadata.get("Creator"):
                osint_finds.append(f"Creator: {metadata['Creator']}")
            if metadata.get("Company"):
                osint_finds.append(f"Company: {metadata['Company']}")
            if metadata.get("GPSPosition"):
                osint_finds.append(f"GPS: {metadata['GPSPosition']}")
            if metadata.get("Software"):
                osint_finds.append(f"Software: {metadata['Software']}")
            
            if osint_finds:
                response_text += "\n**🎯 Key OSINT Findings:**\n"
                for find in osint_finds:
                    response_text += f"  • {find}\n"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "exiftool_extract_url":
            url = arguments.get("url", "").strip()
            all_fields = arguments.get("all_fields", False)
            
            if not url:
                return [types.TextContent(type="text", text="❌ URL is required!")]
            
            logger.info(f"Downloading file from: {url}")
            
            temp_path = await download_file(url)
            
            if not temp_path:
                return [types.TextContent(type="text", text=f"❌ Failed to download file from URL")]
            
            try:
                logger.info(f"Extracting metadata from downloaded file: {temp_path}")
                
                result = run_exiftool(["-json", "-a", "-G1", temp_path])
                
                if not result.get("success"):
                    return [types.TextContent(type="text", text=f"❌ Extraction failed: {result.get('error', 'Unknown error')}")]
                
                metadata_list = parse_exiftool_json(result.get("stdout", ""))
                
                if not metadata_list:
                    return [types.TextContent(type="text", text="❌ Could not parse metadata output")]
                
                metadata = metadata_list[0]
                
                response_text = f"""📄 **Document Metadata Extraction (from URL)**

**URL:** `{url}`
**Downloaded as:** `{os.path.basename(temp_path)}`

{format_metadata(metadata, interesting_only=not all_fields)}"""
                
                return [types.TextContent(type="text", text=response_text)]
            
            finally:
                # Cleanup
                try:
                    os.unlink(temp_path)
                    os.rmdir(os.path.dirname(temp_path))
                except:
                    pass
        
        elif name == "exiftool_batch":
            directory = arguments.get("directory", "").strip()
            recursive = arguments.get("recursive", False)
            file_types = arguments.get("file_types", [])
            
            if not directory:
                return [types.TextContent(type="text", text="❌ Directory path is required!")]
            
            if not os.path.isdir(directory):
                return [types.TextContent(type="text", text=f"❌ Directory not found: {directory}")]
            
            logger.info(f"Batch extracting from: {directory}")
            
            # Build exiftool command
            args = ["-json", "-a"]
            
            if recursive:
                args.append("-r")
            
            args.append(directory)
            
            result = run_exiftool(args, timeout=300)  # 5 min for batch
            
            if not result.get("success"):
                return [types.TextContent(type="text", text=f"❌ Batch extraction failed: {result.get('error', 'Unknown error')}")]
            
            metadata_list = parse_exiftool_json(result.get("stdout", ""))
            
            # Filter by file types if specified
            if file_types:
                file_types_lower = [ft.lower().lstrip('.') for ft in file_types]
                metadata_list = [
                    m for m in metadata_list 
                    if m.get("FileType", "").lower() in file_types_lower
                ]
            
            response_text = f"""📁 **Batch Metadata Extraction**

**Directory:** `{directory}`
**Recursive:** {recursive}
**Files Analyzed:** {len(metadata_list)}

"""
            
            if metadata_list:
                # Collect all unique authors/creators
                authors = set()
                companies = set()
                software = set()
                
                for m in metadata_list:
                    if m.get("Author"):
                        authors.add(m["Author"])
                    if m.get("Creator"):
                        authors.add(m["Creator"])
                    if m.get("LastModifiedBy"):
                        authors.add(m["LastModifiedBy"])
                    if m.get("Company"):
                        companies.add(m["Company"])
                    if m.get("Software"):
                        software.add(str(m["Software"]))
                    if m.get("Producer"):
                        software.add(str(m["Producer"]))
                
                if authors:
                    response_text += "**👤 Unique Authors/Creators Found:**\n"
                    for author in sorted(authors):
                        response_text += f"  - {author}\n"
                    response_text += "\n"
                
                if companies:
                    response_text += "**🏢 Companies Found:**\n"
                    for company in sorted(companies):
                        response_text += f"  - {company}\n"
                    response_text += "\n"
                
                if software:
                    response_text += "**💻 Software Used:**\n"
                    for sw in sorted(software)[:10]:
                        response_text += f"  - {sw}\n"
                    response_text += "\n"
                
                # File breakdown
                response_text += "**Files by Type:**\n"
                type_counts = {}
                for m in metadata_list:
                    ft = m.get("FileType", "Unknown")
                    type_counts[ft] = type_counts.get(ft, 0) + 1
                
                for ft, count in sorted(type_counts.items(), key=lambda x: -x[1]):
                    response_text += f"  - {ft}: {count}\n"
            else:
                response_text += "**No files found matching criteria.**"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "exiftool_gps":
            file_path = arguments.get("file_path", "").strip()
            
            if not file_path:
                return [types.TextContent(type="text", text="❌ File path is required!")]
            
            if not os.path.exists(file_path):
                return [types.TextContent(type="text", text=f"❌ File not found: {file_path}")]
            
            logger.info(f"Extracting GPS from: {file_path}")
            
            # Extract only GPS-related tags
            result = run_exiftool(["-json", "-gps*", "-location*", file_path])
            
            if not result.get("success"):
                return [types.TextContent(type="text", text=f"❌ Extraction failed: {result.get('error', 'Unknown error')}")]
            
            metadata_list = parse_exiftool_json(result.get("stdout", ""))
            
            if not metadata_list:
                return [types.TextContent(type="text", text="❌ Could not parse GPS data")]
            
            metadata = metadata_list[0]
            
            response_text = f"""📍 **GPS Location Extraction**

**File:** `{os.path.basename(file_path)}`

"""
            
            # Check for GPS data
            lat = metadata.get("GPSLatitude")
            lon = metadata.get("GPSLongitude")
            pos = metadata.get("GPSPosition")
            
            if pos or (lat and lon):
                response_text += "**Location Found!**\n"
                
                if lat:
                    response_text += f"  Latitude: {lat}\n"
                if lon:
                    response_text += f"  Longitude: {lon}\n"
                if pos:
                    response_text += f"  Position: {pos}\n"
                
                if metadata.get("GPSAltitude"):
                    response_text += f"  Altitude: {metadata['GPSAltitude']}\n"
                
                if metadata.get("GPSDateTime"):
                    response_text += f"  GPS Time: {metadata['GPSDateTime']}\n"
                
                # Try to parse coordinates for map link
                try:
                    # Parse decimal coordinates from position string
                    if pos:
                        # Format: "41 deg 24' 12.20\" N, 2 deg 10' 26.50\" E"
                        import re
                        coords = re.findall(r'([\d.]+)', str(pos))
                        if len(coords) >= 4:
                            # Rough conversion (not accurate but gives idea)
                            lat_dec = float(coords[0]) + float(coords[1])/60 + float(coords[2])/3600
                            lon_dec = float(coords[3]) + float(coords[4])/60 + float(coords[5])/3600 if len(coords) >= 6 else float(coords[3])
                            
                            # Check for S/W
                            if "S" in str(pos):
                                lat_dec = -lat_dec
                            if "W" in str(pos):
                                lon_dec = -lon_dec
                            
                            response_text += f"\n**🗺️ Map Links:**\n"
                            response_text += f"  [Google Maps](https://www.google.com/maps?q={lat_dec},{lon_dec})\n"
                            response_text += f"  [OpenStreetMap](https://www.openstreetmap.org/?mlat={lat_dec}&mlon={lon_dec}&zoom=15)\n"
                except Exception as e:
                    logger.debug(f"Could not parse coordinates: {e}")
            else:
                response_text += "**No GPS data found in this file.**\n"
                response_text += "\n💡 GPS data is typically found in photos taken with phones or cameras with location services enabled."
            
            return [types.TextContent(type="text", text=response_text)]
        
        else:
            return [types.TextContent(type="text", text=f"❌ Unknown tool: {name}")]
    
    except Exception as e:
        logger.error(f"Error executing tool {name}: {e}", exc_info=True)
        return [types.TextContent(type="text", text=f"❌ Error: {str(e)}")]


async def main():
    """Main entry point"""
    logger.info("Starting ExifTool MCP Server...")
    
    binary = find_exiftool()
    if binary:
        logger.info(f"Found exiftool at: {binary}")
    else:
        logger.warning("exiftool not found! Install with: brew install exiftool")
    
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="exiftool-mcp",
                server_version="1.0.0",
                capabilities=app.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())
