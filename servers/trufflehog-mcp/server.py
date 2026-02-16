#!/usr/bin/env python3
"""
TruffleHog MCP Server - Git Secrets Scanner
Scans git repositories for leaked secrets, API keys, credentials.
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
logger = logging.getLogger("trufflehog-mcp")


def find_trufflehog() -> Optional[str]:
    """Find the trufflehog binary"""
    locations = [
        shutil.which("trufflehog"),
        "/usr/local/bin/trufflehog",
        "/opt/homebrew/bin/trufflehog",
        os.path.expanduser("~/go/bin/trufflehog"),
    ]
    
    for loc in locations:
        if loc and os.path.isfile(loc):
            return loc
    
    return None


def run_trufflehog(args: List[str], timeout: int = 300) -> Dict[str, Any]:
    """Run trufflehog CLI command"""
    binary = find_trufflehog()
    
    if not binary:
        return {
            "success": False,
            "error": "trufflehog not found. Install with: brew install trufflehog"
        }
    
    try:
        # Always output JSON for parsing
        full_args = [binary] + args + ["--json"]
        
        result = subprocess.run(
            full_args,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        return {
            "success": True,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        }
    
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"Scan timed out after {timeout} seconds"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def parse_trufflehog_json(output: str) -> List[Dict[str, Any]]:
    """Parse trufflehog JSON output (newline-delimited JSON)"""
    secrets = []
    
    for line in output.strip().split('\n'):
        if not line.strip():
            continue
        try:
            secret = json.loads(line)
            secrets.append(secret)
        except json.JSONDecodeError:
            continue
    
    return secrets


def format_secret_finding(secret: Dict[str, Any]) -> str:
    """Format a single secret finding for display"""
    result = ""
    
    detector = secret.get("DetectorName", secret.get("detectorName", "Unknown"))
    verified = secret.get("Verified", secret.get("verified", False))
    raw = secret.get("Raw", secret.get("raw", ""))
    
    # Source info
    source_meta = secret.get("SourceMetadata", secret.get("sourceMetadata", {}))
    data = source_meta.get("Data", source_meta.get("data", {}))
    
    # Git source info
    git_info = data.get("Git", data.get("git", {}))
    file_path = git_info.get("file", "Unknown")
    commit = git_info.get("commit", "")[:8] if git_info.get("commit") else "N/A"
    repo = git_info.get("repository", "")
    
    # Redact the actual secret value for safety
    redacted = raw[:4] + "..." + raw[-4:] if len(raw) > 10 else "[REDACTED]"
    
    result += f"""
**🔑 {detector}** {'✅ VERIFIED' if verified else '⚠️ Unverified'}
  File: `{file_path}`
  Commit: `{commit}`
  Secret: `{redacted}`
"""
    
    if repo:
        result += f"  Repository: {repo}\n"
    
    return result


# Initialize MCP server
app = Server("trufflehog-mcp")
logger.info("Initializing TruffleHog Secrets Scanner MCP Server")


@app.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List available secrets scanning tools - TRIMMED for efficiency"""
    return [
        types.Tool(
            name="trufflehog_scan",
            description="Scan a git repository URL for leaked secrets, API keys, and credentials. Checks entire git history.",
            inputSchema={
                "type": "object",
                "properties": {
                    "repo_url": {
                        "type": "string",
                        "description": "Git repository URL (e.g., 'https://github.com/org/repo')"
                    },
                    "only_verified": {
                        "type": "boolean",
                        "description": "Only return verified (confirmed active) secrets",
                        "default": False
                    },
                    "max_depth": {
                        "type": "integer",
                        "description": "Maximum commit depth to scan (default: unlimited)",
                        "default": 0
                    }
                },
                "required": ["repo_url"]
            }
        ),
        # DISABLED: trufflehog_github_org, trufflehog_github_user, trufflehog_filesystem
    ]


@app.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """Execute TruffleHog scanning tools"""
    
    try:
        if name == "trufflehog_scan" or name == "trufflehog_git":  # Support both names
            repo_url = arguments.get("repo_url", "").strip()
            only_verified = arguments.get("only_verified", False)
            max_depth = arguments.get("max_depth", 0)
            
            if not repo_url:
                return [types.TextContent(type="text", text="❌ Repository URL is required!")]
            
            logger.info(f"Scanning git repo: {repo_url}")
            
            args = ["git", repo_url]
            if only_verified:
                args.append("--only-verified")
            if max_depth > 0:
                args.extend(["--max-depth", str(max_depth)])
            
            result = run_trufflehog(args, timeout=600)  # 10 min timeout for large repos
            
            if not result.get("success"):
                return [types.TextContent(type="text", text=f"❌ Scan failed: {result.get('error')}")]
            
            secrets = parse_trufflehog_json(result.get("stdout", ""))
            
            response_text = f"""🔍 **TruffleHog Git Scan Results**

**Repository:** `{repo_url}`
**Only Verified:** {only_verified}
**Secrets Found:** {len(secrets)}

"""
            
            if secrets:
                verified_count = sum(1 for s in secrets if s.get("Verified", s.get("verified", False)))
                response_text += f"**Verified Secrets:** {verified_count}\n\n"
                
                # Group by detector type
                by_type = {}
                for secret in secrets:
                    detector = secret.get("DetectorName", secret.get("detectorName", "Unknown"))
                    if detector not in by_type:
                        by_type[detector] = []
                    by_type[detector].append(secret)
                
                response_text += "**Findings by Type:**\n"
                for detector, findings in sorted(by_type.items(), key=lambda x: -len(x[1])):
                    response_text += f"  - {detector}: {len(findings)}\n"
                
                response_text += "\n**Secret Details:**\n"
                
                # Show first 20 secrets
                for secret in secrets[:20]:
                    response_text += format_secret_finding(secret)
                
                if len(secrets) > 20:
                    response_text += f"\n... and {len(secrets) - 20} more secrets found."
            else:
                response_text += "**✅ No secrets found in this repository.**"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "trufflehog_github_org":
            org_name = arguments.get("org_name", "").strip()
            only_verified = arguments.get("only_verified", True)
            
            if not org_name:
                return [types.TextContent(type="text", text="❌ Organization name is required!")]
            
            logger.info(f"Scanning GitHub org: {org_name}")
            
            args = ["github", "--org", org_name]
            if only_verified:
                args.append("--only-verified")
            
            result = run_trufflehog(args, timeout=1800)  # 30 min for orgs
            
            if not result.get("success"):
                return [types.TextContent(type="text", text=f"❌ Scan failed: {result.get('error')}")]
            
            secrets = parse_trufflehog_json(result.get("stdout", ""))
            
            response_text = f"""🏢 **TruffleHog GitHub Organization Scan**

**Organization:** `{org_name}`
**Secrets Found:** {len(secrets)}

"""
            
            if secrets:
                # Group by repository
                by_repo = {}
                for secret in secrets:
                    source = secret.get("SourceMetadata", {}).get("Data", {}).get("Git", {})
                    repo = source.get("repository", "Unknown")
                    if repo not in by_repo:
                        by_repo[repo] = []
                    by_repo[repo].append(secret)
                
                response_text += "**Findings by Repository:**\n"
                for repo, findings in sorted(by_repo.items(), key=lambda x: -len(x[1])):
                    response_text += f"  - {repo}: {len(findings)} secrets\n"
                
                response_text += "\n**Top Findings:**\n"
                for secret in secrets[:15]:
                    response_text += format_secret_finding(secret)
            else:
                response_text += "**✅ No verified secrets found in this organization's public repos.**"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "trufflehog_github_user":
            username = arguments.get("username", "").strip()
            only_verified = arguments.get("only_verified", False)
            
            if not username:
                return [types.TextContent(type="text", text="❌ GitHub username is required!")]
            
            logger.info(f"Scanning GitHub user: {username}")
            
            # Scan user's repos via github endpoint
            args = ["github", "--repo", f"https://github.com/{username}"]
            if only_verified:
                args.append("--only-verified")
            
            result = run_trufflehog(args, timeout=900)  # 15 min
            
            if not result.get("success"):
                return [types.TextContent(type="text", text=f"❌ Scan failed: {result.get('error')}")]
            
            secrets = parse_trufflehog_json(result.get("stdout", ""))
            
            response_text = f"""👤 **TruffleHog GitHub User Scan**

**User:** `{username}`
**Secrets Found:** {len(secrets)}

"""
            
            if secrets:
                for secret in secrets[:15]:
                    response_text += format_secret_finding(secret)
            else:
                response_text += "**✅ No secrets found in this user's public repositories.**"
            
            return [types.TextContent(type="text", text=response_text)]
        
        elif name == "trufflehog_filesystem":
            path = arguments.get("path", "").strip()
            only_verified = arguments.get("only_verified", False)
            
            if not path:
                return [types.TextContent(type="text", text="❌ Path is required!")]
            
            if not os.path.exists(path):
                return [types.TextContent(type="text", text=f"❌ Path does not exist: {path}")]
            
            logger.info(f"Scanning filesystem: {path}")
            
            args = ["filesystem", path]
            if only_verified:
                args.append("--only-verified")
            
            result = run_trufflehog(args, timeout=600)
            
            if not result.get("success"):
                return [types.TextContent(type="text", text=f"❌ Scan failed: {result.get('error')}")]
            
            secrets = parse_trufflehog_json(result.get("stdout", ""))
            
            response_text = f"""📁 **TruffleHog Filesystem Scan**

**Path:** `{path}`
**Secrets Found:** {len(secrets)}

"""
            
            if secrets:
                for secret in secrets[:20]:
                    response_text += format_secret_finding(secret)
            else:
                response_text += "**✅ No secrets found in this directory.**"
            
            return [types.TextContent(type="text", text=response_text)]
        
        else:
            return [types.TextContent(type="text", text=f"❌ Unknown tool: {name}")]
    
    except Exception as e:
        logger.error(f"Error executing tool {name}: {e}", exc_info=True)
        return [types.TextContent(type="text", text=f"❌ Error: {str(e)}")]


async def main():
    """Main entry point"""
    logger.info("Starting TruffleHog MCP Server...")
    
    binary = find_trufflehog()
    if binary:
        logger.info(f"Found trufflehog at: {binary}")
    else:
        logger.warning("trufflehog not found! Install with: brew install trufflehog")
    
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="trufflehog-mcp",
                server_version="1.0.0",
                capabilities=app.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())
