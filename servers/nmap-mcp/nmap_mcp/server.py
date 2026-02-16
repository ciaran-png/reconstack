#!/usr/bin/env python3
"""
NMAP MCP Server - Network scanning tools for OSINT investigations
"""

import subprocess
import json
import re
from typing import Optional
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("nmap")


def run_nmap(args: list[str], timeout: int = 300) -> dict:
    """Execute nmap with given arguments and return structured results."""
    cmd = ["nmap"] + args
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return {
            "success": True,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "return_code": result.returncode,
            "command": " ".join(cmd)
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": f"Scan timed out after {timeout} seconds",
            "command": " ".join(cmd)
        }
    except FileNotFoundError:
        return {
            "success": False,
            "error": "nmap not found. Install with: brew install nmap",
            "command": " ".join(cmd)
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "command": " ".join(cmd)
        }


@mcp.tool()
def nmap_list_scan(target: str) -> str:
    """
    List scan (-sL) - Enumerate hosts/IPs with reverse DNS lookup.
    Perfect for mapping IP ranges to hostnames without sending packets to targets.
    
    Args:
        target: IP, hostname, or CIDR range (e.g., "185.60.170.0/24")
    
    Returns:
        List of IPs and their resolved hostnames
    """
    result = run_nmap(["-sL", target], timeout=120)
    if result["success"]:
        # Parse the output to extract IP -> hostname mappings
        lines = result["stdout"].split("\n")
        hosts = []
        for line in lines:
            # Match lines like "Nmap scan report for hostname (IP)" or "Nmap scan report for IP"
            match = re.search(r'Nmap scan report for (.+?) \(([0-9.]+)\)', line)
            if match:
                hosts.append({"hostname": match.group(1), "ip": match.group(2)})
            else:
                match = re.search(r'Nmap scan report for ([0-9.]+)', line)
                if match:
                    hosts.append({"hostname": None, "ip": match.group(1)})
        
        return json.dumps({
            "success": True,
            "target": target,
            "hosts_found": len(hosts),
            "hosts": hosts,
            "raw_output": result["stdout"]
        }, indent=2)
    return json.dumps(result, indent=2)


@mcp.tool()
def nmap_ping_scan(target: str) -> str:
    """
    Ping scan (-sn) - Discover live hosts without port scanning.
    
    Args:
        target: IP, hostname, or CIDR range
    
    Returns:
        List of hosts that responded
    """
    result = run_nmap(["-sn", target], timeout=180)
    return json.dumps(result, indent=2)


@mcp.tool()
def nmap_quick_scan(target: str, ports: Optional[str] = None) -> str:
    """
    Quick port scan - Fast scan of common ports.
    
    Args:
        target: IP or hostname to scan
        ports: Optional port specification (e.g., "22,80,443" or "1-1000")
    
    Returns:
        Open ports and services
    """
    args = ["-T4", "-F", target]
    if ports:
        args = ["-T4", "-p", ports, target]
    result = run_nmap(args, timeout=120)
    return json.dumps(result, indent=2)


@mcp.tool()
def nmap_service_scan(target: str, ports: Optional[str] = None) -> str:
    """
    Service/version detection (-sV) - Identify services and versions on open ports.
    
    Args:
        target: IP or hostname to scan
        ports: Optional port specification
    
    Returns:
        Detailed service information
    """
    args = ["-sV", "--version-intensity", "5", target]
    if ports:
        args = ["-sV", "--version-intensity", "5", "-p", ports, target]
    result = run_nmap(args, timeout=300)
    return json.dumps(result, indent=2)


@mcp.tool()
def nmap_os_detect(target: str) -> str:
    """
    OS detection (-O) - Attempt to identify the operating system.
    Requires root/sudo privileges.
    
    Args:
        target: IP or hostname to scan
    
    Returns:
        OS detection results
    """
    result = run_nmap(["-O", "--osscan-guess", target], timeout=180)
    return json.dumps(result, indent=2)


@mcp.tool()
def nmap_full_scan(target: str) -> str:
    """
    Comprehensive scan - Service detection + OS detection + scripts.
    This is thorough but slow.
    
    Args:
        target: IP or hostname to scan
    
    Returns:
        Comprehensive scan results
    """
    result = run_nmap(["-A", "-T4", target], timeout=600)
    return json.dumps(result, indent=2)


@mcp.tool()
def nmap_vuln_scan(target: str, ports: Optional[str] = None) -> str:
    """
    Vulnerability scan - Run NSE vuln scripts against target.
    
    Args:
        target: IP or hostname to scan
        ports: Optional port specification
    
    Returns:
        Vulnerability scan results
    """
    args = ["--script", "vuln", target]
    if ports:
        args = ["--script", "vuln", "-p", ports, target]
    result = run_nmap(args, timeout=600)
    return json.dumps(result, indent=2)


@mcp.tool()
def nmap_dns_brute(domain: str) -> str:
    """
    DNS brute force - Discover subdomains using nmap's dns-brute script.
    
    Args:
        domain: Target domain (e.g., "example.com")
    
    Returns:
        Discovered subdomains
    """
    result = run_nmap(["--script", "dns-brute", domain], timeout=300)
    return json.dumps(result, indent=2)


@mcp.tool()
def nmap_http_enum(target: str, port: int = 80) -> str:
    """
    HTTP enumeration - Run HTTP discovery scripts against web server.
    
    Args:
        target: IP or hostname
        port: HTTP port (default 80)
    
    Returns:
        HTTP enumeration results (directories, methods, headers, etc.)
    """
    result = run_nmap([
        "--script", "http-enum,http-headers,http-methods,http-title",
        "-p", str(port),
        target
    ], timeout=180)
    return json.dumps(result, indent=2)


@mcp.tool()
def nmap_ssl_enum(target: str, port: int = 443) -> str:
    """
    SSL/TLS enumeration - Analyze SSL certificates and ciphers.
    
    Args:
        target: IP or hostname
        port: HTTPS port (default 443)
    
    Returns:
        SSL certificate info, supported ciphers, vulnerabilities
    """
    result = run_nmap([
        "--script", "ssl-cert,ssl-enum-ciphers,ssl-heartbleed",
        "-p", str(port),
        target
    ], timeout=180)
    return json.dumps(result, indent=2)


@mcp.tool()
def nmap_custom(target: str, args: str) -> str:
    """
    Custom nmap scan - Run nmap with custom arguments.
    
    Args:
        target: IP, hostname, or CIDR range
        args: Additional nmap arguments as a string (e.g., "-sS -T4 -p 1-1000")
    
    Returns:
        Scan results
    """
    arg_list = args.split() + [target]
    result = run_nmap(arg_list, timeout=600)
    return json.dumps(result, indent=2)


def main():
    mcp.run()


if __name__ == "__main__":
    main()
