#!/usr/bin/env python3
"""
DNSlytics MCP Server

A Model Context Protocol server for interacting with DNSlytics - the ultimate 
online investigation tool for domains, IPs, and tracking codes.

Supports:
- Domain lookups and search
- IP address analysis  
- Reverse lookups (Adsense, Analytics, IP, MX, NS, SPF)
- AS/BGP information
- Hosting history
- Subdomain discovery
- Tracking code lookups (Google Analytics, Adsense, Tag Manager, Facebook Pixel, etc.)

"""

import os
import json
import re
from typing import Optional, List, Dict, Any
from enum import Enum

import httpx
from bs4 import BeautifulSoup
from pydantic import BaseModel, Field, ConfigDict
from mcp.server.fastmcp import FastMCP

# Initialize MCP server
mcp = FastMCP("dnslytics_mcp")

# Constants
SEARCH_BASE_URL = "https://search.dnslytics.com"
DEFAULT_TIMEOUT = 30.0


class ResponseFormat(str, Enum):
    """Output format for tool responses."""
    MARKDOWN = "markdown"
    JSON = "json"


# ============================================================================
# Pydantic Input Models
# ============================================================================

class DomainInput(BaseModel):
    """Input for domain-based lookups."""
    model_config = ConfigDict(str_strip_whitespace=True)
    
    domain: str = Field(
        ..., 
        description="Domain name to lookup (e.g., 'google.com', 'example.org')",
        min_length=1,
        max_length=255
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for readable or 'json' for structured"
    )


class IPInput(BaseModel):
    """Input for IP address lookups."""
    model_config = ConfigDict(str_strip_whitespace=True)
    
    ip: str = Field(
        ...,
        description="IPv4 or IPv6 address to lookup (e.g., '8.8.8.8', '2001:4860:4860::8888')",
        min_length=1
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for readable or 'json' for structured"
    )


class ASNInput(BaseModel):
    """Input for ASN/BGP lookups."""
    model_config = ConfigDict(str_strip_whitespace=True)
    
    asn: str = Field(
        ...,
        description="AS number (e.g., 'AS15169', '15169', 'as15169')",
        min_length=1
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for readable or 'json' for structured"
    )


class SearchInput(BaseModel):
    """Input for general search."""
    model_config = ConfigDict(str_strip_whitespace=True)
    
    query: str = Field(
        ...,
        description="Search query - can be domain, IP, provider name, or keywords",
        min_length=1,
        max_length=500
    )
    search_type: Optional[str] = Field(
        default=None,
        description="Type of search: 'domains', 'ips', 'providers', or None for all"
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for readable or 'json' for structured"
    )


class TrackingCodeInput(BaseModel):
    """Input for tracking code lookups (Analytics, Adsense, GTM, etc.)."""
    model_config = ConfigDict(str_strip_whitespace=True)
    
    code: str = Field(
        ...,
        description="Tracking code ID (e.g., 'UA-12345-1', 'G-XXXXXXX', 'pub-1234567890', 'GTM-XXXX')",
        min_length=1
    )
    code_type: Optional[str] = Field(
        default=None,
        description="Type of code: 'analytics', 'adsense', 'gtm', 'ga4', 'fbpixel', or None for auto-detect"
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for readable or 'json' for structured"
    )


class ReverseInput(BaseModel):
    """Input for reverse lookups."""
    model_config = ConfigDict(str_strip_whitespace=True)
    
    value: str = Field(
        ...,
        description="Value to reverse lookup (IP, MX hostname, NS hostname, etc.)",
        min_length=1
    )
    limit: int = Field(
        default=100,
        description="Maximum number of results to return",
        ge=1,
        le=1000
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for readable or 'json' for structured"
    )


class HostingHistoryInput(BaseModel):
    """Input for hosting history lookups."""
    model_config = ConfigDict(str_strip_whitespace=True)
    
    domain: str = Field(
        ...,
        description="Domain name to get hosting history for",
        min_length=1,
        max_length=255
    )
    record_type: Optional[str] = Field(
        default=None,
        description="Record type: 'a', 'aaaa', 'mx', 'ns', 'spf', or None for all"
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for readable or 'json' for structured"
    )


class SubdomainInput(BaseModel):
    """Input for subdomain discovery."""
    model_config = ConfigDict(str_strip_whitespace=True)
    
    domain: str = Field(
        ...,
        description="Domain name to find subdomains for",
        min_length=1,
        max_length=255
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for readable or 'json' for structured"
    )


class DomainSearchInput(BaseModel):
    """Input for domain keyword search."""
    model_config = ConfigDict(str_strip_whitespace=True)
    
    keyword: str = Field(
        ...,
        description="Keyword(s) to search for in domain names",
        min_length=1,
        max_length=100
    )
    tld: Optional[str] = Field(
        default=None,
        description="Filter by TLD (e.g., 'com', 'org', 'net')"
    )
    limit: int = Field(
        default=100,
        description="Maximum results to return",
        ge=1,
        le=1000
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for readable or 'json' for structured"
    )


class SubnetInput(BaseModel):
    """Input for subnet/CIDR lookups."""
    model_config = ConfigDict(str_strip_whitespace=True)
    
    cidr: str = Field(
        ...,
        description="CIDR notation (e.g., '8.8.8.0/24', '2001:4860::/32')",
        min_length=1
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for readable or 'json' for structured"
    )


# ============================================================================
# HTTP Client Helpers
# ============================================================================

async def scrape_search_page(
    path: str,
    params: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Scrape the DNSlytics search interface for data."""
    url = f"{SEARCH_BASE_URL}/{path}"
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }
    
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, follow_redirects=True) as client:
        try:
            response = await client.get(url, params=params, headers=headers)
            response.raise_for_status()
            return {"html": response.text, "url": str(response.url)}
        except httpx.HTTPStatusError as e:
            return {"error": f"HTTP error: {e.response.status_code}"}
        except httpx.TimeoutException:
            return {"error": "Request timed out"}
        except Exception as e:
            return {"error": f"Request failed: {str(e)}"}


def parse_search_results(html: str) -> List[Dict[str, Any]]:
    """Parse search results from DNSlytics HTML."""
    soup = BeautifulSoup(html, 'html.parser')
    results = []
    
    # Parse table results (common format)
    for table in soup.find_all('table', class_='table'):
        for row in table.find_all('tr')[1:]:  # Skip header
            cells = row.find_all(['td', 'th'])
            if cells:
                result = {}
                for i, cell in enumerate(cells):
                    link = cell.find('a')
                    if link:
                        result[f'col_{i}'] = {
                            'text': link.get_text(strip=True),
                            'href': link.get('href', '')
                        }
                    else:
                        result[f'col_{i}'] = cell.get_text(strip=True)
                if result:
                    results.append(result)
    
    # Parse card/list results
    for card in soup.find_all(['div', 'li'], class_=['result', 'card', 'list-group-item']):
        result = {'text': card.get_text(strip=True)[:500]}
        links = card.find_all('a')
        if links:
            result['links'] = [{'text': a.get_text(strip=True), 'href': a.get('href', '')} for a in links[:5]]
        results.append(result)
    
    return results[:100]  # Limit results


def parse_domain_info(html: str) -> Dict[str, Any]:
    """Parse domain information page."""
    soup = BeautifulSoup(html, 'html.parser')
    info = {}
    
    # Get page title/header
    h1 = soup.find('h1')
    if h1:
        info['title'] = h1.get_text(strip=True)
    
    # Parse key-value pairs from tables
    for table in soup.find_all('table'):
        for row in table.find_all('tr'):
            cells = row.find_all(['td', 'th'])
            if len(cells) >= 2:
                key = cells[0].get_text(strip=True).rstrip(':').lower().replace(' ', '_')
                value = cells[1].get_text(strip=True)
                if key and value:
                    info[key] = value
    
    # Parse sections
    for section in soup.find_all(['div', 'section'], class_=['card', 'panel', 'section']):
        header = section.find(['h2', 'h3', 'h4', '.card-header'])
        if header:
            section_name = header.get_text(strip=True).lower().replace(' ', '_')
            content = section.get_text(strip=True)
            if len(content) < 2000:
                info[section_name] = content
    
    return info


def detect_tracking_code_type(code: str) -> str:
    """Auto-detect the type of tracking code."""
    code_upper = code.upper().strip()
    
    if code_upper.startswith('UA-') or code_upper.startswith('UA '):
        return 'analytics'
    elif code_upper.startswith('G-'):
        return 'ga4'
    elif code_upper.startswith('GTM-'):
        return 'gtm'
    elif code_upper.startswith('PUB-') or code_upper.startswith('CA-PUB-'):
        return 'adsense'
    elif code_upper.isdigit() and len(code) > 10:
        return 'fbpixel'
    elif re.match(r'^AW-\d+$', code_upper):
        return 'google_ads'
    else:
        return 'unknown'


def format_results_markdown(data: Dict[str, Any], title: str = "Results") -> str:
    """Format results as markdown."""
    lines = [f"## {title}\n"]
    
    if "error" in data:
        return f"## Error\n\n{data['error']}"
    
    def format_value(v: Any, indent: int = 0) -> str:
        prefix = "  " * indent
        if isinstance(v, dict):
            items = []
            for k, val in v.items():
                items.append(f"{prefix}- **{k}**: {format_value(val, indent + 1)}")
            return "\n" + "\n".join(items)
        elif isinstance(v, list):
            if not v:
                return "_empty_"
            items = []
            for item in v[:20]:  # Limit list items
                items.append(f"{prefix}- {format_value(item, indent + 1)}")
            result = "\n" + "\n".join(items)
            if len(v) > 20:
                result += f"\n{prefix}  _...and {len(v) - 20} more_"
            return result
        else:
            return str(v)
    
    for key, value in data.items():
        if key in ['html', 'url']:
            continue
        lines.append(f"**{key.replace('_', ' ').title()}**: {format_value(value)}\n")
    
    return "\n".join(lines)


# ============================================================================
# MCP Tools
# ============================================================================



@mcp.tool(
    name="dnslytics_domain_info",
    annotations={
        "title": "Domain Information Lookup",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def dnslytics_domain_info(params: DomainInput) -> str:
    """Get comprehensive information about a domain name.
    
    Returns DNS records, WHOIS data, hosting info, associated tracking codes,
    and related domains. Perfect for investigating website ownership and infrastructure.
    
    Args:
        params: DomainInput with domain name and response format
    
    Returns:
        Domain information including DNS, hosting, tracking codes, and more
    """
    result = await scrape_search_page(f"domain/{params.domain}")
    
    if "error" in result:
        return json.dumps(result) if params.response_format == ResponseFormat.JSON else result["error"]
    
    info = parse_domain_info(result["html"])
    info["lookup_url"] = result["url"]
    
    if params.response_format == ResponseFormat.JSON:
        return json.dumps(info, indent=2)
    return format_results_markdown(info, f"Domain: {params.domain}")


@mcp.tool(
    name="dnslytics_ip_info",
    annotations={
        "title": "IP Address Information",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def dnslytics_ip_info(params: IPInput) -> str:
    """Get comprehensive information about an IP address.
    
    Returns geolocation, ASN, reverse DNS, hosted domains, reputation,
    and network information. Supports both IPv4 and IPv6.
    
    Args:
        params: IPInput with IP address and response format
    
    Returns:
        IP information including location, network, hosted domains, and more
    """
    result = await scrape_search_page(f"ip/{params.ip}")
    
    if "error" in result:
        return json.dumps(result) if params.response_format == ResponseFormat.JSON else result["error"]
    
    info = parse_domain_info(result["html"])
    info["lookup_url"] = result["url"]
    
    if params.response_format == ResponseFormat.JSON:
        return json.dumps(info, indent=2)
    return format_results_markdown(info, f"IP: {params.ip}")


@mcp.tool(
    name="dnslytics_asn_info",
    annotations={
        "title": "ASN/BGP Information",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def dnslytics_asn_info(params: ASNInput) -> str:
    """Get information about an Autonomous System Number (ASN).
    
    Returns organization name, country, IP prefixes, peer ASNs,
    and network statistics. Useful for network infrastructure analysis.
    
    Args:
        params: ASNInput with ASN number and response format
    
    Returns:
        ASN information including organization, prefixes, peers, and statistics
    """
    # Normalize ASN format
    asn = params.asn.upper().replace('AS', '').strip()
    
    result = await scrape_search_page(f"bgp/as{asn}")
    
    if "error" in result:
        return json.dumps(result) if params.response_format == ResponseFormat.JSON else result["error"]
    
    info = parse_domain_info(result["html"])
    info["lookup_url"] = result["url"]
    
    if params.response_format == ResponseFormat.JSON:
        return json.dumps(info, indent=2)
    return format_results_markdown(info, f"ASN: AS{asn}")


@mcp.tool(
    name="dnslytics_search",
    annotations={
        "title": "DNSlytics Search",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def dnslytics_search(params: SearchInput) -> str:
    """Search DNSlytics for domains, IPs, providers, or any keyword.
    
    The main search interface supports various query types:
    - Domain names (google.com)
    - IP addresses (8.8.8.8)  
    - Provider/organization names (Cloudflare)
    - Keywords (crypto, bank, etc.)
    - Tracking codes
    
    Args:
        params: SearchInput with query, optional search type, and response format
    
    Returns:
        Search results with matching domains, IPs, or other entities
    """
    search_params = {"q": params.query}
    if params.search_type:
        search_params["d"] = params.search_type
    
    result = await scrape_search_page("search", search_params)
    
    if "error" in result:
        return json.dumps(result) if params.response_format == ResponseFormat.JSON else result["error"]
    
    results = parse_search_results(result["html"])
    data = {
        "query": params.query,
        "result_count": len(results),
        "results": results,
        "search_url": result["url"]
    }
    
    if params.response_format == ResponseFormat.JSON:
        return json.dumps(data, indent=2)
    return format_results_markdown(data, f"Search: {params.query}")


@mcp.tool(
    name="dnslytics_reverse_analytics",
    annotations={
        "title": "Reverse Google Analytics Lookup",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def dnslytics_reverse_analytics(params: TrackingCodeInput) -> str:
    """Find all domains using the same Google Analytics tracking ID.
    
    Supports both Universal Analytics (UA-XXXXX-X) and GA4 (G-XXXXXXX) IDs.
    Essential for identifying related websites owned by the same entity.
    
    Args:
        params: TrackingCodeInput with Analytics ID and response format
    
    Returns:
        List of domains sharing the same Analytics tracking code
    """
    code = params.code.strip()
    
    result = await scrape_search_page(f"search", {"q": code, "d": "domains"})
    
    if "error" in result:
        return json.dumps(result) if params.response_format == ResponseFormat.JSON else result["error"]
    
    results = parse_search_results(result["html"])
    data = {
        "analytics_id": code,
        "domain_count": len(results),
        "domains": results,
        "lookup_url": result["url"]
    }
    
    if params.response_format == ResponseFormat.JSON:
        return json.dumps(data, indent=2)
    return format_results_markdown(data, f"Reverse Analytics: {code}")


@mcp.tool(
    name="dnslytics_reverse_adsense",
    annotations={
        "title": "Reverse Google Adsense Lookup",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def dnslytics_reverse_adsense(params: TrackingCodeInput) -> str:
    """Find all domains using the same Google Adsense publisher ID.
    
    Use pub-XXXXX or ca-pub-XXXXX format. Identifies websites monetized 
    by the same Adsense account - useful for finding related properties.
    
    Args:
        params: TrackingCodeInput with Adsense publisher ID and response format
    
    Returns:
        List of domains sharing the same Adsense publisher ID
    """
    code = params.code.strip().upper()
    if not code.startswith('PUB-') and not code.startswith('CA-PUB-'):
        if code.isdigit():
            code = f"PUB-{code}"
    
    result = await scrape_search_page(f"search", {"q": code, "d": "domains"})
    
    if "error" in result:
        return json.dumps(result) if params.response_format == ResponseFormat.JSON else result["error"]
    
    results = parse_search_results(result["html"])
    data = {
        "adsense_id": code,
        "domain_count": len(results),
        "domains": results,
        "lookup_url": result["url"]
    }
    
    if params.response_format == ResponseFormat.JSON:
        return json.dumps(data, indent=2)
    return format_results_markdown(data, f"Reverse Adsense: {code}")


@mcp.tool(
    name="dnslytics_reverse_ip",
    annotations={
        "title": "Reverse IP Lookup",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def dnslytics_reverse_ip(params: ReverseInput) -> str:
    """Find all domains hosted on the same IP address.
    
    Discovers websites sharing the same server/hosting. Useful for 
    identifying co-hosted sites and shared infrastructure.
    
    Args:
        params: ReverseInput with IP address and response format
    
    Returns:
        List of domains hosted on the specified IP address
    """
    result = await scrape_search_page(f"ip/{params.value}")
    
    if "error" in result:
        return json.dumps(result) if params.response_format == ResponseFormat.JSON else result["error"]
    
    results = parse_search_results(result["html"])
    data = {
        "ip": params.value,
        "domain_count": len(results),
        "domains": results,
        "lookup_url": result["url"]
    }
    
    if params.response_format == ResponseFormat.JSON:
        return json.dumps(data, indent=2)
    return format_results_markdown(data, f"Reverse IP: {params.value}")


@mcp.tool(
    name="dnslytics_reverse_mx",
    annotations={
        "title": "Reverse MX Lookup",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def dnslytics_reverse_mx(params: ReverseInput) -> str:
    """Find all domains using the same mail server (MX record).
    
    Discovers domains sharing email infrastructure. Useful for finding
    related organizations or identifying email service customers.
    
    Args:
        params: ReverseInput with MX hostname and response format
    
    Returns:
        List of domains using the specified mail server
    """
    result = await scrape_search_page("search", {"q": f"mx:{params.value}", "d": "domains"})
    
    if "error" in result:
        return json.dumps(result) if params.response_format == ResponseFormat.JSON else result["error"]
    
    results = parse_search_results(result["html"])
    data = {
        "mx_server": params.value,
        "domain_count": len(results),
        "domains": results,
        "lookup_url": result["url"]
    }
    
    if params.response_format == ResponseFormat.JSON:
        return json.dumps(data, indent=2)
    return format_results_markdown(data, f"Reverse MX: {params.value}")


@mcp.tool(
    name="dnslytics_reverse_ns",
    annotations={
        "title": "Reverse NS Lookup",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def dnslytics_reverse_ns(params: ReverseInput) -> str:
    """Find all domains using the same name server (NS record).
    
    Discovers domains sharing DNS infrastructure. Useful for finding
    domains managed by the same DNS provider or organization.
    
    Args:
        params: ReverseInput with NS hostname and response format
    
    Returns:
        List of domains using the specified name server
    """
    result = await scrape_search_page("search", {"q": f"ns:{params.value}", "d": "domains"})
    
    if "error" in result:
        return json.dumps(result) if params.response_format == ResponseFormat.JSON else result["error"]
    
    results = parse_search_results(result["html"])
    data = {
        "ns_server": params.value,
        "domain_count": len(results),
        "domains": results,
        "lookup_url": result["url"]
    }
    
    if params.response_format == ResponseFormat.JSON:
        return json.dumps(data, indent=2)
    return format_results_markdown(data, f"Reverse NS: {params.value}")


@mcp.tool(
    name="dnslytics_hosting_history",
    annotations={
        "title": "Domain Hosting History",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def dnslytics_hosting_history(params: HostingHistoryInput) -> str:
    """Get historical DNS/hosting records for a domain.
    
    Shows how a domain's DNS records have changed over time - IP addresses,
    mail servers, name servers, and SPF records. Essential for tracking
    infrastructure changes and ownership transfers.
    
    Args:
        params: HostingHistoryInput with domain and optional record type filter
    
    Returns:
        Historical DNS records with timestamps showing changes over time
    """
    result = await scrape_search_page(f"domain/{params.domain}")
    
    if "error" in result:
        return json.dumps(result) if params.response_format == ResponseFormat.JSON else result["error"]
    
    info = parse_domain_info(result["html"])
    data = {
        "domain": params.domain,
        "history": info,
        "lookup_url": result["url"]
    }
    
    if params.response_format == ResponseFormat.JSON:
        return json.dumps(data, indent=2)
    return format_results_markdown(data, f"Hosting History: {params.domain}")


@mcp.tool(
    name="dnslytics_subdomains",
    annotations={
        "title": "Subdomain Discovery",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def dnslytics_subdomains(params: SubdomainInput) -> str:
    """Discover subdomains for a domain name.
    
    Finds known subdomains from DNS records and historical data.
    Useful for mapping an organization's web presence and infrastructure.
    
    Args:
        params: SubdomainInput with domain name and response format
    
    Returns:
        List of discovered subdomains with their DNS records
    """
    result = await scrape_search_page(f"search", {"q": f"*.{params.domain}", "d": "domains"})
    
    if "error" in result:
        return json.dumps(result) if params.response_format == ResponseFormat.JSON else result["error"]
    
    results = parse_search_results(result["html"])
    data = {
        "domain": params.domain,
        "subdomain_count": len(results),
        "subdomains": results,
        "lookup_url": result["url"]
    }
    
    if params.response_format == ResponseFormat.JSON:
        return json.dumps(data, indent=2)
    return format_results_markdown(data, f"Subdomains: {params.domain}")


@mcp.tool(
    name="dnslytics_domain_search",
    annotations={
        "title": "Domain Keyword Search",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def dnslytics_domain_search(params: DomainSearchInput) -> str:
    """Search for domains containing specific keywords.
    
    Find registered domain names matching keywords. Can filter by TLD.
    Useful for brand monitoring, finding similar domains, or research.
    
    Args:
        params: DomainSearchInput with keyword, optional TLD filter, and limit
    
    Returns:
        List of domains matching the search criteria
    """
    search_query = params.keyword
    if params.tld:
        search_query += f" tld:{params.tld}"
    
    result = await scrape_search_page("search", {"q": search_query, "d": "domains"})
    
    if "error" in result:
        return json.dumps(result) if params.response_format == ResponseFormat.JSON else result["error"]
    
    results = parse_search_results(result["html"])
    data = {
        "keyword": params.keyword,
        "tld_filter": params.tld,
        "result_count": len(results),
        "domains": results,
        "search_url": result["url"]
    }
    
    if params.response_format == ResponseFormat.JSON:
        return json.dumps(data, indent=2)
    return format_results_markdown(data, f"Domain Search: {params.keyword}")


@mcp.tool(
    name="dnslytics_tracking_code",
    annotations={
        "title": "Tracking Code Lookup",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def dnslytics_tracking_code(params: TrackingCodeInput) -> str:
    """Look up domains using any type of tracking/advertising code.
    
    Supports multiple tracking code types:
    - Google Analytics: UA-XXXXX-X or G-XXXXXXX
    - Google Adsense: pub-XXXXX or ca-pub-XXXXX
    - Google Tag Manager: GTM-XXXXXX
    - Facebook Pixel: numeric ID
    - Google Ads: AW-XXXXXXXXX
    
    Auto-detects code type if not specified.
    
    Args:
        params: TrackingCodeInput with code, optional type, and response format
    
    Returns:
        List of domains using the specified tracking code
    """
    code = params.code.strip()
    code_type = params.code_type or detect_tracking_code_type(code)
    
    # Map to appropriate search
    if code_type in ['analytics', 'ga4']:
        return await dnslytics_reverse_analytics(params)
    elif code_type == 'adsense':
        return await dnslytics_reverse_adsense(params)
    
    # General search for other codes
    result = await scrape_search_page("search", {"q": code, "d": "domains"})
    
    if "error" in result:
        return json.dumps(result) if params.response_format == ResponseFormat.JSON else result["error"]
    
    results = parse_search_results(result["html"])
    data = {
        "tracking_code": code,
        "detected_type": code_type,
        "domain_count": len(results),
        "domains": results,
        "lookup_url": result["url"]
    }
    
    if params.response_format == ResponseFormat.JSON:
        return json.dumps(data, indent=2)
    return format_results_markdown(data, f"Tracking Code: {code}")


@mcp.tool(
    name="dnslytics_subnet_info",
    annotations={
        "title": "Subnet/CIDR Information",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def dnslytics_subnet_info(params: SubnetInput) -> str:
    """Get information about an IP subnet/CIDR range.
    
    Returns network details, ASN information, and domains hosted
    within the specified IP range.
    
    Args:
        params: SubnetInput with CIDR notation and response format
    
    Returns:
        Subnet information including network details and hosted domains
    """
    result = await scrape_search_page(f"cidr/{params.cidr.replace('/', '-')}")
    
    if "error" in result:
        return json.dumps(result) if params.response_format == ResponseFormat.JSON else result["error"]
    
    info = parse_domain_info(result["html"])
    data = {
        "cidr": params.cidr,
        "info": info,
        "lookup_url": result["url"]
    }
    
    if params.response_format == ResponseFormat.JSON:
        return json.dumps(data, indent=2)
    return format_results_markdown(data, f"Subnet: {params.cidr}")


@mcp.tool(
    name="dnslytics_ip_to_asn",
    annotations={
        "title": "IP to ASN Lookup",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True
    }
)
async def dnslytics_ip_to_asn(params: IPInput) -> str:
    """Get the ASN that announces a specific IP address.
    
    Quick lookup to identify which autonomous system owns/routes an IP.
    
    Args:
        params: IPInput with IP address and response format
    
    Returns:
        ASN information for the IP address
    """
    result = await scrape_search_page(f"ip/{params.ip}")
    if "error" in result:
        return json.dumps(result) if params.response_format == ResponseFormat.JSON else result["error"]
    info = parse_domain_info(result["html"])
    api_result = {"ip": params.ip, "info": info}

    if params.response_format == ResponseFormat.JSON:
        return json.dumps(api_result, indent=2)
    return format_results_markdown(api_result, f"IP to ASN: {params.ip}")


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    mcp.run()
