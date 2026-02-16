#!/usr/bin/env python3
"""
Advanced Dorker MCP Server v3.0 - Sophisticated Google Dorking

A production-grade, multi-backend dorking tool with:
- Google Custom Search API as primary backend with operator optimization
- 25+ GHDB-inspired preset categories
- Content extraction and analysis from results
- CSV/JSON report export
- Pagination for deep result crawling
- Intelligent caching, health monitoring, and quality filtering
"""

import asyncio
import csv
import hashlib
import io
import json
import logging
import os
import random
import re
import sqlite3
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx
from bs4 import BeautifulSoup
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field, field_validator

# =============================================================================
# LOGGING
# =============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("dorker_mcp")

# =============================================================================
# MCP SERVER
# =============================================================================

mcp = FastMCP("dorker_mcp_v3")

# =============================================================================
# CONFIGURATION
# =============================================================================

CONFIG = {
    "GOOGLE_API_KEY": os.environ.get("GOOGLE_API_KEY", ""),
    "GOOGLE_CSE_ID": os.environ.get("GOOGLE_CSE_ID", os.environ.get("GOOGLE_CX", "")),
    "BING_API_KEY": os.environ.get("BING_API_KEY", ""),
    "SERPAPI_KEY": os.environ.get("SERPAPI_KEY", ""),
    "BRAVE_API_KEY": os.environ.get("BRAVE_API_KEY", ""),
    "CACHE_DIR": os.environ.get("DORKER_CACHE_DIR", str(Path.home() / ".cache" / "dorker_mcp")),
    "CACHE_TTL_HOURS": int(os.environ.get("DORKER_CACHE_TTL", "24")),
    "GOOGLE_RATE_LIMIT": 10000,
    "BING_RATE_LIMIT": 1000,
    "BRAVE_RATE_LIMIT": 2000,  # 2000/month free tier, 1 req/sec
    "HTTP_TIMEOUT": 30.0,
    "MAX_RETRIES": 3,
    "EXPORT_DIR": os.environ.get("DORKER_EXPORT_DIR", "/tmp/dorker_exports"),
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
]

# =============================================================================
# DORK PRESETS DATABASE (25+ GHDB-inspired categories)
# =============================================================================

DORK_PRESETS: Dict[str, Dict[str, Any]] = {
    # === EXPOSED FILES & DIRECTORIES ===
    "open_directories": {
        "description": "Find open directory listings on web servers",
        "risk_level": "medium",
        "dorks": [
            'intitle:"index of" "parent directory"',
            'intitle:"index of" "last modified"',
            'intitle:"index of /" +.htaccess',
            'intitle:"index of" inurl:ftp',
        ],
    },
    "config_files": {
        "description": "Find exposed configuration files",
        "risk_level": "high",
        "dorks": [
            'intitle:"index of" "wp-config.php"',
            'filetype:xml inurl:sitemap',
            'filetype:conf inurl:httpd',
            'filetype:ini "extension=" "password"',
            'filetype:yaml "password:" OR "secret:"',
        ],
    },
    "credentials_exposed": {
        "description": "Find exposed credentials and secrets",
        "risk_level": "critical",
        "dorks": [
            'filetype:env "DB_PASSWORD"',
            'filetype:env "API_KEY" OR "SECRET_KEY"',
            'intitle:"index of" "id_rsa" OR "id_dsa"',
            '"BEGIN RSA PRIVATE KEY" filetype:key',
            'filetype:log "password" "username"',
        ],
    },
    "database_files": {
        "description": "Find exposed database dumps and files",
        "risk_level": "critical",
        "dorks": [
            'intitle:"index of" "dump.sql"',
            'intitle:"index of" "backup.sql"',
            'filetype:sql "INSERT INTO" "password"',
            'filetype:sql "CREATE TABLE" "users"',
            'filetype:mdb inurl:admin',
        ],
    },
    "git_exposure": {
        "description": "Find exposed Git repositories",
        "risk_level": "high",
        "dorks": [
            'intitle:"index of" ".git"',
            'inurl:"/.git/config"',
            'intitle:"index of" ".gitignore"',
            'inurl:".git/HEAD"',
        ],
    },
    "backup_files": {
        "description": "Find backup and archive files",
        "risk_level": "medium",
        "dorks": [
            'intitle:"index of" "backup" filetype:zip',
            'intitle:"index of" filetype:tar.gz',
            'intitle:"index of" ".bak"',
            'inurl:backup filetype:sql',
        ],
    },
    # === AUTHENTICATION ===
    "login_pages": {
        "description": "Find login portals and authentication pages",
        "risk_level": "low",
        "dorks": [
            'inurl:admin inurl:login',
            'inurl:"/admin/login"',
            'intitle:"admin login"',
            'intitle:"login" inurl:portal',
        ],
    },
    "admin_panels": {
        "description": "Find admin control panels",
        "risk_level": "medium",
        "dorks": [
            'inurl:"/wp-admin"',
            'inurl:"/administrator"',
            'inurl:"/phpmyadmin"',
            'intitle:"dashboard" inurl:admin',
            'inurl:"/cpanel"',
        ],
    },
    "sso_endpoints": {
        "description": "Find SSO/OAuth endpoint discovery",
        "risk_level": "medium",
        "dorks": [
            'inurl:"/oauth/authorize"',
            'inurl:"/saml/SSO"',
            'inurl:"/.well-known/openid-configuration"',
            'inurl:"/adfs/ls" intitle:"sign in"',
        ],
    },
    # === VULNERABILITIES ===
    "sqli_vectors": {
        "description": "Find potential SQL injection vectors",
        "risk_level": "high",
        "dorks": [
            'inurl:"id=" inurl:"product"',
            'inurl:"page=" inurl:".php"',
            'inurl:"cat=" inurl:"id="',
            'inurl:"view=" filetype:php',
        ],
    },
    "lfi_vectors": {
        "description": "Find Local File Inclusion attack surfaces",
        "risk_level": "high",
        "dorks": [
            'inurl:"file=" inurl:".php"',
            'inurl:"page=" ext:php',
            'inurl:"include=" ext:php',
            'inurl:"path=" ext:php',
        ],
    },
    "error_messages": {
        "description": "Find verbose error pages leaking information",
        "risk_level": "medium",
        "dorks": [
            '"Fatal error" "on line" filetype:php',
            '"Warning: mysql" filetype:php',
            'intitle:"500 Internal Server Error" "server at"',
            '"ORA-" "error" site:',
            '"syntax error" "unexpected" filetype:php',
        ],
    },
    # === DEVICES & IOT ===
    "cameras": {
        "description": "Find exposed webcams and CCTV systems",
        "risk_level": "medium",
        "dorks": [
            'intitle:"webcamXP 5" inurl:8080',
            'inurl:"/view/view.shtml"',
            'intitle:"Live View / - AXIS"',
            'inurl:"ViewerFrame?Mode="',
            'intitle:"Network Camera" inurl:"ViewerFrame"',
        ],
    },
    "iot_devices": {
        "description": "Find exposed IoT dashboards and devices",
        "risk_level": "high",
        "dorks": [
            'intitle:"RouterOS" inurl:"winbox"',
            'intitle:"NETGEAR" inurl:"/setup.cgi"',
            'intitle:"MikroTik" inurl:"/webfig"',
            'intitle:"Synology" inurl:"/webman"',
        ],
    },
    # === WEB SERVERS & TECH ===
    "web_servers": {
        "description": "Find server info disclosure pages",
        "risk_level": "low",
        "dorks": [
            'intitle:"Apache Status" "Server Version"',
            'intitle:"phpinfo()" "PHP Version"',
            'intitle:"index of" inurl:"/server-status"',
            '"Server: Microsoft-IIS" intitle:"index"',
        ],
    },
    "wordpress": {
        "description": "Find WordPress-specific exposures",
        "risk_level": "medium",
        "dorks": [
            'inurl:"/wp-content/uploads"',
            'inurl:"/wp-json/wp/v2/users"',
            'filetype:txt inurl:"wp-config" "DB_PASSWORD"',
            'inurl:"/wp-includes/certificates/ca-bundle.crt"',
        ],
    },
    "vbulletin": {
        "description": "Find vBulletin forum vulnerabilities",
        "risk_level": "medium",
        "dorks": [
            'inurl:"/admincp" "vBulletin"',
            'inurl:"showthread.php" "vBulletin"',
            'intitle:"vBulletin" inurl:"/install/upgrade.php"',
        ],
    },
    # === CLOUD & API ===
    "cloud_storage": {
        "description": "Find misconfigured cloud storage (S3/GCS/Azure)",
        "risk_level": "critical",
        "dorks": [
            'site:s3.amazonaws.com filetype:pdf',
            'site:s3.amazonaws.com filetype:xls',
            'site:storage.googleapis.com filetype:pdf',
            'site:blob.core.windows.net filetype:pdf',
            'inurl:"s3.amazonaws.com" "index of"',
        ],
    },
    "api_endpoints": {
        "description": "Find exposed API documentation and endpoints",
        "risk_level": "medium",
        "dorks": [
            'inurl:"/swagger-ui.html"',
            'inurl:"/api-docs" "swagger"',
            'intitle:"API Documentation" inurl:"/docs"',
            'inurl:"/graphql" "query"',
            'inurl:"/api/v1" OR inurl:"/api/v2" filetype:json',
        ],
    },
    "jdbc_strings": {
        "description": "Find exposed JDBC connection strings",
        "risk_level": "critical",
        "dorks": [
            '"jdbc:mysql://" filetype:properties',
            '"jdbc:oracle:" filetype:xml',
            '"connectionString" filetype:config "password"',
            '"jdbc:postgresql://" filetype:properties',
        ],
    },
    # === SECTOR SPECIFIC ===
    "government": {
        "description": "Find government document exposures",
        "risk_level": "low",
        "dorks": [
            'site:gov filetype:pdf "confidential"',
            'site:gov filetype:xls "not for public"',
            'site:gov intitle:"index of" "backup"',
            'site:mil filetype:pdf "unclassified"',
        ],
    },
    "education": {
        "description": "Find education institution leaks",
        "risk_level": "low",
        "dorks": [
            'site:edu filetype:xls "student" "grade"',
            'site:edu inurl:admin',
            'site:edu filetype:sql "password"',
            'site:edu intitle:"index of" "exam"',
        ],
    },
    "nonprofit_990": {
        "description": "Find nonprofit 990 tax filings",
        "risk_level": "low",
        "dorks": [
            '"Form 990" filetype:pdf',
            'site:propublica.org "nonprofit"',
            '"Return of Organization" filetype:pdf "990"',
        ],
    },
    "nonprofit_grants": {
        "description": "Find nonprofit grant information",
        "risk_level": "low",
        "dorks": [
            'filetype:pdf "grant" "recipient" "amount"',
            '"Schedule I" filetype:pdf "grants"',
            'filetype:pdf "grantee" "purpose of grant"',
        ],
    },
    # === DOCUMENTS ===
    "documents": {
        "description": "Find exposed sensitive documents",
        "risk_level": "medium",
        "dorks": [
            'filetype:pdf "confidential"',
            'filetype:doc "internal use only"',
            'filetype:xlsx "salary" OR "payroll"',
            'filetype:pptx "not for distribution"',
        ],
    },
    "logs": {
        "description": "Find exposed log files",
        "risk_level": "medium",
        "dorks": [
            'intitle:"index of" "access.log"',
            'intitle:"index of" "error.log"',
            'filetype:log "password"',
            'filetype:log "authentication" "failed"',
        ],
    },
}

# =============================================================================
# DATA CLASSES
# =============================================================================

class SearchBackend(str, Enum):
    """Available search backends."""
    GOOGLE_CSE = "google_cse"
    BING_API = "bing_api"
    SERPAPI = "serpapi"
    BRAVE_API = "brave_api"
    BING_SCRAPE = "bing_scrape"
    DUCKDUCKGO = "duckduckgo"
    AUTO = "auto"


class ResponseFormat(str, Enum):
    """Output format."""
    MARKDOWN = "markdown"
    JSON = "json"


@dataclass
class SearchResult:
    """Represents a single search result."""
    title: str
    url: str
    snippet: str
    source: str
    quality_score: float = 1.0
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict:
        return {
            "title": self.title,
            "url": self.url,
            "snippet": self.snippet,
            "source": self.source,
            "quality_score": round(self.quality_score, 2),
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class BackendHealth:
    """Tracks health status of a search backend."""
    name: str
    is_healthy: bool = True
    last_success: Optional[datetime] = None
    last_failure: Optional[datetime] = None
    consecutive_failures: int = 0
    total_queries: int = 0
    total_failures: int = 0
    rate_limit_reset: Optional[datetime] = None

    def record_success(self):
        self.last_success = datetime.now()
        self.consecutive_failures = 0
        self.is_healthy = True
        self.total_queries += 1

    def record_failure(self):
        self.last_failure = datetime.now()
        self.consecutive_failures += 1
        self.total_queries += 1
        self.total_failures += 1
        if self.consecutive_failures >= 5:
            self.is_healthy = False

    def is_rate_limited(self) -> bool:
        if self.rate_limit_reset and datetime.now() < self.rate_limit_reset:
            return True
        return False


# =============================================================================
# CACHE MANAGER
# =============================================================================

class CacheManager:
    """SQLite-based cache for search results."""

    def __init__(self, cache_dir: str, ttl_hours: int = 24):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.cache_dir / "dorker_cache.db"
        self.ttl_hours = ttl_hours
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS search_cache (
                    query_hash TEXT PRIMARY KEY,
                    query TEXT,
                    backend TEXT,
                    results TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS api_usage (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    backend TEXT,
                    query TEXT,
                    success BOOLEAN,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    def _hash_query(self, query: str, backend: str) -> str:
        return hashlib.sha256(f"{query}:{backend}".encode()).hexdigest()

    def get(self, query: str, backend: str = "any") -> Optional[Tuple]:
        with sqlite3.connect(str(self.db_path)) as conn:
            cutoff = (datetime.now() - timedelta(hours=self.ttl_hours)).isoformat()
            if backend == "any":
                row = conn.execute(
                    "SELECT results, backend FROM search_cache WHERE query=? AND created_at>? ORDER BY created_at DESC LIMIT 1",
                    (query, cutoff)
                ).fetchone()
            else:
                qhash = self._hash_query(query, backend)
                row = conn.execute(
                    "SELECT results, backend FROM search_cache WHERE query_hash=? AND created_at>?",
                    (qhash, cutoff)
                ).fetchone()
            if row:
                return json.loads(row[0]), row[1]
        return None

    def set(self, query: str, results: List[SearchResult], backend: str):
        qhash = self._hash_query(query, backend)
        data = json.dumps([r.to_dict() for r in results])
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO search_cache (query_hash, query, backend, results) VALUES (?,?,?,?)",
                (qhash, query, backend, data)
            )
            conn.commit()

    def record_api_call(self, backend: str, query: str, success: bool):
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                "INSERT INTO api_usage (backend, query, success) VALUES (?,?,?)",
                (backend, query, success)
            )
            conn.commit()

    def get_daily_usage(self, backend: str) -> int:
        with sqlite3.connect(str(self.db_path)) as conn:
            today = datetime.now().strftime("%Y-%m-%d")
            row = conn.execute(
                "SELECT COUNT(*) FROM api_usage WHERE backend=? AND DATE(created_at)=?",
                (backend, today)
            ).fetchone()
            return row[0] if row else 0

    def cleanup_old_entries(self, days: int = 7):
        with sqlite3.connect(str(self.db_path)) as conn:
            cutoff = (datetime.now() - timedelta(days=days)).isoformat()
            conn.execute("DELETE FROM search_cache WHERE created_at < ?", (cutoff,))
            conn.execute("DELETE FROM api_usage WHERE created_at < ?", (cutoff,))
            conn.commit()


# Initialize globals
cache_manager = CacheManager(CONFIG["CACHE_DIR"], CONFIG["CACHE_TTL_HOURS"])
backend_health: Dict[str, BackendHealth] = {
    backend.value: BackendHealth(name=backend.value)
    for backend in SearchBackend if backend != SearchBackend.AUTO
}

# Pagination context store
_pagination_context: Dict[str, Dict[str, Any]] = {}

# =============================================================================
# SEARCH BACKENDS
# =============================================================================

async def _get_http_client() -> httpx.AsyncClient:
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "DNT": "1",
        "Connection": "keep-alive",
    }
    return httpx.AsyncClient(
        headers=headers,
        timeout=CONFIG["HTTP_TIMEOUT"],
        follow_redirects=True,
    )


async def _search_google_cse(query: str, max_results: int = 10, start_index: int = 1) -> List[SearchResult]:
    """
    Search using Google Custom Search API with operator optimization.
    Extracts site:, filetype:, dateRestrict from query into dedicated API params.
    """
    api_key = CONFIG["GOOGLE_API_KEY"]
    cse_id = CONFIG["GOOGLE_CSE_ID"]

    if not api_key or not cse_id:
        raise RuntimeError(
            "Google CSE not configured. Set GOOGLE_API_KEY and GOOGLE_CSE_ID."
        )

    daily_usage = cache_manager.get_daily_usage("google_cse")
    if daily_usage >= CONFIG["GOOGLE_RATE_LIMIT"]:
        raise RuntimeError(f"Google CSE daily limit reached ({daily_usage}/{CONFIG['GOOGLE_RATE_LIMIT']})")

    modified_query = query
    api_params: Dict[str, str] = {}

    # Extract filetype:/ext: → fileType param
    ft_match = re.search(r'\b(?:filetype|ext):(\w+)', query, re.IGNORECASE)
    if ft_match:
        api_params["fileType"] = ft_match.group(1)
        modified_query = re.sub(r'\b(?:filetype|ext):\w+\s*', '', modified_query, flags=re.IGNORECASE)

    # Extract site: → siteSearch param
    site_match = re.search(r'\bsite:([^\s]+)', query, re.IGNORECASE)
    if site_match:
        api_params["siteSearch"] = site_match.group(1)
        api_params["siteSearchFilter"] = "i"
        modified_query = re.sub(r'\bsite:[^\s]+\s*', '', modified_query, flags=re.IGNORECASE)

    # Extract -site: → siteSearch exclude
    neg_site = re.search(r'-site:([^\s]+)', query, re.IGNORECASE)
    if neg_site and "siteSearch" not in api_params:
        api_params["siteSearch"] = neg_site.group(1)
        api_params["siteSearchFilter"] = "e"
        modified_query = re.sub(r'-site:[^\s]+\s*', '', modified_query, flags=re.IGNORECASE)

    modified_query = re.sub(r'\s+', ' ', modified_query).strip()
    if not modified_query:
        modified_query = "*"

    results = []
    async with await _get_http_client() as client:
        for si in range(start_index, min(start_index + max_results, 101), 10):
            params = {
                "key": api_key,
                "cx": cse_id,
                "q": modified_query,
                "start": si,
                "num": min(10, max_results - len(results)),
                **api_params,
            }

            response = await client.get(
                "https://www.googleapis.com/customsearch/v1",
                params=params
            )

            if response.status_code == 429:
                raise RuntimeError("Google CSE rate limit exceeded")
            if response.status_code != 200:
                error_data = response.json() if response.text else {}
                raise RuntimeError(f"Google CSE error: {error_data.get('error', {}).get('message', response.status_code)}")

            data = response.json()
            for item in data.get("items", []):
                results.append(SearchResult(
                    title=item.get("title", ""),
                    url=item.get("link", ""),
                    snippet=item.get("snippet", ""),
                    source="google_cse",
                    quality_score=_calculate_quality_score(item, query),
                ))

            if len(results) >= max_results or "nextPage" not in data.get("queries", {}):
                break
            await asyncio.sleep(0.1)

    cache_manager.record_api_call("google_cse", query, True)
    return results


async def _search_bing_api(query: str, max_results: int = 10, **kw) -> List[SearchResult]:
    api_key = CONFIG["BING_API_KEY"]
    if not api_key:
        raise RuntimeError("Bing API not configured. Set BING_API_KEY.")

    results = []
    async with httpx.AsyncClient(timeout=CONFIG["HTTP_TIMEOUT"]) as client:
        response = await client.get(
            "https://api.bing.microsoft.com/v7.0/search",
            params={"q": query, "count": min(max_results, 50), "textDecorations": True, "textFormat": "HTML"},
            headers={"Ocp-Apim-Subscription-Key": api_key}
        )
        if response.status_code == 429:
            raise RuntimeError("Bing API rate limit exceeded")
        if response.status_code != 200:
            raise RuntimeError(f"Bing API error: {response.status_code}")

        for item in response.json().get("webPages", {}).get("value", []):
            snippet = re.sub(r'<[^>]+>', '', item.get("snippet", ""))
            results.append(SearchResult(
                title=item.get("name", ""), url=item.get("url", ""),
                snippet=snippet, source="bing_api",
                quality_score=_calculate_quality_score(item, query),
            ))
    cache_manager.record_api_call("bing_api", query, True)
    return results


async def _search_serpapi(query: str, max_results: int = 10, **kw) -> List[SearchResult]:
    api_key = CONFIG["SERPAPI_KEY"]
    if not api_key:
        raise RuntimeError("SerpAPI not configured. Set SERPAPI_KEY.")

    results = []
    async with await _get_http_client() as client:
        response = await client.get(
            "https://serpapi.com/search",
            params={"api_key": api_key, "q": query, "engine": "google", "num": min(max_results, 100)}
        )
        if response.status_code != 200:
            raise RuntimeError(f"SerpAPI error: {response.status_code}")

        for item in response.json().get("organic_results", []):
            results.append(SearchResult(
                title=item.get("title", ""), url=item.get("link", ""),
                snippet=item.get("snippet", ""), source="serpapi",
                quality_score=_calculate_quality_score(item, query),
            ))
    cache_manager.record_api_call("serpapi", query, True)
    return results


async def _search_brave(query: str, max_results: int = 20, **kw) -> List[SearchResult]:
    api_key = CONFIG["BRAVE_API_KEY"]
    if not api_key:
        raise RuntimeError("Brave Search not configured. Set BRAVE_API_KEY.")

    # Brave free tier: 1 request/sec, 2000/month
    await asyncio.sleep(1.0)

    results = []
    async with await _get_http_client() as client:
        response = await client.get(
            "https://api.search.brave.com/res/v1/web/search",
            params={"q": query, "count": min(max_results, 20), "search_lang": "en", "safesearch": "off"},
            headers={"X-Subscription-Token": api_key, "Accept": "application/json"}
        )
        if response.status_code != 200:
            raise RuntimeError(f"Brave API error: {response.status_code}")

        for item in response.json().get("web", {}).get("results", [])[:max_results]:
            results.append(SearchResult(
                title=item.get("title", ""), url=item.get("url", ""),
                snippet=item.get("description", ""), source="brave_api",
                quality_score=_calculate_quality_score(
                    {"title": item.get("title", ""), "link": item.get("url", ""), "snippet": item.get("description", "")},
                    query
                ),
            ))
    cache_manager.record_api_call("brave_api", query, True)
    return results


async def _search_bing_scrape(query: str, max_results: int = 20, **kw) -> List[SearchResult]:
    results = []
    url = f"https://www.bing.com/search?q={urllib.parse.quote_plus(query)}&count={min(max_results, 50)}"
    async with await _get_http_client() as client:
        client.headers["Referer"] = "https://www.bing.com/"
        response = await client.get(url)
        if response.status_code != 200:
            raise RuntimeError(f"Bing scrape failed: HTTP {response.status_code}")

        soup = BeautifulSoup(response.text, "html.parser")
        for result in soup.select(".b_algo")[:max_results]:
            title_elem = result.select_one("h2 a")
            snippet_elem = result.select_one(".b_caption p, .b_caption .b_algoSlug")
            if title_elem:
                href = title_elem.get("href", "")
                if href and not href.startswith("https://www.bing.com/"):
                    results.append(SearchResult(
                        title=title_elem.get_text(strip=True), url=href,
                        snippet=snippet_elem.get_text(strip=True) if snippet_elem else "",
                        source="bing_scrape", quality_score=0.7,
                    ))
    return results


async def _search_duckduckgo(query: str, max_results: int = 20, **kw) -> List[SearchResult]:
    results = []
    url = f"https://html.duckduckgo.com/html/?q={urllib.parse.quote_plus(query)}"
    async with await _get_http_client() as client:
        response = await client.get(url)
        if response.status_code != 200:
            raise RuntimeError(f"DuckDuckGo failed: HTTP {response.status_code}")

        soup = BeautifulSoup(response.text, "html.parser")
        for result in soup.select(".result")[:max_results]:
            title_elem = result.select_one(".result__title a")
            snippet_elem = result.select_one(".result__snippet")
            if title_elem:
                href = title_elem.get("href", "")
                actual_url = urllib.parse.unquote(href.split("uddg=")[1].split("&")[0]) if "uddg=" in href else href
                results.append(SearchResult(
                    title=title_elem.get_text(strip=True), url=actual_url,
                    snippet=snippet_elem.get_text(strip=True) if snippet_elem else "",
                    source="duckduckgo", quality_score=0.6,
                ))
    return results


# =============================================================================
# QUALITY SCORING & FILTERING
# =============================================================================

def _calculate_quality_score(item: Dict, query: str) -> float:
    score = 1.0
    title = item.get("title", "").lower()
    snippet = item.get("snippet", item.get("content", "")).lower()
    url = item.get("link", item.get("url", "")).lower()
    query_lower = query.lower()

    query_terms = re.findall(r'"([^"]+)"|(\b\w+\b)', query_lower)
    query_terms = [t[0] or t[1] for t in query_terms if (t[0] or t[1]) and len(t[0] or t[1]) > 2]

    for term in query_terms:
        if term in title:
            score += 0.2
        if term in url:
            score += 0.1

    for ind in ["wikipedia.org", "dictionary.com", "merriam-webster", "stackexchange.com", "quora.com"]:
        if ind in url:
            score -= 0.3
            break

    if "filetype:" in query_lower:
        for ext in [".pdf", ".doc", ".xls", ".sql", ".txt", ".env", ".log"]:
            if ext in url:
                score += 0.3
                break

    return max(0.1, min(2.0, score))


def _filter_results(results: List[SearchResult], min_quality: float = 0.5) -> List[SearchResult]:
    seen_urls = set()
    filtered = []
    for r in results:
        normalized = r.url.lower().rstrip("/")
        if normalized in seen_urls:
            continue
        seen_urls.add(normalized)
        if r.quality_score < min_quality:
            continue
        if any(re.match(p, r.url) for p in [r"^https?://www\.google\.", r"^https?://www\.bing\.com/search", r"^https?://duckduckgo\.com"]):
            continue
        filtered.append(r)
    filtered.sort(key=lambda x: x.quality_score, reverse=True)
    return filtered


# =============================================================================
# SEARCH ORCHESTRATION
# =============================================================================

async def _search_with_fallback(
    query: str,
    max_results: int = 20,
    preferred_backend: SearchBackend = SearchBackend.AUTO,
    use_cache: bool = True
) -> Tuple[List[SearchResult], str]:
    if use_cache:
        cached = cache_manager.get(query, "any")
        if cached:
            results_data, backend = cached
            results = [
                SearchResult(title=r["title"], url=r["url"], snippet=r["snippet"],
                             source=r["source"], quality_score=r.get("quality_score", 1.0))
                for r in results_data
            ]
            return results, f"{backend} (cached)"

    if preferred_backend == SearchBackend.AUTO:
        backends = [
            (SearchBackend.GOOGLE_CSE, _search_google_cse),
            (SearchBackend.BRAVE_API, _search_brave),
            (SearchBackend.SERPAPI, _search_serpapi),
            (SearchBackend.BING_API, _search_bing_api),
            (SearchBackend.BING_SCRAPE, _search_bing_scrape),
            (SearchBackend.DUCKDUCKGO, _search_duckduckgo),
        ]
    else:
        backend_map = {
            SearchBackend.GOOGLE_CSE: _search_google_cse,
            SearchBackend.BRAVE_API: _search_brave,
            SearchBackend.SERPAPI: _search_serpapi,
            SearchBackend.BING_API: _search_bing_api,
            SearchBackend.BING_SCRAPE: _search_bing_scrape,
            SearchBackend.DUCKDUCKGO: _search_duckduckgo,
        }
        backends = [(preferred_backend, backend_map[preferred_backend])]
        for b, f in backend_map.items():
            if b != preferred_backend:
                backends.append((b, f))

    errors = []
    for backend_enum, search_func in backends:
        backend_name = backend_enum.value
        health = backend_health.get(backend_name)

        if health and not health.is_healthy and health.consecutive_failures >= 5:
            continue
        if health and health.is_rate_limited():
            continue

        try:
            logger.info(f"Trying backend: {backend_name} for query: {query[:50]}...")
            results = await search_func(query, max_results)

            if results:
                results = _filter_results(results)
                if results:
                    if health:
                        health.record_success()
                    if use_cache:
                        cache_manager.set(query, results, backend_name)
                    logger.info(f"Success: {len(results)} results from {backend_name}")
                    return results, backend_name

        except Exception as e:
            error_msg = str(e)
            errors.append(f"{backend_name}: {error_msg}")
            logger.warning(f"Backend {backend_name} failed: {error_msg}")
            if health:
                health.record_failure()
            if "rate limit" in error_msg.lower() or "429" in error_msg:
                if health:
                    health.rate_limit_reset = datetime.now() + timedelta(hours=1)
            await asyncio.sleep(0.5)

    raise RuntimeError(f"All search backends failed:\n" + "\n".join(f"  - {e}" for e in errors))


# =============================================================================
# FORMATTING
# =============================================================================

def _format_results_markdown(results: List[SearchResult], query: str, backend: str, extra_info: Optional[Dict] = None) -> str:
    if not results:
        return f"❌ No results found for query: `{query}`"
    lines = [
        f"## 🔍 Dork Results ({len(results)} found)",
        f"**Query:** `{query}`",
        f"**Backend:** {backend}",
    ]
    if extra_info:
        for key, value in extra_info.items():
            lines.append(f"**{key}:** {value}")
    lines.append("")
    for i, r in enumerate(results, 1):
        qi = "🟢" if r.quality_score >= 1.0 else "🟡" if r.quality_score >= 0.7 else "🔴"
        lines.extend([f"### {i}. {r.title} {qi}", f"**URL:** {r.url}", r.snippet or "_No snippet_", ""])
    return "\n".join(lines)


def _format_results_json(results: List[SearchResult], query: str, backend: str, extra_info: Optional[Dict] = None) -> str:
    data = {"query": query, "backend": backend, "result_count": len(results), "results": [r.to_dict() for r in results]}
    if extra_info:
        data.update(extra_info)
    return json.dumps(data, indent=2)


# =============================================================================
# PYDANTIC INPUT MODELS
# =============================================================================

class DorkSearchInput(BaseModel):
    """Input for dork_search tool."""
    model_config = ConfigDict(use_enum_values=True)
    query: str = Field(description="The Google dork query string")
    max_results: int = Field(default=20, ge=1, le=100, description="Maximum results to return")
    backend: SearchBackend = Field(default=SearchBackend.AUTO, description="Search backend to use")
    use_cache: bool = Field(default=True, description="Whether to use cached results")
    format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format")


class PresetDorkInput(BaseModel):
    """Input for dork_preset tool."""
    model_config = ConfigDict(use_enum_values=True)
    category: str = Field(description="Preset category name")
    target_site: Optional[str] = Field(default=None, description="Target domain to scope dorks to (e.g., example.com)")
    max_results_per_dork: int = Field(default=10, ge=1, le=50, description="Max results per individual dork")
    format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format")

    @field_validator("category")
    @classmethod
    def validate_category(cls, v):
        if v not in DORK_PRESETS:
            available = ", ".join(sorted(DORK_PRESETS.keys()))
            raise ValueError(f"Unknown category '{v}'. Available: {available}")
        return v


class DorkBuilderInput(BaseModel):
    """Input for build_dork tool."""
    base_query: str = Field(description="Core search terms")
    site: Optional[str] = Field(default=None, description="Restrict to domain (site: operator)")
    filetype: Optional[str] = Field(default=None, description="File extension filter (filetype: operator)")
    intitle: Optional[str] = Field(default=None, description="Terms that must appear in page title")
    inurl: Optional[str] = Field(default=None, description="Terms that must appear in URL")
    intext: Optional[str] = Field(default=None, description="Terms that must appear in page body")
    exclude_sites: Optional[List[str]] = Field(default=None, description="Domains to exclude")
    date_range: Optional[str] = Field(default=None, description="Date filter (d=day, w=week, m=month, y=year, e.g. 'm3' for 3 months)")
    exact_match: bool = Field(default=False, description="Wrap base_query in quotes for exact match")


class MultiDorkInput(BaseModel):
    """Input for multi_dork tool."""
    model_config = ConfigDict(use_enum_values=True)
    queries: List[str] = Field(description="List of dork queries to run")
    max_results_per_query: int = Field(default=10, ge=1, le=50, description="Max results per query")
    format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format")


class DorkTargetInput(BaseModel):
    """Input for dork_target tool."""
    model_config = ConfigDict(use_enum_values=True)
    target: str = Field(description="Target domain or organization")
    scan_categories: Optional[List[str]] = Field(default=None, description="Specific categories to scan; defaults to all")
    max_results_per_dork: int = Field(default=5, ge=1, le=20, description="Max results per dork")
    format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format")


class DorkAnalyzeInput(BaseModel):
    """Input for dork_analyze tool."""
    urls: List[str] = Field(description="URLs to extract content from", min_length=1, max_length=10)
    extract_metadata: bool = Field(default=True, description="Extract page metadata (title, description, headers)")
    extract_emails: bool = Field(default=True, description="Extract email addresses from the page")
    extract_links: bool = Field(default=True, description="Extract all links from the page")
    extract_tech: bool = Field(default=True, description="Detect technologies and frameworks")


class DorkExportInput(BaseModel):
    """Input for dork_export tool."""
    query: str = Field(description="Dork query to search and export")
    max_results: int = Field(default=50, ge=1, le=100, description="Maximum results")
    export_format: str = Field(default="csv", description="Export format: csv or json")
    filename: Optional[str] = Field(default=None, description="Custom filename (without extension)")


class DorkSuggestInput(BaseModel):
    """Input for dork_suggest tool."""
    target: str = Field(description="Target domain or topic to generate dorks for")
    focus: Optional[str] = Field(default=None, description="Specific area: credentials, databases, admin, api, cloud, documents, vulnerabilities")
    include_advanced: bool = Field(default=True, description="Include advanced/complex dork combinations")


class DorkPaginateInput(BaseModel):
    """Input for dork_paginate tool."""
    model_config = ConfigDict(use_enum_values=True)
    query: str = Field(description="The dork query to paginate through")
    page: int = Field(default=1, ge=1, le=10, description="Page number (each page = 10 results)")
    format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format")


# =============================================================================
# CONTENT EXTRACTION ENGINE
# =============================================================================

async def _extract_page_content(url: str) -> Dict[str, Any]:
    """Extract content and metadata from a URL."""
    result: Dict[str, Any] = {"url": url, "status": "unknown", "metadata": {}, "emails": [], "links": [], "technologies": []}

    try:
        async with await _get_http_client() as client:
            response = await client.get(url, timeout=15.0)
            result["status"] = f"HTTP {response.status_code}"

            if response.status_code != 200:
                return result

            content_type = response.headers.get("content-type", "")
            if "text/html" not in content_type and "application/xhtml" not in content_type:
                result["metadata"]["content_type"] = content_type
                result["metadata"]["size_bytes"] = len(response.content)
                return result

            soup = BeautifulSoup(response.text, "html.parser")

            # Metadata extraction
            result["metadata"]["title"] = soup.title.string.strip() if soup.title and soup.title.string else ""
            meta_desc = soup.find("meta", attrs={"name": "description"})
            result["metadata"]["description"] = meta_desc["content"] if meta_desc and meta_desc.get("content") else ""
            meta_kw = soup.find("meta", attrs={"name": "keywords"})
            result["metadata"]["keywords"] = meta_kw["content"] if meta_kw and meta_kw.get("content") else ""

            # Server header
            result["metadata"]["server"] = response.headers.get("server", "")
            result["metadata"]["powered_by"] = response.headers.get("x-powered-by", "")

            # Headers hierarchy
            headers = []
            for level in range(1, 4):
                for h in soup.find_all(f"h{level}"):
                    text = h.get_text(strip=True)
                    if text:
                        headers.append(f"H{level}: {text[:100]}")
            result["metadata"]["headers"] = headers[:20]

            # Email extraction
            text_content = soup.get_text()
            emails = set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text_content))
            # Also check href="mailto:"
            for a in soup.find_all("a", href=True):
                if a["href"].startswith("mailto:"):
                    emails.add(a["href"].replace("mailto:", "").split("?")[0])
            result["emails"] = sorted(emails)

            # Link extraction
            links = []
            for a in soup.find_all("a", href=True)[:50]:
                href = a["href"]
                if href.startswith(("http://", "https://")):
                    links.append({"text": a.get_text(strip=True)[:80], "url": href})
            result["links"] = links

            # Technology detection
            techs = []
            page_text = response.text.lower()
            tech_signatures = {
                "WordPress": ["wp-content", "wp-includes", "wordpress"],
                "React": ["react.production.min.js", "_next/static", "react-dom"],
                "Angular": ["ng-version", "angular.min.js"],
                "Vue.js": ["vue.min.js", "vue.runtime"],
                "jQuery": ["jquery.min.js", "jquery-"],
                "Bootstrap": ["bootstrap.min.css", "bootstrap.min.js"],
                "Drupal": ["drupal.js", "sites/default"],
                "Joomla": ["joomla", "/media/system/js/"],
                "Laravel": ["laravel", "csrf-token"],
                "Django": ["csrfmiddlewaretoken", "django"],
                "ASP.NET": ["__viewstate", "asp.net"],
                "Nginx": [],
                "Apache": [],
                "Cloudflare": ["cf-ray"],
                "AWS": ["x-amz-", "amazonaws"],
            }
            # Check server header for Nginx/Apache
            server_header = response.headers.get("server", "").lower()
            if "nginx" in server_header:
                techs.append("Nginx")
            if "apache" in server_header:
                techs.append("Apache")
            if "cloudflare" in server_header:
                techs.append("Cloudflare")

            for tech, sigs in tech_signatures.items():
                if tech in techs:
                    continue
                for sig in sigs:
                    if sig in page_text:
                        techs.append(tech)
                        break

            # Check response headers for more
            for header_name, header_val in response.headers.items():
                hn = header_name.lower()
                hv = header_val.lower()
                if "x-amz" in hn:
                    if "AWS" not in techs:
                        techs.append("AWS")
                if "cf-ray" in hn:
                    if "Cloudflare" not in techs:
                        techs.append("Cloudflare")
                if "x-powered-by" in hn:
                    if "php" in hv and "PHP" not in techs:
                        techs.append("PHP")
                    if "express" in hv and "Express.js" not in techs:
                        techs.append("Express.js")

            result["technologies"] = techs

    except httpx.TimeoutException:
        result["status"] = "timeout"
    except Exception as e:
        result["status"] = f"error: {str(e)[:200]}"

    return result


# =============================================================================
# MCP TOOLS
# =============================================================================

@mcp.tool()
async def dork_search(input: DorkSearchInput) -> str:
    """
    Execute a Google dork query with intelligent backend fallback.
    
    Supports all standard dork operators: site:, filetype:, intitle:, inurl:,
    intext:, ext:, cache:, link:, related:, info:, and boolean operators.
    
    Example queries:
    - site:example.com filetype:pdf "confidential"
    - intitle:"index of" "parent directory" -site:github.com
    - inurl:admin inurl:login
    """
    try:
        results, backend = await _search_with_fallback(
            input.query, input.max_results,
            SearchBackend(input.backend), input.use_cache
        )
        if input.format == "json":
            return _format_results_json(results, input.query, backend)
        return _format_results_markdown(results, input.query, backend)
    except Exception as e:
        return f"❌ Search failed: {str(e)}"


@mcp.tool()
async def dork_preset(input: PresetDorkInput) -> str:
    """
    Run pre-built dork queries from 25+ GHDB-inspired categories.
    
    Categories include: open_directories, config_files, credentials_exposed,
    database_files, git_exposure, backup_files, login_pages, admin_panels,
    sso_endpoints, sqli_vectors, lfi_vectors, error_messages, cameras,
    iot_devices, web_servers, wordpress, vbulletin, cloud_storage,
    api_endpoints, jdbc_strings, government, education, nonprofit_990,
    nonprofit_grants, documents, logs.
    
    Optionally scope all dorks to a specific target domain.
    """
    preset = DORK_PRESETS[input.category]
    all_results: List[SearchResult] = []
    dork_count = len(preset["dorks"])
    backend_used = ""

    for dork in preset["dorks"]:
        if input.target_site:
            dork = f"site:{input.target_site} {dork}"
        try:
            results, backend = await _search_with_fallback(dork, input.max_results_per_dork)
            all_results.extend(results)
            backend_used = backend
        except Exception as e:
            logger.warning(f"Preset dork failed: {dork}: {e}")
        await asyncio.sleep(0.3)

    all_results = _filter_results(all_results)
    extra = {
        "Category": input.category,
        "Description": preset["description"],
        "Risk Level": preset["risk_level"],
        "Dorks Run": dork_count,
        "Target": input.target_site or "unrestricted",
    }

    if input.format == "json":
        return _format_results_json(all_results, f"[preset:{input.category}]", backend_used, extra)
    return _format_results_markdown(all_results, f"[preset:{input.category}]", backend_used, extra)


@mcp.tool()
async def dork_target(input: DorkTargetInput) -> str:
    """
    Comprehensive OSINT scan of a target domain using multiple dork categories.
    Runs dorks from selected (or all) categories scoped to the target.
    
    Returns a consolidated report with findings organized by risk level.
    """
    categories_to_scan = input.scan_categories or list(DORK_PRESETS.keys())
    invalid = [c for c in categories_to_scan if c not in DORK_PRESETS]
    if invalid:
        return f"❌ Unknown categories: {', '.join(invalid)}. Use list_presets to see available categories."

    all_findings: Dict[str, List[SearchResult]] = {}
    total_dorks = 0

    for category in categories_to_scan:
        preset = DORK_PRESETS[category]
        cat_results: List[SearchResult] = []

        for dork in preset["dorks"]:
            scoped_dork = f"site:{input.target} {dork}"
            total_dorks += 1
            try:
                results, _ = await _search_with_fallback(scoped_dork, input.max_results_per_dork)
                cat_results.extend(results)
            except Exception:
                pass
            await asyncio.sleep(0.3)

        if cat_results:
            all_findings[category] = _filter_results(cat_results)

    if input.format == "json":
        data = {
            "target": input.target,
            "total_dorks_run": total_dorks,
            "categories_with_findings": len(all_findings),
            "findings": {cat: [r.to_dict() for r in results] for cat, results in all_findings.items()},
        }
        return json.dumps(data, indent=2)

    # Markdown report
    lines = [
        f"## 🎯 Target Scan Report: {input.target}",
        f"**Dorks executed:** {total_dorks}",
        f"**Categories with findings:** {len(all_findings)} / {len(categories_to_scan)}",
        ""
    ]

    # Sort by risk level
    risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_cats = sorted(all_findings.keys(), key=lambda x: risk_order.get(DORK_PRESETS[x]["risk_level"], 4))

    for cat in sorted_cats:
        preset = DORK_PRESETS[cat]
        results = all_findings[cat]
        risk_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(preset["risk_level"], "⚪")
        lines.extend([
            f"### {risk_emoji} {cat} ({preset['risk_level'].upper()})",
            f"_{preset['description']}_",
            f"**{len(results)} result(s) found:**",
        ])
        for r in results[:10]:
            lines.append(f"- [{r.title}]({r.url})")
            if r.snippet:
                lines.append(f"  _{r.snippet[:120]}_")
        lines.append("")

    if not all_findings:
        lines.append("✅ No findings across scanned categories. Target appears clean.")

    return "\n".join(lines)


@mcp.tool()
async def list_presets() -> str:
    """List all available dork preset categories with descriptions and risk levels."""
    lines = ["## 📚 Available Dork Preset Categories", ""]

    risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_cats = sorted(DORK_PRESETS.items(), key=lambda x: risk_order.get(x[1]["risk_level"], 4))

    for name, preset in sorted_cats:
        risk_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(preset["risk_level"], "⚪")
        lines.append(f"- {risk_emoji} **{name}** ({preset['risk_level']}): {preset['description']} [{len(preset['dorks'])} dorks]")

    lines.extend(["", f"**Total categories:** {len(DORK_PRESETS)}", f"**Total dorks:** {sum(len(p['dorks']) for p in DORK_PRESETS.values())}"])
    return "\n".join(lines)


@mcp.tool()
async def build_dork(input: DorkBuilderInput) -> str:
    """
    Construct a dork query from individual components.
    Useful for building complex queries programmatically.
    """
    parts = []

    if input.site:
        parts.append(f"site:{input.site}")
    if input.filetype:
        parts.append(f"filetype:{input.filetype}")
    if input.intitle:
        parts.append(f'intitle:"{input.intitle}"' if " " in input.intitle else f"intitle:{input.intitle}")
    if input.inurl:
        parts.append(f'inurl:"{input.inurl}"' if " " in input.inurl else f"inurl:{input.inurl}")
    if input.intext:
        parts.append(f'intext:"{input.intext}"' if " " in input.intext else f"intext:{input.intext}")

    if input.exact_match:
        parts.append(f'"{input.base_query}"')
    else:
        parts.append(input.base_query)

    if input.exclude_sites:
        for site in input.exclude_sites:
            parts.append(f"-site:{site}")

    dork_query = " ".join(parts)

    lines = [
        "## 🔧 Built Dork Query",
        f"```",
        dork_query,
        f"```",
        "",
        "**Components:**",
    ]
    if input.site:
        lines.append(f"- Site: `{input.site}`")
    if input.filetype:
        lines.append(f"- File type: `{input.filetype}`")
    if input.intitle:
        lines.append(f"- Title contains: `{input.intitle}`")
    if input.inurl:
        lines.append(f"- URL contains: `{input.inurl}`")
    if input.intext:
        lines.append(f"- Body contains: `{input.intext}`")
    if input.exclude_sites:
        lines.append(f"- Excluded sites: {', '.join(f'`{s}`' for s in input.exclude_sites)}")
    if input.date_range:
        lines.append(f"- Date range: `{input.date_range}`")

    lines.extend(["", "Copy the query above or use `dork_search` to execute it."])
    return "\n".join(lines)


@mcp.tool()
async def multi_dork(input: MultiDorkInput) -> str:
    """
    Execute multiple dork queries in sequence and return consolidated results.
    Useful for comprehensive reconnaissance with varied search angles.
    """
    all_results: List[SearchResult] = []
    per_query: Dict[str, int] = {}

    for query in input.queries:
        try:
            results, _ = await _search_with_fallback(query, input.max_results_per_query)
            per_query[query] = len(results)
            all_results.extend(results)
        except Exception as e:
            per_query[query] = 0
            logger.warning(f"Multi-dork query failed: {query}: {e}")
        await asyncio.sleep(0.3)

    all_results = _filter_results(all_results)

    if input.format == "json":
        data = {
            "queries": input.queries,
            "per_query_counts": per_query,
            "total_unique_results": len(all_results),
            "results": [r.to_dict() for r in all_results],
        }
        return json.dumps(data, indent=2)

    lines = [
        f"## 🔍 Multi-Dork Results ({len(all_results)} unique results)",
        "",
        "**Queries:**",
    ]
    for q, count in per_query.items():
        lines.append(f"- `{q}` → {count} results")
    lines.append("")

    for i, r in enumerate(all_results, 1):
        qi = "🟢" if r.quality_score >= 1.0 else "🟡" if r.quality_score >= 0.7 else "🔴"
        lines.extend([f"### {i}. {r.title} {qi}", f"**URL:** {r.url}", r.snippet or "_No snippet_", ""])

    return "\n".join(lines)


@mcp.tool()
async def dork_analyze(input: DorkAnalyzeInput) -> str:
    """
    Extract content, metadata, emails, links, and technology fingerprints from URLs.
    Use this after dork_search to deeply analyze interesting findings.
    
    Extracts: page title, description, headers, email addresses, outbound links,
    and detected technologies (WordPress, React, PHP, Nginx, AWS, etc.)
    """
    results = []
    for url in input.urls:
        data = await _extract_page_content(url)
        results.append(data)
        await asyncio.sleep(0.5)

    lines = ["## 🔬 Content Analysis Report", ""]
    for data in results:
        lines.append(f"### 📄 {data['url']}")
        lines.append(f"**Status:** {data['status']}")

        meta = data.get("metadata", {})
        if meta.get("title"):
            lines.append(f"**Title:** {meta['title']}")
        if meta.get("description"):
            lines.append(f"**Description:** {meta['description'][:200]}")
        if meta.get("server"):
            lines.append(f"**Server:** {meta['server']}")
        if meta.get("powered_by"):
            lines.append(f"**Powered By:** {meta['powered_by']}")
        if meta.get("headers"):
            lines.append("**Page Headers:**")
            for h in meta["headers"][:10]:
                lines.append(f"  - {h}")

        if input.extract_emails and data.get("emails"):
            lines.append(f"**📧 Emails Found ({len(data['emails'])}):**")
            for email in data["emails"]:
                lines.append(f"  - {email}")

        if input.extract_tech and data.get("technologies"):
            lines.append(f"**🛠 Technologies Detected:** {', '.join(data['technologies'])}")

        if input.extract_links and data.get("links"):
            lines.append(f"**🔗 Links ({len(data['links'])} found):**")
            for link in data["links"][:15]:
                text = link["text"][:60] if link["text"] else "(no text)"
                lines.append(f"  - [{text}]({link['url']})")

        lines.append("")

    return "\n".join(lines)


@mcp.tool()
async def dork_export(input: DorkExportInput) -> str:
    """
    Search and export results to a CSV or JSON file for further analysis.
    Files are saved to the configured export directory.
    """
    try:
        results, backend = await _search_with_fallback(input.query, input.max_results)
    except Exception as e:
        return f"❌ Search failed: {str(e)}"

    export_dir = Path(CONFIG["EXPORT_DIR"])
    export_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = input.filename or f"dorker_{timestamp}"

    if input.export_format == "csv":
        filepath = export_dir / f"{base_name}.csv"
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["title", "url", "snippet", "source", "quality_score", "timestamp"])
        writer.writeheader()
        for r in results:
            writer.writerow(r.to_dict())
        filepath.write_text(output.getvalue())
    else:
        filepath = export_dir / f"{base_name}.json"
        data = {
            "query": input.query,
            "backend": backend,
            "exported_at": datetime.now().isoformat(),
            "result_count": len(results),
            "results": [r.to_dict() for r in results],
        }
        filepath.write_text(json.dumps(data, indent=2))

    return f"## ✅ Export Complete\n\n**Query:** `{input.query}`\n**Results:** {len(results)}\n**File:** `{filepath}`\n**Format:** {input.export_format.upper()}\n**Backend:** {backend}"


@mcp.tool()
async def dork_suggest(input: DorkSuggestInput) -> str:
    """
    Generate smart dork suggestions tailored to a target domain or topic.
    Combines operator knowledge with target context to produce effective queries.
    """
    target = input.target
    suggestions: Dict[str, List[str]] = {}

    # Always include general recon
    suggestions["🔍 General Reconnaissance"] = [
        f'site:{target}',
        f'site:{target} filetype:pdf',
        f'site:{target} filetype:doc OR filetype:docx OR filetype:xls',
        f'site:{target} intitle:"index of"',
    ]

    focus_map = {
        "credentials": {
            "🔑 Credential Exposure": [
                f'site:{target} filetype:env',
                f'site:{target} filetype:log "password"',
                f'site:{target} "username" "password" filetype:txt',
                f'site:{target} inurl:".git/config"',
                f'site:{target} filetype:yaml "password:" OR "secret_key:"',
            ]
        },
        "databases": {
            "🗄️ Database Exposure": [
                f'site:{target} filetype:sql',
                f'site:{target} "phpMyAdmin" OR "phpmyadmin"',
                f'site:{target} filetype:sql "INSERT INTO" "password"',
                f'site:{target} inurl:backup filetype:sql',
                f'site:{target} filetype:json "connectionString"',
            ]
        },
        "admin": {
            "🔐 Admin Panels": [
                f'site:{target} inurl:admin',
                f'site:{target} inurl:login',
                f'site:{target} intitle:"dashboard"',
                f'site:{target} inurl:"/wp-admin"',
                f'site:{target} inurl:"/cpanel" OR inurl:"/webmail"',
            ]
        },
        "api": {
            "🔌 API & Endpoints": [
                f'site:{target} inurl:"/api/" OR inurl:"/api/v1"',
                f'site:{target} inurl:swagger OR inurl:api-docs',
                f'site:{target} filetype:json inurl:api',
                f'site:{target} inurl:"/graphql"',
                f'site:{target} filetype:wsdl',
            ]
        },
        "cloud": {
            "☁️ Cloud Storage": [
                f'site:s3.amazonaws.com "{target.replace(".com","").replace(".org","")}"',
                f'site:storage.googleapis.com "{target.replace(".com","").replace(".org","")}"',
                f'site:blob.core.windows.net "{target.replace(".com","").replace(".org","")}"',
                f'site:{target} inurl:"s3.amazonaws.com"',
            ]
        },
        "documents": {
            "📄 Sensitive Documents": [
                f'site:{target} filetype:pdf "confidential"',
                f'site:{target} filetype:pdf "internal use only"',
                f'site:{target} filetype:xlsx "salary" OR "ssn" OR "password"',
                f'site:{target} filetype:pptx "not for distribution"',
            ]
        },
        "vulnerabilities": {
            "⚠️ Vulnerability Indicators": [
                f'site:{target} "Fatal error" filetype:php',
                f'site:{target} "Warning: mysql" filetype:php',
                f'site:{target} inurl:"id=" inurl:".php"',
                f'site:{target} intitle:"index of" ".env"',
                f'site:{target} "phpinfo()" intitle:"phpinfo"',
            ]
        },
    }

    if input.focus and input.focus in focus_map:
        suggestions.update(focus_map[input.focus])
    elif input.include_advanced:
        for category_dorks in focus_map.values():
            suggestions.update(category_dorks)

    lines = [f"## 💡 Dork Suggestions for `{target}`", ""]
    total = 0
    for category, dorks in suggestions.items():
        lines.append(f"### {category}")
        for dork in dorks:
            lines.append(f"```\n{dork}\n```")
            total += 1
        lines.append("")

    lines.append(f"**Total suggestions:** {total}")
    lines.append("\nUse `dork_search` to execute any of these queries.")
    return "\n".join(lines)


@mcp.tool()
async def dork_paginate(input: DorkPaginateInput) -> str:
    """
    Paginate through dork results for deep crawling.
    Each page returns 10 results. Supports up to 10 pages (100 results).
    Uses Google CSE API pagination.
    """
    start_index = (input.page - 1) * 10 + 1

    try:
        api_key = CONFIG["GOOGLE_API_KEY"]
        cse_id = CONFIG["GOOGLE_CSE_ID"]

        if api_key and cse_id:
            results = await _search_google_cse(input.query, max_results=10, start_index=start_index)
            backend = "google_cse"
        else:
            results, backend = await _search_with_fallback(input.query, 10)
    except Exception as e:
        return f"❌ Pagination failed: {str(e)}"

    results = _filter_results(results, min_quality=0.3)
    extra = {"Page": f"{input.page}/10", "Start Index": start_index}

    if input.format == "json":
        return _format_results_json(results, input.query, backend, extra)
    return _format_results_markdown(results, input.query, backend, extra)


@mcp.tool()
async def dork_operators() -> str:
    """List all supported Google dork operators with examples."""
    operators = [
        ("site:", "Restrict to domain", 'site:example.com "login"'),
        ("filetype:", "Filter by file type", "filetype:pdf confidential"),
        ("ext:", "File extension (alias)", "ext:sql password"),
        ("intitle:", "Search page titles", 'intitle:"index of" admin'),
        ("allintitle:", "All words in title", "allintitle:admin login panel"),
        ("inurl:", "Search in URLs", "inurl:/admin/config"),
        ("allinurl:", "All words in URL", "allinurl:admin panel login"),
        ("intext:", "Search page body", 'intext:"database connection string"'),
        ("allintext:", "All words in body", "allintext:username password login"),
        ("cache:", "Google cached version", "cache:example.com"),
        ("link:", "Find linking pages", "link:example.com"),
        ("related:", "Similar sites", "related:example.com"),
        ("info:", "Page information", "info:example.com"),
        ('"quoted"', "Exact phrase match", '"exact phrase search"'),
        ("OR", "Boolean OR", "admin OR administrator"),
        ("-", "Exclude term", "password -change -reset"),
        ("*", "Wildcard", '"admin * panel"'),
        ("..", "Number range", "salary $50000..$100000"),
        ("before:", "Before date", "before:2024-01-01"),
        ("after:", "After date", "after:2023-01-01"),
        ("AROUND(n)", "Proximity search", '"admin" AROUND(3) "password"'),
    ]

    lines = ["## 📖 Google Dork Operators Reference", ""]
    lines.append("| Operator | Description | Example |")
    lines.append("|----------|-------------|---------|")
    for op, desc, example in operators:
        lines.append(f"| `{op}` | {desc} | `{example}` |")

    lines.extend([
        "",
        "### 💡 Tips",
        "- Combine operators for precision: `site:example.com filetype:pdf intitle:confidential`",
        "- Use quotes for exact phrases: `\"database connection string\"`",
        "- Exclude noise with `-`: `admin -site:stackoverflow.com`",
        "- The `filetype:` and `site:` operators are auto-extracted to Google CSE API params for better results",
    ])
    return "\n".join(lines)


@mcp.tool()
async def dork_health() -> str:
    """Check the health status of all search backends and API usage."""
    lines = ["## 🏥 Backend Health Status", ""]

    for name, health in backend_health.items():
        emoji = "🟢" if health.is_healthy else "🔴"
        lines.append(f"### {emoji} {name}")
        lines.append(f"- Status: {'Healthy' if health.is_healthy else 'DEGRADED'}")
        lines.append(f"- Total queries: {health.total_queries}")
        lines.append(f"- Total failures: {health.total_failures}")
        lines.append(f"- Consecutive failures: {health.consecutive_failures}")
        if health.last_success:
            lines.append(f"- Last success: {health.last_success.strftime('%Y-%m-%d %H:%M:%S')}")
        if health.last_failure:
            lines.append(f"- Last failure: {health.last_failure.strftime('%Y-%m-%d %H:%M:%S')}")
        if health.is_rate_limited():
            lines.append(f"- ⚠️ Rate limited until: {health.rate_limit_reset.strftime('%H:%M:%S')}")
        lines.append("")

    # API usage stats
    lines.append("### 📊 Daily API Usage")
    for backend_name in ["google_cse", "bing_api", "serpapi", "brave_api"]:
        usage = cache_manager.get_daily_usage(backend_name)
        lines.append(f"- **{backend_name}:** {usage} calls today")

    # Config check
    lines.extend(["", "### ⚙️ Configuration"])
    configs = {
        "Google CSE": bool(CONFIG["GOOGLE_API_KEY"] and CONFIG["GOOGLE_CSE_ID"]),
        "Bing API": bool(CONFIG["BING_API_KEY"]),
        "SerpAPI": bool(CONFIG["SERPAPI_KEY"]),
        "Brave Search": bool(CONFIG["BRAVE_API_KEY"]),
    }
    for name, configured in configs.items():
        lines.append(f"- {name}: {'✅ Configured' if configured else '❌ Not configured'}")

    return "\n".join(lines)


@mcp.tool()
async def clear_cache() -> str:
    """Clear the search results cache and old API usage records."""
    try:
        cache_manager.cleanup_old_entries(days=0)
        return "✅ Cache cleared successfully. All cached results and usage records have been removed."
    except Exception as e:
        return f"❌ Cache clear failed: {str(e)}"


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    import sys
    logger.info("Starting Dorker MCP Server v3.0...")
    logger.info(f"Google CSE: {'configured' if CONFIG['GOOGLE_API_KEY'] and CONFIG['GOOGLE_CSE_ID'] else 'NOT configured'}")
    logger.info(f"Cache directory: {CONFIG['CACHE_DIR']}")
    logger.info(f"Export directory: {CONFIG['EXPORT_DIR']}")
    logger.info(f"Preset categories: {len(DORK_PRESETS)}")
    logger.info(f"Total preset dorks: {sum(len(p['dorks']) for p in DORK_PRESETS.values())}")

    # Ensure export dir exists
    Path(CONFIG["EXPORT_DIR"]).mkdir(parents=True, exist_ok=True)

    mcp.run(transport="stdio")
