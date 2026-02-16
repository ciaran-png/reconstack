# Dorker MCP Server v2.0

A production-grade Google dorking tool with intelligent backend fallback, caching, and quality filtering.

## Positioning in ReconStack

Use this server for advanced workflow-style dorking:

- Multi-query orchestration (`dork_target`, `multi_dork`)
- Preset-driven reconnaissance and report-style output
- Backend failover and cache-aware execution

If you only need direct lightweight Google query execution, use `servers/google-dorker` instead.

## Key Features

- **Google Custom Search API** as primary backend
- **SQLite caching** to minimize API calls and avoid rate limits
- **Backend health monitoring** with automatic failover
- **Result quality scoring** to filter low-quality results
- **Comprehensive preset library** for targeted searches
- **Targeted scanning** for OSINT investigations

## Quick Start

### 1. Install Dependencies

```bash
cd dorking
pip install -r requirements.txt
```

### 2. Configure Google Custom Search API (Recommended)

**Step 1: Create Google Cloud Project**
1. Go to https://console.cloud.google.com/
2. Create a new project (or select existing)
3. Enable the "Custom Search API" in APIs & Services

**Step 2: Create API Key**
1. Go to APIs & Services > Credentials
2. Click "Create Credentials" > "API Key"
3. Copy the API key

**Step 3: Create Programmable Search Engine**
1. Go to https://programmablesearchengine.google.com/
2. Click "Add" to create a new search engine
3. Under "What to search": Select "Search the entire web"
4. Give it a name and create
5. Copy the "Search engine ID" (cx parameter)

**Step 4: Set Environment Variables**
```bash
export GOOGLE_API_KEY='<set_here>'
export GOOGLE_CSE_ID='<set_here>'
```

### 3. Optional: Configure Bing API (Secondary)

Free tier: 1000 queries/month

```bash
export BING_API_KEY='<set_here>'
```

### 4. Update Claude Desktop Config

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "dorker": {
      "command": "python",
      "args": ["/path/to/reconstack/servers/dorking/server.py"],
      "env": {
        "GOOGLE_API_KEY": "your-api-key",
        "GOOGLE_CSE_ID": "your-cse-id"
      }
    }
  }
}
```

## Available Tools

| Tool | Description |
|------|-------------|
| `dork_search` | Execute custom dork query |
| `dork_preset` | Run preset dork category |
| `dork_target` | Comprehensive scan of specific target |
| `list_presets` | List all available presets |
| `build_dork` | Build dork query from components |
| `multi_dork` | Execute multiple queries with aggregation |
| `dork_health` | Check backend health and configuration |
| `dork_operators` | Show dork operator reference |
| `clear_cache` | Clear cache and reset health |

## Preset Categories

- **open_directories** — Find open directory listings
- **config_files** — Find exposed configuration files
- **credentials_exposed** — Find exposed credentials (CRITICAL)
- **database_files** — Find exposed database dumps (CRITICAL)
- **git_exposure** — Find exposed Git repositories
- **backup_files** — Find backup/archive files
- **login_pages** — Find login portals
- **admin_panels** — Find admin panels
- **sqli_vectors** — Find SQL injection vectors
- **nonprofit_990** — Find nonprofit 990 tax filings
- **nonprofit_grants** — Find nonprofit grant information
- **documents** — Find exposed documents
- **logs** — Find exposed log files

## Backend Priority

1. **Google CSE** (if configured) — Best for dorks, 100/day free
2. **Bing API** (if configured) — 1000/month free
3. **SerpAPI** (if configured) — 100/month free
4. **Bing Scraping** — No API, less reliable
5. **DuckDuckGo** — No API, may block

## Caching

Results are cached in SQLite at `~/.cache/dorker_mcp/` with 24-hour TTL by default.

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GOOGLE_API_KEY` | Google Cloud API key | - |
| `GOOGLE_CSE_ID` | Programmable Search Engine ID | - |
| `BING_API_KEY` | Bing Web Search API key | - |
| `SERPAPI_KEY` | SerpAPI key | - |
| `DORKER_CACHE_DIR` | Cache directory | `~/.cache/dorker_mcp` |
| `DORKER_CACHE_TTL` | Cache TTL in hours | `24` |

## Example Usage

```
# Basic dork search
dork_search(query="site:example.org filetype:pdf")

# Preset search
dork_preset(preset="nonprofit_990", target="example.org")

# Comprehensive target scan
dork_target(target="example.org", categories=["documents", "nonprofit_990"])

# Build custom query
build_dork(target_domain="example.org", file_types=["pdf", "doc"], keywords=["confidential"])
```

## License

MIT
