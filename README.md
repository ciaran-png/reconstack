# ReconStack

ReconStack is a production MCP suite for security reconnaissance and OSINT workflows.

- Total servers: **21**
- Free tier: **8**
- Pro add-on tier: **13**

## BYOK Policy

ReconStack is a connector and automation layer. Third-party API subscriptions are **not** included.

- You bring your own API keys (BYOK) for providers like Shodan, VirusTotal, DeHashed, Telegram, and Google APIs.
- Keyless tools remain fully usable without paid provider subscriptions.

## Tier Breakdown

### Free Tier (8)
- `crtsh-mcp`
- `dorking`
- `exiftool-mcp`
- `google-dorker`
- `holehe-mcp`
- `social-analyzer-mcp`
- `trufflehog-mcp`
- `wayback-mcp`

### Pro Add-On Tier (13)
- `corpdata-mcp`
- `dehashed-mcp`
- `dnslytics-mcp`
- `gitdorker-mcp`
- `neo4j-osint`
- `nmap-mcp`
- `opencorporates-mcp`
- `phoneinfoga-mcp`
- `sherlockeye-mcp`
- `shodan-mcp`
- `telegram-mcp`
- `urban-scout-mcp`
- `virustotal-mcp`

## Dorking Server Roles (No Overlap)

- `dorking`: advanced multi-backend dork workflow server (presets, caching, multi-query orchestration, backend failover).
- `google-dorker`: lightweight Google Programmable Search executor for targeted, fast dork queries.

## Repository Layout

- `servers/`: all 21 MCP servers
- `install.sh`: dependency installer for all servers
- `configure-claude.sh`: writes/updates Claude Desktop config entries for all servers
- `.env.example`: environment variable template
- `docker-compose.yml`: containerized deployment for all servers
- `Dockerfile.python`: shared Python image for compose services
- `landing-page/`: sales/marketing page

## Quick Start

### 1. Install dependencies

```bash
./install.sh
```

### 2. Configure environment variables

```bash
cp .env.example .env
# edit .env and add required keys
```

### 3. Configure Claude Desktop

```bash
./configure-claude.sh
```

### 4. Restart Claude Desktop

After restarting Claude Desktop, all ReconStack servers will be available.

## Docker Deployment

```bash
docker compose up -d
```

This launches all 21 MCP services and a preconfigured Neo4j database container for `neo4j-osint`.

## Environment Variables

Use canonical variable names for new installs. Legacy aliases are still supported for compatibility.

### Canonical Names
- `SHODAN_API_KEY`
- `VIRUSTOTAL_API_KEY`
- `DEHASHED_API_KEY`
- `DEHASHED_EMAIL` (optional)
- `GOOGLE_API_KEY`
- `GOOGLE_CSE_ID`
- `GITHUB_TOKEN`
- `SHERLOCKEYE_API_KEY`
- `OPENCORPORATES_API_KEY` (optional)
- `COMPANIES_HOUSE_API_KEY` (optional)
- `TELEGRAM_API_ID`
- `TELEGRAM_API_HASH`
- `GOOGLE_MAPS_API_KEY`
- `NEO4J_URI` (neo4j server)
- `NEO4J_USER` (neo4j server)
- `NEO4J_PASSWORD` (neo4j server)
- `SQLITE_DB_PATH` (neo4j sync tools)

### Legacy Aliases (supported)
- `GOOGLE_CX` -> `GOOGLE_CSE_ID`
- `TG_API_ID` -> `TELEGRAM_API_ID`
- `TG_API_HASH` -> `TELEGRAM_API_HASH`
- `URBAN_SCOUT_API_KEY` -> `GOOGLE_MAPS_API_KEY`
- `VT_API_KEY` -> `VIRUSTOTAL_API_KEY`

## Server Entry Points

- Most servers: `server.py`
- `dnslytics-mcp`: `dnslytics_mcp.py`
- `nmap-mcp`: `nmap_mcp/server.py`
- `neo4j-osint`: `src/server.py` (module run: `python3 -m src.server`)
- `urban-scout-mcp`: `urban_scout.py`

`configure-claude.sh` applies these automatically.

## Support

- Email: `support@reconstack.dev`

## License

Commercial license. See `LICENSE` for terms.
