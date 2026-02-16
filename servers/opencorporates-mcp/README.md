# OpenCorporates MCP Server

Corporate registry server backed by the OpenCorporates API.

## Setup

```bash
cd /path/to/reconstack/servers/opencorporates-mcp
pip install -r requirements.txt
python3 server.py
```

## Required Environment Variables

- `OPENCORPORATES_API_KEY` (optional; enables authenticated API access and higher limits)

## Available Tools

- `opencorp_search_company`
- `opencorp_get_company`
- `opencorp_search_officers`
- `opencorp_company_officers`
- `opencorp_company_filings`
- `opencorp_company_network`

## Claude Desktop Configuration

```json
{
  "mcpServers": {
    "opencorporates": {
      "command": "python3",
      "args": ["/path/to/reconstack/servers/opencorporates-mcp/server.py"],
      "env": {
        "OPENCORPORATES_API_KEY": "your_opencorporates_api_key"
      }
    }
  }
}
```

## License

MIT
