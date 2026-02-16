# CorpData MCP Server

Corporate registry intelligence server focused on US nonprofit/public company lookups with optional UK Companies House enrichment.

## Setup

```bash
cd /path/to/reconstack/servers/corpdata-mcp
pip install -r requirements.txt
python3 server.py
```

## Required Environment Variables

- `COMPANIES_HOUSE_API_KEY` (optional): enables UK Companies House lookups.

## Available Tools

- `nonprofit_search`: search US nonprofits by name.
- `nonprofit_details`: fetch nonprofit details by EIN.
- `nonprofit_990`: retrieve nonprofit IRS Form 990 filing data.

## Claude Desktop Configuration

```json
{
  "mcpServers": {
    "corpdata": {
      "command": "python3",
      "args": ["/path/to/reconstack/servers/corpdata-mcp/server.py"],
      "env": {
        "COMPANIES_HOUSE_API_KEY": "your_companies_house_api_key"
      }
    }
  }
}
```

## License

MIT
