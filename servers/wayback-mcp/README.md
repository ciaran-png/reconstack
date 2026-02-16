# Wayback MCP Server

Historical web intelligence server using Internet Archive CDX data.

## Setup

```bash
cd /path/to/reconstack/servers/wayback-mcp
pip install -r requirements.txt
python3 server.py
```

## Required Environment Variables

- None.

## Available Tools

- `wayback_search`
- `wayback_domain_urls`

## Claude Desktop Configuration

```json
{
  "mcpServers": {
    "wayback": {
      "command": "python3",
      "args": ["/path/to/reconstack/servers/wayback-mcp/server.py"]
    }
  }
}
```

## License

MIT
