# Shodan MCP Server

Internet-exposure intelligence server powered by the Shodan API.

## Setup

```bash
cd /path/to/reconstack/servers/shodan-mcp
pip install -r requirements.txt
python3 server.py
```

## Required Environment Variables

- `SHODAN_API_KEY` (required)

## Available Tools

- `shodan_search`
- `shodan_host`
- `shodan_dns_domain`
- `shodan_dns_resolve`
- `shodan_dns_reverse`
- `shodan_api_info`

## Claude Desktop Configuration

```json
{
  "mcpServers": {
    "shodan": {
      "command": "python3",
      "args": ["/path/to/reconstack/servers/shodan-mcp/server.py"],
      "env": {
        "SHODAN_API_KEY": "your_shodan_api_key"
      }
    }
  }
}
```

## License

MIT
