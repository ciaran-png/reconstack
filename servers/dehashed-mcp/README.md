# DeHashed MCP Server

Breach intelligence server for searching exposed credential datasets.

## Setup

```bash
cd /path/to/reconstack/servers/dehashed-mcp
pip install -r requirements.txt
python3 server.py
```

## Required Environment Variables

- `DEHASHED_API_KEY` (required)
- `DEHASHED_EMAIL` (optional)

## Available Tools

- `dehashed_search`: query DeHashed breach data.
- `dehashed_credits`: check remaining account credits.

## Claude Desktop Configuration

```json
{
  "mcpServers": {
    "dehashed": {
      "command": "python3",
      "args": ["/path/to/reconstack/servers/dehashed-mcp/server.py"],
      "env": {
        "DEHASHED_API_KEY": "your_dehashed_api_key",
        "DEHASHED_EMAIL": "your_dehashed_account_email"
      }
    }
  }
}
```

## License

MIT
