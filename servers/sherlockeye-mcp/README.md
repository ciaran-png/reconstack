# SherlockEye MCP Server

Identity-search server for username, email, phone, and related attribution lookups.

## Setup

```bash
cd /path/to/reconstack/servers/sherlockeye-mcp
pip install -r requirements.txt
python3 server.py
```

## Required Environment Variables

- `SHERLOCKEYE_API_KEY` (required)

## Available Tools

- `sherlockeye_search`
- `sherlockeye_get_results`
- `sherlockeye_quick_search`
- `sherlockeye_delete`
- `sherlockeye_balance`
- `sherlockeye_blockchain`

## Claude Desktop Configuration

```json
{
  "mcpServers": {
    "sherlockeye": {
      "command": "python3",
      "args": ["/path/to/reconstack/servers/sherlockeye-mcp/server.py"],
      "env": {
        "SHERLOCKEYE_API_KEY": "your_sherlockeye_api_key"
      }
    }
  }
}
```

## License

MIT
