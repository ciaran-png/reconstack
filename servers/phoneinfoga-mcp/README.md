# PhoneInfoga MCP Server

Phone number intelligence server that wraps the PhoneInfoga CLI.

## Setup

```bash
# macOS example
brew install phoneinfoga

cd /path/to/reconstack/servers/phoneinfoga-mcp
pip install -r requirements.txt
python3 server.py
```

## Required Environment Variables

- None.

## Available Tools

- `phoneinfoga_scan`: scan and enrich a phone number.

## Claude Desktop Configuration

```json
{
  "mcpServers": {
    "phoneinfoga": {
      "command": "python3",
      "args": ["/path/to/reconstack/servers/phoneinfoga-mcp/server.py"]
    }
  }
}
```

## License

MIT
