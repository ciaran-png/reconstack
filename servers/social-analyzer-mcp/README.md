# Social Analyzer MCP Server

Username reconnaissance server powered by Maigret.

## Setup

```bash
pip install maigret

cd /path/to/reconstack/servers/social-analyzer-mcp
pip install -r requirements.txt
python3 server.py
```

## Required Environment Variables

- None.

## Available Tools

- `social_analyzer_search`: scan a username across supported platforms.

## Claude Desktop Configuration

```json
{
  "mcpServers": {
    "social-analyzer": {
      "command": "python3",
      "args": ["/path/to/reconstack/servers/social-analyzer-mcp/server.py"]
    }
  }
}
```

## License

MIT
