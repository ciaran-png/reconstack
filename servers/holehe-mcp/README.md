# Holehe MCP Server

Email-account discovery server powered by Holehe.

## Setup

```bash
pip install holehe

cd /path/to/reconstack/servers/holehe-mcp
pip install -r requirements.txt
python3 server.py
```

## Required Environment Variables

- None.

## Available Tools

- `holehe_check`: check whether an email is registered across supported services.

## Claude Desktop Configuration

```json
{
  "mcpServers": {
    "holehe": {
      "command": "python3",
      "args": ["/path/to/reconstack/servers/holehe-mcp/server.py"]
    }
  }
}
```

## License

MIT
