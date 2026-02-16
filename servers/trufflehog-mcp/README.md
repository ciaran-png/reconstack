# TruffleHog MCP Server

Git secret scanning server that wraps the TruffleHog CLI.

## Setup

```bash
# macOS example
brew install trufflehog

cd /path/to/reconstack/servers/trufflehog-mcp
pip install -r requirements.txt
python3 server.py
```

## Required Environment Variables

- None.

## Available Tools

- `trufflehog_scan`: scan a repository URL for leaked credentials and secrets.

## Claude Desktop Configuration

```json
{
  "mcpServers": {
    "trufflehog": {
      "command": "python3",
      "args": ["/path/to/reconstack/servers/trufflehog-mcp/server.py"]
    }
  }
}
```

## License

MIT
