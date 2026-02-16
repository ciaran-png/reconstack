# ExifTool MCP Server

Metadata extraction server for local files using ExifTool.

## Setup

```bash
# macOS example
brew install exiftool

cd /path/to/reconstack/servers/exiftool-mcp
pip install -r requirements.txt
python3 server.py
```

## Required Environment Variables

- None.

## Available Tools

- `exiftool_extract`: extract and summarize metadata for a local file.

## Claude Desktop Configuration

```json
{
  "mcpServers": {
    "exiftool": {
      "command": "python3",
      "args": ["/path/to/reconstack/servers/exiftool-mcp/server.py"]
    }
  }
}
```

## License

MIT
