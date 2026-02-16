# crt.sh MCP Server

Certificate transparency intelligence server for domain certificate history and subdomain discovery.

## Setup

```bash
cd /path/to/reconstack/servers/crtsh-mcp
pip install -r requirements.txt
python3 server.py
```

## Required Environment Variables

- None.

## Available Tools

- `crtsh_search`: search certificate transparency records for a domain.
- `crtsh_subdomains`: enumerate subdomains from certificate logs.

## Claude Desktop Configuration

```json
{
  "mcpServers": {
    "crtsh": {
      "command": "python3",
      "args": ["/path/to/reconstack/servers/crtsh-mcp/server.py"]
    }
  }
}
```

## License

MIT
