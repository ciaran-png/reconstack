# GitDorker MCP Server

GitHub code-search dorking server for secret and sensitive-data discovery.

## Setup

```bash
cd /path/to/reconstack/servers/gitdorker-mcp
pip install -r requirements.txt
python3 server.py
```

## Required Environment Variables

- `GITHUB_TOKEN` (optional but recommended for better rate limits)

## Available Tools

- `gitdorker_search`: run custom GitHub dork queries.
- `gitdorker_preset`: run preset dork categories against org/user targets.

## Claude Desktop Configuration

```json
{
  "mcpServers": {
    "gitdorker": {
      "command": "python3",
      "args": ["/path/to/reconstack/servers/gitdorker-mcp/server.py"],
      "env": {
        "GITHUB_TOKEN": "your_github_token"
      }
    }
  }
}
```

## License

MIT
