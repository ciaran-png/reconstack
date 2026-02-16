# Google Dorker MCP Server

Google Programmable Search dorking server for targeted web exposure queries.

## Setup

```bash
cd /path/to/reconstack/servers/google-dorker
pip install -r requirements.txt
python3 server.py
```

## Required Environment Variables

- `GOOGLE_API_KEY` (required)
- `GOOGLE_CSE_ID` (required)
- `GOOGLE_CX` (legacy alias supported for `GOOGLE_CSE_ID`)

## Available Tools

- `run_dork_scan`: run a strategy-driven dork scan against a target domain.
- `raw_advanced_search`: run custom raw dork queries.

## Claude Desktop Configuration

```json
{
  "mcpServers": {
    "google-dorker": {
      "command": "python3",
      "args": ["/path/to/reconstack/servers/google-dorker/server.py"],
      "env": {
        "GOOGLE_API_KEY": "your_google_api_key",
        "GOOGLE_CSE_ID": "your_programmable_search_engine_id"
      }
    }
  }
}
```

## License

MIT
