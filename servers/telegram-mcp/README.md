# Telegram MCP Server

Telegram intelligence server for global search, channel inspection, and keyword discovery.

## Setup

```bash
cd /path/to/reconstack/servers/telegram-mcp
pip install -r requirements.txt
python3 auth.py   # one-time login flow, creates anon.session
python3 server.py
```

## Required Environment Variables

- `TELEGRAM_API_ID` (required)
- `TELEGRAM_API_HASH` (required)
- `TG_API_ID` and `TG_API_HASH` are accepted legacy aliases.

## Available Tools

- `search_global`: search Telegram entities globally.
- `get_channel_info`: inspect channel metadata and recent messages.
- `search_messages`: search messages inside a target channel.

## Claude Desktop Configuration

```json
{
  "mcpServers": {
    "telegram": {
      "command": "python3",
      "args": ["/path/to/reconstack/servers/telegram-mcp/server.py"],
      "env": {
        "TELEGRAM_API_ID": "your_telegram_api_id",
        "TELEGRAM_API_HASH": "your_telegram_api_hash"
      }
    }
  }
}
```

## License

MIT
