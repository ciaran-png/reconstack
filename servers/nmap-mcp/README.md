# Nmap MCP Server

Network scanning server for host discovery, service enumeration, and targeted security checks.

## Setup

```bash
# macOS example
brew install nmap

cd /path/to/reconstack/servers/nmap-mcp
pip install .
python3 nmap_mcp/server.py
```

## Required Environment Variables

- None.

## Available Tools

- `nmap_list_scan`
- `nmap_ping_scan`
- `nmap_quick_scan`
- `nmap_service_scan`
- `nmap_os_detect`
- `nmap_full_scan`
- `nmap_vuln_scan`
- `nmap_dns_brute`
- `nmap_http_enum`
- `nmap_ssl_enum`
- `nmap_custom`

## Claude Desktop Configuration

```json
{
  "mcpServers": {
    "nmap": {
      "command": "python3",
      "args": ["/path/to/reconstack/servers/nmap-mcp/nmap_mcp/server.py"]
    }
  }
}
```

## License

MIT
