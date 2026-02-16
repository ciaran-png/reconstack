# VirusTotal MCP Server

Threat intelligence server for domains, IPs, URLs, files, and search operations against VirusTotal.

## Setup

```bash
cd /path/to/reconstack/servers/virustotal-mcp
pip install -r requirements.txt
python3 server.py
```

## Required Environment Variables

- `VIRUSTOTAL_API_KEY` (recommended canonical name)
- `VT_API_KEY` (legacy alias)

## Available Tools

- `vt_domain`
- `vt_domain_dns`
- `vt_domain_subdomains`
- `vt_ip`
- `vt_ip_dns`
- `vt_url`
- `vt_file`
- `vt_search`

## Claude Desktop Configuration

```json
{
  "mcpServers": {
    "virustotal": {
      "command": "python3",
      "args": ["/path/to/reconstack/servers/virustotal-mcp/server.py"],
      "env": {
        "VIRUSTOTAL_API_KEY": "your_virustotal_api_key"
      }
    }
  }
}
```

## Notes

- Free tier limits are enforced by VirusTotal.
- Advanced intelligence features depend on your VirusTotal account plan.

## License

MIT
