# DNSlytics MCP Server

DNS and infrastructure intelligence server powered by DNSlytics data.

## Setup

```bash
cd /path/to/reconstack/servers/dnslytics-mcp
pip install -r requirements.txt
python3 dnslytics_mcp.py
```

## Required Environment Variables

- None.

## Available Tools

- `dnslytics_domain_info`
- `dnslytics_ip_info`
- `dnslytics_asn_info`
- `dnslytics_search`
- `dnslytics_reverse_analytics`
- `dnslytics_reverse_adsense`
- `dnslytics_reverse_ip`
- `dnslytics_reverse_mx`
- `dnslytics_reverse_ns`
- `dnslytics_hosting_history`
- `dnslytics_subdomains`
- `dnslytics_domain_search`
- `dnslytics_tracking_code`
- `dnslytics_subnet_info`
- `dnslytics_ip_to_asn`

## Claude Desktop Configuration

```json
{
  "mcpServers": {
    "dnslytics": {
      "command": "python3",
      "args": ["/path/to/reconstack/servers/dnslytics-mcp/dnslytics_mcp.py"]
    }
  }
}
```

## License

MIT
