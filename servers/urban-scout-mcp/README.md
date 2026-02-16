# Urban Scout MCP Server

Location intelligence server for geocoding, Street View previews, traffic context, and nearby-amenity discovery.

## Setup

```bash
cd /path/to/reconstack/servers/urban-scout-mcp
pip install -r requirements.txt
python3 urban_scout.py
```

## Required Environment Variables

- `GOOGLE_MAPS_API_KEY` (canonical)
- `URBAN_SCOUT_API_KEY` (legacy alias)

## Available Tools

- `get_location_coordinates`
- `get_street_view`
- `analyze_traffic_flow`
- `find_nearby_amenities`
- `generate_scout_map`

## Claude Desktop Configuration

```json
{
  "mcpServers": {
    "urban-scout": {
      "command": "python3",
      "args": ["/path/to/reconstack/servers/urban-scout-mcp/urban_scout.py"],
      "env": {
        "GOOGLE_MAPS_API_KEY": "your_google_maps_api_key"
      }
    }
  }
}
```

## License

MIT
