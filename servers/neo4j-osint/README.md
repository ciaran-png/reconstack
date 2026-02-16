# Neo4j OSINT MCP Server

Graph-analysis MCP server for relationship exploration, path finding, clustering, and Neo4j-backed investigations.

## Setup

```bash
cd /path/to/reconstack/servers/neo4j-osint
pip install -r requirements.txt
python3 -m src.server
```

## Required Environment Variables

- `NEO4J_URI` (default: `bolt://localhost:7687`)
- `NEO4J_USER` (default: `neo4j`)
- `NEO4J_PASSWORD` (required for authenticated database access)
- `SQLITE_DB_PATH` (required only for SQLite sync tools)

## Available Tools

- `neo4j_status`, `neo4j_schema`, `neo4j_init_schema`, `neo4j_query`
- `neo4j_find`, `neo4j_profile`
- `neo4j_shortest_path`, `neo4j_all_paths`, `neo4j_common_connections`
- `neo4j_pagerank`, `neo4j_bridges`, `neo4j_communities`, `neo4j_similar`, `neo4j_triangles`
- `neo4j_money_flow`, `neo4j_officer_network`, `neo4j_address_cluster`, `neo4j_red_flags`
- `neo4j_sync_sqlite`, `neo4j_sync_grants`, `neo4j_sync_officers`

## Claude Desktop Configuration

```json
{
  "mcpServers": {
    "neo4j-osint": {
      "command": "python3",
      "args": ["-m", "src.server"],
      "cwd": "/path/to/reconstack/servers/neo4j-osint",
      "env": {
        "NEO4J_URI": "bolt://localhost:7687",
        "NEO4J_USER": "neo4j",
        "NEO4J_PASSWORD": "your_neo4j_password",
        "SQLITE_DB_PATH": "/path/to/source.sqlite"
      }
    }
  }
}
```

## License

MIT
