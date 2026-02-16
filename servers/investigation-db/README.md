# Investigation DB — MCP Server

A pure-Python MCP server providing **27 tools** for managing an SQLite-backed
investigation notebook.  Think of it as a structured notepad purpose-built for
OSINT and research workflows: hierarchical sections with revision history,
entity/identifier tracking, claim verification, task management, and full-text
search — all accessible as MCP tool calls.

## Quick start

```bash
# Set the database path (defaults to ./data/investigation.sqlite)
export INVESTIGATION_DB_PATH=./data/investigation.sqlite

# Run directly
pip install -r requirements.txt
python -m src.server

# Or via Docker Compose (from the repo root)
docker compose up investigation-db
```

## Environment variables

| Variable                | Default                        | Description                       |
|-------------------------|--------------------------------|-----------------------------------|
| `INVESTIGATION_DB_PATH` | `./data/investigation.sqlite`  | Path to the SQLite database file  |

The schema is applied automatically on first connection — no manual setup needed.

## Tool catalogue (27 tools)

| Category     | Tool                     | Description                                         |
|--------------|--------------------------|-----------------------------------------------------|
| **Overview** | `inv_dashboard`          | Counts, recent activity, claim stats                |
|              | `inv_outline`            | Full document outline tree                          |
| **Search**   | `inv_search`             | FTS5 full-text search                               |
|              | `inv_multi_search`       | Batch multiple FTS queries                          |
|              | `inv_search_and_fetch`   | Search + return full sections in one call            |
| **Sections** | `inv_get_section`        | Fetch section with context, claims, identifiers     |
|              | `inv_get_sections`       | Batch fetch (max 20)                                |
|              | `inv_create_section`     | Create new section                                  |
|              | `inv_update_section`     | Update title/body with revision tracking            |
|              | `inv_delete_section`     | Delete section (cascade/reparent)                   |
|              | `inv_move_section`       | Move/reorder section                                |
|              | `inv_merge_sections`     | Merge source into target + migrate data             |
| **Entities** | `inv_list_entities`      | List entities (person, org, place, other)            |
|              | `inv_get_entity_network` | Entity detail with identifiers + section mentions   |
|              | `inv_upsert_entity`      | Create/update entity                                |
|              | `inv_delete_entity`      | Delete entity (unlink/cascade identifiers)          |
| **IDs**      | `inv_list_identifiers`   | List identifiers (EIN, domain, email, IP …)         |
|              | `inv_link_identifier`    | Link identifier to entity/section                   |
|              | `inv_delete_identifier`  | Delete identifier + mentions                        |
| **Claims**   | `inv_list_claims`        | Filter claims by status/confidence/search           |
|              | `inv_create_claim`       | Create claim linked to section                      |
|              | `inv_update_claim_status`| Update claim status/confidence                      |
|              | `inv_delete_claim`       | Delete claim + evidence                             |
| **Tasks**    | `inv_list_tasks`         | List investigation tasks                            |
|              | `inv_create_task`        | Create task                                         |
|              | `inv_update_task`        | Update status/priority                              |
|              | `inv_delete_task`        | Delete task                                         |
| **Export**   | `inv_export_markdown`    | Export full report to Markdown                      |
| **Maint.**   | `inv_cleanup_orphans`    | Find/remove orphaned records (dry-run default)      |
|              | `inv_rebuild_fts`        | Rebuild FTS5 indexes                                |
|              | `inv_vacuum_db`          | VACUUM database                                     |
|              | `inv_execute_sql`        | Raw SQL (read-only default)                         |

## Architecture

```
src/
├── __init__.py
├── __main__.py      # python -m src.server entry point
├── server.py        # MCP server — tool definitions + handler routing
├── db_api.py        # InvestigationDB class — all business logic
└── db_utils.py      # Shared helpers (hashing, SQLite connect, normalize)
data/
└── schema.sql       # DDL applied on first connection
```

Pure Python, zero external deps beyond the MCP SDK.  SQLite is stdlib.
