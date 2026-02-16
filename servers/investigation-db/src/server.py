"""
Investigation DB MCP Server
===========================
A pure-Python MCP server providing 27 tools for managing an SQLite-backed
investigation notebook.  Covers dashboarding, FTS search, entity/identifier
management, claims tracking, task management, section CRUD with revisions,
markdown export, and database maintenance.

Follows the reconstack pattern used by neo4j-osint and shodan-mcp.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

import mcp.types as types
from mcp.server import Server
from mcp.server.stdio import run_server

from src.db_api import InvestigationDB

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("investigation-db-mcp")

# ---------------------------------------------------------------------------
# Server + global DB handle
# ---------------------------------------------------------------------------
app = Server("investigation-db-mcp")
logger.info("Initializing Investigation DB MCP Server")

_db: InvestigationDB | None = None


def get_db() -> InvestigationDB:
    global _db
    if _db is None:
        db_path = Path(os.getenv("INVESTIGATION_DB_PATH", "./data/investigation.sqlite")).expanduser().resolve()
        logger.info(f"Opening investigation DB at {db_path}")
        _db = InvestigationDB.open(db_path)
    return _db


def fmt(result: Any) -> list[types.TextContent]:
    """Format a result dict as JSON text content."""
    return [types.TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False, default=str))]


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL DEFINITIONS (27 tools)
# ═══════════════════════════════════════════════════════════════════════════════


@app.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    return [
        # ── Navigation & Overview ──────────────────────────────────────────
        types.Tool(
            name="inv_dashboard",
            description="Get a single-call overview of the investigation database: record counts, recent revisions, pending tasks, and claim breakdown.",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        types.Tool(
            name="inv_outline",
            description="Get the full document structure as a navigable outline tree. Much more efficient than blind searching.",
            inputSchema={
                "type": "object",
                "properties": {
                    "include_claims": {"type": "boolean", "description": "Include claims per section", "default": False},
                    "include_tasks": {"type": "boolean", "description": "Include tasks per section", "default": False},
                },
            },
        ),
        # ── Search ─────────────────────────────────────────────────────────
        types.Tool(
            name="inv_search",
            description="Full-text search across sections and claims with optional inline body snippets.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "FTS5 search query"},
                    "limit": {"type": "integer", "default": 10},
                    "kind": {"type": "string", "enum": ["all", "sections", "claims"], "default": "all"},
                    "include_body": {"type": "boolean", "default": False},
                    "max_body_chars": {"type": "integer", "default": 500},
                },
                "required": ["query"],
            },
        ),
        types.Tool(
            name="inv_multi_search",
            description="Execute multiple FTS searches in one call. Perfect for exploring related concepts.",
            inputSchema={
                "type": "object",
                "properties": {
                    "queries": {"type": "array", "items": {"type": "string"}, "description": "List of search queries"},
                    "limit_per_query": {"type": "integer", "default": 5},
                    "kind": {"type": "string", "enum": ["all", "sections", "claims"], "default": "sections"},
                },
                "required": ["queries"],
            },
        ),
        types.Tool(
            name="inv_search_and_fetch",
            description="COMPOSITE: Search and return full section content in one call. Saves 2+ round trips.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "FTS5 search query"},
                    "limit": {"type": "integer", "default": 5},
                    "max_body_chars": {"type": "integer", "default": 1500},
                    "include_claims": {"type": "boolean", "default": True},
                },
                "required": ["query"],
            },
        ),
        # ── Sections ───────────────────────────────────────────────────────
        types.Tool(
            name="inv_get_section",
            description="Fetch a single section with navigation context (breadcrumbs, children, siblings), claims, and identifiers.",
            inputSchema={
                "type": "object",
                "properties": {
                    "section_id": {"type": "integer"},
                    "max_chars": {"type": "integer", "description": "Truncate body to N chars (0 = no limit)"},
                    "include_neighbors": {"type": "boolean", "default": True},
                    "include_claims": {"type": "boolean", "default": True},
                    "include_identifiers": {"type": "boolean", "default": True},
                },
                "required": ["section_id"],
            },
        ),
        types.Tool(
            name="inv_get_sections",
            description="Batch fetch multiple sections by ID (max 20).",
            inputSchema={
                "type": "object",
                "properties": {
                    "section_ids": {"type": "array", "items": {"type": "integer"}},
                    "max_chars": {"type": "integer", "default": 2000},
                    "include_claims": {"type": "boolean", "default": False},
                },
                "required": ["section_ids"],
            },
        ),
        types.Tool(
            name="inv_create_section",
            description="Create a new section in the investigation report.",
            inputSchema={
                "type": "object",
                "properties": {
                    "document_id": {"type": "integer"},
                    "parent_id": {"type": "integer", "description": "Parent section ID (null for top-level)"},
                    "title": {"type": "string"},
                    "body_markdown": {"type": "string", "default": ""},
                    "heading_level": {"type": "integer", "description": "1-6, auto-detected if omitted"},
                    "order_index": {"type": "integer", "description": "Position among siblings, auto-detected if omitted"},
                    "author": {"type": "string", "default": "assistant"},
                },
                "required": ["document_id", "title"],
            },
        ),
        types.Tool(
            name="inv_update_section",
            description="Update a section's title and/or body with a revision record.",
            inputSchema={
                "type": "object",
                "properties": {
                    "section_id": {"type": "integer"},
                    "title": {"type": "string", "description": "New title (null to keep)"},
                    "body_markdown": {"type": "string", "description": "New body (null to keep)"},
                    "author": {"type": "string", "default": "assistant"},
                    "change_note": {"type": "string", "description": "Reason for the change (required)"},
                },
                "required": ["section_id", "change_note"],
            },
        ),
        types.Tool(
            name="inv_delete_section",
            description="Delete a section. Cascade deletes children by default; set cascade=false to reparent them.",
            inputSchema={
                "type": "object",
                "properties": {
                    "section_id": {"type": "integer"},
                    "cascade": {"type": "boolean", "default": True},
                },
                "required": ["section_id"],
            },
        ),
        types.Tool(
            name="inv_move_section",
            description="Move a section to a new parent and/or reorder it. Recursively updates child paths.",
            inputSchema={
                "type": "object",
                "properties": {
                    "section_id": {"type": "integer"},
                    "new_parent_id": {"type": "integer"},
                    "new_order_index": {"type": "integer"},
                    "author": {"type": "string", "default": "assistant"},
                },
                "required": ["section_id"],
            },
        ),
        types.Tool(
            name="inv_merge_sections",
            description="Merge source section content into target section. Moves associated claims, tasks, and mentions.",
            inputSchema={
                "type": "object",
                "properties": {
                    "source_section_id": {"type": "integer"},
                    "target_section_id": {"type": "integer"},
                    "append": {"type": "boolean", "default": True, "description": "Append source to target (true) or prepend (false)"},
                    "delete_source": {"type": "boolean", "default": True},
                    "author": {"type": "string", "default": "assistant"},
                },
                "required": ["source_section_id", "target_section_id"],
            },
        ),
        # ── Entities ───────────────────────────────────────────────────────
        types.Tool(
            name="inv_list_entities",
            description="List all entities (people, orgs, places) with identifier counts.",
            inputSchema={
                "type": "object",
                "properties": {
                    "kind": {"type": "string", "enum": ["person", "org", "place", "other"], "description": "Filter by entity kind"},
                    "limit": {"type": "integer", "default": 50},
                },
            },
        ),
        types.Tool(
            name="inv_get_entity_network",
            description="Get entity with all linked identifiers and section mentions — a complete entity graph.",
            inputSchema={
                "type": "object",
                "properties": {
                    "entity_id": {"type": "integer"},
                    "entity_name": {"type": "string", "description": "Fuzzy name match (alternative to entity_id)"},
                },
            },
        ),
        types.Tool(
            name="inv_upsert_entity",
            description="Create or update an entity (person, org, place, other).",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "kind": {"type": "string", "enum": ["person", "org", "place", "other"]},
                    "aliases": {"type": "array", "items": {"type": "string"}, "description": "Known aliases"},
                },
                "required": ["name", "kind"],
            },
        ),
        types.Tool(
            name="inv_delete_entity",
            description="Delete an entity. By default unlinks identifiers; set unlink_identifiers=false to delete them too.",
            inputSchema={
                "type": "object",
                "properties": {
                    "entity_id": {"type": "integer"},
                    "unlink_identifiers": {"type": "boolean", "default": True},
                },
                "required": ["entity_id"],
            },
        ),
        # ── Identifiers ───────────────────────────────────────────────────
        types.Tool(
            name="inv_list_identifiers",
            description="List identifiers (EIN, domain, email, IP, phone, etc.) with optional mention context.",
            inputSchema={
                "type": "object",
                "properties": {
                    "type": {"type": "string", "enum": ["ein", "domain", "url", "ip", "asn", "gtm", "ga_ua", "ga4", "fb_pixel", "email", "phone", "address", "other"]},
                    "limit": {"type": "integer", "default": 50},
                    "with_mentions": {"type": "boolean", "default": False},
                },
            },
        ),
        types.Tool(
            name="inv_link_identifier",
            description="Create or link an identifier (domain, email, EIN, etc.) to an entity and/or section.",
            inputSchema={
                "type": "object",
                "properties": {
                    "type": {"type": "string", "enum": ["ein", "domain", "url", "ip", "asn", "gtm", "ga_ua", "ga4", "fb_pixel", "email", "phone", "address", "other"]},
                    "value": {"type": "string"},
                    "entity_id": {"type": "integer", "description": "Link to this entity"},
                    "section_id": {"type": "integer", "description": "Create mention in this section"},
                    "context": {"type": "string", "description": "Short note about the mention"},
                },
                "required": ["type", "value"],
            },
        ),
        types.Tool(
            name="inv_delete_identifier",
            description="Delete an identifier and all its mentions.",
            inputSchema={
                "type": "object",
                "properties": {"identifier_id": {"type": "integer"}},
                "required": ["identifier_id"],
            },
        ),
        # ── Claims ─────────────────────────────────────────────────────────
        types.Tool(
            name="inv_list_claims",
            description="List claims with optional filters (status, section, confidence, search).",
            inputSchema={
                "type": "object",
                "properties": {
                    "status": {"type": "string", "enum": ["verified", "claimed", "hypothesis", "unknown"]},
                    "section_id": {"type": "integer"},
                    "min_confidence": {"type": "number"},
                    "search": {"type": "string", "description": "LIKE filter on claim text"},
                    "limit": {"type": "integer", "default": 100},
                },
            },
        ),
        types.Tool(
            name="inv_create_claim",
            description="Create a new claim linked to a section.",
            inputSchema={
                "type": "object",
                "properties": {
                    "claim_text": {"type": "string"},
                    "section_id": {"type": "integer"},
                    "status": {"type": "string", "enum": ["verified", "claimed", "hypothesis", "unknown"], "default": "unknown"},
                    "confidence": {"type": "number", "default": 0.5, "description": "0.0 to 1.0"},
                },
                "required": ["claim_text"],
            },
        ),
        types.Tool(
            name="inv_update_claim_status",
            description="Update the status and/or confidence of a claim.",
            inputSchema={
                "type": "object",
                "properties": {
                    "claim_id": {"type": "integer"},
                    "status": {"type": "string", "enum": ["verified", "claimed", "hypothesis", "unknown"]},
                    "confidence": {"type": "number", "description": "0.0 to 1.0"},
                },
                "required": ["claim_id", "status"],
            },
        ),
        types.Tool(
            name="inv_delete_claim",
            description="Delete a claim and its associated evidence.",
            inputSchema={
                "type": "object",
                "properties": {"claim_id": {"type": "integer"}},
                "required": ["claim_id"],
            },
        ),
        # ── Tasks ──────────────────────────────────────────────────────────
        types.Tool(
            name="inv_list_tasks",
            description="List investigation tasks with optional status filter.",
            inputSchema={
                "type": "object",
                "properties": {
                    "status": {"type": "string", "enum": ["pending", "in_progress", "blocked", "done", "cancelled"]},
                    "limit": {"type": "integer", "default": 50},
                },
            },
        ),
        types.Tool(
            name="inv_create_task",
            description="Create a new investigation task.",
            inputSchema={
                "type": "object",
                "properties": {
                    "task_text": {"type": "string"},
                    "section_id": {"type": "integer", "description": "Link to a section"},
                    "status": {"type": "string", "enum": ["pending", "in_progress", "blocked", "done", "cancelled"], "default": "pending"},
                    "priority": {"type": "integer", "default": 3, "description": "1 (highest) to 5 (lowest)"},
                },
                "required": ["task_text"],
            },
        ),
        types.Tool(
            name="inv_update_task",
            description="Update a task's status and/or priority.",
            inputSchema={
                "type": "object",
                "properties": {
                    "task_id": {"type": "integer"},
                    "status": {"type": "string", "enum": ["pending", "in_progress", "blocked", "done", "cancelled"]},
                    "priority": {"type": "integer", "description": "1-5"},
                },
                "required": ["task_id"],
            },
        ),
        types.Tool(
            name="inv_delete_task",
            description="Delete a task.",
            inputSchema={
                "type": "object",
                "properties": {"task_id": {"type": "integer"}},
                "required": ["task_id"],
            },
        ),
        # ── Export ─────────────────────────────────────────────────────────
        types.Tool(
            name="inv_export_markdown",
            description="Export the investigation report to a Markdown file.",
            inputSchema={
                "type": "object",
                "properties": {
                    "output_path": {"type": "string", "description": "File path to write (default: report.export.md)"},
                    "document_id": {"type": "integer", "description": "Specific document to export (default: latest)"},
                },
            },
        ),
        # ── Database Maintenance ──────────────────────────────────────────
        types.Tool(
            name="inv_cleanup_orphans",
            description="Find and optionally remove orphaned records (identifiers, mentions, claims, tasks without valid parents).",
            inputSchema={
                "type": "object",
                "properties": {
                    "dry_run": {"type": "boolean", "default": True, "description": "Preview only (true) or actually delete (false)"},
                },
            },
        ),
        types.Tool(
            name="inv_rebuild_fts",
            description="Rebuild FTS5 full-text search indexes from scratch.",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="inv_vacuum_db",
            description="Vacuum the database to reclaim space and optimize performance.",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="inv_execute_sql",
            description="Execute raw SQL for advanced queries. Read-only by default (SELECT/PRAGMA only). Set readonly=false for write operations.",
            inputSchema={
                "type": "object",
                "properties": {
                    "sql": {"type": "string", "description": "SQL statement to execute"},
                    "params": {"type": "array", "items": {}, "description": "Bind parameters"},
                    "readonly": {"type": "boolean", "default": True},
                },
                "required": ["sql"],
            },
        ),
    ]


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL HANDLER
# ═══════════════════════════════════════════════════════════════════════════════


def _execute_tool_sync(name: str, args: dict) -> Any:
    """Route tool calls to InvestigationDB methods (synchronous)."""
    db = get_db()

    # ── Navigation & Overview ──────────────────────────────────────────
    if name == "inv_dashboard":
        return db.dashboard()

    if name == "inv_outline":
        return db.get_outline(
            include_claims=bool(args.get("include_claims", False)),
            include_tasks=bool(args.get("include_tasks", False)),
        )

    # ── Search ─────────────────────────────────────────────────────────
    if name == "inv_search":
        return db.search(
            query=str(args.get("query", "")),
            limit=int(args.get("limit", 10)),
            kind=str(args.get("kind", "all")),
            include_body=bool(args.get("include_body", False)),
            max_body_chars=int(args.get("max_body_chars", 500)),
        )

    if name == "inv_multi_search":
        queries = args.get("queries", [])
        if not isinstance(queries, list):
            raise ValueError("queries must be a list of strings")
        return db.multi_search(
            queries=queries,
            limit_per_query=int(args.get("limit_per_query", 5)),
            kind=str(args.get("kind", "sections")),
        )

    if name == "inv_search_and_fetch":
        return db.search_and_fetch(
            query=str(args.get("query", "")),
            limit=int(args.get("limit", 5)),
            max_body_chars=int(args.get("max_body_chars", 1500)),
            include_claims=bool(args.get("include_claims", True)),
        )

    # ── Sections ───────────────────────────────────────────────────────
    if name == "inv_get_section":
        return db.get_section(
            section_id=int(args["section_id"]),
            max_chars=int(args["max_chars"]) if args.get("max_chars") else None,
            include_neighbors=bool(args.get("include_neighbors", True)),
            include_claims=bool(args.get("include_claims", True)),
            include_identifiers=bool(args.get("include_identifiers", True)),
        )

    if name == "inv_get_sections":
        section_ids = args.get("section_ids", [])
        if not isinstance(section_ids, list):
            raise ValueError("section_ids must be a list of integers")
        return db.get_sections(
            section_ids=[int(x) for x in section_ids],
            max_chars=int(args["max_chars"]) if args.get("max_chars") else 2000,
            include_claims=bool(args.get("include_claims", False)),
        )

    if name == "inv_create_section":
        return db.create_section(
            document_id=int(args["document_id"]),
            parent_id=int(args["parent_id"]) if args.get("parent_id") is not None else None,
            title=str(args.get("title", "")),
            body_markdown=str(args.get("body_markdown", "")),
            heading_level=int(args["heading_level"]) if args.get("heading_level") is not None else None,
            order_index=int(args["order_index"]) if args.get("order_index") is not None else None,
            author=str(args.get("author", "assistant")),
        )

    if name == "inv_update_section":
        return db.update_section(
            section_id=int(args["section_id"]),
            title=args.get("title"),
            body_markdown=args.get("body_markdown"),
            author=str(args.get("author") or "assistant"),
            change_note=str(args.get("change_note") or ""),
        )

    if name == "inv_delete_section":
        return db.delete_section(
            section_id=int(args["section_id"]),
            cascade=bool(args.get("cascade", True)),
        )

    if name == "inv_move_section":
        return db.move_section(
            section_id=int(args["section_id"]),
            new_parent_id=int(args["new_parent_id"]) if args.get("new_parent_id") is not None else None,
            new_order_index=int(args["new_order_index"]) if args.get("new_order_index") is not None else None,
            author=str(args.get("author", "assistant")),
        )

    if name == "inv_merge_sections":
        return db.merge_sections(
            source_section_id=int(args["source_section_id"]),
            target_section_id=int(args["target_section_id"]),
            append=bool(args.get("append", True)),
            delete_source=bool(args.get("delete_source", True)),
            author=str(args.get("author", "assistant")),
        )

    # ── Entities ───────────────────────────────────────────────────────
    if name == "inv_list_entities":
        return db.list_entities(
            kind=str(args["kind"]) if args.get("kind") else None,
            limit=int(args.get("limit", 50)),
        )

    if name == "inv_get_entity_network":
        return db.get_entity_network(
            entity_id=int(args["entity_id"]) if args.get("entity_id") else None,
            entity_name=str(args["entity_name"]) if args.get("entity_name") else None,
        )

    if name == "inv_upsert_entity":
        aliases = args.get("aliases")
        if aliases is not None and not isinstance(aliases, list):
            raise ValueError("aliases must be a list of strings")
        return db.upsert_entity(
            name=str(args.get("name") or ""),
            kind=str(args.get("kind") or "other"),
            aliases=aliases,
        )

    if name == "inv_delete_entity":
        return db.delete_entity(
            entity_id=int(args["entity_id"]),
            unlink_identifiers=bool(args.get("unlink_identifiers", True)),
        )

    # ── Identifiers ───────────────────────────────────────────────────
    if name == "inv_list_identifiers":
        return db.list_identifiers(
            ident_type=str(args["type"]) if args.get("type") else None,
            limit=int(args.get("limit", 50)),
            with_mentions=bool(args.get("with_mentions", False)),
        )

    if name == "inv_link_identifier":
        return db.link_identifier(
            ident_type=str(args.get("type") or "other"),
            value=str(args.get("value") or ""),
            entity_id=int(args["entity_id"]) if args.get("entity_id") is not None else None,
            section_id=int(args["section_id"]) if args.get("section_id") is not None else None,
            context=str(args.get("context") or ""),
        )

    if name == "inv_delete_identifier":
        return db.delete_identifier(identifier_id=int(args["identifier_id"]))

    # ── Claims ─────────────────────────────────────────────────────────
    if name == "inv_list_claims":
        return db.list_claims(
            status=str(args["status"]) if args.get("status") else None,
            section_id=int(args["section_id"]) if args.get("section_id") is not None else None,
            min_confidence=float(args["min_confidence"]) if args.get("min_confidence") is not None else None,
            search=str(args["search"]) if args.get("search") else None,
            limit=int(args.get("limit", 100)),
        )

    if name == "inv_create_claim":
        return db.create_claim(
            section_id=int(args["section_id"]) if args.get("section_id") is not None else None,
            claim_text=str(args.get("claim_text") or ""),
            status=str(args.get("status") or "unknown"),
            confidence=float(args.get("confidence", 0.5)),
        )

    if name == "inv_update_claim_status":
        return db.update_claim_status(
            claim_id=int(args["claim_id"]),
            status=str(args.get("status") or "unknown"),
            confidence=float(args["confidence"]) if args.get("confidence") is not None else None,
        )

    if name == "inv_delete_claim":
        return db.delete_claim(claim_id=int(args["claim_id"]))

    # ── Tasks ──────────────────────────────────────────────────────────
    if name == "inv_list_tasks":
        status = args.get("status")
        return db.list_tasks(
            status=str(status) if status is not None else None,
            limit=int(args.get("limit", 50)),
        )

    if name == "inv_create_task":
        return db.create_task(
            task_text=str(args.get("task_text", "")),
            section_id=int(args["section_id"]) if args.get("section_id") is not None else None,
            status=str(args.get("status", "pending")),
            priority=int(args.get("priority", 3)),
        )

    if name == "inv_update_task":
        return db.update_task(
            task_id=int(args["task_id"]),
            status=args.get("status"),
            priority=args.get("priority"),
        )

    if name == "inv_delete_task":
        return db.delete_task(task_id=int(args["task_id"]))

    # ── Export ─────────────────────────────────────────────────────────
    if name == "inv_export_markdown":
        return db.export_markdown(
            output_path=str(args["output_path"]) if args.get("output_path") else None,
            document_id=int(args["document_id"]) if args.get("document_id") else None,
        )

    # ── Database Maintenance ──────────────────────────────────────────
    if name == "inv_cleanup_orphans":
        return db.cleanup_orphans(dry_run=bool(args.get("dry_run", True)))

    if name == "inv_rebuild_fts":
        return db.rebuild_fts()

    if name == "inv_vacuum_db":
        return db.vacuum_db()

    if name == "inv_execute_sql":
        return db.execute_sql(
            sql=str(args.get("sql", "")),
            params=args.get("params"),
            readonly=bool(args.get("readonly", True)),
        )

    raise ValueError(f"Unknown tool: {name}")


@app.call_tool()
async def handle_call_tool(name: str, arguments: dict | None) -> list[types.TextContent]:
    args = arguments or {}
    try:
        result = await asyncio.to_thread(_execute_tool_sync, name, args)
        return fmt(result)
    except KeyError as e:
        return [types.TextContent(type="text", text=json.dumps({"error": "not_found", "detail": str(e)}))]
    except ValueError as e:
        return [types.TextContent(type="text", text=json.dumps({"error": "validation", "detail": str(e)}))]
    except Exception as e:
        logger.exception(f"Tool {name} failed")
        return [types.TextContent(type="text", text=json.dumps({"error": e.__class__.__name__, "detail": str(e)}))]


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRYPOINT
# ═══════════════════════════════════════════════════════════════════════════════


def main():
    logger.info("Starting Investigation DB MCP Server via stdio")
    asyncio.run(run_server(app))


if __name__ == "__main__":
    main()
