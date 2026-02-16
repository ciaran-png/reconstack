"""
Investigation DB API — Optimized for LLM Context Efficiency

Provides a comprehensive API for managing investigation data stored in SQLite:
1. Batch operations (multi_search, get_sections)
2. Composite tools (search_and_fetch)
3. Structural overview (get_outline)
4. Truncation support (max_chars)
5. Stats dashboard
6. Section navigation context
7. Export capability
8. Full CRUD operations (create/delete/move/merge sections)
9. Database maintenance (cleanup, rebuild FTS, vacuum)
10. Raw SQL execution for advanced queries
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional
from datetime import datetime, timezone

from src.db_utils import connect_sqlite, normalize_identifier_value, sha256_text, apply_schema, read_text_file


def _utc_now_sql() -> str:
    return "strftime('%Y-%m-%dT%H:%M:%fZ','now')"


def _slugify(text: str) -> str:
    """Generate a URL-safe anchor/slug from text."""
    slug = re.sub(r"[^\w\s-]", "", text.lower())
    slug = re.sub(r"[\s_]+", "-", slug).strip("-")
    return slug[:80] or "section"


def _path_key(path: str) -> tuple[int, ...]:
    try:
        return tuple(int(p) for p in path.split("/") if p)
    except ValueError:
        return (10**9,)


def _truncate(text: str, max_chars: int | None) -> str:
    """Truncate text with ellipsis indicator."""
    if max_chars is None or max_chars <= 0:
        return text
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n\n... [TRUNCATED - full section has {} more chars]".format(len(text) - max_chars)


@dataclass(frozen=True)
class InvestigationDB:
    conn: sqlite3.Connection

    @classmethod
    def open(cls, db_path: Path) -> "InvestigationDB":
        conn = connect_sqlite(db_path)
        # Auto-apply schema if tables don't exist
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()]
        if "sections" not in tables:
            schema_path = Path(__file__).parent.parent / "data" / "schema.sql"
            if schema_path.exists():
                apply_schema(conn, read_text_file(schema_path))
        return cls(conn=conn)

    def close(self) -> None:
        self.conn.close()

    # ═══════════════════════════════════════════════════════════════════════════
    # HIGH-EFFICIENCY READ APIS
    # ═══════════════════════════════════════════════════════════════════════════

    def dashboard(self) -> dict[str, Any]:
        """
        Single-call overview of entire database state.
        Returns counts, recent activity, pending items.
        """
        counts = {}
        for table in ["sections", "claims", "entities", "identifiers", "tasks", "evidence", "section_revisions"]:
            row = self.conn.execute(f"SELECT COUNT(*) as c FROM {table}").fetchone()
            counts[table] = row["c"]

        # Recent revisions
        recent_revisions = self.conn.execute("""
            SELECT sr.id, sr.section_id, s.title, sr.author, sr.change_note, sr.created_at
            FROM section_revisions sr
            JOIN sections s ON s.id = sr.section_id
            ORDER BY sr.created_at DESC
            LIMIT 5
        """).fetchall()

        # Pending/in-progress tasks
        urgent_tasks = self.conn.execute("""
            SELECT id, task_text, status, priority
            FROM tasks
            WHERE status IN ('pending', 'in_progress', 'blocked')
            ORDER BY priority ASC, id ASC
            LIMIT 10
        """).fetchall()

        # Claim breakdown
        claim_stats = self.conn.execute("""
            SELECT status, COUNT(*) as count
            FROM claims
            GROUP BY status
        """).fetchall()

        return {
            "counts": counts,
            "recent_revisions": [dict(r) for r in recent_revisions],
            "urgent_tasks": [dict(r) for r in urgent_tasks],
            "claim_breakdown": {r["status"]: r["count"] for r in claim_stats},
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_outline(self, include_claims: bool = False, include_tasks: bool = False) -> dict[str, Any]:
        """
        Returns full document structure as a navigable tree.
        Much more efficient than searching blindly.
        """
        rows = self.conn.execute("""
            SELECT id, parent_id, heading_level, title, path, anchor, LENGTH(body_markdown) as body_len
            FROM sections
            ORDER BY path
        """).fetchall()

        sections = []
        for r in rows:
            section = {
                "id": r["id"],
                "parent_id": r["parent_id"],
                "level": r["heading_level"],
                "title": r["title"],
                "path": r["path"],
                "anchor": r["anchor"],
                "body_chars": r["body_len"],
            }

            if include_claims:
                claims = self.conn.execute(
                    "SELECT id, status, confidence FROM claims WHERE section_id = ?",
                    (r["id"],)
                ).fetchall()
                section["claims"] = [dict(c) for c in claims]

            if include_tasks:
                tasks = self.conn.execute(
                    "SELECT id, status, priority FROM tasks WHERE section_id = ?",
                    (r["id"],)
                ).fetchall()
                section["tasks"] = [dict(t) for t in tasks]

            sections.append(section)

        return {"outline": sections, "total_sections": len(sections)}

    def search(
        self,
        query: str,
        limit: int = 10,
        kind: str = "all",
        include_body: bool = False,
        max_body_chars: int = 500,
    ) -> dict[str, Any]:
        """
        Enhanced search with optional inline body snippets.
        """
        q = query.strip()
        if not q:
            return {"results": []}

        results: list[dict[str, Any]] = []

        if kind in ("all", "sections"):
            if include_body:
                rows = self.conn.execute(
                    """
                    SELECT s.id, s.title, s.path, s.anchor, s.body_markdown,
                           snippet(fts_sections, 1, '[[', ']]', '…', 20) AS snippet
                    FROM fts_sections
                    JOIN sections s ON s.id = fts_sections.rowid
                    WHERE fts_sections MATCH ?
                    LIMIT ?
                    """,
                    (q, int(limit)),
                ).fetchall()
                for r in rows:
                    results.append({
                        "type": "section",
                        "id": int(r["id"]),
                        "title": r["title"],
                        "path": r["path"],
                        "anchor": r["anchor"],
                        "snippet": r["snippet"],
                        "body": _truncate(r["body_markdown"], max_body_chars),
                    })
            else:
                rows = self.conn.execute(
                    """
                    SELECT s.id, s.title, s.path, s.anchor,
                           snippet(fts_sections, 1, '[[', ']]', '…', 20) AS snippet
                    FROM fts_sections
                    JOIN sections s ON s.id = fts_sections.rowid
                    WHERE fts_sections MATCH ?
                    LIMIT ?
                    """,
                    (q, int(limit)),
                ).fetchall()
                for r in rows:
                    results.append({
                        "type": "section",
                        "id": int(r["id"]),
                        "title": r["title"],
                        "path": r["path"],
                        "anchor": r["anchor"],
                        "snippet": r["snippet"],
                    })

        if kind in ("all", "claims") and len(results) < limit:
            remaining = max(0, int(limit) - len(results))
            rows = self.conn.execute(
                """
                SELECT c.id, c.status, c.confidence, c.section_id,
                       snippet(fts_claims, 0, '[[', ']]', '…', 25) AS snippet
                FROM fts_claims
                JOIN claims c ON c.id = fts_claims.rowid
                WHERE fts_claims MATCH ?
                LIMIT ?
                """,
                (q, int(remaining)),
            ).fetchall()
            for r in rows:
                results.append({
                    "type": "claim",
                    "id": int(r["id"]),
                    "status": r["status"],
                    "confidence": r["confidence"],
                    "section_id": int(r["section_id"]) if r["section_id"] else None,
                    "snippet": r["snippet"],
                })

        return {"results": results, "query": q, "count": len(results)}

    def multi_search(
        self,
        queries: list[str],
        limit_per_query: int = 5,
        kind: str = "sections",
    ) -> dict[str, Any]:
        """
        Execute multiple searches in one call.
        Perfect for exploring related concepts.
        """
        all_results = {}
        for q in queries:
            all_results[q] = self.search(query=q, limit=limit_per_query, kind=kind)["results"]
        return {"searches": all_results, "query_count": len(queries)}

    def get_section(
        self,
        section_id: int,
        max_chars: int | None = None,
        include_neighbors: bool = True,
        include_claims: bool = True,
        include_identifiers: bool = True,
    ) -> dict[str, Any]:
        """
        Enhanced section fetch with navigation context.
        """
        row = self.conn.execute(
            """
            SELECT id, document_id, parent_id, heading_level, order_index, path, anchor, title, body_markdown,
                   created_at, updated_at
            FROM sections
            WHERE id = ?
            """,
            (int(section_id),),
        ).fetchone()
        if row is None:
            raise KeyError(f"section_id not found: {section_id}")

        # Breadcrumb path
        crumbs: list[dict[str, Any]] = []
        cur_id = row["id"]
        while cur_id is not None:
            r2 = self.conn.execute("SELECT id, parent_id, title, path FROM sections WHERE id = ?", (cur_id,)).fetchone()
            if r2 is None:
                break
            crumbs.append({"id": int(r2["id"]), "title": r2["title"], "path": r2["path"]})
            cur_id = r2["parent_id"]
        crumbs.reverse()

        result = {
            "id": int(row["id"]),
            "document_id": int(row["document_id"]),
            "parent_id": int(row["parent_id"]) if row["parent_id"] else None,
            "heading_level": int(row["heading_level"]),
            "path": row["path"],
            "anchor": row["anchor"],
            "title": row["title"],
            "body": _truncate(row["body_markdown"], max_chars),
            "body_total_chars": len(row["body_markdown"]),
            "breadcrumbs": crumbs,
            "updated_at": row["updated_at"],
        }

        if include_neighbors:
            # Get children
            children = self.conn.execute(
                "SELECT id, title, path FROM sections WHERE parent_id = ? ORDER BY order_index",
                (int(section_id),)
            ).fetchall()
            result["children"] = [{"id": c["id"], "title": c["title"]} for c in children]

            # Get siblings
            if row["parent_id"]:
                siblings = self.conn.execute(
                    """SELECT id, title FROM sections
                       WHERE parent_id = ? AND id != ?
                       ORDER BY order_index""",
                    (row["parent_id"], section_id)
                ).fetchall()
                result["siblings"] = [{"id": s["id"], "title": s["title"]} for s in siblings]

        if include_claims:
            claims = self.conn.execute(
                "SELECT id, claim_text, status, confidence FROM claims WHERE section_id = ?",
                (int(section_id),)
            ).fetchall()
            result["claims"] = [dict(c) for c in claims]

        if include_identifiers:
            identifiers = self.conn.execute(
                """
                SELECT i.id, i.type, i.value, i.normalized_value, im.context
                FROM identifier_mentions im
                JOIN identifiers i ON i.id = im.identifier_id
                WHERE im.section_id = ?
                """,
                (int(section_id),)
            ).fetchall()
            result["identifiers"] = [dict(i) for i in identifiers]

        return result

    def get_sections(
        self,
        section_ids: list[int],
        max_chars: int | None = 2000,
        include_claims: bool = False,
    ) -> dict[str, Any]:
        """
        Batch fetch multiple sections in one call.
        """
        sections = []
        for sid in section_ids[:20]:  # Cap at 20 to prevent abuse
            try:
                sec = self.get_section(
                    section_id=sid,
                    max_chars=max_chars,
                    include_neighbors=False,
                    include_claims=include_claims,
                    include_identifiers=False,
                )
                sections.append(sec)
            except KeyError:
                sections.append({"id": sid, "error": "not found"})
        return {"sections": sections, "fetched": len(sections)}

    def search_and_fetch(
        self,
        query: str,
        limit: int = 5,
        max_body_chars: int = 1500,
        include_claims: bool = True,
    ) -> dict[str, Any]:
        """
        COMPOSITE: Search and return full section content in one call.
        Saves 2+ round trips.
        """
        search_results = self.search(query=query, limit=limit, kind="sections")
        section_ids = [r["id"] for r in search_results["results"]]

        if not section_ids:
            return {"query": query, "sections": [], "count": 0}

        sections = []
        for sid in section_ids:
            sec = self.get_section(
                section_id=sid,
                max_chars=max_body_chars,
                include_neighbors=True,
                include_claims=include_claims,
                include_identifiers=True,
            )
            sections.append(sec)

        return {"query": query, "sections": sections, "count": len(sections)}

    def get_entity_network(self, entity_id: int | None = None, entity_name: str | None = None) -> dict[str, Any]:
        """
        Get entity with all linked identifiers and section mentions.
        """
        if entity_id:
            row = self.conn.execute("SELECT * FROM entities WHERE id = ?", (entity_id,)).fetchone()
        elif entity_name:
            row = self.conn.execute("SELECT * FROM entities WHERE name LIKE ?", (f"%{entity_name}%",)).fetchone()
        else:
            raise ValueError("entity_id or entity_name required")

        if not row:
            raise KeyError(f"Entity not found: {entity_id or entity_name}")

        entity = dict(row)
        entity["aliases"] = json.loads(entity.pop("aliases_json", "[]"))

        # Get identifiers
        identifiers = self.conn.execute(
            "SELECT id, type, value, normalized_value FROM identifiers WHERE entity_id = ?",
            (row["id"],)
        ).fetchall()
        entity["identifiers"] = [dict(i) for i in identifiers]

        # Get all section mentions via identifiers
        mentions = self.conn.execute(
            """
            SELECT DISTINCT s.id, s.title, s.path, im.context
            FROM identifier_mentions im
            JOIN identifiers i ON i.id = im.identifier_id
            JOIN sections s ON s.id = im.section_id
            WHERE i.entity_id = ?
            """,
            (row["id"],)
        ).fetchall()
        entity["section_mentions"] = [dict(m) for m in mentions]

        return entity

    def list_entities(self, kind: str | None = None, limit: int = 50) -> dict[str, Any]:
        """List all entities with identifier counts."""
        if kind:
            rows = self.conn.execute(
                """
                SELECT e.*, COUNT(i.id) as identifier_count
                FROM entities e
                LEFT JOIN identifiers i ON i.entity_id = e.id
                WHERE e.kind = ?
                GROUP BY e.id
                LIMIT ?
                """,
                (kind, limit)
            ).fetchall()
        else:
            rows = self.conn.execute(
                """
                SELECT e.*, COUNT(i.id) as identifier_count
                FROM entities e
                LEFT JOIN identifiers i ON i.entity_id = e.id
                GROUP BY e.id
                LIMIT ?
                """,
                (limit,)
            ).fetchall()

        entities = []
        for r in rows:
            e = dict(r)
            e["aliases"] = json.loads(e.pop("aliases_json", "[]"))
            entities.append(e)
        return {"entities": entities}

    def list_identifiers(
        self,
        ident_type: str | None = None,
        limit: int = 50,
        with_mentions: bool = False,
    ) -> dict[str, Any]:
        """List identifiers with optional mention context."""
        if ident_type:
            rows = self.conn.execute(
                """
                SELECT i.*, e.name as entity_name, e.kind as entity_kind
                FROM identifiers i
                LEFT JOIN entities e ON e.id = i.entity_id
                WHERE i.type = ?
                LIMIT ?
                """,
                (ident_type, limit)
            ).fetchall()
        else:
            rows = self.conn.execute(
                """
                SELECT i.*, e.name as entity_name, e.kind as entity_kind
                FROM identifiers i
                LEFT JOIN entities e ON e.id = i.entity_id
                LIMIT ?
                """,
                (limit,)
            ).fetchall()

        identifiers = []
        for r in rows:
            ident = dict(r)
            if with_mentions:
                mentions = self.conn.execute(
                    """
                    SELECT s.id, s.title, im.context
                    FROM identifier_mentions im
                    JOIN sections s ON s.id = im.section_id
                    WHERE im.identifier_id = ?
                    """,
                    (r["id"],)
                ).fetchall()
                ident["mentions"] = [dict(m) for m in mentions]
            identifiers.append(ident)
        return {"identifiers": identifiers}

    # ═══════════════════════════════════════════════════════════════════════════
    # EXPORT TOOL
    # ═══════════════════════════════════════════════════════════════════════════

    def export_markdown(self, output_path: str | None = None, document_id: int | None = None) -> dict[str, Any]:
        """
        Export the report to Markdown file.
        """
        if document_id is None:
            row = self.conn.execute("SELECT id FROM documents ORDER BY id DESC LIMIT 1").fetchone()
            if row is None:
                raise ValueError("No documents found in DB")
            document_id = int(row["id"])

        rows = self.conn.execute(
            """
            SELECT id, heading_level, title, body_markdown, path
            FROM sections
            WHERE document_id = ?
            """,
            (document_id,),
        ).fetchall()

        sections = sorted(rows, key=lambda r: _path_key(r["path"]))

        out_lines: list[str] = []
        for r in sections:
            level = int(r["heading_level"])
            title = (r["title"] or "").rstrip()
            body = (r["body_markdown"] or "").rstrip()
            out_lines.append("#" * level + " " + title)
            out_lines.append("")
            if body:
                out_lines.append(body)
                out_lines.append("")
            else:
                out_lines.append("")

        content = "\n".join(out_lines).rstrip() + "\n"

        if output_path is None:
            output_path = "report.export.md"

        Path(output_path).write_text(content, encoding="utf-8")

        return {
            "ok": True,
            "document_id": document_id,
            "output_path": output_path,
            "sections_exported": len(sections),
            "bytes_written": len(content.encode("utf-8")),
        }

    # ═══════════════════════════════════════════════════════════════════════════
    # WRITE APIs
    # ═══════════════════════════════════════════════════════════════════════════

    def update_section(
        self,
        section_id: int,
        *,
        title: Optional[str],
        body_markdown: Optional[str],
        author: str,
        change_note: str,
    ) -> dict[str, Any]:
        if not change_note.strip():
            raise ValueError("change_note is required")

        row = self.conn.execute(
            "SELECT id, title, body_markdown FROM sections WHERE id = ?",
            (int(section_id),),
        ).fetchone()
        if row is None:
            raise KeyError(f"section_id not found: {section_id}")

        new_title = (title if title is not None else row["title"]).rstrip()
        new_body = (body_markdown if body_markdown is not None else row["body_markdown"]).rstrip("\n")
        content_hash = sha256_text(new_title + "\n" + new_body)

        self.conn.execute(
            """
            UPDATE sections
            SET title = ?, body_markdown = ?, content_sha256 = ?,
                updated_at = (%s)
            WHERE id = ?
            """
            % _utc_now_sql(),
            (new_title, new_body, content_hash, int(section_id)),
        )
        self.conn.execute(
            """
            INSERT INTO section_revisions (section_id, rev_sha256, author, change_note, title, body_markdown)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (int(section_id), content_hash, author or "unknown", change_note, new_title, new_body),
        )
        self.conn.commit()
        return {"ok": True, "section_id": int(section_id)}

    def list_tasks(self, status: Optional[str] = None, limit: int = 50) -> dict[str, Any]:
        params: list[Any] = []
        where = ""
        if status:
            where = "WHERE status = ?"
            params.append(status)
        params.append(int(limit))
        rows = self.conn.execute(
            f"""
            SELECT id, section_id, task_text, status, priority, origin, created_at, updated_at
            FROM tasks
            {where}
            ORDER BY priority ASC, id ASC
            LIMIT ?
            """,
            tuple(params),
        ).fetchall()
        return {"tasks": [dict(r) for r in rows]}

    def update_task(self, task_id: int, *, status: Optional[str] = None, priority: Optional[int] = None) -> dict[str, Any]:
        row = self.conn.execute("SELECT id FROM tasks WHERE id = ?", (int(task_id),)).fetchone()
        if row is None:
            raise KeyError(f"task_id not found: {task_id}")

        updates: list[str] = []
        params: list[Any] = []
        if status is not None:
            updates.append("status = ?")
            params.append(status)
        if priority is not None:
            updates.append("priority = ?")
            params.append(int(priority))
        if not updates:
            return {"ok": True, "task_id": int(task_id)}

        updates.append(f"updated_at = ({_utc_now_sql()})")
        params.append(int(task_id))
        self.conn.execute(f"UPDATE tasks SET {', '.join(updates)} WHERE id = ?", tuple(params))
        self.conn.commit()
        return {"ok": True, "task_id": int(task_id)}

    def create_claim(
        self,
        *,
        section_id: Optional[int],
        claim_text: str,
        status: str = "unknown",
        confidence: float = 0.5,
    ) -> dict[str, Any]:
        if not claim_text.strip():
            raise ValueError("claim_text required")
        cur = self.conn.execute(
            """
            INSERT INTO claims (section_id, claim_text, status, confidence, origin, updated_at)
            VALUES (?, ?, ?, ?, 'manual', (%s))
            """
            % _utc_now_sql(),
            (int(section_id) if section_id is not None else None, claim_text.strip(), status, float(confidence)),
        )
        self.conn.commit()
        return {"ok": True, "claim_id": int(cur.lastrowid)}

    def update_claim_status(self, claim_id: int, *, status: str, confidence: Optional[float] = None) -> dict[str, Any]:
        row = self.conn.execute("SELECT id FROM claims WHERE id = ?", (int(claim_id),)).fetchone()
        if row is None:
            raise KeyError(f"claim_id not found: {claim_id}")
        updates = ["status = ?"]
        params: list[Any] = [status]
        if confidence is not None:
            updates.append("confidence = ?")
            params.append(float(confidence))
        updates.append(f"updated_at = ({_utc_now_sql()})")
        params.append(int(claim_id))
        self.conn.execute(f"UPDATE claims SET {', '.join(updates)} WHERE id = ?", tuple(params))
        self.conn.commit()
        return {"ok": True, "claim_id": int(claim_id)}

    def upsert_entity(self, *, name: str, kind: str, aliases: list[str] | None = None) -> dict[str, Any]:
        if not name.strip():
            raise ValueError("name required")
        aliases_json = json.dumps(aliases or [], ensure_ascii=False)
        row = self.conn.execute("SELECT id FROM entities WHERE name = ? AND kind = ?", (name.strip(), kind)).fetchone()
        if row is None:
            cur = self.conn.execute(
                """
                INSERT INTO entities (name, kind, aliases_json)
                VALUES (?, ?, ?)
                """,
                (name.strip(), kind, aliases_json),
            )
            self.conn.commit()
            return {"ok": True, "entity_id": int(cur.lastrowid)}

        self.conn.execute(
            f"UPDATE entities SET aliases_json = ?, updated_at = ({_utc_now_sql()}) WHERE id = ?",
            (aliases_json, int(row["id"])),
        )
        self.conn.commit()
        return {"ok": True, "entity_id": int(row["id"])}

    def link_identifier(
        self,
        *,
        ident_type: str,
        value: str,
        entity_id: Optional[int] = None,
        section_id: Optional[int] = None,
        context: Optional[str] = "",
    ) -> dict[str, Any]:
        norm = normalize_identifier_value(value)
        row = self.conn.execute(
            "SELECT id FROM identifiers WHERE type = ? AND normalized_value = ?",
            (ident_type, norm),
        ).fetchone()
        if row is None:
            cur = self.conn.execute(
                "INSERT INTO identifiers (type, value, normalized_value, entity_id) VALUES (?, ?, ?, ?)",
                (ident_type, value, norm, int(entity_id) if entity_id is not None else None),
            )
            identifier_id = int(cur.lastrowid)
        else:
            identifier_id = int(row["id"])
            if entity_id is not None:
                self.conn.execute("UPDATE identifiers SET entity_id = ? WHERE id = ?", (int(entity_id), identifier_id))

        if section_id is not None:
            self.conn.execute(
                "INSERT INTO identifier_mentions (identifier_id, section_id, context) VALUES (?, ?, ?)",
                (identifier_id, int(section_id), (context or "")[:400]),
            )
        self.conn.commit()
        return {"ok": True, "identifier_id": identifier_id}

    # ═══════════════════════════════════════════════════════════════════════════
    # SECTION MANIPULATION (CREATE/DELETE/MOVE/MERGE)
    # ═══════════════════════════════════════════════════════════════════════════

    def create_section(
        self,
        *,
        document_id: int,
        parent_id: Optional[int],
        title: str,
        body_markdown: str = "",
        heading_level: Optional[int] = None,
        order_index: Optional[int] = None,
        author: str = "assistant",
    ) -> dict[str, Any]:
        """Create a new section in the report."""
        if not title.strip():
            raise ValueError("title is required")

        # Determine heading level if not specified
        if heading_level is None:
            if parent_id is not None:
                parent = self.conn.execute(
                    "SELECT heading_level FROM sections WHERE id = ?", (int(parent_id),)
                ).fetchone()
                if parent is None:
                    raise KeyError(f"parent_id not found: {parent_id}")
                heading_level = min(6, int(parent["heading_level"]) + 1)
            else:
                heading_level = 1

        # Determine order_index if not specified
        if order_index is None:
            if parent_id is not None:
                result = self.conn.execute(
                    "SELECT COALESCE(MAX(order_index), -1) + 1 as next_idx FROM sections WHERE parent_id = ?",
                    (int(parent_id),)
                ).fetchone()
            else:
                result = self.conn.execute(
                    "SELECT COALESCE(MAX(order_index), -1) + 1 as next_idx FROM sections WHERE document_id = ? AND parent_id IS NULL",
                    (int(document_id),)
                ).fetchone()
            order_index = int(result["next_idx"])

        # Generate path
        if parent_id is not None:
            parent_row = self.conn.execute("SELECT path FROM sections WHERE id = ?", (int(parent_id),)).fetchone()
            if parent_row is None:
                raise KeyError(f"parent_id not found: {parent_id}")
            path = f"{parent_row['path']}/{order_index}"
        else:
            path = str(order_index)

        # Generate anchor
        anchor = _slugify(title)
        existing = self.conn.execute(
            "SELECT COUNT(*) as cnt FROM sections WHERE document_id = ? AND anchor LIKE ?",
            (int(document_id), f"{anchor}%")
        ).fetchone()
        if int(existing["cnt"]) > 0:
            anchor = f"{anchor}-{int(existing['cnt'])}"

        content_hash = sha256_text(title.strip() + "\n" + body_markdown.strip())

        cur = self.conn.execute(
            """
            INSERT INTO sections (document_id, parent_id, heading_level, order_index, path, anchor, title, body_markdown, content_sha256)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(document_id),
                int(parent_id) if parent_id is not None else None,
                int(heading_level),
                int(order_index),
                path,
                anchor,
                title.strip(),
                body_markdown.strip(),
                content_hash,
            ),
        )
        section_id = int(cur.lastrowid)

        # Create initial revision
        self.conn.execute(
            """
            INSERT INTO section_revisions (section_id, rev_sha256, author, change_note, title, body_markdown)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (section_id, content_hash, author, "Section created", title.strip(), body_markdown.strip()),
        )
        self.conn.commit()
        return {"ok": True, "section_id": section_id, "path": path, "anchor": anchor}

    def delete_section(self, section_id: int, cascade: bool = True) -> dict[str, Any]:
        """Delete a section. If cascade=True, delete children too; otherwise reparent them."""
        row = self.conn.execute(
            "SELECT id, parent_id, document_id, title FROM sections WHERE id = ?", (int(section_id),)
        ).fetchone()
        if row is None:
            raise KeyError(f"section_id not found: {section_id}")

        if not cascade:
            # Reparent children to this section's parent
            self.conn.execute(
                "UPDATE sections SET parent_id = ? WHERE parent_id = ?",
                (row["parent_id"], int(section_id)),
            )

        self.conn.execute("DELETE FROM sections WHERE id = ?", (int(section_id),))
        self.conn.commit()
        return {"ok": True, "deleted_section_id": int(section_id), "title": row["title"]}

    def move_section(
        self,
        section_id: int,
        *,
        new_parent_id: Optional[int] = None,
        new_order_index: Optional[int] = None,
        author: str = "assistant",
    ) -> dict[str, Any]:
        """Move a section to a new parent and/or reorder it."""
        row = self.conn.execute(
            "SELECT id, document_id, parent_id, order_index, path, title FROM sections WHERE id = ?",
            (int(section_id),)
        ).fetchone()
        if row is None:
            raise KeyError(f"section_id not found: {section_id}")

        parent_id = new_parent_id if new_parent_id is not None else row["parent_id"]
        order_index = new_order_index if new_order_index is not None else row["order_index"]

        # Recalculate path
        if parent_id is not None:
            parent_row = self.conn.execute("SELECT path, heading_level FROM sections WHERE id = ?", (int(parent_id),)).fetchone()
            if parent_row is None:
                raise KeyError(f"new_parent_id not found: {parent_id}")
            new_path = f"{parent_row['path']}/{order_index}"
            new_level = min(6, int(parent_row["heading_level"]) + 1)
        else:
            new_path = str(order_index)
            new_level = 1

        self.conn.execute(
            f"""
            UPDATE sections SET parent_id = ?, order_index = ?, path = ?, heading_level = ?, updated_at = ({_utc_now_sql()})
            WHERE id = ?
            """,
            (int(parent_id) if parent_id is not None else None, int(order_index), new_path, new_level, int(section_id)),
        )

        # Recursively update children paths
        self._update_child_paths(int(section_id), new_path)
        self.conn.commit()
        return {"ok": True, "section_id": int(section_id), "new_path": new_path}

    def _update_child_paths(self, parent_id: int, parent_path: str) -> None:
        """Recursively update paths of child sections."""
        children = self.conn.execute(
            "SELECT id, order_index FROM sections WHERE parent_id = ? ORDER BY order_index",
            (parent_id,)
        ).fetchall()
        for child in children:
            child_path = f"{parent_path}/{child['order_index']}"
            self.conn.execute("UPDATE sections SET path = ? WHERE id = ?", (child_path, int(child["id"])))
            self._update_child_paths(int(child["id"]), child_path)

    def merge_sections(
        self,
        source_section_id: int,
        target_section_id: int,
        *,
        append: bool = True,
        delete_source: bool = True,
        author: str = "assistant",
    ) -> dict[str, Any]:
        """Merge source section content into target section."""
        source = self.conn.execute(
            "SELECT id, title, body_markdown FROM sections WHERE id = ?", (int(source_section_id),)
        ).fetchone()
        target = self.conn.execute(
            "SELECT id, title, body_markdown FROM sections WHERE id = ?", (int(target_section_id),)
        ).fetchone()

        if source is None:
            raise KeyError(f"source_section_id not found: {source_section_id}")
        if target is None:
            raise KeyError(f"target_section_id not found: {target_section_id}")

        if append:
            new_body = f"{target['body_markdown']}\n\n---\n\n## Merged from: {source['title']}\n\n{source['body_markdown']}"
        else:
            new_body = f"## Merged from: {source['title']}\n\n{source['body_markdown']}\n\n---\n\n{target['body_markdown']}"

        content_hash = sha256_text(target["title"] + "\n" + new_body)

        self.conn.execute(
            f"UPDATE sections SET body_markdown = ?, content_sha256 = ?, updated_at = ({_utc_now_sql()}) WHERE id = ?",
            (new_body.strip(), content_hash, int(target_section_id)),
        )

        # Create revision
        self.conn.execute(
            """
            INSERT INTO section_revisions (section_id, rev_sha256, author, change_note, title, body_markdown)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (int(target_section_id), content_hash, author, f"Merged content from section {source_section_id}", target["title"], new_body.strip()),
        )

        # Move claims, tasks, identifier_mentions from source to target
        self.conn.execute("UPDATE claims SET section_id = ? WHERE section_id = ?", (int(target_section_id), int(source_section_id)))
        self.conn.execute("UPDATE tasks SET section_id = ? WHERE section_id = ?", (int(target_section_id), int(source_section_id)))
        self.conn.execute("UPDATE identifier_mentions SET section_id = ? WHERE section_id = ?", (int(target_section_id), int(source_section_id)))

        if delete_source:
            self.conn.execute("DELETE FROM sections WHERE id = ?", (int(source_section_id),))

        self.conn.commit()
        return {"ok": True, "target_section_id": int(target_section_id), "source_deleted": delete_source}

    # ═══════════════════════════════════════════════════════════════════════════
    # TASK CRUD
    # ═══════════════════════════════════════════════════════════════════════════

    def create_task(
        self,
        *,
        task_text: str,
        section_id: Optional[int] = None,
        status: str = "pending",
        priority: int = 3,
    ) -> dict[str, Any]:
        """Create a new manual task."""
        if not task_text.strip():
            raise ValueError("task_text is required")

        cur = self.conn.execute(
            """
            INSERT INTO tasks (section_id, task_text, status, priority, origin)
            VALUES (?, ?, ?, ?, 'manual')
            """,
            (int(section_id) if section_id is not None else None, task_text.strip(), status, int(priority)),
        )
        self.conn.commit()
        return {"ok": True, "task_id": int(cur.lastrowid)}

    def delete_task(self, task_id: int) -> dict[str, Any]:
        """Delete a task."""
        row = self.conn.execute("SELECT id, task_text FROM tasks WHERE id = ?", (int(task_id),)).fetchone()
        if row is None:
            raise KeyError(f"task_id not found: {task_id}")

        self.conn.execute("DELETE FROM tasks WHERE id = ?", (int(task_id),))
        self.conn.commit()
        return {"ok": True, "deleted_task_id": int(task_id)}

    # ═══════════════════════════════════════════════════════════════════════════
    # CLAIM CRUD
    # ═══════════════════════════════════════════════════════════════════════════

    def list_claims(
        self,
        status: Optional[str] = None,
        section_id: Optional[int] = None,
        min_confidence: Optional[float] = None,
        search: Optional[str] = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """List claims with optional filters."""
        params: list[Any] = []
        where_clauses: list[str] = []

        if status:
            where_clauses.append("c.status = ?")
            params.append(status)
        if section_id is not None:
            where_clauses.append("c.section_id = ?")
            params.append(int(section_id))
        if min_confidence is not None:
            where_clauses.append("c.confidence >= ?")
            params.append(float(min_confidence))
        if search:
            where_clauses.append("c.claim_text LIKE ?")
            params.append(f"%{search}%")

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        params.append(int(limit))

        rows = self.conn.execute(
            f"""
            SELECT c.id, c.section_id, c.claim_text, c.status, c.confidence, c.origin, c.created_at, c.updated_at,
                   s.title as section_title
            FROM claims c
            LEFT JOIN sections s ON s.id = c.section_id
            {where_sql}
            ORDER BY c.confidence DESC, c.id
            LIMIT ?
            """,
            tuple(params),
        ).fetchall()

        return {"claims": [dict(r) for r in rows]}

    def delete_claim(self, claim_id: int) -> dict[str, Any]:
        """Delete a claim and its evidence."""
        row = self.conn.execute("SELECT id, claim_text FROM claims WHERE id = ?", (int(claim_id),)).fetchone()
        if row is None:
            raise KeyError(f"claim_id not found: {claim_id}")

        self.conn.execute("DELETE FROM evidence WHERE claim_id = ?", (int(claim_id),))
        self.conn.execute("DELETE FROM claims WHERE id = ?", (int(claim_id),))
        self.conn.commit()
        return {"ok": True, "deleted_claim_id": int(claim_id)}

    # ═══════════════════════════════════════════════════════════════════════════
    # ENTITY/IDENTIFIER DELETE
    # ═══════════════════════════════════════════════════════════════════════════

    def delete_entity(self, entity_id: int, unlink_identifiers: bool = True) -> dict[str, Any]:
        """Delete an entity. If unlink_identifiers=True, set entity_id to NULL; otherwise delete identifiers too."""
        row = self.conn.execute("SELECT id, name FROM entities WHERE id = ?", (int(entity_id),)).fetchone()
        if row is None:
            raise KeyError(f"entity_id not found: {entity_id}")

        if unlink_identifiers:
            self.conn.execute("UPDATE identifiers SET entity_id = NULL WHERE entity_id = ?", (int(entity_id),))
        else:
            self.conn.execute("DELETE FROM identifiers WHERE entity_id = ?", (int(entity_id),))

        self.conn.execute("DELETE FROM entities WHERE id = ?", (int(entity_id),))
        self.conn.commit()
        return {"ok": True, "deleted_entity_id": int(entity_id), "entity_name": row["name"]}

    def delete_identifier(self, identifier_id: int) -> dict[str, Any]:
        """Delete an identifier and its mentions."""
        row = self.conn.execute("SELECT id, type, value FROM identifiers WHERE id = ?", (int(identifier_id),)).fetchone()
        if row is None:
            raise KeyError(f"identifier_id not found: {identifier_id}")

        self.conn.execute("DELETE FROM identifier_mentions WHERE identifier_id = ?", (int(identifier_id),))
        self.conn.execute("DELETE FROM identifiers WHERE id = ?", (int(identifier_id),))
        self.conn.commit()
        return {"ok": True, "deleted_identifier_id": int(identifier_id), "type": row["type"], "value": row["value"]}

    # ═══════════════════════════════════════════════════════════════════════════
    # DATABASE MAINTENANCE
    # ═══════════════════════════════════════════════════════════════════════════

    def cleanup_orphans(self, dry_run: bool = True) -> dict[str, Any]:
        """Find and optionally remove orphaned records."""
        orphans = {
            "identifiers_no_entity_no_mentions": [],
            "identifier_mentions_no_section": [],
            "claims_no_section": [],
            "tasks_no_section": [],
        }

        # Identifiers with no entity and no mentions
        rows = self.conn.execute(
            """
            SELECT i.id, i.type, i.value FROM identifiers i
            WHERE i.entity_id IS NULL
            AND NOT EXISTS (SELECT 1 FROM identifier_mentions WHERE identifier_id = i.id)
            """
        ).fetchall()
        orphans["identifiers_no_entity_no_mentions"] = [dict(r) for r in rows]

        # Identifier mentions pointing to deleted sections
        rows = self.conn.execute(
            """
            SELECT im.id, im.identifier_id, im.section_id FROM identifier_mentions im
            WHERE im.section_id IS NOT NULL
            AND NOT EXISTS (SELECT 1 FROM sections WHERE id = im.section_id)
            """
        ).fetchall()
        orphans["identifier_mentions_no_section"] = [dict(r) for r in rows]

        # Claims with section_id pointing to non-existent sections
        rows = self.conn.execute(
            """
            SELECT c.id, c.claim_text FROM claims c
            WHERE c.section_id IS NOT NULL
            AND NOT EXISTS (SELECT 1 FROM sections WHERE id = c.section_id)
            """
        ).fetchall()
        orphans["claims_no_section"] = [dict(r) for r in rows]

        # Tasks with section_id pointing to non-existent sections
        rows = self.conn.execute(
            """
            SELECT t.id, t.task_text FROM tasks t
            WHERE t.section_id IS NOT NULL
            AND NOT EXISTS (SELECT 1 FROM sections WHERE id = t.section_id)
            """
        ).fetchall()
        orphans["tasks_no_section"] = [dict(r) for r in rows]

        deleted = {}
        if not dry_run:
            cur = self.conn.execute(
                """
                DELETE FROM identifier_mentions
                WHERE section_id IS NOT NULL
                AND NOT EXISTS (SELECT 1 FROM sections WHERE id = identifier_mentions.section_id)
                """
            )
            deleted["identifier_mentions"] = cur.rowcount

            cur = self.conn.execute(
                """
                UPDATE claims SET section_id = NULL
                WHERE section_id IS NOT NULL
                AND NOT EXISTS (SELECT 1 FROM sections WHERE id = claims.section_id)
                """
            )
            deleted["claims_unlinked"] = cur.rowcount

            cur = self.conn.execute(
                """
                UPDATE tasks SET section_id = NULL
                WHERE section_id IS NOT NULL
                AND NOT EXISTS (SELECT 1 FROM sections WHERE id = tasks.section_id)
                """
            )
            deleted["tasks_unlinked"] = cur.rowcount

            cur = self.conn.execute(
                """
                DELETE FROM identifiers
                WHERE entity_id IS NULL
                AND NOT EXISTS (SELECT 1 FROM identifier_mentions WHERE identifier_id = identifiers.id)
                """
            )
            deleted["identifiers"] = cur.rowcount

            self.conn.commit()

        return {"orphans": orphans, "deleted": deleted if not dry_run else None, "dry_run": dry_run}

    def rebuild_fts(self) -> dict[str, Any]:
        """Rebuild FTS indexes from scratch."""
        self.conn.execute("DELETE FROM fts_sections")
        self.conn.execute(
            """
            INSERT INTO fts_sections(rowid, title, body_markdown)
            SELECT id, title, body_markdown FROM sections
            """
        )

        self.conn.execute("DELETE FROM fts_claims")
        self.conn.execute(
            """
            INSERT INTO fts_claims(rowid, claim_text)
            SELECT id, claim_text FROM claims
            """
        )

        self.conn.commit()

        sections_count = self.conn.execute("SELECT COUNT(*) FROM fts_sections").fetchone()[0]
        claims_count = self.conn.execute("SELECT COUNT(*) FROM fts_claims").fetchone()[0]

        return {"ok": True, "fts_sections_indexed": sections_count, "fts_claims_indexed": claims_count}

    def vacuum_db(self) -> dict[str, Any]:
        """Vacuum database to reclaim space and optimize."""
        before_pages = self.conn.execute("PRAGMA page_count").fetchone()[0]
        page_size = self.conn.execute("PRAGMA page_size").fetchone()[0]
        before_size = before_pages * page_size

        self.conn.execute("VACUUM")

        after_pages = self.conn.execute("PRAGMA page_count").fetchone()[0]
        after_size = after_pages * page_size

        return {
            "ok": True,
            "before_size_bytes": before_size,
            "after_size_bytes": after_size,
            "freed_bytes": before_size - after_size,
        }

    def execute_sql(self, sql: str, params: Optional[list] = None, readonly: bool = True) -> dict[str, Any]:
        """Execute raw SQL (for advanced users). By default, only SELECT is allowed."""
        sql_stripped = sql.strip().upper()
        if readonly:
            if not sql_stripped.startswith("SELECT") and not sql_stripped.startswith("PRAGMA"):
                raise ValueError("readonly=True only allows SELECT and PRAGMA statements")

        try:
            if params:
                rows = self.conn.execute(sql, tuple(params)).fetchall()
            else:
                rows = self.conn.execute(sql).fetchall()

            if not readonly:
                self.conn.commit()

            if rows and hasattr(rows[0], "keys"):
                return {"rows": [dict(r) for r in rows], "row_count": len(rows)}
            else:
                return {"rows": [[col for col in r] for r in rows], "row_count": len(rows)}
        except Exception:
            if not readonly:
                self.conn.rollback()
            raise
