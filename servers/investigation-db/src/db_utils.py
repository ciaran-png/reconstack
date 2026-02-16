"""
Investigation DB — SQLite utility helpers.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
from pathlib import Path


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def ensure_parent_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def connect_sqlite(db_path: Path) -> sqlite3.Connection:
    ensure_parent_dir(db_path)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    # Enforce FKs per-connection
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def apply_schema(conn: sqlite3.Connection, schema_sql: str) -> None:
    conn.executescript(schema_sql)
    conn.commit()


def read_text_file(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def normalize_identifier_value(value: str) -> str:
    return " ".join(value.strip().lower().split())


def chunk_lines(text: str, max_chars: int) -> list[str]:
    """Simple, deterministic line-based chunker."""
    chunks: list[str] = []
    cur: list[str] = []
    cur_len = 0
    for line in text.splitlines(True):
        if cur_len + len(line) > max_chars and cur:
            chunks.append("".join(cur).rstrip("\n"))
            cur, cur_len = [], 0
        cur.append(line)
        cur_len += len(line)
    if cur:
        chunks.append("".join(cur).rstrip("\n"))
    return chunks


def getenv_path(name: str, default: Path) -> Path:
    raw = os.getenv(name)
    if not raw:
        return default
    return Path(raw).expanduser().resolve()
