-- Investigation DB SQLite schema (local-first knowledge store)
-- This schema is designed for:
-- - deterministic ingestion from a Markdown report
-- - append-only revisions for auditability
-- - fast search via FTS5

PRAGMA foreign_keys = ON;

-- ----------------------------
-- Core documents/sections
-- ----------------------------

CREATE TABLE IF NOT EXISTS documents (
  id INTEGER PRIMARY KEY,
  source_path TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,
  version_label TEXT,
  source_sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS sections (
  id INTEGER PRIMARY KEY,
  document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  parent_id INTEGER REFERENCES sections(id) ON DELETE CASCADE,
  heading_level INTEGER NOT NULL CHECK (heading_level BETWEEN 1 AND 6),
  order_index INTEGER NOT NULL,
  path TEXT NOT NULL,                 -- e.g. "1/2/3" within the doc
  anchor TEXT NOT NULL,               -- deterministic slug/anchor
  title TEXT NOT NULL,
  body_markdown TEXT NOT NULL DEFAULT '',
  content_sha256 TEXT NOT NULL,       -- hash(title+body) for change detection
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  UNIQUE(document_id, path),
  UNIQUE(document_id, anchor)
);

CREATE INDEX IF NOT EXISTS idx_sections_document ON sections(document_id);
CREATE INDEX IF NOT EXISTS idx_sections_parent ON sections(parent_id);

CREATE TABLE IF NOT EXISTS section_revisions (
  id INTEGER PRIMARY KEY,
  section_id INTEGER NOT NULL REFERENCES sections(id) ON DELETE CASCADE,
  rev_sha256 TEXT NOT NULL,            -- hash of body/title at revision time
  author TEXT NOT NULL DEFAULT 'system',
  change_note TEXT NOT NULL,
  title TEXT NOT NULL,
  body_markdown TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_section_revisions_section ON section_revisions(section_id);

-- ----------------------------
-- Entities + identifiers
-- ----------------------------

CREATE TABLE IF NOT EXISTS entities (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('person','org','place','other')),
  aliases_json TEXT NOT NULL DEFAULT '[]', -- JSON array of strings
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  UNIQUE(name, kind)
);

CREATE TABLE IF NOT EXISTS identifiers (
  id INTEGER PRIMARY KEY,
  type TEXT NOT NULL CHECK (
    type IN (
      'ein','domain','url','ip','asn','gtm','ga_ua','ga4','fb_pixel',
      'email','phone','address','other'
    )
  ),
  value TEXT NOT NULL,
  normalized_value TEXT NOT NULL, -- for dedupe/search
  entity_id INTEGER REFERENCES entities(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  UNIQUE(type, normalized_value)
);

CREATE INDEX IF NOT EXISTS idx_identifiers_entity ON identifiers(entity_id);
CREATE INDEX IF NOT EXISTS idx_identifiers_type ON identifiers(type);

CREATE TABLE IF NOT EXISTS identifier_mentions (
  id INTEGER PRIMARY KEY,
  identifier_id INTEGER NOT NULL REFERENCES identifiers(id) ON DELETE CASCADE,
  section_id INTEGER REFERENCES sections(id) ON DELETE SET NULL,
  context TEXT, -- small excerpt/notes
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_identifier_mentions_ident ON identifier_mentions(identifier_id);
CREATE INDEX IF NOT EXISTS idx_identifier_mentions_section ON identifier_mentions(section_id);

-- ----------------------------
-- Claims + evidence
-- ----------------------------

CREATE TABLE IF NOT EXISTS claims (
  id INTEGER PRIMARY KEY,
  section_id INTEGER REFERENCES sections(id) ON DELETE SET NULL,
  claim_text TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('verified','claimed','hypothesis','unknown')) DEFAULT 'unknown',
  confidence REAL NOT NULL DEFAULT 0.5 CHECK (confidence >= 0.0 AND confidence <= 1.0),
  origin TEXT NOT NULL CHECK (origin IN ('extracted','manual')) DEFAULT 'extracted',
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_claims_section ON claims(section_id);
CREATE INDEX IF NOT EXISTS idx_claims_status ON claims(status);

CREATE TABLE IF NOT EXISTS evidence (
  id INTEGER PRIMARY KEY,
  claim_id INTEGER NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
  section_id INTEGER REFERENCES sections(id) ON DELETE SET NULL,
  quote TEXT,             -- optional extracted quote/snippet
  source_ref TEXT,        -- optional filename/url/etc.
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_evidence_claim ON evidence(claim_id);

-- ----------------------------
-- Tasks (backlog)
-- ----------------------------

CREATE TABLE IF NOT EXISTS tasks (
  id INTEGER PRIMARY KEY,
  section_id INTEGER REFERENCES sections(id) ON DELETE SET NULL,
  task_text TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','in_progress','blocked','done','cancelled')) DEFAULT 'pending',
  priority INTEGER NOT NULL DEFAULT 3 CHECK (priority BETWEEN 1 AND 5), -- 1=highest
  origin TEXT NOT NULL CHECK (origin IN ('extracted','manual')) DEFAULT 'extracted',
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_tasks_priority ON tasks(priority);

-- ----------------------------
-- FTS5 search index
-- ----------------------------

-- External content tables for FTS.
CREATE VIRTUAL TABLE IF NOT EXISTS fts_sections
USING fts5(
  title,
  body_markdown,
  content='sections',
  content_rowid='id',
  tokenize='unicode61'
);

CREATE VIRTUAL TABLE IF NOT EXISTS fts_claims
USING fts5(
  claim_text,
  content='claims',
  content_rowid='id',
  tokenize='unicode61'
);

-- Triggers to keep FTS in sync with sections.
CREATE TRIGGER IF NOT EXISTS trg_sections_ai AFTER INSERT ON sections BEGIN
  INSERT INTO fts_sections(rowid, title, body_markdown)
  VALUES (new.id, new.title, new.body_markdown);
END;

CREATE TRIGGER IF NOT EXISTS trg_sections_ad AFTER DELETE ON sections BEGIN
  INSERT INTO fts_sections(fts_sections, rowid, title, body_markdown)
  VALUES('delete', old.id, old.title, old.body_markdown);
END;

CREATE TRIGGER IF NOT EXISTS trg_sections_au AFTER UPDATE ON sections BEGIN
  INSERT INTO fts_sections(fts_sections, rowid, title, body_markdown)
  VALUES('delete', old.id, old.title, old.body_markdown);
  INSERT INTO fts_sections(rowid, title, body_markdown)
  VALUES (new.id, new.title, new.body_markdown);
END;

-- Triggers to keep FTS in sync with claims.
CREATE TRIGGER IF NOT EXISTS trg_claims_ai AFTER INSERT ON claims BEGIN
  INSERT INTO fts_claims(rowid, claim_text)
  VALUES (new.id, new.claim_text);
END;

CREATE TRIGGER IF NOT EXISTS trg_claims_ad AFTER DELETE ON claims BEGIN
  INSERT INTO fts_claims(fts_claims, rowid, claim_text)
  VALUES('delete', old.id, old.claim_text);
END;

CREATE TRIGGER IF NOT EXISTS trg_claims_au AFTER UPDATE ON claims BEGIN
  INSERT INTO fts_claims(fts_claims, rowid, claim_text)
  VALUES('delete', old.id, old.claim_text);
  INSERT INTO fts_claims(rowid, claim_text)
  VALUES (new.id, new.claim_text);
END;
