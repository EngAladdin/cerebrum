"""
database.py — SQLite schema and connection management for Cerebrum.

Tables
------
sessions         Per-source-IP session state: skill_score, current_level, timestamps.
events           Normalized events received from Ingestion (append-only log).
rule_matches     Record of every rule match (session, rule, timestamp, skill_delta).
decisions        Decisions emitted to Orchestrator (session, action, explanation).
kg_nodes         Knowledge-graph nodes (session, event, rule, ip, indicator).
kg_edges         Knowledge-graph directed edges with evidence back-references.
rules            Editable rule definitions stored as JSON blobs.
"""

from __future__ import annotations

import logging
import os
import sqlite3
from contextlib import contextmanager
from typing import Generator

logger = logging.getLogger(__name__)

DB_PATH: str = os.environ.get("CEREBRUM_DB_PATH", "/data/cerebrum.db")


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


@contextmanager
def db_cursor() -> Generator[sqlite3.Cursor, None, None]:
    conn = get_connection()
    try:
        cur = conn.cursor()
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

DDL = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id      TEXT PRIMARY KEY,
    source_ip       TEXT NOT NULL,
    skill_score     INTEGER NOT NULL DEFAULT 0,
    current_level   INTEGER NOT NULL DEFAULT 1,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    event_count     INTEGER NOT NULL DEFAULT 0,
    released        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS events (
    id              TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL,
    timestamp       TEXT NOT NULL,
    protocol        TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    source_ip       TEXT NOT NULL,
    destination_port INTEGER,
    indicators      TEXT,          -- JSON array
    ingestion_source TEXT,
    raw             TEXT,          -- JSON blob
    received_at     TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE TABLE IF NOT EXISTS rule_matches (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    rule_id         TEXT NOT NULL,
    matched_at      TEXT NOT NULL DEFAULT (datetime('now')),
    skill_delta     INTEGER NOT NULL DEFAULT 0,
    window_count    INTEGER NOT NULL DEFAULT 1,
    evidence_ids    TEXT,          -- JSON array of event IDs
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE TABLE IF NOT EXISTS decisions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    rule_id         TEXT NOT NULL,
    action          TEXT NOT NULL,
    skill_score_after INTEGER NOT NULL,
    explanation     TEXT NOT NULL,
    sent_at         TEXT NOT NULL DEFAULT (datetime('now')),
    orchestrator_ack INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE TABLE IF NOT EXISTS kg_nodes (
    id      TEXT PRIMARY KEY,
    type    TEXT NOT NULL,    -- 'session' | 'event' | 'rule' | 'ip' | 'indicator'
    data    TEXT NOT NULL     -- JSON blob
);

CREATE TABLE IF NOT EXISTS kg_edges (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    src               TEXT NOT NULL,
    rel               TEXT NOT NULL,
    dst               TEXT NOT NULL,
    evidence_event_id TEXT,
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (src) REFERENCES kg_nodes(id),
    FOREIGN KEY (dst) REFERENCES kg_nodes(id)
);

CREATE TABLE IF NOT EXISTS rules (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT,
    enabled         INTEGER NOT NULL DEFAULT 1,
    definition      TEXT NOT NULL,   -- full JSON rule object
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_events_session    ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_ts         ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_type       ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_rule_matches_sess ON rule_matches(session_id, matched_at);
CREATE INDEX IF NOT EXISTS idx_decisions_sess    ON decisions(session_id);
CREATE INDEX IF NOT EXISTS idx_kg_edges_src      ON kg_edges(src);
CREATE INDEX IF NOT EXISTS idx_kg_edges_dst      ON kg_edges(dst);
"""


def init_db() -> None:
    """Create all tables and indexes if they do not exist."""
    os.makedirs(os.path.dirname(DB_PATH) if os.path.dirname(DB_PATH) else ".", exist_ok=True)
    conn = get_connection()
    try:
        conn.executescript(DDL)
        conn.commit()
        logger.info("Cerebrum DB initialized at %s", DB_PATH)
    finally:
        conn.close()
