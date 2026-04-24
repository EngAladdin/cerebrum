"""
cerebrum/db.py — SQLite persistence layer.
Tables: events, sessions, decisions, kg_nodes, kg_edges
"""

import json
import sqlite3
import logging
import os
from datetime import datetime, timezone, timedelta

log = logging.getLogger("cerebrum.db")

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS sessions (
    session_id    TEXT PRIMARY KEY,
    source_ip     TEXT NOT NULL,
    skill_score   INTEGER DEFAULT 0,
    current_level INTEGER DEFAULT 1,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id           TEXT PRIMARY KEY,
    session_id   TEXT NOT NULL,
    timestamp    TEXT NOT NULL,
    protocol     TEXT,
    type         TEXT NOT NULL,
    indicators   TEXT,      -- JSON array
    source_ip    TEXT,
    dest_ip      TEXT,
    dest_port    INTEGER,
    username     TEXT,
    sensor       TEXT,
    extra        TEXT,      -- JSON object
    received_at  TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE TABLE IF NOT EXISTS decisions (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id       TEXT NOT NULL,
    rule_id          TEXT NOT NULL,
    skill_score_after INTEGER,
    action           TEXT NOT NULL,
    explanation      TEXT,
    timestamp        TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE TABLE IF NOT EXISTS kg_nodes (
    id         TEXT PRIMARY KEY,
    type       TEXT NOT NULL,   -- 'session' | 'event' | 'rule'
    data       TEXT,            -- JSON blob
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS kg_edges (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    src              TEXT NOT NULL,
    rel              TEXT NOT NULL,
    dst              TEXT NOT NULL,
    evidence_event_id TEXT,
    created_at       TEXT NOT NULL,
    UNIQUE(src, rel, dst)
);

CREATE INDEX IF NOT EXISTS idx_events_session   ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_type      ON events(type);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_decisions_session ON decisions(session_id);
"""


class Database:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._path = path
        self._con  = sqlite3.connect(path, check_same_thread=False)
        self._con.row_factory = sqlite3.Row
        self._con.executescript(SCHEMA)
        self._con.commit()
        log.info(f"Database ready at {path}")

    # ── Internal helpers ──────────────────────────────────────────────────────

    def execute(self, sql: str, params=()) -> sqlite3.Cursor:
        cur = self._con.execute(sql, params)
        self._con.commit()
        return cur

    def fetchone(self, sql: str, params=()) -> sqlite3.Row | None:
        return self._con.execute(sql, params).fetchone()

    def fetchall(self, sql: str, params=()) -> list[sqlite3.Row]:
        return self._con.execute(sql, params).fetchall()

    # ── Sessions ──────────────────────────────────────────────────────────────

    def get_or_create_session(self, session_id: str, source_ip: str) -> dict:
        now = _now()
        self.execute(
            """INSERT OR IGNORE INTO sessions
               (session_id, source_ip, skill_score, current_level, first_seen, last_seen)
               VALUES (?, ?, 0, 1, ?, ?)""",
            (session_id, source_ip, now, now),
        )
        self.execute(
            "UPDATE sessions SET last_seen = ? WHERE session_id = ?",
            (now, session_id),
        )
        return dict(self.fetchone("SELECT * FROM sessions WHERE session_id = ?", (session_id,)))

    def get_session(self, session_id: str) -> dict | None:
        row = self.fetchone("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
        return dict(row) if row else None

    def list_sessions(self, limit: int = 50, level: int | None = None) -> list[dict]:
        if level is not None:
            rows = self.fetchall(
                "SELECT * FROM sessions WHERE current_level = ? ORDER BY last_seen DESC LIMIT ?",
                (level, limit),
            )
        else:
            rows = self.fetchall(
                "SELECT * FROM sessions ORDER BY last_seen DESC LIMIT ?", (limit,)
            )
        return [dict(r) for r in rows]

    def update_skill_score(self, session_id: str, delta: int) -> int:
        self.execute(
            """UPDATE sessions
               SET skill_score   = skill_score + ?,
                   current_level = CASE
                     WHEN skill_score + ? >= 7 THEN 3
                     WHEN skill_score + ? >= 3 THEN 2
                     ELSE 1 END,
                   last_seen     = ?
               WHERE session_id = ?""",
            (delta, delta, delta, _now(), session_id),
        )
        row = self.fetchone("SELECT skill_score FROM sessions WHERE session_id = ?", (session_id,))
        return row["skill_score"] if row else 0

    # ── Events ────────────────────────────────────────────────────────────────

    def save_event(self, event: dict) -> None:
        self.execute(
            """INSERT OR REPLACE INTO events
               (id, session_id, timestamp, protocol, type, indicators,
                source_ip, dest_ip, dest_port, username, sensor, extra, received_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                event["id"],
                event["session_id"],
                event["timestamp"],
                event.get("protocol"),
                event["type"],
                json.dumps(event.get("indicators", [])),
                event.get("source_ip"),
                event.get("dest_ip"),
                event.get("dest_port"),
                event.get("username"),
                event.get("sensor"),
                json.dumps(event.get("extra", {})),
                _now(),
            ),
        )

    def get_events_for_session(self, session_id: str) -> list[dict]:
        rows = self.fetchall(
            "SELECT * FROM events WHERE session_id = ? ORDER BY timestamp ASC",
            (session_id,),
        )
        return [_row_to_dict(r) for r in rows]

    def count_events_in_window(
        self, session_id: str, event_types: list[str], window_seconds: int
    ) -> int:
        if not event_types:
            # Score-based rule — always passes
            return 1
        cutoff = (
            datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        ).isoformat()
        placeholders = ",".join("?" * len(event_types))
        row = self.fetchone(
            f"""SELECT COUNT(*) as cnt FROM events
                WHERE session_id = ?
                  AND type IN ({placeholders})
                  AND timestamp >= ?""",
            (session_id, *event_types, cutoff),
        )
        return row["cnt"] if row else 0

    # ── Decisions ─────────────────────────────────────────────────────────────

    def save_decision(self, decision: dict) -> None:
        self.execute(
            """INSERT INTO decisions
               (session_id, rule_id, skill_score_after, action, explanation, timestamp)
               VALUES (?,?,?,?,?,?)""",
            (
                decision["session_id"],
                decision["rule_id"],
                decision["skill_score_after"],
                decision["action"],
                decision["explanation"],
                decision["timestamp"],
            ),
        )

    def get_decisions_for_session(self, session_id: str) -> list[dict]:
        rows = self.fetchall(
            "SELECT * FROM decisions WHERE session_id = ? ORDER BY timestamp ASC",
            (session_id,),
        )
        return [dict(r) for r in rows]

    def list_decisions(self, limit: int = 100) -> list[dict]:
        rows = self.fetchall(
            "SELECT * FROM decisions ORDER BY timestamp DESC LIMIT ?", (limit,)
        )
        return [dict(r) for r in rows]

    # ── Metrics ───────────────────────────────────────────────────────────────

    def get_metrics(self) -> dict:
        total_sessions  = self.fetchone("SELECT COUNT(*) as c FROM sessions")["c"]
        total_events    = self.fetchone("SELECT COUNT(*) as c FROM events")["c"]
        total_decisions = self.fetchone("SELECT COUNT(*) as c FROM decisions")["c"]
        avg_score       = self.fetchone("SELECT AVG(skill_score) as a FROM sessions")["a"] or 0
        by_level = self.fetchall(
            "SELECT current_level, COUNT(*) as c FROM sessions GROUP BY current_level"
        )
        escalations = self.fetchall(
            "SELECT action, COUNT(*) as c FROM decisions GROUP BY action"
        )
        top_rules = self.fetchall(
            """SELECT rule_id, COUNT(*) as c FROM decisions
               GROUP BY rule_id ORDER BY c DESC LIMIT 10"""
        )
        return {
            "total_sessions":  total_sessions,
            "total_events":    total_events,
            "total_decisions": total_decisions,
            "avg_skill_score": round(avg_score, 2),
            "sessions_by_level": {str(r["current_level"]): r["c"] for r in by_level},
            "decisions_by_action": {r["action"]: r["c"] for r in escalations},
            "top_rules": [{"rule_id": r["rule_id"], "count": r["c"]} for r in top_rules],
        }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    for field in ("indicators", "extra"):
        if field in d and isinstance(d[field], str):
            try:
                d[field] = json.loads(d[field])
            except Exception:
                pass
    return d