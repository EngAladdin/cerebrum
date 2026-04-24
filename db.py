"""
cerebrum/db.py — MySQL persistence layer.
Tables: events, sessions, decisions, kg_nodes, kg_edges
"""

import json
import logging
import os
from datetime import datetime, timezone, timedelta

import pymysql
import pymysql.cursors

log = logging.getLogger("cerebrum.db")

# ---------------------------------------------------------------------------
# Configuration — from environment variables (Railway MySQL)
# ---------------------------------------------------------------------------

MYSQL_HOST     = os.environ.get("MYSQLHOST",     os.environ.get("DB_HOST", "localhost"))
MYSQL_PORT     = int(os.environ.get("MYSQLPORT", os.environ.get("DB_PORT", "3306")))
MYSQL_USER     = os.environ.get("MYSQLUSER",     os.environ.get("DB_USER", "root"))
MYSQL_PASSWORD = os.environ.get("MYSQLPASSWORD", os.environ.get("DB_PASSWORD", ""))
MYSQL_DATABASE = os.environ.get("MYSQLDATABASE", os.environ.get("DB_NAME", "cerebrum"))

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS sessions (
        session_id    VARCHAR(256) PRIMARY KEY,
        source_ip     VARCHAR(64)  NOT NULL,
        skill_score   INT          NOT NULL DEFAULT 0,
        current_level INT          NOT NULL DEFAULT 1,
        first_seen    VARCHAR(64)  NOT NULL,
        last_seen     VARCHAR(64)  NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS events (
        id           VARCHAR(256) PRIMARY KEY,
        session_id   VARCHAR(256) NOT NULL,
        timestamp    VARCHAR(64)  NOT NULL,
        protocol     VARCHAR(32),
        type         VARCHAR(128) NOT NULL,
        indicators   TEXT,
        source_ip    VARCHAR(64),
        dest_ip      VARCHAR(64),
        dest_port    INT,
        username     VARCHAR(128),
        sensor       VARCHAR(128),
        extra        TEXT,
        received_at  VARCHAR(64)  NOT NULL,
        INDEX idx_events_session   (session_id),
        INDEX idx_events_type      (type),
        INDEX idx_events_timestamp (timestamp)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS decisions (
        id                INT AUTO_INCREMENT PRIMARY KEY,
        session_id        VARCHAR(256) NOT NULL,
        rule_id           VARCHAR(128) NOT NULL,
        skill_score_after INT,
        action            VARCHAR(64)  NOT NULL,
        explanation       TEXT,
        timestamp         VARCHAR(64)  NOT NULL,
        INDEX idx_decisions_session (session_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS kg_nodes (
        id         VARCHAR(256) PRIMARY KEY,
        type       VARCHAR(32)  NOT NULL,
        data       TEXT,
        created_at VARCHAR(64)  NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS kg_edges (
        id                INT AUTO_INCREMENT PRIMARY KEY,
        src               VARCHAR(256) NOT NULL,
        rel               VARCHAR(64)  NOT NULL,
        dst               VARCHAR(256) NOT NULL,
        evidence_event_id VARCHAR(256),
        created_at        VARCHAR(64)  NOT NULL,
        UNIQUE KEY uniq_edge (src, rel, dst)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
]


class Database:
    def __init__(self):
        self._connect()
        self._init_schema()
        log.info("MySQL database ready at %s:%s/%s", MYSQL_HOST, MYSQL_PORT, MYSQL_DATABASE)

    def _connect(self):
        self._con = pymysql.connect(
            host=MYSQL_HOST,
            port=MYSQL_PORT,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_DATABASE,
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=True,
            connect_timeout=10,
        )

    def _ensure_connected(self):
        try:
            self._con.ping(reconnect=True)
        except Exception:
            self._connect()

    def _init_schema(self):
        self._ensure_connected()
        with self._con.cursor() as cur:
            for stmt in SCHEMA:
                cur.execute(stmt)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def execute(self, sql: str, params=()):
        # MySQL uses %s instead of ?
        sql = sql.replace("?", "%s")
        self._ensure_connected()
        with self._con.cursor() as cur:
            cur.execute(sql, params)
        return cur

    def fetchone(self, sql: str, params=()) -> dict | None:
        sql = sql.replace("?", "%s")
        self._ensure_connected()
        with self._con.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchone()

    def fetchall(self, sql: str, params=()) -> list[dict]:
        sql = sql.replace("?", "%s")
        self._ensure_connected()
        with self._con.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchall()

    # ── Sessions ──────────────────────────────────────────────────────────────

    def get_or_create_session(self, session_id: str, source_ip: str) -> dict:
        now = _now()
        # MySQL INSERT IGNORE instead of INSERT OR IGNORE
        self.execute(
            """INSERT IGNORE INTO sessions
               (session_id, source_ip, skill_score, current_level, first_seen, last_seen)
               VALUES (?, ?, 0, 1, ?, ?)""",
            (session_id, source_ip, now, now),
        )
        self.execute(
            "UPDATE sessions SET last_seen = ? WHERE session_id = ?",
            (now, session_id),
        )
        return self.fetchone("SELECT * FROM sessions WHERE session_id = ?", (session_id,))

    def get_session(self, session_id: str) -> dict | None:
        return self.fetchone("SELECT * FROM sessions WHERE session_id = ?", (session_id,))

    def list_sessions(self, limit: int = 50, level: int | None = None) -> list[dict]:
        if level is not None:
            return self.fetchall(
                "SELECT * FROM sessions WHERE current_level = ? ORDER BY last_seen DESC LIMIT ?",
                (level, limit),
            )
        return self.fetchall(
            "SELECT * FROM sessions ORDER BY last_seen DESC LIMIT ?", (limit,)
        )

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
        # MySQL REPLACE INTO instead of INSERT OR REPLACE
        self.execute(
            """REPLACE INTO events
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
        return [_parse_json_fields(r) for r in rows]

    def count_events_in_window(
        self, session_id: str, event_types: list[str], window_seconds: int
    ) -> int:
        if not event_types:
            return 1
        cutoff = (
            datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        ).isoformat()
        placeholders = ",".join(["%s"] * len(event_types))
        self._ensure_connected()
        with self._con.cursor() as cur:
            cur.execute(
                f"""SELECT COUNT(*) as cnt FROM events
                    WHERE session_id = %s
                      AND type IN ({placeholders})
                      AND timestamp >= %s""",
                (session_id, *event_types, cutoff),
            )
            row = cur.fetchone()
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
        return self.fetchall(
            "SELECT * FROM decisions WHERE session_id = ? ORDER BY timestamp ASC",
            (session_id,),
        )

    def list_decisions(self, limit: int = 100) -> list[dict]:
        return self.fetchall(
            "SELECT * FROM decisions ORDER BY timestamp DESC LIMIT ?", (limit,)
        )

    # ── Metrics ───────────────────────────────────────────────────────────────

    def get_metrics(self) -> dict:
        total_sessions  = self.fetchone("SELECT COUNT(*) as c FROM sessions")["c"]
        total_events    = self.fetchone("SELECT COUNT(*) as c FROM events")["c"]
        total_decisions = self.fetchone("SELECT COUNT(*) as c FROM decisions")["c"]
        avg_score       = self.fetchone("SELECT AVG(skill_score) as a FROM sessions")["a"] or 0
        by_level        = self.fetchall("SELECT current_level, COUNT(*) as c FROM sessions GROUP BY current_level")
        escalations     = self.fetchall("SELECT action, COUNT(*) as c FROM decisions GROUP BY action")
        top_rules       = self.fetchall(
            "SELECT rule_id, COUNT(*) as c FROM decisions GROUP BY rule_id ORDER BY c DESC LIMIT 10"
        )
        return {
            "total_sessions":     total_sessions,
            "total_events":       total_events,
            "total_decisions":    total_decisions,
            "avg_skill_score":    round(float(avg_score), 2),
            "sessions_by_level":  {str(r["current_level"]): r["c"] for r in by_level},
            "decisions_by_action":{r["action"]: r["c"] for r in escalations},
            "top_rules":          [{"rule_id": r["rule_id"], "count": r["c"]} for r in top_rules],
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_json_fields(row: dict) -> dict:
    for field in ("indicators", "extra"):
        if field in row and isinstance(row[field], str):
            try:
                row[field] = json.loads(row[field])
            except Exception:
                pass
    return row
