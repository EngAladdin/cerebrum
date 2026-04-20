"""
main.py — Cerebrum decision engine service (FastAPI).

Endpoints
---------
POST /events                 Receive normalized event batch from Ingestion
GET  /explain/{session_id}   Full trace: skill score, KG, decisions, rule matches
GET  /sessions               List sessions (with filters)
GET  /sessions/{id}          Single session state
GET  /rules                  List all rules
POST /rules                  Create a new rule
PUT  /rules/{id}             Update a rule
DELETE /rules/{id}           Disable a rule
GET  /decisions              Recent decisions
GET  /kg                     Full knowledge graph (all nodes + edges)
GET  /healthz                Liveness probe
GET  /metrics                Prometheus metrics
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sqlite3
import time
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware

# Local imports
from database import db_cursor, init_db
from knowledge_graph import get_full_graph, get_session_triples, record_event, record_rule_match
from rule_engine import (
    evaluate,
    get_rules,
    increment_event_count,
    invalidate_rule_cache,
    load_rules_from_db,
    seed_default_rules,
)
from schemas import (
    Decision,
    EventBatch,
    ExplainResponse,
    HealthResponse,
    IncomingEvent,
    RuleCreateRequest,
    RuleDefinition,
    RuleUpdateRequest,
    SessionState,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
logger = logging.getLogger("cerebrum")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ORCHESTRATOR_URL: str = os.environ.get("ORCHESTRATOR_URL", "http://orchestrator:8000")
HMAC_SECRET: str = os.environ.get("HMAC_SECRET", "change-me-in-production")
DEFAULT_RULES_PATH: str = os.environ.get("DEFAULT_RULES_PATH", "/app/default_rules.json")

# ---------------------------------------------------------------------------
# HMAC dependency
# ---------------------------------------------------------------------------

from hmac_utils import require_hmac, signed_post  # noqa: E402

# ---------------------------------------------------------------------------
# Decision recorder
# ---------------------------------------------------------------------------

def _persist_decision(decision: Decision) -> None:
    with db_cursor() as cur:
        cur.execute(
            """
            INSERT INTO decisions (session_id, rule_id, action, skill_score_after, explanation)
            VALUES (?,?,?,?,?)
            """,
            (
                decision.session_id,
                decision.rule_id,
                decision.action,
                decision.skill_score_after,
                decision.explanation,
            ),
        )


# ---------------------------------------------------------------------------
# Orchestrator sender
# ---------------------------------------------------------------------------

async def _send_to_orchestrator(decision: Decision) -> None:
    if decision.action not in ("escalate_to_level_2", "escalate_to_level_3"):
        return  # flag / log actions don't require Orchestrator
    payload = decision.model_dump()
    try:
        await signed_post(f"{ORCHESTRATOR_URL}/escalate", payload)
        logger.info("Decision sent to Orchestrator: session=%s action=%s", decision.session_id, decision.action)
    except httpx.HTTPStatusError as exc:
        logger.error("Orchestrator HTTP error %d for session %s", exc.response.status_code, decision.session_id)
    except httpx.RequestError as exc:
        logger.error("Orchestrator unreachable for session %s: %s", decision.session_id, exc)


# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------

_counters: Dict[str, int] = {
    "events_processed": 0,
    "rules_fired": 0,
    "decisions_sent": 0,
    "errors": 0,
}

# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Cerebrum starting up")
    init_db()
    seed_default_rules(DEFAULT_RULES_PATH)
    load_rules_from_db()
    logger.info("Cerebrum ready — %d rules loaded", len(get_rules()))
    yield
    logger.info("Cerebrum shutting down")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="dynamic-labyrinth Cerebrum",
    version="1.0.0",
    description="AI decision engine: rule evaluation, knowledge graph, skill scoring.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Event persistence helper
# ---------------------------------------------------------------------------

def _store_event(event: IncomingEvent) -> None:
    with db_cursor() as cur:
        try:
            cur.execute(
                """
                INSERT OR IGNORE INTO events
                  (id, session_id, timestamp, protocol, event_type, source_ip,
                   destination_port, indicators, ingestion_source, raw)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    event.id,
                    event.session_id,
                    event.timestamp.isoformat(),
                    event.protocol,
                    event.event_type,
                    event.source_ip,
                    event.destination_port,
                    json.dumps(event.indicators),
                    event.ingestion_source,
                    json.dumps(event.raw) if event.raw else None,
                ),
            )
        except sqlite3.IntegrityError:
            pass  # duplicate event_id — idempotent


# ---------------------------------------------------------------------------
# Routes — Events
# ---------------------------------------------------------------------------

@app.post("/events", dependencies=[Depends(require_hmac)])
async def receive_events(batch: EventBatch) -> Dict[str, Any]:
    """
    Process a batch of normalized events from Ingestion.
    For each event: store → update KG → evaluate rules → send decisions.
    """
    accepted = 0
    rejected = 0
    decisions_fired: List[str] = []

    for event in batch.events:
        try:
            # 1. Persist event
            _store_event(event)
            increment_event_count(event.session_id, event.timestamp.isoformat())

            # 2. KG update
            record_event(event)

            # 3. Rule evaluation
            decisions = evaluate(event.session_id, event)
            _counters["events_processed"] += 1
            accepted += 1

            # 4. Handle decisions
            rules = get_rules()
            for decision in decisions:
                # KG: record rule match
                rule = rules.get(decision.rule_id)
                if rule:
                    record_rule_match(event, rule)

                # Persist decision
                _persist_decision(decision)
                _counters["rules_fired"] += 1

                # Forward escalations to Orchestrator
                await _send_to_orchestrator(decision)
                _counters["decisions_sent"] += 1
                decisions_fired.append(f"{decision.session_id}:{decision.rule_id}")

        except Exception as exc:
            _counters["errors"] += 1
            rejected += 1
            logger.exception("Error processing event %s: %s", event.id, exc)

    return {
        "ok": True,
        "accepted": accepted,
        "rejected": rejected,
        "decisions": decisions_fired,
    }


# ---------------------------------------------------------------------------
# Routes — Explain
# ---------------------------------------------------------------------------

@app.get("/explain/{session_id}", response_model=ExplainResponse)
async def explain(session_id: str) -> ExplainResponse:
    """Return full trace for a session: skill score, KG, decisions, rule matches."""
    with db_cursor() as cur:
        cur.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
        sess = cur.fetchone()
        if not sess:
            raise HTTPException(status_code=404, detail=f"Session {session_id!r} not found")

        cur.execute(
            "SELECT * FROM decisions WHERE session_id = ? ORDER BY sent_at DESC LIMIT 50",
            (session_id,),
        )
        decisions_history = [dict(r) for r in cur.fetchall()]

        cur.execute(
            """
            SELECT rm.*, r.name as rule_name FROM rule_matches rm
            LEFT JOIN rules r ON rm.rule_id = r.id
            WHERE rm.session_id = ? ORDER BY rm.matched_at DESC LIMIT 50
            """,
            (session_id,),
        )
        rule_matches = [dict(r) for r in cur.fetchall()]

    triples = get_session_triples(session_id)

    # Human-friendly summary
    decision_summary = ", ".join({d["action"] for d in decisions_history}) or "none"
    summary = (
        f"Session {session_id} | source IP: {sess['source_ip']} | "
        f"skill score: {sess['skill_score']} | level: {sess['current_level']} | "
        f"events: {sess['event_count']} | actions taken: {decision_summary}"
    )

    return ExplainResponse(
        session_id=session_id,
        skill_score=sess["skill_score"],
        current_level=sess["current_level"],
        event_count=sess["event_count"],
        decisions_history=decisions_history,
        kg_triples=triples,
        rule_matches=rule_matches,
        summary=summary,
    )


# ---------------------------------------------------------------------------
# Routes — Sessions
# ---------------------------------------------------------------------------

@app.get("/sessions")
async def list_sessions(
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    min_score: int = Query(0, ge=0),
    level: Optional[int] = Query(None),
) -> Dict[str, Any]:
    with db_cursor() as cur:
        query = "SELECT * FROM sessions WHERE skill_score >= ? AND released = 0"
        params: list = [min_score]
        if level is not None:
            query += " AND current_level = ?"
            params.append(level)
        query += " ORDER BY skill_score DESC LIMIT ? OFFSET ?"
        params += [limit, offset]
        cur.execute(query, params)
        sessions = [dict(r) for r in cur.fetchall()]
        cur.execute("SELECT COUNT(*) as cnt FROM sessions WHERE released = 0")
        total = cur.fetchone()["cnt"]
    return {"sessions": sessions, "total": total, "limit": limit, "offset": offset}


@app.get("/sessions/{session_id}", response_model=SessionState)
async def get_session(session_id: str) -> SessionState:
    with db_cursor() as cur:
        cur.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
        row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Session not found")
    return SessionState(**dict(row))


# ---------------------------------------------------------------------------
# Routes — Rules CRUD
# ---------------------------------------------------------------------------

@app.get("/rules")
async def list_rules(enabled_only: bool = Query(False)) -> Dict[str, Any]:
    with db_cursor() as cur:
        if enabled_only:
            cur.execute("SELECT * FROM rules WHERE enabled = 1 ORDER BY id")
        else:
            cur.execute("SELECT * FROM rules ORDER BY id")
        rows = [dict(r) for r in cur.fetchall()]
    # Parse definition JSON for each row
    for row in rows:
        try:
            row["definition"] = json.loads(row["definition"])
        except Exception:
            pass
    return {"rules": rows, "total": len(rows)}


@app.post("/rules", status_code=201)
async def create_rule(body: RuleCreateRequest, _: None = Depends(require_hmac)) -> Dict[str, Any]:
    rule = body.rule
    raw_defn = rule.model_dump()
    with db_cursor() as cur:
        cur.execute("SELECT 1 FROM rules WHERE id = ?", (rule.id,))
        if cur.fetchone():
            raise HTTPException(status_code=409, detail=f"Rule {rule.id!r} already exists")
        cur.execute(
            "INSERT INTO rules (id, name, description, enabled, definition) VALUES (?,?,?,?,?)",
            (rule.id, rule.name, rule.description, int(rule.enabled), json.dumps(raw_defn)),
        )
    invalidate_rule_cache()
    logger.info("Created rule: %s", rule.id)
    return {"ok": True, "rule_id": rule.id}


@app.put("/rules/{rule_id}")
async def update_rule(rule_id: str, body: RuleUpdateRequest, _: None = Depends(require_hmac)) -> Dict[str, Any]:
    rule = body.rule
    if rule.id != rule_id:
        raise HTTPException(status_code=400, detail="Rule ID in body must match URL")
    raw_defn = rule.model_dump()
    with db_cursor() as cur:
        cur.execute("SELECT 1 FROM rules WHERE id = ?", (rule_id,))
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="Rule not found")
        cur.execute(
            "UPDATE rules SET name=?, description=?, enabled=?, definition=?, updated_at=datetime('now') WHERE id=?",
            (rule.name, rule.description, int(rule.enabled), json.dumps(raw_defn), rule_id),
        )
    invalidate_rule_cache()
    logger.info("Updated rule: %s", rule_id)
    return {"ok": True, "rule_id": rule_id}


@app.delete("/rules/{rule_id}")
async def delete_rule(rule_id: str, _: None = Depends(require_hmac)) -> Dict[str, Any]:
    with db_cursor() as cur:
        cur.execute("UPDATE rules SET enabled = 0 WHERE id = ?", (rule_id,))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Rule not found")
    invalidate_rule_cache()
    logger.info("Disabled rule: %s", rule_id)
    return {"ok": True, "rule_id": rule_id, "note": "Rule disabled (soft delete)"}


# ---------------------------------------------------------------------------
# Routes — Decisions
# ---------------------------------------------------------------------------

@app.get("/decisions")
async def list_decisions(
    limit: int = Query(50, le=500),
    session_id: Optional[str] = Query(None),
) -> Dict[str, Any]:
    with db_cursor() as cur:
        if session_id:
            cur.execute(
                "SELECT * FROM decisions WHERE session_id = ? ORDER BY sent_at DESC LIMIT ?",
                (session_id, limit),
            )
        else:
            cur.execute("SELECT * FROM decisions ORDER BY sent_at DESC LIMIT ?", (limit,))
        rows = [dict(r) for r in cur.fetchall()]
    return {"decisions": rows, "total": len(rows)}


# ---------------------------------------------------------------------------
# Routes — Knowledge Graph
# ---------------------------------------------------------------------------

@app.get("/kg")
async def knowledge_graph() -> Dict[str, Any]:
    return get_full_graph()


@app.get("/kg/{session_id}")
async def session_kg(session_id: str) -> Dict[str, Any]:
    triples = get_session_triples(session_id)
    return {"session_id": session_id, "triples": [t.model_dump() for t in triples]}


# ---------------------------------------------------------------------------
# Routes — Health & Metrics
# ---------------------------------------------------------------------------

@app.get("/healthz", response_model=HealthResponse)
async def health() -> HealthResponse:
    db_ok = False
    sessions_active = 0
    try:
        with db_cursor() as cur:
            cur.execute("SELECT COUNT(*) as cnt FROM sessions WHERE released = 0")
            sessions_active = cur.fetchone()["cnt"]
        db_ok = True
    except Exception as exc:
        logger.error("DB health check failed: %s", exc)

    return HealthResponse(
        status="ok" if db_ok else "degraded",
        db_ok=db_ok,
        rules_loaded=len(get_rules()),
        sessions_active=sessions_active,
    )


@app.get("/metrics")
async def metrics():
    from fastapi.responses import PlainTextResponse
    with db_cursor() as cur:
        cur.execute("SELECT COUNT(*) as cnt FROM sessions")
        total_sessions = cur.fetchone()["cnt"]
        cur.execute("SELECT COUNT(*) as cnt FROM decisions")
        total_decisions = cur.fetchone()["cnt"]
        cur.execute("SELECT COUNT(*) as cnt FROM events")
        total_events = cur.fetchone()["cnt"]

    lines = [
        "# HELP dl_cerebrum_events_processed_total Events processed",
        "# TYPE dl_cerebrum_events_processed_total counter",
        f"dl_cerebrum_events_processed_total {_counters['events_processed']}",
        "# HELP dl_cerebrum_rules_fired_total Rules fired",
        "# TYPE dl_cerebrum_rules_fired_total counter",
        f"dl_cerebrum_rules_fired_total {_counters['rules_fired']}",
        "# HELP dl_cerebrum_sessions_total Total sessions in DB",
        "# TYPE dl_cerebrum_sessions_total gauge",
        f"dl_cerebrum_sessions_total {total_sessions}",
        "# HELP dl_cerebrum_decisions_total Total decisions emitted",
        "# TYPE dl_cerebrum_decisions_total counter",
        f"dl_cerebrum_decisions_total {total_decisions}",
        "# HELP dl_cerebrum_events_stored_total Total events stored",
        "# TYPE dl_cerebrum_events_stored_total counter",
        f"dl_cerebrum_events_stored_total {total_events}",
        "# HELP dl_cerebrum_errors_total Processing errors",
        "# TYPE dl_cerebrum_errors_total counter",
        f"dl_cerebrum_errors_total {_counters['errors']}",
    ]
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")


@app.get("/")
async def root():
    return {"service": "dynamic-labyrinth cerebrum", "version": "1.0.0", "docs": "/docs"}
