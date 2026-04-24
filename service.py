"""
cerebrum/service.py — Decision Engine (FastAPI)
Ingests normalized events, applies rules, maintains KG + skill scores,
emits decisions to Orchestrator (HMAC-signed).
"""

import os
import json
import time
import hmac
import hashlib
import logging
from datetime import datetime, timezone
from contextlib import asynccontextmanager

import httpx
import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException, BackgroundTasks, Request, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional

from rules_engine import RulesEngine, load_rules, SAMPLE_RULES
from kg import KnowledgeGraph
from db import Database

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("cerebrum")

# ── Config ────────────────────────────────────────────────────────────────────
REDIS_URL       = os.getenv("REDIS_URL", "redis://localhost:6379")
ORCHESTRATOR_URL= os.getenv("ORCHESTRATOR_URL", "http://orchestrator:8001")
HMAC_SECRET     = os.getenv("HMAC_SECRET", "super-secret-key").encode()
DB_PATH         = os.getenv("DB_PATH", "/app/data/cerebrum.db")
PORT            = int(os.getenv("PORT", 8002))

# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.db = Database()
    app.state.kg   = KnowledgeGraph(app.state.db)
    app.state.rules= load_rules(SAMPLE_RULES)
    app.state.engine = RulesEngine(app.state.rules, app.state.db)
    try:
        app.state.redis = await aioredis.from_url(REDIS_URL, decode_responses=True)
        log.info("Redis connected")
    except Exception as e:
        log.warning(f"Redis unavailable ({e}); running without queue")
        app.state.redis = None
    log.info(f"Cerebrum started — {len(app.state.rules)} rules loaded")
    yield
    if app.state.redis:
        await app.state.redis.aclose()

app = FastAPI(title="Cerebrum — Decision Engine", lifespan=lifespan)

# ── Schemas ───────────────────────────────────────────────────────────────────
class NormalizedEvent(BaseModel):
    id:         str
    session_id: str
    timestamp:  str
    protocol:   str
    type:       str                          # e.g. "authentication_failed"
    indicators: list[str]  = Field(default_factory=list)
    source_ip:  str
    dest_ip:    Optional[str] = None
    dest_port:  Optional[int] = None
    username:   Optional[str] = None
    sensor:     Optional[str] = None
    extra:      dict           = Field(default_factory=dict)

class RuleCreate(BaseModel):
    id:              str
    description:     str
    protocol:        Optional[str] = None
    event_types:     list[str]
    indicators:      list[str]  = []
    window_seconds:  int        = 300
    count_threshold: int        = 1
    skill_delta:     int        = 1
    level_threshold: int        = 3
    action:          str        = "escalate_to_level_2"

# ── HMAC helper ───────────────────────────────────────────────────────────────
def make_hmac(payload: str) -> str:
    return hmac.new(HMAC_SECRET, payload.encode(), hashlib.sha256).hexdigest()

def verify_hmac(request_hmac: str, payload: str) -> bool:
    expected = make_hmac(payload)
    return hmac.compare_digest(expected, request_hmac)

async def require_hmac(request: Request):
    sig  = request.headers.get("X-HMAC-Signature", "")
    body = await request.body()
    if not verify_hmac(sig, body.decode()):
        raise HTTPException(status_code=401, detail="Invalid HMAC signature")

# ── POST /events — ingest a normalized event ──────────────────────────────────
@app.post("/events", status_code=202)
async def ingest_event(event: NormalizedEvent, background_tasks: BackgroundTasks):
    """Accept a normalized event and process it asynchronously."""
    background_tasks.add_task(_process_event, event, app.state)
    return {"accepted": True, "event_id": event.id}

async def _process_event(event: NormalizedEvent, state):
    try:
        db, kg, engine = state.db, state.kg, state.engine

        # Persist raw event
        db.save_event(event.model_dump())

        # Ensure session exists
        session = db.get_or_create_session(event.session_id, event.source_ip)

        # Add event node to KG
        kg.add_event_node(event)

        # Run rules
        matched = engine.evaluate(event, session)

        for rule, new_score, action in matched:
            decision = {
                "session_id":       event.session_id,
                "rule_id":          rule["id"],
                "skill_score_after": new_score,
                "action":           action,
                "explanation": (
                    f"Matched {rule['id']}: {rule['description']}. "
                    f"Evidence: [{event.id}]. Score now {new_score}."
                ),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            db.save_decision(decision)
            kg.add_decision_edge(event.session_id, event.id, rule["id"])
            log.info(f"Decision: session={event.session_id} rule={rule['id']} action={action}")

            if action.startswith("escalate"):
                await _post_to_orchestrator(decision)

        # Push to Redis decisions stream if available
        if state.redis:
            for _, _, _ in matched:
                await state.redis.xadd("decisions", {"data": json.dumps(decision)})

    except Exception as e:
        log.exception(f"Error processing event {event.id}: {e}")

async def _post_to_orchestrator(decision: dict):
    payload = json.dumps(decision)
    sig     = make_hmac(payload)
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.post(
                f"{ORCHESTRATOR_URL}/escalate",
                content=payload,
                headers={"Content-Type": "application/json", "X-HMAC-Signature": sig},
            )
            if r.status_code != 200:
                log.warning(f"Orchestrator returned {r.status_code}: {r.text}")
    except Exception as e:
        log.warning(f"Could not reach Orchestrator: {e}")

# ── Rules CRUD ────────────────────────────────────────────────────────────────
@app.get("/rules")
def list_rules():
    return {"rules": app.state.rules}

@app.post("/rules", status_code=201)
def create_rule(rule: RuleCreate):
    new = rule.model_dump()
    # Prevent duplicates
    if any(r["id"] == new["id"] for r in app.state.rules):
        raise HTTPException(409, f"Rule '{new['id']}' already exists")
    app.state.rules.append(new)
    app.state.engine.rules = app.state.rules
    return {"created": True, "rule": new}

@app.put("/rules/{rule_id}")
def update_rule(rule_id: str, rule: RuleCreate):
    for i, r in enumerate(app.state.rules):
        if r["id"] == rule_id:
            app.state.rules[i] = rule.model_dump()
            app.state.engine.rules = app.state.rules
            return {"updated": True, "rule": app.state.rules[i]}
    raise HTTPException(404, f"Rule '{rule_id}' not found")

@app.delete("/rules/{rule_id}")
def delete_rule(rule_id: str):
    before = len(app.state.rules)
    app.state.rules = [r for r in app.state.rules if r["id"] != rule_id]
    app.state.engine.rules = app.state.rules
    if len(app.state.rules) == before:
        raise HTTPException(404, f"Rule '{rule_id}' not found")
    return {"deleted": True}

# ── Sessions ──────────────────────────────────────────────────────────────────
@app.get("/sessions")
def list_sessions(limit: int = 50, level: Optional[int] = None):
    return {"sessions": app.state.db.list_sessions(limit=limit, level=level)}

@app.get("/sessions/{session_id}")
def get_session(session_id: str):
    s = app.state.db.get_session(session_id)
    if not s:
        raise HTTPException(404, "Session not found")
    return s

@app.get("/sessions/{session_id}/events")
def get_session_events(session_id: str):
    return {"events": app.state.db.get_events_for_session(session_id)}

# ── Explainability ────────────────────────────────────────────────────────────
@app.get("/explain/{session_id}")
def explain_session(session_id: str):
    session   = app.state.db.get_session(session_id)
    if not session:
        raise HTTPException(404, "Session not found")
    decisions = app.state.db.get_decisions_for_session(session_id)
    kg_data   = app.state.kg.get_session_graph(session_id)
    events    = app.state.db.get_events_for_session(session_id)

    lines = [
        f"Session {session_id}: skill_score={session['skill_score']}, "
        f"level={session['current_level']}, events={len(events)}, "
        f"decisions={len(decisions)}."
    ]
    for d in decisions:
        lines.append(f"  → {d['rule_id']} (score→{d['skill_score_after']}): {d['explanation']}")

    return {
        "session_id":      session_id,
        "skill_score":     session["skill_score"],
        "current_level":   session["current_level"],
        "decisions":       decisions,
        "kg":              kg_data,
        "human_readable":  lines,
    }

# ── Decisions ─────────────────────────────────────────────────────────────────
@app.get("/decisions")
def list_decisions(limit: int = 100):
    return {"decisions": app.state.db.list_decisions(limit=limit)}

# ── Metrics ───────────────────────────────────────────────────────────────────
@app.get("/metrics")
def get_metrics():
    return app.state.db.get_metrics()

# ── Health ────────────────────────────────────────────────────────────────────
@app.get("/healthz")
async def health():
    redis_ok = False
    if app.state.redis:
        try:
            await app.state.redis.ping()
            redis_ok = True
        except Exception:
            pass
    return {"status": "ok", "redis": redis_ok, "rules": len(app.state.rules)}
