"""
cerebrum/service.py — Decision Engine (FastAPI)
Ingests normalized events, applies rules, maintains KG + skill scores,
emits decisions to Orchestrator (HMAC-signed).

Includes built-in Redis consumer that reads from cerebrum:events queue.
"""

import asyncio
import os
import json
import hmac
import hashlib
import logging
from datetime import datetime, timezone
from contextlib import asynccontextmanager

import httpx
import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from pydantic import BaseModel, Field
from typing import Optional

from rules_engine import RulesEngine, load_rules, SAMPLE_RULES
from kg import KnowledgeGraph
from db import Database

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("cerebrum")

# ── Config ────────────────────────────────────────────────────────────────────
REDIS_URL        = os.getenv("REDIS_URL",        "redis://localhost:6379")
REDIS_QUEUE_KEY  = os.getenv("REDIS_QUEUE_KEY",  "cerebrum:events")
ORCHESTRATOR_URL = os.getenv("ORCHESTRATOR_URL", "http://orchestrator:8001")
HMAC_SECRET      = os.getenv("HMAC_SECRET",      "super-secret-key").encode()
PORT             = int(os.getenv("PORT", 8002))


# ── Event mapping helpers ─────────────────────────────────────────────────────

_EVENT_TYPE_MAP = {
    "cowrie.login.failed":         "authentication_failed",
    "cowrie.login.success":        "authentication_success",
    "cowrie.command.input":        "command_input",
    "cowrie.session.connect":      "connection_new",
    "cowrie.session.closed":       "connection_closed",
    "cowrie.session.params":       "connection_new",
    "cowrie.direct-tcpip.request": "connection_new",
    "connection":                  "connection_new",
}


def _map_event_type(et: str) -> str:
    return _EVENT_TYPE_MAP.get(et, et)


def _build_indicators(raw: dict) -> list:
    indicators = list(raw.get("indicators", []))
    if raw.get("username"):
        indicators.append(f"user:{raw['username']}")
    if raw.get("password"):
        indicators.append(f"pass:{raw['password']}")
    if raw.get("command"):
        indicators.append(f"cmd:{raw['command']}")
    if raw.get("payload"):
        indicators.append(f"payload:{str(raw['payload'])[:100]}")
    return indicators


def _map_raw_to_event(raw: dict) -> dict:
    """Map CerebrumEvent (from ingestion) → NormalizedEvent (for cerebrum)."""
    src_ip = raw.get("src_ip", "unknown")
    return {
        "id":         raw.get("event_id", raw.get("id", "")),
        "session_id": src_ip.replace(".", "_"),
        "timestamp":  raw.get("timestamp", ""),
        "protocol":   raw.get("protocol", "unknown"),
        "type":       _map_event_type(raw.get("event_type", "")),
        "indicators": _build_indicators(raw),
        "source_ip":  src_ip,
        "dest_ip":    raw.get("dst_ip"),
        "dest_port":  raw.get("dst_port"),
        "username":   raw.get("username"),
        "sensor":     raw.get("sensor_id"),
        "extra":      raw.get("raw_extra", {}),
    }


# ── Redis consumer ────────────────────────────────────────────────────────────

async def redis_consumer(state):
    """
    Background task: reads events from Redis queue and processes them.
    Runs forever alongside the FastAPI server.
    """
    log.info("Redis consumer started → queue: %s", REDIS_QUEUE_KEY)
    processed = 0
    failed    = 0

    while True:
        try:
            if state.redis is None:
                await asyncio.sleep(5)
                continue

            # BLPOP blocks up to 5s waiting for new events
            result = await state.redis.blpop(REDIS_QUEUE_KEY, timeout=5)

            if result is None:
                continue  # timeout — no events

            _, raw_json = result

            try:
                raw = json.loads(raw_json)
            except json.JSONDecodeError:
                log.warning("Invalid JSON in queue: %s", raw_json[:200])
                continue

            # Map to NormalizedEvent dict
            event_dict = _map_raw_to_event(raw)

            # Validate required fields before processing
            if not event_dict.get("id"):
                log.warning("Event missing ID, skipping: %s", str(raw)[:200])
                continue

            event = NormalizedEvent(**event_dict)

            # Process
            await _process_event(event, state)
            processed += 1

            if processed % 50 == 0:
                log.info("Consumer: processed=%d failed=%d", processed, failed)
            else:
                log.debug("Consumer: event %s processed", event.id)

        except asyncio.CancelledError:
            log.info("Redis consumer stopped — processed=%d failed=%d", processed, failed)
            break
        except Exception as e:
            failed += 1
            log.exception("Consumer error (failed=%d): %s", failed, e)
            await asyncio.sleep(2)


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("Cerebrum starting up")

    # Init DB (MySQL) + KG + Rules
    app.state.db     = Database()
    app.state.kg     = KnowledgeGraph(app.state.db)
    app.state.rules  = load_rules(SAMPLE_RULES)
    app.state.engine = RulesEngine(app.state.rules, app.state.db)

    # Connect to Redis
    try:
        app.state.redis = await aioredis.from_url(
            REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=5,
        )
        await app.state.redis.ping()
        log.info("Redis connected: %s", REDIS_URL)
    except Exception as e:
        log.warning("Redis unavailable (%s) — consumer will retry", e)
        app.state.redis = None

    # Start Redis consumer as background task
    consumer_task = asyncio.create_task(redis_consumer(app.state))

    log.info(
        "Cerebrum ready — %d rules loaded, queue=%s",
        len(app.state.rules),
        REDIS_QUEUE_KEY,
    )
    yield

    # Shutdown
    log.info("Cerebrum shutting down")
    consumer_task.cancel()
    try:
        await consumer_task
    except asyncio.CancelledError:
        pass

    if app.state.redis:
        await app.state.redis.aclose()

    log.info("Cerebrum shutdown complete")


app = FastAPI(title="Cerebrum — Decision Engine", lifespan=lifespan)


# ── Schemas ───────────────────────────────────────────────────────────────────

class NormalizedEvent(BaseModel):
    id:         str
    session_id: str
    timestamp:  str
    protocol:   str
    type:       str
    indicators: list[str]     = Field(default_factory=list)
    source_ip:  str
    dest_ip:    Optional[str] = None
    dest_port:  Optional[int] = None
    username:   Optional[str] = None
    sensor:     Optional[str] = None
    extra:      dict          = Field(default_factory=dict)


class RuleCreate(BaseModel):
    id:              str
    description:     str
    protocol:        Optional[str] = None
    event_types:     list[str]
    indicators:      list[str] = []
    window_seconds:  int       = 300
    count_threshold: int       = 1
    skill_delta:     int       = 1
    level_threshold: int       = 3
    action:          str       = "escalate_to_level_2"


# ── HMAC helpers ──────────────────────────────────────────────────────────────

def make_hmac(payload: str) -> str:
    return hmac.new(HMAC_SECRET, payload.encode(), hashlib.sha256).hexdigest()


def verify_hmac(request_hmac: str, payload: str) -> bool:
    return hmac.compare_digest(make_hmac(payload), request_hmac)


async def require_hmac(request: Request):
    sig  = request.headers.get("X-HMAC-Signature", "")
    body = await request.body()
    if not verify_hmac(sig, body.decode()):
        raise HTTPException(status_code=401, detail="Invalid HMAC signature")


# ── Core event processor ──────────────────────────────────────────────────────

async def _process_event(event: NormalizedEvent, state):
    try:
        db, kg, engine = state.db, state.kg, state.engine

        db.save_event(event.model_dump())
        session = db.get_or_create_session(event.session_id, event.source_ip)
        kg.add_event_node(event)

        matched = engine.evaluate(event, session)

        for rule, new_score, action in matched:
            decision = {
                "session_id":        event.session_id,
                "rule_id":           rule["id"],
                "skill_score_after": new_score,
                "action":            action,
                "explanation": (
                    f"Matched {rule['id']}: {rule['description']}. "
                    f"Evidence: [{event.id}]. Score now {new_score}."
                ),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            db.save_decision(decision)
            kg.add_decision_edge(event.session_id, event.id, rule["id"])
            log.info(
                "Decision: session=%s rule=%s action=%s score=%d",
                event.session_id, rule["id"], action, new_score,
            )

            if action.startswith("escalate"):
                await _post_to_orchestrator(decision)

            if state.redis:
                await state.redis.xadd("decisions", {"data": json.dumps(decision)})

    except Exception as e:
        log.exception("Error processing event %s: %s", event.id, e)


async def _post_to_orchestrator(decision: dict):
    payload = json.dumps(decision)
    sig = make_hmac(payload)
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.post(
                f"{ORCHESTRATOR_URL}/escalate",
                content=payload,
                headers={
                    "Content-Type":    "application/json",
                    "X-HMAC-Signature": sig,
                },
            )
            if r.status_code != 200:
                log.warning("Orchestrator returned %d", r.status_code)
    except Exception as e:
        log.warning("Could not reach Orchestrator: %s", e)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.post("/events", status_code=202)
async def ingest_event(event: NormalizedEvent, background_tasks: BackgroundTasks):
    """Accept a normalized event via HTTP (used for direct POST)."""
    background_tasks.add_task(_process_event, event, app.state)
    return {"accepted": True, "event_id": event.id}


@app.get("/rules")
def list_rules():
    return {"rules": app.state.rules}


@app.post("/rules", status_code=201)
def create_rule(rule: RuleCreate):
    new = rule.model_dump()
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


@app.get("/explain/{session_id}")
def explain_session(session_id: str):
    session = app.state.db.get_session(session_id)
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
        lines.append(
            f"  → {d['rule_id']} (score→{d['skill_score_after']}): {d['explanation']}"
        )

    return {
        "session_id":     session_id,
        "skill_score":    session["skill_score"],
        "current_level":  session["current_level"],
        "decisions":      decisions,
        "kg":             kg_data,
        "human_readable": lines,
    }


@app.get("/decisions")
def list_decisions(limit: int = 100):
    return {"decisions": app.state.db.list_decisions(limit=limit)}


@app.get("/metrics")
def get_metrics():
    return app.state.db.get_metrics()


# ── Health (Railway بيستخدم /health و /healthz) ──────────────────────────────

async def _health_response():
    redis_ok = False
    if app.state.redis:
        try:
            await app.state.redis.ping()
            redis_ok = True
        except Exception:
            pass

    db_ok = False
    try:
        app.state.db.fetchone("SELECT 1")
        db_ok = True
    except Exception:
        pass

    return {
        "status":   "ok" if (redis_ok and db_ok) else "degraded",
        "redis":    redis_ok,
        "db":       db_ok,
        "rules":    len(app.state.rules),
        "consumer": "running" if redis_ok else "disabled",
        "queue":    REDIS_QUEUE_KEY,
    }


@app.get("/healthz")
async def healthz():
    return await _health_response()


@app.get("/health")
async def health():
    return await _health_response()


@app.get("/")
async def root():
    return {
        "service": "cerebrum",
        "status":  "running",
        "rules":   len(app.state.rules),
        "queue":   REDIS_QUEUE_KEY,
        "docs":    "/docs",
    }
