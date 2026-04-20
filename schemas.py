"""
schemas.py — Pydantic models for Cerebrum's API surface and internal data structures.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Inbound: normalized events from Ingestion
# ---------------------------------------------------------------------------

class IncomingEvent(BaseModel):
    id: str
    session_id: str
    timestamp: datetime
    protocol: str
    event_type: str
    indicators: List[str] = Field(default_factory=list)
    source_ip: str
    destination_port: Optional[int] = None
    raw: Optional[Dict[str, Any]] = None
    ingestion_source: Optional[str] = None

    @field_validator("session_id", "id")
    @classmethod
    def no_injection(cls, v: str) -> str:
        import re
        if not re.match(r"^[\w\-\.]{1,256}$", v):
            raise ValueError(f"Invalid identifier: {v!r}")
        return v


class EventBatch(BaseModel):
    events: List[IncomingEvent] = Field(..., max_length=500)


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

class AggregationWindow(BaseModel):
    field: str = "event_type"           # which field to count
    value: str                          # value to match (e.g. "authentication_failed")
    count_threshold: int = Field(..., ge=1)
    window_seconds: int = Field(..., ge=1)


class RulePattern(BaseModel):
    field: str                          # e.g. "event_type", "protocol", "indicators"
    operator: str = "eq"                # eq | contains | in | regex
    value: Any


class RuleDefinition(BaseModel):
    id: str
    name: str
    description: str = ""
    enabled: bool = True
    protocols: List[str] = Field(default_factory=list)   # [] = any
    patterns: List[RulePattern] = Field(default_factory=list)
    aggregation: Optional[AggregationWindow] = None
    skill_delta: int = Field(1, ge=0, le=100)
    level_threshold: int = Field(0, ge=0)   # min skill_score to trigger action
    action: str = "escalate_to_level_2"     # escalate_to_level_2 | escalate_to_level_3 | flag | log


class RuleCreateRequest(BaseModel):
    rule: RuleDefinition


class RuleUpdateRequest(BaseModel):
    rule: RuleDefinition


# ---------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------

class DecisionAction(str, Enum):
    ESCALATE_L2 = "escalate_to_level_2"
    ESCALATE_L3 = "escalate_to_level_3"
    FLAG = "flag"
    LOG = "log"


class Decision(BaseModel):
    session_id: str
    rule_id: str
    skill_score_after: int
    action: str
    explanation: str


# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------

class SessionState(BaseModel):
    session_id: str
    source_ip: str
    skill_score: int
    current_level: int
    first_seen: str
    last_seen: str
    event_count: int
    released: bool


# ---------------------------------------------------------------------------
# Explanation endpoint response
# ---------------------------------------------------------------------------

class KGTriple(BaseModel):
    src: str
    rel: str
    dst: str
    evidence_event_id: Optional[str]
    created_at: str


class ExplainResponse(BaseModel):
    session_id: str
    skill_score: int
    current_level: int
    event_count: int
    decisions_history: List[Dict[str, Any]]
    kg_triples: List[KGTriple]
    rule_matches: List[Dict[str, Any]]
    summary: str


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    status: str
    db_ok: bool
    rules_loaded: int
    sessions_active: int
