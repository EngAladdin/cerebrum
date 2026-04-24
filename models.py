"""
Pydantic models for Cerebrum (decision engine).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class NormalizedEvent(BaseModel):
    id: str
    session_id: str
    timestamp: str
    protocol: str
    event_type: str
    indicators: List[str] = Field(default_factory=list)
    source_ip: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    raw_data: Optional[Dict[str, Any]] = None
    sensor_id: Optional[str] = None


class RulePattern(BaseModel):
    """Matcher definition inside a Rule."""
    event_type: Optional[str] = None
    protocol: Optional[str] = None
    indicators: Optional[str] = None       # regex tested against each indicator
    destination_port: Optional[str] = None  # regex


class Rule(BaseModel):
    id: str
    name: str
    description: str
    patterns: Dict[str, Any]               # flexible — passed directly to match_event()
    aggregation_window_seconds: int = 300
    count_threshold: int = 1
    skill_delta: int = 1
    level_threshold: int = 3              # skill_score at which escalation fires
    action: str = "escalate_to_level_2"  # escalate_to_level_2 | escalate_to_level_3 | alert | log
    enabled: bool = True
    asserts: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)


class Decision(BaseModel):
    session_id: str
    rule_id: str
    skill_score_after: int
    action: str
    explanation: str
    timestamp: str = ""
    evidence: List[str] = Field(default_factory=list)


class SessionState(BaseModel):
    session_id: str
    source_ip: str
    protocol: str
    skill_score: int = 0
    current_level: int = 1
    first_seen: str
    last_seen: str
    event_count: int = 0


class KGNode(BaseModel):
    id: str
    type: str
    data: Dict[str, Any]


class KGEdge(BaseModel):
    src: str
    rel: str
    dst: str
    evidence_event_id: Optional[str] = None
