"""
rule_engine.py — Deterministic rule evaluation for Cerebrum.

Responsibilities
----------------
1. Load rules from DB (hot-reload on change).
2. match_event(event, rule) — check if a single event satisfies all patterns.
3. aggregate_count(session_id, rule) — count matching events in the time window.
4. evaluate(session_id, event) — run all enabled rules; return list of triggered rules.
5. update_skill_score(session_id, delta) — atomic skill score update.
6. build_decision(session_id, rule, window_count) — assemble Decision object.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from database import db_cursor
from schemas import AggregationWindow, Decision, IncomingEvent, RuleDefinition, RulePattern

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Rule loading
# ---------------------------------------------------------------------------

_rule_cache: Dict[str, RuleDefinition] = {}


def load_rules_from_db() -> Dict[str, RuleDefinition]:
    """Read all enabled rules from the DB and return as a dict keyed by rule ID."""
    rules: Dict[str, RuleDefinition] = {}
    with db_cursor() as cur:
        cur.execute("SELECT id, definition FROM rules WHERE enabled = 1")
        for row in cur.fetchall():
            try:
                defn = json.loads(row["definition"])
                rule = RuleDefinition.model_validate(defn)
                rules[rule.id] = rule
            except Exception as exc:
                logger.error("Failed to load rule %s: %s", row["id"], exc)
    logger.info("Loaded %d enabled rules from DB", len(rules))
    return rules


def get_rules() -> Dict[str, RuleDefinition]:
    """Return cached rules; reload if cache is empty."""
    global _rule_cache
    if not _rule_cache:
        _rule_cache = load_rules_from_db()
    return _rule_cache


def invalidate_rule_cache() -> None:
    global _rule_cache
    _rule_cache = {}


def seed_default_rules(rules_json_path: str) -> None:
    """
    Load default_rules.json into the DB on first start.
    Skips rules that already exist (by ID).
    """
    try:
        with open(rules_json_path) as fh:
            rules_raw = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("Cannot load default rules from %s: %s", rules_json_path, exc)
        return

    inserted = 0
    with db_cursor() as cur:
        for raw in rules_raw:
            cur.execute("SELECT 1 FROM rules WHERE id = ?", (raw["id"],))
            if cur.fetchone():
                continue
            rule = RuleDefinition.model_validate(raw)
            cur.execute(
                "INSERT INTO rules (id, name, description, enabled, definition) VALUES (?,?,?,?,?)",
                (rule.id, rule.name, rule.description, int(rule.enabled), json.dumps(raw)),
            )
            inserted += 1
    logger.info("Seeded %d default rules into DB", inserted)
    invalidate_rule_cache()


# ---------------------------------------------------------------------------
# Pattern matching
# ---------------------------------------------------------------------------

def _get_field_value(event: IncomingEvent, field: str) -> Any:
    """Safely retrieve an event field value; handles nested 'indicators' list."""
    if field == "indicators":
        return event.indicators  # return the whole list
    return getattr(event, field, None)


def _match_pattern(event: IncomingEvent, pattern: RulePattern) -> bool:
    """
    Evaluate a single pattern against an event.

    Operators:
      eq       — exact equality (case-insensitive for strings)
      contains — substring match for strings; membership test for lists
      in       — event field value is in pattern.value list
      regex    — re.search on string repr of field
    """
    field_val = _get_field_value(event, pattern.field)
    op = pattern.operator
    pval = pattern.value

    if field_val is None:
        return False

    if op == "eq":
        if isinstance(field_val, str):
            return field_val.lower() == str(pval).lower()
        return field_val == pval

    if op == "contains":
        if isinstance(field_val, list):
            # Check if any element in the list contains the string
            return any(str(pval).lower() in str(item).lower() for item in field_val)
        return str(pval).lower() in str(field_val).lower()

    if op == "in":
        if not isinstance(pval, list):
            pval = [pval]
        if isinstance(field_val, str):
            return field_val.lower() in [str(v).lower() for v in pval]
        return field_val in pval

    if op == "regex":
        target = " ".join(field_val) if isinstance(field_val, list) else str(field_val)
        try:
            return bool(re.search(str(pval), target, re.IGNORECASE))
        except re.error as exc:
            logger.warning("Regex error in rule pattern %r: %s", pval, exc)
            return False

    logger.warning("Unknown pattern operator: %r", op)
    return False


def match_event(event: IncomingEvent, rule: RuleDefinition) -> bool:
    """
    Return True if the event satisfies ALL of a rule's patterns.

    Also enforces protocol filter: if rule.protocols is non-empty, the event's
    protocol must be in that list.
    """
    # Protocol filter
    if rule.protocols and event.protocol.lower() not in [p.lower() for p in rule.protocols]:
        return False

    # All patterns must match (AND semantics)
    for pattern in rule.patterns:
        if not _match_pattern(event, pattern):
            return False

    return True


# ---------------------------------------------------------------------------
# Aggregation (time-windowed count)
# ---------------------------------------------------------------------------

def aggregate_count(session_id: str, rule: RuleDefinition) -> Tuple[int, List[str]]:
    """
    Count events matching the rule's aggregation window for a given session.

    Returns (count, [event_id, ...]) where event IDs are the matching rows.
    """
    if rule.aggregation is None:
        return 1, []

    agg: AggregationWindow = rule.aggregation
    window_start = (
        datetime.now(timezone.utc).timestamp() - agg.window_seconds
    )
    window_start_iso = datetime.fromtimestamp(window_start, tz=timezone.utc).isoformat()

    with db_cursor() as cur:
        cur.execute(
            """
            SELECT id FROM events
            WHERE session_id = ?
              AND event_type = ?
              AND timestamp >= ?
            ORDER BY timestamp ASC
            """,
            (session_id, agg.value, window_start_iso),
        )
        rows = cur.fetchall()

    count = len(rows)
    evidence_ids = [r["id"] for r in rows]
    return count, evidence_ids


# ---------------------------------------------------------------------------
# Session state helpers
# ---------------------------------------------------------------------------

def get_or_create_session(event: IncomingEvent) -> Dict[str, Any]:
    """Upsert session row; return current session dict."""
    now = datetime.now(timezone.utc).isoformat()
    with db_cursor() as cur:
        cur.execute("SELECT * FROM sessions WHERE session_id = ?", (event.session_id,))
        row = cur.fetchone()
        if row is None:
            cur.execute(
                """
                INSERT INTO sessions
                  (session_id, source_ip, skill_score, current_level, first_seen, last_seen, event_count)
                VALUES (?,?,0,1,?,?,0)
                """,
                (event.session_id, event.source_ip, now, now),
            )
            return {
                "session_id": event.session_id,
                "source_ip": event.source_ip,
                "skill_score": 0,
                "current_level": 1,
                "first_seen": now,
                "last_seen": now,
                "event_count": 0,
                "released": 0,
            }
        return dict(row)


def increment_event_count(session_id: str, timestamp: str) -> None:
    with db_cursor() as cur:
        cur.execute(
            "UPDATE sessions SET event_count = event_count + 1, last_seen = ? WHERE session_id = ?",
            (timestamp, session_id),
        )


def update_skill_score(session_id: str, delta: int) -> int:
    """Atomically add delta to skill_score; return new value. Score floor is 0."""
    with db_cursor() as cur:
        cur.execute(
            "UPDATE sessions SET skill_score = MAX(0, skill_score + ?) WHERE session_id = ?",
            (delta, session_id),
        )
        cur.execute("SELECT skill_score FROM sessions WHERE session_id = ?", (session_id,))
        row = cur.fetchone()
        return row["skill_score"] if row else 0


def update_level(session_id: str, new_level: int) -> None:
    with db_cursor() as cur:
        cur.execute(
            "UPDATE sessions SET current_level = MAX(current_level, ?) WHERE session_id = ?",
            (new_level, session_id),
        )


# ---------------------------------------------------------------------------
# Decision builder
# ---------------------------------------------------------------------------

def _determine_action(rule: RuleDefinition, skill_score: int) -> str:
    """Select final action considering the rule definition and current score."""
    # high_skill_persistent override
    if skill_score >= 10 and rule.action != "log":
        return "escalate_to_level_3"
    return rule.action


def build_decision(
    session: Dict[str, Any],
    rule: RuleDefinition,
    window_count: int,
    evidence_ids: List[str],
    skill_score_after: int,
) -> Decision:
    action = _determine_action(rule, skill_score_after)

    if window_count > 1 and rule.aggregation:
        trigger_desc = (
            f"Matched {rule.id}: {window_count} {rule.aggregation.value} events "
            f"within {rule.aggregation.window_seconds}s."
        )
    else:
        trigger_desc = f"Matched {rule.id}: {rule.description}."

    evidence_str = f" Evidence: [{', '.join(evidence_ids[:10])}]" if evidence_ids else ""
    explanation = trigger_desc + evidence_str

    return Decision(
        session_id=session["session_id"],
        rule_id=rule.id,
        skill_score_after=skill_score_after,
        action=action,
        explanation=explanation,
    )


# ---------------------------------------------------------------------------
# Main evaluation entry point
# ---------------------------------------------------------------------------

def evaluate(session_id: str, event: IncomingEvent) -> List[Decision]:
    """
    Run all enabled rules against a single event.

    Returns a (possibly empty) list of Decision objects for rules that fired.
    Each fired rule:
      1. Checks pattern match.
      2. Checks aggregation threshold (if defined).
      3. Updates skill score.
      4. Records a rule_match row.
      5. Builds a Decision.
    """
    rules = get_rules()
    session = get_or_create_session(event)
    decisions: List[Decision] = []

    for rule in rules.values():
        if not rule.enabled:
            continue

        # --- Pattern match ---
        if rule.patterns and not match_event(event, rule):
            continue

        # --- Aggregation threshold ---
        window_count, evidence_ids = aggregate_count(session_id, rule)
        if rule.aggregation and window_count < rule.aggregation.count_threshold:
            logger.debug(
                "Rule %s: session=%s window_count=%d < threshold=%d — not yet",
                rule.id, session_id, window_count, rule.aggregation.count_threshold,
            )
            continue

        # --- Skill score gate ---
        current_score = session["skill_score"]
        if current_score < rule.level_threshold:
            logger.debug("Rule %s: skill_score=%d < level_threshold=%d", rule.id, current_score, rule.level_threshold)
            continue

        # --- Fire ---
        new_score = update_skill_score(session_id, rule.skill_delta)
        session["skill_score"] = new_score  # reflect locally for subsequent rules

        # Level update
        if rule.action == "escalate_to_level_3":
            update_level(session_id, 3)
        elif rule.action == "escalate_to_level_2":
            update_level(session_id, 2)

        # Record match
        _record_rule_match(session_id, rule, window_count, evidence_ids)

        decision = build_decision(
            session=session,
            rule=rule,
            window_count=window_count,
            evidence_ids=evidence_ids,
            skill_score_after=new_score,
        )
        decisions.append(decision)

        logger.info(
            "Rule fired: %s | session=%s | score=%d | action=%s",
            rule.id, session_id, new_score, decision.action,
        )

    return decisions


def _store_event_direct(event: IncomingEvent) -> None:
    """Insert an event row directly — used by tests and replay utilities."""
    import json as _json
    with db_cursor() as cur:
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
                _json.dumps(event.indicators),
                event.ingestion_source,
                None,
            ),
        )


def _record_rule_match(
    session_id: str,
    rule: RuleDefinition,
    window_count: int,
    evidence_ids: List[str],
) -> None:
    with db_cursor() as cur:
        cur.execute(
            """
            INSERT INTO rule_matches (session_id, rule_id, skill_delta, window_count, evidence_ids)
            VALUES (?,?,?,?,?)
            """,
            (session_id, rule.id, rule.skill_delta, window_count, json.dumps(evidence_ids[:20])),
        )
