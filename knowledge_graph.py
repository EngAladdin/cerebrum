"""
knowledge_graph.py — SQLite-backed Knowledge Graph for Cerebrum.

Graph model
-----------
Nodes:  session | event | rule | ip | indicator
Edges:  (session) -[has_event]-> (event)
        (event)   -[matches_rule]-> (rule)
        (session) -[originates_from]-> (ip)
        (event)   -[contains_indicator]-> (indicator)
        (session) -[triggered_decision]-> (rule)

All writes are idempotent — duplicate nodes are ignored via INSERT OR IGNORE.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any, Dict, List, Optional

from database import db_cursor
from schemas import IncomingEvent, KGTriple, RuleDefinition

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Node ID helpers
# ---------------------------------------------------------------------------

def _node_id(node_type: str, key: str) -> str:
    """Stable, short node ID: type:sha256_prefix_12."""
    digest = hashlib.sha256(f"{node_type}:{key}".encode()).hexdigest()[:12]
    return f"{node_type}:{digest}"


def session_node_id(session_id: str) -> str:
    return f"session:{session_id}"


def event_node_id(event_id: str) -> str:
    return f"event:{event_id}"


def rule_node_id(rule_id: str) -> str:
    return f"rule:{rule_id}"


def ip_node_id(ip: str) -> str:
    return _node_id("ip", ip)


def indicator_node_id(indicator: str) -> str:
    return _node_id("indicator", indicator)


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _upsert_node(node_id: str, node_type: str, data: Dict[str, Any]) -> None:
    """Insert node; ignore if already exists."""
    with db_cursor() as cur:
        cur.execute(
            "INSERT OR IGNORE INTO kg_nodes (id, type, data) VALUES (?,?,?)",
            (node_id, node_type, json.dumps(data)),
        )


def _insert_edge(src: str, rel: str, dst: str, evidence_event_id: Optional[str] = None) -> None:
    """Insert edge; skip duplicate (src, rel, dst) pairs."""
    with db_cursor() as cur:
        cur.execute(
            """
            INSERT INTO kg_edges (src, rel, dst, evidence_event_id)
            SELECT ?,?,?,?
            WHERE NOT EXISTS (
                SELECT 1 FROM kg_edges WHERE src=? AND rel=? AND dst=?
            )
            """,
            (src, rel, dst, evidence_event_id, src, rel, dst),
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def record_event(event: IncomingEvent) -> None:
    """
    Add nodes and edges for a newly ingested event:
      session -[has_event]-> event
      session -[originates_from]-> ip
      event   -[contains_indicator]-> indicator  (for each indicator)
    """
    sess_nid = session_node_id(event.session_id)
    evt_nid = event_node_id(event.id)
    ip_nid = ip_node_id(event.source_ip)

    _upsert_node(sess_nid, "session", {
        "session_id": event.session_id,
        "source_ip": event.source_ip,
    })
    _upsert_node(evt_nid, "event", {
        "event_id": event.id,
        "event_type": event.event_type,
        "protocol": event.protocol,
        "timestamp": event.timestamp.isoformat(),
    })
    _upsert_node(ip_nid, "ip", {"address": event.source_ip})

    _insert_edge(sess_nid, "has_event", evt_nid, event.id)
    _insert_edge(sess_nid, "originates_from", ip_nid, event.id)

    for ind in event.indicators[:20]:  # cap to avoid graph bloat
        ind_nid = indicator_node_id(ind)
        _upsert_node(ind_nid, "indicator", {"value": ind})
        _insert_edge(evt_nid, "contains_indicator", ind_nid, event.id)

    logger.debug("KG: recorded event %s for session %s", event.id, event.session_id)


def record_rule_match(event: IncomingEvent, rule: RuleDefinition) -> None:
    """
    Add edges for a rule match:
      event   -[matches_rule]-> rule
      session -[triggered_decision]-> rule
    """
    evt_nid = event_node_id(event.id)
    rule_nid = rule_node_id(rule.id)
    sess_nid = session_node_id(event.session_id)

    _upsert_node(rule_nid, "rule", {
        "rule_id": rule.id,
        "rule_name": rule.name,
        "action": rule.action,
    })

    _insert_edge(evt_nid, "matches_rule", rule_nid, event.id)
    _insert_edge(sess_nid, "triggered_decision", rule_nid, event.id)

    logger.debug("KG: recorded rule match %s for event %s", rule.id, event.id)


def get_session_triples(session_id: str) -> List[KGTriple]:
    """
    Return all KG triples reachable from the given session node.
    Uses a two-hop traversal: session → direct edges, then those nodes → their edges.
    """
    sess_nid = session_node_id(session_id)
    seen_edges: set = set()
    triples: List[KGTriple] = []

    with db_cursor() as cur:
        # Hop 1: edges from session node
        cur.execute(
            "SELECT src, rel, dst, evidence_event_id, created_at FROM kg_edges WHERE src = ?",
            (sess_nid,),
        )
        hop1 = cur.fetchall()

        for row in hop1:
            key = (row["src"], row["rel"], row["dst"])
            if key not in seen_edges:
                seen_edges.add(key)
                triples.append(KGTriple(**dict(row)))

        # Hop 2: edges from directly connected nodes
        connected_ids = {row["dst"] for row in hop1}
        for node_id in connected_ids:
            cur.execute(
                "SELECT src, rel, dst, evidence_event_id, created_at FROM kg_edges WHERE src = ?",
                (node_id,),
            )
            for row in cur.fetchall():
                key = (row["src"], row["rel"], row["dst"])
                if key not in seen_edges:
                    seen_edges.add(key)
                    triples.append(KGTriple(**dict(row)))

    return triples


def get_full_graph() -> Dict[str, Any]:
    """Return entire KG as {nodes: [...], edges: [...]} for dashboard visualization."""
    with db_cursor() as cur:
        cur.execute("SELECT id, type, data FROM kg_nodes LIMIT 2000")
        nodes = [
            {"id": r["id"], "type": r["type"], **json.loads(r["data"])}
            for r in cur.fetchall()
        ]
        cur.execute(
            "SELECT src, rel, dst, evidence_event_id, created_at FROM kg_edges LIMIT 5000"
        )
        edges = [dict(r) for r in cur.fetchall()]

    return {"nodes": nodes, "edges": edges}
