"""
cerebrum/kg.py — Knowledge Graph (MySQL-backed nodes + edges).
Tables: kg_nodes, kg_edges, session_nodes
"""

import json
import logging
from datetime import datetime, timezone

log = logging.getLogger("cerebrum.kg")


class KnowledgeGraph:
    def __init__(self, db):
        self.db = db

    def add_event_node(self, event) -> None:
        """Create a KG node for the event and link it to its session."""
        # Session node (insert if not exists)
        self.db.execute(
            """INSERT IGNORE INTO kg_nodes (id, type, data, created_at)
               VALUES (%s, 'session', %s, %s)""",
            (event.session_id,
             json.dumps({"source_ip": event.source_ip}),
             _now()),
        )
        # Event node (replace if exists)
        self.db.execute(
            """REPLACE INTO kg_nodes (id, type, data, created_at)
               VALUES (%s, 'event', %s, %s)""",
            (event.id,
             json.dumps({
                 "type": event.type,
                 "protocol": event.protocol,
                 "timestamp": event.timestamp
             }),
             _now()),
        )
        # Edge: session -[has_event]-> event
        self.db.execute(
            """INSERT IGNORE INTO kg_edges (src, rel, dst, evidence_event_id, created_at)
               VALUES (%s, 'has_event', %s, %s, %s)""",
            (event.session_id, event.id, event.id, _now()),
        )

    def add_decision_edge(self, session_id: str, event_id: str, rule_id: str) -> None:
        """Add rule node and edges: event -[matches_rule]-> rule."""
        # Rule node
        self.db.execute(
            """INSERT IGNORE INTO kg_nodes (id, type, data, created_at)
               VALUES (%s, 'rule', %s, %s)""",
            (rule_id, json.dumps({"rule_id": rule_id}), _now()),
        )
        # Edge: event -[matches_rule]-> rule
        self.db.execute(
            """INSERT IGNORE INTO kg_edges (src, rel, dst, evidence_event_id, created_at)
               VALUES (%s, 'matches_rule', %s, %s, %s)""",
            (event_id, rule_id, event_id, _now()),
        )
        # Edge: session -[triggered_rule]-> rule
        self.db.execute(
            """INSERT IGNORE INTO kg_edges (src, rel, dst, evidence_event_id, created_at)
               VALUES (%s, 'triggered_rule', %s, %s, %s)""",
            (session_id, rule_id, event_id, _now()),
        )

    def get_session_graph(self, session_id: str) -> dict:
        """Return all nodes and edges reachable from a session node."""
        # Get all edges from/to this session
        edges = self.db.fetchall(
            """SELECT src, rel, dst, evidence_event_id
               FROM kg_edges
               WHERE src = %s OR dst = %s""",
            (session_id, session_id),
        )
        # Collect all node IDs
        node_ids = {session_id}
        for e in edges:
            node_ids.add(e["src"])
            node_ids.add(e["dst"])

        nodes = []
        for nid in node_ids:
            row = self.db.fetchone("SELECT * FROM kg_nodes WHERE id = %s", (nid,))
            if row:
                nodes.append(dict(row))

        return {"nodes": nodes, "edges": [dict(e) for e in edges]}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
