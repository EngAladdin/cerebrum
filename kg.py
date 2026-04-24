"""
cerebrum/kg.py — Knowledge Graph (SQLite-backed nodes + edges).
Tables: kg_nodes, kg_edges, session_nodes
"""

import logging
from datetime import datetime, timezone

log = logging.getLogger("cerebrum.kg")


class KnowledgeGraph:
    def __init__(self, db):
        self.db = db

    def add_event_node(self, event) -> None:
        """Create a KG node for the event and link it to its session."""
        # Session node (upsert)
        self.db.execute(
            """INSERT OR IGNORE INTO kg_nodes (id, type, data, created_at)
               VALUES (?, 'session', ?, ?)""",
            (event.session_id,
             f'{{"source_ip":"{event.source_ip}"}}',
             _now()),
        )
        # Event node
        self.db.execute(
            """INSERT OR REPLACE INTO kg_nodes (id, type, data, created_at)
               VALUES (?, 'event', ?, ?)""",
            (event.id,
             f'{{"type":"{event.type}","protocol":"{event.protocol}",'
             f'"timestamp":"{event.timestamp}"}}',
             _now()),
        )
        # Edge: session -[has_event]-> event
        self.db.execute(
            """INSERT OR IGNORE INTO kg_edges (src, rel, dst, evidence_event_id, created_at)
               VALUES (?, 'has_event', ?, ?, ?)""",
            (event.session_id, event.id, event.id, _now()),
        )

    def add_decision_edge(self, session_id: str, event_id: str, rule_id: str) -> None:
        """Add rule node and edges: event -[matches_rule]-> rule."""
        # Rule node
        self.db.execute(
            """INSERT OR IGNORE INTO kg_nodes (id, type, data, created_at)
               VALUES (?, 'rule', ?, ?)""",
            (rule_id, f'{{"rule_id":"{rule_id}"}}', _now()),
        )
        # Edge: event -[matches_rule]-> rule
        self.db.execute(
            """INSERT OR IGNORE INTO kg_edges (src, rel, dst, evidence_event_id, created_at)
               VALUES (?, 'matches_rule', ?, ?, ?)""",
            (event_id, rule_id, event_id, _now()),
        )
        # Edge: session -[triggered_rule]-> rule
        self.db.execute(
            """INSERT OR IGNORE INTO kg_edges (src, rel, dst, evidence_event_id, created_at)
               VALUES (?, 'triggered_rule', ?, ?, ?)""",
            (session_id, rule_id, event_id, _now()),
        )

    def get_session_graph(self, session_id: str) -> dict:
        """Return all nodes and edges reachable from a session node."""
        # Get all edges from/to this session
        edges = self.db.fetchall(
            """SELECT src, rel, dst, evidence_event_id
               FROM kg_edges
               WHERE src = ? OR dst = ?""",
            (session_id, session_id),
        )
        # Collect all node IDs
        node_ids = {session_id}
        for e in edges:
            node_ids.add(e["src"])
            node_ids.add(e["dst"])

        nodes = []
        for nid in node_ids:
            row = self.db.fetchone("SELECT * FROM kg_nodes WHERE id = ?", (nid,))
            if row:
                nodes.append(dict(row))

        return {"nodes": nodes, "edges": [dict(e) for e in edges]}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()