"""SQLite storage for Attack Surface Topology Graph (nodes & edges)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from backend.app.schemas.graph import (
    GraphDataResponse,
    GraphEdge,
    GraphNode,
    GraphStats,
    NodeRiskLevel,
    NodeType,
    RelationType,
)
from backend.app.storage.db import db

GRAPH_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS graph_nodes (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    type TEXT NOT NULL,
    label TEXT NOT NULL,
    risk_level TEXT DEFAULT 'INFO',
    properties_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS graph_edges (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    source TEXT NOT NULL,
    target TEXT NOT NULL,
    relation TEXT NOT NULL,
    label TEXT,
    properties_json TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_graph_nodes_target ON graph_nodes(target_id);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_risk ON graph_nodes(risk_level);
CREATE INDEX IF NOT EXISTS idx_graph_edges_target ON graph_edges(target_id);
CREATE INDEX IF NOT EXISTS idx_graph_edges_source ON graph_edges(source);
CREATE INDEX IF NOT EXISTS idx_graph_edges_target_node ON graph_edges(target);
"""


class GraphDatabase:
    def __init__(self):
        self.init_tables()

    def init_tables(self):
        with db.get_connection() as conn:
            conn.executescript(GRAPH_SCHEMA_SQL)
            conn.commit()

    def upsert_node(self, node: GraphNode) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO graph_nodes (id, target_id, type, label, risk_level, properties_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    label = excluded.label,
                    risk_level = excluded.risk_level,
                    properties_json = excluded.properties_json,
                    updated_at = excluded.updated_at
                """,
                (
                    node.id,
                    node.target_id,
                    node.type.value if hasattr(node.type, "value") else str(node.type),
                    node.label,
                    node.risk_level.value if hasattr(node.risk_level, "value") else str(node.risk_level),
                    json.dumps(node.properties),
                    node.created_at or now,
                    now,
                ),
            )
            conn.commit()

    def upsert_edge(self, edge: GraphEdge) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO graph_edges (id, target_id, source, target, relation, label, properties_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    edge.id,
                    edge.target_id,
                    edge.source,
                    edge.target,
                    edge.relation.value if hasattr(edge.relation, "value") else str(edge.relation),
                    edge.label,
                    json.dumps(edge.properties),
                    edge.created_at or now,
                ),
            )
            conn.commit()

    def bulk_save(self, target_id: str, nodes: list[GraphNode], edges: list[GraphEdge]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        clean_target = target_id.replace(":", "-")
        raw_target = target_id[7:] if target_id.startswith("target-") else target_id
        target_keys = list(dict.fromkeys([
            target_id,
            clean_target,
            f"target-{target_id}",
            f"target-{clean_target}",
            raw_target,
            raw_target.replace(":", "-"),
        ]))
        placeholders = ",".join("?" for _ in target_keys)
        with db.get_connection() as conn:
            cursor = conn.cursor()
            # Clear old graph of this target and its prefix variants
            cursor.execute(f"DELETE FROM graph_nodes WHERE target_id IN ({placeholders})", target_keys)
            cursor.execute(f"DELETE FROM graph_edges WHERE target_id IN ({placeholders})", target_keys)

            for n in nodes:
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO graph_nodes (id, target_id, type, label, risk_level, properties_json, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        n.id,
                        target_id,
                        n.type.value if hasattr(n.type, "value") else str(n.type),
                        n.label,
                        n.risk_level.value if hasattr(n.risk_level, "value") else str(n.risk_level),
                        json.dumps(n.properties),
                        n.created_at or now,
                        n.updated_at or now,
                    ),
                )

            for e in edges:
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO graph_edges (id, target_id, source, target, relation, label, properties_json, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        e.id,
                        target_id,
                        e.source,
                        e.target,
                        e.relation.value if hasattr(e.relation, "value") else str(e.relation),
                        e.label,
                        json.dumps(e.properties),
                        e.created_at or now,
                    ),
                )
            conn.commit()

    def get_node(self, node_id: str) -> GraphNode | None:
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM graph_nodes WHERE id = ?", (node_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_node(dict(row))

    def get_graph_by_target(self, target_id: str) -> GraphDataResponse:
        clean_target = target_id.replace(":", "-")
        raw_target = target_id[7:] if target_id.startswith("target-") else target_id
        target_keys = list(dict.fromkeys([
            target_id,
            clean_target,
            f"target-{target_id}",
            f"target-{clean_target}",
            raw_target,
            raw_target.replace(":", "-"),
        ]))
        nodes = []
        edges = []
        matched_target = target_id
        with db.get_connection() as conn:
            cursor = conn.cursor()
            for cand in target_keys:
                cursor.execute(
                    "SELECT * FROM graph_nodes WHERE target_id = ? ORDER BY type ASC, label ASC",
                    (cand,),
                )
                node_rows = cursor.fetchall()
                if node_rows:
                    nodes = [self._row_to_node(dict(r)) for r in node_rows]
                    cursor.execute(
                        "SELECT * FROM graph_edges WHERE target_id = ?",
                        (cand,),
                    )
                    edge_rows = cursor.fetchall()
                    edges = [self._row_to_edge(dict(r)) for r in edge_rows]
                    matched_target = cand
                    break

        # Compute stats
        by_type: dict[str, int] = {}
        by_risk: dict[str, int] = {}
        critical_paths = 0

        for n in nodes:
            t = n.type.value if hasattr(n.type, "value") else str(n.type)
            r = n.risk_level.value if hasattr(n.risk_level, "value") else str(n.risk_level)
            by_type[t] = by_type.get(t, 0) + 1
            by_risk[r] = by_risk.get(r, 0) + 1
            if r in ("CRITICAL", "HIGH"):
                critical_paths += 1

        from backend.app.services.graph_builder import build_attack_paths
        attack_paths = build_attack_paths(nodes, edges, matched_target)

        stats = GraphStats(
            total_nodes=len(nodes),
            total_edges=len(edges),
            by_type=by_type,
            by_risk=by_risk,
            critical_path_count=len(attack_paths) if attack_paths else critical_paths,
        )

        return GraphDataResponse(
            target_id=target_id,
            nodes=nodes,
            edges=edges,
            stats=stats,
            attack_paths=attack_paths,
        )

    def get_node_neighbors(self, target_id: str, node_id: str) -> dict[str, Any]:
        with db.get_connection() as conn:
            cursor = conn.cursor()
            # Ingoing edges
            cursor.execute(
                "SELECT * FROM graph_edges WHERE (target_id = ? OR target_id = ?) AND target = ?",
                (target_id, target_id.replace("target-", ""), node_id),
            )
            in_edges = [self._row_to_edge(dict(r)) for r in cursor.fetchall()]

            # Outgoing edges
            cursor.execute(
                "SELECT * FROM graph_edges WHERE (target_id = ? OR target_id = ?) AND source = ?",
                (target_id, target_id.replace("target-", ""), node_id),
            )
            out_edges = [self._row_to_edge(dict(r)) for r in cursor.fetchall()]

            # Fetch connected nodes
            neighbor_ids = {e.source for e in in_edges} | {e.target for e in out_edges}
            neighbors = []
            for nid in neighbor_ids:
                n = self.get_node(nid)
                if n:
                    neighbors.append(n)

        return {
            "node_id": node_id,
            "incoming_edges": in_edges,
            "outgoing_edges": out_edges,
            "neighbors": neighbors,
        }

    def clear_target_graph(self, target_id: str) -> int:
        clean_target = target_id.replace(":", "-")
        raw_target = target_id[7:] if target_id.startswith("target-") else target_id
        target_keys = list(dict.fromkeys([
            target_id,
            clean_target,
            f"target-{target_id}",
            f"target-{clean_target}",
            raw_target,
            raw_target.replace(":", "-"),
        ]))
        placeholders = ",".join("?" for _ in target_keys)
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"DELETE FROM graph_nodes WHERE target_id IN ({placeholders})", target_keys)
            deleted = cursor.rowcount
            cursor.execute(f"DELETE FROM graph_edges WHERE target_id IN ({placeholders})", target_keys)
            conn.commit()
            return deleted

    def _row_to_node(self, row: dict) -> GraphNode:
        props = json.loads(row.get("properties_json") or "{}")
        risk_str = row.get("risk_level") or "INFO"
        try:
            risk = NodeRiskLevel(risk_str)
        except Exception:
            risk = NodeRiskLevel.INFO

        try:
            ntype = NodeType(row.get("type"))
        except Exception:
            ntype = NodeType.TARGET

        return GraphNode(
            id=row["id"],
            target_id=row["target_id"],
            type=ntype,
            label=row["label"],
            risk_level=risk,
            properties=props,
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def _row_to_edge(self, row: dict) -> GraphEdge:
        props = json.loads(row.get("properties_json") or "{}")
        rel_str = row.get("relation") or "EXPOSES"
        try:
            relation = RelationType(rel_str)
        except Exception:
            relation = RelationType.EXPOSES

        return GraphEdge(
            id=row["id"],
            target_id=row["target_id"],
            source=row["source"],
            target=row["target"],
            relation=relation,
            label=row.get("label"),
            properties=props,
            created_at=row["created_at"],
        )


graph_db = GraphDatabase()
