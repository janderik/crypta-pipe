from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


@dataclass
class LineageNode:
    node_id: str
    node_type: str  # source, transform, sink
    name: str
    metadata: dict = field(default_factory=dict)
    inputs: list[str] = field(default_factory=list)
    outputs: list[str] = field(default_factory=list)


@dataclass
class LineageEdge:
    edge_id: str
    source_id: str
    target_id: str
    transform: str = ""
    metadata: dict = field(default_factory=dict)


class LineageTracker:
    """Track data provenance through the pipeline with a directed graph."""

    def __init__(self, store_path: Optional[Path] = None) -> None:
        self._path = store_path or Path("lineage.json")
        self._nodes: dict[str, LineageNode] = {}
        self._edges: list[LineageEdge] = []
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        raw = self._path.read_text()
        if not raw.strip():
            return
        data = json.loads(raw)
        for nd in data.get("nodes", []):
            node = LineageNode(**nd)
            self._nodes[node.node_id] = node
        for ed in data.get("edges", []):
            self._edges.append(LineageEdge(**ed))

    def _save(self) -> None:
        data = {
            "nodes": [asdict(n) for n in self._nodes.values()],
            "edges": [asdict(e) for e in self._edges],
        }
        self._path.write_text(json.dumps(data, indent=2))

    def register_node(
        self,
        node_type: str,
        name: str,
        metadata: Optional[dict] = None,
    ) -> str:
        node_id = str(uuid.uuid4())
        node = LineageNode(
            node_id=node_id,
            node_type=node_type,
            name=name,
            metadata=metadata or {},
        )
        self._nodes[node_id] = node
        self._save()
        return node_id

    def register_edge(
        self,
        source_id: str,
        target_id: str,
        transform: str = "",
        metadata: Optional[dict] = None,
    ) -> str:
        if source_id not in self._nodes:
            raise ValueError(f"Unknown source node: {source_id}")
        if target_id not in self._nodes:
            raise ValueError(f"Unknown target node: {target_id}")
        edge_id = str(uuid.uuid4())
        edge = LineageEdge(
            edge_id=edge_id,
            source_id=source_id,
            target_id=target_id,
            transform=transform,
            metadata=metadata or {},
        )
        self._edges.append(edge)
        self._nodes[source_id].outputs.append(edge_id)
        self._nodes[target_id].inputs.append(edge_id)
        self._save()
        return edge_id

    def provenance(self, node_id: str) -> dict:
        if node_id not in self._nodes:
            return {"error": "node not found"}
        ancestors: set[str] = set()
        edges_up: list[dict] = []

        def walk(nid: str) -> None:
            for e in self._edges:
                if e.target_id == nid and e.source_id not in ancestors:
                    ancestors.add(e.source_id)
                    edges_up.append(asdict(e))
                    walk(e.source_id)

        walk(node_id)
        node = asdict(self._nodes[node_id])
        return {"node": node, "ancestors": list(ancestors), "edges": edges_up}

    def graph(self) -> dict:
        return {
            "nodes": {nid: asdict(n) for nid, n in self._nodes.items()},
            "edges": [asdict(e) for e in self._edges],
        }

    def clear(self) -> None:
        self._nodes.clear()
        self._edges.clear()
        self._save()
