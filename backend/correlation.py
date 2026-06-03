"""Graph-based Correlation Engine for Attack Timeline Reconstruction.

Uses NetworkX to build entity-based correlation graph and BFS for traversal.
"""

import networkx as nx
from collections import deque


CORRELATION_RULES = [
    {"key": "processGuid", "path": "data.win.eventdata.processGuid", "score": 100},
    {"key": "parentProcessGuid", "path": "data.win.eventdata.parentProcessGuid", "score": 90},
    {"key": "hashes", "path": "data.win.eventdata.hashes", "score": 90},
    {"key": "user", "path": "data.win.eventdata.user", "score": 70},
    {"key": "sourceIp", "path": "data.win.eventdata.sourceIp", "score": 60},
    {"key": "host", "path": "agent.name", "score": 50},
    {"key": "destinationIp", "path": "data.win.eventdata.destinationIp", "score": 60},
]


def _get_nested(data: dict, path: str):
    for key in path.split("."):
        if isinstance(data, dict):
            data = data.get(key)
        else:
            return None
    return data


def _extract_entities(alert: dict) -> dict:
    """Extract correlatable entities from an alert."""
    entities = {}
    for rule in CORRELATION_RULES:
        value = _get_nested(alert, rule["path"])
        if value and str(value).strip():
            entities[rule["key"]] = str(value).strip()
    return entities


def compute_correlation_score(entities_a: dict, entities_b: dict) -> int:
    """Compute correlation score between two sets of entities."""
    score = 0
    for rule in CORRELATION_RULES:
        key = rule["key"]
        val_a = entities_a.get(key)
        val_b = entities_b.get(key)
        if val_a and val_b and val_a == val_b:
            score += rule["score"]
    return score


def build_correlation_graph(alerts: list) -> nx.Graph:
    """Build a NetworkX graph from alerts with correlation edges."""
    G = nx.Graph()

    # Add nodes
    for alert in alerts:
        alert_id = alert.get("_id", alert.get("id"))
        G.add_node(alert_id, alert=alert, entities=_extract_entities(alert))

    # Add edges
    node_ids = list(G.nodes())
    for i in range(len(node_ids)):
        for j in range(i + 1, len(node_ids)):
            entities_a = G.nodes[node_ids[i]]["entities"]
            entities_b = G.nodes[node_ids[j]]["entities"]
            score = compute_correlation_score(entities_a, entities_b)
            if score > 0:
                G.add_edge(node_ids[i], node_ids[j], weight=score)

    return G


def bfs_timeline(G: nx.Graph, seed_id: str) -> list:
    """Traverse graph using BFS and return timeline sorted by timestamp."""
    if seed_id not in G:
        return []

    visited = set()
    queue = deque([seed_id])
    timeline_nodes = []

    while queue:
        node = queue.popleft()
        if node not in visited:
            visited.add(node)
            timeline_nodes.append(node)
            for neighbor in G.neighbors(node):
                if neighbor not in visited:
                    queue.append(neighbor)

    # Build timeline with alert data, sorted by timestamp
    result = []
    for node_id in timeline_nodes:
        alert = G.nodes[node_id]["alert"]
        result.append({
            "id": node_id,
            "timestamp": alert.get("@timestamp", ""),
            "agent": _get_nested(alert, "agent.name"),
            "mitre": alert.get("mitre", {}),
            "rule": alert.get("rule", {}),
            "scoring": alert.get("scoring", {}),
        })

    result.sort(key=lambda x: x["timestamp"])
    return result


def build_timeline_with_edges(G: nx.Graph, seed_id: str) -> dict:
    """Build full timeline response including nodes and edges."""
    if seed_id not in G:
        return {"nodes": [], "edges": []}

    visited = set()
    queue = deque([seed_id])
    related_nodes = set()
    related_edges = []

    while queue:
        node = queue.popleft()
        if node not in visited:
            visited.add(node)
            related_nodes.add(node)
            for neighbor in G.neighbors(node):
                edge_data = G.get_edge_data(node, neighbor)
                related_edges.append({
                    "source": node,
                    "target": neighbor,
                    "weight": edge_data["weight"],
                })
                if neighbor not in visited:
                    queue.append(neighbor)

    nodes = []
    for node_id in related_nodes:
        alert = G.nodes[node_id]["alert"]
        nodes.append({
            "id": node_id,
            "timestamp": alert.get("@timestamp", ""),
            "agent": _get_nested(alert, "agent.name"),
            "mitre": alert.get("mitre", {}),
            "rule": alert.get("rule", {}),
            "scoring": alert.get("scoring", {}),
            "summary": (
                alert.get("data", {}).get("win", {}).get("eventdata", {}).get("image", "")
                or alert.get("rule", {}).get("description", "")
            ),
        })

    nodes.sort(key=lambda x: x["timestamp"])
    return {"nodes": nodes, "edges": related_edges}
