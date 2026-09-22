"""Case-level actionability scoring.

The per-alert score answers "is this single alert ready for investigation?".
The case score answers the analyst's real question: "does the correlated case
contain enough evidence?".

Model (aligned with the correlation design report):

    Q_f = 0.30*C_f + 0.30*V_f + 0.25*K_f + 0.15*R_f
    S_case = 100 * SUM(w_f * Q_f * E_f) / SUM(w_f)

for every expected field ``f`` of the technique profile, where:

    C = completeness : the field is present somewhere in the case
    V = validity     : the value passes a field-format check
    K = consistency  : confidence-weighted corroboration across events
                       (seed fact = 0.5 base, each correlated carrier adds
                        0.5 x the confidence of its relationship, capped at 1)
    R = provenance   : the fact is traceable to a raw source document
    E = evidence confidence: confidence of the strongest relationship that
        delivered the fact (1.0 for facts from the seed alert)
    w = AHP global weight of the field

Repeated evidence is deduplicated: a fact is counted once, with its carriers
listed, so ten identical network records cannot inflate the score. The
required-evidence coverage is reported separately as a gate indicator for the
technique's ATT&CK-required fields.
"""

from __future__ import annotations

import ipaddress
import re

from field_metadata import FIELD_META
from scoring import LOW_THRESHOLD, MEDIUM_THRESHOLD, _level, detect_technique, load_weights
from technique_profiles import get_profile

QUALITY_WEIGHTS = {
    "completeness": 0.30,
    "validity": 0.30,
    "consistency": 0.25,
    "provenance": 0.15,
}

_GUID_RE = re.compile(r"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$")
_SHA256_RE = re.compile(r"SHA256=[0-9A-Fa-f]{64}")


def _get_nested(data: dict, path: str):
    for key in path.split("."):
        if isinstance(data, dict):
            data = data.get(key)
        else:
            return None
    return data


def _validity(field: str, value) -> float:
    text = str(value).strip()
    if not text:
        return 0.0
    if field in ("processGuid", "parentProcessGuid"):
        return 1.0 if _GUID_RE.match(text) else 0.5
    if field == "hashes":
        return 1.0 if _SHA256_RE.search(text) else 0.5
    if field == "destinationIp":
        try:
            ipaddress.ip_address(text)
            return 1.0
        except ValueError:
            return 0.0
    if field == "destinationPort":
        try:
            port = int(text)
            return 1.0 if 0 < port <= 65535 else 0.0
        except ValueError:
            return 0.0
    return 1.0


def _node_confidence(node_id: str, seed_id: str, adjacency: dict) -> float:
    if node_id == seed_id:
        return 1.0
    return adjacency.get(node_id, 0.5)


def _build_adjacency(edges: list) -> dict:
    adjacency = {}
    for edge in edges:
        confidence = edge.get("confidence", 0.0)
        for endpoint in (edge["source"], edge["target"]):
            if confidence > adjacency.get(endpoint, 0.0):
                adjacency[endpoint] = confidence
    return adjacency


def _carriers_for(field: str, category: str, nodes: list) -> list:
    path = FIELD_META[category][field]["path"]
    carriers = []
    for node in nodes:
        value = node.get("raw") and _get_nested(node["raw"], path)
        if value and str(value).strip():
            carriers.append({"node": node, "value": str(value).strip()})
    return carriers


def score_case(nodes: list, edges: list, seed_id: str, technique: str | None = None) -> dict:
    """Score the aggregated evidence of a correlated case."""
    weights = load_weights()
    seed = next((node for node in nodes if node["id"] == seed_id), None)
    if seed is None:
        raise ValueError(f"seed {seed_id} not found in case nodes")

    if technique is None:
        technique = detect_technique(seed["raw"] or {})
    profile_key, profile = get_profile(technique)
    expected = profile["fields"]

    adjacency = _build_adjacency(edges)

    facts = []
    total_weight = 0.0
    total_contribution = 0.0
    required_total = 0
    required_covered = 0

    for category, fields in FIELD_META.items():
        for field, meta in fields.items():
            if field not in expected:
                continue
            weight = weights["categories"][category]["fields"][field]["global_weight"]
            role = expected[field]
            carriers = _carriers_for(field, category, nodes)

            completeness = 1.0 if carriers else 0.0
            validity = max((_validity(field, c["value"]) for c in carriers), default=0.0)
            provenance = 1.0 if any(c["node"].get("raw") for c in carriers) else 0.0
            confidence = max(
                (_node_confidence(c["node"]["id"], seed_id, adjacency) for c in carriers),
                default=0.0,
            )

            # Consistency is confidence-weighted corroboration: the seed fact
            # gives a 0.5 base, every correlated carrier adds 0.5 x the
            # confidence of the relationship that delivered it.
            consistency = 0.0
            if carriers:
                base = 0.5 if any(c["node"]["id"] == seed_id for c in carriers) else 0.0
                support = sum(
                    _node_confidence(c["node"]["id"], seed_id, adjacency)
                    for c in carriers
                    if c["node"]["id"] != seed_id
                )
                consistency = min(1.0, base + 0.5 * support)

            quality = (
                QUALITY_WEIGHTS["completeness"] * completeness
                + QUALITY_WEIGHTS["validity"] * validity
                + QUALITY_WEIGHTS["consistency"] * consistency
                + QUALITY_WEIGHTS["provenance"] * provenance
            )
            contribution = weight * quality * confidence

            total_weight += weight
            total_contribution += contribution

            if role == "required":
                required_total += 1
                if completeness:
                    required_covered += 1

            facts.append({
                "field": field,
                "label": meta["label"],
                "category": category,
                "role": role,
                "weight": round(weight, 6),
                "completeness": completeness,
                "validity": validity,
                "consistency": consistency,
                "provenance": provenance,
                "confidence": round(confidence, 4),
                "quality": round(quality, 4),
                "contribution": round(contribution, 6),
                "carriers": [
                    {
                        "event_id": carrier["node"]["id"],
                        "timestamp": carrier["node"]["timestamp"],
                        "event_type": carrier["node"]["event"]["id"],
                        "value": carrier["value"][:120],
                        "relation_confidence": round(
                            _node_confidence(carrier["node"]["id"], seed_id, adjacency), 4
                        ),
                    }
                    for carrier in carriers
                ],
            })

    case_score = round(100 * total_contribution / total_weight, 1) if total_weight else 0.0

    return {
        "case_id": seed_id,
        "technique": technique,
        "profile": profile_key,
        "profile_name": profile["name"],
        "case_score": case_score,
        "level": _level(case_score),
        "required_coverage": round(required_covered / required_total, 4) if required_total else 1.0,
        "required_covered": required_covered,
        "required_total": required_total,
        "facts": facts,
        "nodes": len(nodes),
        "edges": len(edges),
    }


def case_from_graph(graph, seed_id: str, max_depth: int = 3) -> tuple:
    """Extract the bounded case (nodes, edges) around a seed.

    Mirrors ``correlation.build_timeline_with_edges``: identity-backed edges are
    traversed up to ``max_depth``; weak/context edges contribute their
    endpoints as leaves but are never expanded from.
    """
    from collections import deque

    if seed_id not in graph:
        return [], []

    visited = {seed_id}
    queue = deque([(seed_id, 0)])
    edges = {}

    while queue:
        node_id, depth = queue.popleft()
        for neighbor in graph.neighbors(node_id):
            data = graph.get_edge_data(node_id, neighbor) or {}
            key = tuple(sorted((node_id, neighbor)))
            if key not in edges:
                edges[key] = {**data, "source": node_id, "target": neighbor}
            if neighbor not in visited:
                visited.add(neighbor)
                if depth + 1 < max_depth and data.get("expand"):
                    queue.append((neighbor, depth + 1))

    nodes = [graph.nodes[node_id]["norm"] for node_id in visited]
    return nodes, list(edges.values())


def score_graph_case(graph, seed_id: str) -> dict:
    nodes, edges = case_from_graph(graph, seed_id)
    return score_case(nodes, edges, seed_id)


def score_expansion_case(expansion: dict) -> dict:
    """Score an ``expand_case`` result (live Wazuh expansion)."""
    return score_case(
        expansion["nodes"],
        expansion["edges"],
        expansion["seed"]["id"],
    )
