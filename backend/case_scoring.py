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
import heapq
import re

from field_metadata import FIELD_META
from normalizer import is_empty
from scoring import _level, detect_technique, load_weights
from technique_profiles import get_profile
from correlation import MAX_CASE_NODES, MAX_CONTEXT_LEAVES_PER_NODE

QUALITY_WEIGHTS = {
    "completeness": 0.30,
    "validity": 0.30,
    "consistency": 0.25,
    "provenance": 0.15,
}

MAX_CONSISTENCY_CARRIERS = 3

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


def _provenance_score(node: dict) -> float:
    raw = node.get("raw") or {}
    meta = raw.get("_provenance") or {}
    if (meta.get("index") and meta.get("document_id")) or (raw.get("_index") and raw.get("_id")):
        return 1.0
    if raw.get("id") or raw.get("_id"):
        return 0.9
    if raw.get("@timestamp") and raw.get("agent"):
        return 0.75
    return 0.0


def _node_confidence(node_id: str, seed_id: str, adjacency: dict) -> float:
    if node_id == seed_id:
        return 1.0
    return adjacency.get(node_id, {}).get("confidence", 0.0)


def _node_support(node_id: str, seed_id: str, adjacency: dict) -> float:
    """Corroboration weight: identity-backed relationships count fully,
    weak/context relationships count at half."""
    if node_id == seed_id:
        return 1.0
    entry = adjacency.get(node_id)
    if not entry:
        return 0.0
    identity_confidence = entry.get("identity_confidence", 0.0)
    if identity_confidence > 0:
        return identity_confidence
    return 0.5 * entry.get("confidence", 0.5)


def _best_path_confidence(graph: dict, seed_id: str, identity_only: bool = False) -> dict:
    """Maximum product of edge confidences from the seed (weights are <= 1)."""
    best = {seed_id: 1.0}
    queue = [(-1.0, seed_id)]
    while queue:
        negative_score, source = heapq.heappop(queue)
        score = -negative_score
        if score + 1e-12 < best.get(source, 0.0):
            continue
        for target, confidence, identity_backed in graph.get(source, []):
            if identity_only and not identity_backed:
                continue
            candidate = score * max(0.0, min(1.0, confidence))
            if candidate > best.get(target, 0.0) + 1e-12:
                best[target] = candidate
                heapq.heappush(queue, (-candidate, target))
    return best


def _build_adjacency(edges: list, seed_id: str) -> dict:
    """Compute seed-relative confidence instead of taking arbitrary incident edges.

    ``E`` for a multi-hop carrier is the strongest product path from the seed.
    Identity-only path confidence is tracked separately so weak contextual
    edges do not receive the same consistency credit as causal pivots.
    """
    graph = {}
    for edge in edges:
        confidence = edge.get("confidence", 0.0)
        identity_backed = bool(edge.get("identity_backed"))
        source, target = edge["source"], edge["target"]
        graph.setdefault(source, []).append((target, confidence, identity_backed))
        graph.setdefault(target, []).append((source, confidence, identity_backed))

    best_any = _best_path_confidence(graph, seed_id)
    best_identity = _best_path_confidence(graph, seed_id, identity_only=True)
    return {
        node_id: {
            "confidence": best_any.get(node_id, 0.0),
            "identity_confidence": best_identity.get(node_id, 0.0),
        }
        for node_id in set(best_any) | set(best_identity)
    }


def _carriers_for(field: str, category: str, nodes: list) -> list:
    path = FIELD_META[category][field]["path"]
    carriers = []
    for node in nodes:
        value = node.get("raw") and _get_nested(node["raw"], path)
        if not is_empty(value):
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

    adjacency = _build_adjacency(edges, seed_id)

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
            provenance = max((_provenance_score(c["node"]) for c in carriers), default=0.0)
            confidence = max(
                (_node_confidence(c["node"]["id"], seed_id, adjacency) for c in carriers),
                default=0.0,
            )

            # Consistency is confidence-weighted corroboration: the seed fact
            # gives a 0.5 base, every correlated carrier adds 0.5 x the
            # confidence of the relationship that delivered it. Only the three
            # strongest carriers count, so a crowd of weak context events
            # cannot push consistency to 1.0.
            consistency = 0.0
            if carriers:
                base = 0.5 if any(c["node"]["id"] == seed_id for c in carriers) else 0.0
                supports = sorted(
                    (
                        _node_support(c["node"]["id"], seed_id, adjacency)
                        for c in carriers
                        if c["node"]["id"] != seed_id
                    ),
                    reverse=True,
                )[:MAX_CONSISTENCY_CARRIERS]
                consistency = min(1.0, base + 0.5 * sum(supports))

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
                        "source_index": carrier["node"].get("index"),
                        "source_id": carrier["node"].get("source_id"),
                        "agent_id": carrier["node"]["host"].get("id"),
                        "agent_name": carrier["node"]["host"].get("name"),
                        "value": carrier["value"][:120],
                        "relation_confidence": round(
                            _node_confidence(carrier["node"]["id"], seed_id, adjacency), 4
                        ),
                        "identity_backed": bool(
                            carrier["node"]["id"] == seed_id
                            or adjacency.get(carrier["node"]["id"], {}).get("expand")
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


def case_from_graph(graph, seed_id: str, max_depth: int = 3, max_nodes: int = MAX_CASE_NODES) -> tuple:
    """Extract the bounded case (nodes, edges) around a seed.

    Mirrors ``correlation.build_timeline_with_edges``: identity-backed edges are
    traversed up to ``max_depth``; weak/context edges contribute their
    endpoints as leaves but are never expanded from. At most
    ``MAX_CONTEXT_LEAVES_PER_NODE`` context neighbours per node are kept
    (highest confidence first) so same-user/same-host context cannot flood the
    case on busy endpoints.
    """
    from collections import deque

    if seed_id not in graph:
        return [], []

    visited = {seed_id}
    queue = deque([(seed_id, 0)])
    edges = {}

    while queue:
        node_id, depth = queue.popleft()
        identity_neighbors = []
        context_neighbors = []
        for neighbor in graph.neighbors(node_id):
            data = graph.get_edge_data(node_id, neighbor) or {}
            if data.get("expand"):
                identity_neighbors.append((data, neighbor))
            else:
                context_neighbors.append((data, neighbor))

        identity_neighbors.sort(key=lambda item: item[0].get("confidence", 0.0), reverse=True)
        context_neighbors.sort(key=lambda item: item[0].get("confidence", 0.0), reverse=True)
        selected = identity_neighbors + context_neighbors[:MAX_CONTEXT_LEAVES_PER_NODE]

        for data, neighbor in selected:
            if neighbor not in visited and len(visited) >= max_nodes:
                break
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
    nodes = list(expansion["nodes"])
    edges = list(expansion["edges"])
    node_ids = {node["id"] for node in nodes}
    aggregated_count = 0

    # Correlation aggregates repeated context facts to avoid graph explosion.
    # Preserve a bounded set of the omitted source events for case scoring so
    # the representative edge does not discard unique fields/provenance.
    for representative in expansion["edges"]:
        for aggregated in representative.get("aggregated_events", []):
            node = aggregated.get("node")
            edge = aggregated.get("edge")
            if node and node["id"] not in node_ids:
                nodes.append(node)
                node_ids.add(node["id"])
                aggregated_count += 1
            if edge:
                edges.append(edge)

    result = score_case(nodes, edges, expansion["seed"]["id"])
    result["nodes"] = expansion["stats"].get("nodes", len(expansion["nodes"]))
    result["edges"] = expansion["stats"].get("edges", len(expansion["edges"]))
    result["evidence_events"] = len(nodes)
    result["aggregated_evidence_events"] = aggregated_count
    result["aggregation_provenance_truncated"] = expansion["stats"].get(
        "aggregated_provenance_truncated", False
    )
    return result
