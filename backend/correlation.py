"""Typed-edge correlation engine (identity-first, context-second).

Design used in this thesis:

  1. Pivots are classified as *identity* (process.guid, parent->child guid,
     sha256), *behavioral* (destination tuple, DNS, file, registry) or *scope*
     (user, host, timestamp).
  2. Every edge is a typed relationship (SAME_PROCESS, PARENT_CHILD,
     PROCESS_CONNECTED_TO, ...) with provenance evidence, not a blind sum of
     matching fields.
  3. Relationship confidence follows the weighted model:

         C = 0.45*P + 0.20*T + 0.15*H + 0.10*S + 0.10*X

     P = pivot strength, T = temporal proximity (exponential decay),
     H = host consistency, S = session/user consistency,
     X = independent corroborating evidence.
  4. Graph expansion is bounded (depth + node cap) and only identity-backed
     edges may recurse; scope pivots (user/host/time) never expand the graph.
"""

from __future__ import annotations

import math
from collections import deque
from datetime import datetime, timedelta, timezone

import networkx as nx

from normalizer import normalize_alert

# ── Confidence model ─────────────────────────────────────────────
CONFIDENCE_WEIGHTS = {
    "pivot": 0.45,
    "time": 0.20,
    "host": 0.15,
    "session": 0.10,
    "corroboration": 0.10,
}

STRONG_THRESHOLD = 0.85
SUPPORTED_THRESHOLD = 0.65
CANDIDATE_THRESHOLD = 0.45

IDENTITY_PIVOTS = {"process.guid", "parent.child.guid", "file.hash.sha256"}
MAX_CASE_NODES = 200
MAX_CONTEXT_LEAVES_PER_NODE = 5
MAX_AGGREGATED_EVENTS_PER_FACT = 25

# Pivot strengths are separate from relationship labels: e.g. an exact
# ProcessGuid can establish PROCESS_CONNECTED_TO with P=1.00, while a
# destination tuple can establish the same semantic context with P=0.80.
# Values are engineering defaults from deep-research-report.md and must be
# calibrated against labeled data.
PIVOT_STRENGTHS = {
    "process.guid": 1.00,
    "parent.child.guid": 0.98,
    "file.hash.sha256": 0.95,
    "destination.tuple": 0.80,
    "destination.ip": 0.45,
    "user.name": 0.35,
}

# ── Typed relationships ──────────────────────────────────────────
# window_s : retrieval / acceptance window for the relationship
# tau_s    : decay constant for T = exp(-dt/tau)
# expand   : may the edge be traversed to keep expanding the case?
RELATION_TYPES = {
    "SAME_PROCESS": {
        "window_s": 21600, "tau_s": 900, "host": "same", "expand": True,
    },
    "PARENT_CHILD": {
        "window_s": 3600, "tau_s": 900, "host": "same", "expand": True,
    },
    "SAME_BINARY": {
        "window_s": 86400, "tau_s": 21600, "host": "any", "expand": True,
    },
    "PROCESS_CONNECTED_TO": {
        "window_s": 300, "tau_s": 300, "host": "same", "expand": True,
    },
    "PROCESS_QUERIED_DNS": {
        "window_s": 300, "tau_s": 300, "host": "same", "expand": True,
    },
    "PROCESS_MODIFIED_REGISTRY": {
        "window_s": 600, "tau_s": 600, "host": "same", "expand": True,
    },
    "PROCESS_CREATED_FILE": {
        "window_s": 600, "tau_s": 600, "host": "same", "expand": True,
    },
    "PROCESS_TERMINATED": {
        "window_s": 21600, "tau_s": 900, "host": "same", "expand": False,
    },
    "DESTINATION_SHARED": {
        "window_s": 300, "tau_s": 300, "host": "same", "expand": False,
    },
    "SUPPORTING_CONTEXT": {
        "window_s": 300, "tau_s": 300, "host": "same", "expand": False,
    },
}

# Identity-backed relationships keep identity windows even when the event pair
# is a process->network / process->terminate pair (the guid proves identity,
# proximity is not what justifies the edge).
LIFECYCLE_WINDOW_S = 21600
LIFECYCLE_TAU_S = 900


def parse_timestamp(value):
    """Parse ISO-8601 (incl. trailing Z) into an aware UTC datetime."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def format_timestamp(value) -> str | None:
    parsed = parse_timestamp(value)
    if parsed is None:
        return None
    return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


# ── Pivot extraction ─────────────────────────────────────────────
def extract_pivots(norm: dict) -> list:
    """Ranked pivots that can retrieve related telemetry for a normalized event."""
    process = norm["process"]
    pivots = []

    if process["guid"]:
        pivots.append({
            "name": "self_process",
            "field": "process.guid",
            "value": process["guid"],
            "window_s": LIFECYCLE_WINDOW_S,
            "host_scoped": True,
        })
        pivots.append({
            "name": "children",
            "field": "process.parent.guid",
            "value": process["guid"],
            "window_s": LIFECYCLE_WINDOW_S,
            "host_scoped": True,
        })
    if process["parent"]["guid"]:
        pivots.append({
            "name": "parent",
            "field": "process.guid",
            "value": process["parent"]["guid"],
            "window_s": LIFECYCLE_WINDOW_S,
            "host_scoped": True,
        })

    sha256 = norm["file"]["hash"].get("sha256")
    if sha256:
        pivots.append({
            "name": "sha256",
            "field": "file.hash.sha256",
            "value": sha256,
            "window_s": 86400,
            "host_scoped": False,
        })

    if norm["destination"]["ip"]:
        pivots.append({
            "name": "destination",
            "field": "destination.ip",
            "value": norm["destination"]["ip"],
            "window_s": 300,
            "host_scoped": True,
        })

    if norm["user"]["name"]:
        pivots.append({
            "name": "user",
            "field": "user.name",
            "value": norm["user"]["name"],
            "window_s": 300,
            "host_scoped": True,
        })

    return pivots


# ── Pair classification ──────────────────────────────────────────
def _lineage_eligible(a: dict, b: dict) -> bool:
    """Process lineage is only defined between Process Create records."""
    return a["event"]["id"] == "1" and b["event"]["id"] == "1"


def _verified_pivots(a: dict, b: dict) -> list:
    """All pivots that independently hold between two normalized events."""
    found = []
    ap, bp = a["process"], b["process"]

    if ap["guid"] and ap["guid"] == bp["guid"]:
        found.append(("process.guid", PIVOT_STRENGTHS["process.guid"]))
    if _lineage_eligible(a, b):
        if ap["guid"] and ap["guid"] == bp["parent"]["guid"]:
            found.append(("parent.child.guid", PIVOT_STRENGTHS["parent.child.guid"]))
        if bp["guid"] and bp["guid"] == ap["parent"]["guid"]:
            found.append(("parent.child.guid", PIVOT_STRENGTHS["parent.child.guid"]))

    sha_a = a["file"]["hash"].get("sha256")
    sha_b = b["file"]["hash"].get("sha256")
    if sha_a and sha_a == sha_b:
        found.append(("file.hash.sha256", PIVOT_STRENGTHS["file.hash.sha256"]))

    da, db = a["destination"], b["destination"]
    if da["ip"] and da["ip"] == db["ip"]:
        same_tuple = bool(
            da["port"]
            and db["port"]
            and da["port"] == db["port"]
            and da["protocol"]
            and db["protocol"]
            and str(da["protocol"]).lower() == str(db["protocol"]).lower()
        )
        pivot = "destination.tuple" if same_tuple else "destination.ip"
        found.append((pivot, PIVOT_STRENGTHS[pivot]))

    ua, ub = a["user"]["name"], b["user"]["name"]
    if ua and ua == ub:
        found.append(("user.name", PIVOT_STRENGTHS["user.name"]))

    return found


def _relation_label(a: dict, b: dict) -> str | None:
    ap, bp = a["process"], b["process"]
    families = {a["event"]["id"], b["event"]["id"]}

    if ap["guid"] and ap["guid"] == bp["guid"]:
        if "3" in families:
            return "PROCESS_CONNECTED_TO"
        if "22" in families:
            return "PROCESS_QUERIED_DNS"
        if "11" in families:
            return "PROCESS_CREATED_FILE"
        if families & {"12", "13", "14"}:
            return "PROCESS_MODIFIED_REGISTRY"
        if "5" in families:
            return "PROCESS_TERMINATED"
        return "SAME_PROCESS"

    # Lineage requires Process Create records on both sides, so a create event
    # does not also become a "child" of the parent's terminate event (that pair
    # is already linked through SAME_PROCESS).
    if _lineage_eligible(a, b):
        if ap["guid"] and ap["guid"] == bp["parent"]["guid"]:
            return "PARENT_CHILD"
        if bp["guid"] and bp["guid"] == ap["parent"]["guid"]:
            return "PARENT_CHILD"

    sha_a = a["file"]["hash"].get("sha256")
    sha_b = b["file"]["hash"].get("sha256")
    if sha_a and sha_a == sha_b:
        return "SAME_BINARY"

    da, db = a["destination"], b["destination"]
    if da["ip"] and da["ip"] == db["ip"]:
        return "DESTINATION_SHARED"

    ua, ub = a["user"]["name"], b["user"]["name"]
    if ua and ua == ub:
        return "SUPPORTING_CONTEXT"

    return None


def _incidental_corroborators(a: dict, b: dict) -> int:
    count = 0
    if a["process"]["executable"] and a["process"]["executable"] == b["process"]["executable"]:
        count += 1
    if a["process"]["command_line"] and a["process"]["command_line"] == b["process"]["command_line"]:
        count += 1
    if a["process"]["parent"]["guid"] and a["process"]["parent"]["guid"] == b["process"]["parent"]["guid"]:
        count += 1
    return count


def classify_pair(a: dict, b: dict) -> dict | None:
    """Validate the semantic relationship between two normalized events.

    Returns a typed edge with confidence and provenance, or None when the
    pair must not become a case relationship.
    """
    if a["id"] == b["id"]:
        return None

    relation = _relation_label(a, b)
    if relation is None:
        return None

    config = RELATION_TYPES[relation]
    verified = _verified_pivots(a, b)
    if not verified:
        return None

    primary_name, pivot_strength = max(verified, key=lambda item: item[1])
    identity_backed = primary_name in IDENTITY_PIVOTS

    window_s, tau_s = config["window_s"], config["tau_s"]
    if identity_backed:
        window_s = max(window_s, LIFECYCLE_WINDOW_S)
        tau_s = max(tau_s, LIFECYCLE_TAU_S)

    ts_a, ts_b = parse_timestamp(a["timestamp"]), parse_timestamp(b["timestamp"])
    delta_s = None
    if ts_a and ts_b:
        delta_s = abs((ts_a - ts_b).total_seconds())
        if delta_s > window_s:
            return None
        temporal = math.exp(-delta_s / tau_s)
    else:
        temporal = 0.5

    host_a = a["host"]["id"] or a["host"]["name"]
    host_b = b["host"]["id"] or b["host"]["name"]
    same_host = None
    if host_a and host_b:
        same_host = host_a == host_b
    if config["host"] == "same" and same_host is False:
        return None
    host_consistency = 1.0 if same_host else 0.5

    user_a, user_b = a["user"]["name"], b["user"]["name"]
    if user_a and user_b:
        session_consistency = 1.0 if user_a == user_b else 0.0
    else:
        session_consistency = 0.5

    corroborators = max(0, len(verified) - 1) + _incidental_corroborators(a, b)
    corroboration = min(1.0, 0.5 * corroborators)

    confidence = (
        CONFIDENCE_WEIGHTS["pivot"] * pivot_strength
        + CONFIDENCE_WEIGHTS["time"] * temporal
        + CONFIDENCE_WEIGHTS["host"] * host_consistency
        + CONFIDENCE_WEIGHTS["session"] * session_consistency
        + CONFIDENCE_WEIGHTS["corroboration"] * corroboration
    )

    if confidence >= STRONG_THRESHOLD:
        decision = "strong"
    elif confidence >= SUPPORTED_THRESHOLD and corroborators >= 1:
        decision = "supported"
    elif confidence >= CANDIDATE_THRESHOLD:
        decision = "candidate"
    else:
        return None

    evidence = [
        f"primary={primary_name} (P={pivot_strength:.2f})",
        f"temporal={temporal:.3f}" + (f" (dt={delta_s:.0f}s)" if delta_s is not None else ""),
        f"host={host_consistency:.2f}",
        f"session={session_consistency:.2f}",
        f"corroborators={corroborators}",
    ]
    evidence.extend(f"also={name}" for name, _ in verified if name != primary_name)

    if relation == "SAME_BINARY" and same_host:
        # Same bytes on the same host is expected; this pivot exists to find
        # the same binary on OTHER endpoints, so it must not recurse here.
        expandable = False
    else:
        expandable = bool(config["expand"] and identity_backed and decision in ("strong", "supported"))

    edge = {
        "source": a["id"],
        "target": b["id"],
        "relation": relation,
        "confidence": round(confidence, 4),
        "weight": int(round(confidence * 100)),
        "delta_s": delta_s,
        "decision": decision,
        "identity_backed": identity_backed,
        "expand": expandable,
        "evidence": evidence,
    }

    if relation == "PARENT_CHILD":
        if a["process"]["guid"] and a["process"]["guid"] == b["process"]["parent"]["guid"]:
            edge["parent_id"], edge["child_id"] = a["id"], b["id"]
        else:
            edge["parent_id"], edge["child_id"] = b["id"], a["id"]

    return edge


# ── In-memory graph (mock data, dashboard, webhook batch) ────────
def build_correlation_graph(alerts: list, min_confidence: float = CANDIDATE_THRESHOLD) -> nx.Graph:
    """Build a NetworkX graph where edges are typed, validated relationships."""
    graph = nx.Graph()

    normalized = [normalize_alert(alert) for alert in alerts]
    for norm in normalized:
        graph.add_node(norm["id"], alert=norm["raw"], norm=norm)

    for i in range(len(normalized)):
        for j in range(i + 1, len(normalized)):
            edge = classify_pair(normalized[i], normalized[j])
            if edge is None or edge["confidence"] < min_confidence:
                continue
            graph.add_edge(
                normalized[i]["id"],
                normalized[j]["id"],
                **{k: v for k, v in edge.items() if k not in ("source", "target")},
            )

    return graph


def _summary(norm: dict) -> str:
    process = norm["process"]
    return (
        process["executable"]
        or process["command_line"]
        or (norm["rule"] or {}).get("description")
        or norm["event"]["id"]
    )


def bfs_timeline(graph: nx.Graph, seed_id: str, max_depth: int = 3) -> list:
    """Bounded BFS: weak edges provide context but are never traversed."""
    if seed_id not in graph:
        return []

    visited = {seed_id}
    queue = deque([(seed_id, 0)])
    ordered = [seed_id]

    while queue:
        node_id, depth = queue.popleft()
        if depth >= max_depth:
            continue
        identity_neighbors = []
        context_neighbors = []
        for neighbor in graph.neighbors(node_id):
            edge = graph.get_edge_data(node_id, neighbor) or {}
            (identity_neighbors if edge.get("expand") else context_neighbors).append((edge, neighbor))
        identity_neighbors.sort(key=lambda item: item[0].get("confidence", 0.0), reverse=True)
        context_neighbors.sort(key=lambda item: item[0].get("confidence", 0.0), reverse=True)
        for edge, neighbor in identity_neighbors + context_neighbors[:MAX_CONTEXT_LEAVES_PER_NODE]:
            if neighbor not in visited and len(visited) >= MAX_CASE_NODES:
                break
            if neighbor not in visited:
                visited.add(neighbor)
                ordered.append(neighbor)
                if edge.get("expand"):
                    queue.append((neighbor, depth + 1))

    result = [{"id": node_id, "timestamp": graph.nodes[node_id]["alert"].get("@timestamp", "")} for node_id in ordered]
    result.sort(key=lambda item: item["timestamp"])
    return result


def build_timeline_with_edges(graph: nx.Graph, seed_id: str, max_depth: int = 3) -> dict:
    """Timeline response: ordered nodes plus the typed edges that link them."""
    if seed_id not in graph:
        return {"nodes": [], "edges": []}

    visited = {seed_id}
    queue = deque([(seed_id, 0)])
    node_ids = {seed_id}
    edges = {}

    while queue:
        node_id, depth = queue.popleft()
        identity_neighbors = []
        context_neighbors = []
        for neighbor in graph.neighbors(node_id):
            data = graph.get_edge_data(node_id, neighbor) or {}
            (identity_neighbors if data.get("expand") else context_neighbors).append((data, neighbor))
        identity_neighbors.sort(key=lambda item: item[0].get("confidence", 0.0), reverse=True)
        context_neighbors.sort(key=lambda item: item[0].get("confidence", 0.0), reverse=True)
        for data, neighbor in identity_neighbors + context_neighbors[:MAX_CONTEXT_LEAVES_PER_NODE]:
            if neighbor not in visited and len(visited) >= MAX_CASE_NODES:
                break
            key = tuple(sorted((node_id, neighbor)))
            if key not in edges:
                edge_output = {
                    "source": node_id,
                    "target": neighbor,
                    "weight": data.get("weight"),
                    "relation": data.get("relation"),
                    "confidence": data.get("confidence"),
                    "decision": data.get("decision"),
                    "delta_s": data.get("delta_s"),
                    "identity_backed": data.get("identity_backed"),
                    "expand": data.get("expand"),
                    "occurrences": data.get("occurrences", 1),
                }
                for attribute in ("parent_id", "child_id"):
                    if data.get(attribute):
                        edge_output[attribute] = data[attribute]
                edges[key] = edge_output
            if neighbor not in visited:
                visited.add(neighbor)
                node_ids.add(neighbor)
                if depth + 1 < max_depth and data.get("expand"):
                    queue.append((neighbor, depth + 1))

    nodes = []
    for node_id in node_ids:
        norm = graph.nodes[node_id]["norm"]
        nodes.append({
            "id": node_id,
            "timestamp": norm["timestamp"] or "",
            "agent": norm["host"]["name"],
            "mitre": norm["mitre"] or {},
            "rule": norm["rule"] or {},
            "scoring": norm["scoring"] or {},
            "event_id": norm["event"]["id"],
            "user": norm["user"]["name"],
            "process": norm["process"]["name"],
            "summary": _summary(norm),
        })

    nodes.sort(key=lambda item: item["timestamp"])
    return {"nodes": nodes, "edges": list(edges.values())}


# ── Bounded live expansion over the Wazuh Indexer ────────────────
def _fact_key(relation: str, candidate: dict):
    """Collapse repeated evidence into one context fact with occurrences.

    Ten executions of the same binary / ten network records for the same
    destination must not become ten case nodes.
    """
    if relation == "SAME_BINARY":
        sha256 = candidate["file"]["hash"].get("sha256")
        return (relation, sha256, candidate["host"]["name"], candidate["process"]["executable"])
    if relation in ("DESTINATION_SHARED", "SUPPORTING_CONTEXT"):
        return (
            relation,
            candidate["host"]["name"],
            candidate["user"]["name"],
            candidate["process"]["name"],
            candidate["destination"]["ip"],
        )
    return (relation, candidate["id"])


def expand_case(
    seed_raw: dict,
    search_fn,
    max_depth: int = 3,
    max_nodes: int = 200,
    min_confidence: float = CANDIDATE_THRESHOLD,
    max_candidates_per_pivot: int = 300,
) -> dict:
    """Bounded graph expansion: seed -> pivots -> candidates -> typed edges.

    ``search_fn(pivot)`` must return raw Wazuh events for a pivot that carries
    ``field``, ``value``, ``time_from``, ``time_to`` and optional ``agent_name``.

    Repeated evidence of the same fact is aggregated (occurrence count) instead
    of being added as duplicate nodes/edges.
    """
    seed = normalize_alert(seed_raw)
    nodes = {seed["id"]: seed}
    edges = {}
    facts = {}
    queue = deque([(seed["id"], 0)])
    expanded = set()
    stats = {
        "searches": 0,
        "candidates": 0,
        "by_relation": {},
        "aggregated": 0,
        "aggregated_provenance_truncated": False,
        "candidate_results_truncated": 0,
        "errors": [],
        "truncated": False,
    }

    while queue and len(nodes) < max_nodes:
        node_id, depth = queue.popleft()
        if node_id in expanded:
            continue
        expanded.add(node_id)

        current = nodes[node_id]
        if depth >= max_depth:
            continue

        for pivot in extract_pivots(current):
            if len(nodes) >= max_nodes:
                stats["truncated"] = True
                break
            anchor = parse_timestamp(current["timestamp"]) or datetime.now(timezone.utc)
            window_s = pivot["window_s"]
            search_pivot = {
                **pivot,
                "time_from": anchor - timedelta(seconds=window_s),
                "time_to": anchor + timedelta(seconds=window_s),
                "agent_id": current["host"]["id"] if pivot["host_scoped"] else None,
                "agent_name": (
                    current["host"]["name"]
                    if pivot["host_scoped"] and not current["host"]["id"]
                    else None
                ),
            }
            try:
                candidates = search_fn(search_pivot) or []
            except Exception as exc:
                stats["errors"].append(f"{pivot['name']}: {type(exc).__name__}: {exc}")
                continue

            stats["searches"] += 1
            if len(candidates) > max_candidates_per_pivot:
                stats["candidate_results_truncated"] += len(candidates) - max_candidates_per_pivot
                stats["truncated"] = True
            for raw in candidates[:max_candidates_per_pivot]:
                stats["candidates"] += 1
                candidate = normalize_alert(raw)
                if candidate["id"] == current["id"]:
                    continue

                edge = classify_pair(current, candidate)
                if edge is None or edge["confidence"] < min_confidence:
                    continue
                edge["source"], edge["target"] = node_id, candidate["id"]

                key = tuple(sorted((edge["source"], edge["target"])))
                if key in edges:
                    continue

                if candidate["id"] in nodes:
                    edges[key] = edge
                    stats["by_relation"][edge["relation"]] = stats["by_relation"].get(edge["relation"], 0) + 1
                    continue

                fact = _fact_key(edge["relation"], candidate)
                if fact in facts:
                    fact_state = facts[fact]
                    fact_state["occurrences"] += 1
                    representative = edges[fact_state["edge_key"]]
                    representative["occurrences"] = fact_state["occurrences"]
                    if len(fact_state["aggregated_events"]) < MAX_AGGREGATED_EVENTS_PER_FACT:
                        fact_state["aggregated_events"].append(candidate["id"])
                        representative.setdefault("aggregated_events", []).append({
                            "node": candidate,
                            "edge": edge,
                        })
                    else:
                        stats["aggregated_provenance_truncated"] = True
                    stats["aggregated"] += 1
                    continue

                facts[fact] = {
                    "occurrences": 1,
                    "edge_key": key,
                    "aggregated_events": [],
                }
                edge["occurrences"] = 1
                edges[key] = edge
                stats["by_relation"][edge["relation"]] = stats["by_relation"].get(edge["relation"], 0) + 1

                nodes[candidate["id"]] = candidate
                if edge["expand"] and depth + 1 < max_depth:
                    queue.append((candidate["id"], depth + 1))
                if len(nodes) >= max_nodes:
                    stats["truncated"] = True
                    break

    stats["nodes"] = len(nodes)
    stats["edges"] = len(edges)
    return {
        "seed": seed,
        "nodes": list(nodes.values()),
        "edges": list(edges.values()),
        "stats": stats,
    }
