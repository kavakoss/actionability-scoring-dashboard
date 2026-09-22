"""FastAPI Backend for Actionability Scoring & Timeline Dashboard.

Serves as the API layer between React frontend and Wazuh Indexer (OpenSearch).

Two modes:
  MOCK  — uses mock_data.py (default, no Wazuh needed)
  LIVE  — queries Wazuh Indexer via wazuh_client.py
  Set USE_LIVE_WAZUH=true in .env to switch to live mode.

Wazuh Integration flow (live mode):
  1. Wazuh Manager fires alert → POST /api/webhook
  2. Backend extracts entities (processGuid, user, host, IP...)
  3. Backend queries Wazuh Indexer for related events via wazuh_client
  4. All events scored + correlation graph built
  5. Result stored in-memory, retrievable via /api/alerts / /api/timeline
"""

import os
from dotenv import load_dotenv

load_dotenv()  # Load .env if present

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware

from scoring import score_alerts, calculate_score
from correlation import build_correlation_graph, build_timeline_with_edges, expand_case
from case_scoring import score_graph_case, score_expansion_case

USE_LIVE = os.getenv("USE_LIVE_WAZUH", "false").lower() == "true"

if USE_LIVE:
    from wazuh_client import query_alerts, query_related_events, extract_entities, search_pivot
else:
    from mock_data import MOCK_ALERTS

app = FastAPI(title="Actionability Scoring Dashboard API", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── In-memory store ──────────────────────────────────────────────
SCORED_ALERTS: list = []
GRAPH = None
CASES: dict = {}


def _init_mock():
    global SCORED_ALERTS, GRAPH
    SCORED_ALERTS = score_alerts(MOCK_ALERTS)
    _rebuild_graph()


def _rebuild_graph():
    global GRAPH
    GRAPH = build_correlation_graph(SCORED_ALERTS)
    _rebuild_cases()


def _rebuild_cases():
    CASES.clear()
    for alert in SCORED_ALERTS:
        alert_id = alert["_id"]
        if alert_id in GRAPH:
            CASES[alert_id] = score_graph_case(GRAPH, alert_id)


def _case_summary(case_id: str, case: dict) -> dict:
    seed = next((a for a in SCORED_ALERTS if a["_id"] == case_id), None)
    return {
        "case_id": case_id,
        "technique": case["technique"],
        "profile_name": case["profile_name"],
        "case_score": case["case_score"],
        "level": case["level"],
        "required_coverage": case["required_coverage"],
        "nodes": case["nodes"],
        "edges": case["edges"],
        "seed": {
            "timestamp": seed.get("@timestamp") if seed else None,
            "agent": (seed.get("agent") or {}).get("name") if seed else None,
            "rule": seed.get("rule") if seed else None,
        },
    }


if not USE_LIVE:
    _init_mock()


# ── Webhook: Wazuh Integration ───────────────────────────────────
@app.post("/api/webhook")
async def wazuh_webhook(request: Request):
    """Receive alert from Wazuh Manager integration.

    Flow:
      1. Wazuh sends alert JSON → this endpoint
      2. Extract entities from alert
      3. Query Wazuh Indexer for related events
      4. Score all events + rebuild correlation graph
    """
    if not USE_LIVE:
        return {
            "status": "mock_mode",
            "message": "Set USE_LIVE_WAZUH=true in .env to enable live processing",
        }

    alert = await request.json()

    # 1. Score the incoming alert
    [scored_alert] = score_alerts([alert])

    # 2. Bounded typed-edge expansion over the Wazuh Indexer
    expansion = expand_case(alert, search_pivot)
    case = score_expansion_case(expansion)

    # 3. Merge expanded events into the in-memory store (deduplicate by id)
    global SCORED_ALERTS
    seen_ids = {a.get("_id") for a in SCORED_ALERTS}
    for node in expansion["nodes"]:
        raw = node.get("raw") or {}
        raw_id = raw.get("_id")
        if raw_id and raw_id not in seen_ids:
            SCORED_ALERTS.append(score_alerts([raw])[0])
            seen_ids.add(raw_id)
    if scored_alert.get("_id") and scored_alert["_id"] not in seen_ids:
        SCORED_ALERTS.append(scored_alert)
        seen_ids.add(scored_alert["_id"])

    _rebuild_graph()
    CASES[case["case_id"]] = case

    return {
        "status": "processed",
        "seed_alert_id": scored_alert.get("_id"),
        "seed_score": scored_alert.get("scoring", {}).get("total_score"),
        "seed_level": scored_alert.get("scoring", {}).get("level"),
        "related_events_found": len(expansion["nodes"]) - 1,
        "case_id": case["case_id"],
        "case_score": case["case_score"],
        "case_level": case["level"],
        "required_coverage": case["required_coverage"],
        "relations": expansion["stats"]["by_relation"],
    }


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "mode": "live" if USE_LIVE else "mock",
        "alerts_count": len(SCORED_ALERTS),
        "cases_count": len(CASES),
    }


@app.get("/api/alerts")
def list_alerts(
    technique: str | None = Query(None, description="Filter by MITRE technique, e.g. T1059.001"),
    level: str | None = Query(None, description="Filter by actionability level: Low, Medium, High"),
    agent: str | None = Query(None, description="Filter by agent name"),
    sort_by: str = Query("timestamp", description="Sort field"),
):
    results = SCORED_ALERTS

    if technique:
        results = [a for a in results if a.get("mitre", {}).get("technique") == technique]
    if level:
        results = [a for a in results if a.get("scoring", {}).get("level") == level]
    if agent:
        results = [a for a in results if a.get("agent", {}).get("name") == agent]

    if sort_by == "score":
        results = sorted(results, key=lambda a: a.get("scoring", {}).get("total_score", 0), reverse=True)
    else:
        results = sorted(results, key=lambda a: a.get("@timestamp", ""), reverse=True)

    return {
        "total": len(results),
        "alerts": [
            {
                "id": a["_id"],
                "timestamp": a["@timestamp"],
                "agent": a["agent"]["name"],
                "mitre": a["mitre"],
                "rule": a["rule"],
                "scoring": {
                    "total_score": a["scoring"]["total_score"],
                    "level": a["scoring"]["level"],
                    "percentage": a["scoring"]["percentage"],
                },
            }
            for a in results
        ],
    }


@app.get("/api/alerts/{alert_id}")
def alert_detail(alert_id: str):
    alert = next((a for a in SCORED_ALERTS if a["_id"] == alert_id), None)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    return {
        "id": alert["_id"],
        "timestamp": alert["@timestamp"],
        "agent": alert["agent"],
        "rule": alert["rule"],
        "mitre": alert["mitre"],
        "scoring": alert["scoring"],
        "raw": alert["data"],
    }


@app.get("/api/timeline/{alert_id}")
def timeline(alert_id: str):
    """Build attack timeline starting from a seed alert."""
    if alert_id not in GRAPH:
        raise HTTPException(status_code=404, detail="Alert not found in correlation graph")

    result = build_timeline_with_edges(GRAPH, alert_id)
    return result


@app.get("/api/cases")
def list_cases(
    technique: str | None = Query(None, description="Filter by MITRE technique"),
    level: str | None = Query(None, description="Filter by case level: Low, Medium, High"),
):
    """List correlated cases with their aggregated actionability score."""
    items = []
    for case_id, case in CASES.items():
        if technique and case["technique"] != technique:
            continue
        if level and case["level"] != level:
            continue
        items.append(_case_summary(case_id, case))
    items.sort(key=lambda item: item["case_score"], reverse=True)
    return {"total": len(items), "cases": items}


@app.get("/api/cases/{case_id}")
def case_detail(case_id: str):
    """Full case detail: score, required coverage and per-fact evidence."""
    case = CASES.get(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    seed = next((a for a in SCORED_ALERTS if a["_id"] == case_id), None)
    return {
        "summary": _case_summary(case_id, case),
        "case": case,
        "seed_alert": {
            key: seed.get(key) for key in ("_id", "@timestamp", "agent", "rule", "mitre")
        } if seed else None,
    }


@app.get("/api/stats")
def stats():
    """Aggregate statistics for dashboard overview."""
    levels = {"Low": 0, "Medium": 0, "High": 0}
    techniques = {}
    agents = {}

    for a in SCORED_ALERTS:
        lvl = a["scoring"]["level"]
        levels[lvl] = levels.get(lvl, 0) + 1

        tech = a.get("mitre", {}).get("technique", "Unknown")
        if tech not in techniques:
            techniques[tech] = {"count": 0, "total_score": 0, "max_score": 0}
        techniques[tech]["count"] += 1
        techniques[tech]["total_score"] += a["scoring"]["total_score"]
        techniques[tech]["max_score"] += a["scoring"]["max_score"]

        ag = a.get("agent", {}).get("name", "Unknown")
        agents[ag] = agents.get(ag, 0) + 1

    # Average scores per technique
    for tech in techniques:
        t = techniques[tech]
        t["avg_score"] = round(t["total_score"] / t["count"], 1) if t["count"] > 0 else 0
        t["avg_percentage"] = round(t["total_score"] / t["max_score"] * 100, 1) if t["max_score"] > 0 else 0

    return {
        "total_alerts": len(SCORED_ALERTS),
        "by_level": levels,
        "by_technique": techniques,
        "by_agent": agents,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
