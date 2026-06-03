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
from correlation import build_correlation_graph, build_timeline_with_edges

USE_LIVE = os.getenv("USE_LIVE_WAZUH", "false").lower() == "true"

if USE_LIVE:
    from wazuh_client import query_alerts, query_related_events, extract_entities
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


def _init_mock():
    global SCORED_ALERTS, GRAPH
    SCORED_ALERTS = score_alerts(MOCK_ALERTS)
    GRAPH = build_correlation_graph(SCORED_ALERTS)


def _rebuild_graph():
    global GRAPH
    GRAPH = build_correlation_graph(SCORED_ALERTS)


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

    # 2. Extract entities & find related events
    entities = extract_entities(alert)
    related_raw = query_related_events(entities)

    # 3. Score related events
    scored_related = score_alerts(related_raw) if related_raw else []

    # 4. Merge into in-memory store (deduplicate by _id)
    global SCORED_ALERTS
    seen_ids = {a.get("_id") for a in SCORED_ALERTS}
    for a in [scored_alert] + scored_related:
        if a.get("_id") not in seen_ids:
            SCORED_ALERTS.append(a)
            seen_ids.add(a.get("_id"))

    _rebuild_graph()

    return {
        "status": "processed",
        "seed_alert_id": scored_alert.get("_id"),
        "seed_score": scored_alert.get("scoring", {}).get("total_score"),
        "seed_level": scored_alert.get("scoring", {}).get("level"),
        "related_events_found": len(scored_related),
    }


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "mode": "live" if USE_LIVE else "mock",
        "alerts_count": len(SCORED_ALERTS),
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
