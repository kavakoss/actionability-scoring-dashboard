"""FastAPI Backend for Actionability Scoring & Timeline Dashboard.

Data sources, switchable at runtime through the API/UI:
  MOCK — deterministic fixtures from mock_data.py (no Wazuh required)
  LIVE — recent alerts pulled from the Wazuh Indexer via wazuh_client.py

Endpoints:
  GET  /api/source              current source + config (same payload as /api/health)
  POST /api/source {source}     switch source; reloads alerts, graph and cases

The Wazuh integration webhook (POST /api/webhook) scores the incoming alert,
performs a bounded expansion over the Wazuh Indexer and stores the case.
"""

import logging
import os

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from scoring import score_alerts
from correlation import build_correlation_graph, build_timeline_with_edges, expand_case
from case_scoring import score_graph_case, score_expansion_case
from normalizer import normalize_alert

logger = logging.getLogger("actionability")

DEFAULT_SOURCE = "live" if os.getenv("USE_LIVE_WAZUH", "false").lower() == "true" else "mock"
LIVE_HOURS_BACK = int(os.getenv("LIVE_HOURS_BACK", "48"))
LIVE_ALERT_LIMIT = int(os.getenv("LIVE_ALERT_LIMIT", "100"))

app = FastAPI(title="Actionability Scoring Dashboard API", version="0.3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── In-memory store ──────────────────────────────────────────────
SOURCE = "mock"
SCORED_ALERTS: list = []
GRAPH = None
CASES: dict = {}
LAST_ERROR: str | None = None


class SourceRequest(BaseModel):
    source: str


def _prepare_live_alert(raw: dict) -> dict:
    """Make a Wazuh alert usable by the dashboard (id + technique fields)."""
    alert = dict(raw)
    if not alert.get("_id"):
        alert["_id"] = normalize_alert(alert)["id"]
    if not alert.get("mitre"):
        rule_mitre = (alert.get("rule") or {}).get("mitre") or {}
        ids = rule_mitre.get("id") or []
        if isinstance(ids, str):
            ids = [ids]
        if ids:
            tactics = rule_mitre.get("tactic") or []
            alert["mitre"] = {
                "technique": ids[0],
                "tactic": tactics[0] if tactics else None,
                "name": ids[0],
            }
    return alert


def _load_mock() -> list:
    from mock_data import MOCK_ALERTS

    return score_alerts(MOCK_ALERTS)


def _load_live() -> list:
    from wazuh_client import query_alerts

    raw_alerts = query_alerts(hours_back=LIVE_HOURS_BACK, size=LIVE_ALERT_LIMIT)
    return score_alerts([_prepare_live_alert(item) for item in raw_alerts])


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


def health() -> dict:
    return {
        "status": "ok",
        "mode": SOURCE,
        "source": SOURCE,
        "available_sources": ["mock", "live"],
        "alerts_count": len(SCORED_ALERTS),
        "cases_count": len(CASES),
        "last_error": LAST_ERROR,
        "config": {
            "live_hours_back": LIVE_HOURS_BACK,
            "live_alert_limit": LIVE_ALERT_LIMIT,
        },
    }


def load_source(source: str) -> dict:
    """Load a data source into the in-memory store (alerts, graph, cases)."""
    global SOURCE, SCORED_ALERTS, LAST_ERROR
    if source not in ("mock", "live"):
        raise ValueError(f"unknown source '{source}'")

    alerts = _load_live() if source == "live" else _load_mock()

    SOURCE = source
    SCORED_ALERTS = alerts
    LAST_ERROR = None
    _rebuild_graph()
    return health()


# ── Startup ──────────────────────────────────────────────────────
try:
    load_source(DEFAULT_SOURCE)
except Exception as exc:  # noqa: BLE001 - keep serving with the mock source
    logger.warning("failed to load '%s' (%s); falling back to mock", DEFAULT_SOURCE, exc)
    load_source("mock")
    LAST_ERROR = f"{DEFAULT_SOURCE}: {exc}"


# ── Source switching ─────────────────────────────────────────────
@app.get("/api/source")
def get_source():
    return health()


@app.post("/api/source")
def set_source(request: SourceRequest):
    try:
        return load_source(request.source)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"failed to load '{request.source}': {exc}")


# ── Webhook: Wazuh Integration ───────────────────────────────────
@app.post("/api/webhook")
async def wazuh_webhook(request: Request):
    """Receive an alert from the Wazuh Manager integration."""
    if SOURCE != "live":
        return {
            "status": "mock_mode",
            "message": "Switch the data source to 'live' to enable webhook processing",
        }

    from wazuh_client import search_pivot

    alert = await request.json()
    alert.setdefault("_id", normalize_alert(alert)["id"])

    [scored_alert] = score_alerts([alert])

    expansion = expand_case(alert, search_pivot)
    case = score_expansion_case(expansion)

    seen_ids = {a.get("_id") for a in SCORED_ALERTS}
    for node in expansion["nodes"]:
        raw = node.get("raw") or {}
        raw_id = raw.get("_id") or node["id"]
        if raw_id and raw_id not in seen_ids:
            SCORED_ALERTS.append(score_alerts([{**raw, "_id": raw_id}])[0])
            seen_ids.add(raw_id)

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


# ── Alerts ───────────────────────────────────────────────────────
@app.get("/api/health")
def health_endpoint():
    return health()


@app.get("/api/alerts")
def list_alerts(
    technique: str | None = Query(None, description="Filter by MITRE technique, e.g. T1059.001"),
    level: str | None = Query(None, description="Filter by actionability level: Low, Medium, High"),
    agent: str | None = Query(None, description="Filter by agent name"),
    sort_by: str = Query("timestamp", description="Sort field"),
):
    results = SCORED_ALERTS

    if technique:
        results = [a for a in results if (a.get("mitre") or {}).get("technique") == technique]
    if level:
        results = [a for a in results if (a.get("scoring") or {}).get("level") == level]
    if agent:
        results = [a for a in results if (a.get("agent") or {}).get("name") == agent]

    if sort_by == "score":
        results = sorted(results, key=lambda a: (a.get("scoring") or {}).get("total_score", 0), reverse=True)
    else:
        results = sorted(results, key=lambda a: a.get("@timestamp", ""), reverse=True)

    return {
        "total": len(results),
        "source": SOURCE,
        "alerts": [
            {
                "id": a.get("_id"),
                "timestamp": a.get("@timestamp"),
                "agent": (a.get("agent") or {}).get("name") or "unknown",
                "mitre": a.get("mitre") or {},
                "rule": a.get("rule") or {},
                "scoring": {
                    "total_score": (a.get("scoring") or {}).get("total_score"),
                    "level": (a.get("scoring") or {}).get("level"),
                    "percentage": (a.get("scoring") or {}).get("percentage"),
                },
            }
            for a in results
        ],
    }


@app.get("/api/alerts/{alert_id}")
def alert_detail(alert_id: str):
    alert = next((a for a in SCORED_ALERTS if a.get("_id") == alert_id), None)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    return {
        "id": alert.get("_id"),
        "timestamp": alert.get("@timestamp"),
        "agent": alert.get("agent") or {},
        "rule": alert.get("rule") or {},
        "mitre": alert.get("mitre") or {},
        "scoring": alert.get("scoring") or {},
        "raw": alert.get("data") or {},
    }


# ── Timeline + cases ─────────────────────────────────────────────
@app.get("/api/timeline/{alert_id}")
def timeline(alert_id: str):
    """Build the bounded attack timeline starting from a seed alert."""
    if alert_id not in GRAPH:
        raise HTTPException(status_code=404, detail="Alert not found in correlation graph")

    return build_timeline_with_edges(GRAPH, alert_id)


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
    return {"total": len(items), "source": SOURCE, "cases": items}


@app.get("/api/cases/{case_id}")
def case_detail(case_id: str):
    """Full case detail: score, required coverage and per-fact evidence."""
    case = CASES.get(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    seed = next((a for a in SCORED_ALERTS if a.get("_id") == case_id), None)
    return {
        "summary": _case_summary(case_id, case),
        "case": case,
        "seed_alert": {
            key: seed.get(key) for key in ("_id", "@timestamp", "agent", "rule", "mitre")
        } if seed else None,
    }


@app.get("/api/stats")
def stats():
    """Aggregate statistics for the dashboard overview."""
    levels = {"Low": 0, "Medium": 0, "High": 0}
    techniques = {}
    agents = {}

    for a in SCORED_ALERTS:
        scoring = a.get("scoring") or {}
        level = scoring.get("level")
        if level in levels:
            levels[level] += 1

        technique = (a.get("mitre") or {}).get("technique") or "Unknown"
        techniques.setdefault(technique, {"count": 0, "total_score": 0, "max_score": 0})
        techniques[technique]["count"] += 1
        techniques[technique]["total_score"] += scoring.get("total_score", 0)
        techniques[technique]["max_score"] += scoring.get("max_score", 0)

        agent = (a.get("agent") or {}).get("name") or "Unknown"
        agents[agent] = agents.get(agent, 0) + 1

    for data in techniques.values():
        data["avg_score"] = round(data["total_score"] / data["count"], 1) if data["count"] else 0
        data["avg_percentage"] = (
            round(data["total_score"] / data["max_score"] * 100, 1) if data["max_score"] else 0
        )

    return {
        "total_alerts": len(SCORED_ALERTS),
        "source": SOURCE,
        "by_level": levels,
        "by_technique": techniques,
        "by_agent": agents,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
