import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

from dotenv import load_dotenv

load_dotenv()

from scoring import score_alerts, score_seed
from alert_quality import classify_known_benign, exclude_known_benign
from correlation import (
    build_correlation_graph,
    build_timeline_from_case,
    build_timeline_with_edges,
    expand_case,
)
from case_scoring import score_graph_case, score_expansion_case
from normalizer import normalize_alert
from technique_profiles import TECHNIQUE_PROFILES

LIVE_HOURS_BACK = int(os.getenv("LIVE_HOURS_BACK", "48"))
LIVE_FROM = os.getenv("LIVE_FROM") or None
LIVE_TO = os.getenv("LIVE_TO") or None
LIVE_ALERT_LIMIT = int(os.getenv("LIVE_ALERT_LIMIT", "100"))
LIVE_ALERT_FETCH_LIMIT = int(os.getenv("LIVE_ALERT_FETCH_LIMIT", "5000"))
SEED_MIN_LEVEL = int(os.getenv("SEED_MIN_LEVEL", "15"))

def _prepare_live_alert(raw: dict) -> dict:
    """Make a Wazuh alert usable by the dashboard (id + technique fields)."""
    alert = dict(raw)
    if not alert.get("_id"):
        alert["_id"] = normalize_alert(alert)["id"]
    current_mitre = alert.get("mitre") or {}
    current_technique = current_mitre.get("technique")
    if current_technique not in TECHNIQUE_PROFILES:
        rule_mitre = (alert.get("rule") or {}).get("mitre") or {}
        ids = rule_mitre.get("id") or []
        if isinstance(ids, str):
            ids = [ids]
        if ids:
            tactics = rule_mitre.get("tactic") or []
            if isinstance(tactics, str):
                tactics = [tactics]
            normalized_ids = [str(item) for item in ids]
            technique = next(
                (item for item in normalized_ids if item in TECHNIQUE_PROFILES),
                current_technique or normalized_ids[0],
            )
            alert["mitre"] = {
                **current_mitre,
                "technique": technique,
                "tactic": current_mitre.get("tactic") or (tactics[0] if tactics else None),
                "name": current_mitre.get("name") or technique,
            }
    return alert

def _load_live() -> list:
    global LIVE_DATA_QUALITY
    from wazuh_client import query_alerts

    raw_alerts = query_alerts(
        min_level=SEED_MIN_LEVEL,
        hours_back=LIVE_HOURS_BACK,
        size=LIVE_ALERT_FETCH_LIMIT,
        time_from=LIVE_FROM,
        time_to=LIVE_TO,
    )
    eligible_alerts, excluded_by_reason = exclude_known_benign(raw_alerts)
    selected_alerts = eligible_alerts[:LIVE_ALERT_LIMIT]
    LIVE_DATA_QUALITY = {
        "raw_candidates_count": len(raw_alerts),
        "excluded_known_benign_count": sum(excluded_by_reason.values()),
        "excluded_by_reason": excluded_by_reason,
        "omitted_due_to_display_limit": max(0, len(eligible_alerts) - len(selected_alerts)),
        "query_capped": len(raw_alerts) >= LIVE_ALERT_FETCH_LIMIT,
        "window_from": LIVE_FROM,
        "window_to": LIVE_TO,
    }

    alerts = score_alerts([_prepare_live_alert(item) for item in selected_alerts])
    return score_seed([alert for alert in alerts])

SCORED_ALERTS: list = []
GRAPH = None
CASES: dict = {}
CASE_DATA: dict = {}
LAST_ERROR: str | None = None
LIVE_DATA_QUALITY = {
    "raw_candidates_count": 0,
    "excluded_known_benign_count": 0,
    "excluded_by_reason": {},
    "omitted_due_to_display_limit": 0,
    "query_capped": False,
}

def _build_live_case(alert: dict):
    """Expand one seed into alerts + archives and score the resulting case."""
    from wazuh_client import search_pivot

    expansion = expand_case(
        alert,
        search_pivot,
        max_candidates_per_pivot=40,
        max_nodes=100,
    )
    return score_expansion_case(expansion), expansion

def _rebuild_cases():
    CASES.clear()
    CASE_DATA.clear()

    with ThreadPoolExecutor(max_workers=16) as pool:
        futures = {pool.submit(_build_live_case, alert): alert for alert in SCORED_ALERTS}
        for future in as_completed(futures):
            alert = futures[future]
            seed_id = alert.get("_id")
            try:
                case, expansion = future.result()
            except Exception as exc:  # noqa: BLE001 - fall back to graph case
                if seed_id in GRAPH:
                    CASES[seed_id] = score_graph_case(GRAPH, seed_id)
                continue
            CASES[case["case_id"]] = case
            CASE_DATA[case["case_id"]] = expansion

def _rebuild_graph():
    global GRAPH
    GRAPH = build_correlation_graph(SCORED_ALERTS)
    _rebuild_cases()

def load_source(
    seed_min_level: int | None = None,
    live_from: str | None = None,
    live_to: str | None = None,
) -> dict:
    """Load a data source into the in-memory store (alerts, graph, cases)."""
    global SCORED_ALERTS, LAST_ERROR, SEED_MIN_LEVEL, LIVE_DATA_QUALITY
    global LIVE_FROM, LIVE_TO

    if seed_min_level is not None:
        SEED_MIN_LEVEL = max(0, min(15, int(seed_min_level)))
    if live_from is not None:
        LIVE_FROM = live_from or None
    if live_to is not None:
        LIVE_TO = live_to or None

    alerts = _load_live()

    SCORED_ALERTS = alerts
    LAST_ERROR = None
    _rebuild_graph()

try:
    load_source()
except Exception as exc:  # noqa: BLE001 - keep serving with the mock source
    print(exc)

group_by_mitre = {}
for alert in SCORED_ALERTS:
    cases = CASES.get(alert.get('_id'))

    mitre = alert.get('mitre').get('technique')
    s_alert = alert.get('scoring').get('total_score')
    s_seed = alert.get('seed_scoring').get('total_score')
    s_case = cases.get('case_score')
    d_s = (s_case - s_seed) - (s_alert - s_seed)

    if mitre in group_by_mitre:
        group_by_mitre[mitre].append(d_s)
    else:
        group_by_mitre[mitre] = [d_s]

border = f"+{'-'*22}+{'-'*7}+{'-'*10}+{'-'*12}+"
print()
print(border)
print(f"| {'MITRE':<20} | {'N':>5} | {'Mean':>8} | {'Changed':>10} |")
print(f"| {'-'*20} | {'-'*5} | {'-'*8} | {'-'*10} |")
for key, value in group_by_mitre.items():
    n = len(value)
    mean = sum(value) / n
    changed = sum(v > 0.0 for v in value)
    ratio = f'{changed} / {n}'

    print(f'| {key:<20} | {n:>5} | {mean:>8.2f} | {ratio:>10} |')
print(border)