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
    _rebuild_graph()

print('Loading log...')
try:
    load_source()
except Exception as exc:  # noqa: BLE001 - keep serving with the mock source
    print(exc)
print('Finished loading log...')

group_by_mitre = {
    'T1059.001': None,
    'T1059.003': None,
    'T1105': None
}

for alert in SCORED_ALERTS:
    cases = CASES.get(alert.get('_id'))

    mitre = alert.get('mitre').get('technique')
    s_alert = alert.get('scoring').get('total_score')
    s_seed = alert.get('seed_scoring').get('total_score')
    s_case = cases.get('case_score')

    d_s = ((s_case / 100) - (s_seed / 87.5)) * 100

    if mitre not in group_by_mitre or group_by_mitre[mitre] == None:
        group_by_mitre[mitre] = {
            'd_s': [],
            's_alert': [],
            's_seed': [],
            's_case': [],
        }

    group = group_by_mitre[mitre]
    group['d_s'].append(d_s)
    group['s_alert'].append(s_alert)
    group['s_seed'].append(s_seed)
    group['s_case'].append(s_case)


border = f"+{'-'*20}+{'-'*5}+{'-'*12}+{'-'*11}+{'-'*11}+{'-'*10}+{'-'*12}+"

print()
print(border)
print(
    f"| {'MITRE':<18} "
    f"| {'N':>3} "
    f"| {'Mean Alert':>8} "
    f"| {'Mean Seed':>8} "
    f"| {'Mean Case':>8} "
    f"| {'Mean Δ':>8} "
    f"| {'Changed':>10} |"
)
print(f"| {'-'*18} | {'-'*3} | {'-'*10} | {'-'*9} | {'-'*9} | {'-'*8} | {'-'*10} |")

for key, value in group_by_mitre.items():
    n = len(value['d_s'])

    mean_alert = sum(value['s_alert']) / n
    mean_seed = sum(value['s_seed']) / n
    mean_case = sum(value['s_case']) / n
    mean_delta = sum(value['d_s']) / n

    changed = sum(v > 0.0 for v in value['d_s'])
    ratio = f'{changed} / {n}'

    print(
        f"| {key:<18} "
        f"| {n:>3} "
        f"| {mean_alert:>10.2f} "
        f"| {mean_seed:>9.2f} "
        f"| {mean_case:>9.2f} "
        f"| {mean_delta:>8.2f} "
        f"| {ratio:>10} |"
    )

print(border)




# import argparse
# import csv
# import json
# import re
# import urllib.request
# from collections import defaultdict
# from datetime import datetime, timezone
# from pathlib import Path

# TECHNIQUES = ("T1059.001", "T1059.003", "T1105")

# NOTE_RE = re.compile(r"(?P<key>variation|rep|step|status|EID3)=([^|]+)")

# # def parse_iso(value: str) -> datetime:
# #     return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
# def parse_iso(value: str) -> datetime:
#     value = value.replace("Z", "+00:00")

#     # Convert +0000 into +00:00
#     value = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", value)

#     return datetime.fromisoformat(value).astimezone(timezone.utc)

# def parse_notes(notes: str) -> dict:
#     out = {}
#     for key, val in NOTE_RE.findall(notes or ""):
#         out[key.strip()] = val.strip()
#     return out

# def load_runs(path: Path) -> list[dict]:
#     runs = []
#     with path.open(encoding="utf-8-sig", newline="") as handle:
#         for row in csv.DictReader(handle):
#             if row.get("condition") not in ("A", "B"):
#                 continue
#             notes = parse_notes(row.get("notes", ""))
#             if "variation" not in notes:
#                 # Legacy pilot rows from before the 9-variation plan.
#                 continue
#             runs.append({
#                 "run_id": row["run_id"],
#                 "technique": row["technique"],
#                 "condition": row["condition"],
#                 "atomic_test": row["atomic_test"],
#                 "start": parse_iso(row["start_utc"]),
#                 "end": parse_iso(row["end_utc"]),
#                 "variation": notes.get("variation", "?"),
#                 "status": notes.get("status", "?"),
#                 "eid3": notes.get("EID3", "?"),
#                 'notes': notes
#             })
#     return runs

# def in_window(alert: dict, start: datetime, end: datetime, pad_start=5, pad_end=20) -> bool:
#     ts = alert.get("timestamp")
#     if not ts:
#         return False
#     try:
#         dt = parse_iso(ts)
#     except ValueError:
#         return False
#     return (start.timestamp() - pad_start) <= dt.timestamp() <= (end.timestamp() + pad_end)

# runs = load_runs(Path(r"C:/Users/Acer/Downloads/runs.csv"))
# not_found = []

# mitres = {}

# for run in runs:
#     found = False
#     for alert in SCORED_ALERTS:
#         if in_window(alert, run['start'], run['end']):
#             found = True
#             mitre = alert.get('mitre').get('technique')

#             if mitre not in TECHNIQUES:
#                 continue

#             if mitre not in mitres:
#                 mitres[mitre] = 0

#             mitres[mitre] += 1

#     if not found:
#         not_found.append((run['run_id'], run['technique'], run['start'], run['notes']))
            
# sum = 0
# for k, v in mitres.items():
#     print(f'{k}: {v}')
#     sum += v

# print(f'Total: {sum}')
# print()
# print(f'Not Found')
# for i, (run_id, technique, start, guid) in enumerate(not_found):
#     print(f'{i+1}. {run_id} | {technique} | {start} | {guid}')