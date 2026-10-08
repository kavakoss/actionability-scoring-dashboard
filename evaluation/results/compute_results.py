#!/usr/bin/env python3
"""Compute per-variation evaluation results for the thesis.

Combines the ART run log (runs.csv) with the seed alerts and actionability
scores served by the dashboard API (which must be switched to the same
explicit time window as the runs).

Usage:
    python compute_results.py \
        --runs /path/to/runs.csv \
        --api http://127.0.0.1:8000 \
        --out-dir .

Outputs:
    variation_results.csv   machine-readable table
    variation_results.md    human-readable summary (paste into the thesis)
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

TECHNIQUES = ("T1059.001", "T1059.003", "T1105")

NOTE_RE = re.compile(r"(?P<key>variation|rep|step|status|EID3)=([^|]+)")


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def parse_notes(notes: str) -> dict:
    out = {}
    for key, val in NOTE_RE.findall(notes or ""):
        out[key.strip()] = val.strip()
    return out


def load_runs(path: Path) -> list[dict]:
    runs = []
    with path.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            if row.get("condition") not in ("A", "B"):
                continue
            notes = parse_notes(row.get("notes", ""))
            if "variation" not in notes:
                # Legacy pilot rows from before the 9-variation plan.
                continue
            runs.append({
                "technique": row["technique"],
                "condition": row["condition"],
                "atomic_test": row["atomic_test"],
                "start": parse_iso(row["start_utc"]),
                "end": parse_iso(row["end_utc"]),
                "variation": notes.get("variation", "?"),
                "status": notes.get("status", "?"),
                "eid3": notes.get("EID3", "?"),
            })
    return runs


def fetch_alerts(api: str) -> list[dict]:
    with urllib.request.urlopen(f"{api}/api/alerts?sort_by=score", timeout=30) as resp:
        return json.load(resp).get("alerts", [])


def fetch_cases(api: str) -> list[dict]:
    with urllib.request.urlopen(f"{api}/api/cases", timeout=60) as resp:
        return json.load(resp).get("cases", [])


def in_window(alert: dict, start: datetime, end: datetime, pad_start=5, pad_end=20) -> bool:
    ts = alert.get("timestamp")
    if not ts:
        return False
    try:
        dt = parse_iso(ts)
    except ValueError:
        return False
    return (start.timestamp() - pad_start) <= dt.timestamp() <= (end.timestamp() + pad_end)


def aggregate(runs: list[dict], alerts: list[dict]) -> list[dict]:
    groups: dict[tuple, dict] = defaultdict(lambda: {
        "runs": 0, "success": 0, "failed": 0, "skipped": 0,
        "detected": 0, "scores": [],
    })

    for run in runs:
        key = (run["technique"], run["condition"], run["variation"])
        bucket = groups[key]
        bucket["runs"] += 1
        status = run["status"].upper()
        if status == "SUCCESS":
            bucket["success"] += 1
        elif status == "SKIPPED":
            bucket["skipped"] += 1
        else:
            bucket["failed"] += 1

        hits = [a for a in alerts if in_window(a, run["start"], run["end"])]
        if hits:
            bucket["detected"] += 1
            bucket["scores"].extend(
                (a.get("scoring") or {}).get("total_score")
                for a in hits
                if (a.get("scoring") or {}).get("total_score") is not None
            )

    rows = []
    for (technique, condition, variation), data in sorted(groups.items()):
        scores = data["scores"]
        rows.append({
            "technique": technique,
            "condition": condition,
            "variation": variation,
            "runs": data["runs"],
            "success": data["success"],
            "failed": data["failed"],
            "skipped": data["skipped"],
            "detected_runs": f"{data['detected']}/{data['runs']}",
            "detection_rate": round(100 * data["detected"] / data["runs"], 1) if data["runs"] else 0.0,
            "mean_actionability": round(sum(scores) / len(scores), 1) if scores else "",
            "scored_alerts": len(scores),
            "eid3": sorted({r["eid3"] for r in runs
                            if (r["technique"], r["condition"], r["variation"]) == (technique, condition, variation)}),
        })
    return rows


def sensitivity(runs: list[dict], alerts: list[dict], atomic_test: str) -> list[dict]:
    """Same atomic test, Condition A vs B: does actionability drop without EID3?"""
    rows = []
    for condition in ("A", "B"):
        selected = [r for r in runs if r["atomic_test"] == atomic_test and r["condition"] == condition]
        scores = []
        for run in selected:
            for alert in alerts:
                if in_window(alert, run["start"], run["end"]):
                    score = (alert.get("scoring") or {}).get("total_score")
                    if score is not None:
                        scores.append(score)
        rows.append({
            "atomic_test": atomic_test,
            "condition": condition,
            "runs": len(selected),
            "scored_alerts": len(scores),
            "mean_actionability": round(sum(scores) / len(scores), 1) if scores else "",
        })
    if rows[0]["mean_actionability"] != "" and rows[1]["mean_actionability"] != "":
        rows.append({
            "atomic_test": atomic_test,
            "condition": "A-B delta",
            "runs": "",
            "scored_alerts": "",
            "mean_actionability": round(rows[0]["mean_actionability"] - rows[1]["mean_actionability"], 1),
        })
    return rows


def case_sensitivity(
    runs: list[dict],
    alert_cases: list[dict],
    alerts: list[dict],
    atomic_test: str,
) -> list[dict]:
    """Case-level A/B contrast per run (each run weighted equally).

    Each atomic run can yield several seed cases (e.g. the cmd wrapper and the
    certutil download). We average the cases inside a run, then average across
    runs, so a busy run cannot dominate. We also report how many runs actually
    produced an EID3-seeded case (rule 100104), because inconsistent capture
    makes the A/B contrast weak rather than conclusive.
    """
    # case seed id -> case score
    seed_time_to_ids = {}
    for alert in alerts:
        seed_time_to_ids.setdefault(alert.get("timestamp"), []).append(alert.get("id"))
    id_to_score = {}
    for alert in alerts:
        id_to_score[alert.get("id")] = (alert.get("scoring") or {}).get("total_score")

    rows = []
    for condition in ("A", "B"):
        run_means = []
        eid3_runs = 0
        for run in runs:
            if run["atomic_test"] != atomic_test or run["condition"] != condition:
                continue
            scores = []
            has_eid3 = False
            for case in alert_cases:
                seed = case.get("seed") or {}
                if not in_window({"timestamp": seed.get("timestamp")}, run["start"], run["end"]):
                    continue
                if str((seed.get("rule") or {}).get("id")) == "100104":
                    has_eid3 = True
                score = case.get("case_score")
                if score is not None:
                    scores.append(score)
            if scores:
                run_means.append(sum(scores) / len(scores))
            if has_eid3:
                eid3_runs += 1
        rows.append({
            "atomic_test": atomic_test,
            "condition": condition,
            "runs": sum(1 for r in runs if r["atomic_test"] == atomic_test and r["condition"] == condition),
            "runs_with_cases": len(run_means),
            "runs_with_eid3": eid3_runs,
            "mean_case_score": round(sum(run_means) / len(run_means), 1) if run_means else "",
        })
    if rows[0]["mean_case_score"] != "" and rows[1]["mean_case_score"] != "":
        rows.append({
            "atomic_test": atomic_test,
            "condition": "A-B delta",
            "runs": "",
            "runs_with_cases": "",
            "runs_with_eid3": "",
            "mean_case_score": round(rows[0]["mean_case_score"] - rows[1]["mean_case_score"], 1),
        })
    return rows


def to_markdown(rows: list[dict], window: dict, sens: list[dict], case_sens: list[dict]) -> str:
    lines = [
        "# ART variation results",
        "",
        f"- Window: `{window.get('window_from')}` → `{window.get('window_to')}`",
        f"- Seed policy: Wazuh `rule.level >= {window.get('seed_min_level')}`",
        "- Detected = at least one seed alert in the run window (pad −5s/+20s).",
        "- Actionability = mean AHP score of seed alerts in that window.",
        "",
        "| Technique | Cond | Var | Runs | Success | Failed | Skipped | Detected | Detection % | Mean actionability |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in rows:
        lines.append(
            f"| {r['technique']} | {r['condition']} | {r['variation']} | {r['runs']} | "
            f"{r['success']} | {r['failed']} | {r['skipped']} | {r['detected_runs']} | "
            f"{r['detection_rate']} | {r['mean_actionability']} |"
        )
    lines += [
        "",
        "## Sensitivity test — T1105 #7 (certutil download), Condition A vs B",
        "",
        "### Case-level (the thesis metric: correlated case actionability)",
        "",
        "| Atomic test | Condition | Runs | Runs with cases | Runs with EID3 case | Mean case score |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for r in case_sens:
        lines.append(
            f"| {r['atomic_test']} | {r['condition']} | {r['runs']} | {r['runs_with_cases']} | "
            f"{r['runs_with_eid3']} | {r['mean_case_score']} |"
        )
    lines += [
        "",
        "Reported as a limitation: EID3 was captured in only 1 of 3 Condition-A runs,",
        "so the A/B contrast is inconclusive. See `sensitivity_limitation.md`.",
        "",
        "### Seed-alert level (diagnostic, not the thesis metric)",
        "",
        "| Atomic test | Condition | Runs | Scored alerts | Mean actionability |",
        "|---|---|---:|---:|---:|",
    ]
    for r in sens:
        lines.append(
            f"| {r['atomic_test']} | {r['condition']} | {r['runs']} | {r['scored_alerts']} | {r['mean_actionability']} |"
        )
    lines += [
        "",
        "## Notes",
        "- Failed/SKIPPED runs (e.g. missing prerequisites, blocked network) still count as a run;",
        "  they are reported, not hidden.",
        "- Detection here reflects this ruleset (evaluation/wazuh/local_rules.xml v1).",
        "  Rules were tuned after observing these runs — disclose this bias.",
        "- Legacy pilot runs before the 9-variation plan are excluded.",
        "- Failed/SKIPPED runs are detailed with causes in `failed_runs.md`.",
        "- The T1105 #7 A/B sensitivity test is reported as a limitation; see",
        "  `sensitivity_limitation.md` (EID3 capture was inconsistent).",
        "- Seed-level mean mixes EID1 alerts (no network fields) with EID3 alerts (no command line),",
        "  which is why the case-level view is the correct unit for the sensitivity test.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", required=True, type=Path)
    ap.add_argument("--api", default="http://127.0.0.1:8000")
    ap.add_argument("--out-dir", default=".", type=Path)
    args = ap.parse_args()

    with urllib.request.urlopen(f"{args.api}/api/health", timeout=30) as resp:
        health = json.load(resp)

    runs = load_runs(args.runs)
    alerts = fetch_alerts(args.api)
    cases = fetch_cases(args.api)
    rows = aggregate(runs, alerts)
    sens = sensitivity(runs, alerts, "T1105-7")
    case_sens = case_sensitivity(runs, cases, alerts, "T1105-7")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = args.out_dir / "variation_results.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    md = to_markdown(rows, {**health.get("config", {}), **health.get("data_quality", {})}, sens, case_sens)
    (args.out_dir / "variation_results.md").write_text(md, encoding="utf-8")

    print(md)
    print(f"runs={len(runs)} seed_alerts={len(alerts)} -> {csv_path}")


if __name__ == "__main__":
    main()
