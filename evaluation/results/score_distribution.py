#!/usr/bin/env python3
"""Actionability score distribution for the currently loaded LIVE window.

Quantifies the ceiling effect: for process-execution techniques the expected
fields are exactly the fields Sysmon EID 1 always emits, so nearly every seed
scores 100. Where the profile needs a field that lives in a different event
(e.g. T1105 needs destination IP/port from EID 3), the score spreads out.

Usage:
    python score_distribution.py --api http://127.0.0.1:8000 --out-dir .
"""
from __future__ import annotations

import argparse
import json
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

TECH_LABEL = {
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1105": "Ingress Tool Transfer",
}


def fetch(api: str, path: str) -> dict:
    with urllib.request.urlopen(f"{api}{path}", timeout=60) as resp:
        return json.load(resp)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="http://127.0.0.1:8000")
    ap.add_argument("--out-dir", default=".", type=Path)
    args = ap.parse_args()

    health = fetch(args.api, "/api/health")
    alerts = fetch(args.api, "/api/alerts?sort_by=score").get("alerts", [])

    by_tech = defaultdict(Counter)
    by_rule = defaultdict(Counter)
    for alert in alerts:
        tech = (alert.get("mitre") or {}).get("technique") or "Unknown"
        rule = str((alert.get("rule") or {}).get("id"))
        score = (alert.get("scoring") or {}).get("total_score")
        by_tech[tech][score] += 1
        by_rule[rule][score] += 1

    overall = Counter((a.get("scoring") or {}).get("total_score") for a in alerts)
    distinct = len([s for s in overall if s is not None])

    cfg = health.get("config", {})
    dq = health.get("data_quality", {})
    lines = [
        "# Actionability score distribution (LIVE)",
        "",
        f"- Window: `{dq.get('window_from')}` → `{dq.get('window_to')}`",
        f"- Seed policy: Wazuh `rule.level >= {cfg.get('seed_min_level')}`",
        f"- Seeds analyzed: {len(alerts)}",
        f"- Distinct score values: {distinct}",
        "",
        "## By technique",
        "",
        "| Technique | Scores (score × count) |",
        "|---|---|",
    ]
    for tech, counter in sorted(by_tech.items()):
        cells = ", ".join(
            f"{score} × {count}" for score, count in sorted(counter.items(), key=lambda kv: (kv[0] is None, kv[0]))
        )
        lines.append(f"| {tech} {TECH_LABEL.get(tech, '')} | {cells} |")

    lines += [
        "",
        "## By triggering rule",
        "",
        "| Rule | Meaning | Scores |",
        "|---|---|---|",
    ]
    rule_meaning = {
        "100100": "T1059.001 PowerShell (EID 1)",
        "100101": "T1059.003 Command Shell (EID 1)",
        "100102": "T1105 web-request (EID 1)",
        "100103": "T1105 transfer tool (EID 1)",
        "100104": "T1105 network connection (EID 3)",
    }
    for rule, counter in sorted(by_rule.items()):
        cells = ", ".join(
            f"{score} × {count}" for score, count in sorted(counter.items(), key=lambda kv: (kv[0] is None, kv[0]))
        )
        lines.append(f"| {rule} | {rule_meaning.get(rule, '')} | {cells} |")

    lines += [
        "",
        "## Interpretation",
        "",
        "- **Ceiling effect** on T1059.001 / T1059.003: their ATT&CK data sources are",
        "  Process Creation + Command Execution, and Sysmon EID 1 always emits image,",
        "  command line, process GUID, parent image, parent GUID and user. So the",
        "  expected evidence is always present and every seed scores 100.",
        "- **Discrimination appears only when a required field lives in another event.**",
        "  T1105 needs destination IP/port from EID 3: an EID 1 transfer alert scores",
        "  82.3 (no network fields) and an EID 3 alert scores 37.1 (no command line).",
        "- Consequence: for process techniques the metric has **no variance** in this",
        "  setup, so it cannot rank those alerts. It stays informative for techniques",
        "  whose evidence spans multiple event types, and for degraded telemetry.",
        "",
        "## What makes the metric credible",
        "",
        "1. Report the ceiling explicitly; do not use ART-only 100s as the headline.",
        "2. Add **negative controls / degradation**: same technique with a Sysmon",
        "   config that drops specific telemetry, and show the score fall.",
        "3. Add **heterogeneous real alerts** (built-in rules, partial events) so the",
        "   distribution has variance and the metric can be shown to discriminate.",
        "4. Use the **alert vs case** contrast (T1105: 82.3 alert vs 99.1 case) to show",
        "   correlation value.",
        "5. Validate against analyst ground truth (does a higher score mean less",
        "   manual work?) — expert rating or a small user study.",
        "",
    ]

    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "score_distribution.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))
    print(f"\n-> {args.out_dir / 'score_distribution.md'}")


if __name__ == "__main__":
    main()
