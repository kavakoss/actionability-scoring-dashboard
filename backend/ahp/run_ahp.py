"""Generate AHP artifacts: weights.json, AHP_RESULTS.md, traceability CSV.

Usage (from backend/):
    python -m ahp.run_ahp
"""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

from ahp.core import matrix_markdown
from ahp.matrices import CATEGORY_NAMES, compute_all
from field_metadata import CATEGORY_LABELS, FIELD_META
from technique_profiles import DEFAULT_PROFILE_KEY, TECHNIQUE_PROFILES, get_profile

BACKEND_DIR = Path(__file__).resolve().parent.parent
WEIGHTS_PATH = BACKEND_DIR / "weights.json"
REPORT_PATH = BACKEND_DIR / "AHP_RESULTS.md"
TRACEABILITY_PATH = BACKEND_DIR / "data" / "mitre_traceability.csv"

METHOD = (
    "AHP (Saaty 1-9 scale), column-normalized priority vector; "
    "consistency required: CR < 0.10 (Saaty, 1980)"
)


def _ranks(priorities: dict) -> dict:
    ordered = sorted(priorities.items(), key=lambda item: -item[1])
    return {name: position + 1 for position, (name, _) in enumerate(ordered)}


def build_weights() -> dict:
    computed = compute_all()
    category_result = computed["category"]

    categories = {}
    for category in CATEGORY_NAMES:
        field_result = computed["fields"][category]
        ranks = _ranks(field_result["priority"])
        fields = {}
        for name in field_result["names"]:
            meta = FIELD_META[category][name]
            fields[name] = {
                "label": meta["label"],
                "path": meta["path"],
                "ossem": meta["ossem"],
                "mitre_component": meta["mitre_component"],
                "mitre_relationship": meta["mitre_relationship"],
                "local_weight": round(field_result["priority"][name], 6),
                "global_weight": round(field_result["global"][name], 6),
                "rank": ranks[name],
            }
        categories[category] = {
            "label": CATEGORY_LABELS[category],
            "weight": round(category_result["priority"][category], 6),
            "lambda_max": round(field_result["lambda_max"], 6),
            "ci": round(field_result["ci"], 6),
            "cr": round(field_result["cr"], 6),
            "consistent": bool(field_result["consistent"]),
            "fields": fields,
        }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "method": METHOD,
        "matrices_source": "ahp/matrices.py",
        "category_matrix": {
            "weight": {name: round(category_result["priority"][name], 6) for name in CATEGORY_NAMES},
            "lambda_max": round(category_result["lambda_max"], 6),
            "ci": round(category_result["ci"], 6),
            "cr": round(category_result["cr"], 6),
            "consistent": bool(category_result["consistent"]),
        },
        "categories": categories,
    }


def build_report(computed: dict, weights: dict) -> str:
    lines = [
        "# AHP Weight Calculation — Actionability Scoring Instrument",
        "",
        f"Generated: {weights['generated_at']}",
        "",
        f"Method: {METHOD}",
        "",
        "## 1. Category comparison matrix",
        "",
        "| Criterion | " + " | ".join(CATEGORY_NAMES) + " |",
        "|---" * (len(CATEGORY_NAMES) + 1) + "|",
    ]
    for category in CATEGORY_NAMES:
        row = [weights["categories"][category]["label"]]
        matrix = computed["category"]["matrix"]
        index = computed["category"]["names"].index(category)
        row += [f"{matrix[index, j]:.3f}" for j in range(len(CATEGORY_NAMES))]
        lines.append("| **" + "** | **".join(row) + "** |")

    lines += [
        "",
        "### Category weights",
        "",
        "| Criterion | Weight | lambda max | CI | CR | Consistent |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for category in CATEGORY_NAMES:
        entry = weights["categories"][category]
        lines.append(
            f"| {entry['label']} | {entry['weight']:.4f} | {entry['lambda_max']:.4f} | "
            f"{entry['ci']:.4f} | {entry['cr']:.4f} | {'yes' if entry['consistent'] else 'NO'} |"
        )
    cm = weights["category_matrix"]
    lines.append(
        f"| **Category matrix (level 1)** | {sum(cm['weight'].values()):.4f} | {cm['lambda_max']:.4f} | "
        f"{cm['ci']:.4f} | {cm['cr']:.4f} | {'yes' if cm['consistent'] else 'NO'} |"
    )

    lines += ["", "## 2. Field comparison matrices and priority vectors", ""]
    for category in CATEGORY_NAMES:
        entry = weights["categories"][category]
        field_result = computed["fields"][category]
        lines += [
            f"### {entry['label']} (`{category}`)",
            "",
            matrix_markdown(field_result),
            "",
            "| Field | Local priority | Global weight | Rank | CR |",
            "|---|---:|---:|---:|---:|",
        ]
        for name in field_result["names"]:
            field = entry["fields"][name]
            lines.append(
                f"| {field['label']} (`{name}`) | {field['local_weight']:.4f} | "
                f"{field['global_weight']:.4f} | {field['rank']} | {entry['cr']:.4f} |"
            )
        lines += [
            "",
            f"lambda max = {entry['lambda_max']:.4f}, CI = {entry['ci']:.4f}, "
            f"CR = {entry['cr']:.4f} ({'consistent' if entry['consistent'] else 'NOT CONSISTENT'})",
            "",
        ]

    lines += [
        "## 3. Global weights (sorted)",
        "",
        "| Global rank | Field | Category | Global weight | Local weight |",
        "|---:|---|---|---:|---:|",
    ]
    flat = [
        (field["global_weight"], name, category, field)
        for category in CATEGORY_NAMES
        for name, field in weights["categories"][category]["fields"].items()
    ]
    for position, (_, name, category, field) in enumerate(sorted(flat, reverse=True), start=1):
        lines.append(
            f"| {position} | {field['label']} (`{name}`) | {CATEGORY_LABELS[category]} | "
            f"{field['global_weight']:.4f} | {field['local_weight']:.4f} |"
        )

    lines += [
        "",
        "## 4. Notes",
        "",
        "- `parentProcessGuid` is a **proposed new field** (not present in the",
        "  original notebook hierarchy). It is the strongest lineage pivot because",
        "  Sysmon guarantees it on EID 1 and it survives PID reuse.",
        "- Category and field consistency is enforced by `backend/tests/test_ahp.py`.",
        "- Change pairwise values only in `ahp/matrices.py`, then rerun",
        "  `python -m ahp.run_ahp`.",
        "",
    ]
    return "\n".join(lines)


def write_traceability(weights: dict) -> None:
    TRACEABILITY_PATH.parent.mkdir(parents=True, exist_ok=True)
    field_meta = {}
    for category, fields in FIELD_META.items():
        for name, meta in fields.items():
            field_meta[name] = {**meta, "category": category}

    rows = []
    profiles = {**TECHNIQUE_PROFILES, DEFAULT_PROFILE_KEY: get_profile(None)[1]}
    for technique, profile in profiles.items():
        technique_name = profile["name"]
        source = " | ".join(profile["sources"])
        for field, role in profile["fields"].items():
            meta = field_meta[field]
            category = meta["category"]
            weight = weights["categories"][category]["fields"][field]["global_weight"]
            rows.append({
                "technique": technique,
                "technique_name": technique_name,
                "role": role,
                "category": category,
                "field": field,
                "field_label": meta["label"],
                "ahp_global_weight": weight,
                "wazuh_path": meta["path"],
                "ossem_attribute": meta["ossem"] or "",
                "mitre_data_component": meta["mitre_component"],
                "technique_data_sources": source,
            })

    with open(TRACEABILITY_PATH, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    weights = build_weights()
    computed = compute_all()
    report = build_report(computed, weights)

    WEIGHTS_PATH.write_text(json.dumps(weights, indent=2), encoding="utf-8")
    REPORT_PATH.write_text(report, encoding="utf-8")
    write_traceability(weights)

    print(f"wrote {WEIGHTS_PATH}")
    print(f"wrote {REPORT_PATH}")
    print(f"wrote {TRACEABILITY_PATH}")
    print()
    print(f"category CR = {weights['category_matrix']['cr']:.4f} "
          f"({'consistent' if weights['category_matrix']['consistent'] else 'NOT CONSISTENT'})")
    for category in CATEGORY_NAMES:
        entry = weights["categories"][category]
        flag = "ok" if entry["consistent"] else "NOT CONSISTENT"
        print(f"  {category:13s} weight={entry['weight']:.4f} CR={entry['cr']:.4f} {flag}")


if __name__ == "__main__":
    main()
