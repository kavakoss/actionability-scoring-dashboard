"""Actionability Scoring Engine.

Implements the Weighted Actionability Scoring Framework based on:
  - Saaty's Analytic Hierarchy Process (AHP) fundamental scale (1–9)
    Saaty, T. L. (1980). The Analytic Hierarchy Process. McGraw-Hill.
    Saaty, T. L. (2008). Int. Journal of Services Sciences, 1(1), 83–98.

  - MITRE ATT&CK Data Source relationships (direct/indirect)
    MITRE ATT&CK Data Sources: https://attack.mitre.org/datasources/
    Strom, B. E., et al. (2018). MITRE ATT&CK: Design and Philosophy. MITRE TR MTR180202.

  - OSSEM attribute standardization
    Open Threat Research Forge. (2023). OSSEM. https://github.com/OTRF/OSSEM

Weight assignment (AHP scale → MITRE mapping):
    9 — Extreme importance : direct data source, REQUIRED for detection
                                (commandLine, parentImage)
    7 — Very strong importance : direct, strongly correlated data source
                                (parentCommandLine, destinationIp, hashes)
    5 — Strong importance : direct, moderately correlated data source
                                (image, parentProcessId, processGuid,
                                 signatureStatus, destinationPort)
    3 — Moderate importance : indirect data source, contextual
                                (processId, user, currentDirectory,
                                 originalFileName, company, sourceIp,
                                 eventID, ruleLevel, integrityLevel)
    1 — Equal importance : tangential / always present
                                (hostname, description, timestamp, protocol)

Thresholds (derived from max theoretical score ≈ 120):
    Low       < 30   — minimally context; requires extensive manual investigation
    Medium   30–60  — sufficiently informative; needs additional validation
    High      > 60  — rich metadata; ready for immediate incident response
"""

SCORING_CONFIG = {
    "identity": {
        "label": "Identity",
        "fields": {
            "image": {
                "weight": 5,
                "path": "data.win.eventdata.image",
                "mitre_relationship": "direct — Process Creation",
                "ahp_level": "Strong importance (5)",
            },
            "processId": {
                "weight": 3,
                "path": "data.win.eventdata.processId",
                "mitre_relationship": "indirect — cross-event correlation",
                "ahp_level": "Moderate importance (3)",
            },
            "user": {
                "weight": 3,
                "path": "data.win.eventdata.user",
                "mitre_relationship": "indirect — User context",
                "ahp_level": "Moderate importance (3)",
            },
            "hostname": {
                "weight": 1,
                "path": "agent.name",
                "mitre_relationship": "tangential — always available",
                "ahp_level": "Equal importance (1)",
            },
            "integrityLevel": {
                "weight": 3,
                "path": "data.win.eventdata.integrityLevel",
                "mitre_relationship": "indirect — Privilege Escalation indicator",
                "ahp_level": "Moderate importance (3)",
            },
        },
    },
    "behavioral": {
        "label": "Behavioral / Intent",
        "fields": {
            "commandLine": {
                "weight": 9,
                "path": "data.win.eventdata.commandLine",
                "mitre_relationship": "direct — REQUIRED for Command Execution detection",
                "ahp_level": "Extreme importance (9)",
            },
            "currentDirectory": {
                "weight": 3,
                "path": "data.win.eventdata.currentDirectory",
                "mitre_relationship": "indirect — attacker workspace context",
                "ahp_level": "Moderate importance (3)",
            },
            "originalFileName": {
                "weight": 3,
                "path": "data.win.eventdata.originalFileName",
                "mitre_relationship": "indirect — Masquerading detection",
                "ahp_level": "Moderate importance (3)",
            },
            "description": {
                "weight": 1,
                "path": "data.win.eventdata.description",
                "mitre_relationship": "tangential — binary metadata",
                "ahp_level": "Equal importance (1)",
            },
        },
    },
    "relationship": {
        "label": "Relationship / Process Chain",
        "fields": {
            "parentImage": {
                "weight": 9,
                "path": "data.win.eventdata.parentImage",
                "mitre_relationship": "direct — REQUIRED for attack chain reconstruction",
                "ahp_level": "Extreme importance (9)",
            },
            "parentCommandLine": {
                "weight": 7,
                "path": "data.win.eventdata.parentCommandLine",
                "mitre_relationship": "direct — strongly correlated for chain analysis",
                "ahp_level": "Very strong importance (7)",
            },
            "parentProcessId": {
                "weight": 5,
                "path": "data.win.eventdata.parentProcessId",
                "mitre_relationship": "direct — process hierarchy correlation",
                "ahp_level": "Strong importance (5)",
            },
            "processGuid": {
                "weight": 5,
                "path": "data.win.eventdata.processGuid",
                "mitre_relationship": "direct — unique cross-event tracking",
                "ahp_level": "Strong importance (5)",
            },
        },
    },
    "ioc": {
        "label": "IOC / Threat Intelligence",
        "fields": {
            "hashes": {
                "weight": 7,
                "path": "data.win.eventdata.hashes",
                "mitre_relationship": "direct — strongly correlated for IOC matching",
                "ahp_level": "Very strong importance (7)",
            },
            "signatureStatus": {
                "weight": 5,
                "path": "data.win.eventdata.signatureStatus",
                "mitre_relationship": "direct — trusted/untrusted binary validation",
                "ahp_level": "Strong importance (5)",
            },
            "company": {
                "weight": 3,
                "path": "data.win.eventdata.company",
                "mitre_relationship": "indirect — metadata cross-validation",
                "ahp_level": "Moderate importance (3)",
            },
        },
    },
    "network": {
        "label": "Network",
        "fields": {
            "destinationIp": {
                "weight": 7,
                "path": "data.win.eventdata.destinationIp",
                "mitre_relationship": "direct — strongly correlated for C2 detection & containment",
                "ahp_level": "Very strong importance (7)",
            },
            "destinationPort": {
                "weight": 5,
                "path": "data.win.eventdata.destinationPort",
                "mitre_relationship": "direct — service/backdoor identification",
                "ahp_level": "Strong importance (5)",
            },
            "sourceIp": {
                "weight": 3,
                "path": "data.win.eventdata.sourceIp",
                "mitre_relationship": "indirect — traffic direction analysis",
                "ahp_level": "Moderate importance (3)",
            },
            "protocol": {
                "weight": 1,
                "path": "data.win.eventdata.protocol",
                "mitre_relationship": "tangential — traffic classification",
                "ahp_level": "Equal importance (1)",
            },
        },
    },
    "timeline": {
        "label": "Timeline / Event Context",
        "fields": {
            "timestamp": {
                "weight": 1,
                "path": "@timestamp",
                "mitre_relationship": "tangential — always present",
                "ahp_level": "Equal importance (1)",
            },
            "eventID": {
                "weight": 3,
                "path": "data.win.system.eventID",
                "mitre_relationship": "indirect — activity type identification",
                "ahp_level": "Moderate importance (3)",
            },
            "ruleLevel": {
                "weight": 3,
                "path": "rule.level",
                "mitre_relationship": "indirect — static SIEM severity",
                "ahp_level": "Moderate importance (3)",
            },
        },
    },
}


def _get_nested(data: dict, path: str):
    """Retrieve a nested value from a dict using dot-notation path."""
    for key in path.split("."):
        if isinstance(data, dict):
            data = data.get(key)
        else:
            return None
    return data


def calculate_score(alert: dict) -> dict:
    """Calculate actionability score for a single alert.

    Returns:
        dict with keys: total_score, level, categories (per-category breakdown), max_score
    """
    categories = {}
    total = 0
    max_total = 0

    for cat_key, cat_config in SCORING_CONFIG.items():
        cat_score = 0
        cat_max = 0
        fields_detail = []

        for field_key, field_config in cat_config["fields"].items():
            value = _get_nested(alert, field_config["path"])
            weight = field_config["weight"]
            present = bool(value and str(value).strip())

            cat_max += weight
            if present:
                cat_score += weight

            fields_detail.append({
                "field": field_key,
                "weight": weight,
                "ahp_level": field_config.get("ahp_level", ""),
                "mitre_relationship": field_config.get("mitre_relationship", ""),
                "present": present,
                "value": str(value)[:80] if value else None,
            })

        categories[cat_key] = {
            "label": cat_config["label"],
            "score": cat_score,
            "max": cat_max,
            "percentage": round(cat_score / cat_max * 100, 1) if cat_max > 0 else 0,
            "fields": fields_detail,
        }
        total += cat_score
        max_total += cat_max

    # AHP-based thresholds (max theoretical ≈ 120)
    level = "Low"
    if total > 60:
        level = "High"
    elif total >= 30:
        level = "Medium"

    return {
        "total_score": total,
        "max_score": max_total,
        "percentage": round(total / max_total * 100, 1) if max_total > 0 else 0,
        "level": level,
        "categories": categories,
    }


def score_alerts(alerts: list) -> list:
    """Score a list of alerts and attach results."""
    results = []
    for alert in alerts:
        scoring = calculate_score(alert)
        results.append({**alert, "scoring": scoring})
    return results
