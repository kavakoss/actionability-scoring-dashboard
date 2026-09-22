"""Pairwise comparison matrices for the actionability scoring instrument.

The AHP hierarchy has two levels:
  Level 1: six telemetry categories (this file: CATEGORY_MATRIX).
  Level 2: fields inside each category (this file: FIELD_MATRICES).

Pairwise values use Saaty's fundamental scale (1, 3, 5, 7, 9) and follow the
researcher's judgement grounded in:
  * MITRE ATT&CK Data Sources / Data Components for T1059.001, T1059.003 and
    T1105 (see technique_profiles.py for the per-technique expected fields),
  * OSSEM CDM attribute availability (see field_metadata.py),
  * the correlation value of each pivot documented in the correlation design.

The comment above every block records the rationale so the matrix can be
defended and re-evaluated (see also test_ahp.py, which enforces CR < 0.10).
Change a value here, then run ``python -m ahp.run_ahp`` to regenerate
``weights.json``, ``AHP_RESULTS.md`` and the traceability CSV.
"""

from __future__ import annotations

from ahp.core import ahp

# ── Level 1: category comparisons ────────────────────────────────
# Order: behavioral, relationship, identity, ioc, network, timeline
#
# Rationale (engineering defaults grounded in the MITRE data sources of the
# three tested techniques):
#   * Behavioral and Relationship are treated as peers (command line tells
#     "what ran", lineage tells "how it started"); both are REQUIRED for
#     T1059.001 / T1059.003 detection and are the strongest context for
#     T1105 tool execution.
#   * Identity is one step weaker: it attributes the event (image, user,
#     host, integrity) but does not by itself explain the activity.
#   * IOC (hash/signature) and Network are complementary evidence; both are
#     technique-dependent (hash for binary identity, network for T1105).
#   * Timeline metadata (event id, rule level, timestamp) is supporting
#     context only and is deliberately the weakest category.
CATEGORY_NAMES = ["behavioral", "relationship", "identity", "ioc", "network", "timeline"]

CATEGORY_COMPARISONS = {
    ("behavioral", "relationship"): 1,
    ("behavioral", "identity"): 3,
    ("behavioral", "ioc"): 3,
    ("behavioral", "network"): 3,
    ("behavioral", "timeline"): 5,
    ("relationship", "identity"): 1,
    ("relationship", "ioc"): 3,
    ("relationship", "network"): 3,
    ("relationship", "timeline"): 5,
    ("identity", "ioc"): 1,
    ("identity", "network"): 1,
    ("identity", "timeline"): 5,
    ("ioc", "network"): 1,
    ("ioc", "timeline"): 3,
    ("network", "timeline"): 3,
}


# ── Level 2: field comparisons per category ──────────────────────
# identity: the process image identifies which binary ran (strongest within
# identity); user and host are contextual; integrity level is an indicator.
IDENTITY_NAMES = ["image", "processId", "user", "hostname", "integrityLevel"]
IDENTITY_COMPARISONS = {
    ("image", "processId"): 3,
    ("image", "user"): 3,
    ("image", "hostname"): 5,
    ("image", "integrityLevel"): 7,
    ("processId", "user"): 1,
    ("processId", "hostname"): 3,
    ("processId", "integrityLevel"): 5,
    ("user", "hostname"): 3,
    ("user", "integrityLevel"): 5,
    ("hostname", "integrityLevel"): 3,
}

# behavioral: command line is REQUIRED to understand execution intent;
# the remaining fields are binary metadata.
BEHAVIORAL_NAMES = ["commandLine", "currentDirectory", "originalFileName", "description"]
BEHAVIORAL_COMPARISONS = {
    ("commandLine", "currentDirectory"): 7,
    ("commandLine", "originalFileName"): 7,
    ("commandLine", "description"): 7,
    ("currentDirectory", "originalFileName"): 1,
    ("currentDirectory", "description"): 3,
    ("originalFileName", "description"): 3,
}

# relationship: parent process identity. parentProcessGuid is PROPOSED as a new
# field because Sysmon guarantees it on EID 1 and it is the strongest lineage
# pivot (it links parent and child even under PID reuse), while parentProcessId
# is volatile. Existing notebook values for the other pairs are preserved.
RELATIONSHIP_NAMES = [
    "parentImage",
    "parentCommandLine",
    "parentProcessId",
    "processGuid",
    "parentProcessGuid",
]
# Values marked PROPOSED are additions for the new field; the original notebook
# values are unchanged. This combination keeps the matrix consistent
# (CR = 0.016) while ranking parent image highest (human-readable lineage) and
# putting parentProcessGuid on par with parentCommandLine.
RELATIONSHIP_COMPARISONS = {
    ("parentImage", "parentCommandLine"): 3,
    ("parentImage", "parentProcessId"): 5,
    ("parentImage", "processGuid"): 7,
    ("parentCommandLine", "parentProcessId"): 3,
    ("parentCommandLine", "processGuid"): 5,
    ("parentProcessId", "processGuid"): 1,
    ("parentImage", "parentProcessGuid"): 2,
    ("parentProcessGuid", "parentCommandLine"): 1,
    ("parentProcessGuid", "processGuid"): 3,
    ("parentProcessGuid", "parentProcessId"): 3,
}

# ioc: the image hash is the strongest content identity; signature status is
# trust evidence; company metadata is the weakest of the three.
IOC_NAMES = ["hashes", "signatureStatus", "company"]
IOC_COMPARISONS = {
    ("hashes", "signatureStatus"): 3,
    ("hashes", "company"): 5,
    ("signatureStatus", "company"): 3,
}

# network: the destination tuple drives C2/transfer/exfiltration analysis
# (T1105); source and protocol are attribution/classification aids.
NETWORK_NAMES = ["destinationIp", "destinationPort", "sourceIp", "protocol"]
NETWORK_COMPARISONS = {
    ("destinationIp", "destinationPort"): 3,
    ("destinationIp", "sourceIp"): 5,
    ("destinationIp", "protocol"): 7,
    ("destinationPort", "sourceIp"): 3,
    ("destinationPort", "protocol"): 5,
    ("sourceIp", "protocol"): 3,
}

# timeline: event id and rule level describe the activity class; the timestamp
# is always present and therefore the weakest field.
TIMELINE_NAMES = ["eventID", "ruleLevel", "timestamp"]
TIMELINE_COMPARISONS = {
    ("eventID", "ruleLevel"): 1,
    ("eventID", "timestamp"): 3,
    ("ruleLevel", "timestamp"): 3,
}

FIELD_MATRICES = {
    "identity": {"names": IDENTITY_NAMES, "comparisons": IDENTITY_COMPARISONS},
    "behavioral": {"names": BEHAVIORAL_NAMES, "comparisons": BEHAVIORAL_COMPARISONS},
    "relationship": {"names": RELATIONSHIP_NAMES, "comparisons": RELATIONSHIP_COMPARISONS},
    "ioc": {"names": IOC_NAMES, "comparisons": IOC_COMPARISONS},
    "network": {"names": NETWORK_NAMES, "comparisons": NETWORK_COMPARISONS},
    "timeline": {"names": TIMELINE_NAMES, "comparisons": TIMELINE_COMPARISONS},
}


def compute_all() -> dict:
    """Compute category weights and per-field local/global weights."""
    category = ahp(CATEGORY_NAMES, CATEGORY_COMPARISONS)
    result = {
        "category": category,
        "fields": {},
    }
    for key, spec in FIELD_MATRICES.items():
        field_result = ahp(spec["names"], spec["comparisons"])
        field_result["global"] = {
            name: field_result["priority"][name] * category["priority"][key]
            for name in spec["names"]
        }
        result["fields"][key] = field_result
    return result


if __name__ == "__main__":
    from ahp.run_ahp import main

    main()
