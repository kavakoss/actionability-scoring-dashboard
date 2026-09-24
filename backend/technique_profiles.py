"""Per-technique expected telemetry fields (MITRE ATT&CK grounded).

A profile lists the fields the analyst needs to investigate a technique. The
field set is derived from the ATT&CK Data Sources / Data Components of the
technique and the OSSEM attributes available in Sysmon EID 1/3 telemetry:

  T1059.001 PowerShell        Process Creation (DC0032), Command Execution
                              (DS0017), Process Metadata
  T1059.003 Windows Cmd Shell Process Creation (DC0032), Command Execution
                              (DS0017), Process Metadata
  T1105 Ingress Tool Transfer Network Connection Creation (DS0029), File
                              Metadata, Command Execution (DS0017)

Roles are reporting metadata only (required / supporting / context); every
field listed in a profile contributes its AHP global weight to the score.
The role labels are this study's operational interpretation of the technique's
ATT&CK data components; MITRE does not designate individual Sysmon fields as
"required" or "supporting".
Always-present metadata fields (eventID, ruleLevel, timestamp) are excluded
from profile denominators so they cannot inflate the score.

Process Termination (Sysmon EID 5 / MITRE DC0033) is NOT part of these
profiles: ATT&CK maps that data component to techniques such as T1489 and
T1485, not to T1059.001, T1059.003 or T1105. Its role here is correlation
(process lifetime), not alert scoring.
"""

from __future__ import annotations

TECHNIQUE_PROFILES = {
    "T1059.001": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "sources": [
            "MITRE ATT&CK T1059.001 — Data Sources: Process Creation, Command Execution, Process Metadata",
            "OSSEM CDM process entity (process_command_line, process_parent_guid)",
        ],
        "fields": {
            "commandLine": "required",
            "image": "required",
            "processGuid": "required",
            "parentImage": "required",
            "parentProcessGuid": "required",
            "parentCommandLine": "supporting",
            "user": "supporting",
            "integrityLevel": "supporting",
            "hashes": "supporting",
            "originalFileName": "supporting",
            "description": "supporting",
            "company": "supporting",
            "processId": "supporting",
            "hostname": "context",
        },
    },
    "T1059.003": {
        "name": "Command and Scripting Interpreter: Windows Command Shell",
        "sources": [
            "MITRE ATT&CK T1059.003 — Data Sources: Process Creation, Command Execution, Process Metadata",
            "OSSEM CDM process entity (process_command_line, process_parent_guid)",
        ],
        "fields": {
            "commandLine": "required",
            "image": "required",
            "processGuid": "required",
            "parentImage": "required",
            "parentProcessGuid": "required",
            "parentCommandLine": "supporting",
            "user": "supporting",
            "integrityLevel": "supporting",
            "hashes": "supporting",
            "originalFileName": "supporting",
            "description": "supporting",
            "company": "supporting",
            "processId": "supporting",
            "hostname": "context",
        },
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "sources": [
            "MITRE ATT&CK T1105 — Data Sources: Network Connection Creation (DS0029), File Metadata, Command Execution",
            "OSSEM CDM destination entity (dst_ip_addr, dst_port_number)",
        ],
        "fields": {
            "commandLine": "required",
            "image": "required",
            "processGuid": "required",
            "parentImage": "required",
            "parentProcessGuid": "required",
            "destinationIp": "required",
            "destinationPort": "required",
            "protocol": "supporting",
            "sourceIp": "supporting",
            "hashes": "supporting",
            "user": "supporting",
            "integrityLevel": "supporting",
            "parentCommandLine": "supporting",
            "originalFileName": "supporting",
            "description": "supporting",
            "company": "supporting",
            "processId": "supporting",
            "hostname": "context",
        },
    },
}

DEFAULT_PROFILE_KEY = "default"


def _default_profile() -> dict:
    from field_metadata import FIELD_META

    fields = {}
    for category, category_fields in FIELD_META.items():
        # These fields are populated by the logging pipeline even when the
        # event contains almost no investigative context; excluding them keeps
        # an unknown-technique profile from receiving free completeness points.
        if category == "timeline":
            continue
        for name in category_fields:
            fields[name] = "supporting"
    return {
        "name": "Default (technique not profiled)",
        "sources": ["All instrumented fields; used when no technique profile applies"],
        "fields": fields,
    }


def get_profile(technique: str | None) -> tuple[str, dict]:
    """Return (profile_key, profile) for a technique, falling back to default."""
    if technique and technique in TECHNIQUE_PROFILES:
        return technique, TECHNIQUE_PROFILES[technique]
    return DEFAULT_PROFILE_KEY, _default_profile()


def expected_field_names(technique: str | None) -> set:
    _, profile = get_profile(technique)
    return set(profile["fields"].keys())
