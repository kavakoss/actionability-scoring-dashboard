"""Static metadata for every scored telemetry field.

Keeps the Wazuh path, OSSEM CDM mapping and MITRE data component in one place
so ``scoring.py``, the AHP report and the traceability CSV never drift apart.

OSSEM references (Common Data Model):
    process_guid / process_parent_guid / process_command_line /
    process_parent_command_line / process_parent_id / process_id /
    process_integrity_level / process_current_directory /
    process_file_path / process_file_description / process_company /
    process_hash_sha256 / file_hash_sha256 (file entity)
    dst_ip_addr / dst_port_number (destination entity)
    src_ip_addr (source entity)
    network_protocol (network entity)
    user_name (user entity), dvc_hostname (device entity), event_timestamp

MITRE ATT&CK data sources / components use the current Data Source naming
(Command, Process, Network Traffic, File) plus Data Component IDs where ATT&CK
publishes one (e.g. DC0032 Process Creation).
"""

from __future__ import annotations

CATEGORY_LABELS = {
    "identity": "Identity",
    "behavioral": "Behavioral / Intent",
    "relationship": "Relationship / Process Chain",
    "ioc": "IOC / Threat Intelligence",
    "network": "Network",
    "timeline": "Timeline / Event Context",
}

FIELD_META = {
    "identity": {
        "image": {
            "label": "Process Image",
            "path": "data.win.eventdata.image",
            "ossem": "process_file_path",
            "mitre_component": "Process: Process Creation (DC0032)",
            "mitre_relationship": "direct — identifies the executable",
        },
        "processId": {
            "label": "Process ID",
            "path": "data.win.eventdata.processId",
            "ossem": "process_id",
            "mitre_component": "Process: Process Metadata",
            "mitre_relationship": "indirect — volatile identifier",
        },
        "user": {
            "label": "User Context",
            "path": "data.win.eventdata.user",
            "ossem": "user_name",
            "mitre_component": "Process: Process Metadata (owner)",
            "mitre_relationship": "indirect — user context",
        },
        "hostname": {
            "label": "Hostname",
            "path": "agent.name",
            "ossem": "dvc_hostname",
            "mitre_component": "endpoint attribution (no ATT&CK component)",
            "mitre_relationship": "tangential — always available",
        },
        "integrityLevel": {
            "label": "Integrity Level",
            "path": "data.win.eventdata.integrityLevel",
            "ossem": "process_integrity_level",
            "mitre_component": "Process: Process Metadata",
            "mitre_relationship": "indirect — privilege indicator",
        },
    },
    "behavioral": {
        "commandLine": {
            "label": "Command Line",
            "path": "data.win.eventdata.commandLine",
            "ossem": "process_command_line",
            "mitre_component": "Command: Command Execution (DS0017)",
            "mitre_relationship": "direct — REQUIRED for execution analysis",
        },
        "currentDirectory": {
            "label": "Current Directory",
            "path": "data.win.eventdata.currentDirectory",
            "ossem": "process_current_directory",
            "mitre_component": "Process: Process Metadata",
            "mitre_relationship": "indirect — attacker workspace context",
        },
        "originalFileName": {
            "label": "Original File Name",
            "path": "data.win.eventdata.originalFileName",
            "ossem": None,
            "mitre_component": "Process: Process Metadata (binary metadata)",
            "mitre_relationship": "indirect — masquerading check",
            "note": "Sysmon PE metadata; no direct OSSEM CDM attribute",
        },
        "description": {
            "label": "File Description",
            "path": "data.win.eventdata.description",
            "ossem": "process_file_description",
            "mitre_component": "Process: Process Metadata",
            "mitre_relationship": "tangential — binary metadata",
        },
    },
    "relationship": {
        "parentImage": {
            "label": "Parent Image",
            "path": "data.win.eventdata.parentImage",
            "ossem": "process_parent_file_path",
            "mitre_component": "Process: Process Creation (DC0032)",
            "mitre_relationship": "direct — REQUIRED for lineage",
        },
        "parentCommandLine": {
            "label": "Parent Command Line",
            "path": "data.win.eventdata.parentCommandLine",
            "ossem": "process_parent_command_line",
            "mitre_component": "Process: Process Creation (DC0032)",
            "mitre_relationship": "direct — strongly correlated for chain analysis",
        },
        "parentProcessId": {
            "label": "Parent Process ID",
            "path": "data.win.eventdata.parentProcessId",
            "ossem": "process_parent_id",
            "mitre_component": "Process: Process Creation (DC0032)",
            "mitre_relationship": "direct — volatile hierarchy link",
        },
        "processGuid": {
            "label": "Process GUID",
            "path": "data.win.eventdata.processGuid",
            "ossem": "process_guid",
            "mitre_component": "Process: Process Creation (DC0032)",
            "mitre_relationship": "direct — unique cross-event tracking",
        },
        "parentProcessGuid": {
            "label": "Parent Process GUID",
            "path": "data.win.eventdata.parentProcessGuid",
            "ossem": "process_parent_guid",
            "mitre_component": "Process: Process Creation (DC0032)",
            "mitre_relationship": "direct — strongest lineage pivot (PID-reuse safe)",
        },
    },
    "ioc": {
        "hashes": {
            "label": "File Hash",
            "path": "data.win.eventdata.hashes",
            "ossem": "process_hash_sha256 / file_hash_sha256",
            "mitre_component": "Process: Process Metadata / File: File Metadata",
            "mitre_relationship": "direct — content identity",
        },
        "signatureStatus": {
            "label": "Signature Status",
            "path": "data.win.eventdata.signatureStatus",
            "ossem": None,
            "mitre_component": "Process: Process Metadata (trust)",
            "mitre_relationship": "direct — trusted/untrusted binary",
            "note": "Sysmon-specific; no direct OSSEM CDM attribute",
        },
        "company": {
            "label": "Company",
            "path": "data.win.eventdata.company",
            "ossem": "process_company / file_company",
            "mitre_component": "Process: Process Metadata",
            "mitre_relationship": "indirect — metadata cross-validation",
        },
    },
    "network": {
        "destinationIp": {
            "label": "Destination IP",
            "path": "data.win.eventdata.destinationIp",
            "ossem": "dst_ip_addr",
            "mitre_component": "Network Traffic: Network Connection Creation (DS0029)",
            "mitre_relationship": "direct — C2 detection and containment",
        },
        "destinationPort": {
            "label": "Destination Port",
            "path": "data.win.eventdata.destinationPort",
            "ossem": "dst_port_number",
            "mitre_component": "Network Traffic: Network Connection Creation (DS0029)",
            "mitre_relationship": "direct — service/backdoor identification",
        },
        "sourceIp": {
            "label": "Source IP",
            "path": "data.win.eventdata.sourceIp",
            "ossem": "src_ip_addr",
            "mitre_component": "Network Traffic: Network Connection Creation (DS0029)",
            "mitre_relationship": "indirect — traffic direction analysis",
        },
        "protocol": {
            "label": "Protocol",
            "path": "data.win.eventdata.protocol",
            "ossem": "network_protocol",
            "mitre_component": "Network Traffic: Network Connection Creation (DS0029)",
            "mitre_relationship": "tangential — traffic classification",
        },
    },
    "timeline": {
        "eventID": {
            "label": "Event ID",
            "path": "data.win.system.eventID",
            "ossem": "event_id",
            "mitre_component": "log source metadata (no ATT&CK component)",
            "mitre_relationship": "indirect — activity type identification",
            "note": "The event identifier is source-specific; OSSEM maps it to event_id",
        },
        "ruleLevel": {
            "label": "Rule Level",
            "path": "rule.level",
            "ossem": None,
            "mitre_component": "log source metadata (no ATT&CK component)",
            "mitre_relationship": "indirect — static SIEM severity",
            "note": "Wazuh specific, no OSSEM CDM attribute",
        },
        "timestamp": {
            "label": "Timestamp",
            "path": "@timestamp",
            "ossem": "event_timestamp",
            "mitre_component": "always available (no ATT&CK component)",
            "mitre_relationship": "tangential — always present",
        },
    },
}


def all_fields() -> dict:
    """Flat mapping field -> metadata, with its category attached."""
    flat = {}
    for category, fields in FIELD_META.items():
        for name, meta in fields.items():
            flat[name] = {**meta, "category": category}
    return flat
