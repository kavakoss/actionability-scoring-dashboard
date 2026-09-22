"""Canonical normalization layer for Wazuh/Sysmon events.

Maps vendor-specific Wazuh fields into a stable, OSSEM-inspired schema that the
correlation engine and the scoring engine can rely on. The original payload is
preserved under ``raw`` so provenance is never lost.

Reference mapping:
    data.win.eventdata.processGuid        -> process.guid
    data.win.eventdata.parentProcessGuid  -> process.parent.guid
    data.win.eventdata.processId          -> process.id
    data.win.eventdata.parentProcessId    -> process.parent.id
    data.win.eventdata.image              -> process.executable
    data.win.eventdata.commandLine        -> process.command_line
    data.win.eventdata.hashes             -> file.hash.{sha256,sha1,md5,imphash}
    data.win.eventdata.destinationIp      -> destination.ip
    data.win.eventdata.destinationPort    -> destination.port
    data.win.eventdata.sourceIp           -> source.ip
    data.win.eventdata.queryName          -> dns.question.name
    data.win.eventdata.user               -> user.name
    data.win.eventdata.integrityLevel     -> process.integrity_level
    agent.name / agent.id / agent.ip      -> host.name / host.id / host.ip
    @timestamp                            -> timestamp
"""

from __future__ import annotations

from datetime import datetime, timezone

_EMPTY_VALUES = {"", "-", "none", "null", "n/a"}

HASH_ALGORITHMS = ("sha256", "sha1", "imphash", "md5")


def is_empty(value) -> bool:
    """True when a field should be treated as missing for scoring/correlation."""
    if value is None:
        return True
    return str(value).strip().lower() in _EMPTY_VALUES


def normalize_path(value):
    """Canonicalize a Windows path: strip quotes, unify separators, lowercase."""
    if is_empty(value):
        return None
    cleaned = str(value).strip().strip('"').strip("'")
    return cleaned.replace("/", "\\").lower() or None


def base_name(value):
    if not value:
        return None
    return value.replace("/", "\\").rstrip("\\").split("\\")[-1] or None


def normalize_user(value):
    if is_empty(value):
        return None
    return str(value).strip().strip('"').lower() or None


def account_name(user):
    if not user:
        return None
    return user.split("\\")[-1] or None


def parse_hashes(raw) -> dict:
    """Parse Sysmon ``hashes`` ("SHA256=...,MD5=...") into lowercase digests."""
    result = {}
    if is_empty(raw):
        return result
    for chunk in str(raw).split(","):
        if "=" not in chunk:
            continue
        algorithm, _, digest = chunk.partition("=")
        algorithm = algorithm.strip().lower()
        digest = digest.strip().lower()
        if algorithm in HASH_ALGORITHMS and digest:
            result[algorithm] = digest
    return result


def _event_id(win_system: dict) -> str:
    value = win_system.get("eventID")
    return str(value).strip() if not is_empty(value) else ""


def _node(*values):
    return next((v for v in values if not is_empty(v)), None)


def canonical_timestamp(value):
    """ISO-8601 UTC with millisecond precision, or the original string."""
    if is_empty(value):
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return str(value).strip()
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _canonical_id(raw: dict, host_name, event_id, process_guid, process_id, executable):
    """Stable event identity across the alerts and archives indices.

    Wazuh alert documents carry an internal ``id`` that archive documents do
    not, so an explicit ``_id`` wins but a Wazuh alert ``id`` must not: the
    same event is deduplicated by host + event id + process guid + timestamp.
    """
    explicit = raw.get("_id")
    if not is_empty(explicit):
        return explicit
    parts = (
        host_name,
        event_id,
        process_guid or process_id,
        canonical_timestamp(raw.get("@timestamp")),
        executable,
    )
    synthesized = "|".join(str(part) for part in parts if not is_empty(part))
    return synthesized or _node(raw.get("id"), "-")


def normalize_alert(raw: dict) -> dict:
    """Convert a raw Wazuh alert/archive event into the canonical schema."""
    raw = raw or {}
    win = ((raw.get("data") or {}).get("win") or {})
    eventdata = win.get("eventdata") or {}
    system = win.get("system") or {}
    agent = raw.get("agent") or {}

    executable = normalize_path(eventdata.get("image"))
    parent_executable = normalize_path(eventdata.get("parentImage"))
    user = normalize_user(eventdata.get("user"))
    hashes = parse_hashes(eventdata.get("hashes"))
    event_id = _event_id(system)
    process_guid = _node(eventdata.get("processGuid"))
    host_name = _node(agent.get("name"))

    alert_id = _canonical_id(
        raw, host_name, event_id, process_guid, _node(eventdata.get("processId")), executable
    )

    return {
        "id": alert_id,
        "index": raw.get("_index"),
        "timestamp": raw.get("@timestamp"),
        "event": {
            "id": _event_id(system),
            "channel": _node(system.get("channel")),
        },
        "host": {
            "name": _node(agent.get("name")),
            "id": _node(agent.get("id")),
            "ip": _node(agent.get("ip")),
        },
        "user": {
            "name": user,
            "account": account_name(user),
        },
        "process": {
            "guid": _node(eventdata.get("processGuid")),
            "id": _node(eventdata.get("processId")),
            "name": base_name(executable),
            "executable": executable,
            "command_line": _node(eventdata.get("commandLine")),
            "current_directory": normalize_path(eventdata.get("currentDirectory")),
            "integrity_level": _node(eventdata.get("integrityLevel")),
            "parent": {
                "guid": _node(eventdata.get("parentProcessGuid")),
                "id": _node(eventdata.get("parentProcessId")),
                "name": base_name(parent_executable),
                "executable": parent_executable,
                "command_line": _node(eventdata.get("parentCommandLine")),
            },
        },
        "file": {"hash": hashes},
        "destination": {
            "ip": _node(eventdata.get("destinationIp")),
            "port": _node(eventdata.get("destinationPort")),
            "protocol": _node(eventdata.get("protocol")),
        },
        "source": {"ip": _node(eventdata.get("sourceIp"))},
        "dns": {
            "question": {"name": _node(eventdata.get("queryName"))},
        },
        "rule": raw.get("rule"),
        "mitre": raw.get("mitre"),
        "scoring": raw.get("scoring"),
        "raw": raw,
    }
