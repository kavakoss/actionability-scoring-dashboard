"""Narrow, auditable exclusions for confirmed benign lab noise.

Raw Wazuh documents are never changed. These exclusions only keep known benign
signatures out of the dashboard's live seed/case analysis; the API reports how
many were excluded so evaluation results remain transparent.
"""

from __future__ import annotations

from collections import Counter
import re


def _normalized(value) -> str:
    """Case-fold text and normalize Windows path separators for comparisons."""
    return re.sub(r"\\+", "/", str(value or "")).casefold()


def classify_known_benign(alert: dict) -> str | None:
    """Return an auditable exclusion reason for a confirmed benign signature."""
    rule = alert.get("rule") or {}
    eventdata = (((alert.get("data") or {}).get("win") or {}).get("eventdata") or {})
    rule_id = str(rule.get("id") or "")
    image = _normalized(eventdata.get("image")).rstrip("/")
    parent_image = _normalized(eventdata.get("parentImage")).rstrip("/")
    command_line = _normalized(eventdata.get("commandLine"))
    parent_command_line = _normalized(eventdata.get("parentCommandLine"))

    if (
        rule_id == "100101"
        and image.endswith("/cmd.exe")
        and parent_image.endswith("/chrome.exe")
        and "chrome-extension://ahkjpbeeocnddjkakilopmfdlnjdpcdm/" in command_line
        and ("eset" in command_line or "total security" in command_line)
    ):
        return "Chrome security extension launching CMD"

    if (
        rule_id == "100101"
        and image.endswith("/cmd.exe")
        and parent_image.endswith("/wscript.exe")
        and "/intel/sur/queencreek/x64/task.bat" in command_line
        and "/intel/sur/queencreek/x64/task.vbs" in parent_command_line
    ):
        return "Intel SUR scheduled maintenance task"

    if (
        rule_id == "92058"
        and image.endswith("/windows/system32/sdbinst.exe")
        and re.search(r"/sdbinst\.exe\s+-m\s+-bg\s*$", command_line)
        and re.search(
            r"/svchost\.exe\s+-k\s+localsystemnetworkrestricted\s+-p\s+-s\s+pcasvc\s*$",
            parent_command_line,
        )
    ):
        return "PcaSvc background compatibility check"

    return None


def exclude_known_benign(alerts: list[dict]) -> tuple[list[dict], dict[str, int]]:
    """Filter only exact allowlisted signatures and return auditable counts."""
    included = []
    excluded = Counter()
    for alert in alerts:
        reason = classify_known_benign(alert)
        if reason:
            excluded[reason] += 1
        else:
            included.append(alert)
    return included, dict(excluded)
