"""Tests for the technique-aware actionability scoring engine."""


def make_alert(technique="T1059.001", **eventdata):
    base = {
        "processGuid": "{guid-child}",
        "parentProcessGuid": "{guid-parent}",
        "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "parentImage": r"C:\Windows\System32\cmd.exe",
        "commandLine": "powershell.exe -enc SQBFAFgA",
        "parentCommandLine": "cmd.exe /c powershell -enc SQBFAFgA",
        "processId": "5124",
        "parentProcessId": "4520",
        "user": "CORP\\jsmith",
        "integrityLevel": "Medium",
        "hashes": "SHA256=" + "A" * 64,
        "originalFileName": "PowerShell.EXE",
        "description": "Windows PowerShell",
        "company": "Microsoft Corporation",
    }
    base.update(eventdata)
    base = {k: v for k, v in base.items() if v is not None}
    return {
        "_id": f"test-{technique}",
        "@timestamp": "2026-09-22T10:00:00.000Z",
        "agent": {"name": "WIN-THESIS-01"},
        "rule": {"level": 10},
        "mitre": {"technique": technique},
        "data": {"win": {"system": {"eventID": "1"}, "eventdata": base}},
    }


def test_full_t1059_alert_scores_100():
    from scoring import calculate_score

    result = calculate_score(make_alert())
    assert result["total_score"] == 100.0
    assert result["level"] == "High"
    assert result["profile"] == "T1059.001"


def test_missing_command_line_lowers_score_by_its_share():
    """The score is normalized per technique, so removing one field drops the
    score by that field's share of the technique's expected weight."""
    from field_metadata import FIELD_META
    from scoring import calculate_score, load_weights
    from technique_profiles import get_profile

    full = calculate_score(make_alert())
    missing = calculate_score(make_alert(commandLine=""))

    weights = load_weights()
    category_of = {
        field: category for category, fields in FIELD_META.items() for field in fields
    }
    expected = get_profile("T1059.001")[1]["fields"]
    expected_weight = sum(
        weights["categories"][category_of[field]]["fields"][field]["global_weight"]
        for field in expected
    )
    command_share = (
        weights["categories"]["behavioral"]["fields"]["commandLine"]["global_weight"]
        / expected_weight
        * 100
    )

    assert missing["total_score"] < full["total_score"]
    assert abs((full["total_score"] - missing["total_score"]) - command_share) < 0.15


def test_technique_profiles_ignore_network_for_t1059():
    from scoring import calculate_score

    result = calculate_score(make_alert("T1059.001"))
    assert result["categories"]["network"]["applicable"] is False
    assert result["categories"]["network"]["max"] == 0


def test_t1105_requires_network_fields():
    from scoring import calculate_score

    without_network = calculate_score(make_alert("T1105"))
    with_network = calculate_score(make_alert("T1105", destinationIp="203.0.113.20", destinationPort="443"))
    assert with_network["total_score"] > without_network["total_score"]
    assert with_network["categories"]["network"]["applicable"] is True


def test_detect_technique_from_wazuh_rule_mitre():
    from scoring import detect_technique

    alert = make_alert("T1059.003")
    alert.pop("mitre")
    alert["rule"]["mitre"] = {"id": ["T1059.003"], "tactic": ["Execution"]}
    assert detect_technique(alert) == "T1059.003"

    alert["rule"]["mitre"]["id"] = "T1105"
    assert detect_technique(alert) == "T1105"


def test_unknown_technique_uses_default_profile():
    from field_metadata import FIELD_META
    from scoring import calculate_score

    result = calculate_score(make_alert("T9999"))
    assert result["profile"] == "default"
    expected_total = sum(len(fields) for fields in FIELD_META.values())
    assert result["expected_field_count"] == expected_total
    assert result["categories"]["timeline"]["applicable"] is True


def test_score_alerts_attaches_results():
    from scoring import score_alerts

    scored = score_alerts([make_alert(), make_alert("T1105")])
    assert len(scored) == 2
    assert all("scoring" in alert for alert in scored)
    assert scored[0]["scoring"]["profile"] == "T1059.001"


def test_contract_shape_for_frontend():
    from scoring import calculate_score

    result = calculate_score(make_alert())
    for key in ("total_score", "max_score", "percentage", "level", "categories"):
        assert key in result
    category = result["categories"]["behavioral"]
    for field in category["fields"]:
        for key in ("field", "weight", "present", "value", "mitre_relationship", "expected", "role"):
            assert key in field
