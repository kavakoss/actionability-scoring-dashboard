"""Unit tests for the normalization layer and the typed correlation engine."""

from correlation import (
    CANDIDATE_THRESHOLD,
    classify_pair,
    build_correlation_graph,
    build_timeline_with_edges,
    expand_case,
)
from normalizer import normalize_alert, parse_hashes


def make_event(
    event_id,
    timestamp,
    guid=None,
    parent_guid=None,
    image=None,
    parent_image=None,
    command_line=None,
    user=None,
    hashes=None,
    destination_ip=None,
    destination_port=None,
    protocol=None,
    host="WIN-THESIS-01",
    process_id=None,
    parent_process_id=None,
):
    eventdata = {
        "processGuid": guid,
        "parentProcessGuid": parent_guid,
        "image": image,
        "parentImage": parent_image,
        "commandLine": command_line,
        "user": user,
        "hashes": hashes,
        "destinationIp": destination_ip,
        "destinationPort": destination_port,
        "protocol": protocol,
        "processId": process_id,
        "parentProcessId": parent_process_id,
    }
    eventdata = {k: v for k, v in eventdata.items() if v is not None}
    return {
        "_id": f"{event_id}:{timestamp}:{guid}",
        "_index": "wazuh-archives-4.x-test",
        "@timestamp": timestamp,
        "agent": {"name": host, "id": "001"},
        "data": {"win": {"system": {"eventID": str(event_id)}, "eventdata": eventdata}},
    }


GUID_CMD = "{d1fc117c-961c-6ab2-d54a-00000000a401}"
GUID_PARENT = "{d1fc117c-57e3-6aad-5205-00000000a401}"
GUID_CHILD = "{d1fc117c-1111-6ab2-d54a-00000000a401}"


def event_create_cmd(ts="2026-09-22T10:00:00.000Z"):
    return make_event(
        1,
        ts,
        guid=GUID_CMD,
        parent_guid=GUID_PARENT,
        image=r"C:\Windows\System32\cmd.exe",
        parent_image=r"C:\Windows\System32\services.exe",
        command_line="cmd.exe /c whoami",
        user="WIN-THESIS-01\\kevin",
        hashes="SHA256=97AC98B1A92C286054CCE55239CFCCDFC23A5517BD07FE693072C9CA96C7DABB",
    )


def event_network_cmd(ts="2026-09-22T10:00:30.000Z"):
    return make_event(
        3,
        ts,
        guid=GUID_CMD,
        image=r"C:\Windows\System32\cmd.exe",
        user="WIN-THESIS-01\\kevin",
        destination_ip="203.0.113.20",
        destination_port="443",
    )


def event_create_child(ts="2026-09-22T10:01:00.000Z"):
    return make_event(
        1,
        ts,
        guid=GUID_CHILD,
        parent_guid=GUID_CMD,
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        parent_image=r"C:\Windows\System32\cmd.exe",
        command_line="powershell -enc SQBFAFgA",
        user="WIN-THESIS-01\\kevin",
        hashes="SHA256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    )


# ── Normalizer ───────────────────────────────────────────────────
def test_parse_hashes_splits_and_lowercases():
    assert parse_hashes("SHA256=ABC,MD5=DEF") == {"sha256": "abc", "md5": "def"}
    assert parse_hashes("") == {}
    assert parse_hashes(None) == {}


def test_normalize_alert_maps_fields():
    norm = normalize_alert(event_create_cmd())
    assert norm["process"]["guid"] == GUID_CMD
    assert norm["process"]["parent"]["guid"] == GUID_PARENT
    assert norm["process"]["executable"].endswith("cmd.exe")
    assert norm["process"]["name"] == "cmd.exe"
    assert norm["user"]["name"] == "win-thesis-01\\kevin"
    assert norm["user"]["account"] == "kevin"
    assert norm["file"]["hash"]["sha256"].startswith("97ac98b1")
    assert norm["event"]["id"] == "1"
    assert norm["host"]["name"] == "WIN-THESIS-01"


def test_canonical_id_matches_alert_and_archive_copies():
    alert_copy = event_create_cmd()
    archive_copy = dict(alert_copy)
    alert_copy.pop("_id", None)
    alert_copy.pop("_index", None)
    archive_copy.pop("_id", None)
    archive_copy.pop("_index", None)
    alert_copy["id"] = "WAZUH-ALERT-ID-123"
    alert_copy["_provenance"] = {"index": "wazuh-alerts-4.x-test", "document_id": "alert-es-id"}
    archive_copy.pop("id", None)
    archive_copy["_provenance"] = {"index": "wazuh-archives-4.x-test", "document_id": "archive-es-id"}

    alert_norm = normalize_alert(alert_copy)
    archive_norm = normalize_alert(archive_copy)
    assert alert_norm["id"] == archive_norm["id"]
    assert alert_norm["index"] == "wazuh-alerts-4.x-test"
    assert alert_norm["source_id"] == "alert-es-id"
    assert archive_norm["source_id"] == "archive-es-id"


def test_canonical_id_uses_agent_id_to_disambiguate_same_hostname():
    first = event_create_cmd()
    second = event_create_cmd()
    for alert in (first, second):
        alert.pop("_id", None)
        alert.pop("id", None)
        alert["agent"]["name"] = "same-hostname"
    first["agent"]["id"] = "001"
    second["agent"]["id"] = "002"

    assert normalize_alert(first)["id"] != normalize_alert(second)["id"]


# ── Typed relationships ──────────────────────────────────────────
def test_same_process_guid_create_and_network_edge():
    edge = classify_pair(normalize_alert(event_create_cmd()), normalize_alert(event_network_cmd()))
    assert edge is not None
    assert edge["relation"] == "PROCESS_CONNECTED_TO"
    assert edge["decision"] == "strong"
    assert edge["identity_backed"] is True
    assert edge["expand"] is True
    assert edge["confidence"] >= 0.85
    assert "primary=process.guid (P=1.00)" in edge["evidence"]


def test_parent_child_lineage_edge():
    parent = normalize_alert(event_create_cmd())
    child = normalize_alert(event_create_child())
    edge = classify_pair(parent, child)
    assert edge is not None
    assert edge["relation"] == "PARENT_CHILD"
    assert edge["confidence"] >= 0.85
    assert edge["identity_backed"] is True
    assert edge["parent_id"] == parent["id"]
    assert edge["child_id"] == child["id"]

    graph = build_correlation_graph([event_create_cmd(), event_create_child()])
    timeline = build_timeline_with_edges(graph, normalize_alert(event_create_cmd())["id"])
    timeline_edge = next(item for item in timeline["edges"] if item["relation"] == "PARENT_CHILD")
    assert timeline_edge["parent_id"] == parent["id"]
    assert timeline_edge["child_id"] == child["id"]


def test_same_guid_event_pairs_keep_their_semantic_relation_label():
    expected = {
        "3": "PROCESS_CONNECTED_TO",
        "5": "PROCESS_TERMINATED",
        "11": "PROCESS_CREATED_FILE",
        "22": "PROCESS_QUERIED_DNS",
        "13": "PROCESS_MODIFIED_REGISTRY",
    }
    for event_id, relation in expected.items():
        create = normalize_alert(make_event(
            1, "2026-09-22T10:00:00.000Z", guid=GUID_CMD, image=r"C:\x.exe", user="x\\u"
        ))
        related = normalize_alert(make_event(
            int(event_id), "2026-09-22T10:00:01.000Z", guid=GUID_CMD, image=r"C:\x.exe", user="x\\u"
        ))
        edge = classify_pair(create, related)
        assert edge is not None, event_id
        assert edge["relation"] == relation, event_id


def test_user_only_pair_is_candidate_context():
    a = normalize_alert(make_event(1, "2026-09-22T10:00:00.000Z", guid="{a}", image=r"C:\a.exe", user="x\\bob"))
    b = normalize_alert(make_event(1, "2026-09-22T10:00:10.000Z", guid="{b}", image=r"C:\b.exe", user="x\\bob"))
    edge = classify_pair(a, b)
    assert edge is not None
    assert edge["relation"] == "SUPPORTING_CONTEXT"
    assert edge["decision"] == "candidate"
    assert edge["expand"] is False
    assert edge["confidence"] < 0.85


def test_same_binary_cross_host():
    hash_value = "SHA256=" + "B" * 64
    a = normalize_alert(make_event(1, "2026-09-22T08:00:00.000Z", guid="{a}", image=r"C:\tools\x.exe", user="h1\\alice", hashes=hash_value, host="HOST-A"))
    b = normalize_alert(make_event(1, "2026-09-22T09:30:00.000Z", guid="{b}", image=r"C:\tools\x.exe", user="h2\\carol", hashes=hash_value, host="HOST-B"))
    edge = classify_pair(a, b)
    assert edge is not None
    assert edge["relation"] == "SAME_BINARY"
    assert edge["confidence"] >= 0.65


def test_pair_outside_window_is_rejected():
    a = normalize_alert(event_create_cmd("2026-09-22T10:00:00.000Z"))
    b = normalize_alert(event_network_cmd("2026-09-23T10:00:00.000Z"))
    assert classify_pair(a, b) is None


def test_destination_tuple_and_ip_only_use_different_pivot_strengths():
    seed_raw = make_event(
        3, "2026-09-22T10:00:00.000Z", guid="{11111111-1111-1111-1111-111111111111}",
        image=r"C:\a.exe", destination_ip="203.0.113.10", destination_port="443", protocol="tcp",
    )
    tuple_raw = make_event(
        3, "2026-09-22T10:00:10.000Z", guid="{22222222-2222-2222-2222-222222222222}",
        image=r"C:\b.exe", destination_ip="203.0.113.10", destination_port="443", protocol="tcp",
    )
    ip_only_raw = make_event(
        3, "2026-09-22T10:00:10.000Z", guid="{33333333-3333-3333-3333-333333333333}",
        image=r"C:\c.exe", destination_ip="203.0.113.10",
    )

    tuple_edge = classify_pair(normalize_alert(seed_raw), normalize_alert(tuple_raw))
    ip_edge = classify_pair(normalize_alert(seed_raw), normalize_alert(ip_only_raw))

    assert tuple_edge is not None and ip_edge is not None
    assert "primary=destination.tuple (P=0.80)" in tuple_edge["evidence"]
    assert "primary=destination.ip (P=0.45)" in ip_edge["evidence"]
    assert tuple_edge["confidence"] > ip_edge["confidence"]


# ── Graph traversal is bounded ───────────────────────────────────
def test_timeline_does_not_expand_through_weak_edges():
    seed = make_event(1, "2026-09-22T10:00:00.000Z", guid="{seed}", image=r"C:\seed.exe", user="x\\bob")
    context = make_event(1, "2026-09-22T10:00:05.000Z", guid="{ctx}", image=r"C:\ctx.exe", user="x\\bob")
    downstream = make_event(
        1, "2026-09-22T10:00:30.000Z", guid="{deep}", parent_guid="{ctx}",
        image=r"C:\deep.exe", parent_image=r"C:\ctx.exe", user="x\\carol",
    )
    graph = build_correlation_graph([seed, context, downstream])
    timeline = build_timeline_with_edges(graph, normalize_alert(seed)["id"], max_depth=3)
    node_ids = {node["id"] for node in timeline["nodes"]}
    assert normalize_alert(seed)["id"] in node_ids
    assert normalize_alert(context)["id"] in node_ids
    assert normalize_alert(downstream)["id"] not in node_ids


def test_timeline_caps_context_leaves():
    seed = make_event(1, "2026-09-22T10:00:00.000Z", guid="{seed}", image=r"C:\seed.exe", user="x\\bob")
    events = [seed]
    for index in range(10):
        events.append(make_event(
            1,
            f"2026-09-22T10:00:{index + 1:02d}.000Z",
            guid=f"{{{index + 1:08x}-1111-2222-3333-444444444444}}",
            image=rf"C:\ctx{index}.exe",
            user="x\\bob",
        ))
    graph = build_correlation_graph(events)
    timeline = build_timeline_with_edges(graph, normalize_alert(seed)["id"])
    assert len(timeline["nodes"]) <= 1 + 5


# ── Bounded live expansion ───────────────────────────────────────
def test_expand_case_with_fake_search():
    create = event_create_cmd()
    network = event_network_cmd()
    child = event_create_child()
    dataset = [create, network, child]

    def fake_search(pivot):
        hits = []
        for raw in dataset:
            ed = raw["data"]["win"]["eventdata"]
            if pivot["field"] == "process.guid" and ed.get("processGuid") == pivot["value"]:
                hits.append(raw)
            if pivot["field"] == "process.parent.guid" and ed.get("parentProcessGuid") == pivot["value"]:
                hits.append(raw)
        return hits

    result = expand_case(create, fake_search, max_depth=3, max_nodes=50)
    relations = {edge["relation"] for edge in result["edges"]}
    assert "PROCESS_CONNECTED_TO" in relations
    assert "PARENT_CHILD" in relations
    assert result["stats"]["nodes"] == 3

    depths = expand_case(network, fake_search, max_depth=1, max_nodes=50)
    assert depths["stats"]["nodes"] >= 2


def test_min_confidence_filter():
    a = normalize_alert(make_event(1, "2026-09-22T10:00:00.000Z", guid="{a}", image=r"C:\a.exe", user="x\\bob"))
    b = normalize_alert(make_event(1, "2026-09-22T10:00:01.000Z", guid="{b}", image=r"C:\b.exe", user="x\\bob"))
    edge = classify_pair(a, b)
    assert edge is not None and edge["confidence"] >= CANDIDATE_THRESHOLD
