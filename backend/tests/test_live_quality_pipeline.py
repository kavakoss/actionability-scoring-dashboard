import sys
from types import ModuleType

import main
from mock_data import MOCK_ALERTS


def test_live_loader_filters_before_display_limit_and_reports_quality(monkeypatch):
    benign = {
        "_id": "benign-chrome-cmd",
        "@timestamp": "2026-10-02T02:00:00Z",
        "agent": {"name": "WIN-THESIS-01", "id": "001"},
        "rule": {"id": "100101", "level": 15, "description": "CMD execution"},
        "data": {
            "win": {
                "system": {"eventID": "1"},
                "eventdata": {
                    "image": r"C:\Windows\System32\cmd.exe",
                    "commandLine": (
                        r'"C:\Program Files\ESET\Total Security 21.3\bridge.exe" '
                        "chrome-extension://ahkjpbeeocnddjkakilopmfdlnjdpcdm/"
                    ),
                    "parentImage": r"C:\Program Files\Google\Chrome\chrome.exe",
                },
            }
        },
        "mitre": {"technique": "T1059.003", "name": "Windows Command Shell"},
    }
    eligible = {**MOCK_ALERTS[0], "rule": {**MOCK_ALERTS[0]["rule"], "level": 15}}

    fake_wazuh = ModuleType("wazuh_client")
    fake_wazuh.query_alerts = lambda **kwargs: [benign, eligible]
    monkeypatch.setitem(sys.modules, "wazuh_client", fake_wazuh)
    monkeypatch.setattr(main, "LIVE_ALERT_LIMIT", 1)
    monkeypatch.setattr(main, "LIVE_ALERT_FETCH_LIMIT", 10)

    results = main._load_live()

    assert len(results) == 1
    assert results[0]["_id"] == eligible["_id"]
    assert main.LIVE_DATA_QUALITY == {
        "raw_candidates_count": 2,
        "excluded_known_benign_count": 1,
        "excluded_by_reason": {"Chrome security extension launching CMD": 1},
        "omitted_due_to_display_limit": 0,
        "query_capped": False,
        "window_from": None,
        "window_to": None,
    }
