import wazuh_client


class _FakeClient:
    def __init__(self):
        self.body = None

    def search(self, index, body):
        self.body = body
        return {"hits": {"hits": []}}


def _captured_range(monkeypatch, **kwargs):
    fake = _FakeClient()
    monkeypatch.setattr(wazuh_client, "get_client", lambda: fake)
    wazuh_client.query_alerts(size=5, **kwargs)
    return fake.body["query"]["bool"]["filter"]


def test_query_alerts_uses_fixed_window_when_both_bounds_given(monkeypatch):
    filters = _captured_range(
        monkeypatch,
        time_from="2026-10-02T16:50:00.000Z",
        time_to="2026-10-03T05:00:00.000Z",
    )

    timestamp_filter = next(f for f in filters if "@timestamp" in f.get("range", {}))
    assert timestamp_filter["range"]["@timestamp"] == {
        "gte": "2026-10-02T16:50:00.000Z",
        "lte": "2026-10-03T05:00:00.000Z",
    }


def test_query_alerts_falls_back_to_rolling_window(monkeypatch):
    filters = _captured_range(monkeypatch, hours_back=72)

    timestamp_filter = next(f for f in filters if "@timestamp" in f.get("range", {}))
    assert timestamp_filter["range"]["@timestamp"] == {"gte": "now-72h"}


def test_query_alerts_with_single_bound_falls_back_to_rolling_window(monkeypatch):
    filters = _captured_range(monkeypatch, time_from="2026-10-02T16:50:00.000Z", hours_back=48)

    timestamp_filter = next(f for f in filters if "@timestamp" in f.get("range", {}))
    assert timestamp_filter["range"]["@timestamp"] == {"gte": "now-48h"}
