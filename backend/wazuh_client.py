"""Wazuh Indexer (OpenSearch) client with entity-based correlation queries.

Connects to Wazuh Indexer using credentials from .env.
Provides query methods for:
  - Fetching alerts by agent, eventID, timerange
  - Finding related events via entity correlation (processGuid, user, IP, host)
  - Real-time webhook-driven alert processing

Environment variables (in .env):
  WAZUH_INDEXER_HOST=36.93.185.111
  WAZUH_INDEXER_PORT=9200
  WAZUH_INDEXER_USER=admin
  WAZUH_INDEXER_PASS=your-password
"""

import os
from opensearchpy import OpenSearch

# ── Load config from environment ─────────────────────────────────
HOST = os.getenv("WAZUH_INDEXER_HOST", "localhost")
PORT = int(os.getenv("WAZUH_INDEXER_PORT", "9200"))
USER = os.getenv("WAZUH_INDEXER_USER", "admin")
PASSWORD = os.getenv("WAZUH_INDEXER_PASS", "admin")
USE_SSL = os.getenv("WAZUH_INDEXER_SSL", "true").lower() == "true"
VERIFY_CERTS = os.getenv("WAZUH_INDEXER_VERIFY_CERTS", "false").lower() == "true"

ALERTS_INDEX = "wazuh-alerts-*"
ARCHIVES_INDEX = "wazuh-archives-*"

_client = None


def get_client() -> OpenSearch:
    """Lazy-init OpenSearch client (singleton)."""
    global _client
    if _client is None:
        _client = OpenSearch(
            hosts=[{"host": HOST, "port": PORT}],
            http_auth=(USER, PASSWORD),
            use_ssl=USE_SSL,
            verify_certs=VERIFY_CERTS,
            ssl_show_warn=False,
        )
    return _client


# ── Entity Extraction ────────────────────────────────────────────
def extract_entities(alert: dict) -> dict:
    """Extract correlatable entities from a single Wazuh alert.

    Returns dict with keys that can be used for related-event queries.
    """
    entities = {}

    # Navigate nested Wazuh alert structure
    eventdata = alert.get("data", {}).get("win", {}).get("eventdata", {})
    agent = alert.get("agent", {})

    if eventdata.get("processGuid"):
        entities["processGuid"] = eventdata["processGuid"]
    if eventdata.get("parentProcessGuid"):
        entities["parentProcessGuid"] = eventdata["parentProcessGuid"]
    if eventdata.get("user"):
        entities["user"] = eventdata["user"]
    if eventdata.get("hashes"):
        entities["hashes"] = eventdata["hashes"]
    if eventdata.get("destinationIp"):
        entities["destinationIp"] = eventdata["destinationIp"]
    if eventdata.get("sourceIp"):
        entities["sourceIp"] = eventdata["sourceIp"]
    if agent.get("name"):
        entities["host"] = agent["name"]
    if agent.get("id"):
        entities["agentId"] = agent["id"]

    return entities


# ── Query Builders ────────────────────────────────────────────────
def query_alerts(
    agent_name: str | None = None,
    event_id: int | None = None,
    min_level: int | None = None,
    hours_back: int = 24,
    size: int = 100,
) -> list:
    """Fetch alerts from Wazuh Indexer with optional filters."""
    must = []
    filters = []

    if agent_name:
        must.append({"term": {"agent.name": agent_name}})
    if event_id:
        must.append({"term": {"data.win.system.eventID": event_id}})
    if min_level:
        filters.append({"range": {"rule.level": {"gte": min_level}}})

    filters.append({"range": {"@timestamp": {"gte": f"now-{hours_back}h"}}})

    body = {
        "query": {"bool": {"must": must, "filter": filters}},
        "size": size,
        "sort": [{"@timestamp": "desc"}],
    }

    client = get_client()
    resp = client.search(index=ALERTS_INDEX, body=body)
    return [hit["_source"] for hit in resp["hits"]["hits"]]


def query_related_events(entities: dict, hours_back: int = 2160, size: int = 500) -> list:
    """Find all events related to the given entities.

    Uses OR (should) logic: any matching entity = potentially related.
    Applied to BOTH alerts and archives indices.
    """
    should = []

    # Strong entity matches
    if entities.get("processGuid"):
        should.append({"match": {"data.win.eventdata.processGuid": entities["processGuid"]}})
    if entities.get("parentProcessGuid"):
        should.append({"match": {"data.win.eventdata.parentProcessGuid": entities["parentProcessGuid"]}})

    # Medium entity matches
    if entities.get("user"):
        should.append({"match": {"data.win.eventdata.user": entities["user"]}})
    if entities.get("hashes"):
        should.append({"match": {"data.win.eventdata.hashes": entities["hashes"]}})
    if entities.get("destinationIp"):
        should.append({"match": {"data.win.eventdata.destinationIp": entities["destinationIp"]}})
    if entities.get("sourceIp"):
        should.append({"match": {"data.win.eventdata.sourceIp": entities["sourceIp"]}})

    # Weaker matches
    if entities.get("host"):
        should.append({"term": {"agent.name": entities["host"]}})

    if not should:
        return []

    body = {
        "query": {
            "bool": {
                "should": should,
                "minimum_should_match": 1,
                "filter": [{"range": {"@timestamp": {"gte": f"now-{hours_back}h"}}}],
            }
        },
        "size": size,
        "sort": [{"@timestamp": "asc"}],
    }

    client = get_client()
    results = []

    # Search both indices
    for index in [ALERTS_INDEX, ARCHIVES_INDEX]:
        try:
            resp = client.search(index=index, body=body)
            results.extend(hit["_source"] for hit in resp["hits"]["hits"])
        except Exception:
            pass  # archives index might not exist

    return results


def query_by_agent_timeline(
    agent_name: str,
    hours_back: int = 2160,
    size: int = 500,
) -> list:
    """Fetch all events for a specific agent within a time window."""
    body = {
        "query": {
            "bool": {
                "must": [{"term": {"agent.name": agent_name}}],
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{hours_back}h"}}},
                    {"terms": {"data.win.system.eventID": [1, 3, 11, 13, 22, 23]}},
                ],
            }
        },
        "size": size,
        "sort": [{"@timestamp": "asc"}],
    }

    client = get_client()
    results = []

    for index in [ALERTS_INDEX, ARCHIVES_INDEX]:
        try:
            resp = client.search(index=index, body=body)
            results.extend(hit["_source"] for hit in resp["hits"]["hits"])
        except Exception:
            pass

    return results
