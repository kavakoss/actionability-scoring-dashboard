"""Wazuh Indexer (OpenSearch) client with entity-based correlation queries.

Connects to Wazuh Indexer using credentials from .env.
Provides query methods for:
  - Fetching alerts by agent, eventID, timerange
  - Pivot-based retrieval used by the correlation engine (term queries on
    keyword fields, relation-specific time windows)
  - Legacy entity-based related-event queries

Environment variables (in .env):
  WAZUH_INDEXER_HOST=<host-or-tailnet-ip>
  WAZUH_INDEXER_PORT=9200
  WAZUH_INDEXER_USER=admin
  WAZUH_INDEXER_PASS=<secret>
"""

import os
import logging
from datetime import datetime, timezone

from opensearchpy import OpenSearch

# ── Load config from environment ─────────────────────────────────
HOST = os.getenv("WAZUH_INDEXER_HOST", "localhost")
PORT = int(os.getenv("WAZUH_INDEXER_PORT", "9200"))
USER = os.getenv("WAZUH_INDEXER_USER", "admin")
PASSWORD = os.getenv("WAZUH_INDEXER_PASS")
USE_SSL = os.getenv("WAZUH_INDEXER_SSL", "true").lower() == "true"
VERIFY_CERTS = os.getenv("WAZUH_INDEXER_VERIFY_CERTS", "false").lower() == "true"

ALERTS_INDEX = "wazuh-alerts-*"
ARCHIVES_INDEX = "wazuh-archives-*"

# Normalized pivot -> raw Wazuh field (all mapped as keyword)
PIVOT_FIELDS = {
    "process.guid": "data.win.eventdata.processGuid",
    "process.parent.guid": "data.win.eventdata.parentProcessGuid",
    "file.hash.sha256": "data.win.eventdata.hashes",
    "destination.ip": "data.win.eventdata.destinationIp",
    "user.name": "data.win.eventdata.user",
}

SOURCE_FIELDS = [
    "@timestamp",
    "agent.id",
    "agent.name",
    "agent.ip",
    "data.win.system.eventID",
    "data.win.eventdata.processGuid",
    "data.win.eventdata.parentProcessGuid",
    "data.win.eventdata.processId",
    "data.win.eventdata.parentProcessId",
    "data.win.eventdata.image",
    "data.win.eventdata.parentImage",
    "data.win.eventdata.commandLine",
    "data.win.eventdata.parentCommandLine",
    "data.win.eventdata.user",
    "data.win.eventdata.integrityLevel",
    "data.win.eventdata.hashes",
    "data.win.eventdata.destinationIp",
    "data.win.eventdata.destinationPort",
    "data.win.eventdata.sourceIp",
    "data.win.eventdata.protocol",
    "data.win.eventdata.queryName",
]

_client = None
logger = logging.getLogger(__name__)


def get_client() -> OpenSearch:
    """Lazy-init OpenSearch client (singleton)."""
    global _client
    if _client is None:
        if not PASSWORD:
            raise RuntimeError(
                "WAZUH_INDEXER_PASS is not set. Configure it in backend/.env "
                "or the process environment; refusing to try a default password."
            )
        _client = OpenSearch(
            hosts=[{"host": HOST, "port": PORT}],
            http_auth=(USER, PASSWORD),
            use_ssl=USE_SSL,
            verify_certs=VERIFY_CERTS,
            ssl_show_warn=False,
        )
    return _client


def _format_ts(value) -> str:
    if isinstance(value, datetime):
        aware = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return aware.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return str(value)


def _source_with_provenance(hit: dict) -> dict:
    """Return _source plus ES document metadata without changing event identity.

    Wazuh stores the same event separately in alerts and archives with
    different Elasticsearch document IDs. The metadata is therefore kept
    under _provenance, not copied to `_id` (which is used for correlation IDs).
    """
    source = dict(hit.get("_source") or {})
    source["_provenance"] = {
        "index": hit.get("_index"),
        "document_id": hit.get("_id"),
    }
    return source


# ── Pivot-based retrieval (correlation engine) ───────────────────
def search_pivot(pivot: dict, size: int = 200, index: str = ARCHIVES_INDEX) -> list:
    """Retrieve raw events for one normalized pivot.

    Uses a ``term`` query on keyword-mapped fields (exact matching) and an
    explicit time range supplied by the correlation engine.
    """
    field = PIVOT_FIELDS.get(pivot["field"])
    if field is None:
        raise ValueError(f"Unsupported pivot field: {pivot['field']}")

    value = pivot["value"]
    if pivot["field"] == "file.hash.sha256":
        value = f"SHA256={str(value).upper()}"

    filters = [{"term": {field: value}}]
    if pivot.get("time_from") and pivot.get("time_to"):
        filters.append({
            "range": {
                "@timestamp": {
                    "gte": _format_ts(pivot["time_from"]),
                    "lte": _format_ts(pivot["time_to"]),
                }
            }
        })
    if pivot.get("agent_id"):
        filters.append({"term": {"agent.id": pivot["agent_id"]}})
    elif pivot.get("agent_name"):
        filters.append({"term": {"agent.name": pivot["agent_name"]}})

    body = {
        "size": size,
        "track_total_hits": False,
        "_source": SOURCE_FIELDS,
        "query": {"bool": {"filter": filters}},
        "sort": [{"@timestamp": "asc"}],
    }

    response = get_client().search(index=index, body=body)
    return [_source_with_provenance(hit) for hit in response["hits"]["hits"]]


def get_event_by_guid(process_guid: str, event_id: str = "1") -> dict | None:
    """Fetch one event (default: Process Create) for a given process GUID."""
    body = {
        "size": 1,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"data.win.eventdata.processGuid": process_guid}},
                    {"term": {"data.win.system.eventID": event_id}},
                ]
            }
        },
        "sort": [{"@timestamp": "asc"}],
    }
    response = get_client().search(index=ARCHIVES_INDEX, body=body)
    hits = response["hits"]["hits"]
    return _source_with_provenance(hits[0]) if hits else None


def find_seed_alert(hours_back: int = 48, min_level: int = 7) -> dict | None:
    """Fetch one representative high-severity sysmon alert to use as a seed."""
    body = {
        "size": 1,
        "query": {
            "bool": {
                "must": [{"term": {"rule.groups": "sysmon"}}],
                "filter": [
                    {"range": {"rule.level": {"gte": min_level}}},
                    {"range": {"@timestamp": {"gte": f"now-{hours_back}h"}}},
                ],
            }
        },
        "sort": [{"@timestamp": "desc"}],
    }
    response = get_client().search(index=ALERTS_INDEX, body=body)
    hits = response["hits"]["hits"]
    return _source_with_provenance(hits[0]) if hits else None


# ── Entity extraction (legacy webhook flow) ──────────────────────
def extract_entities(alert: dict) -> dict:
    """Extract correlatable entities from a single Wazuh alert."""
    entities = {}

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


# ── Query builders (legacy, exact-match fields) ──────────────────
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
    return [_source_with_provenance(hit) for hit in resp["hits"]["hits"]]


def query_related_events(entities: dict, hours_back: int = 2160, size: int = 500) -> list:
    """Find all events related to the given entities (exact term matches).

    Searches BOTH alerts and archives indices so non-alerting telemetry can
    complete a correlation chain.
    """
    should = []

    if entities.get("processGuid"):
        should.append({"term": {"data.win.eventdata.processGuid": entities["processGuid"]}})
    if entities.get("parentProcessGuid"):
        should.append({"term": {"data.win.eventdata.parentProcessGuid": entities["parentProcessGuid"]}})
    if entities.get("user"):
        should.append({"term": {"data.win.eventdata.user": entities["user"]}})
    if entities.get("hashes"):
        should.append({"term": {"data.win.eventdata.hashes": entities["hashes"]}})
    if entities.get("destinationIp"):
        should.append({"term": {"data.win.eventdata.destinationIp": entities["destinationIp"]}})
    if entities.get("sourceIp"):
        should.append({"term": {"data.win.eventdata.sourceIp": entities["sourceIp"]}})
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

    for index in [ALERTS_INDEX, ARCHIVES_INDEX]:
        try:
            resp = client.search(index=index, body=body)
            results.extend(_source_with_provenance(hit) for hit in resp["hits"]["hits"])
        except Exception as exc:
            logger.warning("related-event search failed for index %s: %s", index, exc)

    return results


def query_by_agent_timeline(
    agent_name: str,
    hours_back: int = 2160,
    size: int = 500,
) -> list:
    """Fetch Sysmon process/network events for a specific agent."""
    body = {
        "query": {
            "bool": {
                "must": [{"term": {"agent.name": agent_name}}],
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{hours_back}h"}}},
                    {"terms": {"data.win.system.eventID": [1, 3, 5]}},
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
            results.extend(_source_with_provenance(hit) for hit in resp["hits"]["hits"])
        except Exception as exc:
            logger.warning("agent timeline search failed for index %s: %s", index, exc)

    return results
