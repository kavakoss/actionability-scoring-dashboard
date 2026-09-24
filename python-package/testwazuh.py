"""Manual smoke test for the legacy WazuhScoring client.

Set WAZUH_INDEXER_HOST, WAZUH_INDEXER_PORT, WAZUH_INDEXER_USER and
WAZUH_INDEXER_PASS in the process environment before running. Never put
credentials in this file or commit a local .env file.
"""

import os

from WazuhScoring import WazuhScoring


def main() -> None:
    host = os.getenv("WAZUH_INDEXER_HOST")
    port = int(os.getenv("WAZUH_INDEXER_PORT", "9200"))
    user = os.getenv("WAZUH_INDEXER_USER")
    password = os.getenv("WAZUH_INDEXER_PASS")

    if not all((host, user, password)):
        raise SystemExit(
            "Set WAZUH_INDEXER_HOST, WAZUH_INDEXER_USER and WAZUH_INDEXER_PASS "
            "in the environment before running this smoke test."
        )

    client = WazuhScoring(
        hosts=[{"host": host, "port": port}],
        auth=(user, password),
        use_ssl=os.getenv("WAZUH_INDEXER_SSL", "true").lower() == "true",
        verify_certs=os.getenv("WAZUH_INDEXER_VERIFY_CERTS", "true").lower() == "true",
    )

    response = client.search(
        index="wazuh-archives-*",
        query={"size": 0, "aggs": {"events": {"value_count": {"field": "@timestamp"}}}},
    )
    count = response.get("aggregations", {}).get("events", {}).get("value", 0)
    print(f"Indexed archive events: {int(count)}")


if __name__ == "__main__":
    main()
