from opensearch import OpenSearch
import math

class WazuhScoring:
    def __init__(self, hosts:dict[str, str], auth: tuple[str, str]) -> None:
        self.client = OpenSearch(hosts=hosts, http_auth=auth)

    def search(self, index: str, query: dict) -> dict:
        response = self.client.search(index=index, body=query)
        return response

    def get_alerts(self, size: int = 100) -> list[dict]:
        query = {
            "size": size,
            "query": {
                "match_all": {}
            },
            "sort": [
                {
                    "@timestamp": "desc"
                }
            ]
        }
        response = self.search(index="wazuh-alerts-*", query=query)
        return response.get("hits", {}).get("hits", [])

    def get_rarity_score(self, index: str, field: str, value: str) -> int:
        query = {
            "size": 0,
            "aggs": {
                "specific_count": {
                    "filter": {
                        "term": {
                            field: value
                        }
                    }
                },
                "total_count": {
                    "value_count": {
                        "field": field
                    }
                }
            }
        }
        response = self.search(index=index, query=query)

        specific_count = response.get("aggregations", {}).get("specific_count", {}).get("doc_count", 0)
        total_count = response.get("aggregations", {}).get("total_count", {}).get("value", 0)

        probability = specific_count / total_count if total_count > 0 else 0

        if probability == 0: return -1

        ic = -math.log2(probability)

        if ic < 1:
            return 1
        elif ic < 3.32:
            return 2
        elif ic < 6.64:
            return 3
        elif ic < 9.97:
            return 4
        else:
            return 5

    def get_noise_socre(self, index: str, field: str, value: str) -> int:
        pass