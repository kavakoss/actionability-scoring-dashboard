from WazuhScoring import WazuhScoring

client = WazuhScoring(hosts={"100.97.166.11": 9200}, auth=("admin", "admin"))

alerts = client.get_rarity_score(index="wazuh-archives-*", field="data.win.eventdata.image", value=r"C:\\Program Files\\Intel\\SUR\\QUEENCREEK\\x64\\esrv_svc.exe")
print(alerts)

query = {
    "size": 0,
    "aggs": {
        "field_count": {
            "value_count": {
                "field": "data.win.eventdata.image"
            }
        }
    }
}

response = client.search(
    index="wazuh-archives-*",
    query=query
)

print(response)