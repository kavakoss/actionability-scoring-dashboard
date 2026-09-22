"""Live correlation demo against the thesis Wazuh lab.

Usage:
    python live_demo.py --hours 48 --level 7 --depth 3

Finds one recent high-severity Sysmon alert as seed, expands the case with the
bounded typed-edge correlation engine, and prints the resulting timeline.
"""

import argparse
import json
from datetime import datetime

from dotenv import load_dotenv

load_dotenv()

from correlation import expand_case
from wazuh_client import find_seed_alert, get_event_by_guid, search_pivot


def _short(value, length=110):
    if not value:
        return "-"
    text = str(value)
    return text if len(text) <= length else text[: length - 3] + "..."


def main():
    parser = argparse.ArgumentParser(description="Wazuh live correlation demo")
    parser.add_argument("--hours", type=int, default=48, help="seed search window")
    parser.add_argument("--level", type=int, default=7, help="seed minimum rule level")
    parser.add_argument("--depth", type=int, default=3, help="max expansion depth")
    parser.add_argument("--max-nodes", type=int, default=200, help="max case nodes")
    parser.add_argument("--out", default="case_output.json", help="JSON dump path")
    parser.add_argument("--seed-guid", default=None, help="expand a specific process GUID instead of the latest alert")
    args = parser.parse_args()

    if args.seed_guid:
        seed = get_event_by_guid(args.seed_guid)
        if not seed:
            print(f"No archived Process Create event found for GUID {args.seed_guid}")
            return
    else:
        seed = find_seed_alert(hours_back=args.hours, min_level=args.level)
        if not seed:
            print("No seed alert found. Is the lab generating alerts?")
            return

    rule = seed.get("rule") or {}
    eventdata = seed.get("data", {}).get("win", {}).get("eventdata", {})
    print("=" * 100)
    print(f"SEED  {seed.get('@timestamp')}  agent={seed.get('agent', {}).get('name')}  eventID={seed.get('data', {}).get('win', {}).get('system', {}).get('eventID')}")
    print(f"      rule={rule.get('id')} level={rule.get('level')} {_short(rule.get('description'))}")
    print(f"      image={_short(eventdata.get('image'), 80)}")
    print(f"      cmd  ={_short(eventdata.get('commandLine'))}")
    print(f"      guid ={eventdata.get('processGuid')}  parent={eventdata.get('parentProcessGuid')}")
    print("=" * 100)

    result = expand_case(seed, search_pivot, max_depth=args.depth, max_nodes=args.max_nodes)
    stats = result["stats"]

    print(f"\nCASE: {stats['nodes']} nodes, {stats['edges']} edges, {stats['searches']} pivot searches, "
          f"{stats['candidates']} candidates inspected, truncated={stats['truncated']}")
    print(f"Relations: {stats['by_relation']}")

    print("\n" + "-" * 100)
    print("TYPED EDGES (sorted by confidence)")
    print("-" * 100)
    by_id = {node["id"]: node for node in result["nodes"]}
    for edge in sorted(result["edges"], key=lambda item: -item["confidence"]):
        source = by_id[edge["source"]]
        target = by_id[edge["target"]]
        print(
            f"{edge['confidence']:.3f} {edge['decision']:9s} {edge['relation']:24s} "
            f"dt={edge['delta_s'] if edge['delta_s'] is not None else '-'}"
        )
        print(f"      {source['event']['id']}:{_short(source['process']['name'], 30)} -> "
              f"{target['event']['id']}:{_short(target['process']['name'], 30)}  |  {'; '.join(edge['evidence'])}")

    print("\n" + "-" * 100)
    print("TIMELINE")
    print("-" * 100)
    ordered = sorted(result["nodes"], key=lambda node: node["timestamp"] or "")
    for node in ordered:
        marker = "*" if node["id"] == result["seed"]["id"] else " "
        print(f"{marker} {node['timestamp']}  eid={node['event']['id']:>3}  {_short(node['process']['name'], 28):28s}  "
              f"{_short(node['process']['command_line'], 70)}")

    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "seed": result["seed"],
                "stats": stats,
                "nodes": result["nodes"],
                "edges": result["edges"],
            },
            handle,
            indent=2,
            default=str,
        )
    print(f"\nFull case written to {args.out}")


if __name__ == "__main__":
    main()
