#!/usr/bin/env python3
"""merge_cfg.py — Merge dynamic edges from QEMU log into cfa_policy.json"""

import json
import re
import sys

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <cfa_policy.json> <qemu.log>")
        sys.exit(1)

    policy_path = sys.argv[1]
    log_path = sys.argv[2]

    # Load statically extracted policy.
    with open(policy_path, "r") as f:
        policy = json.load(f)

    # Preserve monotonic edge IDs when adding runtime-discovered edges.
    max_id = 0
    for e in policy.get("edges", []):
        if e["id"] > max_id:
            max_id = e["id"]

    # Deduplicate by (src, dst) transition pair.
    existing = set()
    for e in policy.get("edges", []):
        existing.add((e["src"], e["dst"]))

    # Parse transitions observed in profiler mode.
    pattern = re.compile(r"\[DYNAMIC_EDGE_DISCOVERED\]\s+(\d+)\s*->\s*(\d+)")
    new_edges = []

    with open(log_path, "r") as f:
        for line in f:
            m = pattern.search(line)
            if m:
                src = int(m.group(1))
                dst = int(m.group(2))
                if (src, dst) not in existing:
                    max_id += 1
                    new_edges.append({"src": src, "dst": dst, "id": max_id})
                    existing.add((src, dst))

    # Extend policy with newly discovered transitions.
    policy["edges"].extend(new_edges)

    # Persist merged policy for subsequent monitor builds.
    with open(policy_path, "w") as f:
        json.dump(policy, f, indent=2)

    # Emit a short merge report for CI/manual inspection.
    print(f"Merged {len(new_edges)} dynamic edge(s) into {policy_path}")
    for e in new_edges:
        print(f"  NEW EDGE: {e['src']} -> {e['dst']}  (id={e['id']})")
    if not new_edges:
        print("  (no new dynamic edges found)")
    print(f"Total edges in policy: {len(policy['edges'])}")

if __name__ == "__main__":
    main()
