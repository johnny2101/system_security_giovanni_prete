import json

# Convert the JSON policy emitted by the LLVM pass into a C header consumed by
# the monitor at build time.
with open("cfa_policy.json", "r") as f:
    policy = json.load(f)

with open("monitor/policy.h", "w") as f:
    f.write("#pragma once\n\n")
    f.write("#include <stdint.h>\n")
    f.write("#include <stdbool.h>\n\n")

    # Edge table: authoritative mapping (src_bb, dst_bb) -> edge_id.
    f.write("typedef struct { int src; int dst; int id; } edge_t;\n\n")
    f.write(f"const edge_t policy_edges[] = {{\n")
    for e in policy.get("edges", []):
        f.write(f"    {{ {e['src']}, {e['dst']}, {e['id']} }},\n")
    f.write(f"}};\n")
    f.write(f"const int num_policy_edges = {len(policy.get('edges', []))};\n\n")
    
    # Loop metadata used by runtime loop folding.
    f.write("typedef struct { int id; int depth; int header; int num_body; const int* body; int num_exits; const int* exits; } loop_t;\n\n")
    for loop in policy.get("loops", []):
        body_arr = "{" + ", ".join(map(str, loop["body"])) + "}" if loop["body"] else "{0}"
        exits_arr = "{" + ", ".join(map(str, loop["exits"])) + "}" if loop["exits"] else "{0}"
        f.write(f"const int loop_{loop['id']}_body[] = {body_arr};\n")
        f.write(f"const int loop_{loop['id']}_exits[] = {exits_arr};\n")
    
    f.write(f"const loop_t policy_loops[] = {{\n")
    for loop in policy.get("loops", []):
        depth = loop.get("depth", 1)
        header = loop.get("header", -1)
        f.write(f"    {{ {loop['id']}, {depth}, {header}, {len(loop['body'])}, loop_{loop['id']}_body, {len(loop['exits'])}, loop_{loop['id']}_exits }},\n")
    f.write(f"}};\n")
    f.write(f"const int num_policy_loops = {len(policy.get('loops', []))};\n\n")

    # Basic block classification for monitor-side transition checks.
    f.write("typedef struct { int bbid; int type; } bb_type_t;\n\n")
    f.write("const bb_type_t policy_bb_types[] = {\n")
    for bt in policy.get("bb_types", []):
        f.write(f"    {{ {bt['bbid']}, {bt['type']} }},\n")
    f.write("};\n")
    f.write(f"const int num_policy_bb_types = {len(policy.get('bb_types', []))};\n\n")

    # Call/return pairing used by the shadow stack logic.
    f.write("typedef struct { int src; int ret; } call_return_t;\n\n")
    f.write("const call_return_t policy_call_returns[] = {\n")
    for cr in policy.get("call_returns", []):
        f.write(f"    {{ {cr['src']}, {cr['ret']} }},\n")
    f.write("};\n")
    f.write(f"const int num_policy_call_returns = {len(policy.get('call_returns', []))};\n\n")

    # Allowed targets for indirect calls/jumps.
    f.write("typedef struct { int src; int num_targets; const int* targets; } indirect_target_t;\n\n")
    for it in policy.get("indirect_targets", []):
        targets_arr = "{" + ", ".join(map(str, it["targets"])) + "}" if it["targets"] else "{0}"
        f.write(f"const int ind_targets_{it['src']}[] = {targets_arr};\n")
    
    f.write("const indirect_target_t policy_indirect_targets[] = {\n")
    for it in policy.get("indirect_targets", []):
        f.write(f"    {{ {it['src']}, {len(it['targets'])}, ind_targets_{it['src']} }},\n")
    f.write("};\n")
    f.write(f"const int num_policy_indirect_targets = {len(policy.get('indirect_targets', []))};\n")
