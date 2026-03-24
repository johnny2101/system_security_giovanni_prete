#pragma once

// Auto-generated monitor policy derived from cfa_policy.json.
// It defines allowed control-flow edges, loop metadata, and block typing used
// by runtime attestation checks in monitor/main.c.

#include <stdint.h>
#include <stdbool.h>

typedef struct { int src; int dst; int id; } edge_t;

const edge_t policy_edges[] = {
    { 1, 2, 1 },
    { 2, 5, 2 },
    { 3, 4, 3 },
    { 5, 6, 4 },
    { 6, 3, 5 },
    { 6, 5, 6 },
};
const int num_policy_edges = 6;

typedef struct { int id; int depth; int header; int num_body; const int* body; int num_exits; const int* exits; } loop_t;

const int loop_1_body[] = {4, 6};
const int loop_1_exits[] = {5};
const loop_t policy_loops[] = {
    { 1, 1, 5, 2, loop_1_body, 1, loop_1_exits },
};
const int num_policy_loops = 1;

typedef struct { int bbid; int type; } bb_type_t;

const bb_type_t policy_bb_types[] = {
    { 1, 0 },
    { 2, 0 },
    { 3, 0 },
    { 4, 2 },
    { 5, 0 },
    { 6, 0 },
};
const int num_policy_bb_types = 6;

typedef struct { int src; int ret; } call_return_t;

const call_return_t policy_call_returns[] = {
};
const int num_policy_call_returns = 0;

typedef struct { int src; int num_targets; const int* targets; } indirect_target_t;

const indirect_target_t policy_indirect_targets[] = {
};
const int num_policy_indirect_targets = 0;
