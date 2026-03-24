#include "altc/altio.h"
#include "altc/string.h"
#include "policy.h"
#include "s3k/s3k.h"

#include <stdint.h>

#include "../utils.h"

#define CFA_EVENT_BRANCH_PROBE 0x80

int get_bb_type(int bbid)
{
	for (int i = 0; i < num_policy_bb_types; i++) {
		if (policy_bb_types[i].bbid == bbid)
			return policy_bb_types[i].type;
	}
	return 0;
}

int get_return_site(int src)
{
	for (int i = 0; i < num_policy_call_returns; i++) {
		if (policy_call_returns[i].src == src)
			return policy_call_returns[i].ret;
	}
	return -1;
}

bool is_valid_indirect(int src, int dst)
{
	for (int i = 0; i < num_policy_indirect_targets; i++) {
		if (policy_indirect_targets[i].src == src) {
			for (int j = 0;
			     j < policy_indirect_targets[i].num_targets; j++) {
				if (policy_indirect_targets[i].targets[j]
				    == dst)
					return true;
			}
		}
	}
	return false;
}

// Returns the policy edge identifier for a concrete transition.
int get_edge_id(int src, int dst)
{
	for (int i = 0; i < num_policy_edges; i++) {
		if (policy_edges[i].src == src && policy_edges[i].dst == dst)
			return policy_edges[i].id;
	}
	return -1;
}

#define APP0_PID 0
#define APP1_PID 1

// Platform capability slot layout (shared with the rest of the project).
#define BOOT_PMP 0
#define RAM_MEM 1
#define UART_MEM 2
#define TIME_MEM 3
#define HART0_TIME 4
#define HART1_TIME 5
#define HART2_TIME 6
#define HART3_TIME 7
#define MONITOR 8
#define CHANNEL 9

#ifndef CFA_STRICT_ENFORCEMENT
#define CFA_STRICT_ENFORCEMENT 0
#endif

#define MAX_TRACKED_LOOPS 64
#define MAX_LOOP_PATHS 16

typedef struct {
	uint64_t path_hash;
	int count;
} loop_path_bucket_t;

typedef struct {
	int active;
	uint64_t stage_hash;
	uint64_t path_hash;
	int path_len;
	loop_path_bucket_t buckets[MAX_LOOP_PATHS];
	int num_buckets;
} loop_ctx_t;

static loop_ctx_t g_loop_ctx[MAX_TRACKED_LOOPS];

// Lightweight mixing function used to update running CFA digests.
static uint64_t cfa_mix(uint64_t state, uint64_t value)
{
	return (state << 5) ^ (state >> 59) ^ value;
}

static void loop_ctx_reset(loop_ctx_t *ctx)
{
	ctx->active = 0;
	ctx->stage_hash = 0;
	ctx->path_hash = 0;
	ctx->path_len = 0;
	ctx->num_buckets = 0;
	for (int i = 0; i < MAX_LOOP_PATHS; i++) {
		ctx->buckets[i].path_hash = 0;
		ctx->buckets[i].count = 0;
	}
}

static void loop_ctx_start(loop_ctx_t *ctx, uint64_t stage_hash)
{
	loop_ctx_reset(ctx);
	ctx->active = 1;
	ctx->stage_hash = stage_hash;
}

static bool loop_ctx_has_pending_path(const loop_ctx_t *ctx)
{
	return ctx->path_len > 0;
}

static void loop_ctx_record_path(loop_ctx_t *ctx)
{
	for (int i = 0; i < ctx->num_buckets; i++) {
		if (ctx->buckets[i].path_hash == ctx->path_hash) {
			ctx->buckets[i].count++;
			return;
		}
	}

	if (ctx->num_buckets < MAX_LOOP_PATHS) {
		ctx->buckets[ctx->num_buckets].path_hash = ctx->path_hash;
		ctx->buckets[ctx->num_buckets].count = 1;
		ctx->num_buckets++;
	}
}

static uint64_t loop_meta_digest(int loop_id, const loop_ctx_t *ctx)
{
	uint64_t digest = cfa_mix(0, (uint64_t)loop_id);
	for (int i = 0; i < ctx->num_buckets; i++) {
		digest = cfa_mix(digest, ctx->buckets[i].path_hash);
		digest = cfa_mix(digest, (uint64_t)ctx->buckets[i].count);
	}
	return digest;
}

static bool loop_edge_kind(int loop_idx, int edge_id, bool *is_body,
			   bool *is_exit)
{
	*is_body = false;
	*is_exit = false;
	for (int j = 0; j < policy_loops[loop_idx].num_body; j++) {
		if (policy_loops[loop_idx].body[j] == edge_id) {
			*is_body = true;
			return true;
		}
	}
	for (int j = 0; j < policy_loops[loop_idx].num_exits; j++) {
		if (policy_loops[loop_idx].exits[j] == edge_id) {
			*is_exit = true;
			return true;
		}
	}
	return false;
}

static int find_innermost_loop_for_edge(int edge_id, bool *is_body,
					bool *is_exit)
{
	int best = -1;
	int best_depth = -1;
	*is_body = false;
	*is_exit = false;

	for (int i = 0; i < num_policy_loops; i++) {
		bool body = false;
		bool exit = false;
		if (!loop_edge_kind(i, edge_id, &body, &exit))
			continue;
		if (policy_loops[i].depth > best_depth) {
			best = i;
			best_depth = policy_loops[i].depth;
			*is_body = body;
			*is_exit = exit;
		}
	}

	return best;
}

static void cfa_handle_violation(void)
{
	// In profiler mode we keep executing and only log dynamic edges.
	// In strict mode we suspend the monitored app immediately.
	if (!CFA_STRICT_ENFORCEMENT)
		return;
	s3k_mon_suspend(MONITOR, APP1_PID);
	alt_puts("CFA: App Suspended. Attestation FAILED.\n");
	while (1)
		;
}

int main(void)
{
	setup_uart();
	alt_puts("CFA Monitor Started.\n");
	setup_app_1();

	setup_scheduling(ROUND_ROBIN);
	s3k_mon_resume(MONITOR, APP1_PID);

	char buf[96];
	

	int current_bbid = -1;
	int shadow_stack[64] = {0};
	int shadow_sp = 0;
	for (int i = 0; i < MAX_TRACKED_LOOPS; i++)
		loop_ctx_reset(&g_loop_ctx[i]);

	uint64_t running_hash = 0xDEADBEEFCAFEBABEULL;

	while (1) {
		uint64_t old_pc, new_pc;
		uint8_t event_type, is_call, is_return;
		// Poll one CFA event produced by kernel instrumentation.
		if (s3k_cfa_get_event(&old_pc, &new_pc, &event_type, &is_call,
				      &is_return)
		    == 0) {
			alt_snprintf(
			    buf, 96,
			    "CFA Event Received: old_pc=0x%X%X, new_pc=0x%X%X",
			    (uint32_t)(old_pc >> 32), (uint32_t)old_pc,
			    (uint32_t)(new_pc >> 32), (uint32_t)new_pc);
			alt_puts(buf);

			if (event_type == CFA_EVENT_BRANCH_PROBE) {
				// Optional lightweight tracing event used for branch-probe experiments.
				alt_snprintf(
				    buf, 96,
				    "CFA BRANCH_PROBE: pc=0x%X%X -> tgt=0x%X%X\n",
				    (uint32_t)(old_pc >> 32), (uint32_t)old_pc,
				    (uint32_t)(new_pc >> 32), (uint32_t)new_pc);
				alt_puts(buf);
				continue;
			}

			int bbid = (int)new_pc;

			if (current_bbid == -1) {
				current_bbid = bbid;
				alt_snprintf(buf, 64, "CFA: Started at BB %d",
					     bbid);
				alt_puts(buf);
				continue;
			}

			int bb_type = get_bb_type(current_bbid);
			alt_printf("CFA: Current BB %d, Next BB %d, Edge Type %d\n",
				   current_bbid, bbid, bb_type);
			bool valid = false;
			int executed_edge_id = -1;

			if (bb_type == 0
			    || bb_type == 1) {
				for (int i = 0; i < num_policy_edges; i++) {
					if (policy_edges[i].src == current_bbid
					    && policy_edges[i].dst == bbid) {
						valid = true;
						executed_edge_id
						    = policy_edges[i].id;
						break;
					}
				}
			} else if (bb_type == 2) {
				alt_printf("CFA: Handling Return from BB %d to BB %d\n",
					   current_bbid, bbid);
				if (shadow_sp > 0) {
					int expected_ret
					    = shadow_stack[--shadow_sp];
					if (expected_ret == bbid) {
						valid = true;
					} else {
						alt_snprintf(
						    buf, 64,
						    "CFA Return Mismatch: expected %d, got %d\n",
						    expected_ret, bbid);
						alt_puts(buf);
					}
				} else {
					alt_puts(
					    "CFA Return Violation: Shadow Stack Underflow\n");
				}
			} else if (bb_type == 3
				   || bb_type
					  == 4) {
				if (is_valid_indirect(current_bbid, bbid)) {
					valid = true;
					// Keep hash computation aligned with policy edge IDs.
					executed_edge_id
					    = get_edge_id(current_bbid, bbid);
				}
			} else if (bb_type == 5) {
				alt_snprintf(
				    buf, 64,
				    "CFA VIOLATION: Inline ASM branch from BB %d -> %d\n",
				    current_bbid, bbid);
				alt_puts(buf);
				// Inline branch assembly is treated as opaque and therefore invalid.
			}

			if (!valid) {
				// Record unknown transitions so the policy can be expanded offline.
				alt_snprintf(
				    buf, 64,
				    "[DYNAMIC_EDGE_DISCOVERED] %d -> %d\n",
				    current_bbid, bbid);
				alt_puts(buf);
				cfa_handle_violation();
			} else {
				alt_snprintf(buf, 64, "CFA OK: %d -> %d\n",
					     current_bbid, bbid);
				alt_puts(buf);
			}

			// State update always runs, even after a violation is logged.

			if (bb_type == 1
			    || bb_type
				   == 3) {
				int ret_site = get_return_site(current_bbid);
				if (ret_site != -1) {
					// Prevent unbounded growth from malformed call traces.
					if (shadow_sp >= 64) {
						alt_puts("CFA VIOLATION: Shadow Stack Overflow\n");
						s3k_mon_suspend(MONITOR, APP1_PID);
						alt_puts("CFA: App Suspended. Attestation FAILED.\n");
						while (1)
							;
					}
					shadow_stack[shadow_sp++] = ret_site;
				}
			}

			// Fold loop executions as sub-program digests to avoid hash explosion.
			if (executed_edge_id != -1 && num_policy_loops > 0
			    && num_policy_loops <= MAX_TRACKED_LOOPS) {
				bool is_body = false;
				bool is_exit = false;
				int loop_idx = find_innermost_loop_for_edge(
				    executed_edge_id, &is_body, &is_exit);

				if (loop_idx >= 0 && is_body) {
					if (!g_loop_ctx[loop_idx].active) {
						loop_ctx_start(&g_loop_ctx[loop_idx],
						       running_hash);
					}
					g_loop_ctx[loop_idx].path_hash
					    = cfa_mix(g_loop_ctx[loop_idx].path_hash,
					      (uint64_t)executed_edge_id);
					g_loop_ctx[loop_idx].path_len++;

					// Close one loop iteration when control returns to the loop header.
					if (policy_loops[loop_idx].header == bbid
					    && loop_ctx_has_pending_path(
					       &g_loop_ctx[loop_idx])) {
						loop_ctx_record_path(
						    &g_loop_ctx[loop_idx]);
						g_loop_ctx[loop_idx].path_hash = 0;
						g_loop_ctx[loop_idx].path_len = 0;
					}
				} else if (loop_idx >= 0 && is_exit
					   && g_loop_ctx[loop_idx].active) {
					// If we exit without seeing a back-edge, flush the pending path first.
					if (loop_ctx_has_pending_path(
						    &g_loop_ctx[loop_idx])) {
						loop_ctx_record_path(
						    &g_loop_ctx[loop_idx]);
						g_loop_ctx[loop_idx].path_hash = 0;
						g_loop_ctx[loop_idx].path_len = 0;
					}
					uint64_t stage_hash
					    = g_loop_ctx[loop_idx].stage_hash;
					uint64_t digest = loop_meta_digest(
					    policy_loops[loop_idx].id,
					    &g_loop_ctx[loop_idx]);

					alt_snprintf(
					    buf, 96,
					    "CFA FOLDING: Loop %d paths=%d digest=%X%X\n",
					    policy_loops[loop_idx].id,
					    g_loop_ctx[loop_idx].num_buckets,
					    (uint32_t)(digest >> 32),
					    (uint32_t)digest);
					alt_puts(buf);

					running_hash
					    = cfa_mix(stage_hash,
					      (uint64_t)executed_edge_id);
					running_hash
					    = cfa_mix(running_hash, digest);
					loop_ctx_reset(&g_loop_ctx[loop_idx]);
				} else {
					running_hash
					    = cfa_mix(running_hash,
					      (uint64_t)executed_edge_id);
				}
			} else {
				// Conservative fallback when no foldable loop context is available.
				uint64_t edge_hash_id
				    = (executed_edge_id != -1) ?
					  (uint64_t)executed_edge_id :
					  (((uint64_t)current_bbid << 32)
					   | (uint32_t)bbid);
				running_hash = cfa_mix(running_hash, edge_hash_id);
			}

			current_bbid = bbid;

			alt_snprintf(buf, 64, "CFA HASH STATE: %X%X\n",
				     (uint32_t)(running_hash >> 32),
				     (uint32_t)running_hash);
			alt_puts(buf);
		}
	}
}