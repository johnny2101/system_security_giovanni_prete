#include "altc/altio.h"
#include "s3k/s3k.h"

// Sends CFA instrumentation metadata to the monitor through an ebreak trap.
// flags encoding: 0 = regular block, 1 = call-site block, 2 = return block.
void __attribute__((noinline)) cfa_bb_enter(int bbid, int flags)
{
	__asm__ volatile("mv t0, %0\n\tmv t1, %1\n\tebreak"
			 :
			 : "r"(bbid), "r"(flags)
			 : "t0", "t1");
}

int main(void)
{
	// Simple deterministic loop workload used to validate loop-aware CFA folding.
	alt_puts("App started");

	for (int i = 0; i < 5; i++) {
		alt_printf("Loop iteration %d\n", i);
	}

	alt_puts("App finished (This should not print!)");
}
