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
	// Legitimate indirect control-flow targets.
	void *jump_table[] = {&&target_1, &&target_2};

	alt_puts("App started");

	int index = 0;

	alt_puts("Executing valid indirect jump to target_1...");
	goto *jump_table[index];

target_1:
	alt_puts("Arrived at target_1 safely.");
	goto exit_point;

target_2:
	alt_puts("Arrived at target_2 safely.");
	goto exit_point;


target_3:
	alt_puts(
	    "Arrived at target_3 illegally. The Monitor should kill us now.");
	return 0;

exit_point:
	alt_puts(
	    "Simulating JOP Attack: Triggering an invisible indirect jump via asm...");

	// Intentionally bypasses visible CFG edges: the assembler jump is opaque to
	// static CFG extraction and should be detected by the monitor at runtime.
	__asm__ goto("j %l0" : : : "memory" : target_3);
	__builtin_unreachable();

	alt_puts("App finished (This should not print!)");
}
