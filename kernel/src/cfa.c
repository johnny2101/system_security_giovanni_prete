#include "cfa.h"

#define CFA_BUF_SIZE 1024

struct {
	uint64_t old_pc;
	uint64_t new_pc;
	uint8_t event_type;
	uint8_t is_call;
	uint8_t is_return;
} cfa_buffer[CFA_BUF_SIZE];

int cfa_head = 0;
int cfa_tail = 0;
int cfa_overflow = 0; // VULN-4 FIX: sticky overflow flag

// This would configure the RISC-V trigger module or Smstateen
// to trap on control flow instructions.
void cfa_init(void)
{
	cfa_head = 0;
	cfa_tail = 0;
	cfa_overflow = 0;
}

void cfa_push_event(uint64_t old_pc, uint64_t new_pc, uint8_t event_type,
		    uint8_t is_call, uint8_t is_return)
{
	// VULN-4 FIX: Detect buffer overflow before writing
	int next_head = (cfa_head + 1) % CFA_BUF_SIZE;
	if (next_head == cfa_tail) {
		cfa_overflow = 1; // Set sticky flag; monitor must detect this
		return;
	}
	cfa_buffer[cfa_head].old_pc = old_pc;
	cfa_buffer[cfa_head].new_pc = new_pc;
	cfa_buffer[cfa_head].event_type = event_type;
	cfa_buffer[cfa_head].is_call = is_call;
	cfa_buffer[cfa_head].is_return = is_return;
	cfa_head = next_head;
}

err_t cfa_get_event(uint64_t *old_pc, uint64_t *new_pc, uint8_t *event_type,
		    uint8_t *is_call, uint8_t *is_return)
{
	if (cfa_head == cfa_tail)
		return ERR_EMPTY;
	*old_pc = cfa_buffer[cfa_tail].old_pc;
	*new_pc = cfa_buffer[cfa_tail].new_pc;
	*event_type = cfa_buffer[cfa_tail].event_type;
	*is_call = cfa_buffer[cfa_tail].is_call;
	*is_return = cfa_buffer[cfa_tail].is_return;
	cfa_tail = (cfa_tail + 1) % CFA_BUF_SIZE;
	return SUCCESS;
}
