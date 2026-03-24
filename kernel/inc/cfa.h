#pragma once
#include <stdint.h>
#include "error.h"

extern int cfa_overflow; // VULN-4: sticky overflow flag

void cfa_init(void);
void cfa_push_event(uint64_t old_pc, uint64_t new_pc, uint8_t event_type,
		    uint8_t is_call, uint8_t is_return);
err_t cfa_get_event(uint64_t *old_pc, uint64_t *new_pc, uint8_t *event_type,
		uint8_t *is_call, uint8_t *is_return);
