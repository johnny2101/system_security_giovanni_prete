/* See LICENSE file for copyright and license details. */
#include "exception.h"

#include "cfa.h"
#include "proc.h"

#define ILLEGAL_INSTRUCTION 0x2
#define BREAKPOINT 0x3
#define CFA_EVENT_BRANCH_PROBE 0x80

#define MRET 0x30200073
#define SRET 0x10200073
#define URET 0x00200073

static inline int64_t _sign_extend(uint64_t value, int bits)
{
	uint64_t mask = 1ULL << (bits - 1);
	return (int64_t)((value ^ mask) - mask);
}

static uint64_t _reg_by_x(const proc_t *proc, uint32_t x)
{
	static const reg_t reg_map[32] = {
		REG_PC,  REG_RA, REG_SP,  REG_GP, REG_TP, REG_T0, REG_T1,  REG_T2,
		REG_S0,  REG_S1, REG_A0,  REG_A1, REG_A2, REG_A3, REG_A4,  REG_A5,
		REG_A6,  REG_A7, REG_S2,  REG_S3, REG_S4, REG_S5, REG_S6,  REG_S7,
		REG_S8,  REG_S9, REG_S10, REG_S11, REG_T3, REG_T4, REG_T5, REG_T6,
	};

	if (x == 0)
		return 0;
	if (x > 31)
		return 0;
	return proc->regs[reg_map[x]];
}

static bool _decode_branch_target(proc_t *proc, uint64_t branch_pc,
					 uint64_t *target_pc)
{
	uint16_t inst16 = *(uint16_t *)branch_pc;

	if ((inst16 & 0x3) != 0x3) {
		*target_pc = branch_pc + 2;
		return false;
	}

	uint32_t inst = *(uint32_t *)branch_pc;
	uint32_t opcode = inst & 0x7f;

	if (opcode == 0x6f) {
		uint32_t imm20 = (inst >> 31) & 0x1;
		uint32_t imm10_1 = (inst >> 21) & 0x3ff;
		uint32_t imm11 = (inst >> 20) & 0x1;
		uint32_t imm19_12 = (inst >> 12) & 0xff;
		int64_t imm = _sign_extend((imm20 << 20) | (imm19_12 << 12)
					  | (imm11 << 11) | (imm10_1 << 1),
					  21);
		*target_pc = branch_pc + imm;
		return true;
	}

	if (opcode == 0x67) {
		uint32_t rs1 = (inst >> 15) & 0x1f;
		int64_t imm = _sign_extend((inst >> 20) & 0xfff, 12);
		*target_pc = (_reg_by_x(proc, rs1) + imm) & ~1ULL;
		return true;
	}

	if (opcode == 0x63) {
		uint32_t funct3 = (inst >> 12) & 0x7;
		uint32_t rs1 = (inst >> 15) & 0x1f;
		uint32_t rs2 = (inst >> 20) & 0x1f;
		uint64_t v1 = _reg_by_x(proc, rs1);
		uint64_t v2 = _reg_by_x(proc, rs2);
		bool taken = false;

		switch (funct3) {
		case 0x0:
			taken = (v1 == v2);
			break;
		case 0x1:
			taken = (v1 != v2);
			break;
		case 0x4:
			taken = ((int64_t)v1 < (int64_t)v2);
			break;
		case 0x5:
			taken = ((int64_t)v1 >= (int64_t)v2);
			break;
		case 0x6:
			taken = (v1 < v2);
			break;
		case 0x7:
			taken = (v1 >= v2);
			break;
		default:
			taken = false;
			break;
		}

		int64_t imm = _sign_extend((((inst >> 31) & 0x1) << 12)
					  | (((inst >> 7) & 0x1) << 11)
					  | (((inst >> 25) & 0x3f) << 5)
					  | (((inst >> 8) & 0xf) << 1),
					  13);
		*target_pc = taken ? (branch_pc + imm) : (branch_pc + 4);
		return true;
	}

	*target_pc = branch_pc + 4;
	return false;
}

static proc_t *_exception_delegate(proc_t *proc, uint64_t mcause,
				   uint64_t mtval)
{
	proc->regs[REG_ECAUSE] = mcause;
	proc->regs[REG_EVAL] = mtval;
	proc->regs[REG_EPC] = proc->regs[REG_PC];
	proc->regs[REG_ESP] = proc->regs[REG_SP];
	proc->regs[REG_PC] = proc->regs[REG_TPC];
	proc->regs[REG_SP] = proc->regs[REG_TSP];
	return proc;
}

static proc_t *_exception_trap_return(proc_t *proc)
{
	proc->regs[REG_PC] = proc->regs[REG_EPC];
	proc->regs[REG_SP] = proc->regs[REG_ESP];
	proc->regs[REG_ECAUSE] = 0;
	proc->regs[REG_EVAL] = 0;
	proc->regs[REG_EPC] = 0;
	proc->regs[REG_ESP] = 0;
	return proc;
}

proc_t *exception_handler(proc_t *proc, uint64_t mcause, uint64_t mtval)
{
	if (mcause == BREAKPOINT) {
		// Mock PC-trace event using ebreak.
		// Real hardware would use Trigger Module to trap on branches.
		uint64_t bbid = proc->regs[REG_T0];
		// VULN-6 FIX: Read event type from t1 register
		// t1 encoding: 0=normal, 1=call, 2=return, 3=indirect call, 4=indirect jump, 5=inline asm
		uint64_t event_type = proc->regs[REG_T1];
		uint16_t inst = *(uint16_t *)proc->regs[REG_PC];
		uint64_t ebreak_len = ((inst & 3) == 3) ? 4 : 2;

		if (event_type == CFA_EVENT_BRANCH_PROBE) {
			uint64_t branch_pc = proc->regs[REG_PC] + ebreak_len;
			uint64_t target_pc = branch_pc + 4;
			_decode_branch_target(proc, branch_pc, &target_pc);
			cfa_push_event(branch_pc, target_pc,
				       CFA_EVENT_BRANCH_PROBE, 0, 0);
			proc->regs[REG_PC] = branch_pc;
			return proc;
		}

		uint8_t is_call = (event_type == 1 || event_type == 3) ? 1 : 0;
		uint8_t is_return = (event_type == 2) ? 1 : 0;
		cfa_push_event(proc->regs[REG_PC], bbid, (uint8_t)event_type,
			       is_call, is_return);
		proc->regs[REG_PC] += ebreak_len; // Skip trapped ebreak
		return proc;
	}
	if (mcause == ILLEGAL_INSTRUCTION
	    && (mtval == MRET || mtval == SRET || mtval == URET))
		return _exception_trap_return(proc);
	return _exception_delegate(proc, mcause, mtval);
}
