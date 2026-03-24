# Project: C-FLAT-style Control-Flow Attestation on S3K

This folder contains a complete **runtime control-flow attestation prototype** built on top of the S3K separation kernel.

It combines:
- static control-flow policy extraction (LLVM pass),
- dynamic edge discovery in QEMU,
- monitor-side policy enforcement,
- and kernel support for exporting control-flow events to a privileged monitor process.

---

## 1) What this project does

At a high level, this project implements a practical, C-FLAT-inspired pipeline:

1. **Instrumented application emits control-flow events**
   - The app uses `ebreak` probes (`app/main.c`) to emit basic-block IDs and event type metadata.

2. **Kernel captures events in a ring buffer**
   - The kernel trap handler decodes probe context and records events (`kernel/src/exception.c`, `kernel/src/cfa.c`).

3. **Privileged monitor consumes events via syscall**
   - A monitor process (PID 0) calls `s3k_cfa_get_event(...)` and validates observed transitions against policy (`monitor/main.c`).

4. **Policy-based verification**
   - The monitor checks:
     - direct and conditional edges,
     - return matching via shadow stack,
     - indirect branch target allow-lists,
     - loop behavior with loop-path folding (to avoid hash explosion).

5. **Two operation modes**
   - **Profiler / learning mode** (`CFA_STRICT_ENFORCEMENT=0`): unknown edges are logged as `[DYNAMIC_EDGE_DISCOVERED] src -> dst`.
   - **Strict / enforcement mode** (`CFA_STRICT_ENFORCEMENT=1`): violations suspend the app and fail attestation.

### Output semantics (what “attestation” means here)

The monitor maintains a running digest-like state (`running_hash`) over validated transitions and loop metadata. During execution it emits logs such as:
- `CFA OK: src -> dst`
- `CFA FOLDING: Loop ...`
- `CFA HASH STATE: ...`
- violation/suspension messages in strict mode.

This gives you a concrete runtime trace validation mechanism aligned with the C-FLAT design principles.

---

## 2) Relation to the C-FLAT paper

This implementation is directly inspired by:

> **C-FLAT: Control-Flow Attestation for Embedded Systems Software**  
> Tigist Abera, N. Asokan, Lucas Davi, Jan-Erik Ekberg, Thomas Nyman, Andrew Paverd, Ahmad-Reza Sadeghi, Gene Tsudik.


### Main concepts from the paper reflected in this project

1. **Runtime control-flow measurement (not only static hash attestation)**
   - Implemented through per-event kernel capture + monitor verification.

2. **Cumulative path fingerprinting**
   - Implemented with running hash mixing (`cfa_mix`) in the monitor.

3. **Loop handling to avoid combinatorial path explosion**
   - Implemented with loop contexts, per-loop path buckets, and folding at loop exit.

4. **Call/return matching**
   - Implemented with monitor shadow stack + `policy_call_returns`.

5. **Detecting both illegal edges and unauthorized-but-valid-path behavior**
   - Illegal transitions trigger violations.
   - Loop-path and iteration-sensitive behavior affects folded digest state.

### Important note on scope

This prototype uses software instrumentation and monitor logic to emulate C-FLAT-style behavior in the S3K/QEMU environment. It is a research/teaching prototype and not a drop-in replacement for the exact TrustZone architecture from the original paper.

---

## 3) Kernel changes introduced 

The following kernel/common changes were introduced.

### 3.1 New kernel CFA module

- **Added:** `kernel/inc/cfa.h`
- **Added:** `kernel/src/cfa.c`

What it adds:
- CFA event ring buffer (`CFA_BUF_SIZE = 1024`)
- APIs:
  - `cfa_init()`
  - `cfa_push_event(...)`
  - `cfa_get_event(...)`
- Sticky overflow flag (`cfa_overflow`) and overflow protection in push path

Security/robustness intent from commit comments:
- `VULN-4 FIX`: detect and signal buffer overflow before write.

### 3.2 Trap/exception path instrumentation support

- **Modified:** `kernel/src/exception.c`

What changed:
- Added handling for `BREAKPOINT` (`mcause == 0x3`) to process `ebreak` probes.
- Reads probe metadata from registers (`t0` = bbid, `t1` = event_type).
- Added branch-probe decode path (`CFA_EVENT_BRANCH_PROBE = 0x80`) with branch target decoding.
- Pushes CFA events to kernel buffer via `cfa_push_event(...)`.
- Advances `PC` over trapped `ebreak` instruction and resumes execution.

Security/robustness intent from commit comments:
- `VULN-6 FIX`: event type taken from `t1` encoding.

### 3.3 Kernel init integrates CFA subsystem

- **Modified:** `kernel/src/kernel.c`

What changed:
- Includes `cfa.h`
- Calls `cfa_init()` during `kernel_init()`
- Logs `# cfa initialized`

### 3.4 New syscall for monitor event retrieval (kernel side)

- **Modified:** `kernel/inc/syscall.h`
- **Modified:** `kernel/src/syscall.c`

What changed:
- Added syscall ID: `SYS_CFA_GET_EVENT`
- Added validator/handler entries.
- Added `handle_cfa_get_event(...)`:
  - allows only PID 0 (monitor) to consume events,
  - returns `old_pc`, `new_pc`, `event_type` via `a0/a1/a2` on success,
  - returns error code in `t0`.

Security/robustness intent from commit comments:
- `VULN-5 FIX`: enforce monitor-only access to CFA events.

### 3.5 User-space syscall API extension (common lib)

- **Modified:** `common/inc/s3k/syscall.h`
- **Modified:** `common/src/s3k/syscall.c`

What changed:
- Added user API:
  - `s3k_err_t s3k_cfa_get_event(uint64_t *old_pc, uint64_t *new_pc, uint8_t *event_type, uint8_t *is_call, uint8_t *is_return);`
- Added userspace syscall dispatcher enum case `S3K_SYS_CFA_GET_EVENT`.
- Userspace wrapper decodes `event_type` and derives `is_call` / `is_return` bits.

---

## 4) Project structure (inside this folder)

- `app/`
  - monitored application
  - `policy_to_consts.py`: converts `cfa_policy.json` to C constants header (`monitor/policy.h`)
- `monitor/`
  - runtime verifier and enforcer
- `llvm-pass/`
  - LLVM pass (`CFAGeneratorPass`) used to extract static CFG metadata
- `merge_cfg.py`
  - merges dynamically discovered edges from QEMU logs into static policy JSON
- `cfa_policy.json`
  - policy database used to generate `monitor/policy.h`
- `test.sh`
  - end-to-end automation script (build, profile, merge, rebuild)
- `Makefile`
  - build and run entrypoints for app/monitor/jop variants

---

## 5) Prerequisites

You need:

1. S3K workspace toolchain (from repo root docs):
   - RISC-V GCC/binutils (`riscv64-unknown-elf-*`)
   - QEMU system for RISC-V (`qemu-system-riscv64`)

2. LLVM toolchain on macOS (paths currently hardcoded in `Makefile`):
   - `clang`, `opt`, `llc` expected under:
     - `/opt/homebrew/opt/llvm/bin/`

3. Python 3:
   - for `policy_to_consts.py` and `merge_cfg.py`

4. `gtimeout` on macOS:
   - used by `policy_dynamic` and `test.sh`
   - usually provided by `coreutils` (GNU timeout)

---

## 6) How to run

From this directory:

```bash
cd projects/project
```

### 6.1 Quick build and run (current policy)

```bash
make clean
make monitor CFA_STRICT_ENFORCEMENT=1
make qemu
```

Notes:
- `make qemu` builds/starts kernel + monitor + app according to `Makefile`.
- strict mode is controlled at monitor compile time with `CFA_STRICT_ENFORCEMENT`.

### 6.2 Full profiling-to-enforcement pipeline (recommended)

Option A (automated):

```bash
chmod +x test.sh
./test.sh
```

What `test.sh` does:
1. builds LLVM pass,
2. builds app + static CFG policy,
3. generates `monitor/policy.h`,
4. runs QEMU in learning mode for a bounded time,
5. merges dynamic edges from logs into `cfa_policy.json`,
6. regenerates policy header and rebuilds final system.

Option B (manual equivalent):

```bash
# 1) Build static artifacts
make clean
make app
python3 app/policy_to_consts.py

# 2) Build and run in profiler mode (strict=0)
make clean
make monitor CFA_STRICT_ENFORCEMENT=0
gtimeout 5s make qemu 2>&1 | tee qemu.log || true

# 3) Merge dynamic edges and regenerate header
python3 merge_cfg.py cfa_policy.json qemu.log
python3 app/policy_to_consts.py

# 4) Rebuild in strict mode
make clean
make monitor CFA_STRICT_ENFORCEMENT=1
make qemu
```

### 6.3 JOP simulation path

```bash
make clean
make jop
make monitor CFA_STRICT_ENFORCEMENT=1
make jop_simulation
```

---

## 7) How to check it works

Use these checks during/after QEMU runs.

### 7.1 Build-time checks

- `monitor/policy.h` exists and is up to date after policy generation.
- build artifacts exist in `build/qemu_virt4/` for `kernel`, `monitor`, `app`.

### 7.2 Runtime checks in monitor output

Expected healthy signals:
- `CFA Monitor Started.`
- `CFA Event Received: ...`
- `CFA OK: ...`
- `CFA HASH STATE: ...`
- (optional) `CFA FOLDING: Loop ...`

Violation signals (strict mode):
- `[DYNAMIC_EDGE_DISCOVERED] src -> dst`
- `CFA: App Suspended. Attestation FAILED.`

### 7.3 Log-based verification commands

After capturing output (for example in `qemu.log`):

```bash
# discovered unknown transitions
grep "\[DYNAMIC_EDGE_DISCOVERED\]" qemu.log

# successful validated edges
grep "CFA OK:" qemu.log

# strict-mode enforcement events
grep "Attestation FAILED" qemu.log

# loop folding evidence
grep "CFA FOLDING:" qemu.log
```

### 7.4 Policy merge verification

After `merge_cfg.py`:
- script prints number of merged edges,
- `cfa_policy.json` edge count increases when new dynamic edges exist,
- regenerated `monitor/policy.h` contains those new edge IDs.

---

## 8) Typical troubleshooting

1. **`gtimeout: command not found`**
   - install GNU coreutils and ensure `gtimeout` is on PATH.

2. **LLVM binaries not found at `/opt/homebrew/opt/llvm/bin/...`**
   - install LLVM via Homebrew or adjust paths in this folder `Makefile`.

3. **No dynamic edges discovered**
   - this can be normal for deterministic workloads already covered by static policy.

4. **Immediate strict-mode suspension**
   - run profiler mode first, merge dynamic edges, regenerate policy, then rebuild strict mode.

5. **Policy/header mismatch after edits**
   - re-run:
     - `python3 app/policy_to_consts.py`
     - clean + rebuild monitor.

---

## 9) Security and research notes

- This is a research prototype that demonstrates C-FLAT-like control-flow attestation ideas on S3K.
- The commit introduces explicit checks for ring buffer overflow and access control to event consumption.
- As with C-FLAT, correctness depends on trusted monitoring path + accurate policy extraction + complete instrumentation coverage.

---

## 10) Minimal command cheat sheet

```bash
# from projects/project

# Full pipeline
./test.sh

# Fast strict build + run
make clean && make monitor CFA_STRICT_ENFORCEMENT=1 && make qemu

# Learning run with log
make clean && make monitor CFA_STRICT_ENFORCEMENT=0 && gtimeout 5s make qemu 2>&1 | tee qemu.log || true

# Merge new edges and rebuild strict
python3 merge_cfg.py cfa_policy.json qemu.log
python3 app/policy_to_consts.py
make clean && make monitor CFA_STRICT_ENFORCEMENT=1
```
