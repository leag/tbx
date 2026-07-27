# v86 Invalid-Opcode Root Cause

**Date:** 2026-06-07
**Status:** Diagnosis complete — gate selects Phase-2 **branch (b)** (v86 source patch).

## Observations

Diagnostic harness: `oracle/tb_v86_diag.js` (probe `oracle/probes/fp.bas` = `X#=1.5# : Y#=X#*2.0# : PRINT Y#`).

| signal | value |
|--------|-------|
| Guest screen at fault | `Invalid Opcode at 53C6 168C ...` (IP=53C6, CS=168C) |
| Linear fault address | `0x1BC86` |
| Faulting opcode bytes | `DF 66 EE ...` |
| Decoded instruction | `DF /4` = **FBLD m80** (x87 load packed BCD) — ModRM `0x66` → mod=01, reg=4, rm=6 |
| v86 debug-wasm panic | `panicked at src/rust/cpu/fpu.rs:439 ... assertion failed: false` in `instr_DF_4_mem` (`fpu_unimpl`) |

The debug wasm (`v86-debug.wasm`) panics on the **same** instruction (`instr_DF_4_mem`) during FreeDOS boot; the release wasm (`v86.wasm`) survives boot but faults on `DF /4` once Turbo Basic's floating-point code runs.

Why a minimal `PRINT "HI"` program would not trip this but `fp.bas` does: Turbo Basic's numeric I/O uses the 8087 packed-BCD path (decimal string ↔ 80-bit BCD ↔ extended float) for reading/printing floating-point values. That path executes `FBLD` (and `FBSTP`), which v86 does not implement.

## Classification

- [ ] (a) JIT-only bug — **RULED OUT.** `instr_DF_4_mem` is unimplemented in v86's CPU *core* (`fpu.rs`), not its JIT; it affects both JIT and interpreter. (The debug wasm asserts in the shared instruction handler.)
- [x] (b) **Unimplemented decoder opcode** — `DF /4` (FBLD) is a real x87 instruction DOSBox executes; v86 stubs it with `fpu_unimpl`.
- [ ] (c) FPU/environment config — N/A; no config knob enables an unimplemented instruction.
- [ ] (d) Fixed upstream — **CHECKED, INSUFFICIENT.** Upstream `master` (npm latest `0.5.360`) now implements **FBSTP** (`fpu_fbstp`, DF /6) but **FBLD (DF /4) is still missing**. A version bump alone does not fix the observed fault.

## Recommended Phase-2 branch: (b) — patch v86 Rust source + rebuild WASM

Implement **FBLD** (`instr_DF_4_mem` → a new `fpu_fbld`) in `src/rust/cpu/fpu.rs`: read the 10-byte (80-bit) packed-BCD operand (9 bytes = 18 decimal digits + 1 sign byte), convert to an integer, and push it onto the FP stack — the inverse of the existing `fpu_fbstp`. Rebuild `v86.wasm` and vendor it into `oracle/`.

Building from upstream `master` (or a recent tag) gets the already-implemented `fpu_fbstp` for free; we add `fpu_fbld`. Verify our build also handles `DF /6` (FBSTP), which Turbo Basic's float→decimal print path uses, so the full FP I/O round-trip works.

### Build prerequisites (NOT yet installed on this machine — gating decision)

- `wasm32-unknown-unknown` Rust std (system `rustc` 1.96 present, but target stdlib absent; no `rustup`).
- `wasm-opt` (binaryen) — not on PATH (may be optional for a debug/unoptimized wasm).
- v86 source build (`make build` / cargo) toolchain. The JS loader (`libv86.js`) can be reused unchanged — only the `.wasm` blob needs rebuilding — so closure-compiler is **not** required.

## Diagnostic harness notes (plan assumptions that were wrong)

1. `v86-debug.wasm` panics at boot on the unimplemented FPU op, so it cannot be the primary capture path. The harness attempts it, detects the WASM panic via `uncaughtException`, and falls back to the release wasm.
2. `cpu_exception_hook` does not fire in v86 0.5.x. The working capture is screen-scrape of `Invalid Opcode at CS IP` + `read_memory` for the opcode bytes.

These were folded into `tb_v86_diag.js`; the original `cpu_exception_hook` wiring is retained as a best-effort first attempt.
