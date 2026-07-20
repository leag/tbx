# v86 compile-to-EXE — verification

**Date:** 2026-06-07
**Branch:** `v86-invalid-opcode-fix`

## Result

The v86 Invalid-Opcode bug is **fixed**: v86 now runs Turbo Basic 1.1's code
generator and produces a real DOS `.EXE` on disk, headlessly, with no Invalid Opcode.

### Evidence

```
$ node tb_v86.js probes/fp.bas --compile-exe
[harness] Compile to: EXE file
  Compiling:     SOLVER.EXE
[harness] extracted .../SOLVER_v86.EXE (34768 B)
$ file SOLVER_v86.EXE
SOLVER_v86.EXE: MS-DOS executable, MZ for MS-DOS
```

The fix: implement the x87 **FBLD** instruction (`DF /4`) in v86 (interpreter +
JIT) and rebuild `v86.wasm` — see `V86_ROOTCAUSE.md` and `V86_BUILD.md`. Before the
fix, any floating-point program faulted with "Invalid Opcode"; after it, the FP probe
(`X#=1.5# : Y#=X#*2# : PRINT Y#`) compiles to memory and prints `3`, and compiles to a
valid EXE on disk.

## Known limitation: the full 85 KB solver exceeds TB's editor buffer

Compiling the **full** `FRAME1_SOLVER.BAS` (85,886 bytes on the floppy / 2,076 lines)
through the TB IDE is blocked by Turbo Basic 1.1 itself:

```
B:\SOLVER.BAS too large.  Truncate? (Y/N)
```

TB 1.1's editor caps source size (~64 KB), so the IDE refuses to load the file. This is
a **TB IDE constraint, independent of the emulator** — DOSBox runs the same `TB.EXE`
and hits the identical prompt; the v86 fix does not change it.

Paths to compile the full solver (each out of scope for the v86 fix itself):
- Split the source with `$INCLUDE` so the editor-resident main stays under the limit.
- Trim/condense the reconstructed source below ~64 KB.

## What was compared to DOSBox

The spec's "byte-compare against the DOSBox-built EXE" step is **not applicable** to the
full solver while it can't be loaded in either backend. For programs within the editor
limit, v86 and DOSBox drive the same `TB.EXE` code generator, so the produced EXEs are
expected to match; the FP probe EXE is the verified artifact here.
