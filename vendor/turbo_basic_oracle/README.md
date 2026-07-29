# TurboBasic 1.1 compiler oracle

A headless/automated TurboBasic 1.1 compiler used as ground truth: compile probe
`.BAS` programs and inspect the produced bytes (to calibrate encodings and
round-trip-verify reconstructed source). The supported backend is v86, fully
headless with no X or GUI dependency.

## v86 harness
`tb_v86.js` + `tb_v86_lib.js` boot FreeDOS (`freedos.img`, `bios/`) with TB on a
generated `work.img` via the `v86` WASM emulator — no X display, no xdotool,
deterministic scancode injection, guest-RAM reads.

- `node tb_v86.js <file.bas> [--run-ms N] [--rows a-b]` — load + Run (compile-to-memory).
- `node tb_v86.js <file.bas> --compile-exe` — set Options→Compile to→EXE file, Compile,
  and extract the produced `SOLVER.EXE` off the guest floppy (`get_disk_fdb` + mtools).
- `node tb_v86_diag.js [--probe f.bas]` — diagnostic harness (captures CPU faults).

**Stock v86 threw an Invalid Opcode in TB's code generator** because it didn't implement
the x87 `FBLD` instruction (`DF /4`) that TB's floating-point I/O uses. Fixed by
`oracle/vendor/v86.wasm` (rebuilt v86 with FBLD added); see `V86_ROOTCAUSE.md`,
`V86_BUILD.md`, `VERIFY.md`. `bootEmulator` loads the patched blob automatically.

Limitation: the full 85 KB `FRAME1_SOLVER.BAS` exceeds TB 1.1's ~64 KB editor buffer
("too large. Truncate?") — a Turbo Basic IDE constraint; see VERIFY.md.

The older `harness.js`/`drive.js`/`compile.js`/`mem.js`/`diag.js` scripts are the
earlier v86 experiments, kept for reference.

## Setup
- `npm install`  (pulls `v86`; not committed)
- `TB.EXE` and the disk images derive from `../Borland Turbo Basic 1.1 (5.25).7z`.

## Calibration results
See `CALIBRATION.md` (verified statement encodings + variable-allocation rule).
