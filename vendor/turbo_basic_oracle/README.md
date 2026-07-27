# TurboBasic 1.1 compiler oracle

A headless/automated TurboBasic 1.1 compiler used as ground truth: compile probe
`.BAS` programs and inspect the produced bytes (to calibrate the encoding and to
round-trip-verify reconstructed solver code). Two backends:

## DOSBox backend (works — used for all real compiles)
`TB.EXE`'s code generator runs correctly under DOSBox.

- `dbx.conf` mounts `oracle/dbx/` as `C:` and auto-launches `TB.EXE`.
- Run on an X/XWayland display: `SDL_VIDEODRIVER=x11 DISPLAY=:0 dosbox -conf dbx.conf &`
- Drive the IDE with `xdotool` (activate the window, then `xdotool key …` via XTEST;
  SDL1.2 ignores synthetic `--window` events). Screenshot with ImageMagick `import`.
- `tbc.sh "<line1>" "<line2>" …` writes `dbx/PROBE.BAS`, reloads + compiles, and
  leaves `dbx/PROBE.EXE` on the host (compiled EXEs land directly in the mounted dir).
- IDE notes: menus are `Alt-<letter>`; **in-menu keys need a held make→break (~120 ms)**;
  arrows need the E0 prefix; Load = `Alt-F, L, Enter` (accept `*.BAS`), `Enter` (pick);
  Compile-to-EXE is set in `Options → Compile to → EXE file`. DOSBox **caches the
  mounted directory**, so a *new* filename needs a DOSBox restart to appear (overwriting
  an existing file is seen fine). Source files must use **CRLF** line endings.

## v86 backend (works — fully headless, no X)
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
("too large. Truncate?"), a TB constraint shared with the DOSBox backend — see VERIFY.md.

The older `harness.js`/`drive.js`/`compile.js`/`mem.js`/`diag.js` scripts are the
earlier v86 experiments, kept for reference.

## Setup
- `npm install`  (pulls `v86`; not committed)
- `TB.EXE` and the disk images derive from `../Borland Turbo Basic 1.1 (5.25).7z`.

## Calibration results
See `CALIBRATION.md` (verified statement encodings + variable-allocation rule).

## Direct text harness (no screenshots) — `mirror.py`
`ptrace_scope=1` forbids reading an unrelated DOSBox's memory, but a process may
read its own children. `mirror.py` launches DOSBox as a child, locates the 80x25
text-mode video buffer (guest `0xB8000`) once by finding the menu text, then
continuously decodes it to `oracle/screen.txt`. Drive with `xdotool` and read the
screen with a plain file read (and `grep`/wait-for-text), instead of `import` PNGs.

  python3 mirror.py &        # owns DOSBox as a child, mirrors video memory
  cat screen.txt             # current 80x25 screen as text
`memprobe.py` is the one-shot feasibility probe that established this.
