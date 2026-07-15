# c0_runtime — the Turbo Basic runtime behind `tbx --emit-c`

Standalone C units: every `.c` here includes `tb_runtime.h` and compiles on
its own. `tbx --emit-c` amalgamates header + fragments (manifest order,
include lines stripped) into one self-contained file; `make` builds the same
code as an ordinary library (`libtbrt.a`, `SDL=1` for the SDL2 backend) for
`tbx --emit-c --no-runtime` programs. gcc or clang required (generated
GOSUB/RETURN uses labels-as-values); POSIX or MinGW-w64 on Windows.

`TB_RT_VERSION` in `tb_runtime.h` names the interface revision. **Changing a
declaration in the header or any surrogate behavior below is a reviewable
event, like golden regeneration**: bump the version, update this file, and
re-capture/waive whatever dosout goldens the change affects.

## The evidence standard

Behavior is calibrated against `tests/fixtures/dosout/` — screens captured
from the ORIGINAL corpus EXEs running on the real (emulated) DOS machine.
Comments in the fragments cite the witnessing stem (e.g. "t1_seek dosout").
Where a modern host cannot reproduce the machine, the divergence is a
**documented surrogate**, listed here and named by the waivers in
`tests/tbx/test_c0.py`.

## Surrogate contract

**The emulated machine** (`machine.c`) — PEEK/POKE/DEF SEG/BLOAD/BSAVE
address a private zero-filled 1 MiB array standing in for the 8086 address
space; BIOS/DOS structures a program expects at a magic address read 0.
I/O ports are 64 K one-byte latches: OUT stores, INP reads the last OUT or
255 (the floating bus, t1_inpf) if none; WAIT returns immediately. REG is
real storage, CALL INTERRUPT passes registers through unchanged, CALL
ABSOLUTE aborts. CHAIN execs the named file as a native executable.

**Console** (`core.c`, `terminal.c`) — PRINT writes stdout with TB's number
image (16 significant digits, three-digit exponent, t1_fp); TB's own
binary→decimal conversion carries ~1e-14 tail noise, so goldens compare 13
significant digits. Screen control (CLS/LOCATE/COLOR) is ANSI escapes;
INKEY$/INSTAT read the terminal (or the SDL window under `-DTB_SDL`).
Untrapped errors print `Error N in line L` to stderr and exit(N) — the DOS
screen said `Error N  at pgm-ctr: X`; both normalize to `Error N`.

**Devices that do not exist here** — LPRINT goes to `TB_LPRINT_TXT` or the
null device, never the console (t1_lprint), with its own column state.
SOUND/BEEP and PLAY decode to PCM (`TB_PLAY_WAV` dumps at exit); joystick,
light pen (PEN errors while PEN OFF, t1_penf), and COM are absent — their
functions read 0 and their event sources never fire. ON TIMER is polled at
statement boundaries, like TB.

**Graphics** (`graphics.c`, `sdl.c`) — SCREEN n allocates a byte-per-pixel
framebuffer with CGA/EGA geometry; a graphics statement without a mode
raises error 5 like real TB (t1_circle). `TB_SCREEN_PPM` dumps the final
frame; `-DTB_SDL` renders into a real SDL2 window instead (`TB_SDL_HOLD=0`
skips the exit-wait; SDL's dummy driver runs headless).

**Files** (`fileio.c`) — DOS `\` separators translate to the host's; error
codes are witnessed (53 missing file, 52 bad channel, 54 SEEK on random
mode, 75/76 path errors). Random-access records are the calibrated 128
bytes; a never-FIELDed PUT writes a space-filled buffer where real DOS
exposed live DGROUP memory (t1_putfile waiver).

## Known divergences (open plan items)

- **Strings are NUL-terminated `char *`**: MK*$ images and CHR$(0) truncate
  (zz_cv_mk* waivers). The string-descriptor refactor (graduation plan
  phase 3) removes this class. String temporaries are never freed —
  short-lived programs only.
- **RND/RANDOMIZE** is the host `rand()`, not TB's generator (plan phase 3
  pins the real sequence via oracle probes).
- **Numerics evaluate in C double**, not TB's 80-bit x87 stack.
- **TB 1.1's CASE IS codegen bug is not reproduced** (zz_sc3 waiver): c0
  keeps the handbook semantics until probes pin the compiled shape's
  behavior across DGROUP layouts.

## IDE Options toggles

`Program.toggles` is honored as compiled: Bounds emits `tb_bix` subscript
checks (error 9), Overflow emits `tb_ichk`/`tb_lchk` integer-store checks
(error 6). Unflagged programs wrap silently, like TB's defaults.
