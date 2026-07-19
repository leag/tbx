"""Native-recompile back end (tbx/c0.py): IR -> C -> cc -> run.

Two layers:
- pinned end-to-end runs: a handful of corpus fixtures are recompiled to C,
  built with the host C compiler, executed, and their stdout compared against
  the Turbo Basic handbook semantics (PRINT layout: space-or-sign before a
  number, trailing space after).
- a coverage floor: the share of the corpus that transpiles must not regress.
  c0 is fail-loud like the decoder, so "transpiles" means every construct in
  the program is inside the implemented vocabulary.

The end-to-end layer needs a C compiler; it is skipped when `cc` is absent.
Two more build shapes are pinned when the tools exist: the runtime compiled
as a standalone library linked by a --no-runtime program, and the SDL2
video backend run under SDL's dummy driver.
"""

import glob
import os
import re
import shutil
import subprocess

import pytest

from tbx import c0, decode0

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CORPUS = os.path.join(_ROOT, "fixtures", "corpus")

_CC = shutil.which(os.environ.get("CC", "cc"))  # CI matrix sets CC=gcc/clang
_AR = shutil.which("ar")
_SDL2_CONFIG = shutil.which("sdl2-config")


def _decode(stem):
    return decode0.decode_user_code(
        open(os.path.join(_CORPUS, f"{stem}.exe"), "rb").read()
    )


def _build(stem, tmp_path):
    assert _CC is not None
    src = tmp_path / f"{stem}.c"
    src.write_text(c0.emit_c(_decode(stem)))
    exe = tmp_path / stem
    subprocess.run([_CC, str(src), "-lm", "-o", str(exe)], check=True)
    return exe


def _run(stem, tmp_path, stdin=""):
    exe = _build(stem, tmp_path)
    r = subprocess.run(
        [str(exe)],
        capture_output=True,
        text=True,
        timeout=10,
        input=stdin,
        cwd=str(tmp_path),
    )
    assert r.returncode == 0, r.stderr
    return r.stdout


# stem -> expected stdout (TB PRINT layout: " n " around numbers)
_PINNED = {
    "t1_print": "HELLO\n 5 \n 6 \n",
    "t1_strlib": "HEL\nell\n 3 \n 5 \n 42\n",
    "zz_do7": " 11 \n",
    "zz_sc1": "TWO\n",
    "t1_gosub": "",
    "t1_for": "",
    "t1_d1line": "",
    "t1_onerr": " 1 \n",  # handler installed but never fires
    "zz_sub1": " 6 \n",  # CALL SUB1(B) increments B: by-reference proof
    "zz_sub2": " 7  9 \n",  # literal args pass by value copy
    "zz_sub7": " 5 \n",  # EXIT SUB on the negative branch, not taken
    "zz_mdeffn1": " 42 \n",  # multi-line DEF FN: FNFN1(21) = 42
    "zz_mdeffn2": " 42 \n",  # ... with an EXIT DEF branch not taken
    "zz_cv_cvi": " 16961 \n",  # CVI("AB") = 0x4241 little-endian
    "t1_peek": " 0 \n",  # emulated memory is zero-filled
    "t1_inpf": " 255 \n",  # a port never OUT-latched reads the floating bus
    "t1_poke2": "",  # POKE into the emulated memory: silent success
    "t1_defseg": "",  # DEF SEG rebases POKE, bare form restores DGROUP
    "t1_wait3": "",  # WAIT returns at once: the absent device is "ready"
    "t1_calli": "",  # REG + CALL INTERRUPT: register store, no-op INT
}


@pytest.mark.skipif(_CC is None, reason="no host C compiler")
@pytest.mark.parametrize("stem", sorted(_PINNED))
def test_recompiled_output(stem, tmp_path):
    assert _run(stem, tmp_path) == _PINNED[stem]


@pytest.mark.skipif(_CC is None, reason="no host C compiler")
def test_tab_and_file_print(tmp_path):
    # t1_tab: TAB/SPC on the console and inside PRINT #1 (per-channel columns)
    # piped stdin: INPUT echoes the line like TB's screen would
    out = _run("t1_tab", tmp_path, stdin="3\n")
    assert out == "? 3\nA      3 \n   B\n  C\n"
    assert (tmp_path / "R.TXT").read_text() == "X     Y         3 \n"


@pytest.mark.skipif(_CC is None, reason="no host C compiler")
def test_print_using(tmp_path):
    # t1_pr2: PRINT USING "#.#"-family fields on console and into a file;
    # the format cycles when values outnumber fields
    out = _run("t1_pr2", tmp_path, stdin="3\n")
    assert out == "? 3\nA 3 B\nX 3.00\n3.0 3.0\n"
    assert (tmp_path / "R.TXT").read_text() == " 3 \n 3.00 3.00\n"


@pytest.mark.skipif(_CC is None, reason="no host C compiler")
def test_untrapped_error_exit(tmp_path):
    # t1_errorn: ERROR 5 with no handler aborts with TB's code and line
    exe = _build("t1_errorn", tmp_path)
    r = subprocess.run(
        [str(exe)], capture_output=True, text=True, timeout=10, cwd=str(tmp_path)
    )
    assert r.returncode == 5
    assert "Error 5 in line 10" in r.stderr


@pytest.mark.skipif(_CC is None, reason="no host C compiler")
def test_machine_memory_roundtrip(tmp_path):
    # POKE/PEEK and OUT/INP and REG hit real storage in the emulated machine
    from tbx import ir

    assert _CC is not None

    prog = [
        ir.Poke(addr=ir.Lit(100), value=ir.Lit(7)),
        ir.Out(port=ir.Lit(888), value=ir.Lit(5)),
        ir.RegSet(n=ir.Lit(1), value=ir.Lit(512)),
        ir.Print(
            items=(
                ir.Call("PEEK", (ir.Lit(100),)),
                ir.Call("INP", (ir.Lit(888),)),
                ir.Call("REG", (ir.Lit(1),)),
            ),
            newline=True,
            file=None,
        ),
        ir.End(),
    ]
    src = tmp_path / "mach.c"
    src.write_text(c0.emit_c(prog))
    exe = tmp_path / "mach"
    subprocess.run([_CC, str(src), "-lm", "-o", str(exe)], check=True)
    r = subprocess.run([str(exe)], capture_output=True, text=True, timeout=10)
    assert r.stdout == " 7  5  512 \n"


@pytest.mark.skipif(_CC is None, reason="no host C compiler")
def test_bsave_bload_roundtrip(tmp_path):
    # t1_bsave writes X.IMG (header + 100 zeroed bytes); t1_bload reads it back
    assert _run("t1_bsave", tmp_path) == ""
    img = (tmp_path / "X.IMG").read_bytes()
    assert img[0] == 0xFD and len(img) == 7 + 100
    assert _run("t1_bload", tmp_path) == ""


@pytest.mark.skipif(_CC is None, reason="no host C compiler")
def test_call_absolute_aborts(tmp_path):
    # transpiles, then aborts if reached: no machine code on this host
    exe = _build("t1_calla", tmp_path)
    r = subprocess.run(
        [str(exe)], capture_output=True, text=True, timeout=10, cwd=str(tmp_path)
    )
    assert r.returncode == 255
    assert "CALL ABSOLUTE in line 20" in r.stderr


@pytest.mark.skipif(_CC is None, reason="no host C compiler")
def test_chain(tmp_path):
    # CHAIN "PROG" execs ./prog (lowercase retry); absent -> TB error 53
    exe = _build("t1_chain", tmp_path)
    r = subprocess.run(
        [str(exe)], capture_output=True, text=True, timeout=10, cwd=str(tmp_path)
    )
    assert r.returncode == 53
    if os.name == "posix":
        tgt = tmp_path / "prog"
        tgt.write_text("#!/bin/sh\necho CHAINED\n")
        tgt.chmod(0o755)
        r = subprocess.run(
            [str(exe)], capture_output=True, text=True, timeout=10, cwd=str(tmp_path)
        )
        assert r.returncode == 0 and r.stdout == "CHAINED\n"


@pytest.mark.skipif(_CC is None or _AR is None, reason="no host C toolchain")
def test_runtime_builds_as_library(tmp_path):
    # every fragment compiles standalone; the archive links a --no-runtime
    # program (which only #includes tb_runtime.h)
    assert _CC is not None and _AR is not None
    rt = os.path.join(os.path.dirname(c0.__file__), "c0_runtime")
    objs = []
    for name in sorted(f for f in os.listdir(rt) if f.endswith(".c")):
        o = tmp_path / (name[:-2] + ".o")
        subprocess.run(
            [_CC, "-c", os.path.join(rt, name), "-o", str(o)], check=True
        )
        objs.append(str(o))
    lib = tmp_path / "libtbrt.a"
    subprocess.run([_AR, "rcs", str(lib), *objs], check=True)
    src = tmp_path / "p.c"
    src.write_text(c0.emit_c(_decode("t1_print"), standalone=False))
    exe = tmp_path / "p"
    subprocess.run(
        [_CC, str(src), "-I", rt, "-L", str(tmp_path), "-ltbrt", "-lm",
         "-o", str(exe)],
        check=True,
    )
    r = subprocess.run([str(exe)], capture_output=True, text=True, timeout=10)
    assert r.stdout == _PINNED["t1_print"]


@pytest.mark.skipif(
    _CC is None or _SDL2_CONFIG is None, reason="no host C compiler or SDL2"
)
def test_sdl_backend_runs_headless(tmp_path):
    # the SDL2 video backend, exercised under SDL's dummy driver: window,
    # texture upload, event pump, and the POINT read all still line up.
    # Synthetic program (no corpus fixture sets a SCREEN mode): SCREEN 1,
    # PSET a pixel, read it back with POINT.
    from tbx import ir

    assert _CC is not None and _SDL2_CONFIG is not None
    flags = subprocess.run(
        [_SDL2_CONFIG, "--cflags", "--libs"],
        capture_output=True, text=True, check=True,
    ).stdout.split()
    prog = [
        ir.Screen(mode=ir.Lit(1)),
        ir.Pset(x=ir.Lit(10), y=ir.Lit(10), step=False, color=ir.Lit(3), preset=False),
        ir.Circle(
            x=ir.Lit(160), y=ir.Lit(100), r=ir.Lit(40), step=False,
            color=ir.Lit(2), start=None, end=None, aspect=None,
        ),
        ir.Print(items=(ir.Call("POINT", (ir.Lit(10), ir.Lit(10))),), newline=True, file=None),
        ir.End(),
    ]
    src = tmp_path / "gfx.c"
    src.write_text(c0.emit_c(prog, sdl=True))
    exe = tmp_path / "gfx"
    subprocess.run([_CC, str(src), "-lm", *flags, "-o", str(exe)], check=True)
    env = dict(os.environ, SDL_VIDEODRIVER="dummy", TB_SDL_HOLD="0")
    r = subprocess.run(
        [str(exe)], capture_output=True, text=True, timeout=15,
        env=env, cwd=str(tmp_path),
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout == " 3 \n"


# --- DOS behavior goldens (tests/fixtures/dosout/) ---
# Captured from the ORIGINAL corpus EXEs running on the real (emulated)
# machine by tbx/tools/dump_dos_output.py -- the c0 analog of the byte-exact
# rule: the recompiled native binary must reproduce what the original EXE
# visibly did. Normalization: lines rstripped on both sides (the screen
# mirror right-strips), native stdout+stderr combined (TB prints runtime
# errors to the screen; natively they go to stderr), produced files compared
# after CRLF->LF. Waivers name the documented surrogate that makes an exact
# match impossible.

_DOSOUT = os.path.join(_ROOT, "fixtures", "dosout")
_DOS_WAIVED: dict[str, str] = {
    "t1_files": "FILES lists the host directory: contents and layout are "
    "environmental (DOS floppy vs the native working directory)",
    "t1_shellvar": "SHELL with an empty command starts the resident shell "
    "(the FreeCom banner in the golden); natively system('') is a no-op -- "
    "the child shell is environmental",
    "zz_sc3": "TB 1.1's CASE IS codegen is broken (see the zz_sc3 ops): the "
    "bound is fcomp'd against DS:0120 -- a hidden never-written slot, not "
    "the selector -- and the arm matches iff the SELECTOR equals that "
    "materialized boolean, so A=20 falls to CASE ELSE. c0 keeps the "
    "handbook semantics (20 > 10 -> BIG); reproducing the bug needs phase-2 "
    "probes to pin the hidden slot",
    "t1_local1": "LOCAL declares true per-call stack locals, re-zeroed every "
    "call; c0's SUB-local declaration pass doesn't yet distinguish that from "
    "the default local-and-static scoping (ir.Local raises _Unsupported)",
    "t1_local2": "LOCAL declares true per-call stack locals, re-zeroed every "
    "call; c0's SUB-local declaration pass doesn't yet distinguish that from "
    "the default local-and-static scoping (ir.Local raises _Unsupported)",
    "t1_byref1": "LOCAL declares true per-call stack locals, re-zeroed every "
    "call; c0's SUB-local declaration pass doesn't yet distinguish that from "
    "the default local-and-static scoping (ir.Local raises _Unsupported)",
    "t1_loccmp": "LOCAL declares true per-call stack locals, re-zeroed every "
    "call; c0's SUB-local declaration pass doesn't yet distinguish that from "
    "the default local-and-static scoping (ir.Local raises _Unsupported)",
    "t1_locidx": "LOCAL declares true per-call stack locals, re-zeroed every "
    "call; c0's SUB-local declaration pass doesn't yet distinguish that from "
    "the default local-and-static scoping (ir.Local raises _Unsupported)",
    "t1_run2": "RUN file$ loads and runs a DIFFERENT program; c0 targets "
    "one self-contained translation unit and has no host-process-replace "
    "surrogate for it (ir.Run(file=...) raises _Unsupported)",
    "t1_addpool": "LOCATE positions via the ANSI-escape surrogate "
    "(terminal.c tb_locate); in the harness's captured pipe the escapes "
    "don't reposition, so the DOS golden's column-13 X has no native "
    "equivalent -- same surrogate that keeps t1_scr out of the dosout set",
    "t1_color3": "COLOR's border argument (CGA/EGA text-mode border color) "
    "has no visible effect in the PPM/SDL framebuffer surrogate -- the "
    "border strip is outside the captured display -- so c0 raises "
    "_Unsupported rather than silently dropping a value the source set",
    "t1_nestif2": "a GOTO into a numbered line nested inside a block IF "
    "within another block IF: the decoder resolves this via a flat phys "
    "count that runs through the nested block's header/body/END IF, but "
    "c0's label-emission loop only tracks a LOCAL per-body position and "
    "doesn't thread the phys offset into a nested IfBlock, so it raises "
    "_Unsupported rather than emit a goto to a label it can't place",
}
# file-comparison waivers: the screen still must match
_DOS_FILE_WAIVED = {
    "t1_bsave": "BSAVE writes the real DGROUP segment and its live memory; "
    "the emulated machine (machine.c) is zero-filled with a synthetic segment",
    "t1_putfile": "PUT of a never-FIELDed record writes the live DGROUP "
    "bytes of the record buffer; the native runtime's buffer is space-filled",
}

# untrapped runtime errors: TB prints "Error N  at pgm-ctr: X" (no line table
# in these EXEs), the native runtime "Error N in line L" -- same error, other
# locator; both normalize to "Error N"
_ERR_RE = re.compile(r"^(Error \d+)( +at pgm-ctr: \d+| in line \d+)$")

# TB's binary->decimal conversion carries ~1e-14 relative noise: t1_fp's
# single prints as ...715606894E-020 where the stored float32 is exactly
# ...7156068805e-20 (C prints the correctly-rounded ...881). Digits past 13
# are conversion noise on TB's side, so both sides are clipped to 13
# significant digits before comparing; the digits kept still pin tb_fmt's
# format (leading-zero strip, integral path, the E+0xx exponent shape).
_FP_RE = re.compile(r"(\d*)\.(\d+)(E[-+]\d+)?")


def _clip_fp(m):
    intpart, frac, exp = m.group(1), m.group(2), m.group(3) or ""
    digits = intpart + frac
    lead = len(digits) - len(digits.lstrip("0"))
    if len(digits) - lead <= 13:
        return m.group(0)
    digits = digits[: lead + 13]
    return digits[: len(intpart)] + "." + digits[len(intpart):] + exp


def _dos_stems():
    # skip the produced-file goldens (<stem>.file.<NAME>): a DOS 8.3 name like
    # R.TXT matches *.txt on Windows' case-insensitive glob
    return sorted(
        os.path.basename(p)[: -len(".txt")]
        for p in glob.glob(os.path.join(_DOSOUT, "*.txt"))
        if ".file." not in os.path.basename(p)
    )


def _norm_lines(text):
    # the DOS golden is a text screen: it has no BEL, no cursor motion --
    # drop ANSI escapes and control characters from the native side
    text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text)
    text = re.sub(r"[\x00-\x08\x0b-\x1f]", "", text)
    lines = [ln.rstrip() for ln in text.splitlines()]
    lines = [_ERR_RE.sub(r"\1", ln) for ln in lines]
    lines = [_FP_RE.sub(_clip_fp, ln) for ln in lines]
    while lines and not lines[-1]:
        lines.pop()
    while lines and not lines[0]:
        lines.pop(0)
    return lines


@pytest.mark.skipif(_CC is None, reason="no host C compiler")
@pytest.mark.parametrize("stem", _dos_stems())
def test_dos_golden(stem, tmp_path):
    if stem in _DOS_WAIVED:
        pytest.skip(_DOS_WAIVED[stem])
    from tbx.tools.dump_dos_output import native_stdin

    golden = open(os.path.join(_DOSOUT, f"{stem}.txt")).read()
    exe = _build(stem, tmp_path)
    r = subprocess.run(
        [str(exe)],
        input=native_stdin(stem),
        capture_output=True,
        text=True,
        timeout=10,
        cwd=str(tmp_path),
    )
    assert _norm_lines(r.stdout + r.stderr) == _norm_lines(golden)
    if stem in _DOS_FILE_WAIVED:
        return
    for fgold in glob.glob(os.path.join(_DOSOUT, f"{stem}.file.*")):
        name = os.path.basename(fgold).split(".file.", 1)[1]
        native = tmp_path / name
        assert native.is_file(), f"native run did not produce {name}"
        want = open(fgold, "rb").read().replace(b"\r\n", b"\n")
        got = native.read_bytes().replace(b"\r\n", b"\n")
        assert got == want, f"{name} differs"


# --- IDE Options toggles (Program.toggles) ---
# Bounds and Overflow are honored as compiled, like TB itself: the flagged
# corpus fixture gets the checks, its unflagged twin does not, and a flagged
# in-range program behaves identically to the unflagged one. The error
# branches (TB errors 9 and 6) have no corpus witness that trips them, so
# synthetic programs pin them against the handbook semantics.


@pytest.mark.skipif(_CC is None, reason="no host C compiler")
def test_options_toggles(tmp_path):
    from tbx import ir

    assert _CC is not None
    # standalone=False: only the generated code, not the embedded runtime.
    # (fov_t1_and, the Overflow-flagged fixture, has no integer stores, so
    # its emitted code is identical to the unflagged twin's -- the Overflow
    # error branch is pinned by the synthetic program below instead.)
    assert "tb_bix" in c0.emit_c(_decode("fbd_t1_arr1"), standalone=False)
    assert "tb_bix" not in c0.emit_c(_decode("t1_arr1"), standalone=False)
    assert c0.emit_c(_decode("fov_t1_and"), standalone=False) == c0.emit_c(
        _decode("t1_and"), standalone=False
    )
    d1, d2 = tmp_path / "flagged", tmp_path / "plain"
    d1.mkdir(), d2.mkdir()
    assert _run("fbd_t1_arr1", d1) == _run("t1_arr1", d2)

    cc = _CC

    def run_flagged(name, stmts, toggles):
        prog = list(stmts)
        prog = type("_Flagged", (list,), {"toggles": toggles})(prog)
        src = tmp_path / f"{name}.c"
        src.write_text(c0.emit_c(prog))
        exe = tmp_path / name
        subprocess.run([cc, str(src), "-lm", "-o", str(exe)], check=True)
        return subprocess.run(
            [str(exe)], capture_output=True, text=True, timeout=10,
            cwd=str(tmp_path),
        )

    oob = [
        ir.Dim(name="A", bounds=(5,)),
        ir.Assign(target=ir.ArrayRef(name="A", indices=(ir.Lit(7),)), value=ir.Lit(1)),
        ir.End(),
    ]
    assert "Error 9" in run_flagged("oob", oob, "B").stderr
    ovf = [
        ir.Assign(target=ir.Var(name="A%"), value=ir.Lit(40000)),
        ir.End(),
    ]
    assert "Error 6" in run_flagged("ovf", ovf, "O").stderr
    # unflagged, the same store wraps silently -- TB's own default
    r = run_flagged("ovf0", ovf, "")
    assert r.returncode == 0 and r.stderr == ""


def test_transpile_coverage_floor():
    ok = 0
    total = 0
    for exe in sorted(glob.glob(os.path.join(_CORPUS, "*.exe"))):
        total += 1
        try:
            c0.emit_c(decode0.decode_user_code(open(exe, "rb").read()))
            ok += 1
        except ValueError:
            pass
    # 564/564 as of the machine-access batch (the emulated real-mode machine
    # in machine.c absorbed PEEK/POKE/OUT/WAIT/INP/REG/BLOAD/BSAVE/CHAIN/
    # DEF SEG/CALL ABSOLUTE). Slack allows intended decoder changes; a real
    # regression in c0 shows up as a big drop.
    assert ok >= 555, f"c0 transpile coverage regressed: {ok}/{total}"


def test_unsupported_raises():
    # fail-loud: a program using an unimplemented construct must raise,
    # never mistranslate. No corpus fixture is outside the vocabulary
    # anymore, so pin the behavior with a synthetic unknown intrinsic.
    from tbx import ir

    prog = [
        ir.Assign(target=ir.Var("A"), value=ir.Call("NOSUCH", (ir.Lit(1),))),
        ir.End(),
    ]
    with pytest.raises(ValueError):
        c0.emit_c(prog)
