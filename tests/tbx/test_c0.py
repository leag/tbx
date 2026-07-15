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

_CC = shutil.which("cc")
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
    "t1_filef": "",  # EOF(1) on a closed file returns -1, no output
    "zz_mdeffn1": " 42 \n",  # multi-line DEF FN: FNFN1(21) = 42
    "zz_mdeffn2": " 42 \n",  # ... with an EXIT DEF branch not taken
    "zz_cv_cvi": " 16961 \n",  # CVI("AB") = 0x4241 little-endian
    "t1_point": " 0 \n",  # POINT on a fresh framebuffer reads attribute 0
    "t1_peek": " 0 \n",  # emulated memory is zero-filled
    "t1_inpf": " 0 \n",  # a port never OUT-latched reads 0
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
    # texture upload, event pump, and the POINT read all still line up
    assert _CC is not None and _SDL2_CONFIG is not None
    flags = subprocess.run(
        [_SDL2_CONFIG, "--cflags", "--libs"],
        capture_output=True, text=True, check=True,
    ).stdout.split()
    for stem, expect in [("t1_point", " 0 \n"), ("t1_circle", "")]:
        src = tmp_path / f"{stem}.c"
        src.write_text(c0.emit_c(_decode(stem), sdl=True))
        exe = tmp_path / stem
        subprocess.run([_CC, str(src), "-lm", *flags, "-o", str(exe)], check=True)
        env = dict(os.environ, SDL_VIDEODRIVER="dummy", TB_SDL_HOLD="0")
        r = subprocess.run(
            [str(exe)], capture_output=True, text=True, timeout=15,
            env=env, cwd=str(tmp_path),
        )
        assert r.returncode == 0, r.stderr
        assert r.stdout == expect


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
_DOS_WAIVED: dict[str, str] = {}
# file-comparison waivers: the screen still must match
_DOS_FILE_WAIVED = {
    "t1_bsave": "BSAVE writes the real DGROUP segment and its live memory; "
    "the emulated machine (machine.c) is zero-filled with a synthetic segment",
}

# untrapped runtime errors: TB prints "Error N  at pgm-ctr: X" (no line table
# in these EXEs), the native runtime "Error N in line L" -- same error, other
# locator; both normalize to "Error N"
_ERR_RE = re.compile(r"^(Error \d+)( +at pgm-ctr: \d+| in line \d+)$")


def _dos_stems():
    return sorted(
        os.path.basename(p)[: -len(".txt")]
        for p in glob.glob(os.path.join(_DOSOUT, "*.txt"))
    )


def _norm_lines(text):
    lines = [ln.rstrip() for ln in text.splitlines()]
    lines = [_ERR_RE.sub(r"\1", ln) for ln in lines]
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
