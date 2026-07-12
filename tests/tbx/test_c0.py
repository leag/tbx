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
"""

import glob
import os
import shutil
import subprocess

import pytest

from tbx import c0, decode0

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CORPUS = os.path.join(_ROOT, "fixtures", "corpus")

_CC = shutil.which("cc")


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
}


@pytest.mark.skipif(_CC is None, reason="no host C compiler")
@pytest.mark.parametrize("stem", sorted(_PINNED))
def test_recompiled_output(stem, tmp_path):
    assert _run(stem, tmp_path) == _PINNED[stem]


@pytest.mark.skipif(_CC is None, reason="no host C compiler")
def test_tab_and_file_print(tmp_path):
    # t1_tab: TAB/SPC on the console and inside PRINT #1 (per-channel columns)
    out = _run("t1_tab", tmp_path, stdin="3\n")
    assert out == "? A      3 \n   B\n  C\n"
    assert (tmp_path / "R.TXT").read_text() == "X     Y         3 \n"


@pytest.mark.skipif(_CC is None, reason="no host C compiler")
def test_untrapped_error_exit(tmp_path):
    # t1_errorn: ERROR 5 with no handler aborts with TB's code and line
    exe = _build("t1_errorn", tmp_path)
    r = subprocess.run(
        [str(exe)], capture_output=True, text=True, timeout=10, cwd=str(tmp_path)
    )
    assert r.returncode == 5
    assert "Error 5 in line 10" in r.stderr


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
    # 348/564 as of the error-trapping/SUB/file-IO batch; keep some slack for
    # intended decoder changes, but a real regression in c0 shows up as a big drop.
    assert ok >= 330, f"c0 transpile coverage regressed: {ok}/{total}"


def test_unsupported_raises():
    # fail-loud: a program using an unimplemented construct must raise,
    # never mistranslate (t1_line uses graphics LINE).
    with pytest.raises(ValueError):
        c0.emit_c(_decode("t1_line"))
