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


def _run(stem, tmp_path):
    assert _CC is not None
    src = tmp_path / f"{stem}.c"
    src.write_text(c0.emit_c(_decode(stem)))
    exe = tmp_path / stem
    subprocess.run([_CC, str(src), "-lm", "-o", str(exe)], check=True)
    r = subprocess.run(
        [str(exe)], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL
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
}


@pytest.mark.skipif(_CC is None, reason="no host C compiler")
@pytest.mark.parametrize("stem", sorted(_PINNED))
def test_recompiled_output(stem, tmp_path):
    assert _run(stem, tmp_path) == _PINNED[stem]


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
    # 272/564 at introduction; keep some slack for intended decoder changes,
    # but a real regression in c0 shows up as a big drop.
    assert ok >= 250, f"c0 transpile coverage regressed: {ok}/{total}"


def test_unsupported_raises():
    # fail-loud: a program using an unimplemented construct must raise,
    # never mistranslate (t1_onerr uses ON ERROR GOTO).
    with pytest.raises(ValueError):
        c0.emit_c(_decode("t1_onerr"))
