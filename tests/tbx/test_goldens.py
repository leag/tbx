"""Golden-fixture sweeps: gate the committed ops and usercode goldens.

Before this sweep, tests/fixtures/ops/ was regenerate-and-diff-review only and
the usercode goldens were spot-checked through two CLI tests; now every
committed golden is compared against a live decode on every run.

The canonical text is produced by the same code as the regeneration tools
(tbx/tools/dump_ops.py, tbx/tools/dump_user_code.py), so a mismatch means the
decoder drifted, never the formats. Regenerate after an INTENDED change:
    python tbx/tools/dump_ops.py
    python tbx/tools/dump_user_code.py
"""

import glob
import os

import pytest

from tbx import decode0, emit0
from tbx.tools.dump_ops import canon

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CORPUS = os.path.join(_ROOT, "fixtures", "corpus")
_OPS = os.path.join(_ROOT, "fixtures", "ops")
_GOLD = os.path.join(_ROOT, "fixtures", "usercode")

_STEMS = sorted(
    os.path.splitext(os.path.basename(p))[0]
    for p in glob.glob(os.path.join(_CORPUS, "*.exe"))
)


def _exe(stem):
    return open(os.path.join(_CORPUS, f"{stem}.exe"), "rb").read()


def test_every_corpus_exe_has_an_ops_golden():
    missing = [s for s in _STEMS if not os.path.exists(os.path.join(_OPS, f"{s}.txt"))]
    assert not missing, f"corpus EXEs without an ops golden: {missing}"


def test_no_orphan_goldens():
    stems = set(_STEMS)
    orphans = [
        os.path.basename(p)
        for d, ext in ((_OPS, "*.txt"), (_GOLD, "*.bas"))
        for p in glob.glob(os.path.join(d, ext))
        if os.path.splitext(os.path.basename(p))[0] not in stems
    ]
    assert not orphans, f"goldens without a corpus EXE: {orphans}"


@pytest.mark.parametrize("stem", _STEMS)
def test_ops_golden(stem):
    exe = _exe(stem)
    start, dia = decode0.find_prologue(exe)
    commits: set[int] = set()
    ops = decode0._scan(exe, start, dia, commits)
    want = open(os.path.join(_OPS, f"{stem}.txt")).read()
    assert canon(stem, start, dia, ops, commits) == want


@pytest.mark.parametrize("stem", _STEMS)
def test_usercode_golden(stem):
    gold = os.path.join(_GOLD, f"{stem}.bas")
    prog = decode0.decode_user_code(_exe(stem))
    if getattr(prog, "toggles", ""):
        # Flag fixtures carry no golden by convention (see dump_user_code.py);
        # test_flags.py pins their decode directly.
        assert not os.path.exists(gold), f"{stem}: flag fixture has a golden"
        return
    assert emit0.emit(prog) == open(gold).read()
