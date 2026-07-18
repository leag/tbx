"""Capture DOS-run behavior goldens for corpus fixtures via the oracle.

    python -m tbx.tools.dump_dos_output STEM [STEM ...]
    python -m tbx.tools.dump_dos_output --all      # every non-v10, non-flag stem
    python -m tbx.tools.dump_dos_output --missing  # --all minus existing goldens
                                                   # (resume an interrupted sweep)

Runs the ORIGINAL corpus EXE on the oracle's emulated machine and records
what it visibly did: the final text screen into tests/fixtures/dosout/
<stem>.txt and every file the program created into <stem>.file.<NAME>.
These are the behavior goldens the recompiled native binaries are compared
against (test_c0.py) -- the c0 analog of the byte-exact rule. Capture once,
commit; regeneration is only for intended semantic changes.

Programs that never return to the DOS prompt within the budget (graphics
modes lose the text screen; event loops wait forever) are reported and get
no golden. Interactive fixtures take their keystrokes from KEYS below,
which the test layer also uses to derive the native run's stdin -- keep the
two in sync by keeping them in this one table.

`v10_` stems are excluded by --all: dialects produce identical IR, so the
TB 1.1 golden already covers them. Flag stems (f*) differ only in runtime
checks, not output.
"""

from __future__ import annotations

import sys
from pathlib import Path

from tbx.tools import oracle

_ROOT = Path(__file__).resolve().parent.parent.parent
_CORPUS = _ROOT / "tests" / "fixtures" / "corpus"
_DOSOUT = _ROOT / "tests" / "fixtures" / "dosout"

# stem -> tb_v86_capture.js key script (JSON). "count" distinguishes the
# n-th INPUT prompt; bare LINE INPUT prints no prompt, hence sleep steps.
KEYS = {
    "t1_and": '[{"wait":"?","send":"2\\r"},{"wait":"?","count":2,"send":"3\\r"}]',
    "t1_ifin": '[{"wait":"?","send":"2\\r"},{"wait":"?","count":2,"send":"3\\r"}]',
    "t1_or": '[{"wait":"?","send":"5\\r"}]',
    "t1_fn": '[{"wait":"?","send":"4\\r"}]',
    # lowercase answers: the oracle's scancode typing can't shift reliably
    "t1_inp": '[{"wait":"?","send":"5\\r"},{"wait":"?","count":2,"send":"ab\\r"}]',
    "t1_inp2": '[{"wait":"X","send":"3\\r"}]',
    "t1_inp4": '[{"wait":"X","send":"ab\\r"}]',
    "t1_sarr2": '[{"wait":"?","send":"3\\r"}]',
    "t1_dimm": '[{"wait":"?","send":"3\\r"}]',
    "t1_dimv": '[{"wait":"?","send":"3\\r"}]',
    "t1_dimv2": '[{"wait":"?","send":"3\\r"}]',
    "t1_dimw": '[{"wait":"?","send":"3\\r"}]',
    "t1_dimw2": '[{"wait":"?","send":"3\\r"}]',
    "t1_dimw3": '[{"wait":"?","send":"3\\r"}]',
    "t1_erase": '[{"wait":"?","send":"3\\r"}]',
    "t1_mix": '[{"wait":"?","send":"3\\r"}]',
    "t1_mix2": '[{"wait":"?","send":"3\\r"}]',
    "t1_mix3": '[{"wait":"?","send":"3\\r"}]',
    "t1_sarr": '[{"wait":"?","send":"3\\r"}]',
    "t1_tab": '[{"wait":"?","send":"3\\r"}]',
    "t1_pr2": '[{"wait":"?","send":"3\\r"}]',
    "t1_poolrun": '[{"wait":"?","send":"x\\r"}]',
    "t1_boolwh": '[{"wait":"?","send":"1\\r"}]',
    "t1_booluntil": '[{"wait":"?","send":"1\\r"}]',
    # 't' would take the CLS path, whose screen-clear defeats the harness's
    # prompt-return detection (t1_scr); 'x' exercises the fall-through lines
    "t1_ifgoto": '[{"wait":"?","send":"x\\r"}]',
    "t1_and3": '[{"wait":"?","send":"2\\r"},{"wait":"?","count":2,"send":"3\\r"},'
    '{"wait":"?","count":3,"send":"2\\r"}]',
    "t1_or3": '[{"wait":"?","send":"5\\r"}]',
    "t1_inpsemi": '[{"wait":"?","send":"3\\r"}]',
    "t1_inpsemis": '[{"wait":"?","send":"ab\\r"}]',
    "t1_inparr": '[{"wait":"?","send":"4\\r"}]',
    "t1_icmpmat": '[{"wait":"?","send":"abc\\r"}]',
    "t1_inpmulti": '[{"wait":"?","send":"3,4\\r"}]',
    "t1_inpmulti3": '[{"wait":"?","send":"1,2,3\\r"}]',
    "t1_inpmixed": '[{"wait":"?","send":"ab,7\\r"}]',
    "t1_relval": '[{"wait":"?","send":"2\\r"}]',
}


# Stems with no capturable golden, so --missing does not retry them. The
# 2026-07 full sweep captured 297/321 eligible stems; every absence below
# has a verified structural reason.
_TRON_HANG = (
    "TRON EXE stalls in the trace hook on the real machine (witnessed: "
    "t1_tron prints its first [line] marker and never returns to DOS)"
)
SKIP = {
    # bare LINE INPUT prints no prompt, so there is nothing on the screen to
    # synchronize the keystrokes on -- and keys sent on a timer get dropped
    # by the statement's startup. No golden until the harness sees the cursor.
    "t1_inp3": "bare LINE INPUT: no screen marker to synchronize keys on",
    "t1_file2": "bare LINE INPUT: no screen marker to synchronize keys on",
    "t1_inp5": "bare INPUT$(1): no screen marker to synchronize keys on",
    # programs that never return to the DOS prompt
    "t1_run": "RUN restarts the program forever",
    "zz_ginf": "infinite DO loop by design",
    "t1_calla": "CALL ABSOLUTE at a bare address: no machine code there",
    "t1_screen": "SCREEN 1 enters a graphics mode; the text screen is lost",
    "t1_screenb": "SCREEN 1 enters a graphics mode; the text screen is lost",
    "t1_screenp": "SCREEN 1 enters a graphics mode; the text screen is lost",
    "t1_paintt": "SCREEN 1 enters a graphics mode; the text screen is lost",
    "t1_scr": "runs to completion on screen (HI at 10,20) but the harness "
    "never sees the DOS prompt return after CLS/LOCATE -- no confirmed-"
    "complete capture",
    "t1_shell": "SHELL DIR completes on screen but the sub-shell confuses "
    "the harness's prompt-return detection -- no confirmed-complete capture",
    "t1_strch": "260 PRINT lines scroll the 25-line screen many times over; "
    "the harness's DOS-prompt-return detection never confirms completion",
    **{
        s: _TRON_HANG
        for s in (
            "t1_tron", "t1_tron2", "t1_tron2r", "t1_tron2r2", "t1_troncase",
            "t1_tronerb", "t1_tronerr", "t1_tronfor", "t1_trongoto",
            "t1_tronif", "t1_tronml", "t1_tronres", "t1_tronsplit",
            "t1_tronwh", "t1_troffin", "t1_evtron",
        )
    },
}


def native_stdin(stem: str) -> str:
    """The stdin a native run needs to receive the same input the DOS run got."""
    import json

    steps = json.loads(KEYS.get(stem, "[]"))
    return "".join(s.get("send", "").replace("\r", "\n") for s in steps)


def capture(stem: str) -> str:
    if stem in SKIP:
        return f"skip: {SKIP[stem]}"
    exe = _CORPUS / f"{stem}.exe"
    r = oracle.run_exe(exe, keys=KEYS.get(stem))
    if r.timed_out:
        return "skip: no DOS prompt (graphics mode or waiting on events)"
    _DOSOUT.mkdir(exist_ok=True)
    (_DOSOUT / f"{stem}.txt").write_text(r.screen + "\n" if r.screen else "")
    for name, data in r.files.items():
        (_DOSOUT / f"{stem}.file.{name}").write_bytes(data)
    extras = "".join(f" +{n}" for n in r.files)
    return f"ok ({len(r.screen.splitlines())} lines{extras})"


def main(argv: list[str]) -> int:
    if argv and argv[0] in ("--all", "--missing"):
        stems = sorted(
            p.stem
            for p in _CORPUS.glob("*.exe")
            if not p.stem.startswith(("v10_", "f"))
        )
        if argv[0] == "--missing":
            stems = [s for s in stems if not (_DOSOUT / f"{s}.txt").is_file()]
    else:
        stems = argv
    if not stems:
        print(__doc__)
        return 2
    for stem in stems:
        try:
            r = capture(stem)
        except Exception as e:  # keep sweeping; one bad run shouldn't stop a batch
            r = f"ERROR: {e}"
        print(f"{stem}: {r}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
