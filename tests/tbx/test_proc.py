"""Procedure-region scan + SUB/CALL/DEF FN recovery."""

import os

from tbx import decode0

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _exe(name):
    return open(os.path.join(_ROOT, "fixtures", "corpus", name), "rb").read()


def test_scan_decodes_proc_region():
    exe = _exe("zz_sub0.exe")
    start, dia = decode0.find_prologue(exe)
    ops = decode0._scan(exe, start, dia)
    kinds = [o[1] for o in ops]
    assert "far_call" in kinds
    assert "proc_enter" in kinds
    assert "proc_ret" in kinds
