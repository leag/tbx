"""Where an EXIT DEF lands in a block DEF FN that frees strings.

A SUB gets its epilogue walked back by `match_proc_body`, so `EXIT SUB` has
resolved to the first `arg_ref; str_temp_free` pair since t1_exitsublocstr. A
block DEF FN has no `proc_enter` to match, and its frame -- opened by the
def-region auto-open -- recorded only the `fn_ret`. An `EXIT DEF` in a body
with LOCAL or parameter strings therefore aimed at an address the frame did
not recognize as its exit and came out a plain Goto, leaving a jump target no
statement owned (wild cleanup.exe, reformat.exe: `jump target 0xd875 / 0xdc00`).
"""

import os

from tbx import decode0, ir
from tbx.decode0.matchers import epilogue_entry

_CORPUS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures", "corpus"
)


def _exe(stem):
    with open(os.path.join(_CORPUS, f"{stem}.exe"), "rb") as fh:
        return fh.read()


def _body(prog):
    for stmt in prog:
        if isinstance(stmt, ir.DefFn):
            return stmt.body
    raise AssertionError("no DEF FN in the program")


def test_exit_def_decodes_as_exit_def_not_a_goto():
    body = _body(decode0.decode_user_code(_exe("t1_exitdeflocstr")))
    kinds = [type(s).__name__ for s in _walk(body)]
    assert "ExitDef" in kinds
    assert "Goto" not in kinds


def _walk(body):
    for stmt in body:
        yield stmt
        for _cond, arm in getattr(stmt, "arms", ()) or ():
            yield from _walk(arm)
        for attr in ("body", "else_body"):
            inner = getattr(stmt, attr, None)
            if inner:
                yield from _walk(inner)


def test_the_def_frame_walks_its_own_epilogue_back():
    """The epilogue really is a run, not just the fn_ret -- otherwise the test
    above would pass for the wrong reason."""
    exe = _exe("t1_exitdeflocstr")
    start, dialect = decode0.find_prologue(exe)
    ops = decode0._scan(exe, start, dialect, set())
    ret = next(j for j, o in enumerate(ops) if o[1] == "fn_ret")
    entry, freed = epilogue_entry(ops, ret)
    assert entry < ret, "no teardown run before the fn_ret"
    assert freed >= 1


def test_epilogue_entry_skips_trap_stamps_and_free_pairs():
    ops = [
        (0x10, "movsi", 4),
        (0x13, "arg_ref", 4),
        (0x17, "str_temp_free"),
        (0x19, "trap_hook"),
        (0x1A, "arg_ref", 8),
        (0x1E, "str_temp_free"),
        (0x20, "fn_ret"),
    ]
    entry, freed = epilogue_entry(ops, 6)
    assert (ops[entry][0], freed) == (0x13, 2)


def test_epilogue_entry_stops_at_a_real_statement():
    ops = [(0x10, "movsi", 4), (0x13, "strassign"), (0x15, "fn_ret")]
    entry, freed = epilogue_entry(ops, 2)
    assert (entry, freed) == (2, 0)


def test_epilogue_entry_skips_a_local_dynamic_array_free():
    """The heap block of a `LOCAL A()` is released in the epilogue too, and an
    EXIT SUB aims ahead of it (wild cleanup.exe, reformat.exe). Not counted as
    a freed string: `freed_strings` feeds the retf pop arithmetic and an array
    block is not a string descriptor."""
    ops = [
        (0x10, "movsi", 4),
        (0x13, "strassign"),
        (0x15, "trap_hook"),
        (0x16, "movsi", 14),
        (0x19, "local_arr_free"),
        (0x1C, "proc_ret", 4),
    ]
    entry, freed = epilogue_entry(ops, 5)
    assert (ops[entry][0], freed) == (0x15, 0)


def test_exit_sub_past_a_local_array_free_resolves():
    body = next(
        s.body
        for s in decode0.decode_user_code(_exe("t1_exitsublocarr"))
        if isinstance(s, ir.SubDef)
    )
    kinds = [type(s).__name__ for s in _walk(body)]
    assert "ExitSub" in kinds
