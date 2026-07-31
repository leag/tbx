"""A numeric SELECT CASE survives an event-trap poll at its own join.

The selector evaluation and the first arm test are separate statements, so a
program with an active trap stamps a poll hook between them:

    arg_ref 6; far_fild_si; fstp64 82     <- evaluate the selector
    trap_hook                             <- the stamp
    fld1; fcomp64 82                      <- first arm

The numeric entry checked the op immediately after `fstp64` and so saw the
stamp, never opened the SELECT, and the arms decoded as an IF chain. That
recompiles to integer compares against the parameter instead of FP compares
against the selector's scratch cell -- wild resume.exe carried 12 of them.

The STRING entry already tolerated this exact hook (its comment cites wild
rsltest.exe under an ON TIMER trap); this is the numeric sibling.
"""

from pathlib import Path

from tbx import decode0, emit0, ir

_CORPUS = Path(__file__).resolve().parents[1] / "fixtures" / "corpus"


def _prog(stem):
    return decode0.decode_user_code((_CORPUS / f"{stem}.exe").read_bytes())


def test_the_select_survives_the_poll_hook():
    prog = _prog("t1_selreftrap")
    sub = next(s for s in prog if isinstance(s, ir.SubDef))
    assert any(isinstance(b, ir.SelectCase) for b in sub.body), [
        type(b).__name__ for b in sub.body
    ]


def test_it_emits_as_a_select_not_an_if_chain():
    src = emit0.emit(_prog("t1_selreftrap"))
    assert "SELECT CASE B%" in src
    assert "END SELECT" in src
    assert "IF B% <> 1" not in src


def test_the_untrapped_form_is_unchanged():
    # zz_sc1 is a numeric SELECT with no trapping: the hook-skipping lookahead
    # must not change how it is recognised.
    prog = _prog("zz_sc1")
    assert sum(isinstance(s, ir.SelectCase) for s in prog) == 1


def test_a_full_stack_metastatement_is_spellable():
    """`$STACK` takes a positive INTEGER constant, so 32768 cannot be said.

    The allocation table counts PARAGRAPHS, so `paras * 16` can land on 32768 --
    which TB rejects as Error 425, and `&H8000` as Error 426 (negative in a
    signed word). 32767 is accepted and rounds to the same 2048 paragraphs, so
    it regenerates the same table. t1_stackmax is itself compiled from
    `$STACK 32767` and decoded as 32768 before this; wild rsltest.exe failed to
    compile on line one for it.
    """
    src = emit0.emit(_prog("t1_stackmax"))
    assert "$STACK 32767" in src
    assert "$STACK 32768" not in src
