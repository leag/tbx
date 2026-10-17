"""Tests for the tbdc front end: unpacking, block repair, call repair, CLI."""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from tbdc.calls import reconcile_calls
from tbdc.cli import main
from tbdc.pipeline import DecompileError, decompile
from tbdc.repair import error_row, locate
from tbdc.structure import drop_after_goto, restructure
from tbdc.unpack import detect, unpack

ROOT = Path(__file__).resolve().parents[2]
HITS = ROOT / "wild" / "hits"


def test_crossing_if_becomes_gotos():
    src = "\n".join([
        "10 DO",
        "20 A$ = INKEY$",
        '30 IF A$ = "" THEN',
        "  LOOP",
        "40 PRINT 1",
        "END IF",
    ])
    result = restructure(src)
    assert result.flattened == {"IF": 1}
    assert result.orphans == []
    assert '30 IF (A$ = "") = 0 THEN TBDC2' in result.source
    assert "END IF" not in result.source
    assert "  LOOP" in result.source


def test_loop_crossing_select_is_rewritten():
    src = "\n".join([
        "1390 DO",
        "1420 SELECT CASE K$",
        "CASE CHR$(27)",
        "  GOTO 100",
        "CASE ELSE",
        "  LOOP",
        "END SELECT",
    ])
    result = restructure(src)
    assert result.flattened == {"DO": 1}
    lines = result.source.splitlines()
    assert lines[:2] == ["1390 REM", "TBDC1:"]
    assert "  GOTO TBDC1" in lines
    assert "END SELECT" in lines


def test_for_inside_one_line_if_is_counted():
    src = 'IF U$ = "A" THEN FOR I = 1 TO 3: PSET (I,1): NEXT I'
    result = restructure(src)
    assert result.source == src
    assert result.orphans == []


def test_nested_one_line_if_closes_a_loop():
    src = "FOR AL = 1 TO N%\nX = 1\nIF A$ = \"Y\" THEN IF AL < N% THEN NEXT AL"
    assert restructure(src).orphans == []


def test_line_continuation_keeps_the_block():
    src = "\n".join([
        '1237 IF A$ = "x" OR _',
        '       A$ = "y" THEN',
        "  RETURN",
        "END IF",
    ])
    result = restructure(src)
    assert result.source == src
    assert result.orphans == []


def test_unmatched_opener_is_commented():
    result = restructure("FOR I = 1 TO 3\nPRINT I")
    assert result.orphans == ["FOR I = 1 TO 3"]
    assert result.source.startswith("REM TBDC: FOR I = 1 TO 3")


def test_statements_after_goto_are_dropped():
    text, dropped = drop_after_goto('10 IF K$ = "R" THEN K$ = "": GOTO 30: GOTO 40\nIF A THEN GOTO 1 ELSE PRINT: PRINT 2')
    assert dropped == 1
    assert text.splitlines() == ['10 IF K$ = "R" THEN K$ = "": GOTO 30', "IF A THEN GOTO 1 ELSE PRINT: PRINT 2"]


def test_call_arguments_follow_parameter_types():
    src = "\n".join([
        "10 SUB S1(A%)",
        "END SUB",
        "20 SUB S2(B%, C$)",
        "END SUB",
        "CALL S1(R)",
        "IF R > 1 THEN PRINT R",
        "CALL S2(1,AV)",
    ])
    out, notes = reconcile_calls(src)
    assert "CALL S1((R))" in out  # R has other uses: pass by value
    assert "CALL S2(1,AV$)" in out  # AV is only an argument: retype it
    assert any("retyped AV as AV$" in n for n in notes)


def test_error_row_uses_cursor(tmp_path):
    screen = "\n".join([
        "Cursor: 7,3",
        "╔═══ Edit ═══╗",
        "║Error 471: Unknown identifier ║",
        "║10 PRINT 1║",
        "║20 PRINT +*║",
        "║30 PRINT 3║",
        "╚══╝",
    ])
    message, rows, cursor = error_row(screen)
    assert message.startswith("Error 471")
    assert cursor == 2
    src = tmp_path / "P.BAS"
    src.write_text("5 CLS\n10 PRINT 1\n20 PRINT +*\n30 PRINT 3\n")
    assert locate([src], rows, cursor) == (src, 3)


@pytest.mark.skipif(not (HITS / "brotheru.exe").is_file(), reason="wild corpus not provisioned")
def test_lzexe_unpack():
    assert detect(b"MZ" + b"\0" * 62) is None
    data = (HITS / "brotheru.exe").read_bytes()
    assert detect(data) == "LZ91"
    image, packer = unpack(data)
    assert packer == "LZ91"
    words = struct.unpack_from("<14H", image, 0)
    assert image[:2] == b"MZ"
    assert len(image) == 177014
    # page count and last-page size describe the restored file exactly
    assert (words[2] - 1) * 512 + words[1] == len(image)
    assert words[3] == 4642  # relocations restored into the header
    assert b"Copyright 1990 by John Steed" in image


def test_not_turbo_basic_is_rejected():
    with pytest.raises(DecompileError, match="not a Turbo Basic"):
        decompile(b"MZ" + b"\0" * 200)


@pytest.mark.skipif(not (HITS / "autonum.exe").is_file(), reason="wild corpus not provisioned")
def test_cli_writes_source_and_report(tmp_path):
    out = tmp_path / "AUTONUM.BAS"
    report = tmp_path / "r.json"
    assert main([str(HITS / "autonum.exe"), "-o", str(out), "--report", str(report), "-q"]) == 0
    data = out.read_bytes()
    assert b"\r\n" in data and b"ON ERROR GOTO" in data
    meta = json.loads(report.read_text())
    assert meta["engine"] == "tbx" and meta["dialect"] == "1.0"


@pytest.mark.skipif(not (HITS / "swbb.exe").is_file(), reason="wild corpus not provisioned")
def test_tbx_failure_falls_back_to_tbd():
    recovery = decompile((HITS / "swbb.exe").read_bytes())
    assert recovery.engine == "tbd"
    assert any(e.startswith("tbx:") for e in recovery.errors)


def test_text_passes_leave_calibrated_fixtures_unchanged():
    """tbdc's source repairs only touch broken programs.

    Every corpus fixture recompiles byte-exactly from tbx's emission, so the
    restructuring, call reconciliation and GOTO cleanup must leave it as is.
    """
    import logging

    from tbx import decode0, emit0

    logging.disable(logging.CRITICAL)
    try:
        checked = 0
        for path in sorted((ROOT / "tests" / "fixtures" / "corpus").glob("*.exe"))[::7]:
            try:
                source = emit0.emit(decode0.decode_user_code(path.read_bytes()))
            except Exception:
                continue
            text, _ = drop_after_goto(source)
            text = restructure(text).source
            text, _ = reconcile_calls(text)
            assert text == source, path.name
            checked += 1
        assert checked > 100
    finally:
        logging.disable(logging.NOTSET)
