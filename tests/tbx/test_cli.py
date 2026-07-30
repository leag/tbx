"""Smoke tests for the tbx CLI (tbx/cli.py)."""

import os

from tbx import cli, emit0

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CORPUS = os.path.join(_ROOT, "fixtures", "corpus")
_GOLD = os.path.join(_ROOT, "fixtures", "usercode")


def test_decompile_to_stdout(capsys):
    assert cli.main([os.path.join(_CORPUS, "t1_tronif.exe")]) == 0
    want = open(os.path.join(_GOLD, "t1_tronif.bas")).read()
    assert capsys.readouterr().out == want


def test_decompile_to_file(tmp_path):
    out = tmp_path / "out.bas"
    assert cli.main([os.path.join(_CORPUS, "v10_t1_delay.exe"), "-o", str(out)]) == 0
    assert out.read_text() == open(os.path.join(_GOLD, "v10_t1_delay.bas")).read()


def test_split_output_writes_the_root_and_latin1_include(tmp_path, monkeypatch):
    out = tmp_path / "out.bas"
    bundle = emit0.SourceBundle(
        '10 A = 1\n$INCLUDE "OUT001.INC"\n20 END\n',
        (("OUT001.INC", '30 SUB SUB1\n  PRINT "Í"\nEND SUB\n'),),
    )
    monkeypatch.setattr(emit0, "emit_split", lambda *_args, **_kwargs: bundle)

    assert (
        cli.main(
            [
                os.path.join(_CORPUS, "v10_t1_delay.exe"),
                "-o",
                str(out),
                "--split",
            ]
        )
        == 0
    )
    assert out.read_bytes() == bundle.root.encode("latin-1")
    assert (tmp_path / "OUT001.INC").read_bytes() == bundle.includes[0][1].encode(
        "latin-1"
    )


def test_split_output_refuses_to_overwrite_an_existing_include(
    tmp_path, monkeypatch, capsys
):
    out = tmp_path / "out.bas"
    include = tmp_path / "OUT001.INC"
    include.write_text("mine")
    bundle = emit0.SourceBundle(
        '$INCLUDE "OUT001.INC"\n',
        (("OUT001.INC", "10 END\n"),),
    )
    monkeypatch.setattr(emit0, "emit_split", lambda *_args, **_kwargs: bundle)

    assert (
        cli.main(
            [
                os.path.join(_CORPUS, "v10_t1_delay.exe"),
                "-o",
                str(out),
                "--split",
            ]
        )
        == 1
    )
    assert include.read_text() == "mine"
    assert not out.exists()
    assert "refusing to overwrite" in capsys.readouterr().err


def test_ops_dump(capsys):
    assert cli.main([os.path.join(_CORPUS, "v10_t1_delay.exe"), "--ops"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("# dialect=1.0 ")
    assert "delay_init" in out and "# commits" in out


def test_missing_file(capsys):
    assert cli.main(["/nonexistent/no.exe"]) == 1
    assert "tbx:" in capsys.readouterr().err


def test_not_a_tb_exe(tmp_path, capsys):
    bogus = tmp_path / "bogus.exe"
    bogus.write_bytes(b"MZ" + b"\x00" * 64)
    assert cli.main([str(bogus)]) == 1
    assert "prologue" in capsys.readouterr().err


def test_version(capsys):
    import pytest

    with pytest.raises(SystemExit) as e:
        cli.main(["--version"])
    assert e.value.code == 0
    assert capsys.readouterr().out.startswith("tbx ")
