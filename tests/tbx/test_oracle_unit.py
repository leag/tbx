"""Fast-path policy tests that do not boot the DOS oracle."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from tbx.tools import oracle


@pytest.mark.parametrize(
    ("snapshot_exists", "script"),
    [(False, "tb_v86.js"), (True, "tb_v86_fast.js")],
)
def test_compile_bas_automatically_uses_an_existing_snapshot(
    tmp_path, monkeypatch, snapshot_exists, script
):
    monkeypatch.setattr(oracle, "oracle_dir", lambda: tmp_path)
    source = tmp_path / "probe.bas"
    source.write_text("10 END\n", encoding="latin-1")
    snapshot = tmp_path / "snapshots" / "tb_floppy.img__none.state"
    if snapshot_exists:
        snapshot.parent.mkdir()
        snapshot.write_bytes(b"snapshot")
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        workspace = Path(command[command.index("--workspace") + 1])
        (workspace / "SOLVER_v86.EXE").write_bytes(b"MZ")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(oracle.subprocess, "run", run)

    assert oracle.compile_bas(source) == b"MZ"
    assert commands[0][1] == script


def test_ensure_snapshot_primes_only_when_absent(tmp_path, monkeypatch):
    snapshot = tmp_path / "compiler.state"
    calls = []
    monkeypatch.setattr(oracle, "_snapshot_path", lambda dialect, toggles: snapshot)

    def prime_snapshot(**kwargs):
        calls.append(kwargs)
        snapshot.write_bytes(b"snapshot")
        return snapshot

    monkeypatch.setattr(oracle, "prime_snapshot", prime_snapshot)

    assert oracle.ensure_snapshot("1.0", "K") == snapshot
    assert oracle.ensure_snapshot("1.0", "K") == snapshot
    assert calls == [{"dialect": "1.0", "toggles": "K", "timeout": 300}]
