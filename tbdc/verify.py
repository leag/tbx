"""Recompile recovered source with Turbo Basic under QEMU and compare.

Needs ``qemu-system-i386``, mtools, a FreeDOS boot floppy and Turbo Basic
compiler floppies. Images are looked up in ``$TBDC_IMAGES`` (default: the
repository's ``oracle/`` directory): ``freedos.img``, ``tb10_floppy.img``
(TB 1.0) and ``tb_floppy.img`` (TB 1.1).
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPILERS = {"1.0": "tb10_floppy.img", "1.1": "tb_floppy.img"}
ERROR = re.compile(r"Error\s+\d+:[^║\n]*")


def images() -> Path:
    return Path(os.environ.get("TBDC_IMAGES", ROOT / "oracle"))


def harness(dialect: str | None):
    sys.path.insert(0, str(ROOT))
    from oracle_qemu.qemu_harness import QemuHarness

    base = images()
    snapshots = Path(os.environ.get("TBDC_SNAPSHOTS", Path(tempfile.gettempdir()) / "tbdc-snapshots"))
    return QemuHarness(
        base / "freedos.img",
        base / COMPILERS.get(dialect or "1.1", "tb_floppy.img"),
        snapshot_directory=snapshots / (dialect or "1.1"),
    )


def compile_source(source: Path, output: Path, dialect: str | None, toggles: str = "", timeout: float = 300) -> dict:
    """Compile ``source`` to ``output``; return ``{"compile": "ok"|"error", ...}``."""

    from oracle_qemu.qemu_harness import HarnessError

    try:
        h = harness(dialect)
        if not h.has_snapshot(toggles):
            h.prime(toggles=toggles)
        h.compile(source, output, toggles=toggles, timeout=timeout)
    except HarnessError as exc:
        match = ERROR.search(str(exc))
        return {
            "compile": "error",
            "compile_error": match.group(0).strip() if match else str(exc)[:300],
            "screen": str(exc),
        }
    return {"compile": "ok"}


def comment_out(path: Path, index: int) -> str:
    """Turn line ``index`` of ``path`` (and its `_` continuations) into a REM."""

    raw = path.read_bytes().decode("latin-1")
    newline = "\r\n" if "\r\n" in raw else "\n"
    lines = raw.split(newline)
    last = index
    while last + 1 < len(lines) and lines[last].rstrip().endswith("_"):
        last += 1
    text = " ".join(line.strip().rstrip("_").strip() for line in lines[index : last + 1])
    m = re.match(r"^(\s*)(\d+)\s+(.*)$", lines[index])
    if m:
        replacement = f"{m.group(1)}{m.group(2)} REM TBDC: {m.group(3).strip()}"
        body = m.group(3)
    else:
        indent = re.match(r"\s*", lines[index]).group(0)
        replacement = f"{indent}REM TBDC: {text}"
        body = text
    lines[index : last + 1] = [replacement]
    path.write_bytes(newline.join(lines).encode("latin-1"))
    return body.strip()


def compile_with_repair(
    source: Path, output: Path, dialect, toggles: str = "", rounds: int = 25, includes=None
) -> dict:
    """Compile; on an error comment out the failing line and try again."""

    from tbdc.repair import error_row, locate

    repairs: list[str] = []
    for _ in range(rounds):
        result = compile_source(source, output, dialect, toggles)
        if result["compile"] == "ok":
            break
        message, rows, cursor = error_row(result.get("screen", ""))
        names = includes if includes is not None else [p.name for p in source.parent.glob("*.INC")]
        sources = [source] + [source.parent / name for name in names]
        hit = locate(sources, rows, cursor)
        if hit is None:
            break
        path, index = hit
        line = path.read_bytes().decode("latin-1").splitlines()[index]
        if "REM TBDC:" in line:
            break  # already commented: the error is elsewhere
        repairs.append(f"{message}: {path.name}:{index + 1}: {comment_out(path, index)}")
    result.pop("screen", None)
    result["repairs"] = repairs
    return result


def verify(original: Path, source: Path, recovery, repair: bool = False) -> dict:
    rebuilt = source.with_suffix(".REBUILT.EXE")
    if repair:
        result = compile_with_repair(
            source,
            rebuilt,
            recovery.dialect,
            recovery.toggles,
            includes=[name for name, _ in recovery.includes],
        )
    else:
        result = compile_source(source, rebuilt, recovery.dialect, recovery.toggles)
        result.pop("screen", None)
    if result["compile"] != "ok":
        return result
    a = original.read_bytes()
    if recovery.packer:
        from tbdc.unpack import unpack

        a = unpack(a)[0]
    b = rebuilt.read_bytes()
    same = sum(x == y for x, y in zip(a, b))
    try:
        from tbx import decode0

        # The user program (from the compiler prologue on) does not depend on
        # the runtime revision linked in front of it.
        ua = a[decode0.find_prologue(a)[0] :]
        ub = b[decode0.find_prologue(b)[0] :]
        result["user_identical"] = ua == ub
        result["user_match"] = round(sum(x == y for x, y in zip(ua, ub)) / max(len(ua), len(ub)), 4)
    except ValueError:
        pass
    result.update(
        rebuilt=str(rebuilt),
        identical=a == b,
        byte_match=round(same / max(len(a), len(b)), 4),
        size_original=len(a),
        size_rebuilt=len(b),
    )
    return result
