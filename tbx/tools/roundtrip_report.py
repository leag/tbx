"""Produce a compact differential report for one EXE round trip.

This is a triage tool, not part of the decoder runtime.  It keeps the emitted
split source and rebuilt EXE, then compares the original and rebuilt scan/layout
directly.  ``verify_wild`` intentionally returns one byte-delta line; this
report is for the next question during a decoder investigation: *what moved?*
"""

from __future__ import annotations

import argparse
import collections
import json
import struct
import tempfile
from pathlib import Path

from tbx import decode0, emit0
from tbx.tools import oracle
from tbx.tools.verify_wild import program_dialect


def _layout_summary(exe: bytes) -> tuple[list[tuple], dict[str, object]]:
    start, dialect = decode0.find_prologue(exe)
    ops = decode0._scan(exe, start, dialect, set())
    layout = decode0._layout(exe, ops)
    return ops, {
        "ds": layout["ds"],
        "delta": layout["delta"],
        "scalar_base": layout["scalar_base"],
        "pool_base": layout["pool_base"],
        "n_scalars": len(layout["scalars"]),
        "n_arrays": len(layout["arrs"]),
        "array_bases": [a["base"] for a in layout["arrs"]],
    }


def _pool_strings(exe: bytes) -> list[str]:
    """Read the compiler's chained string descriptors for a diff report."""
    start, dialect = decode0.find_prologue(exe)
    ops = decode0._scan(exe, start, dialect, set())
    layout = decode0._layout(exe, ops)
    ds = layout["ds"]
    q = layout["pool_base"] - 4
    _, expected = struct.unpack_from("<HH", exe, ds + q)
    q += 4
    descriptors: list[tuple[int, int]] = []
    while q + 4 <= len(exe):
        word, pointer = struct.unpack_from("<HH", exe, ds + q)
        if not word & 0x8000 or pointer != expected:
            break
        length = word & 0x7FFF
        descriptors.append((length, pointer))
        expected += length
        q += 4
    total = sum(length for length, _ in descriptors)
    header = 0x8000 | total
    ss_base = None
    for candidate in range((q + 15) & ~15, ((q + 15) & ~15) + 0x400, 16):
        pos = ds + candidate + 0x10
        if (
            struct.unpack_from("<H", exe, pos)[0] == header
            and exe[pos + 2 : pos + 6] == b"\0" * 4
            and struct.unpack_from("<H", exe, pos + 6 + total)[0] == header
        ):
            ss_base = candidate
            break
    if ss_base is None:
        return []
    return [
        exe[ds + ss_base + pointer : ds + ss_base + pointer + length].decode(
            "latin-1"
        )
        for length, pointer in descriptors
    ]


def _write_bundle(bundle: emit0.SourceBundle, outdir: Path, stem: str) -> Path:
    outdir.mkdir(parents=True, exist_ok=True)
    root = outdir / f"{stem[:8]}.bas"
    root.write_text(bundle.root, encoding="latin-1", newline="")
    for name, source in bundle.includes:
        (outdir / name).write_text(source, encoding="latin-1", newline="")
    return root


def report(exe_path: Path, outdir: Path | None = None, timeout: int = 1200) -> dict:
    original = exe_path.read_bytes()
    program = decode0.decode_user_code(original)
    dialect = program_dialect(original)
    toggles = getattr(program, "toggles", "")
    bundle = emit0.emit_split(program, prefix=exe_path.stem)
    if outdir is None:
        outdir = Path(tempfile.mkdtemp(prefix=f"tbx-roundtrip-{exe_path.stem}-"))
    root = _write_bundle(bundle, outdir, exe_path.stem)
    rebuilt = oracle.compile_bas(root, dialect=dialect, toggles=toggles, timeout=timeout)
    rebuilt_path = outdir / "rebuilt.EXE"
    rebuilt_path.write_bytes(rebuilt)

    original_ops, original_layout = _layout_summary(original)
    rebuilt_ops, rebuilt_layout = _layout_summary(rebuilt)
    first_mismatch = None
    for index, (left, right) in enumerate(zip(original_ops, rebuilt_ops)):
        if left[1:] != right[1:]:
            first_mismatch = {
                "index": index,
                "original": left,
                "rebuilt": right,
            }
            break
    original_pool = collections.Counter(_pool_strings(original))
    rebuilt_pool = collections.Counter(_pool_strings(rebuilt))
    same = sum(a == b for a, b in zip(original, rebuilt))
    return {
        "source": str(root),
        "rebuilt": str(rebuilt_path),
        "dialect": dialect.name if hasattr(dialect, "name") else dialect,
        "toggles": toggles,
        "original_bytes": len(original),
        "rebuilt_bytes": len(rebuilt),
        "delta_bytes": len(rebuilt) - len(original),
        "prefix_equal_bytes": same,
        "original_ops": len(original_ops),
        "rebuilt_ops": len(rebuilt_ops),
        "first_scan_mismatch": first_mismatch,
        "original_layout": original_layout,
        "rebuilt_layout": rebuilt_layout,
        "missing_pool_strings": list((original_pool - rebuilt_pool).elements()),
        "added_pool_strings": list((rebuilt_pool - original_pool).elements()),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe", type=Path)
    parser.add_argument("--outdir", type=Path)
    parser.add_argument("--timeout", type=int, default=1200)
    args = parser.parse_args(argv)
    print(json.dumps(report(args.exe, args.outdir, args.timeout), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
