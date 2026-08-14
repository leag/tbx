"""Compare standalone ``tbd`` IR with calibrated ``tbx`` IR.

This is a calibration tool, not a runtime dependency of ``tbd``::

    uv run python -m tbx.tools.compare_tbd_ir tests/fixtures/corpus

The report separates broad recovery coverage from exact comparison. Exact tree
comparison is only meaningful when a file contains statement kinds migrated to
the fact pipeline and both decoders recover the same kind sequence.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import asdict, dataclass
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

from tbx import decode0, ir
from tbd import decode

MIGRATED_KINDS = frozenset(
    {"Assign", "Beep", "Delay", "Dim", "End", "IfGoto", "Print"}
)


@dataclass(frozen=True)
class Mismatch:
    file: str
    category: str
    detail: str


@dataclass(frozen=True)
class Comparison:
    files: int
    failures: int
    tbx_statements: int
    tbd_statements: int
    aligned_kinds: int
    count_match_files: int
    kind_match_files: int
    migrated_only_files: int
    comparable_files: int
    exact_files: int
    tbx_kinds: dict[str, int]
    aligned_by_kind: dict[str, int]
    mismatches: tuple[Mismatch, ...]

    @property
    def recovery(self) -> float:
        return _ratio(self.tbd_statements, self.tbx_statements)

    @property
    def aligned(self) -> float:
        return _ratio(self.aligned_kinds, self.tbx_statements)


def compare_paths(paths: list[Path], *, examples: int = 12) -> Comparison:
    """Decode every path and aggregate coverage and exact-tree agreement."""

    totals = Counter()
    tbx_kinds = Counter()
    aligned_by_kind = Counter()
    mismatches = []
    for path in paths:
        totals["files"] += 1
        try:
            exact = decode0.decode_user_code(path.read_bytes())
            migrated = decode(path.read_bytes()).canonical_statements
        except Exception as exc:
            totals["failures"] += 1
            _record(mismatches, examples, path, "decode", f"{type(exc).__name__}: {exc}")
            continue
        _compare_file(
            path, exact, migrated, totals, tbx_kinds, aligned_by_kind, mismatches, examples
        )
    return Comparison(
        **{name: totals[name] for name in _TOTAL_FIELDS},
        tbx_kinds=dict(tbx_kinds.most_common()),
        aligned_by_kind=dict(aligned_by_kind),
        mismatches=tuple(mismatches),
    )


def _compare_file(
    path: Path,
    exact: list[Any],
    migrated: tuple[Any, ...],
    totals: Counter,
    tbx_kinds: Counter,
    aligned_by_kind: Counter,
    mismatches: list[Mismatch],
    examples: int,
) -> None:
    exact_kinds = [type(node).__name__ for node in exact]
    migrated_kinds = [node.kind for node in migrated]
    totals["tbx_statements"] += len(exact)
    totals["tbd_statements"] += len(migrated)
    tbx_kinds.update(exact_kinds)
    _align(exact_kinds, migrated_kinds, totals, aligned_by_kind)
    if len(exact) == len(migrated):
        totals["count_match_files"] += 1
    if exact_kinds == migrated_kinds:
        totals["kind_match_files"] += 1
    else:
        _record(mismatches, examples, path, "kinds", _kind_detail(exact_kinds, migrated_kinds))
    if not exact or not set(exact_kinds) <= MIGRATED_KINDS:
        return
    totals["migrated_only_files"] += 1
    if exact_kinds != migrated_kinds:
        return
    totals["comparable_files"] += 1
    left = tuple(_statement(node) for node in exact)
    right = tuple((node.kind, node.operands) for node in migrated)
    if left == right:
        totals["exact_files"] += 1
    else:
        _record(mismatches, examples, path, "tree", _tree_detail(left, right))


def _align(
    exact: list[str], migrated: list[str], totals: Counter, by_kind: Counter
) -> None:
    matcher = SequenceMatcher(a=exact, b=migrated, autojunk=False)
    for block in matcher.get_matching_blocks():
        matched = exact[block.a : block.a + block.size]
        totals["aligned_kinds"] += len(matched)
        by_kind.update(matched)


def _statement(node: Any) -> tuple[str, tuple[object, ...]]:
    if isinstance(node, ir.Assign):
        operands = _expression(node.target), _expression(node.value)
    elif isinstance(node, ir.Dim):
        operands = (
            node.name,
            tuple(_bound(value) for value in node.bounds),
            tuple(
                (name, tuple(_bound(value) for value in bounds))
                for name, bounds in node.also
            ),
            node.dynamic,
        )
    elif isinstance(node, ir.Print):
        mode = "console" if node.file is None else node.file
        operands = mode, tuple(_expression(item) for item in node.items), node.newline
    elif isinstance(node, ir.IfGoto):
        operands = (*_condition(node.cond), node.target)
    elif isinstance(node, ir.Delay):
        operands = (_expression(node.secs),)
    else:
        operands = ()
    return type(node).__name__, operands


def _bound(node: Any) -> object:
    if isinstance(node, int):
        return node
    if isinstance(node, tuple) and len(node) == 2:
        return tuple(
            item if isinstance(item, int) else _expression(item)
            for item in node
        )
    return _expression(node)


def _condition(node: Any) -> tuple[object, ...]:
    if isinstance(node, ir.RelOp):
        return node.op, _expression(node.lhs), _expression(node.rhs)
    return "unsupported-condition", type(node).__name__


def _expression(node: Any) -> object:
    if isinstance(node, ir.Var):
        return "var", node.name
    if isinstance(node, ir.ArrayRef):
        return "array", node.name, tuple(_expression(item) for item in node.indices)
    if isinstance(node, ir.Lit):
        return "const", node.value
    if isinstance(node, ir.StrLit):
        return "string", node.value
    if isinstance(node, ir.BinOp):
        return "binary", node.op, _expression(node.lhs), _expression(node.rhs)
    return "unsupported-expression", type(node).__name__, repr(node)


def _kind_detail(exact: list[str], migrated: list[str]) -> str:
    for index, (left, right) in enumerate(zip(exact, migrated)):
        if left != right:
            return f"statement {index}: tbx={left}, tbd={right}"
    return f"statement count: tbx={len(exact)}, tbd={len(migrated)}"


def _tree_detail(
    exact: tuple[object, ...], migrated: tuple[object, ...]
) -> str:
    for index, (left, right) in enumerate(zip(exact, migrated)):
        if left != right:
            return f"statement {index}: tbx={left!r}, tbd={right!r}"
    return f"statement count: tbx={len(exact)}, tbd={len(migrated)}"


def _record(
    result: list[Mismatch], limit: int, path: Path, category: str, detail: str
) -> None:
    if len(result) < limit:
        result.append(Mismatch(path.name, category, detail))


def _ratio(part: int, whole: int) -> float:
    return 0.0 if not whole else 100.0 * part / whole


def _paths(items: list[str]) -> list[Path]:
    result = []
    for item in items:
        path = Path(item)
        result.extend(sorted(path.glob("*.exe")) if path.is_dir() else [path])
    return result


def _render(report: Comparison) -> str:
    lines = [
        f"files: {report.files} compared, {report.failures} decode failures",
        f"statements: tbx={report.tbx_statements} tbd={report.tbd_statements} "
        f"recovery={report.recovery:.1f}%",
        f"aligned kinds: {report.aligned_kinds}/{report.tbx_statements} "
        f"({report.aligned:.1f}%)",
        f"file agreement: count={report.count_match_files} "
        f"kinds={report.kind_match_files}",
        f"exact canonical trees: {report.exact_files}/{report.comparable_files} "
        f"comparable ({report.migrated_only_files} migrated-only files)",
        "kind coverage:",
    ]
    for kind, count in list(report.tbx_kinds.items())[:20]:
        aligned = report.aligned_by_kind.get(kind, 0)
        lines.append(f"  {kind:<16} {aligned:>5}/{count:<5} {_ratio(aligned, count):5.1f}%")
    if report.mismatches:
        lines.append("mismatch examples:")
        lines.extend(
            f"  {item.file}: {item.category}: {item.detail}"
            for item in report.mismatches
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", help="EXE files or directories")
    parser.add_argument("--examples", type=int, default=12)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    report = compare_paths(_paths(args.paths), examples=max(0, args.examples))
    print(json.dumps(asdict(report), indent=2) if args.json else _render(report))
    return 1 if report.failures else 0


_TOTAL_FIELDS = (
    "files",
    "failures",
    "tbx_statements",
    "tbd_statements",
    "aligned_kinds",
    "count_match_files",
    "kind_match_files",
    "migrated_only_files",
    "comparable_files",
    "exact_files",
)


if __name__ == "__main__":
    raise SystemExit(main())
