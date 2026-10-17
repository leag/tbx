"""Typed intermediate-representation records shared by the decoder stages."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class Diagnostic:
    """A non-fatal condition encountered during analysis."""

    message: str
    offset: int | None = None
    severity: str = "warning"


@dataclass(frozen=True)
class Operation:
    """An instruction or lifted semantic operation."""

    offset: int
    size: int
    kind: str
    operands: tuple[Any, ...] = ()
    raw: str = ""
    confidence: str = "structural"

    @property
    def end(self) -> int:
        """Return the first image offset after this operation."""
        return self.offset + self.size


@dataclass(frozen=True)
class BasicBlock:
    """A control-flow block and its outgoing edges."""

    start: int
    end: int
    instruction_offsets: tuple[int, ...]
    successors: tuple[int, ...] = ()


@dataclass(frozen=True)
class CrossReference:
    """A directed reference between two image offsets."""

    source: int
    target: int
    kind: str


@dataclass(frozen=True)
class Fact:
    """Immutable evidence-backed semantic fact."""

    kind: str
    subject: tuple[Any, ...]
    value: tuple[Any, ...]
    evidence: tuple[int, ...]
    confidence: str


@dataclass(frozen=True)
class FactReport:
    """Summary of one fact-analysis pass."""

    round: int
    name: str
    additions: int
    facts: int
    seconds: float = 0.0


@dataclass(frozen=True)
class Slot:
    """A named memory slot inferred from compiler metadata."""

    offset: int
    name: str
    types: tuple[str, ...] = ()


@dataclass(frozen=True)
class Statement:
    """A recovered Turbo Basic statement."""

    index: int
    address: int
    kind: str
    operands: tuple[Any, ...] = ()


@dataclass(frozen=True)
class Program:
    """Complete intermediate representation produced by :func:`decode`."""

    format: str
    image_size: int
    image_end: int
    entry_point: int | None
    code_start: int
    dialect: str | None
    operations: tuple[Operation, ...]
    instructions: tuple[Operation, ...] = ()
    blocks: tuple[BasicBlock, ...] = ()
    xrefs: tuple[CrossReference, ...] = ()
    facts: tuple[Fact, ...] = ()
    fact_passes: tuple[FactReport, ...] = ()
    fact_operations: tuple[Operation, ...] = ()
    slots: tuple[Slot, ...] = ()
    statements: tuple[Statement, ...] = ()
    fact_statements: tuple[Statement, ...] = ()
    canonical_statements: tuple[Statement, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()

    def to_dict(
        self, *, include_instructions: bool = False, include_facts: bool = False
    ) -> dict[str, Any]:
        """Serialize the program, optionally including analysis internals."""
        result = asdict(self)
        if not include_instructions:
            result.pop("instructions")
        if not include_facts:
            result.pop("facts")
            result.pop("fact_passes")
            result.pop("fact_operations")
            result.pop("fact_statements")
            result.pop("canonical_statements")
        return result

    def render(
        self, *, show_instructions: bool = False, show_facts: bool = False
    ) -> str:
        """Render a human-readable report of the recovered program."""
        dialect = self.dialect or "unknown"
        lines = [
            f"program format={self.format} dialect={dialect} quality=best-effort",
            f"image size={self.image_size} end={self.image_end} "
            f"entry={_hex(self.entry_point)} code={self.code_start:#x}",
            f"analysis blocks={len(self.blocks)} xrefs={len(self.xrefs)} "
            f"instructions={len(self.instructions)} facts={len(self.facts)} "
            f"ir={len(self.operations)}",
        ]
        lines.extend(_render_operation(node) for node in self.operations)
        if show_instructions:
            lines.append("instructions")
            lines.extend(_render_operation(node) for node in self.instructions)
        if show_facts:
            lines.extend(_render_facts(self.facts, self.fact_passes))
            lines.append("fact-operations")
            lines.extend(_render_operation(node) for node in self.fact_operations)
            lines.extend(_render_statements(self.fact_statements, "fact-statements"))
            lines.extend(
                _render_statements(self.canonical_statements, "canonical-statements")
            )
        lines.extend(_render_statements(self.statements))
        for diagnostic in self.diagnostics:
            where = "" if diagnostic.offset is None else f" at {diagnostic.offset:#x}"
            lines.append(f"{diagnostic.severity}{where}: {diagnostic.message}")
        return "\n".join(lines) + "\n"

    def to_basic(self, *, strict: bool = False) -> str:
        """Render recovered canonical statements as Turbo Basic source."""
        from tbd.basic import to_basic

        return to_basic(self, strict=strict)


def _render_operation(operation: Operation) -> str:
    args = " ".join(_render_arg(arg) for arg in operation.operands)
    suffix = f" {args}" if args else ""
    raw = _short_raw(operation.raw)
    return (
        f"{operation.offset:05x}  {raw:<54} "
        f"{operation.kind}{suffix} [{operation.confidence}]"
    )


def _render_facts(
    facts: tuple[Fact, ...], reports: tuple[FactReport, ...]
) -> list[str]:
    lines = ["facts"]
    lines.extend(
        f"  {fact.kind} {fact.subject} = {fact.value} "
        f"evidence={fact.evidence} [{fact.confidence}]"
        for fact in facts
    )
    lines.append("fact-passes")
    lines.extend(
        f"  {report.round}:{report.name} additions={report.additions} "
        f"facts={report.facts}"
        for report in reports
    )
    return lines


def _render_statements(
    statements: tuple[Statement, ...], title: str = "statements"
) -> list[str]:
    if not statements:
        return []
    return [title] + [
        f"  {item.index}: {item.kind} {_render_arg(item.operands)}"
        for item in statements
    ]


def _hex(value: int | None) -> str:
    return "none" if value is None else f"{value:#x}"


def _render_arg(value: object) -> str:
    if isinstance(value, int):
        return f"{value:#x}"
    return str(value)


def _short_raw(raw: str, limit: int = 18) -> str:
    parts = raw.split()
    return raw if len(parts) <= limit else " ".join(parts[:limit]) + " …"
