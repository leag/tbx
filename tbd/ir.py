"""Small data model for recursive discovery and lifted recovery IR."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class Diagnostic:
    message: str
    offset: int | None = None
    severity: str = "warning"


@dataclass(frozen=True)
class Operation:
    """An instruction, signature match, or lifted semantic operation."""

    offset: int
    size: int
    kind: str
    operands: tuple[Any, ...] = ()
    raw: str = ""
    confidence: str = "structural"

    @property
    def end(self) -> int:
        return self.offset + self.size


@dataclass(frozen=True)
class BasicBlock:
    start: int
    end: int
    instruction_offsets: tuple[int, ...]
    successors: tuple[int, ...] = ()


@dataclass(frozen=True)
class CrossReference:
    source: int
    target: int
    kind: str


@dataclass(frozen=True)
class PassReport:
    round: int
    name: str
    changes: int
    nodes: int


@dataclass(frozen=True)
class Program:
    """A standalone best-effort decode, including evidence and lifted IR."""

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
    passes: tuple[PassReport, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()

    def to_dict(self, *, include_instructions: bool = False) -> dict[str, Any]:
        result = asdict(self)
        if not include_instructions:
            result.pop("instructions")
        return result

    def render(self, *, show_instructions: bool = False) -> str:
        """Render lifted IR by default, or the discovered instructions."""

        dialect = self.dialect or "unknown"
        lines = [
            f"program format={self.format} dialect={dialect} quality=best-effort",
            f"image size={self.image_size} end={self.image_end} "
            f"entry={_hex(self.entry_point)} code={self.code_start:#x}",
            f"analysis blocks={len(self.blocks)} xrefs={len(self.xrefs)} "
            f"instructions={len(self.instructions)} ir={len(self.operations)}",
        ]
        lines.extend(_render_operation(node) for node in self.operations)
        if show_instructions:
            lines.append("instructions")
            lines.extend(_render_operation(node) for node in self.instructions)
        if self.passes:
            lines.append("passes")
            lines.extend(
                f"  {item.round}:{item.name} changes={item.changes} nodes={item.nodes}"
                for item in self.passes
            )
        for diagnostic in self.diagnostics:
            where = "" if diagnostic.offset is None else f" at {diagnostic.offset:#x}"
            lines.append(f"{diagnostic.severity}{where}: {diagnostic.message}")
        return "\n".join(lines) + "\n"


def _render_operation(operation: Operation) -> str:
    args = " ".join(_render_arg(arg) for arg in operation.operands)
    suffix = f" {args}" if args else ""
    raw = _short_raw(operation.raw)
    return (
        f"{operation.offset:05x}  {raw:<54} "
        f"{operation.kind}{suffix} [{operation.confidence}]"
    )


def _hex(value: int | None) -> str:
    return "none" if value is None else f"{value:#x}"


def _render_arg(value: Any) -> str:
    if isinstance(value, int):
        return f"{value:#x}"
    return str(value)


def _short_raw(raw: str, limit: int = 18) -> str:
    parts = raw.split()
    return raw if len(parts) <= limit else " ".join(parts[:limit]) + " …"
