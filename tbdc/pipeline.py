"""One entry point over both decoders.

``tbx`` is the calibrated, byte-exact decoder: when it decodes a program its
source recompiles to the same executable (exactly for programs built with the
compiler builds we have, closely for others). ``tbd`` is the best-effort
analyzer: it never gives up on a region, and marks what it could not lift.
``decompile`` tries ``tbx`` first and falls back to ``tbd``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from tbdc.unpack import unpack


@dataclass
class Recovery:
    """Recovered source and what is known about its quality."""

    engine: str
    source: str
    includes: list[tuple[str, str]] = field(default_factory=list)
    assets: list[tuple[str, bytes]] = field(default_factory=list)
    dialect: str | None = None
    toggles: str = ""
    packer: str | None = None
    statements: int = 0
    placeholders: int = 0
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def summary(self) -> dict:
        return {
            "engine": self.engine,
            "dialect": self.dialect,
            "toggles": self.toggles,
            "packer": self.packer,
            "statements": self.statements,
            "placeholders": self.placeholders,
            "includes": [name for name, _ in self.includes],
            "assets": [name for name, _ in self.assets],
            "warnings": self.warnings,
            "errors": self.errors,
        }


class _Collect(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


class DecompileError(ValueError):
    """No engine produced source."""


ENGINES = ("auto", "tbx", "tbd")


def decompile(
    data: bytes,
    *,
    engine: str = "auto",
    prefix: str = "TBX",
    dense: bool = False,
    numbered: bool = False,
    split: bool = True,
) -> Recovery:
    """Recover Turbo Basic source from an executable image."""

    if engine not in ENGINES:
        raise ValueError(f"unknown engine {engine!r}")
    image, packer = unpack(data)
    errors: list[str] = []
    if engine == "auto":
        from tbx import decode0

        try:
            decode0.find_prologue(image)
        except ValueError as exc:
            raise DecompileError(f"not a Turbo Basic 1.0/1.1 program: {exc}") from exc
    if engine in ("auto", "tbx"):
        try:
            recovery = _tbx(image, prefix=prefix, dense=dense, numbered=numbered, split=split)
        except Exception as exc:  # any tbx failure falls back
            errors.append(f"tbx: {exc}")
            if engine == "tbx":
                raise DecompileError(errors[-1]) from exc
        else:
            recovery.packer = packer
            return recovery
    try:
        recovery = _tbd(image, prefix=prefix, split=split)
    except Exception as exc:
        errors.append(f"tbd: {exc}")
        raise DecompileError("; ".join(errors)) from exc
    recovery.packer = packer
    recovery.errors = errors + recovery.errors
    return recovery


def _tbx(image: bytes, *, prefix: str, dense: bool, numbered: bool, split: bool) -> Recovery:
    from tbx import decode0, emit0, ir

    collect = _Collect()
    root = logging.getLogger("tbx")
    root.addHandler(collect)
    previous = root.level
    root.setLevel(logging.WARNING)
    root.propagate = False
    try:
        _, dialect = decode0.find_prologue(image)
        program = decode0.decode_user_code(image)
        assets = list(getattr(program, "inline_files", ()))

        def render(compact: bool = False) -> str:
            text = emit0.emit(program, dense=dense, sparse=not numbered, compact=compact)
            return emit0._externalize_inline_files(text, tuple(assets))

        has_procedures = any(
            isinstance(s, ir.SubDef) or (isinstance(s, ir.DefFn) and s.is_block)
            for s in program
        )
        source, includes, notes = _finish(
            render(), prefix, split, render_compact=(lambda: render(True)) if has_procedures else None
        )
    finally:
        root.removeHandler(collect)
        root.setLevel(previous)
        root.propagate = True
    warnings = list(dict.fromkeys(collect.messages)) + notes
    return Recovery(
        engine="tbx",
        source=source,
        includes=includes,
        assets=assets,
        dialect=dialect.name,
        toggles=getattr(program, "toggles", ""),
        statements=len(program),
        warnings=warnings,
    )


def _tbd(image: bytes, *, prefix: str, split: bool) -> Recovery:
    from tbd import decode
    from tbd.basic import BasicTranslationError

    program = decode(image)
    errors: list[str] = []
    try:
        source = program.to_basic(strict=True)
    except BasicTranslationError as exc:
        errors.append(f"tbd strict: {exc}")
        source = program.to_basic()
    placeholders = sum(
        1 for line in source.splitlines() if "REM TBD" in line.upper()
    )
    from tbdc.fixups import dedupe_declarations, insert_segments

    source, deduped = dedupe_declarations(source)
    source, segments = insert_segments(source)
    source, includes, notes = _finish(source, prefix, split)
    if deduped:
        notes.append(f"dropped {deduped} repeated LOCAL/SHARED name(s)")
    if segments:
        notes.append(f"inserted {segments} $SEGMENT break(s)")
    return Recovery(
        engine="tbd",
        source=source,
        includes=includes,
        dialect=program.dialect,
        statements=len(program.canonical_statements or program.statements),
        placeholders=placeholders,
        warnings=[d.message if hasattr(d, "message") else str(d) for d in program.diagnostics] + notes,
        errors=errors,
    )


def _finish(source: str, prefix: str, split: bool, render_compact=None):
    """Repair block structure, then split past the editor limit."""

    from tbx.emit0 import _source_bytes, split_source

    # The editor refuses files somewhat below 64 KiB (wild nvg.exe: 65,324
    # bytes rejected), so keep a margin.
    limit = 60_000

    from tbdc.structure import drop_after_goto, restructure

    notes: list[str] = []

    def fix(text: str) -> str:
        text, dropped = drop_after_goto(text)
        if dropped:
            notes.append(f"removed unreachable statements after GOTO on {dropped} line(s)")
        result = restructure(text)
        for kind, count in sorted(result.flattened.items()):
            notes.append(f"rewrote {count} crossing {kind} block(s) as GOTOs")
        for orphan in result.orphans:
            notes.append(f"commented out unmatched {orphan!r}")
        return result.source

    from tbdc.calls import reconcile_calls

    source, call_notes = reconcile_calls(fix(source))
    notes.extend(call_notes)
    if not split:
        return source, [], notes
    if _source_bytes(source) > limit and render_compact is not None:
        compact = fix(render_compact())
        if _source_bytes(compact) <= limit:
            return compact, [], notes
    bundle = split_source(source, prefix=prefix, limit=limit)
    return bundle.root, list(bundle.includes), notes
