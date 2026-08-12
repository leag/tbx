"""Standalone, forgiving Turbo Basic analysis pipeline."""

from __future__ import annotations

import struct

from tbd.analysis import discover, lift
from tbd.assignment_facts import ASSIGNMENT_FACT_PASSES
from tbd.fact_ir import build_operations
from tbd.facts import EVIDENCE_PASSES, Evidence, analyze as analyze_facts
from tbd.ir import Diagnostic, Program
from tbd.pool_facts import POOL_FACT_PASSES
from tbd.runtime_facts import RUNTIME_FACT_PASSES
from tbd.slot_facts import SLOT_FACT_PASSES
from tbd.slots import collect
from tbd.statements import reconstruct
from tbd.symbolic_facts import SYMBOLIC_FACT_PASSES

_PROLOGUES = {b"\xcd\xec\xba": "1.1", b"\xcd\xec\xb8": "1.0"}


def decode(
    exe: bytes, *, max_bytes: int | None = None, rounds: int = 8
) -> Program:
    """Discover code and repeatedly lift it into best-effort semantic IR."""

    if max_bytes is not None and max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    if rounds <= 0:
        raise ValueError("rounds must be positive")
    image_end = _image_end(exe)
    entry = _entry_point(exe, image_end)
    prologue, dialect = _find_prologue(exe, image_end)
    start = prologue if prologue is not None else (entry if entry is not None else 0)
    stop = image_end if max_bytes is None else min(image_end, start + max_bytes)
    diagnostics = _loader_diagnostics(exe, prologue)
    instructions, blocks, xrefs, found = discover(exe, start, stop, dialect)
    evidence = Evidence(exe, instructions, blocks, xrefs)
    facts, fact_passes, facts_converged = analyze_facts(
        evidence,
        rounds=rounds,
        passes=(
            EVIDENCE_PASSES
            + POOL_FACT_PASSES
            + SLOT_FACT_PASSES
            + SYMBOLIC_FACT_PASSES
            + ASSIGNMENT_FACT_PASSES
            + RUNTIME_FACT_PASSES
        ),
    )
    operations, passes = lift(instructions, blocks, xrefs, image=exe, rounds=rounds)
    if not facts_converged:
        diagnostics.append(Diagnostic("fact analysis reached the round limit"))
    if stop < image_end:
        diagnostics.append(
            Diagnostic(f"analysis window is limited to {stop - start} bytes", stop)
        )
    return Program(
        format="mz" if exe.startswith(b"MZ") else "raw",
        image_size=len(exe),
        image_end=image_end,
        entry_point=entry,
        code_start=start,
        dialect=dialect,
        operations=operations,
        instructions=instructions,
        blocks=blocks,
        xrefs=xrefs,
        passes=passes,
        facts=facts,
        fact_passes=fact_passes,
        fact_operations=build_operations(evidence, facts),
        slots=collect(operations),
        statements=reconstruct(operations),
        diagnostics=tuple(diagnostics) + found,
    )


def _image_end(exe: bytes) -> int:
    if len(exe) < 6 or exe[:2] != b"MZ":
        return len(exe)
    tail, pages = struct.unpack_from("<HH", exe, 2)
    declared = pages * 512 - (512 - tail if tail else 0) if pages else len(exe)
    return min(len(exe), max(0x20, declared))


def _entry_point(exe: bytes, image_end: int) -> int | None:
    if len(exe) < 0x20 or exe[:2] != b"MZ":
        return None
    header_paragraphs = struct.unpack_from("<H", exe, 8)[0]
    ip, cs = struct.unpack_from("<HH", exe, 20)
    entry = (header_paragraphs + cs) * 16 + ip
    return entry if entry < image_end else None


def _find_prologue(exe: bytes, image_end: int) -> tuple[int | None, str | None]:
    matches = [
        (offset, dialect)
        for marker, dialect in _PROLOGUES.items()
        if (offset := exe.find(marker, 0, image_end)) >= 0
    ]
    return min(matches) if matches else (None, None)


def _loader_diagnostics(exe: bytes, prologue: int | None) -> list[Diagnostic]:
    diagnostics = []
    if not exe.startswith(b"MZ"):
        diagnostics.append(
            Diagnostic("input has no MZ header; treating it as a raw image")
        )
    if prologue is None:
        diagnostics.append(
            Diagnostic("Turbo Basic prologue not found; analyzing from entry point")
        )
    return diagnostics
