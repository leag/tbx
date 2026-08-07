"""Byte-exact round-trip verification over the wild subset the oracle can judge.

    python -m tbx.tools.verify_wild            # the comparable subset, fast
    python -m tbx.tools.verify_wild --all      # compile every decoding program
    python -m tbx.tools.verify_wild NAME ...

The default gates a release and stays quick. `--all` is the thorough sweep: it
COMPILES the programs the default skips rather than printing why they were
skipped, which is what the flag used to do and what made it useless. Exclusion
decides whether a mismatch is a failure, never whether to look -- see
`unreachable_reason`.

`scan_wild --roundtrip` compiles everything it decoded, which makes its tally
read far worse than the decoder is: most wild programs cannot match this
oracle's output whatever the decoder does, for one reason that has nothing to
do with decoding.

**IDE Options toggles are no longer an exclusion reason.** They are baked into
the EXE and have no source spelling, but `compile_bas`'s `toggles` argument
drives the real Options menu before compiling (see
`tb_v86_lib.setOptionsToggles`), the same way `--compile-exe` already drove
"Compile to EXE file" -- so a toggle-carrying program is compiled the way it
actually was, not with defaults. The long-standing blanket claim that such a
program "can never be reproduced" was already wrong for the cheapest toggle
(Keyboard break leaves no trace but the flags mask itself), and is now handled
uniformly for all four (`8KBOS`): verified byte-exact by a self-consistency
round trip (a KBOS-toggled EXE, decoded, re-emitted, and recompiled with the
same toggles reproduces the original exactly), and wild install0.exe went from
unmeasured to 99.17% identical once compiled with its own KBOS toggles.
`FLAGS_ONLY_TOGGLES`/`normalize_flags` remain for `verify_fixture`, which does
not yet drive the toggles menu.

**A different Turbo Basic build.** The runtime is most of a compiled EXE, so a
program built by another release differs almost everywhere no matter how
faithful the decode. Two revisions of Turbo Basic 1.0 are present in the wild
corpus: the one this oracle's 1.0 floppy is, whose programs match its runtime
96-99%, and another that sits at 86-88%. `BUILD_MATCH_FLOOR` splits them.

Note which comparison that is. Both `build_match` and the compile itself use
the program's OWN dialect, and until they did, every one of the 16 TB 1.0
programs here was measured against the 1.1 runtime, scored 4-5%, and was
written off as unreachable. autonum.exe was the standing example of a build
whose "bytes can never be ours"; compiled with 1.0 it comes back 99.91%
identical, delta 0.

Both are recorded per program in `tests/fixtures/wild_roundtrip.json`, which is
the committed half of a corpus that is otherwise gitignored: it pins the sha256
each recorded delta was measured against.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import sys
import tempfile
from pathlib import Path

from tbx import decode0, emit0
from tbx.tools import oracle

_ROOT = Path(__file__).resolve().parents[2]
_HITS = _ROOT / "wild" / "hits"
MANIFEST = _ROOT / "tests" / "fixtures" / "wild_roundtrip.json"

#: Below this much of the runtime region in common with a same-dialect fixture
#: this oracle built, a program is a different Turbo Basic release. The split
#: is not marginal: comparable programs sit at 96-99% and the others at 86-88%
#: (a second TB 1.0 revision). Measured against the WRONG dialect everything
#: collapses to 4-5% and the floor separates nothing -- see `build_match`.
BUILD_MATCH_FLOOR = 90


#: One fixture this oracle built per dialect. The 1.0 and 1.1 runtimes are
#: entirely different code, so a reference from the wrong one scores a
#: same-build program at ~5% -- see `build_match`.
_REFERENCE = {"1.0": "v10_t1_ifgoto.exe", "1.1": "t1_ifgoto.exe"}


def reference_runtime(dialect: str = "1.1") -> bytes:
    """The runtime region of a fixture this oracle compiled itself."""
    exe = _ROOT / "tests" / "fixtures" / "corpus" / _REFERENCE[dialect]
    return exe.read_bytes()[0x100:0x2100]


def program_dialect(data: bytes) -> str:
    """Which Turbo Basic the program was built by, from its prologue."""
    return decode0.find_prologue(data)[1].name


def build_match(data: bytes, dialect: str | None = None) -> int:
    """Percent of the runtime region shared with this oracle's own output.

    Compared against a reference of the program's OWN dialect. It used to
    always use the 1.1 fixture, which made every TB 1.0 program in the corpus
    -- 16 of 37 -- score 4-5% and be written off as "a different Turbo Basic
    build whose bytes can never be ours". They are this oracle's bytes: it has
    a 1.0 floppy too, and wild autonum.exe, long the headline example of an
    unreachable build, comes back 99.91% identical when compiled with it.
    """
    ref = reference_runtime(dialect or program_dialect(data))
    region = data[0x100 : 0x100 + len(ref)]
    return 100 * sum(a == b for a, b in zip(ref, region)) // len(ref)


def distance(a: bytes, b: bytes) -> tuple[int, float]:
    """(bytes of the original the rebuild did not reproduce, % identical).

    A positionwise count is misleading here. One extra byte early in an EXE
    shifts every later byte, so a build differing by a single 48-byte record
    scores as 43641 bytes wrong (wild cal.exe) when it is 98% the same file.
    Aligning first separates "a few localized edits" from "genuinely different
    code", which is the only distinction worth acting on.

    Counted against `a` alone. Summing the unmatched bytes on BOTH sides would
    charge a plain substitution twice -- once as a delete, once as an insert --
    and read worse than the naive count on same-length programs (onelab87.exe:
    76 against a naive 39). The size delta already reports what `b` has that
    `a` does not.

    Costs about a minute per 90k program -- small against the v86 compile that
    produced `b`, and only paid on a mismatch.
    """
    match = sum(
        block.size
        for block in difflib.SequenceMatcher(
            None, a, b, autojunk=False
        ).get_matching_blocks()
    )
    return len(a) - match, 200 * match / (len(a) + len(b))


def load_manifest() -> list[dict]:
    return json.loads(MANIFEST.read_text())["programs"]


#: IDE toggles whose ONLY trace in the compiled image is the flags mask itself.
#: Keyboard break is the whole set: `fkb_t1_and` and `fkb_t1_beep` differ from
#: their default-toggle twins by exactly one byte, the mask at prologue-0x73,
#: with no inserted code and no size change. Contrast Stack test (+3 bytes) and
#: Bounds (+128) in `fst_t1_gosub` / `fbd_t1_arr1`. A program carrying only
#: these is one byte from byte-exact, so it is worth judging rather than
#: excluding -- wild banker.exe comes back 155 bytes off in 94 KB.
FLAGS_ONLY_TOGGLES = frozenset("K")


def normalize_flags(data: bytes, dialect_start: int) -> bytes:
    """`data` with the IDE Options mask zeroed, so a flags-only toggle cancels."""
    at = dialect_start - 0x73
    if at < 0 or at >= len(data):
        return data
    return data[:at] + b"\x00" + data[at + 1 :]


def unreachable_reason(data: bytes, prog, dialect: str) -> str | None:
    """Why this program can never be byte-exact here, or None if it can.

    This decides whether a mismatch is a FAILURE, not whether to look. IDE
    Options toggles are NOT a reason any more: `compile_bas`'s `toggles` drives
    the real Options menu the same way `--compile-exe` drives "Compile to EXE
    file" (see `tb_v86_lib.setOptionsToggles`), verified byte-exact by a
    self-consistency round trip (a KBOS-toggled EXE, decoded, re-emitted, and
    recompiled with the same toggles reproduces the original exactly) and by
    wild install0.exe going from unmeasured to 99.17% identical once compiled
    with its own KBOS toggles.

    A program the oracle cannot reproduce exactly still recompiles into
    something worth diffing: wild pz.exe was built by a different runtime
    revision, so it can never match -- and its op stream still gave up two
    real emitter bugs (a dropped `PRINT ,,` and an `EOF(n)` truth test spelled
    as a comparison), because both live in USER code, which is ours either way.
    """
    match = build_match(data, dialect)
    if match < BUILD_MATCH_FLOOR:
        return f"different Turbo Basic build ({match}% runtime match)"
    return None


def verify(name: str) -> str:
    """'exact' | 'skip: ...' | 'N bytes off (P% identical), delta +M' for one
    wild program, with why byte-exactness is unreachable when it is."""
    path = _HITS / name
    if not path.is_file():
        return f"skip: {name} not present (gitignored corpus)"
    data = path.read_bytes()
    dialect = program_dialect(data)
    prog = decode0.decode_user_code(data)
    toggles = getattr(prog, "toggles", "")
    unreachable = unreachable_reason(data, prog, dialect)

    try:
        with tempfile.TemporaryDirectory(prefix="tbx-wild-") as temp:
            directory = Path(temp)
            bundle = emit0.emit_split(prog, prefix=path.stem)
            bas = directory / f"{path.stem[:8]}.bas"
            bas.write_text(bundle.root, encoding="latin-1", newline="")
            for filename, source in bundle.includes:
                (directory / filename).write_text(
                    source, encoding="latin-1", newline=""
                )
            # The program's own dialect, not a fixed one: compiling a 1.0
            # program with the 1.1 compiler cannot reproduce it whatever the
            # decode did. `toggles` drives the real Options menu to match --
            # see `tb_v86_lib.setOptionsToggles` -- so a toggle-carrying
            # program is compiled the way it actually was, not with defaults.
            out = oracle.compile_bas(bas, dialect=dialect, timeout=1200, toggles=toggles)
    except Exception as exc:  # the harness, not a rejection: report it as such
        return f"COMPILE-FAIL: {str(exc).splitlines()[-1][:80]}"
    if out == data:
        return "exact"
    edit, pct = distance(data, out)
    text = (
        f"{edit} bytes off ({pct:.2f}% identical), "
        f"delta {len(out) - len(data):+d}"
    )
    return text if unreachable is None else f"{text}  [expected: {unreachable}]"


def main(argv: list[str]) -> int:
    entries = load_manifest()
    if argv and argv[0] == "--all":
        names = [e["name"] for e in entries]
    elif argv:
        names = argv
    else:
        names = [e["name"] for e in entries if not e["excluded"]]

    recorded = {e["name"]: e for e in entries}
    bad = 0
    for name in names:
        entry = recorded.get(name)
        path = _HITS / name
        if entry and path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest != entry["sha256"]:
                print(f"{name}: MANIFEST STALE (sha256 differs)")
                bad += 1
                continue
        result = verify(name)
        print(f"{name}: {result}")
        # A mismatch only counts against us where byte-exactness was reachable.
        if not result.startswith(("exact", "skip:")) and "[expected:" not in result:
            bad += 1
    print(f"\n{len(names)} checked, {bad} not byte-exact")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
