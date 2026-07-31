"""Byte-exact round-trip verification over the wild subset the oracle can judge.

    python -m tbx.tools.verify_wild            # the comparable subset
    python -m tbx.tools.verify_wild --all      # every decoding wild program
    python -m tbx.tools.verify_wild NAME ...

`scan_wild --roundtrip` compiles everything it decoded, which makes its tally
read far worse than the decoder is: most wild programs cannot match this
oracle's output whatever the decoder does, for two reasons that have nothing to
do with decoding.

**IDE Options toggles.** They are baked into the EXE and have no source
spelling, so a program compiled with Keyboard break or Bounds checking on can
never be reproduced by an oracle that compiles with defaults.
`verify_fixture` already skips fixtures for exactly this.

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


def verify(name: str) -> str:
    """'exact' | 'skip: ...' | 'N bytes, delta +M' for one wild program."""
    path = _HITS / name
    if not path.is_file():
        return f"skip: {name} not present (gitignored corpus)"
    data = path.read_bytes()
    dialect = program_dialect(data)
    prog = decode0.decode_user_code(data)
    toggles = getattr(prog, "toggles", "")
    if toggles:
        return f"skip: Options toggles {decode0.toggle_names(toggles)}"
    match = build_match(data, dialect)
    if match < BUILD_MATCH_FLOOR:
        return f"skip: different Turbo Basic build ({match}% runtime match)"

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
            # decode did.
            out = oracle.compile_bas(bas, dialect=dialect, timeout=1200)
    except Exception as exc:  # the harness, not a rejection: report it as such
        return f"COMPILE-FAIL: {str(exc).splitlines()[-1][:80]}"
    if out == data:
        return "exact"
    edit, pct = distance(data, out)
    return (
        f"{edit} bytes off ({pct:.2f}% identical), "
        f"delta {len(out) - len(data):+d}"
    )


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
        if not result.startswith(("exact", "skip:")):
            bad += 1
    print(f"\n{len(names)} checked, {bad} not byte-exact")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
