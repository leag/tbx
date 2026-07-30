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
faithful the decode. Wild autonum.exe comes back 3% identical and always would;
it shares 88-96% of its runtime region with strpfind.exe and book.exe, and 5%
with anything this oracle produces.

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

#: Below this much of the runtime region in common with a fixture this oracle
#: built, a program is a different Turbo Basic release. The split is not
#: marginal -- comparable programs sit at 99% and the others at 5%.
BUILD_MATCH_FLOOR = 90


def reference_runtime() -> bytes:
    """The runtime region of a fixture this oracle compiled itself."""
    exe = _ROOT / "tests" / "fixtures" / "corpus" / "t1_ifgoto.exe"
    return exe.read_bytes()[0x100:0x2100]


def build_match(data: bytes) -> int:
    """Percent of the runtime region shared with this oracle's own output."""
    ref = reference_runtime()
    region = data[0x100 : 0x100 + len(ref)]
    return 100 * sum(a == b for a, b in zip(ref, region)) // len(ref)


def distance(a: bytes, b: bytes) -> tuple[int, float]:
    """Alignment-aware distance: (bytes that must be inserted/deleted, % identical).

    A positionwise count is misleading here. One extra byte early in an EXE
    shifts every later byte, so a build that differs by a single 48-byte record
    scores as 43641 bytes wrong (wild cal.exe) when it is 98% the same file.
    Aligning first separates "a few localized edits" from "genuinely different
    code", which is the only distinction worth acting on.

    Costs about a minute per 90k program -- small against the v86 compile that
    produced `b`, and only paid on a mismatch.
    """
    match = sum(
        block.size
        for block in difflib.SequenceMatcher(None, a, b, autojunk=False)
        .get_matching_blocks()
    )
    return (len(a) - match) + (len(b) - match), 200 * match / (len(a) + len(b))


def load_manifest() -> list[dict]:
    return json.loads(MANIFEST.read_text())["programs"]


def verify(name: str) -> str:
    """'exact' | 'skip: ...' | 'N bytes, delta +M' for one wild program."""
    path = _HITS / name
    if not path.is_file():
        return f"skip: {name} not present (gitignored corpus)"
    data = path.read_bytes()
    prog = decode0.decode_user_code(data)
    toggles = getattr(prog, "toggles", "")
    if toggles:
        return f"skip: Options toggles {decode0.toggle_names(toggles)}"
    match = build_match(data)
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
            out = oracle.compile_bas(bas, dialect="1.1", timeout=1200)
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
