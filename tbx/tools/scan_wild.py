"""Triage a tree of downloaded shareware for Turbo Basic EXEs.

    python -m tbx.tools.scan_wild DIR [--copy-hits OUTDIR] [--report FILE]

Walks DIR recursively; descends into .zip archives (including nested ones,
and .exe self-extractors that are really zips); for every DOS MZ executable
tries the tbx prologue detector. Hits are classified:

  HIT           -- full decode succeeded (prints dialect + stmt count)
  TB-BUT-FAILS  -- real TB, but outside the calibrated vocabulary
                   (prints the fail-loud error, i.e. the vocabulary gap)

--report writes the same results as JSON, including address-normalized failure
groups suitable for comparing campaign checkpoints across sessions.

Like cfgview, this is triage-only, never part of the decompile pipeline.
The 2026-07 survey of the PC-SIG 8th-edition CD (discmaster.textfiles.com)
found 89 TB EXEs; the tally of fail-loud errors over that corpus drives
which gaps get probe-authored next (SCREEN optional args and OPEN reclen
came from it: t1_screenb, t1_screenp, t1_open2).

Known unwitnessable pattern: INT CDh (TB 1.0 numbering: INT C7h) pushes an
inline 1-character string -- `c7 06 2e 00 cc 01` stores (char<<8)|1 at
[0x2E] and the INT pushes it -- seen in 4 PC-SIG programs feeding the mode
letter of short-form OPEN. Both our 1.0 and 1.1 compilers pool the same
literal instead (witnessed t1_open2's ops), so those EXEs came from a
different runtime revision; under the calibration rule the pattern stays
out of the vocabulary until a compiler that emits it can verify a fixture
byte-exact. (Same revision skew shows as wild rev.exe recompiling ~937
bytes different from its own decompiled source.)
"""

import io
import hashlib
import json
import re
import sys
import tempfile
import zipfile
from pathlib import Path

from tbx import decode0, emit0
from tbx.tools import oracle

REPORT_SCHEMA_VERSION = 1
hits, fails, corpus_members, roundtrips, nontb, nexe = [], [], [], [], 0, 0


def failure_signature(message: str) -> str:
    """Collapse address-specific failures into a stable triage key."""
    return re.sub(r" at 0x[0-9a-f]+.*$", "", message)


def corpus_fingerprint() -> str:
    """Identify the scanned TB corpus without storing any executable bytes."""
    digest = hashlib.sha256()
    for name, content_hash in sorted(corpus_members):
        digest.update(name.encode())
        digest.update(b"\0")
        digest.update(content_hash.encode())
        digest.update(b"\n")
    return digest.hexdigest()


def roundtrip_category(original: bytes, rebuilt: bytes) -> str:
    """Classify a byte mismatch without masking an actual source/code drift."""
    if original == rebuilt:
        return "exact"
    # MZ's last-page byte count can change when padding differs.  Ignore its
    # two-byte header field only when every payload difference is the known
    # runtime-revision 0x1A/zero filler convention (wild autonum.exe).
    payload = [
        (a, b)
        for i, (a, b) in enumerate(zip(original, rebuilt))
        if a != b and i not in (2, 3)
    ]
    if len(original) == len(rebuilt) and payload and all({a, b} == {0, 0x1A} for a, b in payload):
        return "filler"
    if len(original) == len(rebuilt) and any({a, b} == {0, 0x1A} for a, b in payload):
        return "filler-plus-metadata"
    return "code-or-metadata"


def try_exe(name: str, data: bytes, outdir: Path | None, roundtrip: bool = False):
    global nontb, nexe
    if len(data) < 64 or data[:2] not in (b"MZ", b"ZM"):
        return
    nexe += 1
    try:
        start, dia = decode0.find_prologue(data)
    except ValueError:
        nontb += 1
        return
    corpus_members.append((name, hashlib.sha256(data).hexdigest()))
    try:
        prog = decode0.decode_user_code(data)
        hits.append((name, dia.name, len(prog)))
        print(f"HIT  {dia.name}  {len(prog):4d} stmts  {name}")
        if roundtrip:
            with tempfile.TemporaryDirectory(prefix="tbx-wild-") as work:
                bas = Path(work) / "WILD.BAS"
                bas.write_text(emit0.emit(prog))
                try:
                    rebuilt = oracle.compile_bas(bas, dialect=dia.name)
                    exact = rebuilt == data
                    category = roundtrip_category(data, rebuilt)
                    roundtrips.append((name, exact, len(rebuilt) - len(data), category))
                    print(f"  ROUNDTRIP  {'EXACT' if exact else f'{category} {len(rebuilt) - len(data):+d}'}")
                except Exception as e:
                    roundtrips.append((name, None, None, "compile-fail"))
                    print(f"  ROUNDTRIP  COMPILE-FAIL {str(e)[:80]}")
    except Exception as e:
        fails.append((name, dia.name, str(e)))
        print(f"TB-BUT-FAILS  {dia.name}  {name}: {str(e)[:90]}")
    if outdir:
        out = outdir / Path(name.replace("!", "/")).name.lower()
        outdir.mkdir(parents=True, exist_ok=True)
        out.write_bytes(data)


def walk_zip(name: str, data: bytes, outdir, depth=0):
    if depth > 3:
        return
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        return
    for info in zf.infolist():
        try:
            blob = zf.read(info)
        except Exception:
            continue
        inner = f"{name}!{info.filename}"
        low = info.filename.lower()
        if low.endswith(".zip") or (
            low.endswith(".exe") and blob[:2] in (b"MZ", b"ZM") and b"PK\x03\x04" in blob
        ):
            walk_zip(inner, blob, outdir, depth + 1)
        if low.endswith((".exe", ".com")):
            try_exe(inner, blob, outdir)


def main():
    global hits, fails, corpus_members, roundtrips, nontb, nexe
    hits, fails, corpus_members, roundtrips, nontb, nexe = [], [], [], [], 0, 0
    root = Path(sys.argv[1])
    outdir = None
    if "--copy-hits" in sys.argv:
        outdir = Path(sys.argv[sys.argv.index("--copy-hits") + 1])
    report = None
    roundtrip = "--roundtrip" in sys.argv
    only = sys.argv[sys.argv.index("--only") + 1] if "--only" in sys.argv else None
    if "--report" in sys.argv:
        report = Path(sys.argv[sys.argv.index("--report") + 1])
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if only and p.name.lower() != only.lower():
            continue
        low = p.suffix.lower()
        if low == ".zip":
            walk_zip(str(p), p.read_bytes(), outdir)
        elif low in (".exe", ".com"):
            try_exe(str(p), p.read_bytes(), outdir, roundtrip)
        elif low == ".iso":
            print(f"(skipping iso {p}; mount or extract it first)")
    print(f"\n{nexe} EXEs scanned: {len(hits)} TB decode-ok, "
          f"{len(fails)} TB-but-fail, {nontb} not Turbo Basic")
    if roundtrip:
        exact = sum(ok is True for _, ok, _, _ in roundtrips)
        attempted = sum(ok is not None for _, ok, _, _ in roundtrips)
        print(f"Round trips: {exact}/{attempted} byte-exact ({len(roundtrips) - attempted} compile failures)")
    if report:
        groups: dict[str, list[str]] = {}
        for name, _dialect, message in fails:
            groups.setdefault(failure_signature(message), []).append(name)
        payload = {
            "schema_version": REPORT_SCHEMA_VERSION,
            "generator": "tbx.tools.scan_wild",
            "root": str(root),
            "corpus_fingerprint": corpus_fingerprint(),
            "totals": {
                "executables": nexe,
                "decode_ok": len(hits),
                "decode_failed": len(fails),
                "not_turbo_basic": nontb,
            },
            "hits": [
                {"name": name, "dialect": dialect, "statements": statements}
                for name, dialect, statements in hits
            ],
            "roundtrips": [
                {"name": name, "exact": exact, "size_delta": delta, "category": category}
                for name, exact, delta, category in roundtrips
            ],
            "failures": [
                {
                    "name": name,
                    "dialect": dialect,
                    "message": message,
                    "signature": failure_signature(message),
                }
                for name, dialect, message in fails
            ],
            "groups": [
                {"signature": signature, "count": len(names), "files": sorted(names)}
                for signature, names in sorted(
                    groups.items(), key=lambda item: (-len(item[1]), item[0])
                )
            ],
        }
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps(payload, indent=2) + "\n")


if __name__ == "__main__":
    main()
