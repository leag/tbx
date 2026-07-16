"""Triage a tree of downloaded shareware for Turbo Basic EXEs.

    python -m tbx.tools.scan_wild DIR [--copy-hits OUTDIR]

Walks DIR recursively; descends into .zip archives (including nested ones,
and .exe self-extractors that are really zips); for every DOS MZ executable
tries the tbx prologue detector. Hits are classified:

  HIT           -- full decode succeeded (prints dialect + stmt count)
  TB-BUT-FAILS  -- real TB, but outside the calibrated vocabulary
                   (prints the fail-loud error, i.e. the vocabulary gap)

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
import sys
import zipfile
from pathlib import Path

from tbx import decode0

hits, fails, nontb, nexe = [], [], 0, 0


def try_exe(name: str, data: bytes, outdir: Path | None):
    global nontb, nexe
    if len(data) < 64 or data[:2] not in (b"MZ", b"ZM"):
        return
    nexe += 1
    try:
        start, dia = decode0.find_prologue(data)
    except ValueError:
        nontb += 1
        return
    try:
        prog = decode0.decode_user_code(data)
        hits.append((name, dia.name, len(prog)))
        print(f"HIT  {dia.name}  {len(prog):4d} stmts  {name}")
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
    root = Path(sys.argv[1])
    outdir = None
    if "--copy-hits" in sys.argv:
        outdir = Path(sys.argv[sys.argv.index("--copy-hits") + 1])
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        low = p.suffix.lower()
        if low == ".zip":
            walk_zip(str(p), p.read_bytes(), outdir)
        elif low in (".exe", ".com"):
            try_exe(str(p), p.read_bytes(), outdir)
        elif low == ".iso":
            print(f"(skipping iso {p}; mount or extract it first)")
    print(f"\n{nexe} EXEs scanned: {len(hits)} TB decode-ok, "
          f"{len(fails)} TB-but-fail, {nontb} not Turbo Basic")


if __name__ == "__main__":
    main()
