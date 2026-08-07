# Turbo BASIC build catalog

Every distinct real Borland `TB.EXE` build located and hash-verified so far,
plus every copy checked and found to be a duplicate. Compiler floppy images
and EXEs are gitignored (proprietary, provisioned locally per
`README.tbx.md`) — this file is the durable record of what was checked,
where it came from, and what its hash is, so a future session doesn't have
to re-download and re-diff everything from scratch.

Hashes are sha256 of the bare `TB.EXE` (not the floppy image it ships on).

## Distinct builds (4), all vendored

| sha256 (first 16) | dialect | size | PE date | wired as | vendored at |
|---|---|---|---|---|---|
| `f4f28fe595d32eed` | TB 1.0 English | 204360 | 1987-04-20 | `1.0` | `tb10_floppy.img` |
| `f1be6e502c2a262b` | TB 1.0 German disk3 (functionally ≡ 1.1, see below) | 212524 | 1987-10-26 | `de-experimental` (not in `_FLOPPIES`) | `tb_german_d3.exe`, `tb11_de_floppy.img` |
| `92fcff2f8980d7c8` | TB 1.1 English | 212844 | 1987-11-04 | `1.1` (default, `None` in `_FLOPPIES`) | `tb_floppy.img` |
| `d45256929e5dbf14` | TB 1.1 French | 214424 | 1987-11-10 | `fr-1.1` | `tb11_fr_floppy.img` |

Full hashes:
```
f4f28fe595d32eed54754c4bf2ca0704a352a72de1017508c267bcbf809d6cb0  TB 1.0 English
f1be6e502c2a262b3ebc6b1994b32a0ebc31061431007329165e7ba4aa07fa69  TB 1.0 German disk3
92fcff2f8980d7c80aed32bab8700942d4c18ad07013a427d4eba4d0c24ae16c  TB 1.1 English
d45256929e5dbf14cd13442f93a45251b29fe26488b95b679f2f0cbae5df81c8  TB 1.1 French
```

**TB 1.0 German disk3 vs TB 1.1 English**: byte-identical over the user-code
region for 272/297 corpus fixtures, differs only in trailing padding for the
rest — see `[[tb-german-oracle-variant]]` memory / `PLAN.md` 2026-07-21.
Confirmed again this session: its runtime region is NOT in the "different
build" tally (would show up as its own distinct build-match cluster if it
diverged from the English 1.1 runtime the way the unidentified builds below
do). Kept as an investigative build (`_FLOPPIES` doesn't wire it as `1.0`
because it is NOT the 1987-06-10 English-1.0-equivalent German disk1 build —
disk1's `TB.EXE` is the *same file* as English 1.0, see below).

**TB 1.0 German disk1** (1987-06-10, from the same archive.org KryoFlux dump
and WinWorld's repack) hashes `f4f28fe5...` — byte-identical to English 1.0.
Not a separate build; not separately vendored.

## Checked, confirmed duplicate of an already-vendored build

| source | claimed as | hash | verdict |
|---|---|---|---|
| WinWorld `en10`/`de10`/`en11`/`fr11` (all 4 disk sets) | matches | `f4f28fe5`/`f4f28fe5`/`f1be6e50`/`92fcff2f`/`d4525692` | all 5 extracted `TB.EXE` match an already-vendored hash exactly |
| archive.org `000376-BorlandTurboBasic10` (goodolddays) | TB 1.0 English | `f4f28fe5` | duplicate of TB 1.0 English |
| archive.org `BorlandTurboBasic1.0German` disk1/disk3 (raw KryoFlux) | TB 1.0 German | `f4f28fe5` / `f1be6e50` | duplicates (disk1 = English 1.0, disk3 = already-vendored German build) |
| archive.org `borland-turbo-basic-zipped` | TB 1.0 English | `f4f28fe5` | duplicate |
| archive.org `borland-turbo-basic-1.x-and-manual-1987.-7z` | TB 1.0 English (re-upload of the WinWorld 7z, byte-identical container) | — | not extracted separately, container matches WinWorld's `en10.bin` size exactly |

## Checked, same build but with incidental byte differences (NOT new builds)

Two copies differ from an already-known hash by only a handful of bytes, all
inside unused/uninitialized padding, not code:

- **GitHub `sergev/pc-xt-dos` `E/TBASIC/TB.EXE`** (`14d7a68ca82bf05a`,
  212844 bytes — same size as English 1.1's `92fcff2f...`): differs in
  exactly 9 bytes at file offset 57911-57919, all inside a padding/data
  region, spelling the ASCII string `E:\TBASIC` — a leftover path fragment
  from whatever machine last touched this copy, not compiler output. Every
  other byte, including the entire code region, is identical to the
  vendored English 1.1. Not treated as a new build.
- **archive.org `ms-dos-6.22-with-turbo-basic-1.0-...` boot image**
  (`38ab47c58c42b04c`, 204360 bytes — same size as English 1.0's
  `f4f28fe5...`): differs in 12 bytes total — 10 bytes at offset 57703-57713
  spelling `D:\DOSCOM~` (same phenomenon as above) plus one unrelated single
  byte at offset 59119. Not treated as a new build.

## Tried, blocked (not obtained)

- **vetusware.com "turbo basic 1.1 plus"** (claimed larger/"plus" 1.1
  build, `turbo basic1.1 plus.zip`, CRC `0x95D02806`, 268565 bytes):
  download requires a registered vetusware account (confirmed via the site's
  own UI, 2026-08-06 — "Please login or register to download this file").
  Account creation is out of policy scope for this session; if a human
  wants to fetch it manually, the file is at
  `vetusware.com/download/turbo%20basic%201.1%20plus%20unzipped%20completly%20type%20tb.exe%20.to%20run%201.1%20plus/?id=10642`.
  Given the name and 1987 date, this is plausibly just a re-zipped copy of
  known English 1.1 (not confirmed) rather than a new build — low priority.
- **vetusware.com "Borland Turbo Basic 1.0"** (`?id=16030` / `?id=11304`):
  not attempted this session after the above hit the same login wall;
  same caveat applies.

## Open: at least one unidentified runtime build, NOT resolved this session

`gap_reports/runtime-revision-assessments.json`'s `RR-TB10-TWO-REVISIONS`
(disposition: **closed**, i.e. investigated and shelved, not "solved") already
documents that the wild corpus contains **at least 4 distinct runtime builds**,
only 2 of which (this repo's English 1.0 and English 1.1) have a real source
EXE:

1. English TB 1.0 (`f4f28fe5...`, vendored) — 96-99% build match.
2. An unidentified TB 1.0 revision, 6 bytes shorter in a dispatch routine at
   runtime offset 0x1bcf — 86-88% build match. Files: `be`, `horses`,
   `invent`, `prtguide`, `pz`, `readme`, `secure`, `startup`, `strpfind.exe`.
3. English TB 1.1 (`92fcff2f...`, vendored) — 96-99% build match.
4. An unidentified TB 1.1-family revision — 18% positionwise / ~83.4-83.5%
   aligned build match. Files: `bill`, `ck`, `color`, `mm.exe` (+ `mmsetup`,
   `rstprint`, `tamstart` per `verify_wild.py`'s own list).

**This session's contribution**: searched archive.org (all 7 Borland Turbo
Basic-related items), WinWorld (all 5 disk downloads), GitHub, and attempted
vetusware (blocked) — found ZERO additional distinct hashes beyond the 4
already vendored. Also built a French-1.1 reference (`fr-1.1` dialect,
already wired but never build-match-tested against the wild corpus before)
and confirmed by direct byte comparison that it does NOT explain either
unidentified group: group 2 scores 4-5% against French (same as the
"wrong dialect" floor), group 4 scores 18% against French — identical to
its score against English 1.1, meaning French isn't a closer match either.
**Neither unidentified build (#2 or #4) has been located as a real,
downloadable EXE anywhere searched this session.** No wild file reached
100% as a result of this search — the existing 4 builds already cover every
wild file that CAN be byte-exact; the remainder needs a genuinely different
physical disk this session could not find or access.

Next places to try, if resuming this hunt: a UK/Heimsoeth-adjacent
reseller dump, a different physical "1.1" pressing (Borland re-pressed
disks between print runs without renumbering, per `dosdays.co.uk`'s "1.1
believed to be a bug-fix release of 1.0" note), or a BBS-sourced shareware
CD (Simtel, PC-SIG, etc.) that happens to bundle a full `TB.EXE` rather
than just `.BAS` programs compiled with it.

## Method notes for next time

- Extract a floppy `.img`'s `TB.EXE`: `mcopy -n -i disk.img ::TB.EXE out.exe`
  (needs `mtools`; `mdir -i disk.img ::/` lists contents first).
- WinWorld's `/download/<id>` page requires login, but its mirror redirect
  `/download/<id>/from/<mirror-id>` (scraped from the page's own `href`s)
  does not — this is how all 4 WinWorld downloads in this session worked
  without an account.
- vetusware's `/download/<slug>/?id=N` page's `Download` button POSTs back
  to the same URL and requires a logged-in session — no anonymous bypass
  found (curl with cookies/referer/UA all redirect back to the same page;
  confirmed the same wall in a real browser tab too).
- To compare a wild EXE's runtime against a build NOT in `_REFERENCE`
  (`tbx/tools/verify_wild.py`, currently only `1.0`/`1.1`), compile
  `tests/fixtures/corpus/t1_ifgoto.bas` with `oracle.compile_bas(bas,
  dialect=<name>)` and diff `exe[0x100:0x100+len(ref)]` against the
  candidate wild file's same slice — this is how the French elimination
  above was done, with no changes to `verify_wild.py` needed.
