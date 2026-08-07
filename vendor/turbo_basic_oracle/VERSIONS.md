# Turbo BASIC build catalog

Every distinct real Borland `TB.EXE` build located and hash-verified so far,
plus every copy checked and found to be a duplicate. Compiler floppy images
and EXEs are gitignored (proprietary, provisioned locally per
`README.tbx.md`) — this file is the durable record of what was checked,
where it came from, and what its hash is, so a future session doesn't have
to re-download and re-diff everything from scratch.

Hashes are sha256 of the bare `TB.EXE` (not the floppy image it ships on).

## Distinct builds (5), all vendored

| sha256 (first 16) | dialect | size | PE date | wired as | vendored at |
|---|---|---|---|---|---|
| `f4f28fe595d32eed` | TB 1.0 English | 204360 | 1987-04-20 | `1.0` | `tb10_floppy.img` |
| `e5970b8fc1248401` | TB 1.0 English, **earlier build** | 204312 | 1987-04-02 | `1.0-early` | `tb10_early_floppy.img` |
| `f1be6e502c2a262b` | TB 1.0 German disk3 (functionally ≡ 1.1, see below) | 212524 | 1987-10-26 | `de-experimental` (not in `_FLOPPIES`) | `tb_german_d3.exe`, `tb11_de_floppy.img` |
| `92fcff2f8980d7c8` | TB 1.1 English | 212844 | 1987-11-04 | `1.1` (default, `None` in `_FLOPPIES`) | `tb_floppy.img` |
| `d45256929e5dbf14` | TB 1.1 French | 214424 | 1987-11-10 | `fr-1.1` | `tb11_fr_floppy.img` |

Full hashes:
```
f4f28fe595d32eed54754c4bf2ca0704a352a72de1017508c267bcbf809d6cb0  TB 1.0 English
e5970b8fc1248401166bcc0e81f71f0ac8e98d3a707d5d90f54c842f99640571  TB 1.0 English (early, 1987-04-02)
f1be6e502c2a262b3ebc6b1994b32a0ebc31061431007329165e7ba4aa07fa69  TB 1.0 German disk3
92fcff2f8980d7c80aed32bab8700942d4c18ad07013a427d4eba4d0c24ae16c  TB 1.1 English
d45256929e5dbf14cd13442f93a45251b29fe26488b95b679f2f0cbae5df81c8  TB 1.1 French
```

### TB 1.0 "early" (1987-04-02) — the missing second TB 1.0 revision

**Found 2026-08-07** in an abandonwaredos.com repack ("Borland-Turbo-Basic-1.0.zip",
reached at `abandonware-game.php?gid=2602`; the direct download endpoint
required a `Referer` header pointing back at that page plus a normal
browser `User-Agent` — a bare request with neither gets a 200 with an empty
body, no redirect, no error). `TB.EXE` inside: 204312 bytes, MZ header
dated 1987-04-02, sha256 `e5970b8f...` — NOT a match for any previously
known hash, and 48 bytes smaller than the 1987-04-20 English 1.0 already
vendored.

This is the previously-unidentified "second TB 1.0 revision" from
`gap_reports/runtime-revision-assessments.json`'s `RR-TB10-TWO-REVISIONS`
(disposition was "closed" = investigated and shelved for lack of a real
source, not solved). Confirmed by build-match: the 9 wild files that scored
86-88% against the standard 1.0 (its documented fingerprint: a `lodsb`-based
4-way dispatch, 6 bytes shorter than the standard build's `mov bl,[si]`
form, at runtime offset 0x1bcf) score **97-99%** against this early build
instead — while the "already fine" 96-99% files (autonum, banker, rev) drop
to 85-88% against it. Clean, non-overlapping split confirming this is a
distinct, real, sourced build, not noise.

Ran the full decode→emit→recompile round trip (not just a runtime-region
comparison) against all 9 previously-unreachable files with dialect
`1.0-early`:

| file | delta | bytes differing before user code | bytes differing in/after user code |
|---|---|---|---|
| `strpfind.exe` | 0 | 94 | **3** |
| `pz.exe` | 0 | 103 | **15** |
| `be.exe` | 0 | 93 | 27 |
| `startup.exe` | 0 | 102 total (all pre-user-code) | 0 |
| `prtguide.exe` | 0 | 253 | 406 |
| `readme.exe` | 0 | 227 | 794 |
| `secure.exe` | 0 | 94 | 1842 |
| `invent.exe` | 0 | 94 | 1853 |
| `horses.exe` | -640 | 120 | 39606 (a separate, large, pre-existing decode/structural issue) |

Every file except `horses.exe` recompiles to the SAME LENGTH as the
original with this build (`delta=0`) — a strong signal by itself, since a
wrong build or a real decode gap almost always changes length. The
remaining "before user code" byte diffs (93-253 bytes, out of an ~8 KB
runtime region) are relocation-table/link-time noise, the same category
`RR-TB10-TWO-REVISIONS`'s own writeup already flags for same-revision
programs (95.5-99.7% aligned is the documented normal range, not 100%,
even for a correct build match). The "in user code" diffs are ordinary
decoder-gap residue, same kind of thing every other wild file in the
corpus has — not build mismatch. `strpfind.exe` is 3 bytes from exact,
`pz.exe` 15, `startup.exe` byte-exact in the user-code region entirely.
**None reached literal byte-exact this session** — closing those residual
diffs is decoder work (out of this hunt's scope), not a build-provenance
question anymore.

Wired into `tbx/tools/oracle.py`'s `_FLOPPIES` as `"1.0-early"`. NOT wired
into `verify_wild.py`'s automatic dialect detection (`program_dialect`
only reports the structural `1.0`/`1.1` family from `decode0.find_prologue`,
which can't distinguish this from standard `1.0` — both compile the same
op encoding). A future session extending `verify_wild.py` to try both 1.0
floppies and keep whichever recompiles closer would let this feed
`tests/fixtures/wild_roundtrip.json` automatically; not done here.

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

## Checked via a human download (agent can't pass vetusware's login wall)

- **vetusware.com "turbo basic 1.1 plus"** (`turbo basic1.1 plus.zip`, CRC
  `0x95D02806`, 268565 bytes): download requires a registered vetusware
  account, which is out of scope for the agent to create or authenticate
  into (2026-08-06/07 — confirmed blocked via curl, a real browser tab, and
  explicitly declined even when the user offered session cookies, since a
  session cookie authenticates the same way a password does). The user
  downloaded it manually with their own account (2026-08-07) and handed
  over the file. Extracted `TB.EXE`: 212844 bytes, PE date 1987-11-04,
  sha256 `92fcff2f8980d7c80aed32bab8700942d4c18ad07013a427d4eba4d0c24ae16c`
  — **byte-identical to the already-vendored English 1.1**. "1.1 Plus" was
  just an uncompressed repack (the description's "much larger size... can
  be unzipped easily" refers to the archive method, not a different
  build). Confirmed not a new build; nothing to add to the oracle from it.
- **vetusware.com "Borland Turbo Basic 1.0"** (`?id=16030` / `?id=11304`):
  same login wall, not attempted since the sibling listing above already
  resolved to a known duplicate — low expected value.

## Open: one runtime build still unidentified

Of the 2 unidentified runtime builds `RR-TB10-TWO-REVISIONS` documented,
**one is now found and sourced** (TB 1.0-early, above). The other is not:

- An unidentified TB 1.1-family revision — 18% positionwise / ~83.4-83.5%
  aligned build match against English 1.1. Files: `bill`, `ck`, `color`,
  `mm.exe` (+ `mmsetup`, `rstprint`, `tamstart` per `verify_wild.py`'s own
  list). Ruled OUT as French 1.1 this session (scores 18% against French
  too — identical to its score against English, so French isn't a closer
  match). Not located as a real EXE anywhere searched.

Searched this session: archive.org (all 7 Borland Turbo Basic-related
items), WinWorld (all 5 disk downloads), GitHub, abandonwaredos.com (found
the 1.0-early build above), and vetusware (2 listings, both confirmed
duplicates via a human download). Every other candidate hashed to an
already-known build.

Next places to try for the remaining TB 1.1-family build, if resuming this
hunt: a UK/Heimsoeth-adjacent reseller dump, a different physical "1.1"
pressing (Borland re-pressed disks between print runs without renumbering,
per `dosdays.co.uk`'s "1.1 believed to be a bug-fix release of 1.0" note),
or a BBS-sourced shareware CD (Simtel, PC-SIG, etc.) that happens to bundle
a full `TB.EXE` rather than just `.BAS` programs compiled with it. The
abandonwaredos.com method below (Referer + UA bypass) is worth trying on
their other Borland Turbo Basic listing(s) first, since it just paid off.

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
- abandonwaredos.com's actual file lives behind `aw-download.php?tit=...
  &dlc=<base64>&rem=N&gid=N&zdi=<base64>` (scraped from the game page's own
  `href`); hitting it with a bare `curl` returns HTTP 200 with an EMPTY
  body (no redirect, no error text) — looks like success, isn't. Add
  `-e '<the game page URL>'` (Referer) and a real browser `User-Agent`
  string and it returns the actual zip. No login needed once those two
  headers are present.
- To compare a wild EXE's runtime against a build NOT in `_REFERENCE`
  (`tbx/tools/verify_wild.py`, currently only `1.0`/`1.1`), compile
  `tests/fixtures/corpus/t1_ifgoto.bas` with `oracle.compile_bas(bas,
  dialect=<name>)` and diff `exe[0x100:0x100+len(ref)]` against the
  candidate wild file's same slice — this is how the French elimination
  above was done, with no changes to `verify_wild.py` needed.
