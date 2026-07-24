"""DGROUP layout, line table and pool-window derivation."""

from __future__ import annotations
import struct
from typing import Any

from tbx.decode0.const import ARR_BLOCK, COMMON_BASE, MARKER, VAR_BASE
from tbx.decode0.datapool import _is_rt_slot, _parse_static_slot


def _blit_at(ops: list[tuple[Any, ...]], i: int):
    """Index of the get_gfx/put_gfx consuming ops[i]'s movsi array-descriptor push,
    or None. TB 1.1 pushes the descriptor far (movsi; movdx; movesdx; blit) via the
    relocated array segment; TB 1.0 pushes it near (movsi; blit) -- no segment setup
    (v10_t1_getput)."""
    if ops[i][1] != "movsi":
        return None
    if i + 1 < len(ops) and ops[i + 1][1] in ("get_gfx", "put_gfx"):
        return i + 1
    if (
        i + 3 < len(ops)
        and ops[i + 1][1] == "movdx"
        and ops[i + 2][1] == "movesdx"
        and ops[i + 3][1] in ("get_gfx", "put_gfx")
    ):
        return i + 3
    return None


def _varptr_at(ops: list[tuple[Any, ...]], i: int) -> bool:
    """Whether ops[i]'s movsi is the address source of a VARPTR$ chain."""
    return (
        ops[i][1] == "movsi"
        and i + 6 < len(ops)
        and ops[i + 1][1] == "movdx"
        and ops[i + 2][1] == "movesdx"
        and ops[i + 3][1] == "movm_imm"
        and ops[i + 3][2] == 0x2E
        and ops[i + 4][1] == "movm_es"
        and ops[i + 4][2] == 0x32
        and ops[i + 5][1] == "movm_si"
        and ops[i + 5][2] == 0x30
        and ops[i + 6][1] == "shortstr"
    )


def _layout(exe: bytes, ops: list[tuple[Any, ...]]) -> dict[str, Any]:
    """Solve the DGROUP layout under the unified slot model: every array
    owns a 0x36 slot from DS:0120 (statics first in reverse DIM order, then runtime
    blocks); scalars from grid end; pool at align16(scalar_end)+4 preceded by the
    00 80 16 00 marker. The file image may omit the scalar band: `delta` =
    (ds + pool_base - 4) - marker_pos shifts all pool/descriptor/string file reads.
    Returns {ds, delta, scalar_base, scalars, strs, pool_base, arrs, rt_blocks,
    n_static}."""
    # The LINE box-fill runtime unit (any `,B`/`,BF` — line-op flag bit 0x04) owns a
    # 4-byte DGROUP cell at 0x120 when linked, shifting the user slot grid to 0x124
    # (witnessed: t1_linevb has A at 0x124; t1_lineb's pool at 0x134 = align16(0x124)+4).
    vb = VAR_BASE + (4 if any(o[1] == "line" and o[2] & 0x04 for o in ops) else 0)
    fp_disps = {o[2] for o in ops if o[1] in ("fld", "fstp", "fcomp")} | {
        o[3] for o in ops if o[1] in ("fold", "fold_n")
    }
    # Double-precision FP disps (8-byte slots).
    fp64_disps = {o[2] for o in ops if o[1] in ("fld64", "fstp64")} | {
        o[3] for o in ops if o[1] in ("fold64", "fold_n64")
    }
    fp64_disps = {d for d in fp64_disps if d >= VAR_BASE}
    # Long-integer disps (0xDB FILD/FISTP m32, 0xDA folds) -> width-4 `&` slots.
    long_disps0 = {o[2] for o in ops if o[1] in ("fild32", "fistp32")} | {
        o[3] for o in ops if o[1] == "ifold32"
    }
    long_disps0 = {d for d in long_disps0 if d >= VAR_BASE}
    # Disps below VAR_BASE are runtime system cells (0x2C int<->FP scratch, 0x88/0x94
    # COLOR cells), never scalar slots.
    int_disps0 = {
        o[2]
        for o in ops
        if o[1]
        in (
            "movax_m",
            "addax_m",
            "imul_m",
            "movm_imm",
            "movm_ax",
            "addm_ax",
            "subm_ax",
            "inc_m",
            "dec_m",
            "addm_i8",
            "cmp_mi8",
            "cmp_mi16",
            "cmpm_ax",
            "movsim",
        )
        and o[2] >= VAR_BASE
    }
    fild_disps0 = {o[2] for o in ops if o[1] == "fild" and o[2] >= VAR_BASE}
    # Runtime-DIM bookkeeping blocks: movsi targets opening a dim bracket.
    rt_blocks = sorted(
        {
            ops[i][2]
            for i in range(len(ops) - 3)
            if ops[i][1] == "movsi"
            and ops[i + 1][1] == "movdx"
            and ops[i + 2][1] == "movesdx"
            and ops[i + 3][1] in ("dim_begin", "dim_end", "erase")
        }
    )
    # Static-array ERASE (INT EC sub 38): same movsi/movdx/movesdx prefix as the
    # runtime-DIM forms above, but its target is an ordinary STATIC array slot,
    # not a runtime block and not a string descriptor (probe t1_erasestatic).
    erase_static_disps = {
        ops[i][2]
        for i in range(len(ops) - 3)
        if ops[i][1] == "movsi"
        and ops[i + 1][1] == "movdx"
        and ops[i + 2][1] == "movesdx"
        and ops[i + 3][1] == "erase_static"
    }
    # Far array-element CALL-arg push: movsi:elem; movdx; movesdx; arg_push_arr.
    # The movsi target is the static array element (resolved via loc), not a descriptor.
    argarr_disps = {
        ops[i][2]
        for i in range(len(ops) - 3)
        if ops[i][1] == "movsi"
        and ops[i + 1][1] == "movdx"
        and ops[i + 2][1] == "movesdx"
        and ops[i + 3][1] == "arg_push_arr"
    }
    # GET/PUT graphics-blit array push (both dialect forms, see _blit_at).
    # The movsi target is an ARRAY slot record (witnessed t1_getput), not a string
    # descriptor -- without this exclusion the walk misreads the slot as a string
    # scalar and the layout solves with the pool 0x30 low.
    blit_disps = {ops[i][2] for i in range(len(ops)) if _blit_at(ops, i) is not None}
    varptr_disps = {ops[i][2] for i in range(len(ops)) if _varptr_at(ops, i)}
    # PALETTE USING on a static array passes a constant element address with
    # the same movsi/movdx/movesdx shape as other far array consumers.  It is
    # an INTEGER element, not a string descriptor (probe_paletteusing_static).
    palette_disps = {
        ops[i][2]
        for i in range(len(ops) - 3)
        if ops[i][1] == "movsi"
        and ops[i + 1][1] == "movdx"
        and ops[i + 2][1] == "movesdx"
        and ops[i + 3][1] == "palette_using"
    }
    # A whole-array CALL argument passes the array's slot-record address
    # through SI to runtime vector D4.  The slot is not a string descriptor
    # (probe arrayparam6; wild zip.exe).
    whole_array_disps = {
        ops[i][2]
        for i in range(len(ops) - 1)
        if ops[i][1] == "movsi" and ops[i + 1][1] == "arg_push_array"
    }
    # movsi targets are string descriptors: scalar slots (string vars) or
    # pooled literals -- except constant far-element offsets.
    movsi_disps = (
        {
            ops[i][2]
            for i in range(len(ops))
            if ops[i][1] == "movsi"
            and ops[i][2] >= VAR_BASE  # sub-VAR_BASE = scratch (SELECT CASE str temp)
            and not (
                i + 1 < len(ops)
                and ops[i + 1][1] in ("far_spush", "far_strassign", "add_si_sp")
            )
        }
        - set(rt_blocks)
        - argarr_disps
        - erase_static_disps
        - blit_disps
        - varptr_disps
        - palette_disps
        - whole_array_disps
    )
    prompt_disps = {o[2] for o in ops if o[1] in ("input", "line_input")}
    addsi_bases = {o[2] for o in ops if o[1] == "addsi"}
    P = exe.rfind(MARKER)
    if P < 0:
        raise ValueError("pool marker 00 80 16 00 not found")

    def walk_run(sb):
        """Greedy scalar-band walk from the grid end; evidence below sb is grid-cell
        traffic (slot lo/span reads), not scalars."""
        ints = {d for d in int_disps0 if d >= sb}
        filds = {d for d in fild_disps0 if d >= sb}
        f64s = {d for d in fp64_disps if d >= sb}
        longs = {d for d in long_disps0 if d >= sb}
        run, strs, d = {}, set(), sb
        while True:
            if d in ints or (d in filds and d not in fp_disps and d not in f64s):
                run[d] = 2
                d += 2
            elif d in f64s:
                run[d] = 8
                d += 8
            elif d in fp_disps or d in longs:
                run[d] = 4
                d += 4
            elif d in movsi_disps:  # string var descriptor slot
                run[d] = 4
                strs.add(d)
                d += 4
            elif d + 2 in ints:
                # Phantom FOR step slot: an integer FOR with a variable limit
                # allocates step+limit temp slots before I%, and the step slot
                # is never referenced when STEP is the literal-1 INC fast path
                # (witnessed t1_fori: 0x120 phantom, 0x122 limit, 0x124 I%).
                run[d] = 2
                d += 2
            elif d + 4 in ints:
                # Both temp slots phantom: a literal limit AND a literal step
                # other than 1 need neither temp (the limit folds into cmp_mi8,
                # the step into addm_i8), so both reserved words before I% go
                # unreferenced (witnessed q_forstep: 0x120/0x122 phantom, 0x124
                # I%).
                run[d] = 2
                d += 2
            else:
                return run, strs, d

    def find_statics(ds, sb, n_want):
        """Static records sit at exact slot positions in mixed programs but float
        after a variable-length zero-init table in static-only ones;
        a window-bounded floating scan covers both. Window order == slot order.
        The window extends one extra ARR_BLOCK past `sb`: a literal-limit FOR
        loop can plant its temp/loop-var words inside the tail of the LAST
        array's own 0x36 slot (its bookkeeping record is dead at runtime once
        the loop's constant-base addsi is compiled, so the compiler appears to
        reuse the space) -- when that happens the static-record run legitimately
        starts a bit past `ds + vb` and the last record's populated bytes can
        extend a few bytes past the un-widened `ds + sb` boundary (witnessed
        wild/probes_gap16/q_gap16{q,u}.bas, offsets 48/32 bytes, both < 0x36)."""
        out, pos, end = [], ds + vb, ds + sb + ARR_BLOCK
        while pos < end - 11 and len(out) < n_want:
            rec = _parse_static_slot(exe, pos) if pos + 24 <= len(exe) else None
            if rec is not None:
                out.append(rec)
                pos += 6 * rec["rank"] + 6  # 12 / 18 / 24 bytes
            else:
                pos += 2
        return out if len(out) == n_want else None

    # Scalars found inside the COMMON band (see the rt_blocks branch below);
    # empty on every other path. Captured here so `finish` can report them.
    band_slots: list[int] = []

    def finish(ds, n_static, statics, sb, run, strs, pool_base, delta):
        # Augment `run` with any evidenced scalar disps in [sb, pool_base-4) that
        # walk_run missed due to a gap (e.g. phantom step/limit slots before I% in
        # an integer FOR loop, or typed scalars after a wholly unreferenced slot).
        # The candidate pool boundary separates scalar evidence below it from
        # numeric/string literals at or above it.
        run = dict(run)
        strs = set(strs)
        for d in int_disps0:
            if d >= sb and d < pool_base - 4 and d not in run:
                run[d] = 2
        for d in fp64_disps:
            if d >= sb and d < pool_base - 4 and d not in run:
                run[d] = 8
        for d in fp_disps:
            if d >= sb and d < pool_base - 4 and d not in run:
                # Same candidate-boundary rule for a SINGLE scalar reached
                # after a hole; values at/above the boundary remain pool
                # literals.
                run[d] = 4
        for d in movsi_disps:
            if d >= sb and d < pool_base - 4 and d not in run:
                # An evidenced string scalar can sit beyond an unreferenced
                # hole that stopped walk_run.  The candidate pool boundary
                # distinguishes it from a pooled literal descriptor.
                run[d] = 4
                strs.add(d)
        # Validate every code-referenced descriptor under (pool_base, delta): pooled
        # literal descs (movsi targets that aren't slots) and prompt words map to
        # file P + 4 + (d - pool_base) and must read as <len|8000><ptr> records --
        # except movsi disps landing inside a static STRING array's element span
        # (constant-index element access, e.g. `A$(2) = ...`): those are array
        # elements, not descriptors (witnessed q_sstat).
        str_spans = [
            (a["base"], a["base"] + a["esz"] * a["count"])
            for a in statics
            if a["str"]
        ]
        descs = (movsi_disps - set(run)) | (prompt_disps - {pool_base - 4})
        for d in descs:
            if any(lo <= d < hi for lo, hi in str_spans):
                continue
            off = P + 4 + d - pool_base
            if d < pool_base - 4 or off < 0 or off + 2 > len(exe):
                return None
            w0 = struct.unpack_from("<H", exe, off)[0]
            if not w0 & 0x8000:
                return None
        # All remaining FP/int evidence above the run must fall in a static data
        # span; FP loads may also hit the pool (non-integral literals), but only
        # in the bounded window below the first static base -- without that bound
        # a wrong (too-small) n would pass with elements masquerading as pool.
        spans = [(a["base"], a["base"] + a["esz"] * a["count"]) for a in statics]
        pool_top = min((a["base"] for a in statics), default=None)
        for d in sorted(fp_disps | fp64_disps | int_disps0):
            if d < sb or d in run:
                continue
            if any(lo <= d < hi for lo, hi in spans):
                continue
            if d >= pool_base - 4 and (pool_top is None or d < pool_top):
                continue  # pooled FP literal ('!' singles;
            return None  # descending n guards the no-statics case)
        for d in fild_disps0:  # pooled int literals live above the marker
            if d >= sb and d not in run and d < pool_base - 4:
                return None
        if not addsi_bases <= {a["base"] for a in statics}:
            return None
        for j, a in enumerate(statics):  # slot i -> textual name V{n_static-1-i}
            a["name"] = f"V{n_static - 1 - j}"
            # is_long: the 0x02 type-byte pre-seed (authoritative for [SI]-only loop
            # arrays), OR any long disp landing in the element span (constant-index).
            a["long"] = a["long"] or any(
                a["base"] <= d < a["base"] + a["esz"] * a["count"] for d in long_disps0
            )
        # Long slots: long disps that ended up as scalars (not in an array span).
        long_slots = {d for d in long_disps0 if d in run}
        return {
            "ds": ds,
            "delta": delta,
            "var_base": vb,
            "scalar_base": sb,
            "scalars": run,
            "strs": strs,
            "long_slots": long_slots,
            "pool_base": pool_base,
            "arrs": statics,
            "rt_blocks": rt_blocks,
            "n_static": n_static,
            # Non-empty only when the blocks sit in the COMMON band: those
            # arrays were declared COMMON, which compiles to no ops at all, so
            # the band position is the ONLY evidence of the declaration and
            # core.py has to synthesize it back (probe t1_commonarr).
            "common_arrs": rt_blocks if rt_blocks and rt_blocks[0] == COMMON_BASE < vb else [],
            "common_slots": sorted(band_slots),
        }

    if rt_blocks:
        if rt_blocks[0] == COMMON_BASE < vb:
            # A COMMON'd array's descriptor block lives in the CHAIN-persistent
            # COMMON band at DS:0110, ahead of the ordinary slot grid, so the
            # blocks start BELOW var_base and no static slots precede them, so
            # the same walk-from-sb solve applies -- only the anchor moves
            # (probe t1_commonarr; wild tbd73.exe, whose TBW73.INC COMMONs
            # eleven DIMmed arrays).
            n_static, base0 = 0, COMMON_BASE
        else:
            n_static, rem = divmod(rt_blocks[0] - vb, ARR_BLOCK)
            base0 = vb
            if rem:
                raise ValueError("runtime blocks are not 0x36-contiguous after statics")
        if rt_blocks != [rt_blocks[0] + ARR_BLOCK * i for i in range(len(rt_blocks))]:
            raise ValueError("runtime blocks are not 0x36-contiguous after statics")
        n = n_static + len(rt_blocks)
        sb = base0 + ARR_BLOCK * n
        run, strs, dend = walk_run(sb)
        if base0 == COMMON_BASE:
            # Past the blocks the band runs on into the COMMON SCALARS, then
            # aligns to 16 and carries a 16-byte band stamp; the ORDINARY band
            # starts at stamp+0x10 (probe t1_commonarrmix: `COMMON A(1), C%`
            # puts C% at 0x146 right after the single block, stamp at 0x150,
            # ordinary band empty at 0x160). So the walk above covered the
            # band's own scalars -- those are the COMMON declarations, which
            # compile to no ops and are recoverable from nothing else -- and
            # the ordinary scalars need a second walk past the stamp.
            band_slots[:] = sorted(run)
            ord_base = ((dend + 15) & ~15) + 0x10
            band_run, band_strs = dict(run), set(strs)
        # Anchor ds on the slot grid itself: every runtime block must
        # show the bare rank+type record, every static slot a populated record.
        pat = tuple(
            struct.pack("<HH", 0, (r << 8) | t)
            for r in (1, 2, 3)
            for t in (0x00, 0x04, 0x06, 0x0A)
        )
        need = rt_blocks[-1] + 18  # last record byte we must read
        for pos in range(0, len(exe) - 18, 2):
            if exe[pos : pos + 4] not in pat:
                continue
            ds = pos - rt_blocks[0]
            if ds <= 0 or ds % 16 or ds + need > len(exe):
                continue
            if not all(_is_rt_slot(exe, ds + b) for b in rt_blocks):
                continue
            if base0 == COMMON_BASE:
                # The ORDINARY region opening at `ord_base` is not
                # scalars-only: an ordinary STATIC array's own 0x36 slot sits
                # there first, ahead of the scalars (probe t1_commonarrstatic:
                # `DIM R$(50)` lands its populated record at DS:0160, right at
                # ord_base, with the scalars only starting past it). On the
                # non-COMMON path the static count falls out of the gap between
                # `vb` and the first runtime block; here the statics come AFTER
                # the blocks, so read them off the image directly -- ds is
                # known at this point, which it is not where the band walk runs.
                statics, q = [], ds + ord_base
                while True:
                    rec = _parse_static_slot(exe, q) if q + 24 <= len(exe) else None
                    if rec is None:
                        break
                    statics.append(rec)
                    q += ARR_BLOCK
                sb = ord_base + ARR_BLOCK * len(statics)
                run, strs, dend = walk_run(sb)
                if not run:
                    dend = sb
                run = {**band_run, **run}
                strs = band_strs | strs
                n_static = len(statics)
                for j, a in enumerate(statics):
                    a["name"] = f"V{n_static - 1 - j}"
            else:
                statics = find_statics(ds, rt_blocks[0], n_static)
            if statics is None:
                continue
            # pool_base >= align16(walk end)+4; trailing unreferenced scalars can
            # push it higher -- the descriptor evidence pins it exactly.
            pb0 = ((dend + 15) & ~15) + 4
            # The pool begins no later than the first static array's element
            # data.  Use that structural bound instead of a fixed-size tail:
            # large programs can have hundreds of string scalar descriptors
            # after the last evidence walk reached directly (wild
            # cleanup.exe/reformat.exe).
            pool_stop = min((a["base"] for a in statics), default=pb0 + 0x110) + 4
            for pool_base in range(pb0, pool_stop, 16):
                delta = ds + pool_base - 4 - P
                if delta < 0:
                    continue
                lay = finish(ds, n_static, statics, sb, run, strs, pool_base, delta)
                if lay is not None:
                    return lay
        raise ValueError("DGROUP layout not solvable (runtime slot grid anchor)")

    def read_stamp(pos):
        """A 16-byte COMMON band stamp at file `pos` (see the COMMON block
        below): (s1, b1, s2, b1+s1, 0, b1, 0, b1) -> (s1, s2, b1), or None."""
        if pos < 0 or pos + 16 > len(exe):
            return None
        w = struct.unpack_from("<8H", exe, pos)
        s1, b1, s2, b2, w3, b3, w4, b4 = w
        if w3 or w4 or b3 != b1 or b4 != b1 or b2 != b1 + s1:
            return None
        if b1 < 0x110 or s1 >= 0x1000 or s2 >= 0x1000 or s1 % 2 or s2 % 4:
            return None
        return s1, s2, b1

    # Stamp-anchored solve -- the primary path for every program without
    # runtime arrays. The compiler stamps the ordinary-scalars band
    # descriptor into the init image as 8 LE words
    #   (num_size, num_base, str_size, num_base+num_size,
    #    n_static, grid_base, 0, num_base)
    # with num_base == grid_base + ARR_BLOCK*n_static, DIRECTLY followed by
    # the n_static populated slot records at ARR_BLOCK stride, and DIRECTLY
    # preceded by the COMMON band stamp (degenerate all-(0,0x110) in a
    # program without COMMON -- the adjacency + degeneracy pair holds on
    # every no-rt corpus fixture and disambiguates coincidental byte
    # matches, witnessed zz_vm_darr_loop's zero-init false candidate).
    # The n_static=0 tail collapses to (0, num_base, 0, num_base) -- the
    # same shape read_stamp accepts -- and in the LINE box-fill fixtures
    # the band base is VAR_BASE with the runtime's own 4-byte cell counted
    # inside the band (gb == b1 == 0x120 while the user slots start 0x124;
    # witnessed t1_lineb s1=4 with zero user scalars, t1_linevb s1=8).
    # Scalars are SEGREGATED numerics-first, strings in a trailing sub-band
    # of s2 bytes (witnessed wild schart: s2=76) -- same band model as
    # COMMON. A NON-degenerate COMMON stamp routes to _bands_layout below
    # instead (segregation is then relative to the COMMON bands, witnessed
    # t1_common1). The stamp's own file position floats (error-trap line
    # table and variable-length zero-init data precede it), so it is found
    # by shape. This must run BEFORE the walk paths: a wide scalar band
    # pushes the floating record run far past find_statics's window and the
    # greedy walk can then "solve" a wrong-but-finish-passing layout
    # (witnessed t1_bandwide, where the walk layout later reads a phantom
    # pooled double past EOF; t1_bandstr witnesses the string sub-band;
    # wild schart/hfprop/vhfprop/inv87/invoice surfaced the shape). Where
    # both this and the walk paths solve, the layouts agree -- the stamp is
    # the compiler's own record of the band the walk infers (all 615 no-rt
    # corpus fixtures match it exactly; runtime-array programs carry no
    # stamp at all and stay on the grid-anchored path above).
    for pos in range(16, len(exe) - 16, 2):
        s1, b1, s2, b2, n, gb, z, b4 = struct.unpack_from("<8H", exe, pos)
        if z or b4 != b1 or b2 != b1 + s1:
            continue
        if not 0 <= n <= 31 or b1 != gb + ARR_BLOCK * n:
            continue
        if s1 % 2 or s2 % 4 or s1 >= 0x1000 or s2 >= 0x1000:
            continue
        if n:
            if gb != vb:
                continue
        elif b1 not in (vb, VAR_BASE):
            continue  # n=0: gb == b1; VAR_BASE covers the LINE-cell form
        com = read_stamp(pos - 16)
        if com is None or com[2] != 0x110 or com[0] or com[1]:
            continue  # no adjacent degenerate COMMON stamp
        statics = []
        for i in range(n):
            rec = _parse_static_slot(exe, pos + 16 + i * ARR_BLOCK)
            if rec is None:
                break
            statics.append(rec)
        if len(statics) != n:
            continue
        pool_base = ((b1 + s1 + s2 + 15) & ~15) + 4
        ds = P + 4 - pool_base
        if ds % 16 or ds <= 0:
            continue
        # Band-style scalar construction: evidenced widths (walk_run's
        # priority order), 2-byte int fillers in unreferenced numeric space
        # (phantom FOR temp slots land here), '$' every 4 string bytes.
        run, strs, d = {}, set(), b1
        while d < b1 + s1:
            if d in int_disps0 or (
                d in fild_disps0 and d not in fp_disps and d not in fp64_disps
            ):
                run[d] = 2
                d += 2
            elif d in fp64_disps:
                run[d] = 8
                d += 8
            elif d in fp_disps or d in long_disps0:
                run[d] = 4
                d += 4
            else:
                run[d] = 2
                d += 2
        if d != b1 + s1:
            continue  # an evidenced width straddles the numeric sub-band edge
        for d in range(b1 + s1, b1 + s1 + s2, 4):
            run[d] = 4
            strs.add(d)
        lay = finish(ds, n, statics, b1, run, strs, pool_base, 0)
        if lay is not None:
            return lay

    # No runtime arrays: marker-anchored, delta == 0 (all-witness path). Descending n:
    # a too-small n can misread scalars as pooled literals, but a too-large one can
    # never fabricate records, so the largest consistent candidate is the right one.
    for n in range(31, -1, -1):
        sb = vb + ARR_BLOCK * n
        run, strs, dend = walk_run(sb)
        # Candidate walk ends: greedy first (the normal case), then each
        # 16-aligned string position, longest first. A scalar band ending
        # exactly on a paragraph boundary puts the marker at a movsi-referenced
        # cell (the pooled "" literal doubles as the marker record), and the
        # greedy walk runs away through the pool's descriptors as phantom
        # string scalars (witnessed t1_poolrun).
        for dc in [dend] + sorted((d for d in strs if d % 16 == 0), reverse=True):
            run_c = {k: w for k, w in run.items() if k < dc}
            strs_c = {k for k in strs if k < dc}
            pool_base = ((dc + 15) & ~15) + 4
            ds = P + 4 - pool_base
            if ds % 16 or ds <= 0:
                continue
            statics = find_statics(ds, sb, n)
            if statics is None:
                continue
            # A movsi target unaccounted by the scalar walk and below the pool
            # is only explicable as a static STRING array element (constant
            # index); anything else there is neither a slot nor pooled.
            str_spans_c = [
                (a["base"], a["base"] + a["esz"] * a["count"])
                for a in statics
                if a["str"]
            ]
            if any(
                m < pool_base - 4 and not any(lo <= m < hi for lo, hi in str_spans_c)
                for m in movsi_disps - set(run_c)
            ):
                continue
            lay = finish(ds, n, statics, sb, run_c, strs_c, pool_base, 0)
            if lay is not None:
                return lay

    # COMMON: the compiler stamps two 16-byte band descriptors into the init
    # image, (num_size, num_base)(str_size, num_base+num_size)(0, num_base)
    # (0, num_base) -- one for the CHAIN-persistent COMMON band at DS:0110 and
    # one for the ordinary scalars, which are then SEGREGATED numerics-first
    # (witnessed t1_common1; positions vary and may overlay band cells, so the
    # stamps are found by shape, never position). pool = align16(ord_end) + 4
    # closes the loop on ds. Only engaged for a non-empty COMMON band: plain
    # programs carry degenerate stamps but solve on the walk paths above.
    if not (addsi_bases or argarr_disps or blit_disps):
        # The walk paths' evidence sets are VAR_BASE-filtered, but the COMMON
        # band starts at 0x110: rebuild them 0x110-filtered so a reference
        # into the band's first paragraph types its slot (or fails loud)
        # instead of being silently dropped.
        fp64_c = {o[2] for o in ops if o[1] in ("fld64", "fstp64")} | {
            o[3] for o in ops if o[1] in ("fold64", "fold_n64")
        }
        long_c = {o[2] for o in ops if o[1] in ("fild32", "fistp32")} | {
            o[3] for o in ops if o[1] == "ifold32"
        }
        int_c = {
            o[2]
            for o in ops
            if o[1]
            in (
                "movax_m", "addax_m", "imul_m", "movm_imm", "movm_ax", "addm_ax",
                "subm_ax", "inc_m", "dec_m", "addm_i8", "cmp_mi8", "cmp_mi16",
                "cmpm_ax", "movsim",
            )
        }
        fild_c = {o[2] for o in ops if o[1] == "fild"}
        movsi_c = {
            ops[i][2]
            for i in range(len(ops))
            if ops[i][1] == "movsi"
            and ops[i][2] >= 0x110
            and not (
                i + 1 < len(ops)
                and ops[i + 1][1] in ("far_spush", "far_strassign", "add_si_sp")
            )
        }
        fp64_c = {d for d in fp64_c if d >= 0x110}
        long_c = {d for d in long_c if d >= 0x110}
        int_c = {d for d in int_c if d >= 0x110}
        fild_c = {d for d in fild_c if d >= 0x110}
        for pool_base in range(0x124, 0x1124, 16):
            ds = P + 4 - pool_base
            if ds % 16 or ds <= 0:
                continue
            stamps = []
            for r in range(0x110, pool_base - 4, 16):
                st = read_stamp(ds + r)
                if st is not None:
                    stamps.append(st)
            com = [s for s in stamps if s[2] == 0x110 and s[0] + s[1] > 0]
            ord_ = [
                s
                for s in stamps
                if ((s[2] + s[0] + s[1] + 15) & ~15) + 4 == pool_base
                and s[2] >= 0x110 + sum(com[0][:2] if com else (0,))
            ]
            if len(com) != 1 or len(ord_) != 1:
                continue
            lay = _bands_layout(
                exe, com[0], ord_[0], pool_base, ds, P,
                fp_disps, fp64_c, long_c, int_c, fild_c,
                movsi_c, prompt_disps,
            )
            if lay is not None:
                return lay
    raise ValueError("DGROUP layout not solvable from the calibrated rules")


def _bands_layout(
    exe, com, ord_, pool_base, ds, P,
    fp_disps, fp64_disps, long_disps0, int_disps0, fild_disps0,
    movsi_disps, prompt_disps,
):
    """Validate a COMMON stamp pair against the op-stream evidence and build the
    layout: slots typed by evidence inside each sub-band, 2-byte '%' fillers in
    unreferenced numeric space (width mixes of equal size compile identically,
    so the filler choice is byte-safe -- witnessed t1_common1), '$' every 4
    bytes of string space. Returns None if any evidence contradicts the bands."""
    run: dict[int, int] = {}
    strs: set[int] = set()
    long_slots: set[int] = set()
    spans = []
    for s_num, s_str, base in (com, ord_):
        spans.append((base, base + s_num, base + s_num + s_str))
    # numeric sub-bands: place evidenced widths, fill gaps with 2-byte ints
    for lo, mid, _hi in spans:
        d = lo
        while d < mid:
            if d in fp64_disps:
                run[d] = 8
                d += 8
            elif d in long_disps0:
                run[d] = 4
                long_slots.add(d)
                d += 4
            elif d in fp_disps:
                run[d] = 4
                d += 4
            else:  # int evidence or unreferenced filler
                run[d] = 2
                d += 2
        if d != mid:
            return None  # an evidenced width straddles the band edge
    for _lo, mid, hi in spans:
        for d in range(mid, hi, 4):
            run[d] = 4
            strs.add(d)
    # every piece of evidence must land on a slot of the matching kind, or in
    # the pool window past the marker
    for d in int_disps0 | fild_disps0:
        if d >= 0x110 and not (run.get(d) == 2 or d >= pool_base - 4):
            return None
    for d in fp_disps:
        if d >= 0x110 and not (run.get(d) == 4 and d not in strs) and d < pool_base - 4:
            return None
    for d in fp64_disps:
        if run.get(d) != 8 and d < pool_base - 4:
            return None
    for d in movsi_disps | prompt_disps:
        if d in strs or d == pool_base - 4:
            continue
        off = P + 4 + d - pool_base
        if d < pool_base - 4 or off + 2 > len(exe):
            return None
        if not struct.unpack_from("<H", exe, off)[0] & 0x8000:
            return None
    com_slots = sorted(d for d in run if d < com[2] + com[0] + com[1])
    return {
        "ds": ds,
        "delta": 0,
        "var_base": ord_[2],
        "scalar_base": 0x110,
        "scalars": run,
        "strs": strs,
        "long_slots": long_slots,
        "pool_base": pool_base,
        "arrs": [],
        "rt_blocks": [],
        "n_static": 0,
        "common_slots": com_slots,
    }


def _line_table(
    exe: bytes, start: int, addrs: list[Any], epi_addr: int, extra_offs=frozenset()
):
    """Locate the error-trap line table: one (u16 code-offset, u16 line-number)
    entry per STATEMENT -- same-line statements repeat the line (t1_errml) --
    offsets non-decreasing and matching statement starts, closed by an entry
    at the epilogue offset repeating the last line (t1_onerr/t1_errf). A
    codeless statement (DATA with no READ/RESTORE anywhere to trigger its
    recovery, wild vhfprop.exe) still gets an entry, borrowing the offset of
    whatever real code follows it -- so two or more entries may share the
    SAME offset (probes q_lt1/q_lt3: a lone DATA line's entry precedes the
    next real statement's at that statement's own offset; two same-line DATA
    statements both precede it). Returns `(ent, orphans)` without the
    terminal entry, or `None` if absent: `ent` maps {code_offset: line} (last
    entry wins per offset, i.e. the REAL statement there, since a codeless
    statement's borrowed-offset entry always precedes it in table order);
    `orphans` is the list of (offset, line) entries superseded that way, in
    table order -- the codeless statements' own lines.
    `extra_offs` admits offsets besides statement starts: in a TRON region the
    table entries point PAST the 4-byte trace hook (t1_tronres)."""
    offs = {a - start for a in addrs if a is not None} | set(extra_offs)
    epi = epi_addr - start
    first = struct.pack("<H", 3)  # first statement is at start+3
    p = epi_addr
    while True:
        p = exe.find(first, p + 1)
        if p < 0 or p + 8 > len(exe):
            return None
        ent, orphans, q, prev_off, prev_line = {}, [], p, 0, 0
        while q + 4 <= len(exe):
            off, line = struct.unpack_from("<HH", exe, q)
            if off == epi:  # terminal entry: repeat last line
                if line == prev_line and ent:
                    return ent, orphans
                break
            if off not in offs or off < prev_off or line < prev_line:
                break
            if off in ent:
                orphans.append((off, ent[off]))
            ent[off] = line
            prev_off, prev_line = off, line
            q += 4


def _pool_has_word(exe: bytes, dsd: int, lay: dict[str, Any], value: int) -> bool:
    """True if `value` appears as an aligned word in the const-pool window. Integer
    literals are pooled even when they compile to immediates, but VARPTR's
    slot-offset immediate is NOT -- pool membership tells them apart
    when an immediate happens to equal a live scalar slot displacement."""
    lo = dsd + lay["pool_base"]
    for q in range(lo, len(exe) - 1, 2):
        if struct.unpack_from("<H", exe, q)[0] == value:
            return True
    return False


def _fill_lines(fixed: dict[int, int], n: int) -> list[int | None]:
    """Complete a sparse {stmt index: line} map (TRON trace hooks store REAL,
    byte-significant line numbers) to a full strictly-increasing list of n lines.
    Free runs get canonical 10-spacing when the enclosing gap allows, else an even
    subdivision of the gap."""
    lines: list[int | None] = [fixed.get(i) for i in range(n)]
    prev, j = 0, 0
    while j < n:
        vj = lines[j]
        if vj is not None:
            # Equal consecutive FIXED lines are `:`-grouped statements on one
            # source line (t1_tronml) -- emit0 re-groups them; synthesized runs
            # still need strict room.
            if vj < prev or (vj == prev and j > 0 and lines[j - 1] is None):
                raise ValueError("trace-hook line numbers not increasing")
            prev = vj
            j += 1
            continue
        k = j
        while k < n and lines[k] is None:
            k += 1
        if k == n:
            step = 10
        else:
            vk = lines[k]
            assert vk is not None  # loop above stops at the first non-None entry
            step = min(10, (vk - prev) // (k - j + 1))
        if step < 1:
            raise ValueError(
                f"no room for {k - j} synthesized line numbers "
                f"between {prev} and {lines[k]}"
            )
        for t in range(j, k):
            prev += step
            lines[t] = prev
        j = k
    return lines
