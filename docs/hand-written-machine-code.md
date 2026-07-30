# Hand-written machine code

How `$INLINE` bodies reach a compiled EXE, why they are hard to tell from
compiler output, and the rule this decoder uses to tell them apart. Written
around the case that produced the rule: wild `zip.exe` and `ziptest.exe`.

## The construct

Turbo Basic lets a program embed raw machine code (handbook Appendix C):

    SUB SETRATE INLINE
      $INLINE &HB0,&H74,&HE6,&H43
    END SUB

The compiler copies the byte list verbatim — no prologue, no epilogue, no
argument handling — appends a single far `RET` (`CB`), and brackets the whole
thing with a skip-jump so ordinary control flow steps over the declaration.
These are the bytes the compiler did not choose, which is exactly what makes
them hard to recognise on the way back: every other recovery in the decoder
leans on the compiler having used a template.

`ir.Inline` holds the byte list and `emit0` prints it back as `$INLINE`, so a
recovered body round-trips byte-exactly. The difficulty is never the
representation; it is deciding that a blob *is* one.

## Why it is ambiguous

The skip-jump and the trailing `CB` are the obvious fingerprint, and they are
not enough. A `$INLINE` list may contain anything at all — including bytes that
look exactly like a compiled procedure:

    e9 11 00              jmp over the body
    55 8b ec              push bp; mov bp,sp     <- a proc prologue…
    b0 74 e6 43 …         …the payload…
    5d                    pop bp                 <- …and a proc epilogue
    cb                    retf  (appended by the compiler)

That is byte-for-byte the shape of a genuine framed procedure the scanner
merely failed to understand. The two cases demand opposite responses — reprint
the bytes as `$INLINE`, or fail loud so somebody decodes the construct — and
nothing about the *shape* separates them. Wild `CVT2TB.EXE` and `phone.exe`
both hold real framed helpers ending in a legitimate `5D CB`; TBWINDOW's
`Openbox` is a real `$INLINE` list whose last byte happens to be `5D`, leaning
on the appended `RET`.

`_try_inline_rescue` (`decode0/scan.py`) therefore runs only *after* the
ordinary scan has already given up, and declines the `5D` tail by default. Two
things can overturn that:

- **The chain.** An unambiguous inline body immediately before — one whose own
  tail is not `5D`, so it needed no adjudication — proves the declaration
  region is the user's, and the blobs its skip-jumps bracket are theirs too.
  TBWINDOW seeds this with `Getftblptr`, whose frame-table data ends `C4 CB`.
- **The content.** See below.

## The content rule

> A body holding an instruction the compiler cannot generate was written by
> hand and arrived through `$INLINE`, whatever its framing looks like.

This is decidable where shape is not, because the compiler's instruction
selection is a closed set we can probe. One sequence is recognised today
(`_has_port_immediate`):

    b0 xx    mov al,imm8
    e6 xx    out imm8,al

Turbo Basic has no statement that compiles to an immediate-port `OUT`. `INP`
and `OUT` route the port through `DX` and emit the register forms `EC`/`EE`
whatever their operands — including when both operands fit a byte, which is the
case that looks most like it should be special (`OUT 67, 116` emits the general
form at top level and inside a `SUB` alike: probes
`wild/probes/probe_out_const_toplevel.bas` and
`wild/probes/probe_out_const_in_sub.bas`).

Two properties keep the rule safe:

**It is one-way.** The check only ever rules a body *in*. A body it does not
recognise stays fail-loud, so an unexplained framed helper is still a gap
somebody has to decode rather than something silently reprinted as machine
code.

**It matches whole sequences, never a bare opcode.** These bodies are not
disassembled, so a single-byte test reads operand and ModRM bytes as opcodes.
The first attempt searched the `E4`–`E7` port-I/O opcode range and accepted
`89 E5` — the alternate encoding of `mov bp,sp`, sitting in the prologue of
precisely the framed procedures the guard exists to reject.

Adding another sequence means proving the same thing first: a probe showing the
compiler emitting something else for every source spelling that could
plausibly produce it.

## The case: `zip.exe` and `ziptest.exe`

Both programs fill 26 and 23 procedures respectively with the same twelve-byte
payload, differing only in one operand:

    55 8b ec        push bp; mov bp,sp
    b0 74  e6 43    mov al,74h ; out 43h,al
    b0 LL  e6 41    mov al,LL  ; out 41h,al
    b0 00  e6 41    mov al,00h ; out 41h,al
    5d              pop bp                      (+ cb, appended)

Port `43h` is the 8253/8254 command register and `41h` is **counter 1**'s data
port. Command byte `74h` decodes as counter 1 / write LSB then MSB / mode 2
(rate generator) / binary — identical in all 49 bodies, so only the divisor
varies.

Counter 1 is the **DRAM refresh** request generator, which drives DMA channel
0. It is not the speaker (counter 2, port `42h`, gated through `61h`) and not
the system tick (counter 0, port `40h`).

The divisors are 9, 12, 15, 18, then 30…240 by tens. **18 is the stock IBM
value** — a refresh burst roughly every 15 µs. Raising it means fewer bursts
per second, so the DMA controller steals fewer bus cycles and the machine runs
a few percent faster, at the risk of DRAM losing charge between refreshes.
`zip.exe` writes one stub per setting, `ZIPA.BIN` … `ZIPZ.BIN`, indexed by the
string `"ABCDEFGHIJKLMNOPQRSTUVWXYZ"`. It is a PC speed-up utility.

The split between the two programs falls out of that reading: `ziptest.exe`
carries only the 23 settings from stock upward, because its job is to find how
far a given machine's RAM tolerates the reduced refresh; `zip.exe` adds 9/12/15
*below* stock — more frequent refresh, slower but safer — for machines that
fail the test.

## What went wrong here, and how it was found

The scanner used to read `mov al,imm8; out imm8,al` as an op called `out_imm`,
described as a byte-constant `OUT` that the compiler had folded. No such fold
exists. The mapping had never been calibrated: `t1_out.bas` uses port 888
(>255) and `t1_out2.bas` a variable operand, so no fixture reached it, and its
test asserted the scanner's behaviour on hand-built bytes plus "wild zip.exe
decodes" — never that anything recompiled. A checker written alongside a
mapping shares its assumptions.

The cost was invisible to every structural check and obvious to the oracle.
Emitting `OUT p, v` recompiled into the general register form, so `zip.exe`
came back 592 bytes too long and `ziptest.exe` 224 — the two least-identical
comparable programs in the corpus, at 96.9% and 93.2%.

The technique that located it generalises, and is worth reaching for whenever a
program decodes cleanly but rebuilds wrong:

1. **Decode the program's own rebuild** and diff that decode against the
   original's. This reports what the compiler did with our source, rather than
   what we hoped it would do.
2. **Compare operation *kinds*, not operations.** Raw op streams are swamped by
   shifted displacements and renamed variables; a `Counter` over kind names
   collapses that noise. Here it printed the answer directly:

       out_imm   78 -> 0
       out        0 -> 78
       movdxbx    0 -> 78

3. **Probe the spelling** before believing any story about what the compiler
   does. Three probes settled it in minutes.

Recorded as `RO-OUT-IMM-FOLD` in `gap_reports/ruled-out-hypotheses.json`.
Fixture `t1_inlineport` is the shape in miniature; `t1_inline`, `t1_inlinebp`
and `t1_inlinedata` cover the unframed and data-tailed variants.
