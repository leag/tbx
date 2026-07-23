# Turbo BASIC decoder statement support

Status: 2026-07-23

This is the statement-level support matrix for `tbx.decode0`. “Supported” means
that the decoder has a typed IR representation and an emitter form for the
statement. It does not mean that every possible compiler encoding or every
runtime edge case is accepted. Unsupported byte shapes remain fail-loud.

## Corpus comparison

The comparison below uses the checked-in fixtures in
`tests/fixtures/corpus/`: 291 `.BAS` source files and 774 `.EXE` files. The
source scan is lexical and is intended to answer “does the known source corpus
exercise this statement?”, not to count every occurrence. Some statements are
represented only by an executable fixture, or are hidden by compiler
preprocessing.

### Statements observed in the source corpus

| Area | Observed statements |
|---|---|
| Control flow | `END`, `GOTO`, `GOSUB`, `RETURN`, `IF ... THEN`, `FOR`, `NEXT`, `WHILE`, `WEND`, `DO`, `LOOP`, `RUN`, `SELECT CASE`, `END IF`, `END SELECT`, `EXIT SUB` |
| Data and declarations | `DIM`, `ERASE`, `OPTION BASE`, `DATA`, `DEF SEG`, `LOCAL`, `SHARED`, `COMMON` |
| Console/printer | `PRINT`, `PRINT USING`, `LPRINT`, `INPUT`, `LINE INPUT`, `TAB`, `SPC`, `WRITE`, `BEEP`, `CLS`, `LOCATE`, `COLOR`, `KEY` |
| Files and DOS | `OPEN`, `CLOSE`, `GET`, `PUT`, `KILL`, `BLOAD`, `INPUT #`, `LINE INPUT #`, `DATE$ =`, `TIME$ =` |
| Error and events | `ON ERROR`, `RESUME`, `ERROR`, `TRON`, `TROFF`, `ON PEN`, `ON KEY`, `ON PLAY`, `ON TIMER`, event `ON`/`OFF`/`STOP` controls |
| Graphics and hardware | `SCREEN`, `PSET`, `PRESET`, `LINE`, `CIRCLE`, `PAINT`, `DRAW`, `VIEW`, `WINDOW`, `PALETTE`, `PALETTE USING`, `POKE`, `OUT`, `WAIT`, `PLAY`, `RANDOMIZE` |
| Procedures | `SUB`, `END SUB`, `CALL`, `$INLINE` byte lists, `DEF FN`/multi-line function bodies |

### Supported but not present in the checked-in `.BAS` source scan

These are implemented in the decoder IR/emitter but do not have a matching
source witness in the 291-file source set, or the syntax is only present in a
form the simple scan does not distinguish:

`EXIT FOR`, `EXIT LOOP`, `EXIT DEF`, `PRINT #`, `WRITE #`, `RESET`, `FILES`,
`NAME`, `SEEK`, `FIELD`, `LSET`, `RSET`, `BSAVE`, `READ`, `RESTORE`, `CHAIN`,
`ON GOTO`, `ON GOSUB`, `ON COM`, `ON PEN`, `ON PLAY`, `ON TIMER`, `ON STRIG`,
`CALL INTERRUPT`, `CALL ABSOLUTE`, `REG`, `KEY LIST`, `MTIMER`, `CLEAR`,
`DELAY`, `SOUND`, `CHDIR`, `MKDIR`, `RMDIR`, `ENVIRON`, `SHELL`, `WIDTH`,
`KEY n, string$`, `GET$`, `PUT` graphics blits, `FIELD`, and `MID$(...) = ...`.

This is not a claim that Turbo BASIC rejects those forms. It means that the
known source subset does not provide a direct source-level witness for them.

## Complete decoder statement inventory

### Control flow and blocks

| IR node | Turbo BASIC form | Status |
|---|---|---|
| `Assign` | `variable = expression`, array and string assignment forms | Supported; corpus observed |
| `End` | `END` | Supported; corpus observed |
| `Goto` | `GOTO line` | Supported; corpus observed |
| `IfGoto` | `IF condition THEN line` | Supported; corpus observed |
| `IfInline` | `IF condition THEN statement[:statement...]` | Supported; corpus observed |
| `IfBlock` | `IF ... THEN` / `ELSEIF` / `ELSE` / `END IF` | Supported; corpus observed |
| `For` | `FOR v = init TO limit [STEP step]` | Supported; corpus observed, including variable-step SINGLE locals and mixed DEF FN frames whose limit/step are BP-relative while the loop variable is global |
| `NextStmt` | `NEXT [v]` | Supported; corpus observed |
| `Gosub` | `GOSUB line` | Supported; corpus observed |
| `Return` | `RETURN` | Supported; corpus observed |
| `While`, `Wend` | `WHILE condition` / `WEND` | Supported; corpus observed |
| `Do`, `Loop` | `DO [WHILE/UNTIL]` / `LOOP [WHILE/UNTIL]` | Supported; corpus observed |
| `ExitFor` | `EXIT FOR` | Supported; no source witness |
| `ExitLoop` | `EXIT LOOP` | Supported; no source witness |
| `ExitSub` | `EXIT SUB` | Supported; corpus observed |
| `ExitDef` | `EXIT DEF` | Supported; no source witness |
| `SelectCase` | `SELECT CASE ... END SELECT` | Supported; corpus observed |
| `Run` | `RUN [file$]` | Supported; corpus observed |

### Declarations, data, and procedures

| IR node | Turbo BASIC form | Status |
|---|---|---|
| `Dim` | `DIM name(bounds)[, ...]` | Supported; corpus observed |
| `Erase` | `ERASE name[, ...]` | Supported; corpus observed |
| `OptionBase` | `OPTION BASE 0|1` | Supported; corpus observed |
| `DefType` | `DEFINT`, `DEFSTR`, `DEFSNG`, `DEFDBL` | Recovered/rendered canonically; weak source provenance |
| `Data` | `DATA item[, ...]` | Supported; corpus observed |
| `Read` | `READ target[, ...]` | Supported; executable/source witness may be indirect |
| `Restore` | `RESTORE [line]` | Supported; executable/source witness may be indirect |
| `SubDef` | `SUB name[(params)] ... END SUB` | Supported, including witnessed rank-1 array parameters declared as `A(1)`; c0 is fail-loud for array parameters |
| `CallStmt` | `CALL name[(args)]` | Supported, including whole-array `A()` arguments (D4); c0 remains fail-loud for whole-array parameters |
| `DefFn` | `DEF FN... = expression` or block form | Supported; corpus observed in function fixtures |
| `FnResult` | assignment to a multi-line `DEF FN` result | Internal procedure-body node; emitted as source |
| `Inline` | `$INLINE byte, ...` inside a `SUB` | Supported; corpus observed |
| `Shared` | `SHARED ...` inside a procedure | Supported; corpus observed |
| `Local` | `LOCAL ...` inside a `SUB` or block `DEF FN` | Supported for INTEGER, SINGLE, scalar STRING reads/writes, large BP+disp16 frames, and witnessed local dynamic arrays including STRING arrays in mixed DEF FN frames; c0 remains fail-loud |
| `Common` | `COMMON ...` | Supported; corpus observed |

### Console, printer, and formatting

| IR node | Turbo BASIC form | Status |
|---|---|---|
| `Print` | `PRINT [#n,] ...` | Supported; corpus observed |
| `PrintUsing` | `PRINT [#n,] USING format; ...` | Supported; corpus observed |
| `Lprint` | `LPRINT ...` | Supported, including comma-zone separators (C2) |
| `Write` | `WRITE [#n,] ...` | Supported; corpus observed in executable fixtures |
| `Input` | console `INPUT ...` | Supported; corpus observed |
| `LineInput` | `LINE INPUT ...` | Supported; corpus observed |
| `InputFile` | `INPUT #n, ...` | Supported; corpus observed |
| `Tab`/`Spc` print items | `TAB(n)` / `SPC(n)` | Supported; corpus observed |
| `Beep` | `BEEP` | Supported; corpus observed |
| `Cls` | `CLS` | Supported; corpus observed |
| `Locate` | `LOCATE ...` | Supported; corpus observed |
| `Color` | `COLOR ...` | Supported; corpus observed |
| `Width` | `WIDTH cols` / `WIDTH device$, cols` / `WIDTH #filenum, cols` | Supported; both extended forms oracle-verified, file form also wild-observed |
| `Key` | `KEY ON|OFF` | Supported; corpus observed |
| `KeyDef` | `KEY n, string$` | Supported; corpus observed in key fixtures |
| `KeyList` | `KEY LIST` | Supported; no direct source witness |

### Files and DOS services

| IR node | Turbo BASIC form | Status |
|---|---|---|
| `Open` | `OPEN ...` | Supported; corpus observed |
| `Close` | `CLOSE [#n]` | Supported; corpus observed |
| `Reset` | `RESET` | Supported; no source witness |
| `Files` | `FILES [spec$]` | Supported; no source witness |
| `Name` | `NAME old$ AS new$` | Supported; no source witness |
| `Kill` | `KILL file$` | Supported; corpus observed |
| `Get` | `GET #n, record` | Supported; corpus observed |
| `GetString` | `GET$ #n, count, string$` | Supported; no source witness |
| `Put` | `PUT #n, record` | Supported; corpus observed |
| `Seek` | `SEEK #n, position` | Supported; no source witness |
| `Ioctl` | `IOCTL #n, string$` | Supported; oracle-verified, no wild witness |
| `Call("IOCTL$", (n,))` | `IOCTL$(n)` | Supported; oracle-verified, no wild witness |
| `PutString` | `PUT$ #n, string$` | Supported; corpus observed (wild nvginst/pwinst/secure) |
| `Field` | `FIELD #n, width AS string$` | Supported; no source witness |
| `Lset` / `Rset` | `LSET` / `RSET` | Supported; no source witness |
| `MidAssign` | `MID$(target$, start[, length]) = source$` | Supported; no source witness |
| `Bload` / `Bsave` | `BLOAD` / `BSAVE` | Supported; `BLOAD` observed |
| `Chdir` / `Mkdir` / `Rmdir` | DOS directory statements | Supported; no source witness |
| `Environ` | `ENVIRON string$` | Supported; no source witness |
| `Shell` | `SHELL string$` | Supported; no source witness |
| `Chain` | `CHAIN file$` | Supported; no source witness |

### Errors, events, and machine services

| IR node | Turbo BASIC form | Status |
|---|---|---|
| `OnGoto` / `OnGosub` | `ON n GOTO/GOSUB ...` | Supported; no source witness |
| `OnError` | `ON ERROR GOTO ...` | Supported; corpus observed |
| `Resume` | `RESUME [NEXT|line]` | Supported; corpus observed |
| `ErrorStmt` | `ERROR n` | Supported; corpus observed |
| `OnTrap` | `ON COM/KEY/PEN/PLAY/TIMER ... GOSUB` | Supported; corpus observed |
| `TrapCtl` | event `ON`, `OFF`, or `STOP` | Supported; corpus observed |
| `Tron` / `Troff` | `TRON` / `TROFF` | Supported; corpus observed |
| `RegSet` | `REG n, value` | Supported; no direct source witness |
| `CallInterrupt` | `CALL INTERRUPT n` | Supported; no direct source witness |
| `CallAbsolute` | `CALL ABSOLUTE address` | Supported; corpus observed in call fixtures |
| `DateTimeSet` | `DATE$ = ...` / `TIME$ = ...` | Supported; corpus observed |
| `DefSeg` | `DEF SEG [= segment]` | Supported; corpus observed |
| `Swap` | `SWAP a, b` | Supported; corpus observed |

### Graphics, sound, and ports

| IR node | Turbo BASIC form | Status |
|---|---|---|
| `Screen` | `SCREEN mode[, ...]` | Supported; corpus observed, including omitted mode/page arguments (`SCREEN ,,0,0`) |
| `Pset` | `PSET` / `PRESET` | Supported; corpus observed |
| `LineStmt` | `LINE ...` | Supported; corpus observed |
| `Circle` | `CIRCLE ...` | Supported; corpus observed |
| `Paint` | `PAINT ...` | Supported; corpus observed |
| `Draw` | `DRAW command$` | Supported; corpus observed |
| `GetGfx` / `PutGfx` | graphics `GET` / `PUT` blits | Supported; corpus observed in graphics fixtures |
| `Palette` | `PALETTE ...` | Supported; corpus observed |
| `PaletteUsing` | `PALETTE USING array%(index)` | Supported for witnessed rank-1 INTEGER arrays; static and dynamic constant/variable-index probes |
| `View` | `VIEW [SCREEN] ...` | Supported; corpus observed |
| `Window` | `WINDOW [SCREEN] ...` | Supported; corpus observed |
| `Play` | `PLAY music$` | Supported; corpus observed |
| `Mtimer` | `MTIMER` | Supported; no direct source witness |
| `Sound` | `SOUND frequency, duration` | Supported; executable/source witness is sparse |
| `Delay` | `DELAY seconds` | Supported; no direct source witness |
| `Out` | `OUT port, value` | Supported, including byte-constant `B0 vv E6 pp` optimization |
| `Wait` | `WAIT port, mask[, xor]` | Supported; corpus observed |
| `Poke` | `POKE address, value` | Supported; corpus observed |
| `Clear` | `CLEAR` | Supported; no direct source witness |
| `Randomize` | `RANDOMIZE [seed]` | Supported; corpus observed |

## Metastatements and preprocessing

These are not ordinary executable statements, but the decoder has explicit
handling for the ones whose effects survive compilation:

| Source construct | Decoder treatment |
|---|---|
| `$STACK n` | Recovered from the runtime allocation table and emitted as metadata. |
| `$SOUND n` | Recovered from the runtime allocation table and emitted as metadata. |
| `$EVENT ON/OFF` | Recovered from the compiler’s statement poll hooks and emitted as metadata. |
| `$INLINE byte, ...` | Recovered as an `Inline` body payload. |
| `$INLINE "file"` | The oracle stages the external file; the compiled bytes are recovered as inline payload. |
| `$INCLUDE "file"` | Oracle-only compile-time preprocessing. Included statements are flattened into the executable; the decoder cannot recover the include boundary or filename. |
| `$SEGMENT` | Compile-time control-flow/layout directive. The oracle accepts it, and the scanner recognizes the resulting far-transfer family, but full multi-segment target mapping and source-boundary recovery are not yet supported. It is not present in the checked-in corpus source scan. |

## Important interpretation limits

1. An observed source statement can still have unsupported encodings. The
   corpus comparison is evidence of exercised shapes, not a promise for all
   operand combinations.
2. A statement may be codeless (`DATA`, static `DIM`, declarations) and be
   recovered from the error-trap line table or allocation metadata rather than
   from an opcode.
3. `$INCLUDE` leaves no executable marker. A decompile of a compiled program
   can reproduce the flattened statements, but cannot reconstruct which lines
   came from which included file without an external source manifest.
4. `BodyLine`, `OpaqueHelper`, `CaseArm`, and `DataItem` are recovery/emission
   support nodes, not user-facing Turbo BASIC statements.
