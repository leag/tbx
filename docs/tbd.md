# `tbd`: compact iterative decoding

`tbd` is a standalone, forgiving companion to `tbx`. It borrows two ideas
from IDA without trying to reproduce IDA itself:

- recursive traversal follows branches and calls from known entry points, so
  unreachable data is not decoded merely because it follows code;
- FLIRT-style signatures recognize stable compiler/runtime byte patterns and
  give later passes stronger facts. The implementation uses ordinary Python
  predicate functions rather than a signature-file format.

See the [official FLIRT overview](https://docs.hex-rays.com/user-guide/signatures/flirt)
for the original library-recognition concept.

## Use

```sh
tbd PROGRAM.EXE                 # compact lifted IR as JSON
tbd PROGRAM.EXE --text          # compact lifted IR as text
tbd PROGRAM.EXE --instructions  # also expose discovered instructions
tbd PROGRAM.EXE --rounds 12     # change the fixed-point limit
python -m tbd PROGRAM.EXE
```

Python callers use one function:

```python
from tbd import decode

program = decode(open("PROGRAM.EXE", "rb").read())
for block in program.blocks:
    print(block.start, block.successors)
for operation in program.operations:
    print(operation.offset, operation.kind, operation.operands)
for statement in program.statements:
    print(statement.index, statement.kind, statement.operands)
```

## Analysis model

The pipeline is deliberately small:

1. Read the MZ bounds, entry point, and Turbo Basic prologue signature.
2. Discover instructions recursively and record basic blocks and cross-references.
3. Record signature matches for Turbo Basic dispatches and runtime calls.
4. Repeatedly propagate register and FP-stack values, solve anchored constant-
   pool candidates, name DGROUP slots, lift assignments and PRINT chains,
   recover call arguments and conditions, and normalize control flow until a
   complete round makes no changes.
5. Group everything not yet lifted into `unknown.region` nodes.
6. Reconstruct a source-shaped statement sequence from the stable operation
   stream, resolving branch addresses to statement indexes when possible.

`Program.instructions` retains the low-level evidence. `Program.operations`
is the compact IR and is what the CLI emits by default. `Program.passes`
records every pass, round, change count, and resulting node count, making it
clear whether another round helped.

`Program.statements` is a second, source-shaped view. It currently recovers
simple assignments, PRINT statements, IF/GOTO pairs, DELAY, END, and generic
runtime statements. This view is intentionally lossy and incomplete: a value
stays a memory or string-pool address until a pass has enough evidence to name
or decode it. The operation stream remains available to explain every lifted
statement.

The pool lift is generic across the simple Turbo Basic scalar layout, rather
than across arbitrary executable formats. It derives candidates from evidenced
assignment targets and memory references, then requires the compiler's pool
marker and EOF anchor before decoding integer, single-precision, or string
literals. Mixed-width scalar bands, arrays, overlays, or an ambiguous layout
remain unresolved for later passes.

Unknown bytes never stop discovery. Conflicting code targets, scan limits,
and opaque bytes become diagnostics. More signatures and rewrite functions
can progressively decode an unknown region in later versions without changing
the traversal engine.

`tbd` imports no `tbx` decoder or emitter modules and makes no byte-exactness
promise. Use `tbx` and the oracle when correctness means a byte-identical
recompile.

New analysis work follows the normative [fact-engine design](tbd-design.md).
