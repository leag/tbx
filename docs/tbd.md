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
tbd PROGRAM.EXE --facts         # expose facts, provenance, and fact-pass reports
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
for fact in program.facts:
    print(fact.kind, fact.subject, fact.value, fact.evidence)
for statement in program.statements:
    print(statement.index, statement.kind, statement.operands)
for statement in program.canonical_statements:
    print(statement.kind, statement.operands)
```

## Analysis model

The pipeline is deliberately small:

1. Read the MZ bounds, entry point, and Turbo Basic prologue signature.
2. Discover instructions recursively and record basic blocks and cross-references.
3. Record signature matches for Turbo Basic dispatches and runtime calls.
4. Repeatedly add immutable register, FP-stack, layout, source-statement, and
   control-flow facts until a complete round adds nothing.
5. Materialize semantic operations from stable facts and group every uncovered
   discovered instruction into a lossless `unknown.region` node.
6. Reconstruct a source-shaped statement sequence from the stable operation
   stream, resolving branch addresses to statement indexes when possible.

`Program.instructions` retains the low-level evidence. `Program.operations`
is the compact fact-owned IR and is what the CLI emits by default. It combines
recognized semantic operations with high-level signatures and uncovered byte
regions, so unsupported input remains visible. `Program.fact_passes` records
every fact pass, round, addition count, and resulting fact count, making it
clear whether another round helped.

`Program.statements` is a fact-owned, address-bearing source view.
`Program.canonical_statements` applies stable procedure, function, parameter,
and variable names plus comparison-only expression normalization. Both remain
intentionally incomplete: unsupported shapes stay in the operation evidence
instead of becoming guessed source.

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
