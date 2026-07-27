# Rebuilding v86.wasm with the FBLD patch

The vendored `oracle/vendor/v86.wasm` is a locally-rebuilt v86 CPU blob that adds the
x87 **FBLD** instruction (`DF /4`, load packed BCD), which stock v86 leaves
unimplemented and which Turbo Basic's floating-point I/O requires. See
`oracle/V86_ROOTCAUSE.md` for the diagnosis.

`tb_v86_lib.js` `bootEmulator()` loads `oracle/vendor/v86.wasm` in preference to the
npm package's `node_modules/v86/build/v86.wasm`, so the patch survives `npm install`.
The unpatched `v86-debug.wasm` / `v86-fallback.wasm` are still used from node_modules
(only the release `v86.wasm` is patched).

## What the patch changes (`oracle/v86-fbld.patch`)

Base commit: **e37189a4ad6ce4138e7168508f07553d0d3b6b3f** (= npm `v86@0.5.359+ge37189a`,
matched so the rebuilt wasm's ABI lines up with the vendored `libv86.js`).

- `src/rust/cpu/fpu.rs` — add `fpu_fbld(addr)`: read the 80-bit packed BCD operand
  (9 bytes = 18 digits, low nibble first; byte 9 bit 7 = sign), build an `i64`, push
  `F80::of_i64(value)`. The inverse of the existing `fpu_fbstp`.
- `src/rust/cpu/instructions.rs` — `instr_DF_4_mem` now calls `fpu_fbld` (was `fpu_unimpl`).
- `src/rust/jit_instructions.rs` — `instr_DF_4_mem_jit` now resolves the operand and
  calls `fpu_fbld` with pagefault-exit handling (was `gen_trigger_ud`). This is the path
  that actually fired the fault: v86 runs guest code through the JIT by default.
- `Makefile` — added `--import-undefined --allow-undefined` to the wasm link args.
  Required because modern `rust-lld` (rustc 1.96) errors on the undefined host-import
  symbols (`mmap_read8`, `microtick`, …) that v86 expects to import from JS `env`.

## Reproduce

Prereqs (installed during this work; user-level, no sudo): `rustup` + `cargo` with the
`wasm32-unknown-unknown` target, `clang` (for `softfloat.o`/`zstddeclib.o`), `node`.
`wasm-opt` (binaryen) is NOT needed — the Makefile guards it behind `WASM_OPT=false`.

```bash
cd oracle
git clone https://github.com/copy/v86.git v86-src
cd v86-src
git fetch --unshallow 2>/dev/null || true
git checkout e37189a4ad6ce4138e7168508f07553d0d3b6b3f
git apply ../v86-fbld.patch
export PATH="$HOME/.cargo/bin:$PATH"
make build/v86.wasm          # builds release wasm; ignore the guarded "wasm-opt" error
cp build/v86.wasm ../vendor/v86.wasm
```

`oracle/v86-src/` is gitignored (large checkout); the tracked artifacts are
`oracle/vendor/v86.wasm` (the built blob) and `oracle/v86-fbld.patch` (the source diff).
