#!/usr/bin/env node
// Fast TurboBasic compile harness: restores a pre-primed v86 snapshot (TB
// IDE running, "Compile to: EXE file" and the given IDE Options toggles
// already set) instead of rebooting FreeDOS + launching TB + navigating the
// Options menu on every compile. tb_v86.js remains the byte-exact reference
// path; this is a speed optimization on top of the same real IDE-driven
// flow, not a different compile mechanism -- correctness must be verified
// against tb_v86.js's output before this is trusted for anything but speed.
//
// Usage:
//   node tb_v86_fast.js --prime --floppy tb10_floppy.img --toggles KB
//                        --snapshot-dir DIR [--workspace WS]
//     Boots once, sets "Compile to: EXE file" and the given toggles, saves
//     a v86 state snapshot to DIR/<floppy>__<toggles>.state for reuse.
//
//   node tb_v86_fast.js <file.bas> --floppy tb10_floppy.img --toggles KB
//                        --snapshot-dir DIR --compile-exe --workspace WS
//     Restores the matching snapshot, hot-swaps a fresh B: floppy holding
//     <file.bas> as SOLVER.BAS via v86's set_fdb, loads it through TB's
//     File -> Load, compiles, and extracts SOLVER.EXE -- same on-disk
//     contract as tb_v86.js --compile-exe. Exits 3 (not a silent fallback)
//     if no matching snapshot exists; run --prime first for that
//     (floppy, toggles) pair.
const fs = require("fs");
const path = require("path");
const lib = require("./tb_v86_lib.js");

const HERE = __dirname;
const args = process.argv.slice(2);
const basArg = args.find(a => !a.startsWith("--"));
const opt = (name, def) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : def; };
const PRIME = args.includes("--prime");
const RUN_MS = parseInt(opt("--run-ms", "9000"), 10);
const TOGGLES = opt("--toggles", "");
const FLOPPY = opt("--floppy", "tb_floppy.img");
const SNAPSHOT_DIR = path.resolve(opt("--snapshot-dir", path.join(HERE, "snapshots")));
const WORKSPACE = path.resolve(opt("--workspace", HERE));
const sleep = lib.sleep, ENTER = lib.ENTER;

function snapshotPath() {
  return path.join(SNAPSHOT_DIR, `${FLOPPY}__${TOGGLES || "none"}.state`);
}

// Node Buffers may be views into a larger, pooled ArrayBuffer; slice to the
// buffer's own byte range before handing it to v86 (which expects the whole
// ArrayBuffer to BE the image).
function toArrayBuffer(buf) {
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
}

async function setCompileToExe(driver, scr) {
  const { altKey, held, tapKeyExt } = driver;
  for (let attempt = 1; attempt <= 4 && !(scr().includes("Compile to") || scr().includes("Compilation")); attempt++) {
    await altKey(0x18); // Alt-O (Options); "Compile to" is the first item
    if (!(scr().includes("Compile to") || scr().includes("Compilation"))) { await held(0x01, 400); await sleep(800); }
  }
  await held(ENTER, 600);   // open the Compile-to popup (Memory/EXE file/Chain file)
  await tapKeyExt(0x50, 500); // Down to EXE file
  await held(ENTER, 700);   // select
  await sleep(500);
  const compileTo = scr();
  if (!compileTo.includes("EXE file") && !compileTo.includes("EXE")) {
    console.error("[prime] FAILED to set Compile to EXE file; screen:\n" + compileTo);
    process.exit(1);
  }
  await held(0x01, 500); // Esc closes the Options menu
}

async function prime() {
  fs.mkdirSync(SNAPSHOT_DIR, { recursive: true });
  fs.mkdirSync(WORKSPACE, { recursive: true });
  // A minimal placeholder .bas exercises the same command-line auto-load
  // path every real compile goes through, so the primed state's editor/file
  // bookkeeping matches what a real compile expects to restore into.
  const placeholder = path.join(WORKSPACE, ".prime-placeholder.bas");
  fs.writeFileSync(placeholder, "10 END\r\n", "latin1");
  const workImg = lib.buildWorkImg(placeholder, HERE, FLOPPY, WORKSPACE);

  const emulator = lib.bootEmulator({ here: HERE, workImg });
  const { scr } = lib.attachScreen(emulator);
  const driver = lib.makeDriver(emulator);
  const { altKey, tapKey, typeSlow, waitFor } = driver;

  const booted = await waitFor(scr, ":\\>", 12000);
  if (!booted) throw new Error("FreeDOS prompt did not appear");
  await typeSlow("b:"); await tapKey(ENTER, 800);
  // buildWorkImg always stages the source as SOLVER.BAS on the image
  // regardless of the host filename; match that here.
  await typeSlow("tb.exe solver.bas"); await tapKey(ENTER, 0);
  await waitFor(scr, "Turbo Basic", 15000);
  const loaded = await waitFor(scr, "SOLVER.BAS", 20000);
  if (loaded) await lib.waitForStableScreen(scr, 700, 20000);
  if (!loaded) throw new Error("placeholder did not auto-load during prime");

  if (TOGGLES) {
    await lib.setOptionsToggles(driver, scr, TOGGLES);
    console.error("[prime] toggles set:", TOGGLES);
  }

  await setCompileToExe(driver, scr);
  console.error("[prime] Compile to: EXE file set");

  const state = await emulator.save_state();
  fs.writeFileSync(snapshotPath(), Buffer.from(state));
  console.error(`[prime] saved snapshot: ${snapshotPath()} (${state.byteLength} bytes)`);
  process.exit(0);
}

async function fastCompile() {
  if (!basArg) {
    console.error("usage: node tb_v86_fast.js <file.bas> --floppy F --toggles T --snapshot-dir DIR --compile-exe --workspace WS");
    process.exit(2);
  }
  const snapPath = snapshotPath();
  if (!fs.existsSync(snapPath)) {
    console.error(`[fast] no snapshot at ${snapPath}; run --prime first for floppy=${FLOPPY} toggles=${TOGGLES || "(none)"}`);
    process.exit(3);
  }
  const workImg = lib.buildWorkImg(basArg, HERE, FLOPPY, WORKSPACE);

  const v86Module = require("v86");
  const V86 = v86Module.V86 || v86Module;
  const v86BuildDir = path.dirname(require.resolve("v86/build/v86.wasm"));
  const vendored = path.join(HERE, "vendor", "v86.wasm");
  const wasmPath = fs.existsSync(vendored) ? vendored : path.join(v86BuildDir, "v86.wasm");
  const stateBuf = fs.readFileSync(snapPath);
  const emulator = new V86({
    wasm_path: wasmPath,
    bios: { url: path.join(HERE, "bios/seabios.bin") },
    vga_bios: { url: path.join(HERE, "bios/vgabios.bin") },
    initial_state: { buffer: toArrayBuffer(stateBuf) },
    autostart: true,
    disable_keyboard: false,
  });
  const { scr } = lib.attachScreen(emulator);
  const driver = lib.makeDriver(emulator);
  const { altKey, held, waitFor } = driver;

  // Give the restored machine a moment to resume painting before probing it.
  await sleep(300);

  // Hot-swap B: with a fresh floppy holding the new SOLVER.BAS.
  await emulator.set_fdb({ buffer: toArrayBuffer(fs.readFileSync(workImg)) });
  await sleep(200);

  // File -> Load. A plain instantaneous down+up scancode pair (tapKey, as
  // tb_v86.js uses from a fresh boot) is unreliable immediately after
  // v86's restore_state -- verified empirically: identical keystrokes sent
  // via tapKey are silently dropped after a restore (even plain character
  // typing into the editor), while `held` (separate down and up calls with
  // a real gap between them) registers reliably. Use `held` throughout this
  // post-restore path instead of tapKey. The `after` delays here are kept
  // short since the waitFor() poll below is what actually gates on
  // readiness -- a long fixed sleep here would just be dead time.
  // buildWorkImg always stages the source as SOLVER.BAS, matching what the
  // primed snapshot already had loaded -- TB's Load dialog pre-fills that
  // exact name, so confirm it as-is instead of retyping (which corrupts
  // the field, since it isn't cleared/selected first).
  await altKey(0x21); await held(0x26, 200); // Alt-F, L
  await held(ENTER, 200);
  const loaded = await waitFor(scr, "SOLVER.BAS", 15000);
  if (loaded) await lib.waitForStableScreen(scr, 700, 20000);
  if (!loaded) {
    console.error("[fast] DEBUG screen at failure:\n" + scr());
    throw new Error("SOLVER.BAS did not load from the hot-swapped floppy");
  }
  console.error("[fast] loaded:", loaded);

  await altKey(0x2E); // Alt-C = Compile
  if (!await waitFor(scr, "Compiling", 4000)) throw new Error("Turbo Basic did not enter the compile screen");
  const outImg = path.join(WORKSPACE, "work_out.img");
  const out = path.join(WORKSPACE, "SOLVER_v86.EXE");
  const ok = await lib.waitForExe(emulator, outImg, "SOLVER.EXE", out, RUN_MS);
  console.error("[fast] extracted", out, ok ? `(${fs.statSync(out).size} B)` : "(empty/timeout)");
  process.exit(ok ? 0 : 1);
}

(async () => {
  if (PRIME) await prime();
  else await fastCompile();
})().catch(e => { console.error(e); process.exit(1); });
