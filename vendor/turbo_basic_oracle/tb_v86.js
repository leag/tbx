#!/usr/bin/env node
// Headless TurboBasic 1.1 harness via v86. Boots FreeDOS, launches TB, loads
// SOLVER.BAS, then Run (compile-to-memory) or --compile-exe (compile-to-EXE on disk).
// Usage: node tb_v86.js <file.bas> [--run-ms N] [--rows a-b] [--compile-exe]
//                       [--floppy tb10_floppy.img]   (default tb_floppy.img = TB 1.1)
const path = require("path");
const lib = require("./tb_v86_lib.js");

const HERE = __dirname;
const args = process.argv.slice(2);
const basArg = args.find(a => !a.startsWith("--"));
const opt = (name, def) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : def; };
const RUN_MS = parseInt(opt("--run-ms", "9000"), 10);
const ROWS = opt("--rows", "0-24");
const COMPILE_EXE = args.includes("--compile-exe");
if (!basArg) { console.error("usage: node tb_v86.js <file.bas> [--run-ms N] [--rows a-b] [--compile-exe]"); process.exit(2); }

const workImg = lib.buildWorkImg(basArg, HERE, opt("--floppy", undefined));
console.error(`[harness] work.img built with SOLVER.BAS`);

const emulator = lib.bootEmulator({ here: HERE, workImg });
const { scr } = lib.attachScreen(emulator);
const { altKey, tapKey, typeSlow, waitFor, held, heldExt } = lib.makeDriver(emulator);
const sleep = lib.sleep, ENTER = lib.ENTER;
const fs = require("fs");

(async () => {
  await sleep(5000);
  await typeSlow("b:"); await tapKey(ENTER, 800);
  await typeSlow("tb.exe solver.bas"); await tapKey(ENTER, 0);
  await waitFor(scr, "Turbo Basic", 15000);
  // Wait for the file to finish loading into the editor (large files take a while to
  // tokenize; sending menu keys while TB is busy drops them).
  const loaded = await waitFor(scr, "SOLVER.BAS", 20000); await sleep(4000);
  console.error("[harness] auto-loaded:", loaded);
  if (!loaded) { await altKey(0x21); await tapKey(0x26, 700); await typeSlow("SOLVER.BAS"); await tapKey(ENTER, 2500); }

  if (COMPILE_EXE) {
    // Set Options -> Compile to -> EXE file. In-menu keys must be held to register;
    // the hold auto-repeats once, so 2 Downs wrap Memory->Chain file->EXE file.
    for (let attempt = 1; attempt <= 4 && !scr().includes("Compile to"); attempt++) {
      await altKey(0x18);              // Alt-O (Options); "Compile to" is the first item
      if (!scr().includes("Compile to")) { await held(0x01, 400); await sleep(800); }  // retry
    }
    await held(ENTER, 600);            // open the Compile-to popup (Memory/EXE file/Chain file)
    await heldExt(0x50, 500);          // Down
    await heldExt(0x50, 500);          // Down (wraps to EXE file)
    await held(ENTER, 700);            // select
    const compileTo = (scr().split("\n")[3] || "").trim();
    if (!compileTo.includes("EXE file")) {
      console.error("[harness] FAILED to set Compile to EXE file; row3:", compileTo);
      process.exit(1);
    }
    console.error("[harness] Compile to: EXE file");
    await held(0x01, 500);             // Esc to close the Options menu
    await altKey(0x2E);                 // Alt-C = Compile (writes SOLVER.EXE to B:)
    await waitFor(scr, "Compiling", 4000);
    await sleep(RUN_MS);               // let the compile + EXE write finish
    // Pull the guest floppy back (writes live in v86 RAM) and extract the EXE.
    const outImg = path.join(HERE, "work_out.img");
    const out = path.join(HERE, "SOLVER_v86.EXE");
    let ok = false;
    try {
      await lib.saveFdb(emulator, outImg);
      lib.extractExe(outImg, "SOLVER.EXE", out);
      ok = fs.existsSync(out) && fs.statSync(out).size > 0;
      console.error("[harness] extracted", out, ok ? `(${fs.statSync(out).size} B)` : "(empty/failed)");
    } catch (e) { console.error("[harness] EXE extract failed:", e.message); }
    console.log("=== COMPILE-EXE screen ==="); console.log(scr());
    process.exit(ok ? 0 : 1);
  }

  await altKey(0x13); await tapKey(0x13, 1000);   // Alt-R, R (Run = compile-to-memory)
  await sleep(RUN_MS);
  const [a, b] = ROWS.split("-").map(Number);
  console.log("=== SCREEN (rows " + ROWS + ") ===");
  console.log(scr().split("\n").slice(a, b + 1).join("\n"));
  process.exit(0);
})().catch(e => { console.error(e); process.exit(1); });
