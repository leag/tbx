#!/usr/bin/env node
// Headless run of a TB-compiled DOS EXE in v86: boot FreeDOS, run the EXE on B:, then
// drive its interactive INPUT prompts entirely via the emulated keyboard (v86 reaches the
// BIOS buffer -- unlike an SDL-dummy display), reading the mirrored text screen to know when
// each prompt appears. The byte-exact FRAME1 asks for two filenames:
//   1. "...ARCHIVO DE DATOS"  -> the input .DAT
//   2. "...ARCHIVO DE SALIDA" -> the output report file (appears after the solve)
// We answer both, let it write + CLOSE the report, then pull that file back off the floppy.
// Usage:
//   node tb_v86_runexe.js <exe-on-host> <dat-on-host> [--run-ms N] [--out RESULT.OUT] [--out-ms N]
const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");
const lib = require("./tb_v86_lib.js");

const HERE = __dirname;
const args = process.argv.slice(2);
const pos = args.filter(a => !a.startsWith("--"));
const opt = (n, d) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : d; };
const EXE = pos[0], DAT = pos[1];
const RUN_MS = parseInt(opt("--run-ms", "40000"), 10);   // budget to reach the SALIDA prompt
const OUT_MS = parseInt(opt("--out-ms", "12000"), 10);   // wait after answering it (write+CLOSE)
const OUTNAME = opt("--out", "RESULT.OUT");
if (!EXE || !DAT) { console.error("usage: node tb_v86_runexe.js <exe> <dat> [--run-ms N] [--out NAME] [--out-ms N]"); process.exit(2); }

// Period-free 8.3 guest filenames. keyboard_send_text (simulate_char) drops '.', so we
// never type one: the .DAT is staged as DATA and we answer the output prompt with RESULT.
const GUEST_DAT = "DATA";
const GUEST_OUT = "RESULT";

// Build a run floppy: tb_floppy.img + SOLVER.EXE + the .DAT (staged under GUEST_DAT).
const runImg = path.join(HERE, "run.img");
fs.copyFileSync(path.join(HERE, "tb_floppy.img"), runImg);
execFileSync("mcopy", ["-o", "-i", runImg, EXE, "::SOLVER.EXE"]);
execFileSync("mcopy", ["-o", "-i", runImg, DAT, "::" + GUEST_DAT]);

const emulator = lib.bootEmulator({ here: HERE, workImg: runImg });
const { scr } = lib.attachScreen(emulator);
const { typeSlow, tapKey, waitFor, held } = lib.makeDriver(emulator);
const sleep = lib.sleep, ENTER = lib.ENTER;

// Answer one TB INPUT prompt: type the (period-free) text via keyboard_send_text -- the
// simulate_char path TB's input poll actually sees -- then submit with a HELD Enter. A
// zero-gap Enter tap is too fast for TB's INPUT (same reason its menus need held keys).
const answer = async (text) => { await typeSlow(text); await sleep(600); await held(ENTER, 600); };

(async () => {
  await sleep(5000);
  await typeSlow("b:"); await tapKey(ENTER, 800);
  await typeSlow("solver.exe"); await tapKey(ENTER, 0);

  // Prompt 1 -- input data file ("...ARCHIVO DE DATOS").
  if (await waitFor(scr, "DATOS", 8000)) {
    await sleep(500);
    console.error("[runexe] data file:", GUEST_DAT);
    await answer(GUEST_DAT);
  } else {
    console.error("[runexe] no data-file prompt (hardcoded?); continuing");
  }

  // Prompt 2 -- output report file ("...ARCHIVO DE SALIDA"). Printed only after the solve,
  // so allow the full RUN_MS compute window. Answer with GUEST_OUT so the report lands in a
  // file we can pull back; then give it OUT_MS to finish writing and CLOSE #1.
  if (await waitFor(scr, "SALIDA", RUN_MS)) {
    await sleep(500);
    console.error("[runexe] output file:", GUEST_OUT);
    await answer(GUEST_OUT);
    await sleep(OUT_MS);
  } else {
    console.error("[runexe] no output-file prompt within run-ms; assuming hardcoded output");
    await sleep(OUT_MS);
  }
  // Pull the floppy back and extract the guest report (GUEST_OUT) to the host as RUN_<OUT>.
  const outImg = path.join(HERE, "run_out.img");
  await lib.saveFdb(emulator, outImg);
  const out = path.join(HERE, "RUN_" + OUTNAME);
  let ok = false;
  try { lib.extractExe(outImg, GUEST_OUT, out); ok = fs.existsSync(out); }
  catch (e) { console.error("[runexe] could not extract", GUEST_OUT, ":", e.message); }
  console.error("[runexe]", ok ? `extracted ${out} (${fs.statSync(out).size} B)` : "no output file");
  console.log("=== final screen ==="); console.log(scr());
  process.exit(ok ? 0 : 1);
})().catch(e => { console.error(e); process.exit(1); });
