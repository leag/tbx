#!/usr/bin/env node
// Generic headless run of a DOS EXE in v86 with screen + file capture.
// Unlike tb_v86_runexe.js (which drives FRAME1's two specific prompts), this
// harness runs ANY small EXE: boot FreeDOS, CLS, launch the program on B:,
// optionally answer its prompts from a key script, wait for the DOS prompt to
// come back, then emit the program's screen output between markers and pull
// every file the program created off the floppy. Built for the tbx corpus
// fixtures (decompiler regression EXEs), whose output fits one screen.
//
// Usage:
//   node tb_v86_capture.js PROG.EXE [--keys JSON] [--boot-ms N] [--run-ms N]
//                          [--outdir DIR]
//   --keys:  JSON array of steps: {"wait":"substr","count":n,"send":"text",
//            "delay":ms}. Each step waits until `wait` appears on the screen
//            at least `count` times (default 1; lets a second INPUT's "?" be
//            told from the first), then types `send` as held scancodes (a
//            trailing "\r" becomes a held Enter) -- TB programs poll the
//            keyboard like the IDE and miss instantaneous keys. {"sleep":ms}
//            pauses unconditionally.
//   --outdir: where extracted new files go (default: cwd).
//
// Output contract (stdout): lines `=== screen ===` ... `=== end ===` with the
// program's screen text (command echo and returning DOS prompt stripped),
// then one `file: NAME SIZE` line per extracted file. Exit 0 when the program
// ran to the DOS prompt within budget, 3 on timeout (screen still printed).
const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");
const lib = require("./tb_v86_lib.js");

const HERE = __dirname;
const args = process.argv.slice(2);
const pos = args.filter(a => !a.startsWith("--") && args[args.indexOf(a) - 1] !== "--keys"
  && !["--boot-ms", "--run-ms", "--outdir", "--keys"].includes(args[args.indexOf(a) - 1]));
const opt = (n, d) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : d; };
const EXE = pos[0];
const BOOT_MS = parseInt(opt("--boot-ms", "6000"), 10);
const RUN_MS = parseInt(opt("--run-ms", "20000"), 10);
const OUTDIR = opt("--outdir", process.cwd());
const KEYS = JSON.parse(opt("--keys", "[]"));
if (!EXE) { console.error("usage: node tb_v86_capture.js PROG.EXE [--keys JSON] [--boot-ms N] [--run-ms N] [--outdir DIR]"); process.exit(2); }

// 8.3 guest name from the host basename (period-free stem, "PROG.EXE" style).
const stem = path.basename(EXE).replace(/\.exe$/i, "").replace(/[^A-Za-z0-9_]/g, "").slice(0, 8).toUpperCase() || "PROG";
const GUEST_EXE = stem + ".EXE";

// Run floppy: bare tb_floppy.img + the EXE. work_cap*.img match the
// gitignored work*.img pattern.
const runImg = path.join(HERE, "work_cap.img");
fs.copyFileSync(path.join(HERE, "tb_floppy.img"), runImg);
execFileSync("mcopy", ["-o", "-i", runImg, EXE, "::" + GUEST_EXE]);
const baseline = new Set(
  execFileSync("mdir", ["-i", runImg, "-b"]).toString().split("\n")
    .map(l => l.trim().replace(/^::\/?/, "")).filter(Boolean));

const emulator = lib.bootEmulator({ here: HERE, workImg: runImg });
const { scr } = lib.attachScreen(emulator);
const { tapKey, typeSlow, waitFor, held } = lib.makeDriver(emulator);
const sleep = lib.sleep, ENTER = lib.ENTER;

// TB-compiled programs read the keyboard like the TB IDE: instantaneous
// make/break pairs (keyboard_send_text) are missed, keys must be HELD. Type
// through XT set-1 scancodes. Unlike send_text this also delivers '.' fine.
// KNOWN LIMIT: wrapping a key in shift makes TB register it twice (and
// unshifted) no matter how the make/breaks are grouped -- prefer lowercase
// and digits in key scripts.
const SC = {};
"1234567890-=".split("").forEach((c, i) => SC[c] = 0x02 + i);
"qwertyuiop".split("").forEach((c, i) => SC[c] = 0x10 + i);
"asdfghjkl;'".split("").forEach((c, i) => SC[c] = 0x1E + i);
"zxcvbnm,./".split("").forEach((c, i) => SC[c] = 0x2C + i);
SC[" "] = 0x39;
const SHIFTED = { "!": "1", '"': "'", "#": "3", "$": "4", "%": "5", "&": "7",
  "*": "8", "(": "9", ")": "0", "_": "-", "+": "=", ":": ";", "<": ",",
  ">": ".", "?": "/" };
const typeHeld = async (s, hold) => {
  for (const ch of s) {
    const lower = ch.toLowerCase();
    const shifted = SHIFTED[ch] || (ch >= "A" && ch <= "Z" ? lower : null);
    const code = SC[shifted || lower];
    if (code === undefined) { console.error(`[capture] no scancode for ${JSON.stringify(ch)}`); continue; }
    // makes and breaks batched per call so shift state is never ambiguous;
    // ~100ms hold registers without reaching the typematic repeat
    emulator.keyboard_send_scancodes(shifted ? [0x2A, code] : [code]);
    await sleep(hold || 100);
    emulator.keyboard_send_scancodes(shifted ? [code | 0x80, 0xAA] : [code | 0x80]);
    await sleep(120);
  }
};

// The returning FreeDOS prompt marks program exit. CLS before launch makes
// "B:\>" unique: row 0 is the echoed command, the next "B:\>" is the return.
const PROMPT = "B:\\>";
const promptCount = () => (scr().match(/B:\\>/g) || []).length;

const countOf = (sub) => scr().split(sub).length - 1;
const waitForCount = async (sub, n, ms) => {
  const t = Date.now();
  while (Date.now() - t < ms) { if (countOf(sub) >= n) return true; await sleep(150); }
  return false;
};
const answer = async (step) => {
  if (step.sleep) { await sleep(step.sleep); return; }
  if (step.wait && !(await waitForCount(step.wait, step.count || 1, RUN_MS)))
    console.error(`[capture] wait ${JSON.stringify(step.wait)} timed out`);
  // TB's runtime installs its keyboard handling around the first INPUT;
  // typing too early loses the keys, so give it a beat (tunable per step)
  await sleep(step.delay ?? 1200);
  let text = step.send || "";
  const enter = text.endsWith("\r");
  if (enter) text = text.slice(0, -1);
  if (text) await typeHeld(text, step.hold);
  if (enter) { await sleep(500); await held(ENTER, 500); }
};

(async () => {
  await sleep(BOOT_MS);
  await typeSlow("b:"); await tapKey(ENTER, 800);
  await typeSlow("cls"); await tapKey(ENTER, 800);
  const before = promptCount();                      // the fresh empty prompt
  await typeSlow(stem.toLowerCase()); await tapKey(ENTER, 300);
  for (const step of KEYS) await answer(step);
  // done when a prompt beyond the pre-launch one appears (the echoed command
  // consumed the first)
  const t0 = Date.now();
  let done = false;
  while (Date.now() - t0 < RUN_MS) {
    if (promptCount() >= before + 1 && scr().trimEnd().endsWith(PROMPT)) { done = true; break; }
    await sleep(200);
  }
  await sleep(300);

  // Screen: drop the echoed-command / returning-prompt rows and outer blanks.
  // NOTE rows arrive right-stripped (attachScreen), so consumers must compare
  // with per-line rstrip.
  const rows = scr().split("\n");
  let out = rows.filter(r => !r.startsWith(PROMPT));
  while (out.length && !out[0].trim()) out.shift();
  while (out.length && !out[out.length - 1].trim()) out.pop();
  console.log("=== screen ===");
  for (const r of out) console.log(r);
  console.log("=== end ===");

  // New files on the floppy -> host.
  const outImg = path.join(HERE, "work_capout.img");
  await lib.saveFdb(emulator, outImg);
  const after = execFileSync("mdir", ["-i", outImg, "-b"]).toString().split("\n")
    .map(l => l.trim().replace(/^::\/?/, "")).filter(Boolean);
  for (const name of after) {
    if (baseline.has(name)) continue;
    const dst = path.join(OUTDIR, name);
    try {
      lib.extractExe(outImg, name, dst);
      console.log(`file: ${name} ${fs.statSync(dst).size}`);
    } catch (e) { console.error(`[capture] extract ${name}: ${e.message}`); }
  }
  if (!done) console.error("[capture] TIMEOUT: DOS prompt did not return");
  process.exit(done ? 0 : 3);
})().catch(e => { console.error(e); process.exit(1); });
