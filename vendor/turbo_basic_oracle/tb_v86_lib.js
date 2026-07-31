// Shared primitives for the v86 TurboBasic harnesses (run + diagnostic).
const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

// Build work.img = tb_floppy.img + <basPath> as SOLVER.BAS (CRLF), referenced
// external $INLINE files, and staged dbx/*.DAT.
// `tbFloppy` selects an alternate base image (e.g. tb10_floppy.img for Turbo Basic 1.0).
function buildWorkImg(basPath, here, tbFloppy, workspace = here) {
  fs.mkdirSync(workspace, { recursive: true });
  const work = path.join(workspace, "work.img");
  fs.copyFileSync(path.join(here, tbFloppy || "tb_floppy.img"), work);
  const basText = fs.readFileSync(basPath, "latin1").replace(/\r?\n/g, "\r\n");
  const tmp = path.join(workspace, ".solver.bas.tmp");
  fs.writeFileSync(tmp, basText, "latin1");
  execFileSync("mcopy", ["-o", "-i", work, tmp, "::SOLVER.BAS"]);
  // Turbo BASIC's external `$INLINE "file"` and `$INCLUDE "file"` forms
  // read host files from DOS while the compiler is running.  Stage the
  // dependencies explicitly: SOLVER.BAS alone is insufficient, and an
  // unstaged include otherwise produces Error 493.  Includes may nest (the
  // compiler documents six levels), so walk them relative to each source
  // file.  Byte-list `$INLINE` remains source-only and needs no staging.
  const staged = new Map(); // DOS basename -> { host, include }; detect collisions
  const pending = [{ host: path.resolve(basPath), text: basText }];
  const seen = new Set();
  while (pending.length) {
    const current = pending.shift();
    const sourceDir = path.dirname(current.host);
    const patterns = [
      { re: /^\s*\$INCLUDE\s*:?\s*(?:"([^"]+)"|'([^']+)')/gim, ext: ".BAS", label: "$INCLUDE" },
      { re: /\$INLINE\s+"([^"]+)"/ig, ext: "", label: "$INLINE" },
    ];
    for (const { re, ext, label } of patterns) {
      for (const m of current.text.matchAll(re)) {
        const requested = m[1] || m[2];
        const normalized = requested.replace(/[\\/]/g, path.sep);
        const rooted = path.isAbsolute(normalized)
          ? normalized
          : path.join(sourceDir, normalized);
        const candidates = [rooted];
        if (ext && !path.extname(rooted)) candidates.push(rooted + ext);
        const candidate = candidates.find((f) => fs.existsSync(f));
        if (!candidate) {
          throw new Error(`${label} file not found on host: ${requested}`);
        }
        const resolved = path.resolve(candidate);
        const dosName = path.basename(resolved).toUpperCase();
        const prior = staged.get(dosName);
        if (prior && prior.host !== resolved) {
          throw new Error(`DOS filename collision while staging ${requested}`);
        }
        staged.set(dosName, {
          host: resolved,
          include: (prior && prior.include) || label === "$INCLUDE",
        });
        if (!seen.has(resolved)) {
          seen.add(resolved);
          pending.push({
            host: resolved,
            text: fs.readFileSync(resolved, "latin1"),
          });
        }
      }
    }
  }
  const includeTemps = [];
  for (const [dosName, entry] of staged) {
    let source = entry.host;
    if (entry.include) {
      source = path.join(workspace, `.include-${includeTemps.length}.tmp`);
      const text = fs.readFileSync(entry.host, "latin1").replace(/\r?\n/g, "\r\n");
      fs.writeFileSync(source, text, "latin1");
      includeTemps.push(source);
    }
    execFileSync("mcopy", ["-o", "-i", work, source, "::" + dosName]);
  }
  for (const f of includeTemps) {
    fs.unlinkSync(f);
  }
  const dbx = path.join(here, "dbx");
  if (fs.existsSync(dbx)) {
    for (const f of fs.readdirSync(dbx)) {
      if (/\.dat$/i.test(f)) {
        try { execFileSync("mcopy", ["-o", "-i", work, path.join(dbx, f), "::" + f.toUpperCase()]); } catch {}
      }
    }
  }
  fs.unlinkSync(tmp);
  return work;
}

// Copy a file OUT of a FAT image to the host.
function extractExe(workImg, nameInImage, outPath) {
  execFileSync("mcopy", ["-o", "-i", workImg, "::" + nameInImage, outPath]);
  return outPath;
}

// Parse v86's debug "#ud <OPCODE>/.." log line -> the opcode hex token, else null.
function parseUdToken(line) {
  const m = /#ud\s+([0-9A-Fa-f]+)\//.exec(line);
  return m ? m[1].toUpperCase() : null;
}

// Boot a v86 emulator. opts: { here, workImg, wasmFile, logLevel, disableJit }.
// wasmFile defaults to "v86.wasm"; pass "v86-debug.wasm" for the logging build.
function bootEmulator(opts) {
  const { here, workImg, wasmFile = "v86.wasm", logLevel, disableJit } = opts;
  const v86Module = require("v86");
  const V86 = v86Module.V86 || v86Module;
  // Resolve v86's build dir via require.resolve (robust to node_modules hoisting),
  // then select the requested wasm blob (v86.wasm / v86-debug.wasm / v86-fallback.wasm).
  const v86BuildDir = path.dirname(require.resolve("v86/build/v86.wasm"));
  // Prefer our locally-rebuilt blob if vendored (e.g. the FBLD-patched v86.wasm) so the
  // fix survives `npm install` clobbering node_modules. See oracle/V86_BUILD.md.
  const vendored = path.join(here, "vendor", wasmFile);
  const wasmPath = fs.existsSync(vendored) ? vendored : path.join(v86BuildDir, wasmFile);
  const cfg = {
    wasm_path: wasmPath,
    bios: { url: path.join(here, "bios/seabios.bin") },
    vga_bios: { url: path.join(here, "bios/vgabios.bin") },
    fda: { url: path.join(here, "freedos.img") },
    fdb: { url: workImg },
    autostart: true,
    disable_keyboard: false,
  };
  if (typeof logLevel === "number") cfg.log_level = logLevel;
  if (disableJit) cfg.disable_jit = true;
  return new V86(cfg);
}

// Attach an 80x25 text-screen mirror. Returns { scr() } reading the current screen.
function attachScreen(emulator) {
  let screen = Array.from({ length: 25 }, () => Array(80).fill(" "));
  emulator.add_listener("screen-put-char", function () {
    const a = Array.isArray(arguments[0]) ? arguments[0] : Array.from(arguments);
    const row = a[0], col = a[1], cc = a[2] & 0xFF;
    if (row >= 0 && row < 25 && col >= 0 && col < 80)
      screen[row][col] = (cc >= 32 && cc <= 126) ? String.fromCharCode(cc) : " ";
  });
  emulator.add_listener("screen-clear", () => { screen = Array.from({ length: 25 }, () => Array(80).fill(" ")); });
  // `clear()` blanks the host-side mirror so a poll for a marker (e.g. "Stack:") cannot
  // match leftover text from a previous screen; the guest repaints on its next update.
  const clear = () => { screen = Array.from({ length: 25 }, () => Array(80).fill(" ")); };
  return { scr: () => screen.map(r => r.join("").replace(/\s+$/, "")).join("\n"), clear };
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

async function waitForStableScreen(scrFn, stableMs, timeoutMs) {
  const started = Date.now();
  let last = scrFn(), since = Date.now();
  while (Date.now() - started < timeoutMs) {
    await sleep(100);
    const now = scrFn();
    if (now !== last) { last = now; since = Date.now(); }
    else if (Date.now() - since >= stableMs) return true;
  }
  return false;
}

async function waitForExe(emulator, imagePath, guestName, outPath, timeoutMs) {
  const started = Date.now();
  let lastSize = -1, stable = 0;
  while (Date.now() - started < timeoutMs) {
    await sleep(200);
    try {
      await saveFdb(emulator, imagePath);
      fs.rmSync(outPath, { force: true });
      extractExe(imagePath, guestName, outPath);
      const size = fs.statSync(outPath).size;
      if (size > 0 && size === lastSize) stable++;
      else stable = 0;
      lastSize = size;
      if (stable >= 2) return true;
    } catch (_) {
      stable = 0;
      lastSize = -1;
    }
  }
  return false;
}

// Keyboard driving primitives (XT make/break scancodes).
const ENTER = 0x1C;
function makeDriver(emulator) {
  const altKey = async (make) => { emulator.keyboard_send_scancodes([0x38, make, make | 0x80, 0xB8]); await sleep(600); };
  const tapKey = async (make, after = 500) => { emulator.keyboard_send_scancodes([make, make | 0x80]); await sleep(after); };
  const typeSlow = async (s) => { for (const ch of s) { emulator.keyboard_send_text(ch); await sleep(70); } };
  const waitFor = async (scrFn, sub, ms) => { const t = Date.now(); while (Date.now() - t < ms) { if (scrFn().includes(sub)) return true; await sleep(150); } return false; };
  // Held make->break: TB's in-menu keys must be held (~130ms) to register. Note the
  // hold also triggers one typematic repeat, so each press moves a menu cursor twice.
  const held = async (make, after = 500) => { emulator.keyboard_send_scancodes([make]); await sleep(130); emulator.keyboard_send_scancodes([make | 0x80]); await sleep(after); };
  // Extended (E0-prefixed) held key, e.g. arrow keys.
  const heldExt = async (make, after = 500) => { emulator.keyboard_send_scancodes([0xE0, make]); await sleep(130); emulator.keyboard_send_scancodes([0xE0, make | 0x80]); await sleep(after); };
  // Extended key, quick press-release (no hold): unlike `heldExt`, this does NOT
  // trigger a typematic repeat, so it moves a menu cursor exactly one item --
  // needed to land precisely on one of the Options toggle rows (see
  // `setOptionsToggles`), where `heldExt`'s double-step would overshoot.
  const tapKeyExt = async (make, after = 350) => { emulator.keyboard_send_scancodes([0xE0, make, 0xE0, make | 0x80]); await sleep(after); };
  return { altKey, tapKey, typeSlow, waitFor, held, heldExt, tapKeyExt };
}

// Options-menu row index for each IDE toggle letter (decode0.Program.toggles
// alphabet), with row 0 ("Compile to") as the fixed navigation anchor.
const TOGGLE_ROW = { "8": 1, K: 2, B: 3, O: 4, S: 5 };
const DOWN = 0x50, UP = 0x48;

// Set the given Options toggles (e.g. "KBOS") to ON via the real IDE menu, then
// leave the Options menu closed. Assumes it starts closed and TB is idle at the
// editor (as tb_v86.js's COMPILE_EXE branch expects before its own Alt-O).
//
// Every toggle here started OFF (Turbo Basic's default), so this only turns
// toggles ON; it does not need to detect current state. `held`/`heldExt` (used
// for the "Compile to" popup, see tb_v86.js) advance a cursor by TWO rows per
// call due to typematic repeat -- confirmed by watching the toggle rows flip on
// screen -- but the Options toggle LIST needs single-row precision, so this
// uses `tapKeyExt` (a quick tap, no repeat) instead. Verified byte-exact via a
// self-consistency round trip: a KBOS-toggled EXE, decoded, re-emitted, and
// recompiled with the same toggles reproduces the original exactly.
async function setOptionsToggles(driver, scrFn, togglesStr) {
  if (!togglesStr) return;
  const { altKey, held, tapKeyExt } = driver;
  await altKey(0x18); // Alt-O, cursor starts at row 0 ("Compile to")
  await sleep(400);
  let cur = 0;
  for (const letter of togglesStr) {
    const target = TOGGLE_ROW[letter];
    if (target === undefined) throw new Error(`setOptionsToggles: unknown toggle letter ${letter}`);
    const delta = target - cur;
    const key = delta > 0 ? DOWN : UP;
    for (let i = 0; i < Math.abs(delta); i++) await tapKeyExt(key);
    await held(ENTER, 300);
    cur = target;
  }
  for (let i = 0; i < cur; i++) await tapKeyExt(UP); // back to row 0
  await held(0x01, 400); // Esc closes the Options menu
}

// Dump the guest's B: floppy (fdb) to a host file so files the guest wrote (e.g. a
// TB-compiled SOLVER.EXE) can be read back with mtools -- v86 keeps disk writes in RAM.
async function saveFdb(emulator, outPath) {
  const buf = await emulator.get_disk_fdb();
  fs.writeFileSync(outPath, Buffer.from(buf));
  return outPath;
}

module.exports = { buildWorkImg, extractExe, parseUdToken, bootEmulator, attachScreen, makeDriver, saveFdb, waitForStableScreen, waitForExe, setOptionsToggles, sleep, ENTER };
