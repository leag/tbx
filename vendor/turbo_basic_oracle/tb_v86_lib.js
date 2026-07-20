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
  // Turbo BASIC's `$INLINE "file"` form reads the file from DOS while the
  // compiler is running.  The old harness only staged SOLVER.BAS, so the
  // compiler always reported Error 496 for valid external inline files.  Find
  // quoted files in the source, resolve them beside the .BAS file (or as an
  // explicit absolute path), and copy them into the image under their DOS
  // basename.  Byte-list `$INLINE` remains source-only and needs no staging.
  const inlineFiles = new Set();
  for (const m of basText.matchAll(/\$INLINE\s+"([^"]+)"/ig)) {
    const requested = m[1];
    const candidate = path.isAbsolute(requested)
      ? requested
      : path.join(path.dirname(path.resolve(basPath)), requested);
    if (!fs.existsSync(candidate)) {
      throw new Error(`$INLINE file not found on host: ${requested}`);
    }
    inlineFiles.add(candidate);
  }
  for (const f of inlineFiles) {
    const dosName = path.basename(f).toUpperCase();
    execFileSync("mcopy", ["-o", "-i", work, f, "::" + dosName]);
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
  return { altKey, tapKey, typeSlow, waitFor, held, heldExt };
}

// Dump the guest's B: floppy (fdb) to a host file so files the guest wrote (e.g. a
// TB-compiled SOLVER.EXE) can be read back with mtools -- v86 keeps disk writes in RAM.
async function saveFdb(emulator, outPath) {
  const buf = await emulator.get_disk_fdb();
  fs.writeFileSync(outPath, Buffer.from(buf));
  return outPath;
}

module.exports = { buildWorkImg, extractExe, parseUdToken, bootEmulator, attachScreen, makeDriver, saveFdb, waitForStableScreen, waitForExe, sleep, ENTER };
