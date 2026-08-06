"""Bridge to the external Turbo Basic toolchain oracle (triage/authoring only).

The oracle is a headless v86 automation of the ORIGINAL Borland toolchain
vendored under ``vendor/turbo_basic_oracle``; tbx depends only on this contract:

    node <oracle>/tb_v86.js FILE.BAS --compile-exe [--floppy IMG]
        compiles FILE.BAS with the real Turbo Basic compiler and leaves the
        produced EXE at <oracle>/SOLVER_v86.EXE
    node <oracle>/tb_v86_capture.js PROG.EXE [--keys JSON] [--run-ms N]
                                    [--outdir DIR]
        runs PROG.EXE on the emulated machine, answers prompts from the key
        script, prints the final text screen between `=== screen ===` and
        `=== end ===`, and extracts files the program created into DIR
        (`file: NAME SIZE` lines). Exit 3 = the program never returned to the
        DOS prompt (interactive/graphics/hang) -- no usable capture.

Locate it with TBX_ORACLE=/path/to/oracle (default: the vendored
`vendor/turbo_basic_oracle`; a compatible external harness may be selected
explicitly). Needs node and mtools. Like cfgview, this is
never part of the decompile pipeline; everything here is for verifying new
fixtures byte-exact and capturing behavior goldens.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent.parent

# dialect -> the oracle floppy image carrying that compiler
_FLOPPIES = {
    "1.1": None,              # English 1.1 oracle default
    "1.0": "tb10_floppy.img",
    "fr-1.1": "tb11_fr_floppy.img",
}

#: Public: the `dialect` values `compile_bas` accepts.
DIALECTS = tuple(_FLOPPIES)


def preflight() -> None:
    """Fail early when the external oracle harness cannot run."""
    d = oracle_dir()
    missing = [name for name in ("node", "mcopy") if shutil.which(name) is None]
    if missing:
        raise RuntimeError(f"Turbo Basic oracle missing tools: {', '.join(missing)}")
    check = subprocess.run(
        ["node", "-e", "require.resolve('v86')"], cwd=d,
        capture_output=True, text=True,
    )
    if check.returncode:
        raise RuntimeError(
            f"Turbo Basic oracle dependency v86 is unavailable in {d}; "
            "run npm ci there"
        )


def oracle_dir() -> Path:
    """The oracle directory, or raise with setup instructions."""
    env = os.environ.get("TBX_ORACLE")
    if env:
        cand = Path(env)
    else:
        # The repository-vendored v86 harness is the supported default.
        vendored = _REPO / "vendor" / "turbo_basic_oracle"
        cand = vendored
    if not (cand / "tb_v86.js").is_file():
        raise RuntimeError(
            f"Turbo Basic oracle not found at {cand} -- set TBX_ORACLE to the "
            "oracle directory (needs node + mtools)"
        )
    return cand


def _floppy_name(dialect: str) -> str:
    """The floppy filename `tb_v86_fast.js` keys snapshots by (never None)."""
    return _FLOPPIES[dialect] or "tb_floppy.img"


def _snapshot_path(dialect: str, toggles: str) -> Path:
    return oracle_dir() / "snapshots" / f"{_floppy_name(dialect)}__{toggles or 'none'}.state"


def has_snapshot(dialect: str = "1.1", toggles: str = "") -> bool:
    """Whether `compile_bas(fast=True)` has a snapshot ready for this pair."""
    return _snapshot_path(dialect, toggles).is_file()


def prime_snapshot(dialect: str = "1.1", toggles: str = "", timeout: int = 300) -> Path:
    """Prime a `compile_bas(fast=True)` snapshot for (dialect, toggles).

    One-time setup per (dialect, toggles) pair: boots the oracle, sets the
    given IDE Options toggles and "Compile to: EXE file" through the real
    menus, then saves a v86 state snapshot that `compile_bas(fast=True)`
    restores from on every subsequent call instead of rebooting -- cuts a
    ~8s compile to ~4s. See `tb_v86_fast.js`'s module docstring for the
    mechanism and why it's verified byte-identical to the plain path.
    """
    d = oracle_dir()
    snap_path = _snapshot_path(dialect, toggles)
    with tempfile.TemporaryDirectory(prefix="tbx-oracle-prime-") as workspace:
        cmd = [
            "node", "tb_v86_fast.js", "--prime",
            "--floppy", _floppy_name(dialect),
            "--snapshot-dir", str(snap_path.parent),
            "--workspace", workspace,
        ]
        if toggles:
            cmd += ["--toggles", toggles]
        r = subprocess.run(cmd, cwd=d, capture_output=True, text=True, timeout=timeout)
        if r.returncode:
            raise RuntimeError(f"oracle prime failed:\n{r.stdout[-2000:]}\n{r.stderr[-2000:]}")
    return snap_path


def compile_bas(
    bas: Path | str,
    dialect: str = "1.1",
    timeout: int = 300,
    toggles: str = "",
    fast: bool = False,
) -> bytes:
    """Compile a .BAS with the real Turbo Basic compiler; return EXE bytes.

    The vendored harness stages external ``$INCLUDE`` and ``$INLINE``
    dependencies relative to the source file before invoking Turbo Basic.

    `toggles` sets IDE Options before compiling (any of "8KBOS", ON only --
    they are all OFF by default), driven through the real Options menu the
    same way `--compile-exe` drives "Compile to EXE file". See
    `tb_v86_lib.setOptionsToggles`.

    `fast=True` restores a pre-primed v86 snapshot instead of rebooting
    FreeDOS and re-navigating the IDE menus on every call -- see
    `prime_snapshot`, which must be called once for this exact
    (dialect, toggles) pair before `fast=True` can be used; raises
    RuntimeError naming the missing snapshot otherwise. Verified
    byte-identical to the non-fast path across the fixture corpus and both
    dialects; use it freely once primed.
    """
    d = oracle_dir()
    with tempfile.TemporaryDirectory(prefix="tbx-oracle-") as workspace:
        out = Path(workspace) / "SOLVER_v86.EXE"
        if fast:
            snap_path = _snapshot_path(dialect, toggles)
            if not snap_path.is_file():
                raise RuntimeError(
                    f"no primed snapshot for dialect={dialect!r} toggles={toggles!r} "
                    f"(expected {snap_path}); call oracle.prime_snapshot(dialect={dialect!r}, "
                    f"toggles={toggles!r}) first"
                )
            cmd = [
                "node", "tb_v86_fast.js", str(Path(bas).resolve()),
                "--floppy", _floppy_name(dialect), "--snapshot-dir", str(snap_path.parent),
                "--compile-exe", "--workspace", workspace,
            ]
            if toggles:
                cmd += ["--toggles", toggles]
        else:
            cmd = [
                "node", "tb_v86.js", str(Path(bas).resolve()), "--compile-exe",
                "--workspace", workspace,
            ]
            if toggles:
                cmd += ["--toggles", toggles]
            floppy = _FLOPPIES[dialect]
            if floppy:
                cmd += ["--floppy", floppy]
        r = subprocess.run(cmd, cwd=d, capture_output=True, text=True, timeout=timeout)
        if not out.is_file():
            raise RuntimeError(
                f"oracle compile failed for {bas}:\n{r.stdout[-2000:]}\n{r.stderr[-2000:]}"
            )
        return out.read_bytes()


@dataclass
class RunResult:
    screen: str  # final text screen, prompt rows stripped, lines rstripped
    files: dict[str, bytes]  # files the program created on its disk
    timed_out: bool  # True: never returned to the DOS prompt


def run_exe(
    exe: Path | str,
    keys: str | None = None,
    run_ms: int = 20000,
    timeout: int = 180,
    workdir: Path | str | None = None,
) -> RunResult:
    """Run a DOS EXE on the emulated machine and capture screen + files.

    `keys` is the harness's JSON key script (see module docstring)."""
    import tempfile

    d = oracle_dir()
    with tempfile.TemporaryDirectory(dir=workdir) as td:
        cmd = [
            "node", "tb_v86_capture.js", str(Path(exe).resolve()),
            "--run-ms", str(run_ms), "--outdir", td,
        ]
        if keys:
            cmd += ["--keys", keys]
        r = subprocess.run(cmd, cwd=d, capture_output=True, text=True, timeout=timeout)
        if r.returncode not in (0, 3):
            raise RuntimeError(f"oracle run failed for {exe}:\n{r.stderr[-2000:]}")
        lines = r.stdout.split("\n")
        try:
            a, b = lines.index("=== screen ==="), lines.index("=== end ===")
        except ValueError:
            raise RuntimeError(f"oracle run produced no capture for {exe}") from None
        screen = "\n".join(lines[a + 1 : b])
        files = {
            p.name: p.read_bytes() for p in sorted(Path(td).iterdir()) if p.is_file()
        }
    return RunResult(screen=screen, files=files, timed_out=r.returncode == 3)
