"""Bridge to the external Turbo Basic toolchain oracle (triage/authoring only).

The oracle is a headless automation of the ORIGINAL Borland toolchain living
outside this repository (a sister project); tbx depends only on this contract:

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
`vendor/turbo_basic_oracle`, falling back to `../frame/oracle`). Needs node and
mtools. Like cfgview, this is
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
_FLOPPIES = {"1.1": None, "1.0": "tb10_floppy.img"}  # None = oracle default


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
        # Prefer the repository-vendored harness; retain the historical sibling
        # checkout as a fallback for existing development environments.
        vendored = _REPO / "vendor" / "turbo_basic_oracle"
        sibling = _REPO.parent / "frame" / "oracle"
        cand = vendored if (vendored / "tb_v86.js").is_file() else sibling
    if not (cand / "tb_v86.js").is_file():
        raise RuntimeError(
            f"Turbo Basic oracle not found at {cand} -- set TBX_ORACLE to the "
            "oracle directory (needs node + mtools)"
        )
    return cand


def compile_bas(bas: Path | str, dialect: str = "1.1", timeout: int = 300) -> bytes:
    """Compile a .BAS with the real Turbo Basic compiler; return EXE bytes.

    The vendored harness stages external ``$INCLUDE`` and ``$INLINE``
    dependencies relative to the source file before invoking Turbo Basic.
    """
    d = oracle_dir()
    with tempfile.TemporaryDirectory(prefix="tbx-oracle-") as workspace:
        out = Path(workspace) / "SOLVER_v86.EXE"
        cmd = [
            "node", "tb_v86.js", str(Path(bas).resolve()), "--compile-exe",
            "--workspace", workspace,
        ]
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
