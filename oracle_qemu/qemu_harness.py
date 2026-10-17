#!/usr/bin/env python3
"""Headless Turbo Basic compiler and DOS execution harness using QEMU.

The harness talks to QEMU through QMP. Keyboard events are sent as QEMU key
codes, and the 80x25 text display is read from VGA memory. No graphical
display, terminal scraping, or host keyboard automation is required.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

SCREEN_ADDRESS = 0xB8000
SCREEN_COLUMNS = 80
SCREEN_ROWS = 25
SCREEN_BYTES = SCREEN_COLUMNS * SCREEN_ROWS * 2
SNAPSHOT_FORMAT_VERSION = 3

_INCLUDE_RE = re.compile(
    r"^\s*\$INCLUDE\s*:?\s*(?:\"([^\"]+)\"|'([^']+)')",
    re.IGNORECASE | re.MULTILINE,
)
_INLINE_RE = re.compile(
    r'^\s*(?:\d+\s+)?\$INLINE\s+"([^"]+)"',
    re.IGNORECASE | re.MULTILINE,
)
_DOS_NAME_RE = re.compile(
    r"^[A-Z0-9!#$%&'()@^_`{}~-]{1,8}(?:\.[A-Z0-9!#$%&'()@^_`{}~-]{1,3})?$"
)
# The IDE shows the message inside the editor's frame (``║Error 418: ...``).
_ERROR_RE = re.compile(r"^[\s║│]*Error\s+\d+:", re.IGNORECASE | re.MULTILINE)


class HarnessError(RuntimeError):
    """An actionable harness setup or guest automation failure."""


@dataclass(frozen=True)
class SourceAsset:
    host_path: Path
    guest_name: str
    is_source: bool


@dataclass(frozen=True)
class RunResult:
    screen: str
    files: dict[str, bytes]
    timed_out: bool


def _read_latin1(path: Path) -> str:
    try:
        return path.read_text(encoding="latin-1")
    except OSError as error:
        raise HarnessError(f"cannot read {path}: {error}") from error


def _dos_basename(path: Path) -> str:
    name = path.name.upper()
    if not _DOS_NAME_RE.fullmatch(name):
        raise HarnessError(
            f"{path.name!r} is not an unambiguous DOS 8.3 filename; "
            "rename the referenced file before staging it"
        )
    return name


def _case_insensitive_file(path: Path) -> Path | None:
    if path.is_file():
        return path.resolve()
    try:
        matches = [
            entry
            for entry in path.parent.iterdir()
            if entry.name.casefold() == path.name.casefold()
        ]
    except OSError:
        return None
    return matches[0].resolve() if len(matches) == 1 and matches[0].is_file() else None


def _resolve_source_reference(owner: Path, reference: str, include: bool) -> Path:
    normalized = reference.replace("\\", os.sep).replace("/", os.sep)
    requested = Path(normalized)
    rooted = requested if requested.is_absolute() else owner.parent / requested
    candidates = [rooted]
    if include and not rooted.suffix:
        candidates.append(rooted.with_suffix(".BAS"))
    for candidate in candidates:
        resolved = _case_insensitive_file(candidate)
        if resolved is not None:
            return resolved
    directive = "$INCLUDE" if include else "$INLINE"
    raise HarnessError(
        f"{directive} file {reference!r}, referenced by {owner}, was not found"
    )


def discover_source_assets(source: Path | str) -> tuple[SourceAsset, ...]:
    """Return recursively referenced include/inline files in staging order."""

    root = Path(source).resolve()
    if not root.is_file():
        raise HarnessError(f"BASIC source does not exist: {root}")

    pending = [root]
    scanned: set[Path] = set()
    by_guest_name: dict[str, SourceAsset] = {}

    while pending:
        owner = pending.pop(0)
        if owner in scanned:
            continue
        scanned.add(owner)
        text = _read_latin1(owner)
        references: list[tuple[str, bool]] = []
        references.extend(
            ((left or right), True) for left, right in _INCLUDE_RE.findall(text)
        )
        references.extend((name, False) for name in _INLINE_RE.findall(text))

        for reference, is_source in references:
            host = _resolve_source_reference(owner, reference, is_source)
            guest_name = _dos_basename(host)
            asset = SourceAsset(host, guest_name, is_source)
            prior = by_guest_name.get(guest_name)
            if prior is not None and prior.host_path != host:
                raise HarnessError(
                    f"DOS filename collision: {prior.host_path} and {host} "
                    f"both map to {guest_name}"
                )
            if prior is None or (is_source and not prior.is_source):
                by_guest_name[guest_name] = asset
            if is_source and host not in scanned:
                pending.append(host)

    return tuple(by_guest_name.values())


def normalize_basic_source(text: str) -> bytes:
    """Encode source as Latin-1 with the CRLF lines expected by DOS tools."""

    unix_text = re.sub(r"\r\n|\r|\n", "\n", text)
    return unix_text.replace("\n", "\r\n").encode("latin-1")


def decode_vga_text(memory: bytes) -> str:
    """Decode the character cells of an 80x25 color text-mode VGA page."""

    if len(memory) != SCREEN_BYTES:
        raise HarnessError(
            f"expected {SCREEN_BYTES} bytes of VGA text memory, got {len(memory)}"
        )
    characters = memory[0::2]
    rows = []
    for row_index in range(SCREEN_ROWS):
        start = row_index * SCREEN_COLUMNS
        raw = characters[start : start + SCREEN_COLUMNS]
        text = "".join(
            " " if value < 32 else bytes((value,)).decode("cp437") for value in raw
        )
        rows.append(text.rstrip())
    return "\n".join(rows)


def guest_executable_name(path: Path | str) -> str:
    stem = re.sub(r"[^A-Za-z0-9_]", "", Path(path).stem)[:8].upper() or "PROGRAM"
    return f"{stem}.EXE"


def _qemu_drive_path(path: Path) -> str:
    """Escape a filename embedded in QEMU's comma-separated -drive syntax."""

    return str(path).replace(",", ",,")


def _normalize_toggles(toggles: str) -> str:
    order = "8KBOS"
    rows = set(order)
    normalized = toggles.upper()
    unknown = sorted(set(normalized) - rows)
    if unknown:
        raise HarnessError(f"unknown Turbo Basic option toggle(s): {''.join(unknown)}")
    if len(set(normalized)) != len(normalized):
        raise HarnessError("Turbo Basic option toggles must not be repeated")
    return "".join(toggle for toggle in order if toggle in normalized)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise HarnessError(f"cannot fingerprint {path}: {error}") from error
    return digest.hexdigest()


def _qcode_for_character(character: str) -> tuple[str, ...]:
    unshifted = {
        " ": "spc",
        "-": "minus",
        "=": "equal",
        "[": "bracket_left",
        "]": "bracket_right",
        ";": "semicolon",
        "'": "apostrophe",
        "`": "grave_accent",
        "\\": "backslash",
        ",": "comma",
        ".": "dot",
        "/": "slash",
    }
    shifted = {
        "!": "1",
        "@": "2",
        "#": "3",
        "$": "4",
        "%": "5",
        "^": "6",
        "&": "7",
        "*": "8",
        "(": "9",
        ")": "0",
        "_": "minus",
        "+": "equal",
        "{": "bracket_left",
        "}": "bracket_right",
        ":": "semicolon",
        '"': "apostrophe",
        "~": "grave_accent",
        "|": "backslash",
        "<": "comma",
        ">": "dot",
        "?": "slash",
    }
    if character.isascii() and (character.islower() or character.isdigit()):
        return (character,)
    if character.isascii() and character.isupper():
        return ("shift", character.lower())
    if character in unshifted:
        return (unshifted[character],)
    if character in shifted:
        return ("shift", shifted[character])
    raise HarnessError(f"cannot type character {character!r} with the QEMU key map")


class QMPClient:
    """Small synchronous QMP client with event-aware response framing."""

    def __init__(self, socket_path: Path, timeout: float = 10.0):
        self.socket_path = socket_path
        self.timeout = timeout
        self._socket: socket.socket | None = None
        self._reader = None
        self._next_id = 1

    def connect(self) -> None:
        deadline = time.monotonic() + self.timeout
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(min(0.25, self.timeout))
        while True:
            try:
                sock.connect(str(self.socket_path))
                break
            except PermissionError as error:
                sock.close()
                raise HarnessError(
                    f"permission denied while connecting to QEMU's QMP socket: {error}"
                ) from error
            except (FileNotFoundError, ConnectionRefusedError, socket.timeout) as error:
                if time.monotonic() >= deadline:
                    sock.close()
                    raise HarnessError(
                        f"QEMU did not create a usable QMP socket: {error}"
                    ) from error
                time.sleep(0.05)
        sock.settimeout(self.timeout)
        self._socket = sock
        self._reader = sock.makefile("rb")
        greeting = self._read_message()
        if "QMP" not in greeting:
            raise HarnessError(f"invalid QMP greeting: {greeting!r}")
        self.execute("qmp_capabilities")

    def _read_message(self) -> dict:
        if self._reader is None:
            raise HarnessError("QMP client is not connected")
        while True:
            line = self._reader.readline()
            if not line:
                raise HarnessError("QMP connection closed unexpectedly")
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(message, dict):
                return message

    def execute(self, command: str, arguments: dict | None = None):
        if self._socket is None:
            raise HarnessError("QMP client is not connected")
        request_id = self._next_id
        self._next_id += 1
        payload = {"execute": command, "id": request_id}
        if arguments:
            payload["arguments"] = arguments
        wire = json.dumps(payload, separators=(",", ":")).encode() + b"\r\n"
        self._socket.sendall(wire)
        while True:
            response = self._read_message()
            if response.get("id") != request_id:
                continue
            if "error" in response:
                detail = response["error"].get("desc", response["error"])
                raise HarnessError(f"QMP {command} failed: {detail}")
            return response.get("return")

    def close(self) -> None:
        if self._reader is not None:
            self._reader.close()
            self._reader = None
        if self._socket is not None:
            self._socket.close()
            self._socket = None


class QemuSession(AbstractContextManager):
    def __init__(
        self,
        qemu: str,
        boot_image: Path,
        work_image: Path,
        workspace: Path,
        memory_mb: int = 16,
        incoming: Path | None = None,
    ):
        self.qemu = qemu
        self.boot_image = boot_image
        self.work_image = work_image
        self.workspace = workspace
        self.memory_mb = memory_mb
        self.incoming = incoming
        token = f"{os.getpid()}-{uuid.uuid4().hex[:8]}"
        self.socket_path = Path("/tmp") / f"tbd-qmp-{token}.sock"
        self.screen_path = Path("/tmp") / f"tbd-vga-{token}.bin"
        self.stderr_path = workspace / "qemu.stderr.log"
        self.process: subprocess.Popen | None = None
        self.qmp = QMPClient(self.socket_path)

    def __enter__(self):
        stderr_stream = self.stderr_path.open("wb")
        command = [
            self.qemu,
            "-name",
            "tbd-qemu-harness",
            "-machine",
            "pc,accel=tcg",
            "-cpu",
            "486",
            "-m",
            str(self.memory_mb),
            "-display",
            "none",
            "-serial",
            "none",
            "-monitor",
            "none",
            "-boot",
            "order=a",
            "-no-reboot",
            "-qmp",
            f"unix:{self.socket_path},server=on,wait=off",
            "-drive",
            f"file={_qemu_drive_path(self.boot_image)},if=none,format=raw,"
            "readonly=on,id=boot",
            "-device",
            "floppy,drive=boot,id=floppyA,unit=0",
            "-drive",
            f"file={_qemu_drive_path(self.work_image)},if=none,"
            "format=raw,cache=writethrough,id=work",
            "-device",
            "floppy,drive=work,id=floppyB,unit=1",
        ]
        if self.incoming is not None:
            command.extend(("-incoming", f"file:{self.incoming}"))
        try:
            self.process = subprocess.Popen(
                command, stdout=subprocess.DEVNULL, stderr=stderr_stream
            )
        except OSError as error:
            raise HarnessError(f"cannot start {self.qemu}: {error}") from error
        finally:
            stderr_stream.close()
        try:
            self.qmp.connect()
        except Exception:
            self.close()
            raise
        return self

    def wait_for_running(self, timeout: float = 20) -> None:
        deadline = time.monotonic() + timeout
        last_status = "unknown"
        while time.monotonic() < deadline:
            status = self.qmp.execute("query-status")
            last_status = status.get("status", "unknown")
            if last_status == "running":
                return
            time.sleep(0.05)
        raise HarnessError(
            f"restored QEMU did not enter the running state (last state: {last_status})"
        )

    def change_work_disk(self, image: Path) -> None:
        self.qmp.execute(
            "blockdev-change-medium",
            {
                "id": "floppyB",
                "filename": str(image),
                "format": "raw",
                "read-only-mode": "read-write",
                "force": True,
            },
        )

    def save_migration(self, destination: Path, timeout: float = 60) -> None:
        destination.unlink(missing_ok=True)
        self.qmp.execute("migrate", {"uri": f"file:{destination}"})
        deadline = time.monotonic() + timeout
        last = {}
        while time.monotonic() < deadline:
            last = self.qmp.execute("query-migrate")
            status = last.get("status")
            if status == "completed":
                return
            if status in {"failed", "cancelled"}:
                detail = last.get("error-desc", status)
                raise HarnessError(f"QEMU snapshot migration failed: {detail}")
            time.sleep(0.05)
        raise HarnessError(f"QEMU snapshot migration timed out: {last}")

    def screen(self) -> str:
        self.screen_path.unlink(missing_ok=True)
        self.qmp.execute(
            "pmemsave",
            {
                "val": SCREEN_ADDRESS,
                "size": SCREEN_BYTES,
                "filename": str(self.screen_path),
            },
        )
        try:
            memory = self.screen_path.read_bytes()
        except OSError as error:
            raise HarnessError(
                f"QEMU did not produce a VGA memory snapshot: {error}"
            ) from error
        return decode_vga_text(memory)

    def cursor(self) -> tuple[int, int]:
        """The page-0 text cursor (row, column) from the BIOS data area."""

        path = self.screen_path.with_name("cursor.bin")
        path.unlink(missing_ok=True)
        self.qmp.execute("pmemsave", {"val": 0x450, "size": 2, "filename": str(path)})
        try:
            column, row = path.read_bytes()[:2]
        except (OSError, ValueError):
            return -1, -1
        return row, column

    def send_keys(
        self, keys: Sequence[str], hold_ms: int = 80, after: float = 0.12
    ) -> None:
        encoded = [{"type": "qcode", "data": key} for key in keys]
        self.qmp.execute("send-key", {"keys": encoded, "hold-time": hold_ms})
        time.sleep(after)

    def tap(self, key: str, hold_ms: int = 80, after: float = 0.12) -> None:
        self.send_keys((key,), hold_ms, after)

    def chord(self, modifier: str, key: str, after: float = 0.35) -> None:
        self.send_keys((modifier, key), 100, after)

    def type_text(self, text: str, interval: float = 0.055) -> None:
        for character in text:
            self.send_keys(_qcode_for_character(character), 55, interval)

    def wait_for(
        self,
        predicate: Callable[[str], bool],
        timeout: float,
        description: str,
        poll_interval: float = 0.02,
    ) -> str:
        deadline = time.monotonic() + timeout
        last = ""
        while time.monotonic() < deadline:
            last = self.screen()
            if predicate(last):
                return last
            time.sleep(poll_interval)
        raise HarnessError(
            f"timed out waiting for {description}\nFinal screen:\n{last}"
        )

    def wait_for_text(self, text: str, timeout: float) -> str:
        return self.wait_for(
            lambda screen: text.casefold() in screen.casefold(), timeout, repr(text)
        )

    def wait_until_stable(self, quiet_for: float, timeout: float) -> str:
        deadline = time.monotonic() + timeout
        previous = self.screen()
        changed_at = time.monotonic()
        while time.monotonic() < deadline:
            time.sleep(0.02)
            current = self.screen()
            if current != previous:
                previous = current
                changed_at = time.monotonic()
            elif time.monotonic() - changed_at >= quiet_for:
                return current
        raise HarnessError("the guest screen did not become stable")

    def wait_for_compile_start(self, timeout: float) -> str:
        """Wait until Turbo Basic enters its compiler status screen."""

        deadline = time.monotonic() + timeout
        last_screen = ""
        while time.monotonic() < deadline:
            last_screen = self.screen()
            if _ERROR_RE.search(last_screen):
                time.sleep(0.3)
                last_screen = self.screen()
                row, column = self.cursor()
                raise HarnessError(
                    f"Turbo Basic reported a compile error\nCursor: {row},{column}"
                    f"\nScreen:\n{last_screen}"
                )
            if "compiling" in last_screen.casefold():
                return last_screen
            time.sleep(0.02)
        raise HarnessError(
            f"Turbo Basic did not start compiling within {timeout:.1f}s"
            f"\nScreen:\n{last_screen}"
        )

    def wait_for_compile_finish(self, timeout: float) -> str:
        """Wait for the final code/data/stack summary or a compiler error."""

        deadline = time.monotonic() + timeout
        last_screen = ""
        while time.monotonic() < deadline:
            last_screen = self.screen()
            if _ERROR_RE.search(last_screen):
                time.sleep(0.3)
                last_screen = self.screen()
                row, column = self.cursor()
                raise HarnessError(
                    f"Turbo Basic reported a compile error\nCursor: {row},{column}"
                    f"\nScreen:\n{last_screen}"
                )
            if re.search(r"\b(?:Stack|Stk):", last_screen):
                return last_screen
            time.sleep(0.02)
        raise HarnessError(
            f"Turbo Basic did not finish compiling within {timeout:.1f}s"
            f"\nScreen:\n{last_screen}"
        )

    def close(self) -> None:
        if self.process is not None and self.process.poll() is None:
            try:
                self.qmp.execute("quit")
            except (HarnessError, OSError):
                self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.qmp.close()
        self.socket_path.unlink(missing_ok=True)
        self.screen_path.unlink(missing_ok=True)

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


class _Workspace(AbstractContextManager):
    def __init__(self, requested: Path | None):
        self.requested = requested
        self._temporary: tempfile.TemporaryDirectory | None = None
        self.path: Path | None = None

    def __enter__(self) -> Path:
        if self.requested is None:
            self._temporary = tempfile.TemporaryDirectory(prefix="tbd-qemu-")
            self.path = Path(self._temporary.name)
        else:
            self.path = self.requested.resolve()
            self.path.mkdir(parents=True, exist_ok=True)
        return self.path

    def __exit__(self, exc_type, exc, traceback) -> None:
        if self._temporary is not None:
            self._temporary.cleanup()


class QemuHarness:
    """Build private guest disks and automate Turbo Basic or DOS under QEMU."""

    def __init__(
        self,
        boot_image: Path | str,
        compiler_image: Path | str,
        *,
        qemu: str = "qemu-system-i386",
        mcopy: str = "mcopy",
        mdir: str = "mdir",
        snapshot_directory: Path | str | None = None,
    ):
        self.boot_image = Path(boot_image).resolve()
        self.compiler_image = Path(compiler_image).resolve()
        self.qemu = qemu
        self.mcopy = mcopy
        self.mdir = mdir
        self.snapshot_directory = (
            Path(snapshot_directory).resolve()
            if snapshot_directory is not None
            else Path(__file__).resolve().parent / "snapshots"
        )

    def preflight(self) -> None:
        missing = [
            tool
            for tool in (self.qemu, self.mcopy, self.mdir)
            if shutil.which(tool) is None
        ]
        if missing:
            raise HarnessError(f"required command(s) not found: {', '.join(missing)}")
        for label, image in (
            ("boot", self.boot_image),
            ("compiler", self.compiler_image),
        ):
            if not image.is_file():
                raise HarnessError(f"{label} floppy image does not exist: {image}")

    def _qemu_version(self) -> str:
        try:
            result = subprocess.run(
                [self.qemu, "--version"],
                check=True,
                capture_output=True,
                text=True,
            )
        except (OSError, subprocess.CalledProcessError) as error:
            raise HarnessError(f"cannot identify {self.qemu}: {error}") from error
        return result.stdout.splitlines()[0].strip()

    def _snapshot_metadata(self, toggles: str) -> dict[str, str | int]:
        return {
            "format": SNAPSHOT_FORMAT_VERSION,
            "qemu": self._qemu_version(),
            "boot_sha256": _file_sha256(self.boot_image),
            "compiler_sha256": _file_sha256(self.compiler_image),
            "toggles": _normalize_toggles(toggles),
            "machine": "pc,accel=tcg",
            "cpu": "486",
            "memory_mb": 16,
        }

    def snapshot_path(self, toggles: str = "") -> Path:
        metadata = self._snapshot_metadata(toggles)
        encoded = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
        fingerprint = hashlib.sha256(encoded).hexdigest()[:20]
        toggle_name = metadata["toggles"] or "none"
        return self.snapshot_directory / f"tb-{toggle_name}-{fingerprint}.mig"

    def has_snapshot(self, toggles: str = "") -> bool:
        return self.snapshot_path(toggles).is_file()

    def _mtool(
        self, executable: str, image: Path, *arguments: str
    ) -> subprocess.CompletedProcess:
        command = [executable, "-i", str(image), *arguments]
        try:
            return subprocess.run(command, check=True, capture_output=True, text=True)
        except (OSError, subprocess.CalledProcessError) as error:
            detail = getattr(error, "stderr", "") or str(error)
            raise HarnessError(
                f"mtools command failed: {' '.join(command)}\n{detail.strip()}"
            ) from error

    def _copy_into_image(self, image: Path, host: Path, guest_name: str) -> None:
        self._mtool(self.mcopy, image, "-o", str(host), f"::{guest_name}")

    def _directory(self, image: Path) -> set[str]:
        result = self._mtool(self.mdir, image, "-b", "::")
        names = set()
        for line in result.stdout.splitlines():
            name = (
                line.strip().replace("\\", "/").removeprefix("::/").removeprefix("::")
            )
            if name and "/" not in name:
                names.add(name.upper())
        return names

    def _extract(self, image: Path, guest_name: str, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        self._mtool(self.mcopy, image, "-o", f"::{guest_name}", str(destination))

    def _stage_source(self, source: Path, image: Path, workspace: Path) -> None:
        main_copy = workspace / "SOLVER.BAS"
        main_copy.write_bytes(normalize_basic_source(_read_latin1(source)))
        self._copy_into_image(image, main_copy, "SOLVER.BAS")
        for index, asset in enumerate(discover_source_assets(source)):
            staged = asset.host_path
            if asset.is_source:
                staged = workspace / f"include-{index:03d}.bas"
                staged.write_bytes(
                    normalize_basic_source(_read_latin1(asset.host_path))
                )
            self._copy_into_image(image, staged, asset.guest_name)

    @staticmethod
    def _enter_dos_drive(session: QemuSession) -> None:
        session.wait_for(lambda text: ":\\>" in text, 20, "the FreeDOS prompt")
        session.type_text("b:")
        session.tap("ret", after=0.5)

    @staticmethod
    def _set_toggles(session: QemuSession, toggles: str) -> None:
        labels = {
            "8": "8087 required",
            "K": "Keyboard break",
            "B": "Bounds",
            "O": "Overflow",
            "S": "Stack test",
        }
        normalized = _normalize_toggles(toggles)
        if not normalized:
            return
        session.chord("alt", "o")
        session.wait_for_text("Compile to", 5)
        for toggle in normalized:
            label = labels[toggle]
            session.tap(toggle.lower(), hold_ms=10, after=0.2)
            screen = session.screen()
            if not re.search(rf"{re.escape(label)}\s+ON", screen, re.IGNORECASE):
                session.tap("ret", hold_ms=100, after=0.2)
                screen = session.screen()
            if not re.search(rf"{re.escape(label)}\s+ON", screen, re.IGNORECASE):
                raise HarnessError(
                    f"could not enable option {label!r}\nScreen:\n{screen}"
                )
        for _ in range(3):
            session.tap("esc", hold_ms=10, after=0.2)
            if "Compile to" not in session.screen():
                break
        else:
            raise HarnessError("could not close the Options menu after setting toggles")

    @staticmethod
    def _wait_for_loaded_source(session: QemuSession) -> None:
        session.wait_for_text("SOLVER.BAS", 30)
        loaded_screen = session.wait_until_stable(0.7, 30)
        if "too large" in loaded_screen.casefold():
            raise HarnessError(
                "Turbo Basic rejected SOLVER.BAS because it exceeds the editor limit"
            )

    def _open_ide(self, session: QemuSession, toggles: str) -> None:
        self._enter_dos_drive(session)
        session.type_text("tb.exe solver.bas")
        session.tap("ret", after=0.2)
        session.wait_for_text("Turbo Basic", 20)
        self._wait_for_loaded_source(session)
        self._set_toggles(session, toggles)
        self._select_exe_output(session)

    @staticmethod
    def _open_load_dialog(session: QemuSession) -> None:
        session.chord("alt", "f", after=0)
        session.wait_for_text("Change dir", 5)
        session.tap("l", hold_ms=10, after=0)
        session.wait_for_text("Load File Name", 5)

    @staticmethod
    def _reload_source(session: QemuSession, disk: Path) -> None:
        session.wait_for_running()
        session.wait_for_text("Load File Name", 5)
        session.change_work_disk(disk)
        session.tap("ret", hold_ms=100, after=0)
        loaded_screen = session.wait_for(
            lambda screen: "Load File Name" not in screen,
            30,
            "Turbo Basic to finish loading SOLVER.BAS",
        )
        if "too large" in loaded_screen.casefold():
            raise HarnessError(
                "Turbo Basic rejected SOLVER.BAS because it exceeds the editor limit"
            )

    @staticmethod
    def _compile_loaded_source(session: QemuSession, timeout: float) -> None:
        session.chord("alt", "c", after=0)
        session.wait_for_compile_start(min(timeout, 60))
        session.wait_for_compile_finish(timeout)

    def prime(
        self,
        *,
        toggles: str = "",
        timeout: float = 120,
        force: bool = False,
    ) -> Path:
        """Create a compatible snapshot with the source Load dialog waiting."""

        self.preflight()
        normalized = _normalize_toggles(toggles)
        destination = self.snapshot_path(normalized)
        if destination.is_file() and not force:
            return destination
        destination.parent.mkdir(parents=True, exist_ok=True)
        partial = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
        try:
            with _Workspace(None) as work:
                disk = work / "prime-work.img"
                shutil.copyfile(self.compiler_image, disk)
                source = work / "SOLVER.BAS"
                source.write_bytes(b"END\r\n")
                self._copy_into_image(disk, source, "SOLVER.BAS")
                with QemuSession(self.qemu, self.boot_image, disk, work) as session:
                    self._open_ide(session, normalized)
                    self._open_load_dialog(session)
                    session.save_migration(partial, timeout=min(timeout, 60))
            os.replace(partial, destination)
            manifest = destination.with_suffix(".json")
            manifest.write_text(
                json.dumps(self._snapshot_metadata(normalized), indent=2) + "\n",
                encoding="utf-8",
            )
        finally:
            partial.unlink(missing_ok=True)
        return destination

    @staticmethod
    def _select_exe_output(session: QemuSession) -> None:
        session.chord("alt", "o")
        session.wait_for_text("Compile to", 5)
        session.tap("c", hold_ms=10, after=0.3)
        popup = session.screen()
        if "EXE file" not in popup or "Chain file" not in popup:
            session.tap("ret", hold_ms=100, after=0.3)
        session.tap("e", hold_ms=10, after=0.4)
        screen = session.screen()
        if not re.search(r"Compile to\s+EXE file", screen, re.IGNORECASE):
            session.tap("ret", hold_ms=100, after=0.4)
            screen = session.screen()
        if not re.search(r"Compile to\s+EXE file", screen, re.IGNORECASE):
            raise HarnessError(
                f"could not verify 'Compile to: EXE file'\nScreen:\n{screen}"
            )
        session.tap("esc", after=0.3)

    def compile(
        self,
        source: Path | str,
        output: Path | str,
        *,
        toggles: str = "",
        timeout: float = 120,
        workspace: Path | str | None = None,
        fast: bool | None = None,
    ) -> Path:
        self.preflight()
        normalized = _normalize_toggles(toggles)
        snapshot = self.snapshot_path(normalized)
        if fast is True and not snapshot.is_file():
            toggle_hint = f" --toggles {normalized}" if normalized else ""
            raise HarnessError(
                f"no compatible hot-start snapshot exists at {snapshot}; "
                f"run the 'prime' command{toggle_hint}"
            )
        use_snapshot = snapshot.is_file() if fast is None else fast
        source_path = Path(source).resolve()
        output_path = Path(output).resolve()
        with _Workspace(Path(workspace) if workspace is not None else None) as work:
            disk = work / "compiler-work.img"
            shutil.copyfile(self.compiler_image, disk)
            self._stage_source(source_path, disk, work)
            if use_snapshot:
                resume_disk = work / "resume-work.img"
                shutil.copyfile(self.compiler_image, resume_disk)
                with QemuSession(
                    self.qemu,
                    self.boot_image,
                    resume_disk,
                    work,
                    incoming=snapshot,
                ) as session:
                    self._reload_source(session, disk)
                    self._compile_loaded_source(session, timeout)
            else:
                with QemuSession(self.qemu, self.boot_image, disk, work) as session:
                    self._open_ide(session, normalized)
                    self._compile_loaded_source(session, timeout)
            if "SOLVER.EXE" not in self._directory(disk):
                qemu_log = (work / "qemu.stderr.log").read_text(
                    encoding="utf-8", errors="replace"
                )
                raise HarnessError(
                    f"Turbo Basic produced no SOLVER.EXE\nQEMU log:\n{qemu_log[-2000:]}"
                )
            self._extract(disk, "SOLVER.EXE", output_path)
        return output_path

    def run(
        self,
        executable: Path | str,
        *,
        keys: Sequence[dict] = (),
        files: Sequence[tuple[Path | str, str | None]] = (),
        output_directory: Path | str = ".",
        timeout: float = 20,
        workspace: Path | str | None = None,
    ) -> RunResult:
        self.preflight()
        executable_path = Path(executable).resolve()
        guest_name = guest_executable_name(executable_path)
        output_path = Path(output_directory).resolve()
        with _Workspace(Path(workspace) if workspace is not None else None) as work:
            disk = work / "run-work.img"
            shutil.copyfile(self.compiler_image, disk)
            self._copy_into_image(disk, executable_path, guest_name)
            for host_value, requested_name in files:
                host = Path(host_value).resolve()
                name = requested_name.upper() if requested_name else _dos_basename(host)
                if not _DOS_NAME_RE.fullmatch(name):
                    raise HarnessError(f"invalid guest filename: {name!r}")
                self._copy_into_image(disk, host, name)
            baseline = self._directory(disk)
            timed_out = False
            with QemuSession(self.qemu, self.boot_image, disk, work) as session:
                self._enter_dos_drive(session)
                session.type_text("cls")
                session.tap("ret", after=0.4)
                session.type_text(Path(guest_name).stem.lower())
                session.tap("ret", after=0.2)
                for step in keys:
                    if "sleep" in step:
                        time.sleep(float(step["sleep"]) / 1000)
                        continue
                    marker = step.get("wait")
                    if marker:
                        count = int(step.get("count", 1))
                        session.wait_for(
                            lambda screen, marker=marker, count=count: screen.count(
                                marker
                            )
                            >= count,
                            timeout,
                            f"{count} occurrence(s) of {marker!r}",
                        )
                    time.sleep(float(step.get("delay", 250)) / 1000)
                    send = str(step.get("send", ""))
                    parts = send.split("\r")
                    for index, part in enumerate(parts):
                        if part:
                            session.type_text(part)
                        if index < len(parts) - 1:
                            session.tap(
                                "ret",
                                hold_ms=int(step.get("hold", 100)),
                                after=0.2,
                            )
                deadline = time.monotonic() + timeout
                final_screen = session.screen()
                while time.monotonic() < deadline:
                    final_screen = session.screen()
                    if final_screen.rstrip().endswith("B:\\>"):
                        break
                    time.sleep(0.15)
                else:
                    timed_out = True
                time.sleep(0.25)
                final_screen = session.screen()
            rows = [
                row for row in final_screen.splitlines() if not row.startswith("B:\\>")
            ]
            while rows and not rows[0].strip():
                rows.pop(0)
            while rows and not rows[-1].strip():
                rows.pop()
            captured = "\n".join(rows)
            files_out: dict[str, bytes] = {}
            for name in sorted(self._directory(disk) - baseline):
                destination = output_path / name
                self._extract(disk, name, destination)
                files_out[name] = destination.read_bytes()
        return RunResult(captured, files_out, timed_out)


def _image_argument(value: str | None, environment: str, fallback: Path) -> Path:
    selected = value or os.environ.get(environment)
    return Path(selected) if selected else fallback


def _load_key_script(path: Path | None) -> list[dict]:
    if path is None:
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise HarnessError(f"cannot load key script {path}: {error}") from error
    if not isinstance(payload, list) or not all(
        isinstance(step, dict) for step in payload
    ):
        raise HarnessError("key script must be a JSON array of objects")
    return payload


def _file_argument(value: str) -> tuple[Path, str | None]:
    host, separator, guest = value.partition(":")
    return Path(host), guest if separator else None


def _parser() -> argparse.ArgumentParser:
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description="Headless Turbo Basic harness using qemu-system-i386"
    )
    parser.add_argument(
        "--boot-image", help="bootable FreeDOS floppy (or TBD_QEMU_BOOT_IMAGE)"
    )
    parser.add_argument(
        "--compiler-image",
        help="writable Turbo Basic floppy (or TBD_QEMU_COMPILER_IMAGE)",
    )
    parser.add_argument(
        "--qemu", default=os.environ.get("TBD_QEMU", "qemu-system-i386")
    )
    parser.add_argument(
        "--workspace", type=Path, help="retain private working files here"
    )
    parser.add_argument(
        "--snapshot-directory",
        type=Path,
        default=os.environ.get("TBD_QEMU_SNAPSHOT_DIR"),
        help="hot-start cache directory (or TBD_QEMU_SNAPSHOT_DIR)",
    )
    subparsers = parser.add_subparsers(dest="action", required=True)

    prime_parser = subparsers.add_parser(
        "prime", help="create a reusable hot-start IDE snapshot"
    )
    prime_parser.add_argument(
        "--toggles", default="", help="Turbo Basic Options toggles from 8KBOS"
    )
    prime_parser.add_argument("--timeout", type=float, default=120)
    prime_parser.add_argument("--force", action="store_true")

    compile_parser = subparsers.add_parser(
        "compile", help="compile BASIC source to a DOS EXE"
    )
    compile_parser.add_argument("source", type=Path)
    compile_parser.add_argument("-o", "--output", type=Path, required=True)
    compile_parser.add_argument(
        "--toggles", default="", help="Turbo Basic Options toggles from 8KBOS"
    )
    compile_parser.add_argument("--timeout", type=float, default=120)
    speed = compile_parser.add_mutually_exclusive_group()
    speed.add_argument(
        "--fast",
        dest="fast",
        action="store_true",
        default=None,
        help="require a compatible hot-start snapshot",
    )
    speed.add_argument(
        "--cold",
        dest="fast",
        action="store_false",
        help="ignore hot-start snapshots and boot from scratch",
    )

    run_parser = subparsers.add_parser(
        "run", help="run a DOS EXE and capture text/files"
    )
    run_parser.add_argument("executable", type=Path)
    run_parser.add_argument("--keys", type=Path, help="JSON input script")
    run_parser.add_argument(
        "--file",
        action="append",
        default=[],
        type=_file_argument,
        metavar="HOST[:GUEST]",
    )
    run_parser.add_argument("--output-directory", type=Path, default=Path("."))
    run_parser.add_argument("--timeout", type=float, default=20)

    parser.set_defaults(
        default_boot=here / "freedos.img",
        default_compiler=here / "tb_floppy.img",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    harness = QemuHarness(
        _image_argument(args.boot_image, "TBD_QEMU_BOOT_IMAGE", args.default_boot),
        _image_argument(
            args.compiler_image,
            "TBD_QEMU_COMPILER_IMAGE",
            args.default_compiler,
        ),
        qemu=args.qemu,
        snapshot_directory=args.snapshot_directory,
    )
    try:
        if args.action == "prime":
            snapshot = harness.prime(
                toggles=args.toggles,
                timeout=args.timeout,
                force=args.force,
            )
            print(f"snapshot: {snapshot} ({snapshot.stat().st_size} bytes)")
            return 0
        if args.action == "compile":
            output = harness.compile(
                args.source,
                args.output,
                toggles=args.toggles,
                timeout=args.timeout,
                workspace=args.workspace,
                fast=args.fast,
            )
            print(f"compiled: {output} ({output.stat().st_size} bytes)")
            return 0
        result = harness.run(
            args.executable,
            keys=_load_key_script(args.keys),
            files=args.file,
            output_directory=args.output_directory,
            timeout=args.timeout,
            workspace=args.workspace,
        )
        print("=== screen ===")
        print(result.screen)
        print("=== end ===")
        for name, payload in result.files.items():
            print(f"file: {name} {len(payload)}")
        return 3 if result.timed_out else 0
    except HarnessError as error:
        print(f"qemu-harness: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
