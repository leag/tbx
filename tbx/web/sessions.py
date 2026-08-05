"""Per-upload temp-directory bookkeeping for the web UI's decompile/recompile flow."""

from __future__ import annotations

import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Session:
    id: str
    exe_path: Path
    dialect: str


class SessionStore:
    """Keeps one temp directory per uploaded EXE, keyed by a UUID.

    Local dev tool: directories are not explicitly cleaned up, matching the
    throwaway-workspace pattern already used by tbx.tools.oracle.compile_bas.
    """

    def __init__(self, base_dir: Path | None = None) -> None:
        self._base_dir = base_dir
        self._sessions: dict[str, Session] = {}

    def create(self, exe_bytes: bytes, dialect: str) -> Session:
        session_id = uuid.uuid4().hex
        workdir = Path(tempfile.mkdtemp(prefix=f"tbx-web-{session_id}-", dir=self._base_dir))
        exe_path = workdir / "original.exe"
        exe_path.write_bytes(exe_bytes)
        session = Session(id=session_id, exe_path=exe_path, dialect=dialect)
        self._sessions[session_id] = session
        return session

    def get(self, session_id: str) -> Session:
        return self._sessions[session_id]
