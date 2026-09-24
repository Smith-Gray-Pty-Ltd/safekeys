"""Fake sidecar for the SDK tests.

A real Unix socket server that speaks the sidecar protocol, so the tests
exercise the actual transport rather than a mock.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

Handler = Callable[[dict[str, Any]], dict[str, Any]]


class FakeSidecar:
    """A minimal sidecar that records requests and returns canned responses."""

    def __init__(self, tmpdir: Path) -> None:
        self.socket_path = str(tmpdir / "sidecar.sock")
        self.requests: list[dict[str, Any]] = []
        self.handler: Handler = lambda req: {"ok": True}
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(self.socket_path)
        self._sock.listen(8)
        self._sock.settimeout(0.2)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            with conn:
                chunks: list[bytes] = []
                while True:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
                try:
                    req = json.loads(b"".join(chunks).decode("utf-8"))
                except json.JSONDecodeError:
                    conn.sendall(b'{"ok":false,"error":"denied"}')
                    continue
                self.requests.append(req)
                try:
                    resp = self.handler(req)
                except Exception:  # noqa: BLE001  # pragma: no cover
                    # A test handler may raise to simulate a failure; the fake
                    # sidecar turns that into a generic denial, as the real one does.
                    resp = {"ok": False, "error": "denied"}
                conn.sendall(json.dumps(resp).encode("utf-8"))

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            self._sock.close()
        if self._thread is not None:
            self._thread.join(timeout=2)
        try:
            os.remove(self.socket_path)
        except OSError:
            pass


def b64(s: str) -> str:
    """Base64-encode, mirroring how the Go sidecar sends byte fields."""
    return base64.b64encode(s.encode("utf-8")).decode("ascii")
