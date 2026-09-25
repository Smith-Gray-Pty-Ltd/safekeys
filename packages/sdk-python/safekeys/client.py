"""The Safekeys client.

This module contains no cryptography and holds no keys. Every operation is
delegated to the local sidecar over its Unix domain socket — see contract
``sidecar-is-the-transport`` in
``.usm/features/integration/python-sdk.usm``.

The public API accepts and returns only capability tokens and folder paths. No
public function returns a secret value.
"""

from __future__ import annotations

import json
import os
import socket
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "CreatedSecret",
    "ObjectMetadata",
    "ResolveResult",
    "Safekeys",
    "SafekeysDenied",
    "SafekeysError",
    "SafekeysUnavailable",
    "default_socket_path",
]

#: The token URI scheme, matching spec/capability-token.
TOKEN_SCHEME = "safekey://"

#: The default socket path, matching SAFEKEYS_SOCKET in the Go components.
DEFAULT_TIMEOUT_SECONDS = 60.0


def default_socket_path() -> str:
    """Return the sidecar socket path, honouring ``SAFEKEYS_SOCKET``."""
    env = os.environ.get("SAFEKEYS_SOCKET")
    if env:
        return env
    return str(Path(tempfile.gettempdir()) / "safekeys" / "sidecar.sock")


class SafekeysError(Exception):
    """Base class for SDK errors."""


class SafekeysDenied(SafekeysError):
    """The sidecar refused the request.

    The reason is deliberately not surfaced here: a detailed denial reason is a
    probing oracle (ADR ``generic-denials``). It is recorded in the sidecar's
    audit log instead, which is where an operator should look.
    """


class SafekeysUnavailable(SafekeysError):
    """The sidecar could not be reached.

    Safekeys fails closed. There is no local fallback that could resolve a
    secret, by design — see conformance vector ``sidecar-unavailable-is-an-error``.
    """


# ─── Result types ───────────────────────────────────────────────────────────


@dataclass(frozen=True)
class CreatedSecret:
    """The result of creating a secret.

    Note what is absent: there is no field holding the secret's value. The
    caller receives a token (safe to pass anywhere) and a path to the ciphertext
    folder.
    """

    object_id: str
    folder: str
    token: str
    jti: str | None = None
    expires: int | None = None
    scope: tuple[str, ...] = ()

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"CreatedSecret(object_id={self.object_id!r}, folder={self.folder!r})"


@dataclass(frozen=True)
class ResolveResult:
    """The result of resolving a secret into a consumer.

    ``stdout`` is the *consumer's own* output, relayed back. It is not the
    secret, and the SDK never returns the secret.
    """

    exit_code: int
    stdout: str = ""
    stderr: str = ""
    descriptor: str = ""


@dataclass(frozen=True)
class ObjectMetadata:
    """Metadata about a registered secret object. Never a value."""

    id: str
    owner: str | None = None
    content_type: str | None = None
    wrapping_kid: str | None = None
    created_at: str | None = None


# ─── Client ─────────────────────────────────────────────────────────────────


@dataclass
class Safekeys:
    """A token-only client for the local Safekeys sidecar.

    Args:
        socket_path: Path to the sidecar's Unix socket. Defaults to
            ``SAFEKEYS_SOCKET`` or the platform temp directory.
        timeout: Socket timeout in seconds. Resolution runs a subprocess, so the
            default is generous.
        principal: Attribution for created objects. Falls back to
            ``SAFEKEYS_PRINCIPAL``.
    """

    socket_path: str = field(default_factory=default_socket_path)
    timeout: float = DEFAULT_TIMEOUT_SECONDS
    principal: str | None = field(
        default_factory=lambda: os.environ.get("SAFEKEYS_PRINCIPAL")
    )

    # ── create ──────────────────────────────────────────────────────────────

    def create_secret(
        self,
        source_file: str | os.PathLike[str] | None = None,
        *,
        value: bytes | None = None,
        object_id: str | None = None,
        content_type: str | None = None,
        scope: Sequence[str] | None = None,
        audience: str | None = None,
        ttl_seconds: int | None = None,
    ) -> CreatedSecret:
        """Create a secret and receive a capability token.

        Prefer ``source_file``: the sidecar reads the file itself, so the value
        never passes through the caller's arguments. ``value`` exists for trusted
        in-process callers (a CLI reading stdin, a test), not for agent-authored
        code — an agent should always use a file.

        Returns:
            A :class:`CreatedSecret` carrying a token and a folder path. The
            secret's value is never returned.
        """
        if source_file is None and value is None:
            raise ValueError("provide source_file (preferred) or value")
        if source_file is not None and value is not None:
            raise ValueError("provide exactly one of source_file or value")

        req: dict[str, Any] = {
            "op": "create",
            "object_id": object_id,
            "content_type": content_type,
            "scope_list": list(scope) if scope else None,
            "audience": audience,
            "ttl_seconds": ttl_seconds,
            "principal": self.principal,
        }
        if source_file is not None:
            req["source_file"] = str(source_file)

        resp = self._send(req, payload_value=value)
        created = resp.get("created") or {}
        return CreatedSecret(
            object_id=created.get("object_id", ""),
            folder=created.get("folder", ""),
            token=created.get("token", ""),
            jti=created.get("jti"),
            expires=created.get("expires"),
            scope=tuple(created.get("scope") or ()),
        )

    # ── resolve ─────────────────────────────────────────────────────────────

    def resolve_for_tool(
        self,
        token: str,
        command: Sequence[str],
        *,
        name: str | None = None,
        scope: str = "inject-env",
    ) -> ResolveResult:
        """Run a command with a secret injected into its environment.

        The command receives the value; this method returns the command's own
        output and exit status. It never returns the value.

        Args:
            token: A capability token URI. Safe to pass — it carries no secret.
            command: The argv to run.
            name: Environment variable name for the injected value.
            scope: Operation to request. Defaults to ``inject-env``.

        Returns:
            A :class:`ResolveResult` with the consumer's exit status and output.
        """
        if not token.startswith(TOKEN_SCHEME):
            raise ValueError(f"expected a {TOKEN_SCHEME} token, not a raw value")
        resp = self._send(
            {
                "op": "resolve",
                "token": token,
                "command": list(command),
                "name": name,
                "scope": scope,
                "principal": self.principal,
            }
        )
        return ResolveResult(
            exit_code=int(resp.get("exit_code") or 0),
            stdout=_maybe_b64(resp.get("stdout")),
            stderr=_maybe_b64(resp.get("stderr")),
            descriptor=resp.get("descriptor", ""),
        )

    # ── list / revoke ───────────────────────────────────────────────────────

    def list_objects(self) -> list[ObjectMetadata]:
        """List registered secret objects. Metadata only — never values."""
        resp = self._send({"op": "list"})
        return [
            ObjectMetadata(
                id=o.get("id", ""),
                owner=o.get("owner_principal"),
                content_type=o.get("content_type"),
                wrapping_kid=o.get("wrapping_kid"),
                created_at=o.get("created_at"),
            )
            for o in (resp.get("objects") or [])
        ]

    def revoke_token(self, jti: str) -> None:
        """Revoke a capability token by its id.

        Takes effect immediately rather than at expiry, so this is the kill
        switch for a token believed leaked.
        """
        self._send({"op": "revoke", "jti": jti})

    # ── transport ───────────────────────────────────────────────────────────

    def _send(self, req: dict[str, Any], payload_value: bytes | None = None) -> dict[str, Any]:
        """Send one request to the sidecar and return the response.

        ``payload_value`` is written to a private temp file which the sidecar
        reads, so even the in-process ``value`` path does not put bytes on the
        socket. There is no fallback: if the sidecar is unreachable this raises
        :class:`SafekeysUnavailable`.
        """
        cleanup: str | None = None
        if payload_value is not None:
            fd, path = tempfile.mkstemp(prefix="safekeys-", suffix=".src")
            try:
                os.write(fd, payload_value)
            finally:
                os.close(fd)
            os.chmod(path, 0o600)
            req["source_file"] = path
            cleanup = path

        try:
            raw = self._roundtrip(req)
        finally:
            if cleanup is not None:
                _shred(cleanup)

        parsed: dict[str, Any] = json.loads(raw)
        if not parsed.get("ok"):
            raise SafekeysDenied(parsed.get("error") or "denied")
        return parsed

    def _roundtrip(self, req: dict[str, Any]) -> str:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect(self.socket_path)
                sock.sendall(json.dumps(req).encode("utf-8"))
                sock.shutdown(socket.SHUT_WR)
                chunks: list[bytes] = []
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
        except (TimeoutError, FileNotFoundError, ConnectionRefusedError) as exc:
            raise SafekeysUnavailable(
                f"no sidecar listening at {self.socket_path}; "
                "Safekeys fails closed rather than resolving locally"
            ) from exc
        except OSError as exc:
            raise SafekeysUnavailable(str(exc)) from exc
        return b"".join(chunks).decode("utf-8")


def _maybe_b64(value: Any) -> str:
    """The Go sidecar base64-encodes byte fields. Decode for display."""
    if not value:
        return ""
    import base64

    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    try:
        return base64.b64decode(value).decode("utf-8", "replace")
    except (ValueError, TypeError):
        # Not base64: treat it as already-decoded text rather than guessing.
        return ""


def _shred(path: str) -> None:
    """Remove a temp source file. Best-effort: the OS may have page-cached it."""
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as fh:
            fh.write(b"\x00" * size)
        os.remove(path)
    except OSError:
        pass
