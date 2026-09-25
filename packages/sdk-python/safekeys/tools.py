"""LangChain and LangGraph tools.

These wrap the same :class:`~safekeys.client.Safekeys` methods used by the raw
SDK — see contract ``langchain-tool-parity`` in
``.usm/features/integration/python-sdk.usm``. A tool's output never includes a
resolved value, and its schema accepts only tokens and paths.

``langchain-core`` is optional. If it is not installed, the tool specifications
are still importable as plain dictionaries so an integrator can register them
with any framework, and :func:`build_langchain_tools` raises a clear error.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from .client import Safekeys

__all__ = [
    "TOOL_SPECS",
    "ToolSpec",
    "build_langchain_tools",
    "create_secret_tool",
    "resolve_for_tool_tool",
]

#: Maximum token lifetime, mirroring the control plane's bound. Tokens are
#: short-lived by design, so the tool schema cannot request a long one.
MAX_TTL_SECONDS = 43_200  # 12 hours


@dataclass(frozen=True)
class ToolSpec:
    """A framework-neutral tool definition.

    The ``parameters`` dict is JSON-Schema shaped, so it is directly usable by
    LangChain, the OpenAI Agents SDK, Mastra, or anything else that consumes JSON
    Schema. Note that no parameter is named ``value``, ``secret``, or similar —
    a model cannot supply one.
    """

    name: str
    description: str
    parameters: dict[str, Any]


TOOL_SPECS: tuple[ToolSpec, ...] = (
    ToolSpec(
        name="create_secret",
        description=(
            "Create a secret and receive a capability token. Takes a path to a file "
            "containing the secret; the sidecar reads and encrypts it. Returns a "
            "token and a folder path, never the secret's value. There is no "
            "parameter for the value itself."
        ),
        parameters={
            "type": "object",
            "properties": {
                "source_file": {
                    "type": "string",
                    "description": (
                        "Absolute path to a file containing the secret. The sidecar "
                        "reads this file itself; the value is never passed through "
                        "this call."
                    ),
                },
                "object_id": {"type": "string", "description": "Optional object id."},
                "content_type": {"type": "string", "description": "Optional media-type hint."},
                "ttl_seconds": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_TTL_SECONDS,
                    "description": "Token lifetime in seconds. Bounded to 12 hours.",
                },
            },
            "required": ["source_file"],
        },
    ),
    ToolSpec(
        name="resolve_for_tool",
        description=(
            "Run a command with a secret injected into its environment. The command "
            "receives the value; this tool returns the command's own output and exit "
            "status. The value is never returned."
        ),
        parameters={
            "type": "object",
            "properties": {
                "token": {
                    "type": "string",
                    "description": "A safekey:// capability token. Contains no secret material.",
                },
                "command": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "The command to run, as an argv array.",
                },
                "name": {
                    "type": "string",
                    "description": "Environment variable name for the injected value.",
                },
            },
            "required": ["token", "command"],
        },
    ),
)


def create_secret_tool(sk: Safekeys) -> Any:
    """Return a callable that creates a secret, as plain Python.

    Returns a function taking keyword arguments and returning a JSON-serialisable
    dict. It is framework-agnostic; :func:`build_langchain_tools` wraps it for
    LangChain.
    """

    def _create_secret(
        source_file: str,
        object_id: str | None = None,
        content_type: str | None = None,
        ttl_seconds: int | None = None,
    ) -> dict[str, Any]:
        created = sk.create_secret(
            source_file=source_file,
            object_id=object_id,
            content_type=content_type,
            ttl_seconds=ttl_seconds,
        )
        # A token and a path leave this function — never a value.
        return {
            "ok": True,
            "object_id": created.object_id,
            "folder": created.folder,
            "token": created.token,
            "jti": created.jti,
            "expires": created.expires,
            "message": (
                f"Created {created.object_id}. The value was read by the sidecar and "
                "never passed through this call."
            ),
        }

    return _create_secret


def resolve_for_tool_tool(sk: Safekeys) -> Any:
    """Return a callable that resolves a secret into a command."""

    def _resolve_for_tool(
        token: str,
        command: Sequence[str],
        name: str | None = None,
    ) -> dict[str, Any]:
        result = sk.resolve_for_tool(token, list(command), name=name)
        return {
            "ok": result.exit_code == 0,
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "message": (
                f"Command ran with the secret injected. Exit status {result.exit_code}. "
                "The value was never returned to this caller."
            ),
        }

    return _resolve_for_tool


def build_langchain_tools(sk: Safekeys) -> list[Any]:
    """Build LangChain tool objects for Safekeys.

    Requires ``langchain-core`` (install with ``safekeys[langchain]``). Raises a
    clear error if it is absent rather than degrading silently.

    The tools wrap the same functions as the raw SDK, so a LangGraph agent and a
    direct caller behave identically.
    """
    try:
        from langchain_core.tools import StructuredTool
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise ImportError(
            "langchain-core is required for build_langchain_tools(); "
            "install with `pip install safekeys[langchain]`, or use TOOL_SPECS "
            "with your own framework."
        ) from exc

    create_fn = create_secret_tool(sk)
    resolve_fn = resolve_for_tool_tool(sk)
    specs = {s.name: s for s in TOOL_SPECS}

    return [
        StructuredTool.from_function(
            func=create_fn,
            name="create_secret",
            description=specs["create_secret"].description,
        ),
        StructuredTool.from_function(
            func=resolve_fn,
            name="resolve_for_tool",
            description=specs["resolve_for_tool"].description,
        ),
    ]
