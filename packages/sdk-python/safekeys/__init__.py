"""Safekeys — token-only Python SDK.

Encrypted secret transport for agents, built so plaintext never enters model
context.

The API surface is deliberately narrow. It accepts and returns only capability
tokens and folder paths, and it contains no cryptography at all: every
resolution is delegated to the local sidecar over a Unix socket. That is what
makes the guarantee structural rather than a matter of discipline.

    from safekeys import Safekeys

    sk = Safekeys()

    # Create: takes a PATH, never a value. The sidecar reads the file.
    secret = sk.create_secret(source_file="/tmp/api-key.txt")
    print(secret.token)   # safekey://v1/...#<JWS> — contains no secret material

    # Use: the command receives the value; you receive its output and status.
    result = sk.resolve_for_tool(secret.token, ["gh", "api", "/user"])

There is no function anywhere in this package that returns a secret value.
"""

from .client import (
    CreatedSecret,
    ObjectMetadata,
    ResolveResult,
    Safekeys,
    SafekeysDenied,
    SafekeysError,
    SafekeysUnavailable,
)

__version__ = "0.1.0"

__all__ = [
    "CreatedSecret",
    "ObjectMetadata",
    "ResolveResult",
    "Safekeys",
    "SafekeysDenied",
    "SafekeysError",
    "SafekeysUnavailable",
    "__version__",
]
