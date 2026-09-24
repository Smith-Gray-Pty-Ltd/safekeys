"""SDK contract tests.

These assert the guarantees in
``.usm/features/integration/python-sdk.usm``: token-only surface, no plaintext
in context, the sidecar as the only transport, and LangChain tool parity.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest
from conftest import FakeSidecar, b64

from safekeys import Safekeys, SafekeysDenied, SafekeysUnavailable

SECRET = "sk-live-SDK-MUST-NOT-APPEAR"


@pytest.fixture()
def sidecar(tmp_path: Path):
    # macOS caps AF_UNIX paths at ~104 chars and pytest's tmp_path is longer, so
    # bind the fake sidecar under a short, unique system temp directory.
    import tempfile

    short = Path(tempfile.mkdtemp(prefix="sfk-", dir="/tmp"))
    s = FakeSidecar(short)
    s.start()
    yield s
    s.stop()
    import shutil

    shutil.rmtree(short, ignore_errors=True)


@pytest.fixture()
def sk(sidecar: FakeSidecar) -> Safekeys:
    return Safekeys(socket_path=sidecar.socket_path, principal="agent-a")


# ─── create ─────────────────────────────────────────────────────────────────


def test_create_returns_token_and_path_never_a_value(sidecar: FakeSidecar, sk: Safekeys):
    sidecar.handler = lambda req: {
        "ok": True,
        "created": {
            "object_id": "obj_abc",
            "folder": "/home/u/.safekeys/folder/obj_abc",
            "token": "safekey://v1/obj_abc#aaa.bbb.ccc",
            "jti": "jti_1",
            "expires": 1790013600,
            "scope": ["inject-env", "read"],
        },
    }

    created = sk.create_secret(source_file="/tmp/api-key.txt")

    assert created.token.startswith("safekey://v1/")
    assert created.folder
    # The dataclass has no field for a value, so it cannot carry one.
    assert not hasattr(created, "value")
    assert not hasattr(created, "secret")
    assert SECRET not in repr(created)


def test_create_prefers_a_file_and_sends_no_value_over_the_socket(
    sidecar: FakeSidecar, sk: Safekeys
):
    sidecar.handler = lambda req: {"ok": True, "created": {"object_id": "o", "folder": "f", "token": "safekey://v1/o#a.b.c"}}
    source = Path(sidecar.socket_path).parent / "src.txt"
    source.write_text(SECRET)

    sk.create_secret(source_file=source)

    req = sidecar.requests[-1]
    # The request names a source path; the value is never on the wire.
    assert req["source_file"] == str(source)
    assert SECRET not in __import__("json").dumps(req)


def test_create_with_in_process_value_uses_a_private_temp_file(
    sidecar: FakeSidecar, sk: Safekeys
):
    sidecar.handler = lambda req: {"ok": True, "created": {"object_id": "o", "folder": "f", "token": "safekey://v1/o#a.b.c"}}

    sk.create_secret(value=SECRET.encode())

    req = sidecar.requests[-1]
    # Even the in-process path does not put bytes on the socket: it writes a
    # 0600 temp file and names it.
    assert "source_file" in req
    assert SECRET not in __import__("json").dumps(req)


def test_create_requires_exactly_one_source(sk: Safekeys):
    with pytest.raises(ValueError, match="source_file"):
        sk.create_secret()
    with pytest.raises(ValueError, match="exactly one"):
        sk.create_secret(source_file="/tmp/x", value=b"y")


def test_create_denial_raises_without_a_detail(sidecar: FakeSidecar, sk: Safekeys):
    sidecar.handler = lambda req: {"ok": False, "error": "denied"}
    with pytest.raises(SafekeysDenied) as exc:
        sk.create_secret(source_file="/tmp/x")
    # Denials are generic: the reason lives in the sidecar's audit log.
    assert str(exc.value) == "denied"


# ─── resolve ────────────────────────────────────────────────────────────────


def test_resolve_returns_command_output_not_the_value(sidecar: FakeSidecar, sk: Safekeys):
    sidecar.handler = lambda req: {
        "ok": True,
        "exit_code": 0,
        "stdout": b64("marker-line\n"),
    }

    result = sk.resolve_for_tool("safekey://v1/obj_abc#a.b.c", ["/bin/sh", "-c", "echo marker"])

    assert result.exit_code == 0
    assert "marker-line" in result.stdout
    assert SECRET not in result.stdout
    assert not hasattr(result, "value")


def test_resolve_rejects_a_raw_value_instead_of_a_token(sk: Safekeys):
    # Passing a value where a token belongs is a caller error, caught loudly.
    with pytest.raises(ValueError, match="safekey://"):
        sk.resolve_for_tool("ghp_actualgithubtoken", ["true"])


def test_resolve_propagates_a_nonzero_exit_as_a_result(sidecar: FakeSidecar, sk: Safekeys):
    sidecar.handler = lambda req: {"ok": True, "exit_code": 7}
    result = sk.resolve_for_tool("safekey://v1/o#a.b.c", ["false"])
    # A failing command is not a denial; it is a result with a status.
    assert result.exit_code == 7


# ─── list / revoke ──────────────────────────────────────────────────────────


def test_list_projects_metadata_only(sidecar: FakeSidecar, sk: Safekeys):
    sidecar.handler = lambda req: {
        "ok": True,
        "objects": [
            {
                "id": "obj_1",
                "owner_principal": "agent-a",
                "content_type": "text/plain",
                "wrapping_kid": "kek-1",
                "created_at": "2026-09-23T00:00:00Z",
                "value": SECRET,  # an unexpected field the handler must drop
            }
        ],
    }
    objs = sk.list_objects()
    assert len(objs) == 1
    assert objs[0].id == "obj_1"
    assert SECRET not in repr(objs)
    assert not hasattr(objs[0], "value")


def test_revoke_sends_only_a_jti(sidecar: FakeSidecar, sk: Safekeys):
    sidecar.handler = lambda req: {"ok": True}
    sk.revoke_token("jti_1")
    assert sidecar.requests[-1]["jti"] == "jti_1"


# ─── sidecar-is-the-transport ───────────────────────────────────────────────


def test_unreachable_sidecar_fails_closed():
    import tempfile

    short = Path(tempfile.mkdtemp(prefix="sfk-", dir="/tmp"))
    sk = Safekeys(socket_path=str(short / "nope.sock"), timeout=1.0)
    with pytest.raises(SafekeysUnavailable, match="fails closed"):
        sk.create_secret(source_file="/tmp/x")


def test_sdk_contains_no_cryptography():
    """The SDK must delegate all crypto; a local implementation would defeat
    the audit story and duplicate the sidecar's role."""
    import safekeys.client as client_mod
    import safekeys.tools as tools_mod

    forbidden = [
        "cryptography",
        "Crypto",
        "nacl",
        "hashlib",
        "hmac",
        "ssl",
    ]
    for mod in (client_mod, tools_mod):
        source = inspect.getsource(mod)
        for name in forbidden:
            assert f"import {name}" not in source, f"{mod.__name__} imports {name}"


def test_public_api_never_returns_a_plaintext_type():
    """Every public method's return annotation must be a token/path/status type."""
    allowed = {"CreatedSecret", "ResolveResult", "ObjectMetadata", "None", "list"}
    for name, member in inspect.getmembers(Safekeys, predicate=inspect.isfunction):
        if name.startswith("_"):
            continue
        ret = inspect.signature(member).return_annotation
        text = str(ret)
        assert any(a in text for a in allowed), f"{name} returns {text!r}"


# ─── langchain-tool-parity ──────────────────────────────────────────────────


def test_tool_specs_expose_no_value_parameter():
    from safekeys.tools import TOOL_SPECS

    for spec in TOOL_SPECS:
        props = set(spec.parameters.get("properties", {}).keys())
        for forbidden in ("value", "secret", "plaintext", "content", "password"):
            assert forbidden not in props, f"{spec.name} exposes a {forbidden!r} parameter"


def test_tool_specs_cover_both_operations():
    from safekeys.tools import TOOL_SPECS

    names = {s.name for s in TOOL_SPECS}
    assert names == {"create_secret", "resolve_for_tool"}


def test_plain_callables_wrap_the_same_sdk_calls(sidecar: FakeSidecar, sk: Safekeys):
    """The framework-agnostic wrappers must behave identically to the SDK."""
    from safekeys.tools import create_secret_tool, resolve_for_tool_tool

    sidecar.handler = lambda req: (
        {"ok": True, "created": {"object_id": "o", "folder": "f", "token": "safekey://v1/o#a.b.c"}}
        if req.get("op") == "create"
        else {"ok": True, "exit_code": 0, "stdout": b64("out")}
    )

    made = create_secret_tool(sk)(source_file="/tmp/x")
    assert made["token"].startswith("safekey://")
    assert SECRET not in str(made)

    ran = resolve_for_tool_tool(sk)("safekey://v1/o#a.b.c", ["true"])
    assert ran["exit_code"] == 0
    assert ran["stdout"] == "out"


def test_langchain_builder_errors_clearly_when_the_extra_is_missing(sk: Safekeys):
    """langchain-core is optional; the builder must say so rather than fail obscurely."""
    from safekeys.tools import build_langchain_tools

    try:
        import langchain_core  # noqa: F401
    except ImportError:
        with pytest.raises(ImportError, match="safekeys\\[langchain\\]"):
            build_langchain_tools(sk)
    else:  # pragma: no cover - only when the extra is installed
        tools = build_langchain_tools(sk)
        assert {t.name for t in tools} == {"create_secret", "resolve_for_tool"}
