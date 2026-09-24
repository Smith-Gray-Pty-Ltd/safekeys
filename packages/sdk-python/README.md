# Safekeys Python SDK

Token-only client for Safekeys. Encrypted secret transport for agents, built so
**plaintext never enters model context**.

```bash
pip install safekeys              # core: no dependencies
pip install 'safekeys[langchain]' # + LangChain/LangGraph tools
```

## Why the API looks like this

There is no function in this package that returns a secret value. That is not a
convention — it is the shape of the API:

- `create_secret` takes a **file path**, not a value. The sidecar reads the file
  itself, so an agent authoring the call never holds the bytes.
- `resolve_for_tool` takes a **token** and a command, and returns the *command's*
  output and exit status.
- The SDK contains **no cryptography**. Every resolution is delegated to the
  local sidecar over a Unix socket. If the sidecar is unreachable the call fails;
  there is no fallback.

## Usage

```python
from safekeys import Safekeys

sk = Safekeys()          # reads SAFEKEYS_SOCKET

# Create — the sidecar reads the file; you receive a token and a path.
secret = sk.create_secret(source_file="/tmp/api-key.txt", ttl_seconds=900)
print(secret.token)      # safekey://v1/obj_x#<JWS> — safe to pass anywhere
print(secret.folder)     # ciphertext folder

# Use — the command gets the value in its environment.
result = sk.resolve_for_tool(secret.token, ["gh", "api", "/user"])
print(result.exit_code, result.stdout)   # never the value

# Manage
for obj in sk.list_objects():
    print(obj.id, obj.owner)

sk.revoke_token(secret.jti)              # immediate, not at expiry
```

### LangChain / LangGraph

```python
from safekeys import Safekeys
from safekeys.tools import build_langchain_tools

tools = build_langchain_tools(Safekeys())
agent = create_react_agent(model, tools)
```

The tools wrap the same SDK functions, so a LangGraph agent and a direct caller
behave identically. Tool arguments carry tokens; tool outputs never carry values.

If `langchain-core` is not installed, import `TOOL_SPECS` instead — it is a
framework-neutral JSON-Schema description you can register with any runtime.

## Error handling

| Exception | Meaning |
|-----------|---------|
| `SafekeysUnavailable` | The sidecar could not be reached. Fails closed — there is no local fallback. |
| `SafekeysDenied` | The sidecar refused. The reason is deliberately not surfaced; check the sidecar's audit log. |

## Requirements

- A running Safekeys sidecar on the same host
- Python 3.10+
- **No network access** — the SDK only speaks to a local Unix socket

## Tests

```bash
pip install -e '.[dev]'
pytest -q
```

The suite includes a real Unix-socket fake sidecar, tests that the wire never
carries a value, that the SDK imports no cryptography, that every public method's
return type is value-free, and that the tool specs expose no value parameter.

## License

Apache-2.0 © Smith & Gray Pty Ltd
