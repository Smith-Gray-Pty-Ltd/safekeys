# @smithgray/safekeys-sdk

Token-only TypeScript SDK for Safekeys — encrypted secret transport for
agents, so plaintext never enters model context. **Early preview (0.1.0).**

```js
import { Safekeys } from "@smithgray/safekeys-sdk";

const sk = new Safekeys();

// Create: takes a PATH, never a value. The sidecar reads the file itself.
const secret = await sk.createSecret("/tmp/api-key.txt");
// secret.token — safekey://v1/...#<JWS>, contains zero secret material

// Use: the command receives the value in its environment; you receive its
// redacted, size-capped output and exit status.
const res = await sk.resolveForTool(secret.token, ["gh", "api", "/user"]);
```

The API accepts and returns only capability tokens and folder paths. It
performs no cryptography and holds no credentials: every resolution is
delegated to the local sidecar over a Unix socket. There is no method that
can return a resolved value.

Requires a running sidecar (`make dev` in the repository, or the deployed
sidecar). Official packages are listed in
[SECURITY.md](https://github.com/Smith-Gray-Pty-Ltd/safekeys/blob/main/SECURITY.md).
