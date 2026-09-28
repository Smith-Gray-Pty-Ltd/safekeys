# @smithgray/safekeys-cli

The Safekeys CLI, installed as prebuilt per-platform binaries via npm's
optionalDependencies (the esbuild pattern). **No install scripts, no download
at install time** — npm places the binary package for your platform on disk,
and this package's `bin` launcher spawns it. **Early preview (0.1.0).**

    npm i -g @smithgray/safekeys-cli

Supported platforms: darwin/arm64, darwin/x64, linux/x64, linux/arm64,
win32/x64. An unsupported platform fails loudly — use the GitHub Release
binaries (checksums at the release), or the documented `curl | sh` fallback
which verifies a sha256 checksum.

Official packages are only under `@smithgray/` — see
[SECURITY.md](https://github.com/Smith-Gray-Pty-Ltd/safekeys/blob/main/SECURITY.md).
