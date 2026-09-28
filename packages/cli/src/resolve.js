// Resolution logic, exported for tests: pick the platform package name for a
// host. Unsupported platforms fail loudly — never a download fallback.
export const platformPkgs = {
  "darwin-arm64": "@smithgray/safekeys-cli-darwin-arm64",
  "darwin-x64": "@smithgray/safekeys-cli-darwin-x64",
  "linux-x64": "@smithgray/safekeys-cli-linux-x64",
  "linux-arm64": "@smithgray/safekeys-cli-linux-arm64",
  "win32-x64": "@smithgray/safekeys-cli-win32-x64",
};

export function platformPackage(platform, arch) {
  const key = `${platform}-${arch}`;
  const pkg = platformPkgs[key];
  if (!pkg) {
    const err = new Error(`no prebuilt Safekeys CLI for ${key}; use the GitHub Release binaries`);
    err.code = "ESDK_UNSUPPORTED_PLATFORM";
    throw err;
  }
  return pkg;
}
