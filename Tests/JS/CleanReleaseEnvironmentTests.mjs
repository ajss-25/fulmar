import assert from "node:assert/strict";
import { execFile, spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { rootWatchdogChildOptions } from "./RootWatchdogChildProcess.mjs";

const execFileAsync = promisify(execFile);

test("release authority strips loader, Node, PATH, proxy, CA, and unexpected environment injection", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-clean-release-env-"));
  const helper = join(process.cwd(), "scripts", "clean-release-environment.zsh");
  const wrapper = join(root, "wrapper.zsh");
  const captured = join(root, "captured.env");
  await writeFile(wrapper, `#!/bin/zsh
set -euo pipefail
helper="$1"
captured="$2"
source "$helper"
fulmar_require_clean_release_environment public "$0" "$@"
/usr/bin/env | /usr/bin/sort > "$captured"
`, { mode: 0o700 });
  try {
    const hostile = {
      ...process.env,
      PATH: `${root}:/usr/bin:/bin`,
      NODE_OPTIONS: "--require=/private/tmp/fulmar-hostile-loader.cjs",
      NODE_PATH: "/private/tmp/fulmar-hostile-modules",
      // A missing image can terminate the interpreter before this wrapper runs.
      // libSystem is already loaded, so this remains a nonempty safe scrub sentinel.
      DYLD_INSERT_LIBRARIES: "/usr/lib/libSystem.B.dylib",
      DYLD_LIBRARY_PATH: "/private/tmp/fulmar-hostile-libraries",
      HTTP_PROXY: "http://127.0.0.1:9",
      HTTPS_PROXY: "http://127.0.0.1:9",
      ALL_PROXY: "socks5://127.0.0.1:9",
      SSL_CERT_FILE: "/private/tmp/fulmar-hostile-ca.pem",
      SSL_CERT_DIR: "/private/tmp/fulmar-hostile-ca",
      CURL_CA_BUNDLE: "/private/tmp/fulmar-hostile-ca.pem",
      FULMAR_UNREVIEWED: "must disappear"
    };
    const result = spawnSync("/bin/zsh", ["-f", wrapper, helper, captured], rootWatchdogChildOptions({
      env: hostile, encoding: "utf8", timeout: 20_000
    }));
    assert.equal(result.status, 0, result.stderr || result.error?.message);
    const environment = await readFile(captured, "utf8");
    for (const name of ["NODE_OPTIONS", "NODE_PATH", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
      "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE",
      "FULMAR_UNREVIEWED"]) assert.doesNotMatch(environment, new RegExp(`^${name}=`, "mu"));
    assert.match(environment, /^PATH=\/usr\/bin:\/bin:\/usr\/sbin:\/sbin$/mu);
    assert.match(environment, /^TMPDIR=\/private\/tmp\/$/mu);
    assert.match(environment, /^FULMAR_CLEAN_RELEASE_MODE=public$/mu);
    const helperSource = await readFile(helper, "utf8");
    assert.doesNotMatch(helperSource, /grep -Ev[\s\S]*\|\| true/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("release and public authority scripts enter the clean environment before any pinned Node execution", async () => {
  const names = ["verify-release.sh", "prepare-public-release-assets.sh", "verify-public-distribution.sh"];
  for (const name of names) {
    const script = await readFile(join(process.cwd(), "scripts", name), "utf8");
    const clean = script.indexOf("fulmar_require_clean_release_environment");
    const node = script.indexOf("node-v22.23.1-darwin-arm64/bin/node");
    assert.ok(clean >= 0 && node > clean, `${name} must clean its environment before locating Node`);
    assert.doesNotMatch(script, /\brg\b/u);
  }
});

test("the transitive clean-release shell closure has no ambient ripgrep dependency", async () => {
  const scriptsRoot = join(process.cwd(), "scripts");
  const pending = [
    "build-app.sh",
    "clean-release-environment.zsh",
    "release-command-gate.zsh",
    "run-public-release.sh",
    "verify-release.sh",
    "prepare-public-release-assets.sh",
    "verify-public-distribution.sh"
  ];
  const visited = new Set();
  while (pending.length > 0) {
    const name = pending.shift();
    if (visited.has(name)) continue;
    visited.add(name);
    const script = await readFile(join(scriptsRoot, name), "utf8");
    assert.doesNotMatch(script, /\brg\s+-/u, `${name} cannot rely on Homebrew ripgrep`);
    for (const match of script.matchAll(/scripts\/([A-Za-z0-9._-]+\.(?:sh|zsh))/gu)) {
      if (!visited.has(match[1])) pending.push(match[1]);
    }
  }
  assert.ok(visited.size >= 29, "the release call-graph audit must cover the complete shell closure");
  await assert.rejects(
    execFileAsync("/usr/bin/env", ["-i", "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "/bin/zsh", "-f", "-c", "command -v rg"]),
    "the test host must demonstrate that ambient rg is absent from the clean release PATH"
  );
});
