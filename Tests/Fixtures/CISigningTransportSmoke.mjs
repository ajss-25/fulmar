import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  rootWatchdogChildOptions,
  rootWatchdogLogicalArguments
} from "../JS/RootWatchdogChildProcess.mjs";

const fixtureProject = dirname(dirname(dirname(fileURLToPath(import.meta.url))));

export function assertCIWorkflowSigningTransport(project, workflow) {
  assert.equal(project, fixtureProject, "CI signing smoke must target the exact test checkout");
  assert.equal(
    workflow.includes("scripts/run-with-watchdog.sh")
      && workflow.includes("scripts/provision-ci-signing-keychain.sh"),
    true,
    "CI must execute the signing bootstrap through the reviewed watchdog and descriptor consumer"
  );
  assert.doesNotMatch(
    workflow,
    /\/usr\/bin\/security\s+(?:create-keychain|unlock-keychain)[^\n]*\s-p(?:\s|$)/u,
    "CI must never place its Keychain password in a security(1) argument"
  );
  assert.equal(
    workflow.includes("/bin/zsh -f scripts/create-local-signing-identity.sh)"),
    false,
    "CI must not bypass the private descriptor bootstrap with the legacy direct identity invocation"
  );
  const provision = workflow.slice(workflow.indexOf("- name: Provision one isolated unlocked CI Keychain"),
    workflow.indexOf("- name: Build the exact stable-signed candidate fixtures"));
  const provisioningOrder = [
    'require("node:os").userInfo().homedir',
    'ci_keychain="$account_home/Library/Keychains/fulmar-ci.keychain-db"',
    '/bin/zsh -f scripts/provision-ci-signing-keychain.sh "$ci_keychain"',
    'test "${#identity}" -eq 40',
    'echo "LOCAL_HARNESS_SIGNING_KEYCHAIN=$ci_keychain" >> "$GITHUB_ENV"'
  ];
  let preceding = -1;
  for (const step of provisioningOrder) {
    const position = provision.indexOf(step);
    assert.ok(position > preceding, `CI signing provision order must retain ${step}`);
    assert.equal(provision.indexOf(step, position + step.length), -1,
      "CI signing provision must not duplicate path assignment, provisioning, or export");
    preceding = position;
  }
  assert.doesNotMatch(workflow, /ci_keychain="\$RUNNER_TEMP\//u,
    "the isolated file-based Keychain must be reachable by the unchanged broker sandbox");
  const cleanup = workflow.slice(workflow.indexOf("- name: Remove the isolated CI Keychain"),
    workflow.indexOf("  minimum-macos-candidate:"));
  const cleanupStatements = cleanup.split("\n").map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"));
  assert.deepEqual(cleanupStatements, [
    "- name: Remove the isolated CI Keychain",
    "if: always()",
    "run: |",
    'ci_keychain="${LOCAL_HARNESS_SIGNING_KEYCHAIN:-}"',
    'if test -n "$ci_keychain"; then',
    'account_home="$("$PWD/VendorRuntime/node-v22.23.1-darwin-arm64/bin/node" \\',
    '-p \'require("node:os").userInfo().homedir\')"',
    'test "$ci_keychain" = "$account_home/Library/Keychains/fulmar-ci.keychain-db"',
    'test -f "$ci_keychain" && test ! -L "$ci_keychain"',
    'test "$(/usr/bin/stat -f \'%u:%l\' "$ci_keychain")" = "$(/usr/bin/id -u):1"',
    '/usr/bin/security delete-keychain "$ci_keychain"',
    "fi"
  ], "failure cleanup must delete only its successfully exported exact owned regular Keychain, after every guard");

  const secret = `fulmar-ci-smoke-${randomUUID()}`;
  const provisioner = join(project, "scripts", "provision-ci-signing-keychain.sh");
  const bypass = spawnSync("/bin/zsh", ["-f", provisioner, "--transport-smoke"], {
    cwd: project,
    encoding: "utf8",
    timeout: 5_000,
    env: { ...process.env, LOCAL_HARNESS_SIGNING_KEYCHAIN_PASSWORD: secret }
  });
  assert.equal(bypass.error, undefined, bypass.error?.message);
  assert.equal(bypass.status, 126);
  assert.match(bypass.stderr, /private watchdog descriptor|authenticated watchdog signing descriptor/u);
  assert.equal(`${bypass.stdout}${bypass.stderr}`.includes(secret), false);

  const logicalArguments = [
    "--seconds", "30",
    "--max-rss-bytes", String(1024 * 1024 * 1024),
    "--rss-grace-seconds", "2",
    "--emergency-rss-bytes", String(2 * 1024 * 1024 * 1024),
    "--label", "Fulmar CI signing transport smoke",
    "--", "/bin/zsh", "-f",
    provisioner,
    "--transport-smoke"
  ];
  const result = spawnSync(
    join(project, "scripts", "run-with-watchdog.sh"),
    rootWatchdogLogicalArguments(logicalArguments),
    rootWatchdogChildOptions({
      cwd: project,
      encoding: "utf8",
      timeout: 40_000,
      maxBuffer: 1024 * 1024,
      env: { ...process.env, LOCAL_HARNESS_SIGNING_KEYCHAIN_PASSWORD: secret }
    })
  );
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.signal, null);
  assert.equal(result.stdout, "FULMAR_CI_SIGNING_TRANSPORT_OK\n");
  assert.equal(`${result.stdout}${result.stderr}`.includes(secret), false);
}
