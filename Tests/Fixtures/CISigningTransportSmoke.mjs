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
