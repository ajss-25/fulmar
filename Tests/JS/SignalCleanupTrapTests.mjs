import assert from "node:assert/strict";
import test from "node:test";
import { existsSync } from "node:fs";
import { chmod, link, mkdir, mkdtemp, readFile, rename, rm, stat, symlink, writeFile } from "node:fs/promises";
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";

const repositoryRoot = process.cwd();
const verifier = join(repositoryRoot, "scripts", "verify-signal-cleanup-traps.mjs");
const node = process.execPath;
const buildScratchHelper = join(repositoryRoot, "scripts", "build-scratch-root.zsh");

async function temporaryRepository(script) {
  const root = await mkdtemp(join(tmpdir(), "fulmar-signal-traps-"));
  await mkdir(join(root, "scripts"));
  await writeFile(join(root, "scripts", "probe.sh"), script, { mode: 0o644 });
  return root;
}

function runVerifier(root) {
  return spawnSync(node, [verifier, root], { encoding: "utf8" });
}

test("every repository shell signal trap preserves deterministic signal status", () => {
  const result = runVerifier(repositoryRoot);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /^SIGNAL_CLEANUP_TRAPS_OK files=\d+\n$/u);
});

test("combined EXIT and signal cleanup is rejected", async (t) => {
  const root = await temporaryRepository("#!/bin/zsh -f\ncleanup() { :; }\ntrap cleanup EXIT HUP INT TERM\n");
  t.after(() => rm(root, { recursive: true, force: true }));
  const result = runVerifier(root);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /EXIT cleanup and direct signals share one trap/u);
});

test("an inline combined trap cannot evade structural review", async (t) => {
  const root = await temporaryRepository("#!/bin/zsh -f\nprobe() { trap cleanup EXIT HUP INT TERM; }\n");
  t.after(() => rm(root, { recursive: true, force: true }));
  const result = runVerifier(root);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /inline trap is not structurally reviewable/u);
});

test("partial or status-swallowing signal handlers are rejected", async (t) => {
  const root = await temporaryRepository("#!/bin/zsh -f\ntrap 'cleanup' HUP\ntrap 'exit 130' INT\ntrap 'exit 143' TERM\n");
  t.after(() => rm(root, { recursive: true, force: true }));
  const result = runVerifier(root);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /HUP trap does not deterministically exit 129/u);
});

test("an on_signal shim that does not clean up and exit is rejected", async (t) => {
  const root = await temporaryRepository(`#!/bin/zsh -f
on_signal() {
  :
}
trap 'on_signal 129' HUP
trap 'on_signal 130' INT
trap 'on_signal 143' TERM
`);
  t.after(() => rm(root, { recursive: true, force: true }));
  const result = runVerifier(root);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /on_signal must disable all traps, attempt cleanup, and explicitly exit/u);
});

test("signal ignoring is rejected outside the exact sandbox adversarial fixtures", async (t) => {
  const root = await temporaryRepository("#!/bin/zsh -f\ntrap \"\" TERM INT HUP\n");
  t.after(() => rm(root, { recursive: true, force: true }));
  const result = runVerifier(root);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /signal-ignore trap is not an approved adversarial child fixture/u);
});

async function waitForFile(path) {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    if (existsSync(path)) return;
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 10));
  }
  throw new Error(`timed out waiting for ${path}`);
}

for (const [signal, expectedStatus] of [["SIGHUP", 129], ["SIGINT", 130], ["SIGTERM", 143]]) {
  test(`${signal} runs cleanup once and exits ${expectedStatus}`, async (t) => {
    const root = await mkdtemp(join(tmpdir(), "fulmar-signal-probe-"));
    const target = join(root, "private-root");
    const ready = join(root, "ready");
    const script = join(root, "probe.zsh");
    await writeFile(script, `#!/bin/zsh -f
set -u
target="$1"
ready="$2"
child=""
cleanup() {
  local exit_code="\${1:-$?}"
  if [[ "$child" == <-> ]] && /bin/kill -0 "$child" >/dev/null 2>&1; then
    /bin/kill -KILL "$child" >/dev/null 2>&1 || true
    wait "$child" >/dev/null 2>&1 || true
  fi
  /bin/rm -rf -- "$target"
  return "$exit_code"
}
on_signal() {
  local exit_code="$1"
  trap - EXIT HUP INT TERM
  cleanup "$exit_code" || true
  exit "$exit_code"
}
trap cleanup EXIT
trap 'on_signal 129' HUP
trap 'on_signal 130' INT
trap 'on_signal 143' TERM
/bin/mkdir -m 0700 "$target"
: > "$ready"
/bin/sleep 30 &
child="$!"
wait "$child"
`, { mode: 0o700 });
    await chmod(script, 0o700);
    const child = spawn("/bin/zsh", ["-f", script, target, ready], { stdio: "ignore" });
    t.after(async () => {
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
      await rm(root, { recursive: true, force: true });
    });
    await waitForFile(ready);
    assert.equal(child.kill(signal), true);
    const result = await new Promise((resolveClose) => child.once("close", (code, closedSignal) => resolveClose({ code, closedSignal })));
    assert.deepEqual(result, { code: expectedStatus, closedSignal: null });
    assert.equal(existsSync(target), false, "the private fixture root must be removed before signal exit");
  });
}

test("the verifier itself remains parseable source", async () => {
  const source = await readFile(verifier, "utf8");
  assert.match(source, /ALLOWED_ADVERSARIAL_IGNORES/u);
  const result = spawnSync(node, ["--check", verifier], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
});

async function buildScratchFixture(options = {}) {
  const namespaceNonce = randomBytes(16).toString("hex");
  const prefix = `fulmar-build-scratch-fixture.${namespaceNonce}.`;
  const root = await mkdtemp(`/private/tmp/${prefix}`);
  await chmod(root, 0o700);
  const metadata = await stat(root);
  const identity = `${metadata.dev}:${metadata.ino}:${metadata.uid}:Directory:700`;
  const marker = join(root, ".fulmar-build-scratch-owner-v1");
  const watchdogPid = options.watchdogPid ?? 999_998;
  const capabilityNonce = options.capabilityNonce ?? randomBytes(32).toString("hex");
  const capability = options.capabilityPath
    ?? `/private/tmp/fulmar-watchdog-capability.${watchdogPid}.${capabilityNonce}`;
  const ownerPid = options.ownerPid ?? 999_999;
  const ownerStarted = options.ownerStarted ?? "dead-fixture-owner";
  const createdEpoch = Math.floor(Date.now() / 1000) - (options.ageSeconds ?? 60);
  const recordedIdentity = options.recordedIdentity ?? identity;
  const contents = [
    "FULMAR_BUILD_SCRATCH_ROOT_V1",
    String(ownerPid),
    ownerStarted,
    recordedIdentity,
    String(createdEpoch),
    capability,
    capabilityNonce,
    String(watchdogPid)
  ].join("\n");
  if (!options.omitMarker) {
    await writeFile(marker, `${contents}\n`, { mode: 0o600 });
    await chmod(marker, 0o600);
  }
  if (options.activeCapability) {
    await writeFile(capability, "fixture\n", { mode: 0o600 });
    await chmod(capability, 0o600);
  }
  return { root, parent: "/private/tmp", prefix, identity, marker, capability, capabilityNonce, watchdogPid };
}

function recoverBuildScratch(fixture) {
  return spawnSync("/bin/zsh", [
    "-f", "-c",
    'source "$1"; fulmar_recover_stale_build_scratch_roots "$2" "$3"',
    "fulmar-build-scratch-test", buildScratchHelper, fixture.parent, fixture.prefix
  ], { encoding: "utf8" });
}

function attestBuildScratch(fixture, failurePhase = "") {
  const started = spawnSync("/bin/ps", ["-p", String(process.pid), "-o", "lstart="], { encoding: "utf8" }).stdout.replace(/\n+$/u, "");
  return spawnSync("/bin/zsh", [
    "-f", "-c",
    'source "$1"; fulmar_attest_new_build_scratch_root "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "${10}" "${11}" "${12}"',
    "fulmar-build-scratch-test", buildScratchHelper, fixture.root, fixture.parent, fixture.prefix,
    fixture.identity, String(process.pid), started, String(Math.floor(Date.now() / 1000)), fixture.capability,
    fixture.capabilityNonce, String(fixture.watchdogPid), failurePhase
  ], { encoding: "utf8" });
}

function cleanupCurrentBuildScratch(fixture) {
  return spawnSync("/bin/zsh", [
    "-f", "-c",
    'source "$1"; fulmar_remove_current_build_scratch_root "$2" "$3" "$4" "$5"',
    "fulmar-build-scratch-test", buildScratchHelper, fixture.root, fixture.parent, fixture.prefix, fixture.identity
  ], { encoding: "utf8" });
}

function attestWithExitCleanup(fixture, failurePhase) {
  const started = spawnSync("/bin/ps", ["-p", String(process.pid), "-o", "lstart="], { encoding: "utf8" }).stdout.replace(/\n+$/u, "");
  return spawnSync("/bin/zsh", [
    "-f", "-c",
    `source "$1"
fixture_root="$2"
fixture_parent="$3"
fixture_prefix="$4"
fixture_identity="$5"
cleanup_fixture() { fulmar_remove_current_build_scratch_root "$fixture_root" "$fixture_parent" "$fixture_prefix" "$fixture_identity"; }
trap cleanup_fixture EXIT
fulmar_attest_new_build_scratch_root "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "\${10}" "\${11}" "\${12}" >/dev/null
result_code=$?
exit "$result_code"`,
    "fulmar-build-scratch-test", buildScratchHelper, fixture.root, fixture.parent, fixture.prefix,
    fixture.identity, String(process.pid), started, String(Math.floor(Date.now() / 1000)), fixture.capability,
    fixture.capabilityNonce, String(fixture.watchdogPid), failurePhase
  ], { encoding: "utf8" });
}

async function removeBuildScratchFixture(fixture) {
  await rm(fixture.root, { recursive: true, force: true });
  await rm(fixture.capability, { force: true });
}

test("an attested dead build scratch root is recovered within the bounded age window", async (t) => {
  const fixture = await buildScratchFixture();
  t.after(() => removeBuildScratchFixture(fixture));
  const result = recoverBuildScratch(fixture);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Removed stale attested build scratch root/u);
  assert.equal(existsSync(fixture.root), false);
});

test("new-root attestation writes an exact PID/nonce-bound watchdog record", async (t) => {
  const fixture = await buildScratchFixture({ omitMarker: true });
  t.after(() => removeBuildScratchFixture(fixture));
  const result = attestBuildScratch(fixture);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), fixture.identity);
  const record = await readFile(fixture.marker, "utf8");
  assert.match(record, new RegExp(`\\n${fixture.capability.replaceAll(".", "\\.")}\\n${fixture.capabilityNonce}\\n${fixture.watchdogPid}\\n$`, "u"));
});

for (const [failurePhase, finalMarker, stagingMarker] of [
  ["before-marker", false, false],
  ["after-marker-create", false, true],
  ["after-durable-publication", true, false]
]) {
  test(`current-run cleanup removes only its exact inode after ${failurePhase} failure`, async (t) => {
    const fixture = await buildScratchFixture({ omitMarker: true });
    t.after(() => removeBuildScratchFixture(fixture));
    const result = attestBuildScratch(fixture, failurePhase);
    assert.equal(result.status, 125, result.stderr);
    assert.equal(existsSync(fixture.marker), finalMarker);
    assert.equal(existsSync(`${fixture.marker}.staging`), stagingMarker);
    const cleanup = cleanupCurrentBuildScratch(fixture);
    assert.equal(cleanup.status, 0, cleanup.stderr);
    assert.equal(existsSync(fixture.root), false);
  });

  test(`EXIT cleanup closes the real ${failurePhase} publication boundary`, async (t) => {
    const fixture = await buildScratchFixture({ omitMarker: true });
    t.after(() => removeBuildScratchFixture(fixture));
    const result = attestWithExitCleanup(fixture, failurePhase);
    assert.equal(result.status, 125, result.stderr);
    assert.equal(existsSync(fixture.root), false);
  });
}

test("a complete staged marker left by a hard kill remains recoverable", async (t) => {
  const fixture = await buildScratchFixture();
  t.after(() => removeBuildScratchFixture(fixture));
  await rename(fixture.marker, `${fixture.marker}.staging`);
  const result = recoverBuildScratch(fixture);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Removed stale attested build scratch root/u);
  assert.equal(existsSync(fixture.root), false);
});

test("an unmarked legacy build scratch root is retained for manual review", async (t) => {
  const fixture = await buildScratchFixture({ omitMarker: true });
  t.after(() => removeBuildScratchFixture(fixture));
  const result = recoverBuildScratch(fixture);
  assert.equal(result.status, 126);
  assert.match(result.stderr, /unattested legacy scratch root requiring manual review/u);
  assert.equal(existsSync(fixture.root), true);
});

test("a live exact owner prevents build scratch recovery", async (t) => {
  const started = spawnSync("/bin/ps", ["-p", String(process.pid), "-o", "lstart="], { encoding: "utf8" }).stdout.replace(/\n+$/u, "");
  assert.notEqual(started, "");
  const fixture = await buildScratchFixture({ ownerPid: process.pid, ownerStarted: started });
  t.after(() => removeBuildScratchFixture(fixture));
  const result = recoverBuildScratch(fixture);
  assert.equal(result.status, 75);
  assert.match(result.stderr, /live exact owner/u);
  assert.equal(existsSync(fixture.root), true);
});

test("an active watchdog capability prevents build scratch recovery", async (t) => {
  const fixture = await buildScratchFixture({ activeCapability: true });
  t.after(() => removeBuildScratchFixture(fixture));
  const result = recoverBuildScratch(fixture);
  assert.equal(result.status, 75);
  assert.match(result.stderr, /watchdog cleanup is still active/u);
  assert.equal(existsSync(fixture.root), true);
});

test("an inode identity mismatch fails closed without deleting the build root", async (t) => {
  const fixture = await buildScratchFixture({ recordedIdentity: "1:2:3:Directory:700" });
  t.after(() => removeBuildScratchFixture(fixture));
  const result = recoverBuildScratch(fixture);
  assert.equal(result.status, 126);
  assert.match(result.stderr, /malformed scratch-root attestation/u);
  assert.equal(existsSync(fixture.root), true);
});

test("a watchdog path not exactly bound to its PID and nonce is rejected", async (t) => {
  const fixture = await buildScratchFixture({
    capabilityPath: `/private/tmp/fulmar-watchdog-capability.999998.${"b".repeat(64)}`,
    capabilityNonce: "a".repeat(64),
    watchdogPid: 999_998
  });
  t.after(() => removeBuildScratchFixture(fixture));
  const result = recoverBuildScratch(fixture);
  assert.equal(result.status, 126);
  assert.match(result.stderr, /malformed scratch-root attestation/u);
  assert.equal(existsSync(fixture.root), true);
});

test("a too-young attested build scratch root is retained", async (t) => {
  const fixture = await buildScratchFixture({ ageSeconds: 2 });
  t.after(() => removeBuildScratchFixture(fixture));
  const result = recoverBuildScratch(fixture);
  assert.equal(result.status, 126);
  assert.match(result.stderr, /outside its 30-second to 30-day recovery window/u);
  assert.equal(existsSync(fixture.root), true);
});

test("an attested build scratch root older than the 30-day ceiling is retained", async (t) => {
  const fixture = await buildScratchFixture({ ageSeconds: 2_592_001 });
  t.after(() => removeBuildScratchFixture(fixture));
  const result = recoverBuildScratch(fixture);
  assert.equal(result.status, 126);
  assert.match(result.stderr, /outside its 30-second to 30-day recovery window/u);
  assert.equal(existsSync(fixture.root), true);
});

test("permissive build-root modes fail closed", async (t) => {
  const fixture = await buildScratchFixture();
  t.after(() => removeBuildScratchFixture(fixture));
  await chmod(fixture.root, 0o755);
  const result = recoverBuildScratch(fixture);
  assert.equal(result.status, 126);
  assert.match(result.stderr, /non-private scratch-root candidate/u);
  assert.equal(existsSync(fixture.root), true);
});

test("permissive marker modes fail closed", async (t) => {
  const fixture = await buildScratchFixture();
  t.after(() => removeBuildScratchFixture(fixture));
  await chmod(fixture.marker, 0o644);
  const result = recoverBuildScratch(fixture);
  assert.equal(result.status, 126);
  assert.match(result.stderr, /unattested legacy scratch root requiring manual review/u);
  assert.equal(existsSync(fixture.root), true);
});

test("linked marker topology fails closed without following the link", async (t) => {
  const fixture = await buildScratchFixture();
  const externalMarker = `${fixture.root}.external-marker`;
  t.after(async () => {
    await removeBuildScratchFixture(fixture);
    await rm(externalMarker, { force: true });
  });
  await writeFile(externalMarker, await readFile(fixture.marker), { mode: 0o600 });
  await rm(fixture.marker);
  await symlink(externalMarker, fixture.marker);
  const result = recoverBuildScratch(fixture);
  assert.equal(result.status, 126);
  assert.match(result.stderr, /unattested legacy scratch root requiring manual review/u);
  assert.equal(existsSync(fixture.root), true);
  assert.equal(existsSync(externalMarker), true, "the external link target must not be removed");
});

test("hard-linked marker topology fails closed", async (t) => {
  const fixture = await buildScratchFixture();
  const externalMarker = `${fixture.root}.hardlink`;
  t.after(async () => {
    await removeBuildScratchFixture(fixture);
    await rm(externalMarker, { force: true });
  });
  await link(fixture.marker, externalMarker);
  const result = recoverBuildScratch(fixture);
  assert.equal(result.status, 126);
  assert.match(result.stderr, /unattested legacy scratch root requiring manual review/u);
  assert.equal(existsSync(fixture.root), true);
  assert.equal(existsSync(externalMarker), true);
});

test("linked build-root topology fails closed without touching its target", async (t) => {
  const namespaceNonce = randomBytes(16).toString("hex");
  const prefix = `fulmar-build-scratch-fixture.${namespaceNonce}.`;
  const target = await mkdtemp("/private/tmp/fulmar-build-scratch-link-target.");
  const linkedRoot = `/private/tmp/${prefix}ABC123`;
  await chmod(target, 0o700);
  await symlink(target, linkedRoot);
  t.after(async () => {
    await rm(linkedRoot, { force: true });
    await rm(target, { recursive: true, force: true });
  });
  const result = recoverBuildScratch({ parent: "/private/tmp", prefix });
  assert.equal(result.status, 126);
  assert.match(result.stderr, /unsafe scratch-root candidate/u);
  assert.equal(existsSync(linkedRoot), true);
  assert.equal(existsSync(target), true);
});

test("recovery refuses a namespace with more than 32 candidate roots", async (t) => {
  const namespaceNonce = randomBytes(16).toString("hex");
  const prefix = `fulmar-build-scratch-fixture.${namespaceNonce}.`;
  const roots = [];
  t.after(async () => {
    for (const root of roots) await rm(root, { recursive: true, force: true });
  });
  for (let index = 0; index < 33; index += 1) {
    const root = await mkdtemp(`/private/tmp/${prefix}`);
    roots.push(root);
    await chmod(root, 0o700);
  }
  const result = recoverBuildScratch({ parent: "/private/tmp", prefix });
  assert.equal(result.status, 126);
  assert.match(result.stderr, /too many private scratch roots for bounded recovery/u);
  assert.equal(roots.every(existsSync), true);
});

test("current-run cleanup refuses a pathname replaced with a different inode", async (t) => {
  const fixture = await buildScratchFixture();
  const retained = `${fixture.root}.retained`;
  t.after(async () => {
    await removeBuildScratchFixture(fixture);
    await rm(retained, { recursive: true, force: true });
  });
  await rename(fixture.root, retained);
  await mkdir(fixture.root, { mode: 0o700 });
  await chmod(fixture.root, 0o700);
  await writeFile(fixture.marker, "replacement\n", { mode: 0o600 });
  await chmod(fixture.marker, 0o600);
  const result = cleanupCurrentBuildScratch(fixture);
  assert.equal(result.status, 126);
  assert.equal(existsSync(fixture.root), true, "the replacement inode must not be removed");
  assert.equal(existsSync(retained), true, "the original inode must not be followed after rename");
});

test("build-app binds cleanup and recovery to the exact attested scratch inode", async () => {
  const source = await readFile(join(repositoryRoot, "scripts", "build-app.sh"), "utf8");
  assert.match(source, /source "\$PROJECT_DIR\/scripts\/build-scratch-root\.zsh"/u);
  assert.match(source, /fulmar_recover_stale_build_scratch_roots[\s\S]*FULMAR_BUILD_SCRATCH_PRODUCTION_PREFIX/u);
  assert.match(source, /BUILD_SCRATCH_IDENTITY="\$\(fulmar_build_scratch_root_identity "\$BUILD_SCRATCH"\)"/u);
  assert.match(source, /PUBLISHED_BUILD_SCRATCH_IDENTITY="\$\(fulmar_attest_new_build_scratch_root/u);
  assert.match(source, /fulmar_remove_current_build_scratch_root[\s\S]*"\$BUILD_SCRATCH_IDENTITY"/u);
  const helper = await readFile(buildScratchHelper, "utf8");
  assert.match(helper, /fulmar-watchdog-capability\.\$watchdog_pid\.\$capability_nonce/u);
  assert.match(helper, /fulmar_build_scratch_root_identity "\$stale_root"\)" == "\$identity"/u);
  assert.match(helper, /fulmar_build_scratch_marker_metadata "\$marker"\)" == "\$marker_metadata"/u);
  assert.match(helper, /fulmar_fsync_build_scratch_file "\$staging"/u);
  assert.match(helper, /fulmar_fsync_build_scratch_directory "\$parent"/u);
  const syntax = spawnSync("/bin/zsh", ["-f", "-n", join(repositoryRoot, "scripts", "build-app.sh")], { encoding: "utf8" });
  assert.equal(syntax.status, 0, syntax.stderr);
});
