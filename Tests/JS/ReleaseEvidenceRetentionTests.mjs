import assert from "node:assert/strict";
import {
  chmod, cp, link, lstat, mkdir, mkdtemp, open, opendir, readFile, readdir, rename,
  rm, rmdir, stat, symlink, unlink, utimes, writeFile
} from "node:fs/promises";
import { constants } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import test from "node:test";
import { isInsideAuthenticatedRootWatchdog } from "./RootWatchdogChildProcess.mjs";

const selfRootTest = isInsideAuthenticatedRootWatchdog ? test.skip : test;

const project = new URL("../..", import.meta.url).pathname.replace(/\/$/u, "");
const wrapperSource = join(project, "scripts", "retain-release-verification.sh");
const recorderSource = join(project, "scripts", "record-release-verification.mjs");
const retainedVerifierSource = join(project, "scripts", "verify-retained-release-evidence.mjs");
const attestedReaderSource = join(project, "scripts", "attested-regular-file.mjs");
const redactorSource = join(project, "scripts", "bounded-redacted-release-stream.mjs");
const watchdogLauncherSource = join(project, "scripts", "run-with-watchdog.sh");
const watchdogSource = join(project, "scripts", "run-with-watchdog.pl");
const processTreeWatchdogSource = join(project, "scripts", "run-process-tree-watchdog.mjs");
const watchdogRootSource = join(project, "scripts", "watchdog-root.zsh");
const rootLockSource = join(project, "scripts", "root-group-lock.zsh");
const inspectorSource = join(project, "scripts", "bounded-process-group-inspector.mjs");
const capabilityFDSource = join(project, "scripts", "attest-watchdog-capability-fd.pl");
const watchdogSampleSource = join(project, "scripts", "FulmarWatchdogSample.pm");
const watchdogCapabilityJanitorSource = join(project, "scripts", "FulmarWatchdogCapabilityJanitor.pm");
const nodeSource = join(project, "VendorRuntime", "node-v22.23.1-darwin-arm64", "bin", "node");
const digest = (value) => createHash("sha256").update(value).digest("hex");
const fixtureOwnerMarkerName = ".fulmar-release-evidence-owner-v1";
const fixtureOwnerMarkerPendingName = `${fixtureOwnerMarkerName}.pending`;
const productionFixtureParent = "/private/tmp";
const productionFixtureNamePattern = /^fulmar-release-evidence-test\.([A-Za-z0-9]{6})$/u;
const isolatedRecoveryParentPattern =
  /^\/private\/tmp\/fulmar-release-evidence-recovery-fixture\.[a-f0-9]{32}$/u;

function processBirthIdentity(pid) {
  assert.ok(Number.isSafeInteger(pid) && pid > 1, "fixture owner is not a safe PID");
  const result = spawnSync("/bin/ps", ["-p", String(pid), "-o", "lstart="], {
    encoding: "utf8",
    env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", LC_ALL: "C", LANG: "C" },
    timeout: 2_000,
    maxBuffer: 4_096,
    stdio: ["ignore", "pipe", "pipe"]
  });
  if (result.error) {
    throw new Error(`fixture owner birth inspection failed: ${result.error.message}`);
  }
  if (result.status === 1 && result.signal === null
      && result.stdout.trim().length === 0 && result.stderr.trim().length === 0) {
    return null;
  }
  assert.equal(result.status, 0, `fixture owner birth inspection failed: ${result.stderr.trim()}`);
  assert.equal(result.signal, null, "fixture owner birth inspection was signalled");
  const lines = result.stdout.split("\n").map((line) => line.trim()).filter(Boolean);
  assert.equal(lines.length, 1, "fixture owner birth inspection was ambiguous");
  assert.match(lines[0], /^[\x20-\x7e]{8,128}$/u, "fixture owner birth identity was unsafe");
  return lines[0];
}

const fixtureProcessStarted = processBirthIdentity(process.pid);

function exactFixtureRoot(root, parent = productionFixtureParent) {
  assert.ok(parent === productionFixtureParent || isolatedRecoveryParentPattern.test(parent),
    "release-evidence recovery parent is outside its reviewed namespaces");
  const prefix = `${parent}/`;
  assert.equal(root.startsWith(prefix), true, "release-evidence fixture escaped its exact parent");
  const name = root.slice(prefix.length);
  const match = productionFixtureNamePattern.exec(name);
  assert.ok(match && !name.includes("/"), "release-evidence fixture has an unsafe name");
  return Object.freeze({ name, nonce: match[1] });
}

function markerBytes(ownerPID, ownerStarted, createdAtMs, nonce, identity) {
  assert.ok(Number.isSafeInteger(createdAtMs) && createdAtMs > 0,
    "fixture marker creation time is unsafe");
  const encodedStarted = Buffer.from(ownerStarted, "utf8").toString("base64");
  return Buffer.from([
    "FULMAR_RELEASE_EVIDENCE_TEST_OWNER_V1",
    String(ownerPID),
    encodedStarted,
    String(createdAtMs),
    nonce,
    String(identity.dev),
    String(identity.ino),
    String(identity.uid),
    String(identity.mode),
    ""
  ].join("\n"));
}

async function publishFixtureOwnerMarker(root, capturedRoot, options = {}) {
  const ownerPID = options.ownerPID ?? process.pid;
  const ownerStarted = options.ownerStarted ?? fixtureProcessStarted;
  const createdAtMs = options.createdAtMs ?? Date.now();
  const marker = join(root, fixtureOwnerMarkerName);
  const pending = join(root, fixtureOwnerMarkerPendingName);
  assert.equal(processBirthIdentity(ownerPID), ownerStarted,
    "fixture owner identity changed before marker publication");
  const bytes = markerBytes(ownerPID, ownerStarted, createdAtMs,
    capturedRoot.nonce, capturedRoot.identity);
  await writeFile(pending, bytes, { flag: "wx", mode: 0o600 });
  const pendingHandle = await open(pending, constants.O_RDONLY | constants.O_NOFOLLOW);
  try { await pendingHandle.sync(); } finally { await pendingHandle.close(); }
  await rename(pending, marker);
  const rootHandle = await open(root, constants.O_RDONLY | constants.O_NOFOLLOW);
  try { await rootHandle.sync(); } finally { await rootHandle.close(); }
  return attestFixtureOwnerMarker(marker, root, capturedRoot.identity);
}

async function captureReleaseEvidenceFixtureRoot(root, parent = productionFixtureParent) {
  const fixtureIdentity = exactFixtureRoot(root, parent);
  const details = await lstat(root);
  assert.equal(details.isDirectory(), true, "release-evidence fixture root must be a directory");
  assert.equal(details.isSymbolicLink(), false, "release-evidence fixture root must not be linked");
  assert.equal(details.uid, process.getuid(), "release-evidence fixture root must be test-user-owned");
  assert.equal(details.mode & 0o777, 0o700, "release-evidence fixture root must be owner-private");
  return Object.freeze({
    nonce: fixtureIdentity.nonce,
    identity: Object.freeze({
      dev: details.dev, ino: details.ino, uid: details.uid, mode: details.mode & 0o777
    })
  });
}

async function fixture(exitCode = 0, verifierBody = undefined, options = {}) {
  const root = await mkdtemp("/private/tmp/fulmar-release-evidence-test.");
  let capture;
  let value;
  try {
    capture = options.capture;
    if (capture) capture.root = root;
    const capturedRoot = await captureReleaseEvidenceFixtureRoot(root);
    const setupState = { capability: undefined, rootMarker: undefined };
    const lock = `/private/tmp/FulmarEvidenceTest-${capturedRoot.nonce}.lock`;
    const app = join(root, "project");
    const verifier = join(root, "fixture-verifier.zsh");
    value = Object.freeze({
      root, app, verifier, lock, rootIdentity: capturedRoot.identity, setupState,
      capture
    });
    setupState.rootMarker = await publishFixtureOwnerMarker(root, capturedRoot);
    if (capture) Object.assign(capture, { lock, value });
    if (options.failurePoint === "root-only") throw options.injectedFailure;
    if (options.failurePoint === "retained-capability") {
      await createSyntheticRetainedFixtureState(value, {
        failAfterCapability: true,
        injectedFailure: options.injectedFailure
      });
    }
    if (options.failurePoint === "retained-root") {
      const capability = await createSyntheticRetainedFixtureState(value);
      if (capture) capture.capability = capability;
      throw options.injectedFailure;
    }
    await mkdir(join(app, "scripts"), { recursive: true });
    await mkdir(join(app, "Config"));
    await mkdir(join(app, "build"), { mode: 0o700 });
    await mkdir(join(app, "VendorRuntime", "node-v22.23.1-darwin-arm64", "bin"), { recursive: true });
    await cp(wrapperSource, join(app, "scripts", "retain-release-verification.sh"));
    await cp(recorderSource, join(app, "scripts", "record-release-verification.mjs"));
    await cp(retainedVerifierSource, join(app, "scripts", "verify-retained-release-evidence.mjs"));
    await cp(attestedReaderSource, join(app, "scripts", "attested-regular-file.mjs"));
    await cp(redactorSource, join(app, "scripts", "bounded-redacted-release-stream.mjs"));
    await cp(watchdogLauncherSource, join(app, "scripts", "run-with-watchdog.sh"));
    await cp(watchdogSource, join(app, "scripts", "run-with-watchdog.pl"));
    await cp(processTreeWatchdogSource, join(app, "scripts", "run-process-tree-watchdog.mjs"));
    await cp(watchdogRootSource, join(app, "scripts", "watchdog-root.zsh"));
    await cp(rootLockSource, join(app, "scripts", "root-group-lock.zsh"));
    await cp(inspectorSource, join(app, "scripts", "bounded-process-group-inspector.mjs"));
    await cp(capabilityFDSource, join(app, "scripts", "attest-watchdog-capability-fd.pl"));
    await cp(watchdogSampleSource, join(app, "scripts", "FulmarWatchdogSample.pm"));
    await cp(watchdogCapabilityJanitorSource,
      join(app, "scripts", "FulmarWatchdogCapabilityJanitor.pm"));
    await cp(nodeSource, join(app, "VendorRuntime", "node-v22.23.1-darwin-arm64", "bin", "node"));
    const identity = { productDisplayName: "Fulmar", appVersion: "9.8.7", appBuild: 987, releaseArchiveName: "Fulmar.app.zip" };
    const archive = Buffer.from("candidate archive");
    await writeFile(join(app, "Config", "ReleaseIdentity.json"), JSON.stringify(identity));
    await writeFile(join(app, "build", "Fulmar.app.zip"), archive, { mode: 0o600 });
    const staticSecurityBytes = Buffer.from(`${JSON.stringify({
      schemaVersion: 1, passed: true, unreviewedFindingCount: 0
    })}\n`);
    const sourceInputBytes = Buffer.from(`${JSON.stringify({
      schemaVersion: 1, rootLabel: "LocalHarnessBuildInputs"
    })}\n`);
    await writeFile(join(app, "build", "static-security-summary.json"), staticSecurityBytes, { mode: 0o600 });
    await writeFile(join(app, "build", "source-build-inputs.json"), sourceInputBytes, { mode: 0o600 });
    const descriptor = (file, bytes) => ({ file, bytes: bytes.length, sha256: digest(bytes) });
    const manifest = {
      schemaVersion: 6,
      version: identity.appVersion, build: identity.appBuild, archive: identity.releaseArchiveName,
      archiveBytes: archive.length, sha256: digest(archive),
      inventories: {
        staticSecurity: descriptor("static-security-summary.json", staticSecurityBytes),
        buildInputs: descriptor("source-build-inputs.json", sourceInputBytes)
      }
    };
    const manifestBytes = Buffer.from(JSON.stringify(manifest));
    await writeFile(join(app, "build", "release-manifest.json"), manifestBytes);
    const summary = {
      schemaVersion: 1,
      evidenceType: "fulmar-candidate-qualification",
      profile: "full-hardware",
      product: identity.productDisplayName,
      version: identity.appVersion,
      build: identity.appBuild,
      candidate: { archive: manifest.archive, bytes: manifest.archiveBytes, sha256: manifest.sha256 },
      evidence: {
        releaseManifest: { sha256: digest(manifestBytes) },
        inventories: { staticSecurity: manifest.inventories.staticSecurity }
      },
      gates: { deterministicCandidate: "passed", physicalQwenHardware: "passed" },
      finalPublicReleaseQualified: false
    };
    await writeFile(join(app, "build", "fixture-ci-summary.json"), `${JSON.stringify(summary)}\n`);
    await writeFile(verifier, verifierBody ?? `#!/bin/zsh
/bin/cp "$PWD/build/fixture-ci-summary.json" "\${2:-$PWD/build/ci-evidence-summary.json}"
print 'Release manifest verified for 9.8.7 (987), ${archive.length} bytes, ${digest(archive)}.'
print 'fixture transcript'
print -u2 'fixture stderr'
print 'Release verification passed against the extracted archive: fixture.'
exit ${exitCode}
`, { mode: 0o700 });
    await chmod(verifier, 0o700);
    await chmod(join(app, "scripts", "run-with-watchdog.sh"), 0o700);
    await chmod(join(app, "scripts", "run-with-watchdog.pl"), 0o600);
    return value;
  } catch (error) {
    let cleanupError;
    try {
      if (!value) {
        const capturedRoot = await captureReleaseEvidenceFixtureRoot(root);
        const setupState = { capability: undefined, rootMarker: undefined };
        value = Object.freeze({
          root,
          app: join(root, "project"),
          verifier: join(root, "fixture-verifier.zsh"),
          lock: `/private/tmp/FulmarEvidenceTest-${capturedRoot.nonce}.lock`,
          rootIdentity: capturedRoot.identity,
          setupState,
          capture
        });
      }
      await cleanupFixture(value);
      if (options.injectedCleanupFailure) throw options.injectedCleanupFailure;
    } catch (cleanupFailure) {
      cleanupError = cleanupFailure;
    }
    if (cleanupError) {
      throw new AggregateError(
        [error, cleanupError],
        "fixture setup and its attested cleanup both failed",
        { cause: error }
      );
    }
    throw error;
  }
}

async function createSyntheticRetainedFixtureState(value, options = {}) {
  const rootPID = 99_000_001;
  const processGroup = 99_000_002;
  const nonce = digest(`fixture-construction-cleanup:${value.root}`);
  const capability = `/private/tmp/fulmar-watchdog-capability.${rootPID}.${nonce}`;
  await mkdir(value.lock, { mode: 0o700 });
  await writeFile(
    capability,
    `${rootPID}\n${processGroup}\n${nonce}\n`,
    { flag: "wx", mode: 0o600 }
  );
  value.setupState.capability = capability;
  if (value.capture) value.capture.capability = capability;
  if (options.failAfterCapability) throw options.injectedFailure;
  await writeFile(
    join(value.lock, "owner.pid"),
    `${rootPID}\n${processGroup}\n${capability}\n${nonce}\n`,
    { flag: "wx", mode: 0o600 }
  );
  return capability;
}

async function readAttestedPrivateFile(path) {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat();
    assert.equal(before.isFile(), true, `${path} must be a regular file`);
    assert.equal(before.nlink, 1, `${path} must not be hard linked`);
    assert.equal(before.uid, process.getuid(), `${path} must remain owned by the test user`);
    assert.equal(before.mode & 0o777, 0o600, `${path} must remain owner-private`);
    assert.ok(before.size >= 1 && before.size <= 1024, `${path} has an unsafe size`);
    const bytes = await handle.readFile();
    const after = await handle.stat();
    assert.deepEqual(
      [
        after.dev, after.ino, after.uid, after.mode & 0o777, after.nlink, after.size,
        after.mtimeMs, after.ctimeMs, after.birthtimeMs
      ],
      [
        before.dev, before.ino, before.uid, before.mode & 0o777, before.nlink, before.size,
        before.mtimeMs, before.ctimeMs, before.birthtimeMs
      ],
      `${path} changed while it was read`
    );
    assert.equal(bytes.length, before.size, `${path} was truncated while it was read`);
    return Object.freeze({
      bytes,
      identity: Object.freeze({
        dev: before.dev,
        ino: before.ino,
        uid: before.uid,
        mode: before.mode & 0o777,
        nlink: before.nlink,
        size: before.size,
        mtimeMs: before.mtimeMs,
        ctimeMs: before.ctimeMs,
        birthtimeMs: before.birthtimeMs
      })
    });
  } finally { await handle.close(); }
}

async function unlinkAttestedPrivateFile(path, attestation, label) {
  const current = await lstat(path);
  assert.equal(current.isFile(), true, `${label} changed type before removal`);
  assert.equal(current.isSymbolicLink(), false, `${label} became a symbolic link before removal`);
  assert.deepEqual(
    [
      current.dev, current.ino, current.uid, current.mode & 0o777, current.nlink, current.size,
      current.mtimeMs, current.ctimeMs, current.birthtimeMs
    ],
    [
      attestation.dev,
      attestation.ino,
      attestation.uid,
      attestation.mode,
      attestation.nlink,
      attestation.size,
      attestation.mtimeMs,
      attestation.ctimeMs,
      attestation.birthtimeMs
    ],
    `${label} identity changed before removal`
  );
  await unlink(path);
  await assert.rejects(lstat(path), { code: "ENOENT" });
}

function assertSamePrivateFileIdentity(current, expected, label) {
  assert.deepEqual(
    [
      current.dev, current.ino, current.uid, current.mode & 0o777, current.nlink,
      current.size, current.mtimeMs, current.ctimeMs, current.birthtimeMs
    ],
    [
      expected.dev, expected.ino, expected.uid, expected.mode, expected.nlink,
      expected.size, expected.mtimeMs, expected.ctimeMs, expected.birthtimeMs
    ],
    `${label} identity changed`
  );
}

function parseFixtureOwnerMarker(record, root, rootIdentity, parent = productionFixtureParent) {
  const rootName = exactFixtureRoot(root, parent).name;
  const payload = /^FULMAR_RELEASE_EVIDENCE_TEST_OWNER_V1\n([1-9][0-9]{0,9})\n([A-Za-z0-9+/]+={0,2})\n([0-9]{10,16})\n([A-Za-z0-9]{6})\n([0-9]+)\n([0-9]+)\n([0-9]+)\n([0-9]+)\n$/u.exec(
    record.bytes.toString("utf8")
  );
  assert.ok(payload, "release-evidence fixture owner marker has an unknown schema");
  const ownerPID = Number(payload[1]);
  const ownerStartedBytes = Buffer.from(payload[2], "base64");
  const ownerStarted = ownerStartedBytes.toString("utf8");
  assert.equal(ownerStartedBytes.toString("base64"), payload[2],
    "fixture owner birth identity is not canonical base64");
  assert.match(ownerStarted, /^[\x20-\x7e]{8,128}$/u,
    "fixture owner birth identity was unsafe");
  const createdAtMs = Number(payload[3]);
  const parsedIdentity = {
    dev: Number(payload[5]), ino: Number(payload[6]), uid: Number(payload[7]), mode: Number(payload[8])
  };
  assert.ok(Number.isSafeInteger(ownerPID) && ownerPID > 1, "fixture owner PID is unsafe");
  assert.ok(Number.isSafeInteger(createdAtMs) && createdAtMs > 0,
    "fixture owner creation time is unsafe");
  for (const [key, value] of Object.entries(parsedIdentity)) {
    assert.ok(Number.isSafeInteger(value) && value >= 0, `fixture root ${key} is unsafe`);
  }
  assert.equal(rootName, `fulmar-release-evidence-test.${payload[4]}`,
    "fixture owner marker nonce differs from its root");
  assert.deepEqual(parsedIdentity, rootIdentity,
    "fixture owner marker differs from the exact root inode");
  assert.ok(Math.abs(record.identity.mtimeMs - createdAtMs) <= 10_000,
    "fixture owner marker time differs from its attested creation time");
  assert.ok(record.identity.birthtimeMs > 0
      && Math.abs(record.identity.birthtimeMs - createdAtMs) <= 10_000,
    "fixture owner marker birth time differs from its attested creation time");
  return Object.freeze({ ownerPID, ownerStarted, createdAtMs });
}

async function attestFixtureOwnerMarker(
  marker, root, rootIdentity, expectedIdentity = undefined, parent = productionFixtureParent
) {
  const record = await readAttestedPrivateFile(marker);
  if (expectedIdentity) {
    assertSamePrivateFileIdentity(record.identity, expectedIdentity, "fixture owner marker");
  }
  return Object.freeze({
    ...record,
    owner: parseFixtureOwnerMarker(record, root, rootIdentity, parent)
  });
}

async function attestFixtureRootForCleanup(value) {
  exactFixtureRoot(value.root, value.recoveryParent ?? productionFixtureParent);
  const rootDetails = await lstat(value.root);
  assert.equal(rootDetails.isDirectory(), true, "fixture root must remain a directory");
  assert.equal(rootDetails.isSymbolicLink(), false, "fixture root must not become linked");
  assert.deepEqual(
    [rootDetails.dev, rootDetails.ino, rootDetails.uid, rootDetails.mode & 0o777],
    [value.rootIdentity.dev, value.rootIdentity.ino, value.rootIdentity.uid, value.rootIdentity.mode],
    "fixture recovery root identity changed before unit removal"
  );
  if (value.setupState.rootMarker) {
    await attestFixtureOwnerMarker(
      value.setupState.rootMarkerPath ?? join(value.root, fixtureOwnerMarkerName),
      value.root,
      value.rootIdentity,
      value.setupState.rootMarker.identity,
      value.recoveryParent ?? productionFixtureParent
    );
  }
}

async function attestRecoveryParent(parent) {
  const details = await lstat(parent);
  assert.equal(details.isDirectory(), true, "release-evidence recovery parent must be a directory");
  assert.equal(details.isSymbolicLink(), false, "release-evidence recovery parent must not be linked");
  if (parent === productionFixtureParent) {
    assert.equal(details.uid, 0, "/private/tmp must remain root-owned");
    assert.equal(details.mode & 0o7777, 0o1777, "/private/tmp must remain sticky and public");
  } else {
    assert.match(parent, isolatedRecoveryParentPattern);
    assert.equal(details.uid, process.getuid(), "isolated recovery parent must be test-user-owned");
    assert.equal(details.mode & 0o777, 0o700, "isolated recovery parent must be owner-private");
  }
  return Object.freeze({ dev: details.dev, ino: details.ino, uid: details.uid,
    mode: details.mode & 0o7777 });
}

async function boundedFixtureRootNames(parent, maximumEntries, maximumRoots) {
  const names = [];
  let entries = 0;
  const directory = await opendir(parent);
  for await (const entry of directory) {
    entries += 1;
    assert.ok(entries <= maximumEntries, "release-evidence recovery entry bound was exceeded");
    if (productionFixtureNamePattern.test(entry.name)) names.push(entry.name);
    assert.ok(names.length <= maximumRoots, "release-evidence recovery root bound was exceeded");
  }
  return names.sort();
}

async function recoverStaleReleaseEvidenceFixtures(options = {}) {
  const parent = options.parent ?? productionFixtureParent;
  const maximumEntries = options.maximumEntries ?? 4_096;
  const maximumRoots = options.maximumRoots ?? 64;
  const minimumAgeMs = options.minimumAgeMs ?? 60_000;
  const maximumAgeMs = options.maximumAgeMs ?? 30 * 24 * 60 * 60 * 1_000;
  const nowMs = options.nowMs ?? Date.now();
  assert.ok(Number.isSafeInteger(maximumEntries) && maximumEntries >= 1 && maximumEntries <= 16_384,
    "release-evidence recovery entry bound is unsafe");
  assert.ok(Number.isSafeInteger(maximumRoots) && maximumRoots >= 1 && maximumRoots <= 256,
    "release-evidence recovery root bound is unsafe");
  assert.ok(Number.isSafeInteger(minimumAgeMs) && minimumAgeMs >= 0,
    "release-evidence recovery minimum age is unsafe");
  assert.ok(Number.isSafeInteger(maximumAgeMs) && maximumAgeMs > minimumAgeMs,
    "release-evidence recovery maximum age is unsafe");
  assert.ok(Number.isSafeInteger(nowMs) && nowMs > 0, "release-evidence recovery clock is unsafe");
  const parentIdentity = await attestRecoveryParent(parent);
  const names = await boundedFixtureRootNames(parent, maximumEntries, maximumRoots);
  const afterScan = await attestRecoveryParent(parent);
  assert.deepEqual(afterScan, parentIdentity, "release-evidence recovery parent identity changed");
  const result = { removed: [], live: [], young: [], legacy: [] };
  for (const name of names) {
    const root = join(parent, name);
    const rootCapture = await captureReleaseEvidenceFixtureRoot(root, parent);
    const marker = join(root, fixtureOwnerMarkerName);
    const pendingMarker = join(root, fixtureOwnerMarkerPendingName);
    let markerRecord;
    try {
      let markerPath = marker;
      try {
        await lstat(marker);
        await assert.rejects(lstat(pendingMarker), { code: "ENOENT" });
      } catch (error) {
        if (error?.code !== "ENOENT") throw error;
        markerPath = pendingMarker;
      }
      markerRecord = await attestFixtureOwnerMarker(
        markerPath, root, rootCapture.identity, undefined, parent
      );
      markerRecord = Object.freeze({ ...markerRecord, path: markerPath });
    } catch (error) {
      if (error?.code === "ENOENT") {
        result.legacy.push(root);
        continue;
      }
      throw error;
    }
    const ageMs = nowMs - markerRecord.owner.createdAtMs;
    assert.ok(ageMs >= -5_000, "release-evidence fixture marker is unreasonably future-dated");
    if (ageMs < minimumAgeMs) {
      result.young.push(root);
      continue;
    }
    assert.ok(ageMs <= maximumAgeMs, "release-evidence fixture marker exceeded its recovery age bound");
    const observedBirth = processBirthIdentity(markerRecord.owner.ownerPID);
    if (observedBirth === markerRecord.owner.ownerStarted) {
      result.live.push(root);
      continue;
    }
    if (options.beforeCleanup) await options.beforeCleanup(root);
    const finalBirth = processBirthIdentity(markerRecord.owner.ownerPID);
    if (finalBirth === markerRecord.owner.ownerStarted) {
      result.live.push(root);
      continue;
    }
    const setupState = {
      capability: undefined,
      rootMarker: markerRecord,
      rootMarkerPath: markerRecord.path
    };
    await cleanupFixture(Object.freeze({
      root,
      lock: `/private/tmp/FulmarEvidenceTest-${rootCapture.nonce}.lock`,
      rootIdentity: rootCapture.identity,
      recoveryParent: parent,
      setupState
    }));
    result.removed.push(root);
  }
  return Object.freeze(Object.fromEntries(
    Object.entries(result).map(([key, paths]) => [key, Object.freeze(paths)])
  ));
}

function assertDeadPID(pid, label) {
  assert.ok(Number.isSafeInteger(pid) && pid > 1, `${label} is not a safe PID`);
  try { process.kill(pid, 0); } catch (error) {
    assert.equal(error?.code, "ESRCH", `${label} could not be proven dead`);
    return;
  }
  assert.fail(`${label} is still live`);
}

function assertEmptyProcessGroup(pgid) {
  assert.ok(Number.isSafeInteger(pgid) && pgid > 1, "retained lock has an unsafe process group");
  try { process.kill(-pgid, 0); } catch (error) {
    assert.equal(error?.code, "ESRCH", "retained process group could not be proven empty");
    return;
  }
  assert.fail("retained process group is still live");
}

async function attestRetainedCapability(path) {
  const pathMatch = /^\/private\/tmp\/fulmar-watchdog-capability\.([0-9]+)\.([a-f0-9]{64})$/u.exec(path);
  assert.ok(pathMatch, "retained fixture capability has an unsafe path");
  const record = await readAttestedPrivateFile(path);
  const payload = /^([0-9]+)\n([0-9]+)\n([a-f0-9]{64})\n$/u.exec(record.bytes.toString("utf8"));
  assert.ok(payload, "retained fixture capability has an unknown schema");
  const rootPID = Number(payload[1]);
  const processGroup = Number(payload[2]);
  const nonce = payload[3];
  assert.equal(rootPID, Number(pathMatch[1]), "retained capability PID differs from its path");
  assert.equal(nonce, pathMatch[2], "retained capability nonce differs from its path");
  assertDeadPID(rootPID, "retained watchdog root");
  assertEmptyProcessGroup(processGroup);
  return Object.freeze({ ...record, rootPID, processGroup, nonce });
}

async function assertExclusiveCapabilityReference(capability, expectedLock) {
  const privateTmpIdentity = await attestRecoveryParent(productionFixtureParent);
  const references = [];
  let entryCount = 0;
  let lockCount = 0;
  const directory = await opendir(productionFixtureParent);
  for await (const entry of directory) {
    entryCount += 1;
    assert.ok(entryCount <= 4_096, "capability reference scan entry bound was exceeded");
    if (!/^[A-Za-z0-9._-]{1,200}\.lock$/u.test(entry.name)) continue;
    const lockPath = join(productionFixtureParent, entry.name);
    let lockDetails;
    try { lockDetails = await lstat(lockPath); } catch (error) {
      if (error?.code === "ENOENT") continue;
      throw error;
    }
    if (!lockDetails.isDirectory() || lockDetails.isSymbolicLink()
        || lockDetails.uid !== process.getuid() || (lockDetails.mode & 0o777) !== 0o700) continue;
    // Regular .lock files cannot reference a watchdog capability. They remain
    // covered by the entry bound, not the separate eligible-directory bound.
    lockCount += 1;
    assert.ok(lockCount <= 256, "capability reference scan lock bound was exceeded");
    let entries;
    try { entries = (await readdir(lockPath)).sort(); } catch (error) {
      if (error?.code === "ENOENT") continue;
      throw error;
    }
    if (entries.length !== 1 || entries[0] !== "owner.pid" || lockDetails.nlink !== 3) continue;
    let owner;
    try { owner = await readAttestedPrivateFile(join(lockPath, "owner.pid")); } catch (error) {
      if (["EACCES", "ELOOP", "ENOENT", "ENOTDIR"].includes(error?.code)
          || error?.code === "ERR_ASSERTION") continue;
      throw error;
    }
    const ordinary = /^([0-9]+)\n([0-9]+)\n(\/private\/tmp\/fulmar-watchdog-capability\.[0-9]+\.[a-f0-9]{64})\n([a-f0-9]{64})\n$/u.exec(
      owner.bytes.toString("utf8")
    );
    if (ordinary?.[3] === capability) references.push(lockPath);
  }
  assert.deepEqual(await attestRecoveryParent(productionFixtureParent), privateTmpIdentity,
    "capability reference scan parent identity changed");
  assert.deepEqual(references.sort(), [expectedLock],
    "retained capability did not have one exclusive exact lock reference");
}

async function cleanupFixture(value) {
  await attestFixtureRootForCleanup(value);
  let lockDetails;
  try { lockDetails = await lstat(value.lock); } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  if (lockDetails) {
    assert.equal(lockDetails.isDirectory(), true, "fixture lock must be a directory");
    assert.equal(lockDetails.isSymbolicLink(), false, "fixture lock must not be linked");
    assert.equal(lockDetails.uid, process.getuid(), "fixture lock must remain test-user-owned");
    assert.equal(lockDetails.mode & 0o777, 0o700, "fixture lock must remain owner-private");
    const entries = (await readdir(value.lock)).sort();
    assert.ok(entries.length === 0 || (entries.length === 1 && entries[0] === "owner.pid"),
      "fixture lock contains an unreviewed entry");
    assert.equal(lockDetails.nlink, entries.length + 2,
      "fixture lock link count does not match its reviewed entries");
    if (entries.length === 0) {
      const capability = value.setupState.capability;
      if (capability) {
        const capabilityRecord = await attestRetainedCapability(capability);
        await unlinkAttestedPrivateFile(
          capability,
          capabilityRecord.identity,
          "partial fixture capability"
        );
        value.setupState.capability = undefined;
      }
    } else {
      const owner = join(value.lock, "owner.pid");
      const ownerRecord = await readAttestedPrivateFile(owner);
      const ownerBytes = ownerRecord.bytes.toString("utf8");
      const successor = /^FULMAR_LOCK_SUCCESSOR_V1\n([0-9]+)\n([a-f0-9]{64})\n$/u.exec(ownerBytes);
      const root = /^([0-9]+)\n([0-9]+)\n(\/private\/tmp\/fulmar-watchdog-capability\.[0-9]+\.[a-f0-9]{64})\n([a-f0-9]{64})\n$/u.exec(ownerBytes);
      assert.ok(successor || root, "fixture lock owner has an unknown schema");
      if (successor) {
        assert.equal(value.setupState.capability, undefined,
          "a successor-only fixture lock cannot own a setup capability");
        assertDeadPID(Number(successor[1]), "retained successor");
      } else {
        const rootPID = Number(root[1]);
        const processGroup = Number(root[2]);
        const capability = root[3];
        const nonce = root[4];
        assert.equal(
          capability,
          `/private/tmp/fulmar-watchdog-capability.${rootPID}.${nonce}`,
          "retained capability path does not match its exact owner"
        );
        if (value.setupState.capability) {
          assert.equal(capability, value.setupState.capability,
            "setup capability differs from the retained lock owner");
        }
        const capabilityRecord = await attestRetainedCapability(capability);
        assert.deepEqual(
          [capabilityRecord.rootPID, capabilityRecord.processGroup, capabilityRecord.nonce],
          [rootPID, processGroup, nonce],
          "retained capability bytes do not match the exact dead root"
        );
        await assertExclusiveCapabilityReference(capability, value.lock);
        assertDeadPID(rootPID, "retained watchdog root");
        assertEmptyProcessGroup(processGroup);
        await unlinkAttestedPrivateFile(
          capability,
          capabilityRecord.identity,
          "retained fixture capability"
        );
        value.setupState.capability = undefined;
      }
      await unlinkAttestedPrivateFile(owner, ownerRecord.identity, "retained fixture lock owner");
    }
    assert.deepEqual(await readdir(value.lock), []);
    const after = await lstat(value.lock);
    assert.deepEqual(
      [after.dev, after.ino, after.uid, after.mode & 0o777, after.nlink],
      [lockDetails.dev, lockDetails.ino, lockDetails.uid, 0o700, 2],
      "fixture lock changed before exact removal"
    );
    await rmdir(value.lock);
    await assert.rejects(lstat(value.lock), { code: "ENOENT" });
  } else {
    assert.equal(value.setupState.capability, undefined,
      "a setup capability cannot be removed without its exact fixture lock");
  }
  // Keep this exact audit phrase stable: fixture root identity changed before recursive removal.
  await attestFixtureRootForCleanup(value);
  // fs.rm does not follow a root symlink, and the exact root and marker were just reattested.
  // A same-user replacement in the final syscall-sized path-to-rm interval remains residual.
  await rm(value.root, { recursive: true });
  await assert.rejects(lstat(value.root), { code: "ENOENT" });
}

function run(value, extraEnv = {}) {
  return spawnSync("/bin/zsh", ["-f", join(value.app, "scripts", "retain-release-verification.sh"), "/tmp/Fulmar.app"], {
    cwd: value.app, encoding: "utf8", env: {
      PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
      FULMAR_RELEASE_EVIDENCE_TEST_ONLY: "1",
      FULMAR_RELEASE_EVIDENCE_TEST_VERIFIER: value.verifier,
      ...extraEnv
    }
  });
}

function runAsync(value, extraEnv = {}) {
  return new Promise((resolve) => {
    const child = spawn("/bin/zsh", ["-f", join(value.app, "scripts", "retain-release-verification.sh"), "/tmp/Fulmar.app"], {
      cwd: value.app, env: {
        PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
        FULMAR_RELEASE_EVIDENCE_TEST_ONLY: "1",
        FULMAR_RELEASE_EVIDENCE_TEST_VERIFIER: value.verifier,
        ...extraEnv
      }
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (bytes) => { stdout += bytes; });
    child.stderr.on("data", (bytes) => { stderr += bytes; });
    child.on("close", (status, signal) => resolve({ status, signal, stdout, stderr }));
  });
}

async function hostileZshStartupEnvironment(value, label) {
  const startupRoot = join(value.root, `hostile-zdotdir-${label}`);
  const marker = join(startupRoot, "zsh-startup.marker");
  await mkdir(startupRoot, { mode: 0o700 });
  await writeFile(
    join(startupRoot, ".zshenv"),
    `print -rn -- sourced > ${JSON.stringify(marker)}\nexit 97\n`,
    { mode: 0o600 }
  );
  return Object.freeze({
    marker,
    environment: Object.freeze({ HOME: startupRoot, ZDOTDIR: startupRoot })
  });
}

async function retainedSet(value) {
  const manifest = JSON.parse(await readFile(join(value.app, "build", "release-manifest.json"), "utf8"));
  return join(
    value.app,
    "build",
    `release-verify-9.8.7-build987-${manifest.sha256}.evidence`
  );
}

async function retainedFiles(value) {
  const set = await retainedSet(value);
  const base = "release-verify-9.8.7-build987";
  return {
    set,
    log: join(set, `${base}.log`),
    record: join(set, `${base}.json`),
    summary: join(set, `${base}-ci-evidence.json`)
  };
}

async function publishedEvidenceSets(value) {
  return (await readdir(join(value.app, "build")))
    .filter((name) => name.startsWith("release-verify-9.8.7-build987-") && name.endsWith(".evidence"));
}

async function waitForPath(path) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try { await stat(path); return; } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error(`timed out waiting for ${path}`);
}

await recoverStaleReleaseEvidenceFixtures();

selfRootTest("successful release evidence is exact-candidate bound, private, and build named", async () => {
  const value = await fixture();
  try {
    const startup = await hostileZshStartupEnvironment(value, "sync");
    const result = run(value, {
      ...startup.environment,
      SECRET_SENTINEL_SHOULD_NOT_APPEAR: "very-secret"
    });
    assert.equal(result.status, 0, result.stderr);
    await assert.rejects(lstat(startup.marker), { code: "ENOENT" });
    const files = await retainedFiles(value);
    const [log, record, summary, setStat, logStat, recordStat, summaryStat] = await Promise.all([
      readFile(files.log), readFile(files.record, "utf8"), readFile(files.summary),
      stat(files.set), stat(files.log), stat(files.record), stat(files.summary)
    ]);
    assert.match(log.toString(), /fixture transcript[\s\S]*fixture stderr/u);
    assert.doesNotMatch(log.toString(), /very-secret/u);
    assert.equal(setStat.mode & 0o777, 0o700);
    assert.equal(logStat.mode & 0o777, 0o600);
    assert.equal(recordStat.mode & 0o777, 0o600);
    assert.equal(summaryStat.mode & 0o777, 0o600);
    const parsed = JSON.parse(record);
    assert.equal(parsed.schemaVersion, 3);
    assert.equal(parsed.transcript.file, "release-verify-9.8.7-build987.log");
    assert.equal(parsed.transcript.bytes, log.length);
    assert.equal(parsed.transcript.sha256, digest(log));
    assert.equal(parsed.candidate.sha256, digest(Buffer.from("candidate archive")));
    assert.match(parsed.candidate.manifestSHA256, /^[a-f0-9]{64}$/u);
    assert.deepEqual(parsed.staticSecurity, {
      ...JSON.parse(await readFile(join(value.app, "build", "release-manifest.json"), "utf8")).inventories.staticSecurity,
      sourceBuildInputsSHA256: digest(await readFile(join(value.app, "build", "source-build-inputs.json")))
    });
    assert.equal(parsed.fullHardwareSummary.file, "release-verify-9.8.7-build987-ci-evidence.json");
    assert.equal(parsed.fullHardwareSummary.bytes, summary.length);
    assert.equal(parsed.fullHardwareSummary.sha256, digest(summary));
    const verification = spawnSync(nodeSource, [
      join(value.app, "scripts", "verify-retained-release-evidence.mjs"),
      join(value.app, "Config", "ReleaseIdentity.json"),
      join(value.app, "build", "release-manifest.json"),
      join(value.app, "build")
    ], { encoding: "utf8", env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" } });
    assert.equal(verification.status, 0, verification.stderr);
  } finally { await cleanupFixture(value); }
});

selfRootTest("raw, copied, and published release evidence never retain emitted credentials or PEM bodies", async () => {
  const secret = "sk-retainedEvidenceSentinel123456789";
  const privateBody = "MIIEvRetainedPrivateBodySentinel";
  const archive = Buffer.from("candidate archive");
  const value = await fixture(0, `#!/bin/zsh
/bin/cp "$PWD/build/fixture-ci-summary.json" "\${2:-$PWD/build/ci-evidence-summary.json}"
print 'Release manifest verified for 9.8.7 (987), ${archive.length} bytes, ${digest(archive)}.'
print 'api_key=${secret}'
print -- '-----BEGIN PRIVATE KEY-----'
print '${privateBody}'
print -- '-----END PRIVATE KEY-----'
print 'Release verification passed against the extracted archive: fixture.'
exit 0
`);
  try {
    const result = run(value);
    assert.equal(result.status, 0, result.stderr);
    assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, new RegExp(`${secret}|${privateBody}`, "u"));
    const files = await retainedFiles(value);
    const published = Buffer.concat(await Promise.all(
      [files.log, files.record, files.summary].map((path) => readFile(path))
    )).toString("utf8");
    assert.doesNotMatch(published, new RegExp(`${secret}|${privateBody}`, "u"));
    assert.match(published, /api_key=<redacted>/u);
    assert.match(published, /<redacted private key material>/u);
  } finally { await cleanupFixture(value); }
});

selfRootTest("retained-evidence verification rejects a post-publication summary mutation", async () => {
  const value = await fixture();
  try {
    assert.equal(run(value).status, 0);
    const files = await retainedFiles(value);
    const originalSummary = await readFile(files.summary);
    await writeFile(
      files.summary,
      JSON.stringify({ profile: "full-hardware", tampered: true }),
      { mode: 0o600 }
    );
    const result = spawnSync(nodeSource, [
      join(value.app, "scripts", "verify-retained-release-evidence.mjs"),
      join(value.app, "Config", "ReleaseIdentity.json"),
      join(value.app, "build", "release-manifest.json"),
      join(value.app, "build")
    ], { encoding: "utf8", env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" } });
    assert.notEqual(result.status, 0);
    await writeFile(files.summary, originalSummary, { mode: 0o600 });
    const staticSecurityPath = join(value.app, "build", "static-security-summary.json");
    const originalStaticSecurity = await readFile(staticSecurityPath);
    await writeFile(staticSecurityPath, `${JSON.stringify({
      schemaVersion: 1, passed: true, unreviewedFindingCount: 0, tampered: true
    })}\n`, { mode: 0o600 });
    let staticResult = spawnSync(nodeSource, [
      join(value.app, "scripts", "verify-retained-release-evidence.mjs"),
      join(value.app, "Config", "ReleaseIdentity.json"),
      join(value.app, "build", "release-manifest.json"),
      join(value.app, "build")
    ], { encoding: "utf8", env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" } });
    assert.notEqual(staticResult.status, 0);
    assert.match(staticResult.stderr, /static-security evidence no longer matches/u);
    await rm(staticSecurityPath);
    staticResult = spawnSync(nodeSource, [
      join(value.app, "scripts", "verify-retained-release-evidence.mjs"),
      join(value.app, "Config", "ReleaseIdentity.json"),
      join(value.app, "build", "release-manifest.json"),
      join(value.app, "build")
    ], { encoding: "utf8", env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" } });
    assert.notEqual(staticResult.status, 0);
    assert.match(staticResult.stderr, /ENOENT|no such file/u);
    await writeFile(staticSecurityPath, originalStaticSecurity, { mode: 0o600 });
  } finally { await cleanupFixture(value); }
});

selfRootTest("pipefail preserves verifier failure and publishes no incomplete evidence", async () => {
  const value = await fixture(23);
  try {
    const result = run(value);
    assert.equal(result.status, 23);
    assert.deepEqual(await publishedEvidenceSets(value), []);
  } finally { await cleanupFixture(value); }
});

selfRootTest("a successful-looking verifier that leaks a descendant cannot publish evidence", async () => {
  const archive = Buffer.from("candidate archive");
  const value = await fixture(0, `#!/bin/zsh
/bin/cp "$PWD/build/fixture-ci-summary.json" "\${2:-$PWD/build/ci-evidence-summary.json}"
/usr/bin/perl -e 'my $pid=fork(); die $! unless defined $pid; if($pid==0){$SIG{TERM}="IGNORE";open(STDIN,"<","/dev/null");open(STDOUT,">","/dev/null");open(STDERR,">","/dev/null");sleep 30;exit 0} open(my $fh, ">", $ARGV[0]) or die $!; print $fh $pid; close($fh); exit 0' "$PWD/build/leaked-descendant.pid"
print 'Release manifest verified for 9.8.7 (987), ${archive.length} bytes, ${digest(archive)}.'
print 'fixture transcript'
print 'Release verification passed against the extracted archive: fixture.'
exit 0
`);
  try {
    const result = run(value);
    assert.equal(result.status, 126, result.stderr);
    assert.deepEqual(await publishedEvidenceSets(value), []);
    const leakedPID = Number((await readFile(join(value.app, "build", "leaked-descendant.pid"), "utf8")).trim());
    assert.throws(() => process.kill(leakedPID, 0), { code: "ESRCH" });
  } finally { await cleanupFixture(value); }
});

selfRootTest("signal exit is exact and cleanup leaves no hidden or final evidence", async () => {
  const value = await fixture(0, "#!/bin/zsh\nprint 'partial transcript'\nkill -TERM $PPID\nsleep 0.2\nexit 0\n");
  try {
    const result = run(value);
    assert.equal(result.status, 143, result.stderr);
    assert.deepEqual(await publishedEvidenceSets(value), []);
  } finally { await cleanupFixture(value); }
});

selfRootTest("post-verification candidate drift fails closed and removes the transcript", async () => {
  const value = await fixture();
  try {
    await writeFile(join(value.app, "build", "Fulmar.app.zip"), "changed candidate");
    const result = run(value);
    assert.notEqual(result.status, 0);
    assert.deepEqual(await publishedEvidenceSets(value), []);
  } finally { await cleanupFixture(value); }
});

selfRootTest("deterministic-only or stale CI evidence cannot be retained as full hardware proof", async () => {
  const value = await fixture();
  try {
    const path = join(value.app, "build", "fixture-ci-summary.json");
    const summary = JSON.parse(await readFile(path, "utf8"));
    summary.profile = "deterministic-ci";
    summary.gates.physicalQwenHardware = "required-not-run";
    await writeFile(path, JSON.stringify(summary));
    const result = run(value);
    assert.notEqual(result.status, 0);
    assert.deepEqual(await publishedEvidenceSets(value), []);
  } finally { await cleanupFixture(value); }
});

selfRootTest("a successful-looking transcript for another candidate cannot be associated", async () => {
  const value = await fixture(0, `#!/bin/zsh
/bin/cp "$PWD/build/fixture-ci-summary.json" "$PWD/build/ci-evidence-summary.json"
print 'Release manifest verified for 9.8.7 (987), 17 bytes, ${"0".repeat(64)}.'
print 'Release verification passed against the extracted archive: fixture.'
exit 0
`);
  try {
    const result = run(value);
    assert.notEqual(result.status, 0);
    assert.deepEqual(await publishedEvidenceSets(value), []);
  } finally { await cleanupFixture(value); }
});

selfRootTest("a failed rerun preserves the complete previously retained candidate set byte-for-byte", async () => {
  const value = await fixture();
  try {
    assert.equal(run(value).status, 0);
    const files = await retainedFiles(value);
    const before = await Promise.all([files.log, files.record, files.summary].map((path) => readFile(path)));
    const verifier = await readFile(value.verifier, "utf8");
    await writeFile(value.verifier, verifier.replace(/exit 0\n$/u, "exit 29\n"), { mode: 0o700 });

    const failed = run(value);
    assert.equal(failed.status, 29, failed.stderr);
    const after = await Promise.all([files.log, files.record, files.summary].map((path) => readFile(path)));
    assert.deepEqual(after, before);
    assert.deepEqual(await publishedEvidenceSets(value), [files.set.split("/").at(-1)]);
  } finally { await cleanupFixture(value); }
});

selfRootTest("SIGKILL before publication cannot replace or mix an existing valid evidence set", async () => {
  const value = await fixture();
  try {
    assert.equal(run(value).status, 0);
    const files = await retainedFiles(value);
    const before = await Promise.all([files.log, files.record, files.summary].map((path) => readFile(path)));

    const killed = run(value, { FULMAR_RELEASE_EVIDENCE_TEST_KILL_AT: "before-publish" });
    assert.equal(killed.status, null);
    assert.equal(killed.signal, "SIGKILL");
    const after = await Promise.all([files.log, files.record, files.summary].map((path) => readFile(path)));
    assert.deepEqual(after, before);
    assert.deepEqual(await publishedEvidenceSets(value), [files.set.split("/").at(-1)]);
  } finally { await cleanupFixture(value); }
});

selfRootTest("SIGKILL after the directory rename exposes one complete verifiable set, never mixed flat files", async () => {
  const value = await fixture();
  try {
    const killed = run(value, {
      FULMAR_RELEASE_EVIDENCE_TEST_KILL_AT: "after-publish-before-parent-fsync"
    });
    assert.equal(killed.status, null);
    assert.equal(killed.signal, "SIGKILL");
    const files = await retainedFiles(value);
    assert.deepEqual((await readdir(files.set)).sort(), [
      "release-verify-9.8.7-build987-ci-evidence.json",
      "release-verify-9.8.7-build987.json",
      "release-verify-9.8.7-build987.log"
    ]);
    const verification = spawnSync(nodeSource, [
      join(value.app, "scripts", "verify-retained-release-evidence.mjs"),
      join(value.app, "Config", "ReleaseIdentity.json"),
      join(value.app, "build", "release-manifest.json"),
      join(value.app, "build")
    ], { encoding: "utf8", env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" } });
    assert.equal(verification.status, 0, verification.stderr);
  } finally { await cleanupFixture(value); }
});

selfRootTest("concurrent same-candidate retention is serialized and cannot mix or nest evidence sets", async () => {
  const archive = Buffer.from("candidate archive");
  const value = await fixture(0, `#!/bin/zsh
/bin/sleep 0.35
/bin/cp "$PWD/build/fixture-ci-summary.json" "\${2:-$PWD/build/ci-evidence-summary.json}"
print 'Release manifest verified for 9.8.7 (987), ${archive.length} bytes, ${digest(archive)}.'
print 'fixture transcript'
print 'Release verification passed against the extracted archive: fixture.'
exit 0
`);
  try {
    const startup = await hostileZshStartupEnvironment(value, "async");
    const first = runAsync(value, startup.environment);
    await new Promise((resolve) => setTimeout(resolve, 80));
    const second = runAsync(value, startup.environment);
    const results = await Promise.all([first, second]);
    assert.deepEqual(
      results.map((result) => result.status).sort(),
      [0, 75],
      JSON.stringify(results.map((result) => ({
        status: result.status, signal: result.signal, stderr: result.stderr
      })))
    );
    const files = await retainedFiles(value);
    assert.deepEqual(await publishedEvidenceSets(value), [files.set.split("/").at(-1)]);
    assert.deepEqual((await readdir(files.set)).sort(), [
      "release-verify-9.8.7-build987-ci-evidence.json",
      "release-verify-9.8.7-build987.json",
      "release-verify-9.8.7-build987.log"
    ]);
    await assert.rejects(stat(join(value.app, "build", "ci-evidence-summary.json")));
    await assert.rejects(lstat(startup.marker), { code: "ENOENT" });
  } finally { await cleanupFixture(value); }
});

selfRootTest("the parent publication lock blocks a candidate-manifest mutator through atomic rename and fsync", async () => {
  const archive = Buffer.from("candidate archive");
  const value = await fixture(0, `#!/bin/zsh
/bin/sleep 0.5
/bin/cp "$PWD/build/fixture-ci-summary.json" "\${2:-$PWD/build/ci-evidence-summary.json}"
print 'Release manifest verified for 9.8.7 (987), ${archive.length} bytes, ${digest(archive)}.'
print 'fixture transcript'
print 'Release verification passed against the extracted archive: fixture.'
exit 0
`);
  const lock = value.lock;
  const manifest = join(value.app, "build", "release-manifest.json");
  const original = await readFile(manifest);
  try {
    const retention = runAsync(value);
    await waitForPath(join(lock, "owner.pid"));
    const mutator = spawnSync(join(value.app, "scripts", "run-with-watchdog.sh"), [
      "--seconds", "5", "--max-rss-bytes", String(256 * 1024 * 1024),
      "--rss-grace-seconds", "1", "--emergency-rss-bytes", String(512 * 1024 * 1024),
      "--lock-dir", lock, "--lock-wait-seconds", "0", "--label", "manifest mutator fixture", "--",
      "/bin/zsh", "-f", "-c", "print -r -- MUTATED > \"$1\"", "_", manifest
    ], { cwd: value.app, encoding: "utf8", timeout: 10_000 });
    assert.equal(mutator.error, undefined, mutator.error?.message);
    assert.equal(mutator.status, 75, mutator.stderr);
    const retained = await retention;
    assert.equal(retained.status, 0, retained.stderr);
    assert.deepEqual(await readFile(manifest), original);
    assert.equal((await publishedEvidenceSets(value)).length, 1);
  } finally {
    await cleanupFixture(value);
  }
});

selfRootTest("partial and stale candidate-specific sets are rejected instead of being mistaken for retained proof", async () => {
  const value = await fixture();
  try {
    assert.equal(run(value).status, 0);
    const files = await retainedFiles(value);
    await rm(files.summary);
    const verification = spawnSync(nodeSource, [
      join(value.app, "scripts", "verify-retained-release-evidence.mjs"),
      join(value.app, "Config", "ReleaseIdentity.json"),
      join(value.app, "build", "release-manifest.json"),
      join(value.app, "build")
    ], { encoding: "utf8", env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" } });
    assert.notEqual(verification.status, 0);
    assert.match(verification.stderr, /does not contain exactly its three reviewed files/u);
  } finally { await cleanupFixture(value); }
});

selfRootTest("retained-evidence verification rejects a symbolic evidence-set directory", async () => {
  const value = await fixture();
  try {
    assert.equal(run(value).status, 0);
    const files = await retainedFiles(value);
    const displaced = `${files.set}.displaced`;
    await rename(files.set, displaced);
    await symlink(displaced, files.set);
    const verification = spawnSync(nodeSource, [
      join(value.app, "scripts", "verify-retained-release-evidence.mjs"),
      join(value.app, "Config", "ReleaseIdentity.json"),
      join(value.app, "build", "release-manifest.json"),
      join(value.app, "build")
    ], { encoding: "utf8", env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" } });
    assert.notEqual(verification.status, 0);
    assert.match(verification.stderr, /ELOOP|symbolic|too many levels|not a directory/iu);
  } finally { await cleanupFixture(value); }
});

test("test verifier substitution is rejected outside the disposable fixture namespace", async () => {
  const [source, testSource] = await Promise.all([
    readFile(wrapperSource, "utf8"),
    readFile(new URL(import.meta.url), "utf8")
  ]);
  assert.match(source, /set -euo pipefail/u);
  assert.match(source, /bounded-redacted-release-stream\.mjs/u);
  assert.match(source, /2>&1[\s\S]*bounded-redacted-release-stream\.mjs[\s\S]*\/usr\/bin\/tee/u);
  assert.match(source, /PROJECT_DIR" == \/private\/tmp\/fulmar-release-evidence-test\.\*\/\*/u);
  assert.match(source, /FIXTURE_NAME" =~ '\^fulmar-release-evidence-test\\\.\[A-Za-z0-9\]\{6\}\$'/u);
  assert.match(source, /LOCK_DIR="\/private\/tmp\/FulmarEvidenceTest-\$\{FIXTURE_NONCE\}\.lock"/u);
  assert.doesNotMatch(source, /FulmarEvidenceTest-\$\{VERSION/u);
  assert.match(testSource, /async function cleanupFixture\(value\)/u);
  const cleanupStart = testSource.indexOf("async function cleanupFixture(");
  const cleanupEnd = testSource.indexOf("\n}\n\nfunction run", cleanupStart);
  const rootIdentityMessage = ["fixture root identity changed before ", "recursive removal"].join("");
  assert.ok(cleanupStart >= 0 && cleanupEnd > cleanupStart);
  assert.equal(testSource.slice(cleanupStart, cleanupEnd).includes(rootIdentityMessage), true);
  assert.equal(testSource.split(rootIdentityMessage).length - 1, 1);
  assert.match(testSource, /assertDeadPID\(rootPID, "retained watchdog root"\)/u);
  assert.match(testSource, /assertEmptyProcessGroup\(processGroup\)/u);
  assert.match(testSource, /await unlinkAttestedPrivateFile\([\s\S]*capabilityRecord\.identity/u);
  assert.match(testSource,
    /cp\(watchdogCapabilityJanitorSource,[\s\S]*?FulmarWatchdogCapabilityJanitor\.pm/u,
    "isolated release-evidence watchdog fixtures omitted the production capability janitor");
  assert.match(testSource,
    /current\.dev, current\.ino, current\.uid, current\.mode & 0o777, current\.nlink, current\.size/u);
  assert.match(testSource, /finally \{ await cleanupFixture\(value\); \}/u);
  const referenceScan = testSource.slice(
    testSource.indexOf("async function assertExclusiveCapabilityReference("),
    testSource.indexOf("async function cleanupFixture(")
  );
  assert.ok(referenceScan.indexOf("lockCount += 1")
    > referenceScan.indexOf("if (!lockDetails.isDirectory()"),
  "unrelated regular lock files must not consume the eligible-directory budget");
  assert.match(referenceScan, /entryCount <= 4_096/u);
  assert.match(referenceScan, /lockCount <= 256/u);
  assert.doesNotMatch(source, /(^|\n)\s*(env|export|set)\s*$/mu);
  for (const failurePoint of ["root-only", "retained-capability", "retained-root"]) {
    const capture = {};
    const injectedFailure = new Error(`injected fixture setup failure: ${failurePoint}`);
    await assert.rejects(
      fixture(0, undefined, { failurePoint, capture, injectedFailure }),
      (error) => {
        assert.equal(error, injectedFailure, "fixture cleanup must preserve the original setup error");
        assert.equal(error.cleanupFailure, undefined, "attested setup cleanup must complete exactly");
        return true;
      }
    );
    await assert.rejects(lstat(capture.root), { code: "ENOENT" });
    await assert.rejects(lstat(capture.lock), { code: "ENOENT" });
    if (capture.capability) {
      await assert.rejects(lstat(capture.capability), { code: "ENOENT" });
    }
  }
  let captureSetterRoot;
  const captureSetterFailure = new Error("injected fixture capture setter failure");
  const throwingCapture = {};
  Object.defineProperty(throwingCapture, "root", {
    set(value) {
      captureSetterRoot = value;
      throw captureSetterFailure;
    }
  });
  await assert.rejects(
    fixture(0, undefined, { capture: throwingCapture }),
    (error) => {
      assert.equal(error, captureSetterFailure,
        "capture setter failure must survive successful attested cleanup unchanged");
      return true;
    }
  );
  assert.match(captureSetterRoot, /^\/private\/tmp\/fulmar-release-evidence-test\.[A-Za-z0-9]{6}$/u);
  await assert.rejects(lstat(captureSetterRoot), { code: "ENOENT" });

  const originalFailure = Object.preventExtensions(new Error("non-extensible fixture setup failure"));
  const cleanupFailure = new Error("injected post-cleanup diagnostic failure");
  const aggregateCapture = {};
  await assert.rejects(
    fixture(0, undefined, {
      failurePoint: "root-only",
      capture: aggregateCapture,
      injectedFailure: originalFailure,
      injectedCleanupFailure: cleanupFailure
    }),
    (error) => {
      assert.ok(error instanceof AggregateError);
      assert.equal(error.cause, originalFailure);
      assert.deepEqual(error.errors, [originalFailure, cleanupFailure]);
      return true;
    }
  );
  await assert.rejects(lstat(aggregateCapture.root), { code: "ENOENT" });
  await assert.rejects(lstat(aggregateCapture.lock), { code: "ENOENT" });

  const replacementRoot = await mkdtemp("/private/tmp/fulmar-release-evidence-test.");
  const capturedReplacementRoot = await captureReleaseEvidenceFixtureRoot(replacementRoot);
  const replacementState = { capability: undefined };
  const replacementValue = Object.freeze({
    root: replacementRoot,
    app: join(replacementRoot, "project"),
    verifier: join(replacementRoot, "fixture-verifier.zsh"),
    lock: `/private/tmp/FulmarEvidenceTest-${capturedReplacementRoot.nonce}.lock`,
    rootIdentity: capturedReplacementRoot.identity,
    setupState: replacementState
  });
  const replacementPath = join(replacementRoot, "replacement-probe");
  try {
    await writeFile(replacementPath, "original", { flag: "wx", mode: 0o600 });
    const original = await readAttestedPrivateFile(replacementPath);
    await unlinkAttestedPrivateFile(replacementPath, original.identity, "original replacement probe");
    await writeFile(replacementPath, "replacement", { flag: "wx", mode: 0o600 });
    await assert.rejects(
      unlinkAttestedPrivateFile(replacementPath, original.identity, "replaced probe"),
      /identity changed before removal/u
    );
    assert.equal(await readFile(replacementPath, "utf8"), "replacement");
    const replacement = await readAttestedPrivateFile(replacementPath);
    await unlinkAttestedPrivateFile(replacementPath, replacement.identity, "replacement probe");
  } finally {
    await cleanupFixture(replacementValue);
  }
});

async function isolatedRecoveryParent() {
  const parent = `/private/tmp/fulmar-release-evidence-recovery-fixture.${randomBytes(16).toString("hex")}`;
  await mkdir(parent, { mode: 0o700 });
  const identity = await attestRecoveryParent(parent);
  return Object.freeze({ parent, identity });
}

async function removeIsolatedRecoveryParent(value) {
  const current = await attestRecoveryParent(value.parent);
  assert.deepEqual(current, value.identity, "isolated recovery parent identity changed before removal");
  await rm(value.parent, { recursive: true });
  await assert.rejects(lstat(value.parent), { code: "ENOENT" });
}

async function withIsolatedRecoveryParent(body) {
  const value = await isolatedRecoveryParent();
  try { await body(value.parent); } finally { await removeIsolatedRecoveryParent(value); }
}

async function syntheticRecoveryRoot(parent, options = {}) {
  const root = await mkdtemp(join(parent, "fulmar-release-evidence-test."));
  const captured = await captureReleaseEvidenceFixtureRoot(root, parent);
  const marker = join(root, fixtureOwnerMarkerName);
  const ownerPID = options.ownerPID ?? process.pid;
  const ownerStarted = options.ownerStarted ?? "Thu Jan  1 00:00:00 1970";
  const createdAtMs = options.createdAtMs ?? Date.now();
  const bytes = options.markerBytes ?? markerBytes(
    ownerPID, ownerStarted, createdAtMs, captured.nonce, captured.identity
  );
  await writeFile(marker, bytes, { flag: "wx", mode: 0o600 });
  await utimes(marker, createdAtMs / 1_000, createdAtMs / 1_000);
  if (options.markerMode !== undefined) await chmod(marker, options.markerMode);
  if (options.rootMode !== undefined) await chmod(root, options.rootMode);
  return Object.freeze({ root, marker, captured });
}

async function createSuccessorLock(rootValue, pid) {
  const lockPath = `/private/tmp/FulmarEvidenceTest-${rootValue.captured.nonce}.lock`;
  await mkdir(lockPath, { mode: 0o700 });
  await writeFile(
    join(lockPath, "owner.pid"),
    `FULMAR_LOCK_SUCCESSOR_V1\n${pid}\n${digest(`successor:${rootValue.root}`)}\n`,
    { flag: "wx", mode: 0o600 }
  );
  return lockPath;
}

async function createOrdinaryLock(rootValue) {
  const rootPID = 99_000_003;
  const processGroup = 99_000_004;
  const nonce = digest(`ordinary:${rootValue.root}`);
  const capability = `/private/tmp/fulmar-watchdog-capability.${rootPID}.${nonce}`;
  const lockPath = `/private/tmp/FulmarEvidenceTest-${rootValue.captured.nonce}.lock`;
  await writeFile(capability, `${rootPID}\n${processGroup}\n${nonce}\n`, {
    flag: "wx", mode: 0o600
  });
  await mkdir(lockPath, { mode: 0o700 });
  await writeFile(
    join(lockPath, "owner.pid"),
    `${rootPID}\n${processGroup}\n${capability}\n${nonce}\n`,
    { flag: "wx", mode: 0o600 }
  );
  return Object.freeze({ lockPath, capability, rootPID, processGroup, nonce });
}

async function removeOwnedGlobalTestPath(path, expectedType) {
  const details = await lstat(path);
  assert.equal(details.uid, process.getuid(), "test-owned global path changed owner");
  assert.equal(details.isSymbolicLink(), false, "test-owned global path became a link");
  assert.equal(expectedType === "directory" ? details.isDirectory() : details.isFile(), true,
    "test-owned global path changed type");
  assert.equal(details.mode & 0o777, expectedType === "directory" ? 0o700 : 0o600,
    "test-owned global path changed mode");
  await rm(path, { recursive: expectedType === "directory" });
  await assert.rejects(lstat(path), { code: "ENOENT" });
}

selfRootTest("release-evidence fixture startup recovery is bounded, crash-safe, and exact-unit correlated", async () => {
  const createdAtMs = Date.now();
  const nowMs = createdAtMs + 120_000;

  await withIsolatedRecoveryParent(async (parent) => {
    const crashProbe = String.raw`
const fs = require("node:fs");
const { spawnSync } = require("node:child_process");
const parent = process.argv[1];
const phase = process.argv[2];
const root = fs.mkdtempSync(parent + "/fulmar-release-evidence-test.");
const name = root.slice(root.lastIndexOf("/") + 1);
const nonce = name.slice(name.lastIndexOf(".") + 1);
const details = fs.lstatSync(root);
const started = spawnSync("/bin/ps", ["-p", String(process.pid), "-o", "lstart="], {
  encoding: "utf8", env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", LC_ALL: "C", LANG: "C" }
}).stdout.trim();
const created = Date.now();
const bytes = Buffer.from(["FULMAR_RELEASE_EVIDENCE_TEST_OWNER_V1", String(process.pid),
  Buffer.from(started).toString("base64"), String(created), nonce, String(details.dev),
  String(details.ino), String(details.uid), String(details.mode & 0o777), ""].join("\n"));
const pending = root + "/.fulmar-release-evidence-owner-v1.pending";
const marker = root + "/.fulmar-release-evidence-owner-v1";
fs.writeFileSync(pending, bytes, { flag: "wx", mode: 0o600 });
let fd = fs.openSync(pending, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
fs.fsyncSync(fd); fs.closeSync(fd);
if (phase === "pending") {
  fs.writeSync(1, root + "\n");
  process.kill(process.pid, "SIGKILL");
}
fs.renameSync(pending, marker);
fd = fs.openSync(root, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
fs.fsyncSync(fd); fs.closeSync(fd);
fs.writeSync(1, root + "\n");
process.kill(process.pid, "SIGKILL");
`;
    for (const phase of ["pending", "published"]) {
      const killed = spawnSync(nodeSource, ["-e", crashProbe, parent, phase], {
        encoding: "utf8", timeout: 5_000,
        env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" }
      });
      assert.equal(killed.status, null);
      assert.equal(killed.signal, "SIGKILL");
      const killedRoot = killed.stdout.trim();
      assert.equal(exactFixtureRoot(killedRoot, parent).name.length > 0, true);
      const recovered = await recoverStaleReleaseEvidenceFixtures({
        parent, minimumAgeMs: 0, nowMs: Date.now()
      });
      assert.deepEqual(recovered.removed, [killedRoot]);
      await assert.rejects(lstat(killedRoot), { code: "ENOENT" });
    }
  });

  await withIsolatedRecoveryParent(async (parent) => {
    const live = await syntheticRecoveryRoot(parent, {
      ownerPID: process.pid, ownerStarted: fixtureProcessStarted, createdAtMs
    });
    const result = await recoverStaleReleaseEvidenceFixtures({ parent, nowMs });
    assert.deepEqual(result.live, [live.root]);
    assert.equal((await lstat(live.root)).isDirectory(), true);
  });

  await withIsolatedRecoveryParent(async (parent) => {
    const reused = await syntheticRecoveryRoot(parent, {
      ownerPID: process.pid,
      ownerStarted: "Thu Jan  1 00:00:00 1970",
      createdAtMs
    });
    const result = await recoverStaleReleaseEvidenceFixtures({ parent, nowMs });
    assert.deepEqual(result.removed, [reused.root]);
  });

  for (const kind of ["symlink", "hardlink", "marker-mode", "root-mode", "malformed"]) {
    await withIsolatedRecoveryParent(async (parent) => {
      const value = await syntheticRecoveryRoot(parent, {
        createdAtMs,
        markerBytes: kind === "malformed" ? Buffer.from("not a fixture owner marker\n") : undefined
      });
      if (kind === "symlink") {
        const target = `${value.marker}.target`;
        await rename(value.marker, target);
        await symlink(target, value.marker);
      } else if (kind === "hardlink") {
        await link(value.marker, `${value.marker}.second-link`);
      } else if (kind === "marker-mode") {
        await chmod(value.marker, 0o644);
      } else if (kind === "root-mode") {
        await chmod(value.root, 0o755);
      }
      await assert.rejects(
        recoverStaleReleaseEvidenceFixtures({ parent, nowMs }),
        /symbolic|too many levels|hard linked|owner-private|unknown schema/iu
      );
      assert.equal((await lstat(value.root)).isDirectory(), true);
    });
  }

  await withIsolatedRecoveryParent(async (parent) => {
    const young = await syntheticRecoveryRoot(parent, { createdAtMs });
    const result = await recoverStaleReleaseEvidenceFixtures({
      parent, nowMs: createdAtMs + 1_000
    });
    assert.deepEqual(result.young, [young.root]);
  });
  await withIsolatedRecoveryParent(async (parent) => {
    const ancient = await syntheticRecoveryRoot(parent, { createdAtMs });
    await assert.rejects(
      recoverStaleReleaseEvidenceFixtures({
        parent, nowMs: createdAtMs + 31 * 24 * 60 * 60 * 1_000
      }),
      /exceeded its recovery age bound/u
    );
    assert.equal((await lstat(ancient.root)).isDirectory(), true);
  });

  await withIsolatedRecoveryParent(async (parent) => {
    const roots = await Promise.all(Array.from({ length: 3 }, () => syntheticRecoveryRoot(parent, {
      createdAtMs
    })));
    await assert.rejects(
      recoverStaleReleaseEvidenceFixtures({ parent, nowMs, maximumRoots: 2 }),
      /root bound was exceeded/u
    );
    for (const value of roots) assert.equal((await lstat(value.root)).isDirectory(), true);
    await writeFile(join(parent, "unrelated-entry"), "x", { mode: 0o600 });
    await assert.rejects(
      recoverStaleReleaseEvidenceFixtures({ parent, nowMs, maximumEntries: 2 }),
      /entry bound was exceeded|root bound was exceeded/u
    );
  });

  await withIsolatedRecoveryParent(async (parent) => {
    const original = await syntheticRecoveryRoot(parent, { createdAtMs });
    const displaced = `${original.root}.displaced`;
    await assert.rejects(
      recoverStaleReleaseEvidenceFixtures({
        parent,
        nowMs,
        beforeCleanup: async (root) => {
          assert.equal(root, original.root);
          await rename(root, displaced);
          await mkdir(root, { mode: 0o700 });
          await rename(join(displaced, fixtureOwnerMarkerName), join(root, fixtureOwnerMarkerName));
        }
      }),
      /differs from the exact root inode|identity changed/iu
    );
    assert.equal((await lstat(original.root)).isDirectory(), true);
    assert.equal((await lstat(displaced)).isDirectory(), true);
  });

  await withIsolatedRecoveryParent(async (parent) => {
    const successor = await syntheticRecoveryRoot(parent, { createdAtMs });
    const lockPath = await createSuccessorLock(successor, 99_000_002);
    const result = await recoverStaleReleaseEvidenceFixtures({ parent, nowMs });
    assert.deepEqual(result.removed, [successor.root]);
    await assert.rejects(lstat(lockPath), { code: "ENOENT" });
  });

  await withIsolatedRecoveryParent(async (parent) => {
    const ordinary = await syntheticRecoveryRoot(parent, { createdAtMs });
    const unit = await createOrdinaryLock(ordinary);
    const result = await recoverStaleReleaseEvidenceFixtures({ parent, nowMs });
    assert.deepEqual(result.removed, [ordinary.root]);
    await assert.rejects(lstat(unit.lockPath), { code: "ENOENT" });
    await assert.rejects(lstat(unit.capability), { code: "ENOENT" });
  });

  await withIsolatedRecoveryParent(async (parent) => {
    const ambiguous = await syntheticRecoveryRoot(parent, { createdAtMs });
    const unit = await createOrdinaryLock(ambiguous);
    const duplicate = `/private/tmp/FulmarEvidenceReference-${randomBytes(8).toString("hex")}.lock`;
    await mkdir(duplicate, { mode: 0o700 });
    await writeFile(
      join(duplicate, "owner.pid"),
      `${unit.rootPID}\n${unit.processGroup}\n${unit.capability}\n${unit.nonce}\n`,
      { flag: "wx", mode: 0o600 }
    );
    await assert.rejects(
      recoverStaleReleaseEvidenceFixtures({ parent, nowMs }),
      /one exclusive exact lock reference/u
    );
    assert.equal((await lstat(ambiguous.root)).isDirectory(), true);
    assert.equal((await lstat(unit.capability)).isFile(), true);
    await removeOwnedGlobalTestPath(duplicate, "directory");
    await removeOwnedGlobalTestPath(unit.lockPath, "directory");
    await removeOwnedGlobalTestPath(unit.capability, "file");
  });

  await withIsolatedRecoveryParent(async (parent) => {
    const blocked = await syntheticRecoveryRoot(parent, { createdAtMs });
    const lockPath = await createSuccessorLock(blocked, process.pid);
    await assert.rejects(
      recoverStaleReleaseEvidenceFixtures({ parent, nowMs }),
      /retained successor is still live/u
    );
    assert.equal((await lstat(blocked.root)).isDirectory(), true);
    assert.equal((await lstat(lockPath)).isDirectory(), true);
    await removeOwnedGlobalTestPath(lockPath, "directory");
  });
});
