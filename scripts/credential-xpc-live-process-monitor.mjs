#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import {
  closeSync, fsyncSync, lstatSync, openSync,
  realpathSync, writeFileSync
} from "node:fs";
import { basename, dirname } from "node:path";
import { readAttestedRegularFileSync } from "./attested-regular-file.mjs";

const [executable, readyPath, donePath, evidencePath] = process.argv.slice(2);
const expectedNames = new Set([
  "LocalHarnessCredentialMigrationService",
  "LocalHarnessCredentialBrokerService"
]);
const startedPattern = "[A-Z][a-z]{2}\\s+[A-Z][a-z]{2}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2}\\s+\\d{4}";
const rowPattern = new RegExp(`^\\s*(\\d+)\\s+(${startedPattern})\\s+(.+)$`, "u");
let reviewedExecutableIdentity;
let reviewedCDHash;
let phase = "input-validation";

function fail() {
  // Only a fixed lifecycle label is exposed; never process rows or credentials.
  process.stderr.write(`Credential XPC exact-process evidence failed (${phase}).\n`);
  process.exit(1);
}

function bounded(executablePath, argumentsList, maximumBytes = 2 * 1024 * 1024) {
  const result = spawnSync(executablePath, argumentsList, {
    encoding: "utf8",
    timeout: 2_000,
    maxBuffer: maximumBytes,
    env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" }
  });
  if (result.status !== 0 || result.signal !== null || result.error
      || Buffer.byteLength(result.stdout ?? "") > maximumBytes
      || Buffer.byteLength(result.stderr ?? "") > maximumBytes) fail();
  return result;
}

function validateInputs() {
  if (process.argv.length !== 6 || typeof executable !== "string"
      || !executable.startsWith("/") || executable.includes("\0")
      || realpathSync(executable) !== executable || !expectedNames.has(basename(executable))) fail();
  const details = lstatSync(executable);
  if (!details.isFile() || details.isSymbolicLink() || details.nlink !== 1
      || (details.mode & 0o111) === 0) fail();
  const identityBeforeSignature = lstatSync(executable, { bigint: true });
  const serviceMacOS = dirname(executable);
  const serviceContents = dirname(serviceMacOS);
  const serviceBundle = dirname(serviceContents);
  const xpcServices = dirname(serviceBundle);
  if (basename(serviceMacOS) !== "MacOS" || basename(serviceContents) !== "Contents"
      || !basename(serviceBundle).endsWith("Service.xpc")
      || basename(xpcServices) !== "XPCServices" || basename(dirname(xpcServices)) !== "Contents") fail();
  bounded("/usr/bin/codesign", ["--verify", "--strict", serviceBundle]);
  const signature = spawnSync("/usr/bin/codesign", ["-dvvv", serviceBundle], {
    encoding: "utf8", timeout: 2_000, maxBuffer: 256 * 1024,
    env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" }
  });
  const digest = /(?:^|\n)CDHash=([a-f0-9]{40,128})(?:\n|$)/u
    .exec(signature.stderr ?? "")?.[1];
  if (signature.status !== 0 || signature.signal !== null || signature.error
      || !signature.stderr.includes("Identifier=com.angadjairath.localharness.credential-helper")
      || !digest) fail();
  const identityAfterSignature = lstatSync(executable, { bigint: true });
  if (identityAfterSignature.dev !== identityBeforeSignature.dev
      || identityAfterSignature.ino !== identityBeforeSignature.ino
      || identityAfterSignature.size !== identityBeforeSignature.size
      || identityAfterSignature.mtimeNs !== identityBeforeSignature.mtimeNs) fail();
  reviewedExecutableIdentity = {
    device: identityAfterSignature.dev,
    inode: identityAfterSignature.ino
  };
  reviewedCDHash = digest;

  const evidenceRoot = dirname(evidencePath);
  if (dirname(readyPath) !== evidenceRoot || dirname(donePath) !== evidenceRoot
      || !evidenceRoot.startsWith("/private/tmp/")
      || realpathSync(evidenceRoot) !== evidenceRoot
      || basename(readyPath) !== "monitor.ready" || basename(donePath) !== "client.done"
      || basename(evidencePath) !== "service.evidence") fail();
  const root = lstatSync(evidenceRoot);
  if (!root.isDirectory() || root.isSymbolicLink() || root.nlink < 2
      || root.uid !== process.getuid() || (root.mode & 0o777) !== 0o700) fail();
}

function processRows() {
  const result = bounded("/bin/ps", ["-axo", "pid=,lstart=,command="]);
  const lines = result.stdout.split("\n").filter(Boolean);
  if (lines.length < 1 || lines.length > 16_384) fail();
  // Unrelated processes can disappear between ps collecting its rows and
  // rendering the command column, which can leave an otherwise irrelevant
  // row without a command. Only a row which names the exact reviewed
  // executable participates in this identity proof; any malformed row that
  // does name it remains a hard failure.
  return lines.filter((line) => line.includes(executable)).map((line) => {
    const match = rowPattern.exec(line);
    if (!match) fail();
    const pid = Number(match[1]);
    if (!Number.isSafeInteger(pid) || pid <= 1) fail();
    return { pid, started: match[2], command: match[3] };
  });
}

function exactTextIdentity(pid) {
  const result = spawnSync(
    "/usr/sbin/lsof",
    ["-a", "-p", String(pid), "-d", "txt", "-FfDin"],
    {
    encoding: "utf8", timeout: 2_000, maxBuffer: 256 * 1024,
    env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" }
    }
  );
  if (result.status !== 0 || result.signal !== null || result.error) return undefined;
  const records = [];
  let record;
  for (const line of result.stdout.split("\n").filter(Boolean)) {
    if (line.startsWith("f")) {
      if (record) records.push(record);
      record = { descriptor: line.slice(1) };
    } else if (record && line.startsWith("D")) {
      try { record.device = BigInt(line.slice(1)); } catch { return undefined; }
    } else if (record && line.startsWith("i")) {
      try { record.inode = BigInt(line.slice(1)); } catch { return undefined; }
    } else if (record && line.startsWith("n")) {
      record.path = line.slice(1);
    }
  }
  if (record) records.push(record);
  const matches = records.filter((candidate) =>
    candidate.descriptor === "txt" && candidate.path === executable
      && candidate.device === reviewedExecutableIdentity.device
      && candidate.inode === reviewedExecutableIdentity.inode);
  return matches.length === 1 ? reviewedExecutableIdentity : undefined;
}

function exactProcesses() {
  const candidates = processRows().filter((row) =>
    row.command === executable || row.command.startsWith(`${executable} `));
  if (candidates.length > 4) fail();
  return candidates.filter((row) => exactTextIdentity(row.pid) !== undefined);
}

function sameIdentity(identity) {
  const row = processRows().find((candidate) => candidate.pid === identity.pid);
  return row?.started === identity.started && exactTextIdentity(identity.pid) !== undefined;
}

function sleep(milliseconds) {
  const buffer = new SharedArrayBuffer(4);
  Atomics.wait(new Int32Array(buffer), 0, 0, milliseconds);
}

function validateDone() {
  let artifact;
  try {
    artifact = readAttestedRegularFileSync(donePath, {
      label: "credential XPC completion marker",
      minimumBytes: 5,
      maximumBytes: 5,
      requireCurrentUser: true,
      requirePrivateMode: true,
      requireSingleLink: true
    });
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    fail();
  }
  if (artifact.bytes.toString("utf8") !== "done\n") fail();
  return true;
}

function writeEvidence(identity) {
  if (!reviewedCDHash || exactTextIdentity(identity.pid) === undefined) fail();
  const bytes = `pid=${identity.pid}\nstarted=${identity.started}\ncdhash=${reviewedCDHash}\n`;
  const descriptor = openSync(evidencePath, "wx", 0o600);
  try {
    writeFileSync(descriptor, bytes, { encoding: "utf8" });
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function writeReady() {
  const descriptor = openSync(readyPath, "wx", 0o600);
  try {
    writeFileSync(descriptor, "ready\n", { encoding: "utf8" });
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function signalExact(identity, signal) {
  if (!sameIdentity(identity)) return;
  try { process.kill(identity.pid, signal); } catch (error) {
    if (error?.code !== "ESRCH") fail();
  }
}

function drainExactProcesses() {
  for (let pass = 0; pass < 8; pass += 1) {
    const current = exactProcesses();
    if (current.length === 0) return;
    for (const identity of current) signalExact(identity, "SIGTERM");
    for (let attempt = 0; attempt < 20 && current.some(sameIdentity); attempt += 1) sleep(50);
    for (const identity of current) signalExact(identity, "SIGKILL");
    for (let attempt = 0; attempt < 20 && current.some(sameIdentity); attempt += 1) sleep(50);
    if (current.some(sameIdentity)) fail();
  }
  fail();
}

validateInputs();
phase = "preexisting-service-check";
if (exactProcesses().length !== 0) fail();
writeReady();
phase = "waiting-for-service";
const launchDeadline = Date.now() + 10_000;
let captured;
while (Date.now() < launchDeadline) {
  const current = exactProcesses();
  if (current.length === 1) { captured = current[0]; break; }
  if (current.length > 1) fail();
  // Re-sample after completion: launch and reply can occur between the empty
  // snapshot above and the done marker. That service still needs exact drain.
  // If no service is observed, report failure here rather than obscure an
  // early client failure behind the outer verifier's 8-second drain bound.
  if (validateDone()) {
    const completed = exactProcesses();
    if (completed.length !== 1) fail();
    captured = completed[0];
    break;
  }
  sleep(10);
}
if (!captured) fail();
phase = "recording-service-identity";
writeEvidence(captured);

phase = "waiting-for-client";
const completionDeadline = Date.now() + 20_000;
while (Date.now() < completionDeadline && !validateDone()) sleep(10);
if (!validateDone()) fail();
phase = "draining-service";
drainExactProcesses();
if (exactProcesses().length !== 0) fail();
process.stdout.write("FULMAR_CREDENTIAL_XPC_PROCESS_DRAIN_OK\n");
