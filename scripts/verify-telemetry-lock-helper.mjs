#!/usr/bin/env node
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmod, lstat, mkdir, mkdtemp, open, rm } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";

const helper = resolve(process.argv[2] ?? "");
if (!isAbsolute(helper)) throw new Error("the credential helper path must be absolute");
const helperInfo = await lstat(helper);
if (!helperInfo.isFile() || helperInfo.isSymbolicLink() || (helperInfo.mode & 0o111) === 0) {
  throw new Error("the credential helper is missing, linked, or non-executable");
}

const children = new Set();
// Exercise the exact system alias that Foundation renders as `/tmp` while
// realpath(3) and Node preserve as `/private/tmp` in this qualification path.
const root = await mkdtemp("/private/tmp/local-harness-lock-helper-");
const applicationSupport = join(root, "Local Harness");
const telemetryDirectory = join(applicationSupport, "PerformanceTelemetry");
const telemetryFile = join(telemetryDirectory, "performance-telemetry.json");
const lockFile = join(telemetryDirectory, ".performance-telemetry.lock");
const delay = (milliseconds) => new Promise((resolveDelay) => setTimeout(resolveDelay, milliseconds));

function launchLockHelper() {
  const child = spawn(helper, ["telemetry-lock", applicationSupport, telemetryFile], {
    env: { PATH: "/usr/bin:/bin" },
    stdio: ["pipe", "pipe", "pipe"]
  });
  children.add(child);
  let stdout = Buffer.alloc(0);
  let stderr = Buffer.alloc(0);
  child.stdout.on("data", (chunk) => {
    stdout = Buffer.concat([stdout, chunk]);
    if (stdout.length > 64) child.kill("SIGKILL");
  });
  child.stderr.on("data", (chunk) => {
    stderr = Buffer.concat([stderr, chunk]);
    if (stderr.length > 4_096) child.kill("SIGKILL");
  });
  const exited = new Promise((resolveExit, rejectExit) => {
    child.once("error", rejectExit);
    child.once("close", (code, signal) => {
      children.delete(child);
      resolveExit({ code, signal, stdout: stdout.toString("utf8"), stderr: stderr.toString("utf8") });
    });
  });
  return { child, exited, stdout: () => stdout.toString("utf8") };
}

async function waitUntilLocked(holder) {
  // Cold code-signature validation can exceed two seconds while a release
  // build is saturating the machine. Keep the gate bounded without turning
  // normal launch contention into a flaky failure.
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    if (holder.stdout() === "LOCKED\n") return;
    if (holder.child.exitCode !== null || holder.child.signalCode !== null) {
      const result = await holder.exited;
      throw new Error(`lock holder exited early (${result.code ?? result.signal}): ${result.stderr}`);
    }
    await delay(5);
  }
  holder.child.kill("SIGKILL");
  await holder.exited.catch(() => {});
  throw new Error("lock holder did not acquire within the bounded deadline");
}

function waitForExitWithin(operation, label, deadlineMilliseconds = 5_000) {
  return new Promise((resolveExit, rejectExit) => {
    let settled = false;
    const finish = (action, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      action(value);
    };
    const timer = setTimeout(() => {
      operation.child.kill("SIGKILL");
      operation.exited.then(
        () => finish(rejectExit, new Error(`${label} exceeded ${deadlineMilliseconds} ms`)),
        (error) => finish(rejectExit, error)
      );
    }, deadlineMilliseconds);
    operation.exited.then(
      (result) => finish(resolveExit, result),
      (error) => finish(rejectExit, error)
    );
  });
}

async function runProbe() {
  const probe = launchLockHelper();
  probe.child.stdin.end();
  return await waitForExitWithin(probe, "telemetry-lock probe");
}

try {
  await mkdir(applicationSupport, { mode: 0o700 });
  await mkdir(telemetryDirectory, { mode: 0o700 });
  await chmod(applicationSupport, 0o700);
  await chmod(telemetryDirectory, 0o700);
  const telemetry = await open(telemetryFile, "wx", 0o600);
  try {
    await telemetry.writeFile('{"schemaVersion":1,"records":[]}');
    await telemetry.sync();
  } finally {
    await telemetry.close();
  }
  const lock = await open(lockFile, "wx", 0o600);
  try { await lock.sync(); } finally { await lock.close(); }

  const holder = launchLockHelper();
  await waitUntilLocked(holder);
  const busy = await runProbe();
  assert.deepEqual(busy, { code: 4, signal: null, stdout: "BUSY\n", stderr: "" });
  holder.child.stdin.end();
  assert.deepEqual(await waitForExitWithin(holder, "telemetry-lock holder"), { code: 0, signal: null, stdout: "LOCKED\n", stderr: "" });
  assert.deepEqual(await runProbe(), { code: 0, signal: null, stdout: "LOCKED\n", stderr: "" });

  const killed = launchLockHelper();
  await waitUntilLocked(killed);
  assert.equal(killed.child.kill("SIGKILL"), true);
  const killedExit = await waitForExitWithin(killed, "killed telemetry-lock holder");
  assert.equal(killedExit.code, null);
  assert.equal(killedExit.signal, "SIGKILL");
  assert.equal(killedExit.stdout, "LOCKED\n");
  assert.equal(killedExit.stderr, "");
  assert.deepEqual(await runProbe(), { code: 0, signal: null, stdout: "LOCKED\n", stderr: "" });

  const lockInfo = await lstat(lockFile);
  assert.equal(lockInfo.isFile(), true);
  assert.equal(lockInfo.isSymbolicLink(), false);
  assert.equal(lockInfo.nlink, 1);
  assert.equal(lockInfo.mode & 0o777, 0o600);
  assert.equal(lockInfo.size, 0);
  process.stdout.write("Crash-releasing telemetry lock contention and recovery verification passed.\n");
} finally {
  for (const child of children) {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  }
  await Promise.all([...children].map((child) => new Promise((resolveClose) => child.once("close", resolveClose))));
  await rm(root, { recursive: true, force: true });
}
