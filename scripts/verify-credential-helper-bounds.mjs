#!/usr/bin/env node
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { spawn } from "node:child_process";

const helper = process.argv[2];
assert.ok(helper, "credential helper path is required");

const maximumBytes = 1_048_576;
const suffix = randomUUID().replaceAll("-", "").toUpperCase();
const retainedReference = `LOCAL_HARNESS_BOUNDED_RETAINED_${suffix}`;
const continuousReference = `LOCAL_HARNESS_BOUNDED_CONTINUOUS_${suffix}`;
const retainedRecord = `local-harness/bounded-retained-${suffix.toLowerCase()}`;
const continuousRecord = `local-harness/bounded-continuous-${suffix.toLowerCase()}`;
const deadlineMilliseconds = 3_000;

function run(arguments_, input = null, deadline = deadlineMilliseconds) {
  return new Promise((resolve, reject) => {
    const child = spawn(helper, arguments_, { stdio: ["pipe", "pipe", "pipe"] });
    const output = [];
    const errors = [];
    let outputBytes = 0;
    let errorBytes = 0;
    let settled = false;
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish(new Error(`credential helper exceeded ${deadline} ms`));
    }, deadline);
    function finish(error, result) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve(result);
    }
    child.on("error", finish);
    child.stdout.on("data", (chunk) => {
      outputBytes += chunk.length;
      if (outputBytes > 64 * 1_024) {
        child.kill("SIGKILL");
        finish(new Error("credential helper stdout exceeded the test bound"));
      } else output.push(chunk);
    });
    child.stderr.on("data", (chunk) => {
      errorBytes += chunk.length;
      if (errorBytes > 64 * 1_024) {
        child.kill("SIGKILL");
        finish(new Error("credential helper stderr exceeded the test bound"));
      } else errors.push(chunk);
    });
    child.on("close", (status, signal) => finish(null, {
      status,
      signal,
      stdout: Buffer.concat(output),
      stderr: Buffer.concat(errors)
    }));
    child.stdin.on("error", (error) => {
      if (error.code !== "EPIPE") finish(error);
    });
    if (input === null) child.stdin.end();
    else child.stdin.end(input);
  });
}

async function cleanup() {
  // The production credentials service serializes helper mutations. Keep the
  // canary faithful to that contract rather than racing two Security.framework
  // clients during teardown.
  await run(["unset", retainedReference]).catch(() => {});
  await run(["unset", continuousReference]).catch(() => {});
  await run(["unset-record", retainedRecord]).catch(() => {});
  await run(["unset-record", continuousRecord]).catch(() => {});
}

async function rejectContinuous(setCommand, subject, describeCommand, label) {
  const child = spawn(helper, [setCommand, subject], { stdio: ["pipe", "pipe", "pipe"] });
  const continuous = new Promise((resolve, reject) => {
    let settled = false;
    let stderrBytes = 0;
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      if (!settled) reject(new Error(`${label} continuous input was not rejected within the deadline`));
      settled = true;
    }, deadlineMilliseconds);
    child.stderr.on("data", (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes > 64 * 1_024) {
        child.kill("SIGKILL");
        if (!settled) reject(new Error(`${label} continuous-input diagnostic exceeded the test bound`));
        settled = true;
      }
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      if (!settled) reject(error);
      settled = true;
    });
    child.on("close", (status, signal) => {
      clearTimeout(timer);
      if (!settled) resolve({ status, signal });
      settled = true;
    });
  });
  child.stdin.on("error", (error) => {
    if (error.code !== "EPIPE") child.kill("SIGKILL");
  });
  const chunk = Buffer.alloc(64 * 1_024, 0x62);
  function writeContinuously() {
    while (!child.killed && child.stdin.writable) {
      if (!child.stdin.write(chunk)) {
        child.stdin.once("drain", writeContinuously);
        return;
      }
    }
  }
  writeContinuously();
  const result = await continuous;
  assert.notEqual(result.status, 0, `${label} continuous oversized input unexpectedly succeeded`);
  const absent = await run([describeCommand, subject]);
  assert.equal(absent.status, 0, absent.stderr.toString("utf8"));
  assert.equal(absent.stdout.toString("utf8"), "0");
}

try {
  let result = await run(["set", retainedReference], Buffer.from("retained-value"));
  assert.equal(result.status, 0, result.stderr.toString("utf8"));
  result = await run(["describe", retainedReference]);
  assert.equal(result.status, 0, result.stderr.toString("utf8"));
  assert.equal(result.stdout.toString("utf8"), "1");

  result = await run(["set", retainedReference], Buffer.alloc(maximumBytes + 1, 0x61));
  assert.notEqual(result.status, 0, "fixed oversized input unexpectedly succeeded");
  const retained = await run(["get", retainedReference]);
  assert.equal(retained.status, 0);
  assert.equal(retained.stdout.toString("utf8"), "retained-value");

  const retainedRecordValue = Buffer.from('{"kind":"api-key","key":"retained-value"}');
  result = await run(["set-record", retainedRecord], retainedRecordValue);
  assert.equal(result.status, 0, result.stderr.toString("utf8"));
  result = await run(["describe-record", retainedRecord]);
  assert.equal(result.status, 0, result.stderr.toString("utf8"));
  assert.equal(result.stdout.toString("utf8"), "1");
  result = await run(["set-record", retainedRecord], Buffer.alloc(maximumBytes + 1, 0x61));
  assert.notEqual(result.status, 0, "fixed oversized record input unexpectedly succeeded");
  const retainedRecordResult = await run(["get-record", retainedRecord]);
  assert.equal(retainedRecordResult.status, 0, retainedRecordResult.stderr.toString("utf8"));
  assert.deepEqual(retainedRecordResult.stdout, retainedRecordValue);

  await rejectContinuous("set", continuousReference, "describe", "reference");
  await rejectContinuous("set-record", continuousRecord, "describe-record", "record");
  process.stdout.write("Keychain reference, structured-record, and input bounds verification passed.\n");
} finally {
  await cleanup();
}
