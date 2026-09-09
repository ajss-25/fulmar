#!/usr/bin/env node
import { spawn } from "node:child_process";
import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
  readdirSync
} from "node:fs";
import { fileURLToPath } from "node:url";

const [mode, rawFirst, rawSecond, capabilityPath, capabilityNonce] = process.argv.slice(2);
const first = Number(rawFirst);
const second = rawSecond === undefined ? undefined : Number(rawSecond);
if (!Number.isSafeInteger(first) || first <= 1
    || (second !== undefined && (!Number.isSafeInteger(second) || second <= 1))
    || !["child-group", "count", "pid-in-group", "root-attest", "sole-child", "detect-root"].includes(mode)) {
  throw new Error("usage: bounded-process-group-inspector.mjs <child-group|count|pid-in-group|root-attest|sole-child|detect-root> <pid-or-pgid> [pgid]");
}

const capabilityIdentityFields = Object.freeze([
  "dev", "ino", "mode", "nlink", "uid", "gid", "size", "mtimeNs", "ctimeNs"
]);

function readCapability(path, expected) {
  const descriptor = openSync(
    path,
    fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | (fsConstants.O_CLOEXEC ?? 0)
  );
  try {
    const before = fstatSync(descriptor, { bigint: true });
    const expectedBytes = Buffer.from(expected, "utf8");
    if (!before.isFile() || before.nlink !== 1n
        || before.uid !== BigInt(process.getuid()) || (before.mode & 0o777n) !== 0o600n
        || before.size !== BigInt(expectedBytes.length)) {
      throw new Error("unsafe root-watchdog capability identity");
    }
    const openedPath = lstatSync(path, { bigint: true });
    if (!capabilityIdentityFields.every((field) => before[field] === openedPath[field])) {
      throw new Error("root-watchdog capability path changed after open");
    }
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor, { bigint: true });
    const finalPath = lstatSync(path, { bigint: true });
    if (!capabilityIdentityFields.every((field) => before[field] === after[field])
        || !capabilityIdentityFields.every((field) => before[field] === finalPath[field])) {
      throw new Error("root-watchdog capability changed while it was read");
    }
    if (!bytes.equals(expectedBytes)) {
      throw new Error("stale root-watchdog capability content");
    }
    return { dev: before.dev, ino: before.ino, size: before.size };
  } finally {
    closeSync(descriptor);
  }
}

function capabilitySnapshot() {
  if (mode !== "root-attest") return undefined;
  if (!/^[a-f0-9]{64}$/u.test(capabilityNonce ?? "")
      || capabilityPath !== `/private/tmp/fulmar-watchdog-capability.${first}.${capabilityNonce}`) {
    throw new Error("malformed root-watchdog capability path");
  }
  const expected = `${first}\n${second}\n${capabilityNonce}\n`;
  if (Buffer.byteLength(expected) < 68 || Buffer.byteLength(expected) > 256) {
    throw new Error("unsafe root-watchdog capability identity");
  }
  return readCapability(capabilityPath, expected);
}
const capabilityBefore = capabilitySnapshot();

// Deterministic failure injection is available only from a private disposable
// copy of this script. The production inspector always executes absolute
// /bin/ps, even if a caller supplies hostile environment variables.
const seamNames = [
  "FULMAR_PROCESS_INSPECTOR_TEST_ONLY_V1",
  "FULMAR_PROCESS_INSPECTOR_TEST_PS_V1",
  "FULMAR_PROCESS_INSPECTOR_TEST_HOLD_CLOSE_V1"
];
const seamRequested = seamNames.some((name) => Object.hasOwn(process.env, name));
let psExecutable = "/bin/ps";
let holdCloseAfterKill = false;
if (seamRequested) {
  const scriptPath = realpathSync(fileURLToPath(import.meta.url));
  const match = /^(\/private\/tmp\/fulmar-process-inspector-test\.[A-Za-z0-9]+)\/bounded-process-group-inspector\.mjs$/u.exec(scriptPath);
  const rawPS = process.env.FULMAR_PROCESS_INSPECTOR_TEST_PS_V1 ?? "";
  const rawHold = process.env.FULMAR_PROCESS_INSPECTOR_TEST_HOLD_CLOSE_V1 ?? "0";
  if (process.env.FULMAR_PROCESS_INSPECTOR_TEST_ONLY_V1 !== "1" || !match
      || !rawPS.startsWith(`${match[1]}/`) || !["0", "1"].includes(rawHold)) {
    throw new Error("process-inspector test seam is unavailable outside a disposable private fixture");
  }
  psExecutable = realpathSync(rawPS);
  const psDetails = lstatSync(psExecutable);
  if (!psExecutable.startsWith(`${match[1]}/`) || !psDetails.isFile()
      || psDetails.isSymbolicLink() || psDetails.nlink !== 1
      || psDetails.uid !== process.getuid() || (psDetails.mode & 0o111) === 0
      || psDetails.size < 1 || psDetails.size > 64 * 1024) {
    throw new Error("process-inspector test executable is unsafe");
  }
  holdCloseAfterKill = rawHold === "1";
}

const child = spawn(psExecutable, ["-axo", "pid=,ppid=,pgid="], {
  stdio: ["ignore", "pipe", "ignore"]
});
let output = Buffer.alloc(0);
let terminalError;
let killRequested = false;
let settled = false;
let killTimer;
let failTimer;
const requestKill = () => {
  killRequested = true;
  try { child.kill("SIGKILL"); } catch { /* the hard timer still fails closed */ }
};
const result = await new Promise((resolve) => {
  const finish = (value) => {
    if (settled) return;
    settled = true;
    clearTimeout(killTimer);
    clearTimeout(failTimer);
    resolve(value);
  };
child.stdout.on("data", (chunk) => {
  if (output.length + chunk.length > 2 * 1024 * 1024) {
      terminalError = new Error("process table exceeded its byte limit");
      requestKill();
  } else {
    output = Buffer.concat([output, chunk]);
  }
});
  child.once("error", (error) => finish({ error }));
  child.once("close", (code, signal) => {
    if (holdCloseAfterKill && killRequested) return;
    finish(terminalError ? { error: terminalError } : { code, signal });
  });
  killTimer = setTimeout(() => {
    terminalError ??= new Error("bounded process table inspection timed out");
    requestKill();
  }, 750);
  // SIGKILL is not proof that an uninterruptible sampler emitted close. This
  // independent timer guarantees every direct caller regains control.
  failTimer = setTimeout(() => {
    requestKill();
    finish({ error: terminalError ?? new Error("bounded process table inspection did not terminate") });
  }, 1_250);
});
if (result.error || result.code !== 0 || result.signal !== null) {
  throw new Error("bounded process-group inspection failed");
}
if (output.length === 0 || output[output.length - 1] !== 0x0a) {
  throw new Error("bounded process-group inspection returned an empty or unterminated table");
}
const rows = output.toString("utf8").split("\n").filter(Boolean).map((line) => {
  if (line.length > 128) throw new Error("oversized process row");
  const match = /^\s*(\d+)\s+(\d+)\s+(\d+)\s*$/u.exec(line);
  if (!match) throw new Error("malformed process row");
  return { pid: Number(match[1]), ppid: Number(match[2]), pgid: Number(match[3]) };
});
if (rows.length < 1 || rows.length > 16_384) throw new Error("invalid process-table row count");

if (mode === "count") {
  process.stdout.write(`${rows.filter((row) => row.pgid === first).length}\n`);
} else if (mode === "pid-in-group") {
  const matches = rows.filter((row) => row.pid === first && row.pgid === second);
  if (matches.length !== 1) process.exitCode = 1;
} else if (mode === "child-group") {
  const children = rows.filter((row) => row.ppid === first);
  if (children.length !== 1 || children[0].pid !== children[0].pgid) process.exitCode = 1;
  else process.stdout.write(`${children[0].pgid}\n`);
} else if (mode === "sole-child") {
  const children = rows.filter((row) => row.ppid === first && row.pgid === second);
  if (children.length !== 1) process.exitCode = 1;
  else process.stdout.write(`${children[0].pid}\n`);
} else if (mode === "root-attest") {
  const leader = rows.filter((row) => row.pid === second && row.pgid === second && row.ppid === first);
  const inspector = rows.filter((row) => row.pid === process.pid && row.pgid === second);
  if (leader.length !== 1 || inspector.length !== 1) process.exitCode = 1;
  const capabilityAfter = capabilitySnapshot();
  if (capabilityBefore.dev !== capabilityAfter.dev || capabilityBefore.ino !== capabilityAfter.ino
      || capabilityBefore.size !== capabilityAfter.size) process.exitCode = 1;
} else {
  const leader = rows.filter((row) => row.pid === first && row.pgid === first);
  let detected = false;
  if (leader.length === 1 && leader[0].ppid > 1) {
    const prefix = `fulmar-watchdog-capability.${leader[0].ppid}.`;
    for (const name of readdirSync("/private/tmp")) {
      if (!name.startsWith(prefix)) continue;
      const nonce = name.slice(prefix.length);
      if (!/^[a-f0-9]{64}$/u.test(nonce)) continue;
      const path = `/private/tmp/${name}`;
      try {
        const expected = `${leader[0].ppid}\n${first}\n${nonce}\n`;
        readCapability(path, expected);
        detected = true;
      } catch { /* fail this candidate closed and continue exact matching */ }
    }
  }
  if (!detected) process.exitCode = 1;
}
