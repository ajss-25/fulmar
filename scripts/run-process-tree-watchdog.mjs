import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { closeSync, fstatSync, readSync, writeSync } from "node:fs";
import { fileURLToPath } from "node:url";

const commandBarrierDescriptor = 3;
const internalCommandBarrierArgument = "--fulmar-command-start-barrier-v2";
const maximumCommandFrameBytes = 1024 * 1024;
const maximumCommandArguments = 4_096;

function readCommandBarrierFrame() {
  const chunks = [];
  const buffer = Buffer.allocUnsafe(8_192);
  let length = 0;
  try {
    while (true) {
      const count = readSync(commandBarrierDescriptor, buffer, 0, buffer.length, null);
      if (count === 0) break;
      length += count;
      if (length > maximumCommandFrameBytes) throw new Error("oversized command barrier frame");
      chunks.push(Buffer.from(buffer.subarray(0, count)));
    }
  } finally {
    closeSync(commandBarrierDescriptor);
  }
  const bytes = Buffer.concat(chunks, length);
  if (bytes.length < 1 || bytes.at(-1) !== 0x0a) throw new Error("unterminated command barrier frame");
  const frame = JSON.parse(bytes.subarray(0, -1).toString("utf8"));
  const expectedNonce = process.env.FULMAR_COMMAND_START_NONCE;
  if (frame === null || Array.isArray(frame) || typeof frame !== "object"
      || Object.keys(frame).sort().join(",") !== "command,nonce,version"
      || frame.version !== "FULMAR_COMMAND_START_V2"
      || !/^[a-f0-9]{64}$/u.test(expectedNonce ?? "")
      || frame.nonce !== expectedNonce
      || !Array.isArray(frame.command) || frame.command.length < 1
      || frame.command.length > maximumCommandArguments
      || frame.command.some((value) => typeof value !== "string" || value.includes("\0"))
      || frame.command[0].length === 0) {
    throw new Error("invalid command barrier frame");
  }
  return frame.command;
}

if (process.argv.length === 3 && process.argv[2] === internalCommandBarrierArgument) {
  try {
    if (typeof process.execve !== "function") throw new Error("execve unavailable");
    const command = readCommandBarrierFrame();
    delete process.env.FULMAR_COMMAND_START_NONCE;
    // `env --` provides execvp-compatible PATH lookup while the option barrier
    // keeps every requested command and argument in an opaque argv position.
    // No requested byte is ever parsed as shell or interpreter source.
    process.execve("/usr/bin/env", ["/usr/bin/env", "--", ...command], process.env);
  } catch {
    process.stderr.write("Fulmar command start barrier rejected its private frame.\n");
    process.exit(126);
  }
}

const argv = process.argv.slice(2);
function take(name) {
  if (argv.shift() !== name || argv.length === 0) throw new Error(`missing ${name}`);
  return argv.shift();
}
const seconds = Number(take("--seconds"));
const maximumRSSBytes = Number(take("--max-rss-bytes"));
let rssGraceSeconds = 5;
if (argv[0] === "--rss-grace-seconds") rssGraceSeconds = Number(take("--rss-grace-seconds"));
const emergencyRSSBytes = Number(take("--emergency-rss-bytes"));
const label = take("--label");
if (argv.shift() !== "--" || argv.length === 0 || argv.length > maximumCommandArguments
    || argv[0].length === 0
    || !Number.isSafeInteger(seconds) || seconds < 1 || seconds > 21_600
    || !Number.isSafeInteger(maximumRSSBytes) || maximumRSSBytes < 64 * 1024 * 1024
    || !Number.isSafeInteger(rssGraceSeconds) || rssGraceSeconds < 0 || rssGraceSeconds > 300
    || !Number.isSafeInteger(emergencyRSSBytes) || emergencyRSSBytes < maximumRSSBytes
    || emergencyRSSBytes > 48 * 1024 * 1024 * 1024
    || label.length < 1 || label.length > 128 || /[\r\n\0]/u.test(label)) {
  throw new Error("invalid bounded process-tree watchdog invocation");
}
const command = argv;

const proofDescriptorRaw = process.env.FULMAR_TREE_DRAIN_PROOF_FD_V1;
const proofNonce = process.env.FULMAR_TREE_DRAIN_PROOF_NONCE_V1;
let proofDescriptor;
if (proofDescriptorRaw !== undefined || proofNonce !== undefined) {
  proofDescriptor = Number(proofDescriptorRaw);
  if (proofDescriptor !== 197 || !/^[a-f0-9]{64}$/u.test(proofNonce ?? "")
      || !fstatSync(proofDescriptor).isFIFO()) {
    throw new Error("invalid tree-drain proof capability");
  }
}
let proofPublished = false;
function publishDrainProof(status) {
  if (proofDescriptor === undefined) return;
  if (proofPublished || !Number.isSafeInteger(status) || status < 0 || status > 255) {
    throw new Error("invalid tree-drain proof status");
  }
  const frame = `TREE_DRAIN_V1:${proofNonce}:${status}\n`;
  if (writeSync(proofDescriptor, frame) !== Buffer.byteLength(frame)) {
    throw new Error("tree-drain proof publication was incomplete");
  }
  closeSync(proofDescriptor);
  proofPublished = true;
}

const signalCodes = new Map([["SIGHUP", 129], ["SIGINT", 130], ["SIGTERM", 143]]);
let requestedSignal;
for (const signal of signalCodes.keys()) {
  process.once(signal, () => { requestedSignal ??= signal; });
}

let commandStdio = ["inherit", "inherit", "inherit", "pipe"];
const inheritedSecretDescriptors = [];
for (const [name, expected] of [
  ["FULMAR_AUTH_TOKEN_FD_V1", 195],
  ["FULMAR_SIGNING_SECRET_FD_V1", 196]
]) {
  if (process.env[name] === undefined) continue;
  const descriptor = Number(process.env[name]);
  const details = descriptor === expected ? fstatSync(descriptor) : undefined;
  if (descriptor !== expected || !details.isFile() || details.nlink !== 0
      || details.uid !== process.getuid() || (details.mode & 0o777) !== 0o600
      || details.size < 1 || details.size > 4_097) {
    throw new Error("invalid inherited private-secret descriptor");
  }
  inheritedSecretDescriptors.push({ name, descriptor });
}
if (process.env.FULMAR_ROOT_WATCHDOG_FD_V1 === "198" || inheritedSecretDescriptors.length > 0) {
  commandStdio = Array(199).fill("ignore");
  commandStdio[0] = "inherit";
  commandStdio[1] = "inherit";
  commandStdio[2] = "inherit";
  commandStdio[commandBarrierDescriptor] = "pipe";
  if (process.env.FULMAR_ROOT_WATCHDOG_FD_V1 === "198") commandStdio[198] = 198;
  for (const { descriptor } of inheritedSecretDescriptors) commandStdio[descriptor] = descriptor;
}
const commandBarrierNonce = randomBytes(32).toString("hex");
const commandBarrierFrame = Buffer.from(`${JSON.stringify({
  version: "FULMAR_COMMAND_START_V2",
  nonce: commandBarrierNonce,
  command
})}\n`, "utf8");
if (commandBarrierFrame.length > maximumCommandFrameBytes) {
  throw new Error("invalid bounded process-tree watchdog command frame");
}
const commandStartedAt = Date.now();
const child = spawn(process.execPath, [
  fileURLToPath(import.meta.url), internalCommandBarrierArgument
], {
  stdio: commandStdio,
  env: { ...process.env, FULMAR_COMMAND_START_NONCE: commandBarrierNonce }
});
// spawn(2) has duplicated each explicitly mapped descriptor into the command
// barrier child. The monitor is not a credential consumer, so retire its own
// copies immediately and remove even the non-secret descriptor markers from
// its long-lived environment. This does not affect the child's copies.
for (const { name, descriptor } of inheritedSecretDescriptors) {
  closeSync(descriptor);
  delete process.env[name];
}
let childExit;
child.once("error", (error) => { childExit = { error }; });
child.once("exit", (code, signal) => { childExit = { code, signal }; });

const maximumProcessTableBytes = 2 * 1024 * 1024;
const processRow = /^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+([A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s*$/u;
async function processTable() {
  const inspector = spawn("/bin/ps", ["-axo", "pid=,ppid=,pgid=,rss=,lstart="], {
    stdio: ["ignore", "pipe", "ignore"]
  });
  let bytes = Buffer.alloc(0);
  let settled = false;
  return new Promise((resolve, reject) => {
    const finish = (error, rows) => {
      if (settled) return;
      settled = true;
      clearTimeout(killTimer);
      clearTimeout(failTimer);
      if (error) reject(error); else resolve(rows);
    };
    inspector.stdout.on("data", (chunk) => {
      if (bytes.length + chunk.length > maximumProcessTableBytes) {
        inspector.kill("SIGKILL");
        finish(new Error("process table exceeded its byte limit"));
      } else {
        bytes = Buffer.concat([bytes, chunk]);
      }
    });
    inspector.once("error", (error) => finish(error));
    inspector.once("close", (code, signal) => {
      if (code !== 0 || signal !== null || bytes.length === 0) {
        finish(new Error("bounded process table inspection failed"));
        return;
      }
      try {
        const lines = bytes.toString("utf8").split("\n").filter((line) => line.length > 0);
        if (lines.length < 1 || lines.length > 16_384) throw new Error("invalid process-table row count");
        const rows = lines.map((line) => {
          if (line.length > 192) throw new Error("oversized process-table row");
          const match = processRow.exec(line);
          if (!match) throw new Error("malformed process-table row");
          const [pid, ppid, pgid, rssKiB] = match.slice(1, 5).map(Number);
          if (![pid, ppid, pgid, rssKiB].every(Number.isSafeInteger)
              || pid < 1 || ppid < 0 || pgid < 1 || rssKiB < 0) {
            throw new Error("invalid process-table value");
          }
          return { pid, ppid, pgid, rssBytes: rssKiB * 1024, started: match[5] };
        });
        finish(undefined, rows);
      } catch (error) { finish(error); }
    });
    const killTimer = setTimeout(() => inspector.kill("SIGKILL"), 750);
    const failTimer = setTimeout(() => {
      inspector.kill("SIGKILL");
      finish(new Error("process table inspection did not terminate"));
    }, 1_000);
  });
}

const known = new Map();
const knownGroups = new Set();
const retiredPIDs = new Set();
const maximumKnownIdentities = 8_192;
const maximumKnownGroups = 2_048;
// Only fixed diagnostic codes cross this boundary. Never print raw ps rows,
// child arguments, environment values or arbitrary exception messages.
function inspectionFailureCode(error) {
  switch (error?.message) {
    case "process table exceeded its byte limit": return "ps_byte_limit";
    case "bounded process table inspection failed": return "ps_status";
    case "process table inspection did not terminate": return "ps_timeout";
    case "invalid process-table row count": return "ps_row_count";
    case "oversized process-table row": return "ps_row_size";
    case "malformed process-table row": return "ps_row_format";
    case "invalid process-table value": return "ps_row_value";
    case "supervisor disappeared from the process table": return "supervisor_absent";
    case "supervisor process group changed": return "supervisor_group_changed";
    case "a retired test-runner PID reappeared while supervised": return "leader_retired_visible";
    case "test-runner PID identity changed": return "leader_identity_changed";
    case "a retired descendant PID reappeared while supervised": return "descendant_retired_visible";
    case "descendant PID identity changed while supervised": return "descendant_identity_changed";
    case "tracked descendant identity limit exceeded": return "known_identity_limit";
    case "retired descendant identity limit exceeded": return "retired_identity_limit";
    case "tracked descendant group limit exceeded": return "known_group_limit";
    default: return "unknown_inspection_failure";
  }
}
function inspectionFailureDiagnostic(error) {
  return `code=${inspectionFailureCode(error)} known=${known.size} retired=${retiredPIDs.size} groups=${knownGroups.size}`;
}
let childIdentity;
let childIdentityActive = false;
let supervisorPGID;
function sameIdentity(row, identity) {
  return row?.pid === identity?.pid && row.started === identity.started;
}
function updateOwnership(rows) {
  const byPID = new Map(rows.map((row) => [row.pid, row]));
  const supervisor = byPID.get(process.pid);
  if (!supervisor) throw new Error("supervisor disappeared from the process table");
  supervisorPGID ??= supervisor.pgid;
  if (supervisor.pgid !== supervisorPGID) throw new Error("supervisor process group changed");

  if (childExit !== undefined && childIdentityActive) {
    childIdentityActive = false;
    retiredPIDs.add(child.pid);
  }
  const observedRoot = byPID.get(child.pid);
  if (observedRoot && !childIdentityActive) {
    throw new Error("a retired test-runner PID reappeared while supervised");
  }
  const root = childIdentityActive && sameIdentity(observedRoot, childIdentity) ? observedRoot : undefined;
  if (observedRoot && childIdentity && !sameIdentity(observedRoot, childIdentity)) {
    throw new Error("test-runner PID identity changed");
  }
  if (childIdentityActive && !root) {
    childIdentityActive = false;
    retiredPIDs.add(child.pid);
  }

  const frontier = new Set();
  if (root && childIdentity && sameIdentity(root, childIdentity)) frontier.add(root.pid);
  for (const [pid, identity] of known) {
    if (sameIdentity(byPID.get(pid), identity)) frontier.add(pid);
    else {
      known.delete(pid);
      retiredPIDs.add(pid);
    }
  }
  let changed = true;
  while (changed) {
    changed = false;
    for (const row of rows) {
      if (!frontier.has(row.ppid) || frontier.has(row.pid)) continue;
      if (retiredPIDs.has(row.pid)) {
        throw new Error("a retired descendant PID reappeared while supervised");
      }
      const identity = { pid: row.pid, started: row.started, pgid: row.pgid };
      const previous = known.get(row.pid);
      if (previous && previous.started !== identity.started) {
        throw new Error("descendant PID identity changed while supervised");
      }
      known.set(row.pid, identity);
      if (known.size > maximumKnownIdentities) throw new Error("tracked descendant identity limit exceeded");
      if (retiredPIDs.size > maximumKnownIdentities) throw new Error("retired descendant identity limit exceeded");
      frontier.add(row.pid);
      changed = true;
    }
  }
  for (const pid of frontier) {
    if (pid === child.pid) continue;
    const row = byPID.get(pid);
    if (row && row.pgid !== supervisorPGID) knownGroups.add(row.pgid);
  }
  for (const pgid of knownGroups) {
    if (!rows.some((row) => row.pgid === pgid)) knownGroups.delete(pgid);
  }
  if (knownGroups.size > maximumKnownGroups) throw new Error("tracked descendant group limit exceeded");

  const owned = rows.filter((row) => {
    if (childIdentityActive && childIdentity && sameIdentity(row, childIdentity)) return true;
    const identity = known.get(row.pid);
    if (identity && sameIdentity(row, identity)) return true;
    return row.pgid !== supervisorPGID && knownGroups.has(row.pgid);
  });
  return { owned, byPID };
}

async function establishChildIdentity() {
  const deadline = Date.now() + 2_000;
  while (Date.now() < deadline && childExit === undefined) {
    const rows = await processTable();
    const byPID = new Map(rows.map((row) => [row.pid, row]));
    const supervisor = byPID.get(process.pid);
    const root = byPID.get(child.pid);
    if (!supervisor) throw new Error("supervisor disappeared before command release");
    if (root) {
      if (root.ppid !== process.pid || root.pgid !== supervisor.pgid) {
        throw new Error("command barrier did not remain the direct supervised child");
      }
      supervisorPGID = supervisor.pgid;
      childIdentity = { pid: root.pid, started: root.started };
      childIdentityActive = true;
      const barrier = child.stdio[commandBarrierDescriptor];
      if (!barrier?.writable) throw new Error("command start barrier could not be released");
      await new Promise((resolve, reject) => {
        let settled = false;
        const finish = (error) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          barrier.off("error", onError);
          if (error) reject(error); else resolve();
        };
        const onError = () => finish(new Error("command start barrier write failed"));
        const timer = setTimeout(() => {
          barrier.destroy();
          finish(new Error("command start barrier write timed out"));
        }, 2_000);
        barrier.once("error", onError);
        barrier.end(commandBarrierFrame, () => finish());
      });
      return;
    }
    await pause(20);
  }
  throw new Error("command start barrier could not be attested before exit");
}

function signalOwned(rows, signal) {
  const { owned } = updateOwnership(rows);
  const groups = new Set(owned.map((row) => row.pgid)
    .filter((pgid) => pgid > 1 && pgid !== supervisorPGID));
  for (const pgid of groups) {
    try { process.kill(-pgid, signal); } catch (error) {
      if (error?.code !== "ESRCH") throw error;
    }
  }
  for (const row of owned.sort((left, right) => right.pid - left.pid)) {
    try { process.kill(row.pid, signal); } catch (error) {
      if (error?.code !== "ESRCH") throw error;
    }
  }
}

const pause = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
async function drain() {
  for (const [signal, milliseconds] of [["SIGTERM", 3_000], ["SIGKILL", 2_000]]) {
    const deadline = Date.now() + milliseconds;
    while (Date.now() < deadline) {
      const rows = await processTable();
      signalOwned(rows, signal);
      const { owned } = updateOwnership(rows);
      if (owned.length === 0 && childExit !== undefined) return true;
      await pause(50);
    }
  }
  const rows = await processTable();
  return updateOwnership(rows).owned.length === 0 && childExit !== undefined;
}

let startFailure;
try {
  await establishChildIdentity();
} catch (error) {
  startFailure = error;
  child.stdio[commandBarrierDescriptor]?.destroy();
}

const deadline = commandStartedAt + seconds * 1_000;
let pressureSince;
let inspectionFailures = 0;
let terminationCode;
let terminationMessage;
let exitedRunnerDescendantsSince;
let treeProvenEmpty = false;
if (startFailure) {
  terminationCode = 126;
  terminationMessage = `${label} could not attest its command start barrier safely.`;
}
while (terminationCode === undefined) {
  let rows;
  let owned;
  try {
    rows = await processTable();
    ({ owned } = updateOwnership(rows));
    inspectionFailures = 0;
  } catch (error) {
    inspectionFailures += 1;
    if (inspectionFailures >= 3) {
      terminationCode = 126;
      terminationMessage = `${label} could not inspect its complete process tree safely. ${inspectionFailureDiagnostic(error)}`;
      break;
    }
    await pause(50);
    continue;
  }
  const aggregateRSS = owned.reduce((total, row) => total + row.rssBytes, 0);
  if (aggregateRSS >= emergencyRSSBytes) {
    terminationCode = 125;
    terminationMessage = `${label} exceeded its emergency aggregate RSS limit.`;
    break;
  }
  if (aggregateRSS > maximumRSSBytes) pressureSince ??= Date.now(); else pressureSince = undefined;
  if (pressureSince !== undefined && Date.now() - pressureSince >= rssGraceSeconds * 1_000) {
    terminationCode = 125;
    terminationMessage = `${label} remained above its aggregate RSS limit.`;
    break;
  }
  if (requestedSignal) {
    terminationCode = signalCodes.get(requestedSignal);
    terminationMessage = `${label} received ${requestedSignal}.`;
    break;
  }
  if (Date.now() >= deadline) {
    terminationCode = 124;
    terminationMessage = `${label} exceeded its ${seconds}-second wall limit.`;
    break;
  }
  if (childExit !== undefined) {
    const descendants = owned.filter((row) => row.pid !== child.pid);
    if (descendants.length > 0) {
      exitedRunnerDescendantsSince ??= Date.now();
      // Node's test worker can remain observable for a final scheduling tick
      // after its runner has reported exit. Give naturally terminating workers
      // one short bounded grace interval; a real orphan still fails and is
      // drained before this monitor releases its caller.
      if (Date.now() - exitedRunnerDescendantsSince < 500) {
        await pause(50);
        continue;
      }
      terminationCode = 126;
      const identities = descendants.slice(0, 8)
        .map((row) => `${row.pid}@pgid${row.pgid}`).join(",");
      terminationMessage = `${label} supervised command exited while tracked descendants were still running (${identities}).`;
      break;
    }
    exitedRunnerDescendantsSince = undefined;
    if (childExit.error) {
      terminationCode = 126;
      terminationMessage = `${label} test runner could not start.`;
    } else if (childExit.signal) {
      terminationCode = signalCodes.get(childExit.signal) ?? 126;
    } else {
      terminationCode = childExit.code ?? 126;
    }
    if (terminationCode === 0) treeProvenEmpty = true;
    break;
  }
  await pause(50);
}

if (terminationMessage) process.stderr.write(`${terminationMessage}\n`);
let drained = false;
if (treeProvenEmpty) drained = true;
else try { drained = await drain(); } catch (error) {
  drained = false;
  process.stderr.write(`${label} process-tree drain inspection failed. ${inspectionFailureDiagnostic(error)}\n`);
}
if (!drained) {
  process.stderr.write(`${label} could not prove its complete process tree empty after bounded TERM/KILL cleanup.\n`);
  process.exit(126);
}
const finalStatus = terminationCode ?? 126;
try { publishDrainProof(finalStatus); } catch (error) {
  process.stderr.write(`${label} could not publish its authenticated tree-drain proof.\n`);
  process.exit(126);
}
process.exit(finalStatus);
