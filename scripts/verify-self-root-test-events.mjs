#!/usr/bin/env node
import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";

const [eventPath] = process.argv.slice(2);
if (!eventPath || process.argv.length !== 3
    || !/^\/private\/tmp\/fulmar-watchdog-self-tests\.[A-Za-z0-9]+\/events\.jsonl$/u.test(eventPath)) {
  throw new Error("usage: verify-self-root-test-events.mjs </private/tmp/fulmar-watchdog-self-tests.NAME/events.jsonl>");
}

const expectedNames = Object.freeze([
  "watchdog secret backing objects are anonymous before the first secret byte exists",
  "the signing-secret reader accepts its exact byte boundary and rejects malformed descriptors",
  "the zsh secret-closing wrapper preserves argv and closes FD 196",
  "watchdog secret boundaries and malformed inherited markers fail closed",
  "watchdog secrets are absent from argv, environments, listings, logs, and relay parents",
  "nested inherited watchdogs relay each private descriptor exactly once",
  "watchdog preserves an ordinary command status",
  "fixed capability and drain-proof descriptors survive inherited descriptor pressure",
  "the public launcher strips hostile language and shell preload hooks",
  "the cross-session self-test monitor preserves status and drains a TERM-resistant session",
  "watchdog source contains no blocking reap fallback",
  "watchdog process-table parser fails closed on malformed or unterminated rows",
  "the shared process inspector is bounded and rejects empty or malformed process tables",
  "every direct shared-inspector caller propagates inspection failure",
  "a transient descendant RSS spike inside the grace window is allowed",
  "sustained allocation terminates the exact supervised group",
  "aggregate RSS includes descendants rather than only the leader",
  "a leader that exits with an orphaned descendant fails closed and drains it",
  "an observed descendant that changes session cannot escape cleanup after its leader exits",
  "a timed-out observed session-changing descendant is killed before status 124 is published",
  "an external signal lets the tree owner drain an observed session-changing descendant",
  "memory enforcement never kills an unrelated process",
  "wall timeout returns 124 and drains descendants",
  "wall timeout escalates to KILL and drains TERM-ignoring descendants",
  "external SIGTERM is forwarded to the exact child group only",
  "external SIGINT is forwarded to the exact child group only",
  "external SIGHUP is forwarded to the exact child group only",
  "nested watchdog composition is rejected before a separately supervised command can escape",
  "stripping every marker and closing the capability FD cannot create a second root",
  "an inherited logical stage enforces its wall deadline without creating a session",
  "an inherited logical stage enforces a tighter aggregate RSS profile",
  "a supervisor-owned lock is removed only after descendant drain",
  "an ownerless pre-existing lock fails closed after one bounded publication window",
  "cleanup failure changes the final status receipt instead of publishing a stale zero",
  "unexpected capability removal fails closed and leaves no false success receipt",
  "missing tree-drain proof retains the lock and blocks a next contender",
  "release targets never wrap verification around its already bounded gates",
  "release, Swift, status, and evidence call sites contain no legacy PID-only or shlock path",
  "successful release evidence is exact-candidate bound, private, and build named",
  "raw, copied, and published release evidence never retain emitted credentials or PEM bodies",
  "retained-evidence verification rejects a post-publication summary mutation",
  "pipefail preserves verifier failure and publishes no incomplete evidence",
  "a successful-looking verifier that leaks a descendant cannot publish evidence",
  "signal exit is exact and cleanup leaves no hidden or final evidence",
  "post-verification candidate drift fails closed and removes the transcript",
  "deterministic-only or stale CI evidence cannot be retained as full hardware proof",
  "a successful-looking transcript for another candidate cannot be associated",
  "a failed rerun preserves the complete previously retained candidate set byte-for-byte",
  "SIGKILL before publication cannot replace or mix an existing valid evidence set",
  "SIGKILL after the directory rename exposes one complete verifiable set, never mixed flat files",
  "concurrent same-candidate retention is serialized and cannot mix or nest evidence sets",
  "the parent publication lock blocks a candidate-manifest mutator through atomic rename and fsync",
  "partial and stale candidate-specific sets are rejected instead of being mistaken for retained proof",
  "retained-evidence verification rejects a symbolic evidence-set directory",
  "test verifier substitution is rejected outside the disposable fixture namespace"
]);

const descriptor = openSync(eventPath, constants.O_RDONLY | constants.O_NOFOLLOW);
let details;
let bytes;
try {
  details = fstatSync(descriptor);
  if (!details.isFile() || details.isSymbolicLink() || details.nlink !== 1
      || details.uid !== process.getuid() || (details.mode & 0o777) !== 0o600
      || details.size < 1 || details.size > 2 * 1024 * 1024) {
    throw new Error("self-root test event stream has unsafe metadata");
  }
  bytes = Buffer.alloc(details.size);
  let offset = 0;
  while (offset < bytes.length) {
    const count = readSync(descriptor, bytes, offset, bytes.length - offset, offset);
    if (count < 1) throw new Error("self-root test event stream was truncated while reading");
    offset += count;
  }
  const after = fstatSync(descriptor);
  if (after.dev !== details.dev || after.ino !== details.ino || after.size !== details.size) {
    throw new Error("self-root test event stream changed while reading");
  }
} finally { closeSync(descriptor); }
if (bytes.length < 1 || bytes.length > 2 * 1024 * 1024 || bytes.at(-1) !== 0x0a) {
  throw new Error("self-root test event stream is empty, oversized, or unterminated");
}
const records = bytes.toString("utf8").split("\n").slice(0, -1).map((line, index) => {
  if (line.length < 2 || line.length > 16 * 1024) throw new Error(`invalid event line ${index + 1}`);
  let value;
  try { value = JSON.parse(line); } catch { throw new Error(`malformed event JSON on line ${index + 1}`); }
  if (!value || typeof value !== "object" || Array.isArray(value) || typeof value.type !== "string") {
    throw new Error(`invalid event record on line ${index + 1}`);
  }
  return value;
});

const topLevelStarts = records.filter((record) => record.type === "test:start" && record.nesting === 0);
const topLevelPasses = records.filter((record) => record.type === "test:pass" && record.nesting === 0);
const failures = records.filter((record) => record.type === "test:fail");
const skips = records.filter((record) => record.type === "test:pass" && record.skip !== undefined);
const todos = records.filter((record) => record.type === "test:pass" && record.todo !== undefined);
const plans = records.filter((record) => record.type === "test:plan" && record.nesting === 0);
const summaries = records.filter((record) => record.type === "test:summary");
const expectedSorted = [...expectedNames].sort();
const startedNames = topLevelStarts.map((record) => record.name).sort();
const passedNames = topLevelPasses.map((record) => record.name).sort();
if (new Set(expectedNames).size !== expectedNames.length
    || topLevelStarts.length !== expectedNames.length || topLevelPasses.length !== expectedNames.length
    || JSON.stringify(startedNames) !== JSON.stringify(expectedSorted)
    || JSON.stringify(passedNames) !== JSON.stringify(expectedSorted)) {
  throw new Error(`self-root test topology mismatch: expected ${expectedNames.length}, started ${topLevelStarts.length}, passed ${topLevelPasses.length}`);
}
if (failures.length !== 0 || skips.length !== 0 || todos.length !== 0) {
  throw new Error(`self-root test terminal mismatch: failures=${failures.length} skips=${skips.length} todo=${todos.length}`);
}
if (plans.length !== 1 || plans[0].count !== expectedNames.length) {
  throw new Error("self-root test run did not publish its exact top-level plan");
}
if (summaries.length !== 1 || summaries[0].success !== true
    || summaries[0].counts?.tests !== expectedNames.length
    || summaries[0].counts?.passed !== expectedNames.length
    || summaries[0].counts?.failed !== 0 || summaries[0].counts?.cancelled !== 0
    || summaries[0].counts?.skipped !== 0 || summaries[0].counts?.todo !== 0) {
  throw new Error("self-root test run did not publish one complete passing summary");
}
process.stdout.write(`Self-root JavaScript event accounting passed: ${expectedNames.length} exact tests, 0 failures, 0 skips.\n`);
