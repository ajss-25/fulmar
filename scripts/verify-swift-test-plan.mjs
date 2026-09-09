#!/usr/bin/env node
import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";
import { createHash } from "node:crypto";

const [listPath, planPath] = process.argv.slice(2);
if (process.argv.length !== 4
    || !/^\/private\/tmp\/fulmar-swift-tests\.[A-Za-z0-9]+\/swift-test-plan-[a-f0-9]{32}\.txt$/u.test(listPath ?? "")
    || typeof planPath !== "string" || !planPath.endsWith("/Config/SwiftTestPlan.json")) {
  throw new Error("usage: verify-swift-test-plan.mjs <private-list-path> <plan-path>");
}

function snapshot(path, maximumBytes, { privateFile = false } = {}) {
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = fstatSync(descriptor);
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1
        || before.uid !== process.getuid()
        || (privateFile && (before.mode & 0o777) !== 0o600)
        || before.size < 1 || before.size > maximumBytes) {
      throw new Error("Swift test-plan input has unsafe metadata");
    }
    const bytes = Buffer.alloc(before.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = readSync(descriptor, bytes, offset, bytes.length - offset, offset);
      if (count < 1) throw new Error("Swift test-plan input was truncated");
      offset += count;
    }
    const after = fstatSync(descriptor);
    if (after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size
        || after.uid !== before.uid || after.mode !== before.mode || after.nlink !== before.nlink) {
      throw new Error("Swift test-plan input changed while reading");
    }
    return bytes;
  } finally {
    closeSync(descriptor);
  }
}

const planBytes = snapshot(planPath, 16 * 1024);
let plan;
try { plan = JSON.parse(planBytes.toString("utf8")); }
catch { throw new Error("Swift test plan is not valid JSON"); }
if (!plan || typeof plan !== "object" || Array.isArray(plan)
    || Object.keys(plan).sort().join(",") !== "functionCount,schemaVersion,sortedSpecifierSHA256"
    || plan.schemaVersion !== 1
    || !Number.isSafeInteger(plan.functionCount) || plan.functionCount < 1 || plan.functionCount > 10_000
    || !/^[a-f0-9]{64}$/u.test(plan.sortedSpecifierSHA256 ?? "")) {
  throw new Error("Swift test plan has an invalid schema");
}

const listBytes = snapshot(listPath, 8 * 1024 * 1024, { privateFile: true });
if (listBytes.at(-1) !== 0x0a || listBytes.includes(0) || listBytes.includes(0x0d)) {
  throw new Error("Swift test list has invalid framing");
}
const specifiers = listBytes.toString("utf8").split("\n").slice(0, -1);
// A specifier names one test function: parameterless functions end in "()",
// and parameterized @Test(arguments:) functions end in a label list such as
// "(stage:)" or "(filename:mime:data:expectedCategory:)".
const specifierSuffix = /\((?:[A-Za-z_][A-Za-z0-9_]*:)*\)$/u;
if (specifiers.length < 1 || specifiers.length > 10_000
    || specifiers.some((value) => value.length < 3 || value.length > 4096 || !specifierSuffix.test(value))
    || new Set(specifiers).size !== specifiers.length) {
  throw new Error("Swift test list contains invalid or duplicate specifiers");
}
const sorted = [...specifiers].sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
const digest = createHash("sha256").update(`${sorted.join("\n")}\n`).digest("hex");
if (specifiers.length !== plan.functionCount || digest !== plan.sortedSpecifierSHA256) {
  throw new Error("Swift test binary does not match the frozen full-suite plan");
}
process.stdout.write(`Swift full-suite plan passed: ${plan.functionCount} exact function specifiers.\n`);
