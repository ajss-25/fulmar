import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { chmod, link, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { join } from "node:path";

const verifier = join(process.cwd(), "scripts", "verify-swift-test-plan.mjs");

function digest(specifiers) {
  const sorted = [...specifiers].sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
  return createHash("sha256").update(`${sorted.join("\n")}\n`).digest("hex");
}

async function fixture(specifiers, overrides = {}) {
  const root = await mkdtemp("/private/tmp/fulmar-swift-tests.");
  const config = join(root, "Config");
  await mkdir(config, { mode: 0o700 });
  const list = join(root, "swift-test-plan-0123456789abcdef0123456789abcdef.txt");
  const plan = join(config, "SwiftTestPlan.json");
  await writeFile(list, `${specifiers.join("\n")}\n`, { mode: 0o600 });
  await writeFile(plan, `${JSON.stringify({
    schemaVersion: 1,
    functionCount: specifiers.length,
    sortedSpecifierSHA256: digest(specifiers),
    ...overrides
  })}\n`, { mode: 0o600 });
  await chmod(list, 0o600);
  await chmod(plan, 0o600);
  return { root, list, plan };
}

function verify(value) {
  return spawnSync(process.execPath, [verifier, value.list, value.plan], {
    encoding: "utf8",
    timeout: 5_000,
    env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" }
  });
}

test("Swift test-plan verifier accepts the exact order-independent topology", async () => {
  const value = await fixture([
    "Module/Suite/two()",
    "Module/Suite/one()",
    "Module/Suite/parameterized(stage:expectedCategory:)"
  ]);
  try {
    const result = verify(value);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /3 exact function specifiers/u);
  } finally { await rm(value.root, { recursive: true, force: true }); }
});

test("Swift test-plan verifier rejects count, digest, duplicate, and framing drift", async () => {
  const cases = [
    { specifiers: ["Module/Suite/one()"], overrides: { functionCount: 2 } },
    { specifiers: ["Module/Suite/one()"], overrides: { sortedSpecifierSHA256: "0".repeat(64) } },
    { specifiers: ["Module/Suite/one()", "Module/Suite/one()"] },
    { specifiers: ["Module/Suite/one()", "Module/Suite/unlabelled(stage)"] },
    { specifiers: ["Module/Suite/one()", "Module/Suite/bare"] }
  ];
  for (const entry of cases) {
    const value = await fixture(entry.specifiers, entry.overrides);
    try { assert.notEqual(verify(value).status, 0); }
    finally { await rm(value.root, { recursive: true, force: true }); }
  }
  const unterminated = await fixture(["Module/Suite/one()"]);
  try {
    await writeFile(unterminated.list, "Module/Suite/one()", { mode: 0o600 });
    assert.notEqual(verify(unterminated).status, 0);
  } finally { await rm(unterminated.root, { recursive: true, force: true }); }
});

test("Swift test-plan verifier rejects linked, symbolic, and permissive inputs", async () => {
  const linked = await fixture(["Module/Suite/one()"]);
  try {
    await link(linked.list, join(linked.root, "second-link"));
    assert.notEqual(verify(linked).status, 0);
  } finally { await rm(linked.root, { recursive: true, force: true }); }

  const symbolic = await fixture(["Module/Suite/one()"]);
  try {
    const original = `${symbolic.list}.original`;
    await writeFile(original, "Module/Suite/one()\n", { mode: 0o600 });
    await rm(symbolic.list);
    await symlink(original, symbolic.list);
    assert.notEqual(verify(symbolic).status, 0);
  } finally { await rm(symbolic.root, { recursive: true, force: true }); }

  const permissive = await fixture(["Module/Suite/one()"]);
  try {
    await chmod(permissive.list, 0o644);
    assert.notEqual(verify(permissive).status, 0);
  } finally { await rm(permissive.root, { recursive: true, force: true }); }
});
