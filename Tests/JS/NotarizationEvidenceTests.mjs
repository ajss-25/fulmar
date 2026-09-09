import assert from "node:assert/strict";
import { chmod, link, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import test from "node:test";

const verifier = join(process.cwd(), "scripts", "verify-notarization-evidence.mjs");
const job = "12345678-1234-4abc-8def-1234567890ab";

async function fixture() {
  const root = await mkdtemp("/private/tmp/fulmar-notary-evidence-test.");
  const submission = join(root, "notarization-submission.json");
  const log = join(root, "notarization-log.json");
  await writeFile(submission, JSON.stringify({ id: job, status: "Accepted" }), { mode: 0o600 });
  await writeFile(log, JSON.stringify({ jobId: job, status: "Accepted", issues: [] }), { mode: 0o600 });
  return { root, submission, log };
}

function run(value) {
  return spawnSync(process.execPath, [verifier, value.submission, value.log], {
    encoding: "utf8",
    env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" }
  });
}

test("notarization evidence requires one matching Accepted issue-free private pair", async () => {
  const value = await fixture();
  try {
    const result = run(value);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, new RegExp(job, "u"));

    await writeFile(value.log, JSON.stringify({ jobId: job, status: "Accepted", issues: [{ message: "problem" }] }));
    assert.notEqual(run(value).status, 0);
    await writeFile(value.log, JSON.stringify({ jobId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", status: "Accepted", issues: null }));
    assert.notEqual(run(value).status, 0);
    await writeFile(value.log, JSON.stringify({ jobId: job, status: "Invalid", issues: null }));
    assert.notEqual(run(value).status, 0);
  } finally { await rm(value.root, { recursive: true, force: true }); }
});

test("notarization evidence rejects permissive, linked, hard-linked, malformed and oversized inputs", async () => {
  const value = await fixture();
  try {
    const missing = run({ ...value, submission: join(value.root, "missing-submission.json") });
    assert.notEqual(missing.status, 0);
    assert.match(missing.stderr, /notarization evidence is missing: missing-submission\.json/u);
    assert.doesNotMatch(missing.stderr, /ENOENT/u);

    await chmod(value.submission, 0o644);
    assert.notEqual(run(value).status, 0);
    await chmod(value.submission, 0o600);

    const linked = join(value.root, "linked.json");
    await symlink(value.log, linked);
    assert.notEqual(run({ ...value, log: linked }).status, 0);

    const hard = join(value.root, "hard.json");
    await link(value.log, hard);
    assert.notEqual(run(value).status, 0);
    await rm(hard);

    await writeFile(value.log, "not json", { mode: 0o600 });
    assert.notEqual(run(value).status, 0);
    await writeFile(value.log, "x".repeat(16 * 1024 * 1024 + 1), { mode: 0o600 });
    assert.notEqual(run(value).status, 0);
  } finally { await rm(value.root, { recursive: true, force: true }); }
});
