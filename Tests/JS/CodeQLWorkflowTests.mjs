import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const project = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const actionCommit = "cdf488f595d80d6e07e03d4674febd5ab45fa938";

test("CodeQL is a bounded JavaScript and TypeScript source gate with least privilege", async () => {
  const workflow = await readFile(join(project, ".github", "workflows", "verify-source.yml"), "utf8");
  const start = workflow.indexOf("  codeql-javascript:\n");
  const end = workflow.indexOf("  macos:\n");
  assert.ok(start >= 0 && end > start, "the CodeQL job is missing or misplaced");
  const job = workflow.slice(start, end);
  assert.match(job, /^  codeql-javascript:\n    name: codeql-javascript$/mu);
  assert.match(job, /runs-on: ubuntu-24\.04/u);
  assert.match(job, /timeout-minutes: 20/u);
  assert.match(job, /permissions:\n      contents: read\n      security-events: write/u);
  assert.doesNotMatch(job, /^[ \t]+(?:actions|checks|deployments|id-token|issues|packages|pages|pull-requests|statuses): write$/mu);
  assert.match(job, /languages: javascript-typescript/u);
  assert.match(job, /build-mode: none/u);
  assert.match(job, /queries: security-extended/u);
  assert.match(job, /category: \/language:javascript-typescript/u);
  assert.doesNotMatch(job, /\blanguages: swift\b|pull_request_target/u);
});

test("CodeQL action code is pinned to the reviewed signed-release commit", async () => {
  const workflow = await readFile(join(project, ".github", "workflows", "verify-source.yml"), "utf8");
  const expected = new RegExp(`github/codeql-action/(?:init|analyze)@${actionCommit} # v4\\.37\\.9`, "gu");
  assert.equal((workflow.match(expected) ?? []).length, 2);
  assert.doesNotMatch(workflow, /github\/codeql-action\/(?:init|analyze)@(?!cdf488f595d80d6e07e03d4674febd5ab45fa938)/u);
});

test("CodeQL never runs repository code before the operating-system tracked-index gate", async () => {
  const workflow = await readFile(join(project, ".github", "workflows", "verify-source.yml"), "utf8");
  const start = workflow.indexOf("  codeql-javascript:\n");
  const end = workflow.indexOf("  macos:\n");
  const job = workflow.slice(start, end);
  const checkout = job.indexOf("actions/checkout@");
  const indexGate = job.indexOf("scripts/verify-tracked-index.sh .");
  const initialize = job.indexOf("github/codeql-action/init@");
  const analyze = job.indexOf("github/codeql-action/analyze@");
  assert.ok(checkout >= 0 && checkout < indexGate && indexGate < initialize && initialize < analyze);
  assert.equal((job.match(/persist-credentials: false/gu) ?? []).length, 1);
});
