import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { appendFile, cp, mkdir, mkdtemp, readFile, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const project = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const sanitizer = join(project, "scripts/sanitize-agent-presets.mjs");
const verifier = join(project, "scripts/verify-sanitized-agent-presets.mjs");
const nativePatch = join(project, "Resources/LocalHarness.patch.yml");
const sourcePreset = join(project, "VendorRuntime/node_modules/@deepseek-ai/dsh/config/agent-presets");
const sourceDSH = join(project, "VendorRuntime/node_modules/@deepseek-ai/dsh");
const relativeRoots = Object.freeze(["config/agent-presets"]);

function invoke(script, ...args) {
  return spawnSync(process.execPath, [script, ...args], { encoding: "utf8", timeout: 30_000 });
}

async function fixture() {
  const parent = await realpath(await mkdtemp(join(tmpdir(), "local-harness-sanitized-presets.")));
  const dsh = join(parent, "dsh");
  await mkdir(dsh, { recursive: true });
  await cp(join(sourceDSH, "package.json"), join(dsh, "package.json"));
  await mkdir(join(dsh, "lib"), { recursive: true });
  await cp(join(sourceDSH, "lib/bin.js"), join(dsh, "lib/bin.js"));
  for (const relativeRoot of relativeRoots) {
    const destination = join(dsh, ...relativeRoot.split("/"));
    await mkdir(dirname(destination), { recursive: true });
    await cp(sourcePreset, destination, { recursive: true, force: false });
    const result = invoke(sanitizer, destination);
    assert.equal(result.status, 0, result.stderr || result.stdout);
  }
  return { parent, dsh };
}

async function withFixture(action) {
  const current = await fixture();
  try { await action(current); }
  finally { await rm(current.parent, { recursive: true, force: true }); }
}

test("the packaged Runtime has one authoritative DSH package, CLI, and policy-bound preset root", async () => {
  await withFixture(async ({ dsh }) => {
    const result = invoke(verifier, dsh);
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.match(result.stdout, /Verified one authoritative DSH package, CLI, and exact sanitized preset root/u);

    const compositions = await Promise.all(relativeRoots.map((relativeRoot) =>
      readFile(join(dsh, ...relativeRoot.split("/"), "standard/agent.cordis.yml"), "utf8")
    ));
    assert.doesNotMatch(compositions[0], /dsh-(?:workflow-worker-thread|tool-workflow|tool-ralph)/u);
    assert.match(compositions[0], /^- id: tool-web\n  name: '@deepseek-ai\/dsh-tool-web'\n  config:\n    search: false\n    fetch: true\n    fetchTimeoutMs: 30000\n    fetchMaxOutputChars: 200000$/mu);
    assert.doesNotMatch(compositions[0], /^    search: true$/mu);
    assert.doesNotMatch(compositions[0], /^    fetch: false$/mu);
  });
});

test("the native patch disables workflow consumers together with their disabled worker", async () => {
  const source = await readFile(nativePatch, "utf8");
  for (const id of ["workflow-worker-thread", "tool-workflow", "tool-ralph"]) {
    assert.match(source, new RegExp(`^- id: ${id}\\n(?:  #[^\\n]*\\n)*  disabled: true$`, "m"));
  }
});

test("the native patch disables the upstream filesystem row and inserts the reviewed confined provider", async () => {
  const source = await readFile(nativePatch, "utf8");
  assert.match(source, /^- id: fs-sandbox\n(?:  #[^\n]*\n)*  disabled: true$/mu);
  assert.match(source, /^- insert:\n    - id: fs-confined\n      name: '@local-harness\/dsh-fs-confined'$/mu);
  assert.doesNotMatch(source, /^- id: fs-sandbox\n(?:  #[^\n]*\n)*  name:/mu);
});

test("DSH composes the reviewed filesystem replacement without a skipped name-mismatch patch", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "local-harness-dump-config.")));
  try {
    const result = spawnSync(process.execPath, [
      join(sourceDSH, "lib/bin.js"),
      "web", "--patch", nativePatch, "--dump-config"
    ], {
      encoding: "utf8",
      timeout: 30_000,
      env: {
        ...process.env,
        DSH_HOME: root,
        LOCAL_HARNESS_MCP_CATALOG: join(root, "catalog.json"),
        LOCAL_HARNESS_SANDBOX_HELPER: "/bin/false"
      }
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.doesNotMatch(result.stderr, /name mismatch|skipping/u);
    assert.match(result.stdout, /^- id: fs-sandbox\n  name: '@deepseek-ai\/dsh-fs-sandbox'\n  disabled: true$/mu);
    assert.match(result.stdout, /^- id: fs-confined\n  name: '@local-harness\/dsh-fs-confined'$/mu);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a reintroduced unsafe workflow row fails closed", async () => {
  await withFixture(async ({ dsh }) => {
    const composition = join(dsh, ...relativeRoots[0].split("/"), "standard/agent.cordis.yml");
    await appendFile(composition, "\n- id: tool-workflow\n  name: '@deepseek-ai/dsh-tool-workflow'\n");
    const result = invoke(verifier, dsh);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /unsafe preset row remained|unsafe preset capability remained/u);
  });
});

test("missing and unexpected discoverable preset copies are release failures", async () => {
  await withFixture(async ({ dsh }) => {
    await rm(join(dsh, ...relativeRoots[0].split("/")), { recursive: true, force: true });
    const missing = invoke(verifier, dsh);
    assert.notEqual(missing.status, 0);
    assert.match(missing.stderr, /unexpected discoverable preset roots/u);
  });

  await withFixture(async ({ dsh }) => {
    const extra = join(dsh, "extra/config/agent-presets");
    await mkdir(dirname(extra), { recursive: true });
    await cp(join(dsh, ...relativeRoots[0].split("/")), extra, { recursive: true, force: false });
    const unexpected = invoke(verifier, dsh);
    assert.notEqual(unexpected.status, 0);
    assert.match(unexpected.stderr, /unexpected discoverable preset roots/u);
  });
});

test("a nested DSH self-package is a release failure even when its preset is absent", async () => {
  await withFixture(async ({ dsh }) => {
    const duplicate = join(dsh, "node_modules/@deepseek-ai/dsh");
    await mkdir(join(duplicate, "lib"), { recursive: true });
    await cp(join(sourceDSH, "package.json"), join(duplicate, "package.json"));
    await cp(join(sourceDSH, "lib/bin.js"), join(duplicate, "lib/bin.js"));
    const result = invoke(verifier, dsh);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /unexpected @deepseek-ai\/dsh package roots/u);
  });
});
