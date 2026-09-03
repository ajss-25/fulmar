import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const project = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const materializer = join(project, "scripts", "materialize-local-plugin-dependencies.mjs");
const expectedLocal = Object.freeze({
  "@local-harness/dsh-client-security-bridge": "1.2.1",
  "@local-harness/dsh-credentials-keychain": "1.0.8",
  "@local-harness/dsh-fs-confined": "1.0.0",
  "@local-harness/dsh-mcp-guarded": "1.0.0",
  "@local-harness/dsh-performance-profile": "1.2.0",
  "@local-harness/dsh-web-fetch-safe": "1.0.0"
});

function invoke(manifest) {
  return spawnSync(process.execPath, [materializer, manifest, project], { encoding: "utf8" });
}

async function fixture(dependencies = { "@deepseek-ai/dsh-base": "0.1.1-rc.1", "@local-harness/dsh-credentials-keychain": "1.0.3" }) {
  const root = await mkdtemp(join(tmpdir(), "local-harness-runtime-manifest."));
  const manifest = join(root, "package.json");
  await writeFile(manifest, `${JSON.stringify({
    name: "@deepseek-ai/dsh",
    version: "0.1.1-rc.1",
    private: true,
    dependencies
  }, null, 2)}\n`, { mode: 0o640 });
  return { root, manifest };
}

test("materializes the exact signed local dependency closure deterministically", async () => {
  const current = await fixture();
  try {
    const first = invoke(current.manifest);
    assert.equal(first.status, 0, first.stderr);
    const bytes = await readFile(current.manifest);
    const value = JSON.parse(bytes.toString("utf8"));
    assert.deepEqual(
      Object.fromEntries(Object.entries(value.dependencies).filter(([name]) => name.startsWith("@local-harness/"))),
      expectedLocal
    );
    assert.equal((await stat(current.manifest)).mode & 0o777, 0o640);
    const second = invoke(current.manifest);
    assert.equal(second.status, 0, second.stderr);
    assert.deepEqual(await readFile(current.manifest), bytes);
  } finally {
    await rm(current.root, { recursive: true, force: true });
  }
});

test("rejects unknown local dependencies and linked destination manifests", async () => {
  const unknown = await fixture({ "@local-harness/unknown": "1.0.0" });
  try {
    const result = invoke(unknown.manifest);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /unreviewed Fulmar local dependency/u);
  } finally {
    await rm(unknown.root, { recursive: true, force: true });
  }

  const linked = await fixture();
  try {
    const target = join(linked.root, "target.json");
    await writeFile(target, await readFile(linked.manifest), { mode: 0o640 });
    await rm(linked.manifest);
    await symlink(target, linked.manifest);
    const result = invoke(linked.manifest);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /unsafe regular file/u);
  } finally {
    await rm(linked.root, { recursive: true, force: true });
  }
});

test("rejects absent, partial, and version-drifted local dependency closures", async () => {
  const cases = [
    { "@deepseek-ai/dsh-base": "0.1.1-rc.1" },
    {
      "@deepseek-ai/dsh-base": "0.1.1-rc.1",
      "@local-harness/dsh-credentials-keychain": "1.0.8",
      "@local-harness/dsh-client-security-bridge": "1.2.1"
    },
    {
      "@deepseek-ai/dsh-base": "0.1.1-rc.1",
      ...expectedLocal,
      "@local-harness/dsh-performance-profile": "9.9.9"
    }
  ];
  for (const dependencies of cases) {
    const current = await fixture(dependencies);
    try {
      const result = invoke(current.manifest);
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /unreviewed Fulmar local dependency/u);
    } finally {
      await rm(current.root, { recursive: true, force: true });
    }
  }
});
