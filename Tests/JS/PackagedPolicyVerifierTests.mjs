import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const project = process.cwd();
const verifier = join(project, "scripts", "verify-packaged-policy.mjs");

async function fixture() {
  const root = await realpath(await mkdtemp(join(tmpdir(), "fulmar-packaged-policy-")));
  const presetRoot = join(root, "presets");
  const standard = join(presetRoot, "standard");
  await mkdir(standard, { recursive: true, mode: 0o700 });
  for (const name of ["agent.cordis.yml", "preset.yml"]) {
    await copyFile(
      join(project, "VendorRuntime", "node_modules", "@deepseek-ai", "dsh", "config", "agent-presets", "standard", name),
      join(standard, name)
    );
  }
  await execFileAsync(process.execPath, [join(project, "scripts", "sanitize-agent-presets.mjs"), presetRoot]);
  const runtime = join(root, "Runtime");
  const packageRoot = join(runtime, "dsh", "node_modules", "fixture-package");
  await mkdir(packageRoot, { recursive: true, mode: 0o700 });
  await writeFile(join(packageRoot, "package.json"), JSON.stringify({ name: "fixture-package", version: "1.0.0", license: "MIT" }));
  await writeFile(join(packageRoot, "LICENSE"), "MIT fixture licence\n");
  await writeFile(join(runtime, "NODE_LICENSE"), "Node fixture licence\n");
  await writeFile(join(runtime, "package-lock.json"), JSON.stringify({
    name: "fixture-runtime",
    version: "1.0.0",
    lockfileVersion: 3,
    packages: {
      "": { name: "fixture-runtime", version: "1.0.0" },
      "node_modules/fixture-package": { version: "1.0.0", license: "MIT" }
    }
  }));
  const overrides = join(root, "overrides.json");
  await writeFile(overrides, JSON.stringify({ schemaVersion: 1, overrides: [] }));
  const notices = join(root, "THIRD_PARTY_NOTICES.md");
  await execFileAsync(process.execPath, [
    join(project, "scripts", "generate-third-party-notices.mjs"),
    join(project, "Resources", "THIRD_PARTY_NOTICES.md"),
    runtime,
    overrides,
    notices
  ]);
  const patch = join(root, "LocalHarness.patch.yml");
  await copyFile(join(project, "Resources", "LocalHarness.patch.yml"), patch);
  return { root, patch, preset: join(standard, "agent.cordis.yml"), notices };
}

async function verify({ patch, preset, notices }) {
  return execFileAsync(process.execPath, [verifier, patch, preset, notices]);
}

test("packaged policy verifier accepts the generated notices and sanitized standard preset", async () => {
  const files = await fixture();
  try {
    const result = await verify(files);
    assert.match(result.stdout, /Packaged DSH policy and dependency notices verified/u);
  } finally {
    await rm(files.root, { recursive: true, force: true });
  }
});

test("packaged policy verifier rejects dependency, composition, and file-topology drift", async () => {
  for (const mutate of [
    async (files) => {
      const text = await readFile(files.notices, "utf8");
      await writeFile(files.notices, text.replace(/^\| `dsh\/node_modules\/[^\n]+\n/mu, ""));
    },
    async (files) => {
      const text = await readFile(files.patch, "utf8");
      await writeFile(files.patch, text.replace("id: code-runtime\n  disabled: true", "id: code-runtime\n  disabled: false"));
    },
    async (files) => {
      const text = await readFile(files.preset, "utf8");
      await writeFile(files.preset, text.replace("    search: false", "    search: true"));
    },
    async (files) => {
      const target = join(files.root, "linked-notices.md");
      await symlink(files.notices, target);
      files.notices = target;
    }
  ]) {
    const files = await fixture();
    try {
      await mutate(files);
      await assert.rejects(verify(files));
    } finally {
      await rm(files.root, { recursive: true, force: true });
    }
  }
});
