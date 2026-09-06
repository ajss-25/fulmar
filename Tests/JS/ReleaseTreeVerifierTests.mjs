import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, link, mkdir, mkdtemp, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const project = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const verifier = join(project, "scripts", "verify-release-tree.mjs");

function invoke(source, extracted) {
  return spawnSync(process.execPath, [verifier, source, extracted], {
    encoding: "utf8",
    timeout: 30_000
  });
}

function setLinkMode(path, mode) {
  const result = spawnSync("/bin/chmod", ["-h", mode, path], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr || result.stdout);
}

test("release tree ignores only macOS symlink mode masking", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-release-tree."));
  const source = join(root, "source.app");
  const extracted = join(root, "extracted.app");
  try {
    for (const app of [source, extracted]) {
      await mkdir(join(app, "Runtime", "bin"), { recursive: true, mode: 0o755 });
      await chmod(app, 0o755);
      await chmod(join(app, "Runtime"), 0o755);
      await chmod(join(app, "Runtime", "bin"), 0o755);
      await writeFile(join(app, "Runtime", "tool.js"), "reviewed\n", { mode: 0o644 });
      await writeFile(join(app, "Runtime", "alternate.js"), "alternate\n", { mode: 0o644 });
      await chmod(join(app, "Runtime", "tool.js"), 0o644);
      await chmod(join(app, "Runtime", "alternate.js"), 0o644);
      await symlink("../tool.js", join(app, "Runtime", "bin", "tool"));
    }

    setLinkMode(join(source, "Runtime", "bin", "tool"), "0755");
    setLinkMode(join(extracted, "Runtime", "bin", "tool"), "0700");
    let result = invoke(source, extracted);
    assert.equal(result.status, 0, result.stderr || result.stdout);

    await unlink(join(extracted, "Runtime", "bin", "tool"));
    await symlink("../alternate.js", join(extracted, "Runtime", "bin", "tool"));
    result = invoke(source, extracted);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /archive extraction differs/u);

    await unlink(join(extracted, "Runtime", "bin", "tool"));
    await symlink("../tool.js", join(extracted, "Runtime", "bin", "tool"));
    await chmod(join(extracted, "Runtime", "tool.js"), 0o600);
    result = invoke(source, extracted);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /archive extraction differs/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("release tree rejects hard-linked bundle files even when both trees have matching bytes", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-release-tree-hardlink."));
  const source = join(root, "source.app");
  const extracted = join(root, "extracted.app");
  try {
    for (const app of [source, extracted]) {
      await mkdir(join(app, "Contents"), { recursive: true, mode: 0o755 });
      const first = join(app, "Contents", "first");
      await writeFile(first, "same bytes\n", { mode: 0o644 });
      await link(first, join(app, "Contents", "second"));
    }
    const result = invoke(source, extracted);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /must not be hard linked/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("release tree rejects a symbolic app root instead of resolving it before traversal", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-release-tree-root-link."));
  const source = join(root, "source.app");
  const sourceLink = join(root, "source-link.app");
  const extracted = join(root, "extracted.app");
  try {
    for (const app of [source, extracted]) {
      await mkdir(join(app, "Contents"), { recursive: true, mode: 0o755 });
      await writeFile(join(app, "Contents", "artifact"), "same bytes\n", { mode: 0o644 });
    }
    await symlink(source, sourceLink);
    const result = invoke(sourceLink, extracted);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /ELOOP|symbolic|too many levels|not a directory/iu);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
