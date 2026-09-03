import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, open, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const project = new URL("../..", import.meta.url).pathname.replace(/\/$/u, "");
const gate = join(project, "scripts", "verify-tracked-index.sh");
const git = "/usr/bin/git";

function command(executable, argumentsList, options = {}) {
  const { env = {}, ...spawnOptions } = options;
  const result = spawnSync(executable, argumentsList, {
    encoding: "utf8",
    timeout: 30_000,
    maxBuffer: 4 * 1024 * 1024,
    env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", HOME: tmpdir(), LC_ALL: "C", ...env },
    ...spawnOptions
  });
  assert.equal(result.error, undefined, result.error?.message);
  return result;
}

function gitOK(root, ...argumentsList) {
  const result = command(git, ["-C", root, ...argumentsList]);
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "fulmar-index-policy-test."));
  gitOK(root, "init", "--quiet");
  gitOK(root, "config", "core.precomposeunicode", "false");
  await writeFile(join(root, "README.md"), "Fulmar index policy fixture\n", "utf8");
  await mkdir(join(root, "scripts"));
  await writeFile(join(root, "scripts", "fixture.sh"), "#!/bin/sh\nexit 0\n", "utf8");
  gitOK(root, "add", "README.md", "scripts/fixture.sh");
  return root;
}

function runGate(root, env = {}) {
  return command("/bin/bash", ["-p", gate, root], { env });
}

function assertRejected(result, pattern) {
  assert.notEqual(result.status, 0, result.stdout);
  assert.match(result.stderr, pattern);
  assert.doesNotMatch(result.stdout, /policy passed/u);
}

async function withFixture(body) {
  const root = await fixture();
  try { await body(root); }
  finally { await rm(root, { recursive: true, force: true }); }
}

async function addFile(root, path, bytes = "fixture\n") {
  await mkdir(dirname(join(root, path)), { recursive: true });
  await writeFile(join(root, path), bytes);
  gitOK(root, "add", "--", path);
}

function addIndexBlob(root, path, content = "collision fixture\n") {
  const object = command(git, ["-C", root, "hash-object", "-w", "--stdin"], { input: content });
  assert.equal(object.status, 0, object.stderr);
  gitOK(root, "update-index", "--add", "--cacheinfo", "100644", object.stdout.trim(), path);
}

test("tracked-index gate is system-tool-only, rejects a missing Git index honestly, and accepts bounded source blobs", async () => {
  const source = await readFile(gate, "utf8");
  assert.match(source, /^#!\/bin\/bash -p\n/u);
  assert.match(source, /\/usr\/bin\/git/u);
  assert.match(source, /\/usr\/bin\/perl/u);
  assert.doesNotMatch(source, /\b(?:node|python|ruby|curl|npm|npx)\b/u);

  const noGit = await mkdtemp(join(tmpdir(), "fulmar-no-git."));
  try {
    const absent = runGate(noGit);
    assert.equal(absent.status, 2);
    assert.match(absent.stderr, /NOT RUN: this source tree has no Git metadata/u);
  } finally {
    await rm(noGit, { recursive: true, force: true });
  }

  await withFixture(async (root) => {
    const result = runGate(root);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /policy passed for 2 bounded regular source blobs/u);
    assert.match(result.stdout, /does not scan Git history/u);

    const hostileHome = await mkdtemp(join(tmpdir(), "fulmar-hostile-git-home."));
    try {
      const hostileConfig = join(hostileHome, ".gitconfig");
      const bashEnvironment = join(hostileHome, "hostile-bash-environment.sh");
      const environmentMarker = join(hostileHome, "bash-environment-executed");
      const functionMarker = join(hostileHome, "exported-function-executed");
      await writeFile(hostileConfig, "this is deliberately invalid Git configuration\n", "utf8");
      await writeFile(
        bashEnvironment,
        'printf injected > "$FULMAR_BASH_ENV_MARKER"\nfulmar_injected\n',
        { mode: 0o600 }
      );
      const isolated = runGate(root, {
        HOME: hostileHome,
        BASH_ENV: bashEnvironment,
        ENV: bashEnvironment,
        FULMAR_BASH_ENV_MARKER: environmentMarker,
        FULMAR_EXPORTED_FUNCTION_MARKER: functionMarker,
        "BASH_FUNC_fulmar_injected%%":
          '() { printf injected > "$FULMAR_EXPORTED_FUNCTION_MARKER"; }',
        GIT_CONFIG_GLOBAL: hostileConfig,
        GIT_CONFIG_COUNT: "1",
        GIT_CONFIG_KEY_0: "include.path",
        GIT_CONFIG_VALUE_0: hostileConfig
      });
      assert.equal(isolated.status, 0, isolated.stderr);
      assert.match(isolated.stdout, /policy passed for 2 bounded regular source blobs/u);
      await assert.rejects(readFile(environmentMarker), { code: "ENOENT" });
      await assert.rejects(readFile(functionMarker), { code: "ENOENT" });
    } finally {
      await rm(hostileHome, { recursive: true, force: true });
    }
  });
});

test("tracked-index gate rejects generated, private, VendorRuntime-generated, and unapproved roots", async () => {
  for (const [path, pattern] of [
    ["build/private.log", /generated\/private root is tracked: build/u],
    ["recovered-duplicates/private.swift", /generated\/private root is tracked: recovered-duplicates/u],
    ["VendorRuntime/node_modules/unreviewed.js", /generated VendorRuntime content is tracked/u],
    ["NEW.md", /unapproved top-level source entry: NEW\.md/u]
  ]) {
    await withFixture(async (root) => {
      await addFile(root, path);
      assertRejected(runGate(root), pattern);
    });
  }
});

test("tracked-index gate accepts only an exact top-level LICENSE file", async () => {
  await withFixture(async (root) => {
    await addFile(root, "LICENSE", "future owner-selected licence fixture\n");
    const result = runGate(root);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /policy passed for 3 bounded regular source blobs/u);
  });

  await withFixture(async (root) => {
    await addFile(root, "LICENSE/terms.txt", "must remain a top-level file\n");
    assertRejected(runGate(root), /approved top-level file is used as a directory: LICENSE/u);
  });
});

test("tracked-index gate rejects symlinks and gitlinks instead of treating them as source files", async () => {
  await withFixture(async (root) => {
    await symlink("../README.md", join(root, "scripts", "linked.sh"));
    gitOK(root, "add", "scripts/linked.sh");
    assertRejected(runGate(root), /unsafe tracked type or mode.*120000/u);
  });

  await withFixture(async (root) => {
    gitOK(root, "config", "user.name", "Fulmar CI Fixture");
    gitOK(root, "config", "user.email", "fixture@invalid.example");
    gitOK(root, "commit", "--quiet", "-m", "fixture");
    const commit = gitOK(root, "rev-parse", "HEAD");
    gitOK(root, "update-index", "--add", "--cacheinfo", "160000", commit, "docs/submodule");
    assertRejected(runGate(root), /unsafe tracked type or mode.*160000/u);
  });
});

test("tracked-index gate rejects unreviewed executable modes and reviewed executables with a downgraded mode", async () => {
  await withFixture(async (root) => {
    await chmod(join(root, "scripts", "fixture.sh"), 0o755);
    gitOK(root, "add", "scripts/fixture.sh");
    assertRejected(runGate(root), /unapproved executable source mode/u);
  });

  await withFixture(async (root) => {
    await writeFile(join(root, "scripts", "verify-tracked-index.sh"), "#!/bin/bash\nexit 0\n", { mode: 0o644 });
    gitOK(root, "add", "scripts/verify-tracked-index.sh");
    assertRejected(runGate(root), /reviewed executable source lost its executable mode/u);
  });
});

test("tracked-index gate rejects case-folded and Unicode-normalized collisions from index bytes", async () => {
  await withFixture(async (root) => {
    addIndexBlob(root, "docs/Collision.md");
    addIndexBlob(root, "docs/collision.md");
    assertRejected(runGate(root), /case\/Unicode path collision/u);
  });

  await withFixture(async (root) => {
    addIndexBlob(root, "docs/caf\u00e9.md");
    addIndexBlob(root, "docs/cafe\u0301.md");
    assertRejected(runGate(root), /case\/Unicode path collision/u);
  });
});

test("tracked-index gate rejects blobs above 100 MiB and credential or certificate filenames", async () => {
  await withFixture(async (root) => {
    const path = join(root, "Resources", "oversized.bin");
    await mkdir(dirname(path), { recursive: true });
    const handle = await open(path, "w", 0o600);
    try { await handle.truncate(104_857_601); }
    finally { await handle.close(); }
    gitOK(root, "add", "Resources/oversized.bin");
    assertRejected(runGate(root), /tracked blob exceeds 100 MiB/u);
  });

  for (const sensitive of ["docs/client.pem", "Config/.ENV.production", "Tests/token.json"]) {
    await withFixture(async (root) => {
      await addFile(root, sensitive, "not-a-real-secret\n");
      assertRejected(runGate(root), /credential\/certificate filename is tracked/u);
    });
  }
});
