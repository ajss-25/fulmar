import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  chmod,
  link,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  unlink,
  writeFile
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const project = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const verifier = join(project, "scripts/runtime-inventory.mjs");

async function fixture() {
  const parent = await mkdtemp(join(tmpdir(), "local-harness-runtime-inventory-test."));
  const root = join(parent, "root");
  const manifest = join(parent, "inventory.json");
  await mkdir(join(root, "nested"), { recursive: true, mode: 0o755 });
  await writeFile(join(root, "alpha.txt"), "reviewed bytes\n", { mode: 0o644 });
  await writeFile(join(root, "nested", "target.txt"), "target one\n", { mode: 0o640 });
  await writeFile(join(root, "nested", "other.txt"), "target two\n", { mode: 0o600 });
  await symlink("nested/target.txt", join(root, "current"));
  return { parent, root, manifest };
}

function invoke(...args) {
  return spawnSync(process.execPath, [verifier, ...args], { encoding: "utf8", timeout: 30_000 });
}

function expectPass(result) {
  assert.equal(result.status, 0, result.stderr || result.stdout);
}

function expectFailure(result, pattern) {
  assert.notEqual(result.status, 0, `expected failure, received: ${result.stdout}`);
  assert.match(result.stderr, pattern);
}

async function generate(current) {
  const result = invoke("generate", current.root, current.manifest, "Fixture");
  expectPass(result);
}

async function withFixture(action) {
  const current = await fixture();
  try {
    await action(current);
  } finally {
    await rm(current.parent, { recursive: true, force: true });
  }
}

test("deterministic inventory verifies unchanged directories, files, modes, and internal symlinks", async () => {
  await withFixture(async (current) => {
    await generate(current);
    const first = await readFile(current.manifest);
    expectPass(invoke("verify", current.root, current.manifest, "Fixture"));
    await generate(current);
    assert.deepEqual(await readFile(current.manifest), first);
  });
});

test("prefix verification binds an exact inventoried bootstrap subtree before it executes", async () => {
  await withFixture(async (current) => {
    await generate(current);
    expectPass(invoke("verify-prefix", join(current.root, "nested"), current.manifest, "nested", "Fixture"));
    await writeFile(join(current.root, "nested", "target.txt"), "tampered bootstrap\n", { mode: 0o640 });
    expectFailure(
      invoke("verify-prefix", join(current.root, "nested"), current.manifest, "nested", "Fixture"),
      /inventory prefix nested changed at target\.txt/u
    );
  });
});

test("prefix verification rejects root-mode drift, missing prefixes, and extra files", async () => {
  await withFixture(async (current) => {
    await generate(current);
    await chmod(join(current.root, "nested"), 0o700);
    expectFailure(
      invoke("verify-prefix", join(current.root, "nested"), current.manifest, "nested", "Fixture"),
      /prefix root changed/u
    );
    await chmod(join(current.root, "nested"), 0o755);
    expectFailure(
      invoke("verify-prefix", join(current.root, "nested"), current.manifest, "missing", "Fixture"),
      /prefix is not one reviewed directory/u
    );
    await writeFile(join(current.root, "nested", "extra.txt"), "extra\n", { mode: 0o600 });
    expectFailure(
      invoke("verify-prefix", join(current.root, "nested"), current.manifest, "nested", "Fixture"),
      /extra entry extra\.txt/u
    );
  });
});

test("streamed hashing verifies a multi-chunk file", async () => {
  await withFixture(async (current) => {
    await writeFile(join(current.root, "large.bin"), randomBytes(3 * 1024 * 1024), { mode: 0o644 });
    await generate(current);
    expectPass(invoke("verify", current.root, current.manifest, "Fixture"));
  });
});

test("file-byte mutation is rejected", async () => {
  await withFixture(async (current) => {
    await generate(current);
    await writeFile(join(current.root, "alpha.txt"), "tampered bytes\n", { mode: 0o644 });
    expectFailure(invoke("verify", current.root, current.manifest, "Fixture"), /changed at alpha\.txt/u);
  });
});

test("an extra filesystem entry is rejected", async () => {
  await withFixture(async (current) => {
    await generate(current);
    await writeFile(join(current.root, "extra.txt"), "extra\n", { mode: 0o644 });
    expectFailure(invoke("verify", current.root, current.manifest, "Fixture"), /extra entry extra\.txt/u);
  });
});

test("a missing filesystem entry is rejected", async () => {
  await withFixture(async (current) => {
    await generate(current);
    await unlink(join(current.root, "alpha.txt"));
    expectFailure(invoke("verify", current.root, current.manifest, "Fixture"), /missing alpha\.txt/u);
  });
});

test("a regular-file mode mutation is rejected", async () => {
  await withFixture(async (current) => {
    await generate(current);
    await chmod(join(current.root, "alpha.txt"), 0o600);
    expectFailure(invoke("verify", current.root, current.manifest, "Fixture"), /changed at alpha\.txt/u);
  });
});

test("a symlink-target mutation is rejected", async () => {
  await withFixture(async (current) => {
    await generate(current);
    await unlink(join(current.root, "current"));
    await symlink("nested/other.txt", join(current.root, "current"));
    expectFailure(invoke("verify", current.root, current.manifest, "Fixture"), /changed at current/u);
  });
});

test("absolute, escaping, dangling, and cyclic symlinks are rejected during generation", async () => {
  for (const target of ["/etc/passwd", "../outside.txt", "missing", "self"]) {
    await withFixture(async (current) => {
      await writeFile(join(current.parent, "outside.txt"), "outside\n", { mode: 0o600 });
      await symlink(target, join(current.root, "self"));
      expectFailure(invoke("generate", current.root, current.manifest, "Fixture"), /symlink/u);
    });
  }
});

test("special filesystem objects are rejected", async () => {
  await withFixture(async (current) => {
    const fifo = join(current.root, "pipe");
    const created = spawnSync("/usr/bin/mkfifo", [fifo], { encoding: "utf8" });
    assert.equal(created.status, 0, created.stderr);
    expectFailure(invoke("generate", current.root, current.manifest, "Fixture"), /unsupported filesystem object/u);
  });
});

test("control characters in filesystem names are rejected", async () => {
  await withFixture(async (current) => {
    await writeFile(join(current.root, "bad\nname"), "no\n", { mode: 0o600 });
    expectFailure(invoke("generate", current.root, current.manifest, "Fixture"), /unsafe path segment/u);
  });
});

test("hard-linked regular files are rejected", async () => {
  await withFixture(async (current) => {
    await link(join(current.root, "alpha.txt"), join(current.root, "alpha-alias.txt"));
    expectFailure(invoke("generate", current.root, current.manifest, "Fixture"), /hard-linked/u);
  });
});

test("traversal and case-normalized duplicates in a canonical manifest are rejected", async () => {
  await withFixture(async (current) => {
    await generate(current);
    const traversal = JSON.parse(await readFile(current.manifest, "utf8"));
    traversal.entries[0].path = "../escape";
    await writeFile(current.manifest, `${JSON.stringify(traversal, null, 2)}\n`, { mode: 0o644 });
    expectFailure(invoke("verify", current.root, current.manifest, "Fixture"), /safe bounded relative path|unsafe path segment/u);

    await generate(current);
    const duplicate = JSON.parse(await readFile(current.manifest, "utf8"));
    const original = duplicate.entries.find((entry) => entry.path === "alpha.txt");
    const copy = { ...original, path: "ALPHA.txt" };
    duplicate.entries.push(copy);
    duplicate.entries.sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));
    duplicate.entryCount += 1;
    duplicate.totalFileBytes = String(BigInt(duplicate.totalFileBytes) + BigInt(copy.size));
    await writeFile(current.manifest, `${JSON.stringify(duplicate, null, 2)}\n`, { mode: 0o644 });
    expectFailure(invoke("verify", current.root, current.manifest, "Fixture"), /duplicate case\/canonical-normalized manifest path/u);
  });
});

test("signing transition rejects a mutation outside the exact Mach-O allowlist", async () => {
  await withFixture(async (current) => {
    await writeFile(join(current.root, "node"), Buffer.from([0xfe, 0xed, 0xfa, 0xcf, 0, 0, 0, 1]), { mode: 0o755 });
    expectPass(invoke("generate", current.root, current.manifest, "Runtime"));
    const signables = join(current.parent, "signables.json");
    const finalManifest = join(current.parent, "final.json");
    expectPass(invoke("create-signables", current.root, current.manifest, signables));
    await writeFile(join(current.root, "alpha.txt"), "changed outside signing\n", { mode: 0o644 });
    expectFailure(
      invoke("verify-signing-transition", current.manifest, current.root, signables, finalManifest),
      /non-signable Runtime entry changed during signing/u
    );
  });
});

test("signing transition permits only declared Mach-O bytes and seals their exact final state", async () => {
  await withFixture(async (current) => {
    const node = join(current.root, "node");
    await writeFile(node, Buffer.from([0xfe, 0xed, 0xfa, 0xcf, 0, 0, 0, 1]), { mode: 0o755 });
    expectPass(invoke("generate", current.root, current.manifest, "Runtime"));
    const signables = join(current.parent, "signables.json");
    const finalManifest = join(current.parent, "final.json");
    expectPass(invoke("create-signables", current.root, current.manifest, signables));
    await writeFile(node, Buffer.from([0xfe, 0xed, 0xfa, 0xcf, 0, 0, 0, 2]), { mode: 0o755 });
    expectPass(invoke("verify-signing-transition", current.manifest, current.root, signables, finalManifest));
    expectPass(invoke("verify-signed-runtime", current.manifest, current.root, signables, finalManifest));
    await writeFile(node, Buffer.from([0xfe, 0xed, 0xfa, 0xcf, 0, 0, 0, 3]), { mode: 0o755 });
    expectFailure(
      invoke("verify-signed-runtime", current.manifest, current.root, signables, finalManifest),
      /extracted signed Runtime changed at node/u
    );
  });
});
