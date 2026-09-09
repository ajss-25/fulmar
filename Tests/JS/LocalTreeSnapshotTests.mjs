import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  symlink,
  unlink,
  utimes,
  writeFile
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import {
  LocalTreeSnapshotError,
  snapshotLocalTree,
  writeLocalTreeSnapshot
} from "../../scripts/local-tree-snapshot.mjs";
import { readAttestedRegularFile } from "../../scripts/attested-regular-file.mjs";

async function fixture() {
  const temporary = await mkdtemp(path.join(tmpdir(), "local-tree-snapshot-tests."));
  const root = path.join(temporary, "tree");
  await mkdir(path.join(root, "nested"), { recursive: true, mode: 0o700 });
  await writeFile(path.join(root, "alpha.txt"), "alpha", { mode: 0o600 });
  await writeFile(path.join(root, "nested", "beta.txt"), "beta", { mode: 0o640 });
  await symlink("alpha.txt", path.join(root, "link"));
  return {
    root,
    temporary,
    cleanup: () => rm(temporary, { recursive: true, force: true })
  };
}

function decoded(snapshot) {
  return JSON.parse(snapshot.toString("utf8"));
}

function entry(snapshot, relativePath) {
  return decoded(snapshot).entries.find((candidate) => candidate.path === relativePath);
}

async function expectSnapshotError(action, code) {
  await assert.rejects(action, (error) => {
    assert.ok(error instanceof LocalTreeSnapshotError);
    assert.equal(error.code, code);
    assert.equal(error.message, "Local tree snapshot rejected.");
    return true;
  });
}

test("unchanged trees produce byte-for-byte identical deterministic snapshots", async () => {
  const tree = await fixture();
  try {
    const first = await snapshotLocalTree(tree.root);
    const second = await snapshotLocalTree(tree.root);
    assert.deepEqual(second, first);
    assert.deepEqual(
      decoded(first).entries.map((candidate) => candidate.path),
      [".", "alpha.txt", "link", "nested", "nested/beta.txt"]
    );
    const alpha = entry(first, "alpha.txt");
    assert.deepEqual(Object.keys(alpha), ["path", "type", "mode", "uid", "gid", "size", "mtimeNs", "sha256"]);
    assert.equal(alpha.type, "file");
    assert.equal(alpha.mode, 0o600);
    assert.equal(alpha.uid, String(process.getuid()));
    assert.equal(alpha.gid, String(process.getgid()));
    assert.equal(alpha.size, "5");
    assert.match(alpha.mtimeNs, /^[0-9]+$/u);
    assert.match(alpha.sha256, /^[0-9a-f]{64}$/u);
  } finally {
    await tree.cleanup();
  }
});

test("regular-file byte changes alter the streamed SHA-256 evidence", async () => {
  const tree = await fixture();
  try {
    const before = await snapshotLocalTree(tree.root);
    await writeFile(path.join(tree.root, "alpha.txt"), "omega", { mode: 0o600 });
    const after = await snapshotLocalTree(tree.root);
    assert.notEqual(entry(after, "alpha.txt").sha256, entry(before, "alpha.txt").sha256);
    assert.notDeepEqual(after, before);
  } finally {
    await tree.cleanup();
  }
});

test("POSIX mode changes alter snapshot evidence", async () => {
  const tree = await fixture();
  try {
    const before = await snapshotLocalTree(tree.root);
    await chmod(path.join(tree.root, "alpha.txt"), 0o644);
    const after = await snapshotLocalTree(tree.root);
    assert.equal(entry(before, "alpha.txt").mode, 0o600);
    assert.equal(entry(after, "alpha.txt").mode, 0o644);
    assert.equal(entry(after, "alpha.txt").sha256, entry(before, "alpha.txt").sha256);
    assert.notDeepEqual(after, before);
  } finally {
    await tree.cleanup();
  }
});

test("nanosecond mtime changes alter snapshot evidence", async () => {
  const tree = await fixture();
  try {
    const target = path.join(tree.root, "alpha.txt");
    const before = await snapshotLocalTree(tree.root);
    const info = await lstat(target);
    const changedSeconds = (info.mtimeMs / 1000) + 10;
    await utimes(target, changedSeconds, changedSeconds);
    const after = await snapshotLocalTree(tree.root);
    assert.notEqual(entry(after, "alpha.txt").mtimeNs, entry(before, "alpha.txt").mtimeNs);
    assert.equal(entry(after, "alpha.txt").sha256, entry(before, "alpha.txt").sha256);
    assert.notDeepEqual(after, before);
  } finally {
    await tree.cleanup();
  }
});

test("symlink target changes are recorded without following the link", async () => {
  const tree = await fixture();
  try {
    const before = await snapshotLocalTree(tree.root);
    await unlink(path.join(tree.root, "link"));
    await symlink("nested/beta.txt", path.join(tree.root, "link"));
    const after = await snapshotLocalTree(tree.root);
    assert.equal(entry(before, "link").target, "alpha.txt");
    assert.equal(entry(after, "link").target, "nested/beta.txt");
    assert.notDeepEqual(after, before);
  } finally {
    await tree.cleanup();
  }
});

test("an escaping symlink target is recorded opaquely and never followed", async () => {
  const tree = await fixture();
  try {
    const external = path.join(tree.temporary, "outside.txt");
    await writeFile(external, "outside one", { mode: 0o600 });
    await unlink(path.join(tree.root, "link"));
    await symlink("../outside.txt", path.join(tree.root, "link"));
    const before = await snapshotLocalTree(tree.root);
    await writeFile(external, "outside two", { mode: 0o600 });
    const after = await snapshotLocalTree(tree.root);
    assert.equal(entry(before, "link").target, "../outside.txt");
    assert.deepEqual(after, before);
  } finally {
    await tree.cleanup();
  }
});

test("extra paths alter snapshot evidence", async () => {
  const tree = await fixture();
  try {
    const before = await snapshotLocalTree(tree.root);
    await writeFile(path.join(tree.root, "extra.txt"), "extra", { mode: 0o600 });
    const after = await snapshotLocalTree(tree.root);
    assert.ok(entry(after, "extra.txt"));
    assert.notDeepEqual(after, before);
  } finally {
    await tree.cleanup();
  }
});

test("entry, file, total-byte, depth, path, symlink, and metadata bounds fail closed", async () => {
  const tree = await fixture();
  try {
    await expectSnapshotError(() => snapshotLocalTree(tree.root, { maxEntries: 2 }), "ENTRY_LIMIT");
    await expectSnapshotError(() => snapshotLocalTree(tree.root, { maxFileBytes: 3n }), "FILE_SIZE_LIMIT");
    await expectSnapshotError(
      () => snapshotLocalTree(tree.root, { maxTotalFileBytes: 8n }),
      "TOTAL_SIZE_LIMIT"
    );
    await expectSnapshotError(() => snapshotLocalTree(tree.root, { maxDepth: 1 }), "DEPTH_LIMIT");
    await expectSnapshotError(() => snapshotLocalTree(tree.root, { maxPathBytes: 3 }), "PATH_LIMIT");
    await expectSnapshotError(
      () => snapshotLocalTree(tree.root, { maxSymlinkTargetBytes: 3 }),
      "SYMLINK_LIMIT"
    );
    await expectSnapshotError(
      () => snapshotLocalTree(tree.root, { maxMetadataBytes: 1n }),
      "METADATA_LIMIT"
    );
  } finally {
    await tree.cleanup();
  }
});

test("control-character paths, special files, symlink roots, and in-tree outputs are rejected", async () => {
  const tree = await fixture();
  try {
    await writeFile(path.join(tree.root, "line\nbreak"), "unsafe", { mode: 0o600 });
    await expectSnapshotError(() => snapshotLocalTree(tree.root), "INVALID_PATH");
    await unlink(path.join(tree.root, "line\nbreak"));

    const fifo = path.join(tree.root, "named-pipe");
    const created = spawnSync("/usr/bin/mkfifo", [fifo], { stdio: "ignore" });
    assert.equal(created.status, 0);
    await expectSnapshotError(() => snapshotLocalTree(tree.root), "SPECIAL_FILE");
    await unlink(fifo);

    const rootLink = path.join(tree.temporary, "tree-link");
    await symlink(tree.root, rootLink);
    await expectSnapshotError(() => snapshotLocalTree(rootLink), "INVALID_ROOT");
    await expectSnapshotError(
      () => writeLocalTreeSnapshot(tree.root, path.join(tree.root, "snapshot.json")),
      "OUTPUT_INSIDE_ROOT"
    );
  } finally {
    await tree.cleanup();
  }
});

test("CLI writes a private snapshot silently and reports failures generically", async () => {
  const tree = await fixture();
  try {
    const script = path.resolve("scripts/local-tree-snapshot.mjs");
    const output = path.join(tree.temporary, "snapshot.json");
    const success = spawnSync(process.execPath, [script, tree.root, output], { encoding: "utf8" });
    assert.equal(success.status, 0);
    assert.equal(success.stdout, "");
    assert.equal(success.stderr, "");
    assert.equal((await stat(output)).mode & 0o777, 0o600);
    const snapshot = await readAttestedRegularFile(output, {
      label: "CLI tree snapshot",
      maximumBytes: 1024 * 1024,
      requirePrivateMode: true
    });
    assert.deepEqual(snapshot.bytes, await snapshotLocalTree(tree.root));

    const sensitiveMarker = path.join(tree.temporary, "private-customer-name-does-not-exist");
    const failure = spawnSync(process.execPath, [script, sensitiveMarker, output], { encoding: "utf8" });
    assert.equal(failure.status, 1);
    assert.equal(failure.stdout, "");
    assert.equal(failure.stderr, "Local tree snapshot failed.\n");
    assert.ok(!failure.stderr.includes("private-customer-name"));
  } finally {
    await tree.cleanup();
  }
});
