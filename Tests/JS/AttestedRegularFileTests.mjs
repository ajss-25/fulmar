import assert from "node:assert/strict";
import { link, mkdir, mkdtemp, open, rename, rm, rmdir, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  readAttestedRegularFile, readAttestedRegularFileSync, withAttestedDirectory
} from "../../scripts/attested-regular-file.mjs";

test("attested regular-file reader returns only bytes from one stable no-follow descriptor", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-attested-file-stable."));
  try {
    const path = join(root, "artifact.json");
    await writeFile(path, "reviewed bytes\n", { mode: 0o600 });
    const result = await readAttestedRegularFile(path, {
      label: "fixture artifact",
      minimumBytes: 1,
      maximumBytes: 1024,
      requireCurrentUser: true,
      requirePrivateMode: true,
      requireSingleLink: true
    });
    assert.equal(result.bytes.toString("utf8"), "reviewed bytes\n");
    assert.equal(result.metadata.nlink, 1n);
    const synchronous = readAttestedRegularFileSync(path, {
      label: "synchronous fixture artifact",
      minimumBytes: 1,
      maximumBytes: 1024,
      requireCurrentUser: true,
      requirePrivateMode: true,
      requireSingleLink: true
    });
    assert.equal(synchronous.bytes.toString("utf8"), "reviewed bytes\n");
    assert.equal(synchronous.metadata.nlink, 1n);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("attested regular-file reader rejects symbolic and hard-linked inputs", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-attested-file-links."));
  try {
    const target = join(root, "target");
    const symbolic = join(root, "symbolic");
    const hard = join(root, "hard");
    await writeFile(target, "reviewed", { mode: 0o600 });
    await symlink(target, symbolic);
    await assert.rejects(
      readAttestedRegularFile(symbolic, { maximumBytes: 1024 }),
      /ELOOP|symbolic|too many levels/iu
    );
    assert.throws(
      () => readAttestedRegularFileSync(symbolic, { maximumBytes: 1024 }),
      /ELOOP|symbolic|too many levels/iu
    );
    assert.throws(
      () => readAttestedRegularFileSync(target, { maximumBytes: 2 }),
      /permitted byte bounds/u
    );
    await link(target, hard);
    await assert.rejects(
      readAttestedRegularFile(target, { maximumBytes: 1024 }),
      /must not be hard linked/u
    );
    assert.throws(
      () => readAttestedRegularFileSync(target, { maximumBytes: 1024 }),
      /must not be hard linked/u
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("attested regular-file reader rejects an atomic pathname replacement after open", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-attested-file-rename."));
  try {
    const path = join(root, "artifact");
    const displaced = join(root, "displaced");
    await writeFile(path, "original", { mode: 0o600 });
    await assert.rejects(
      readAttestedRegularFile(path, {
        maximumBytes: 1024,
        afterOpen: async () => {
          await rename(path, displaced);
          await writeFile(path, "attacker", { mode: 0o600 });
        }
      }),
      /path changed before its bytes were read/u
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("attested regular-file reader rejects same-size mutation during a multi-chunk read", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-attested-file-mutate."));
  try {
    const path = join(root, "artifact");
    await writeFile(path, Buffer.alloc(2 * 1024 * 1024, 0x41), { mode: 0o600 });
    let mutated = false;
    await assert.rejects(
      readAttestedRegularFile(path, {
        maximumBytes: 3 * 1024 * 1024,
        chunkBytes: 64 * 1024,
        afterChunk: async ({ chunkIndex }) => {
          if (chunkIndex !== 0 || mutated) return;
          mutated = true;
          const writer = await open(path, "r+");
          try {
            await writer.write(Buffer.from("B"), 0, 1, 1024 * 1024);
            await writer.sync();
          } finally {
            await writer.close();
          }
        }
      }),
      /changed while its bytes were read/u
    );
    assert.equal(mutated, true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("attested directory traversal accepts one stable no-follow directory", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-attested-directory-stable."));
  try {
    const directory = join(root, "evidence");
    await mkdir(directory, { mode: 0o700 });
    const value = await withAttestedDirectory(directory, {
      label: "fixture evidence directory",
      requireCurrentUser: true,
      requirePrivateMode: true
    }, async ({ metadata }) => metadata.ino);
    assert.equal(typeof value, "bigint");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("attested directory traversal rejects an initial symbolic directory", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-attested-directory-symlink."));
  try {
    const target = join(root, "target");
    const symbolic = join(root, "symbolic");
    await mkdir(target, { mode: 0o700 });
    await symlink(target, symbolic);
    await assert.rejects(
      withAttestedDirectory(symbolic, { requirePrivateMode: true }, async () => undefined),
      /ELOOP|symbolic|too many levels|not a directory/iu
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("attested directory traversal rejects atomic directory replacement before descent", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-attested-directory-rename."));
  try {
    const directory = join(root, "evidence");
    const displaced = join(root, "displaced");
    await mkdir(directory, { mode: 0o700 });
    let traversed = false;
    await assert.rejects(
      withAttestedDirectory(directory, {
        requirePrivateMode: true,
        afterOpen: async () => {
          await rename(directory, displaced);
          await mkdir(directory, { mode: 0o700 });
        }
      }, async () => { traversed = true; }),
      /path changed before traversal/u
    );
    assert.equal(traversed, false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("attested directory traversal rejects a directory-to-symlink swap during descent", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-attested-directory-swap."));
  try {
    const directory = join(root, "evidence");
    const displaced = join(root, "displaced");
    const attacker = join(root, "attacker");
    await mkdir(directory, { mode: 0o700 });
    await mkdir(attacker, { mode: 0o700 });
    await assert.rejects(
      withAttestedDirectory(directory, { requirePrivateMode: true }, async () => {
        await rename(directory, displaced);
        await symlink(attacker, directory);
      }),
      /changed during traversal/u
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("attested directory traversal rejects rename-away-and-restore ABA substitution", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-attested-directory-aba."));
  try {
    const directory = join(root, "evidence");
    const displaced = join(root, "displaced");
    await mkdir(directory, { mode: 0o700 });
    await assert.rejects(
      withAttestedDirectory(directory, { requirePrivateMode: true }, async () => {
        await rename(directory, displaced);
        await mkdir(directory, { mode: 0o700 });
        await rmdir(directory);
        await rename(displaced, directory);
      }),
      /changed during traversal/u
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("attested read-only directory traversal rejects child-set mutation during descent", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-attested-directory-child-set."));
  try {
    const directory = join(root, "evidence");
    await mkdir(directory, { mode: 0o700 });
    await assert.rejects(
      withAttestedDirectory(directory, { requirePrivateMode: true }, async () => {
        await writeFile(join(directory, "late-artifact"), "unreviewed", { mode: 0o600 });
      }),
      /changed during traversal/u
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("attested output-directory guard permits child-file writes but still rejects directory replacement", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-attested-output-directory."));
  try {
    const directory = join(root, "output");
    const displaced = join(root, "displaced");
    await mkdir(directory, { mode: 0o700 });
    await withAttestedDirectory(directory, {
      allowContentMutation: true,
      requirePrivateMode: true
    }, async () => writeFile(join(directory, "artifact"), "reviewed", { mode: 0o600 }));

    await assert.rejects(
      withAttestedDirectory(directory, {
        allowContentMutation: true,
        requirePrivateMode: true,
        afterOpen: async () => {
          await rename(directory, displaced);
          await mkdir(directory, { mode: 0o700 });
        }
      }, async () => undefined),
      /path changed before traversal/u
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
