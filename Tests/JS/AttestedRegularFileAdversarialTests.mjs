import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  closeSync, constants, existsSync, fstatSync, fsyncSync, mkdirSync, openSync,
  readFileSync, readdirSync, renameSync, rmdirSync, symlinkSync, truncateSync, writeFileSync, writeSync
} from "node:fs";
import {
  chmod, link, mkdir, mkdtemp, open, realpath, rename, rm, rmdir, symlink, truncate, utimes, writeFile
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  readAttestedRegularFile,
  readAttestedRegularFileSync,
  publishAttestedRegularFileSync,
  sha256AttestedRegularFile,
  withAttestedDirectory,
  withAttestedDirectorySync
} from "../../scripts/attested-regular-file.mjs";
import { publishFromAnchoredWorkingDirectorySync } from "../../scripts/attested-publication-worker.mjs";

const currentUID = process.getuid();

async function fixtureRoot(prefix) {
  return realpath(await mkdtemp(join(tmpdir(), prefix)));
}

function probeRead(path) {
  try { return readFileSync(path, "utf8"); } catch (error) { if (error?.code === "ENOENT") return null; throw error; }
}

function probeErrorText(error) {
  if (!(error instanceof Error)) return String(error);
  const nested = error instanceof AggregateError ? error.errors.map(probeErrorText) : [];
  return [error.message, ...nested].join(" | ");
}

function runPublicationWorkerProbe() {
  if (process.argv[2] !== "--publication-worker-probe") return false;
  const phase = process.argv[3];
  const directory = resolve(process.argv[4]);
  const publishMode = process.argv[5];
  const displaced = `${directory}.displaced`;
  const destinationLeaf = "result";
  const descriptor = openSync(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  const metadata = fstatSync(descriptor, { bigint: true });
  const specification = {
    schemaVersion: 1,
    canonicalDirectory: directory,
    destinationLeaf,
    publishMode,
    fileMode: 0o600,
    maximumBytes: 64,
    label: "publication probe",
    directoryIdentity: Object.fromEntries(
      ["dev", "ino", "mode", "uid", "gid"].map((field) => [field, metadata[field].toString()])
    )
  };
  const swapDirectory = () => {
    renameSync(directory, displaced);
    mkdirSync(directory, { mode: 0o700 });
  };
  const hooks = {};
  if (phase === "after-anchor-directory-swap") hooks.afterAnchor = swapDirectory;
  if (phase === "after-write-directory-swap") hooks.afterWrite = swapDirectory;
  if (phase === "after-commit-directory-swap") hooks.afterCommit = swapDirectory;
  if (phase === "after-commit-aba") {
    hooks.afterCommit = () => {
      swapDirectory();
      rmdirSync(directory);
      renameSync(displaced, directory);
    };
  }
  if (phase === "destination-substitute") {
    hooks.afterWrite = ({ destinationLeaf: leaf }) => {
      renameSync(leaf, "owned-aside");
      writeFileSync(leaf, "attacker", { mode: 0o600 });
    };
  }
  if (phase === "destination-same-inode-mutate") {
    hooks.afterWrite = ({ destinationLeaf: leaf }) => {
      const writer = openSync(leaf, "r+");
      try { writeSync(writer, Buffer.from("attacker"), 0, 8, 0); fsyncSync(writer); } finally { closeSync(writer); }
    };
  }
  if (phase === "committed-same-inode-mutate") {
    hooks.afterCommit = ({ destinationLeaf: leaf }) => {
      const writer = openSync(leaf, "r+");
      try { writeSync(writer, Buffer.from("attacker"), 0, 8, 0); fsyncSync(writer); } finally { closeSync(writer); }
    };
  }
  process.chdir(directory);
  if (phase === "existing-destination" || phase === "upsert-existing") {
    writeFileSync(destinationLeaf, "original", { mode: 0o600 });
  }
  let error = null;
  try {
    publishFromAnchoredWorkingDirectorySync(specification, Buffer.from("reviewed"), {
      directoryDescriptor: descriptor,
      hooks
    });
  } catch (caught) {
    error = probeErrorText(caught);
  } finally {
    closeSync(descriptor);
  }
  const result = {
    error,
    canonicalEntries: existsSync(directory) ? readdirSync(directory).sort() : null,
    displacedEntries: existsSync(displaced) ? readdirSync(displaced).sort() : null,
    canonicalDestination: probeRead(join(directory, destinationLeaf)),
    displacedDestination: probeRead(join(displaced, destinationLeaf)),
    canonicalAside: probeRead(join(directory, "owned-aside")),
    displacedAside: probeRead(join(displaced, "owned-aside"))
  };
  process.stdout.write(`${JSON.stringify(result)}\n`);
  process.exit(0);
}

runPublicationWorkerProbe();

test("owner-controlled mode accepts 0644 and rejects 0664/0666 for files and directories", async () => {
  const root = await fixtureRoot("fulmar-attested-owner-mode.");
  try {
    const path = join(root, "artifact.json");
    await writeFile(path, "{}\n", { mode: 0o644 });
    await chmod(path, 0o644);
    const accepted = await readAttestedRegularFile(path, { maximumBytes: 64, requireOwnerControlledMode: true });
    assert.equal(accepted.bytes.toString("utf8"), "{}\n");
    assert.equal(readAttestedRegularFileSync(path, { maximumBytes: 64, requireOwnerControlledMode: true }).bytes.length, 3);
    for (const mode of [0o664, 0o666]) {
      await chmod(path, mode);
      await assert.rejects(
        readAttestedRegularFile(path, { maximumBytes: 64, requireOwnerControlledMode: true }),
        /group- or world-writable/u
      );
      assert.throws(
        () => readAttestedRegularFileSync(path, { maximumBytes: 64, requireOwnerControlledMode: true }),
        /group- or world-writable/u
      );
    }
    await chmod(path, 0o666);
    const unconstrained = await readAttestedRegularFile(path, { maximumBytes: 64 });
    assert.equal(unconstrained.bytes.length, 3);

    const directory = join(root, "evidence");
    await mkdir(directory, { mode: 0o755 });
    await chmod(directory, 0o755);
    await withAttestedDirectory(directory, { requireOwnerControlledMode: true }, async () => undefined);
    withAttestedDirectorySync(directory, { requireOwnerControlledMode: true }, () => undefined);
    for (const mode of [0o775, 0o777]) {
      await chmod(directory, mode);
      await assert.rejects(
        withAttestedDirectory(directory, { requireOwnerControlledMode: true }, async () => undefined),
        /group- or world-writable/u
      );
      assert.throws(
        () => withAttestedDirectorySync(directory, { requireOwnerControlledMode: true }, () => undefined),
        /group- or world-writable/u
      );
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("accepted owner sets and bounded link counts replace the current-user and single-link rules exactly", async () => {
  const root = await fixtureRoot("fulmar-attested-owner-set.");
  try {
    const path = join(root, "tool");
    await writeFile(path, "binary", { mode: 0o755 });
    const accepted = await sha256AttestedRegularFile(path, {
      maximumBytes: 64, acceptedOwnerUIDs: [0, currentUID], requireOwnerControlledMode: true
    });
    assert.match(accepted.sha256, /^[a-f0-9]{64}$/u);
    await assert.rejects(
      sha256AttestedRegularFile(path, { maximumBytes: 64, acceptedOwnerUIDs: [currentUID + 65_536] }),
      /not owned by one accepted reviewed owner/u
    );
    assert.throws(
      () => readAttestedRegularFileSync(path, { maximumBytes: 64, acceptedOwnerUIDs: [] }),
      /acceptedOwnerUIDs/u
    );
    await link(path, join(root, "tool-alias"));
    await assert.rejects(readAttestedRegularFile(path, { maximumBytes: 64 }), /must not be hard linked/u);
    const bounded = await readAttestedRegularFile(path, { maximumBytes: 64, requireSingleLink: false, maximumLinks: 2 });
    assert.equal(bounded.metadata.nlink, 2n);
    await assert.rejects(
      readAttestedRegularFile(path, { maximumBytes: 64, requireSingleLink: false, maximumLinks: 1 }),
      /exceeds its permitted link count/u
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("canonical-path enforcement rejects a symbolically linked ancestor for files and directories", async () => {
  const root = await fixtureRoot("fulmar-attested-canonical.");
  try {
    const real = join(root, "real");
    await mkdir(real, { mode: 0o700 });
    const path = join(real, "artifact");
    await writeFile(path, "reviewed", { mode: 0o600 });
    const linked = join(root, "linked");
    await symlink(real, linked);
    const viaLink = join(linked, "artifact");
    assert.equal((await readAttestedRegularFile(viaLink, { maximumBytes: 64 })).bytes.toString("utf8"), "reviewed");
    await assert.rejects(
      readAttestedRegularFile(viaLink, { maximumBytes: 64, requireCanonicalPath: true }),
      /not one canonical real path/u
    );
    assert.throws(
      () => readAttestedRegularFileSync(viaLink, { maximumBytes: 64, requireCanonicalPath: true }),
      /not one canonical real path/u
    );
    const sub = join(real, "sub");
    await mkdir(sub, { mode: 0o700 });
    const subViaLink = join(linked, "sub");
    assert.equal(await withAttestedDirectory(subViaLink, {}, async () => "opened"), "opened");
    await assert.rejects(
      withAttestedDirectory(subViaLink, { requireCanonicalPath: true }, async () => undefined),
      /not one canonical real path/u
    );
    assert.throws(
      () => withAttestedDirectorySync(subViaLink, { requireCanonicalPath: true }, () => undefined),
      /not one canonical real path/u
    );
    assert.equal(await withAttestedDirectory(sub, { requireCanonicalPath: true }, async () => "ok"), "ok");
    assert.throws(
      () => withAttestedDirectorySync(linked, {}, () => undefined),
      /ELOOP|ENOTDIR|symbolic|not a directory/iu
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("file readers reject truncation, growth, same-size mutation and timestamp changes after open", async () => {
  const root = await fixtureRoot("fulmar-attested-mutation.");
  try {
    const path = join(root, "artifact");
    const original = Buffer.alloc(4096, 0x41);
    const midRead = async (mutate) => {
      await writeFile(path, original, { mode: 0o600 });
      let fired = false;
      return async ({ chunkIndex }) => {
        if (chunkIndex !== 0 || fired) return;
        fired = true;
        await mutate();
      };
    };
    const readOptions = (afterChunk) => ({ maximumBytes: 8192, chunkBytes: 1024, afterChunk });

    await assert.rejects(
      readAttestedRegularFile(path, readOptions(await midRead(async () => truncate(path, 1024)))),
      /ended before its attested size/u
    );
    await assert.rejects(
      readAttestedRegularFile(path, readOptions(await midRead(async () => {
        const writer = await open(path, "a");
        try { await writer.write(Buffer.from("more")); } finally { await writer.close(); }
      }))),
      /grew while its bytes were read/u
    );
    await assert.rejects(
      readAttestedRegularFile(path, readOptions(await midRead(async () => {
        const writer = await open(path, "r+");
        try { await writer.write(Buffer.from("B"), 0, 1, 3000); } finally { await writer.close(); }
      }))),
      /changed while its bytes were read/u
    );
    await assert.rejects(
      readAttestedRegularFile(path, readOptions(await midRead(async () => utimes(path, new Date(0), new Date(0))))),
      /changed while its bytes were read/u
    );

    // The synchronous reader has no mid-read hook; every post-open mutation is
    // caught by the pathname re-attestation that precedes the read.
    const afterOpenSync = (mutate) => {
      writeFileSync(path, original, { mode: 0o600 });
      return { maximumBytes: 8192, afterOpen: mutate };
    };
    assert.throws(
      () => readAttestedRegularFileSync(path, afterOpenSync(() => {
        const descriptor = openSync(path, "r+");
        try { writeSync(descriptor, Buffer.from("B"), 0, 1, 100); fsyncSync(descriptor); } finally { closeSync(descriptor); }
      })),
      /path changed before its bytes were read/u
    );
    assert.throws(
      () => readAttestedRegularFileSync(path, afterOpenSync(() => {
        const descriptor = openSync(path, "a");
        try { writeSync(descriptor, Buffer.from("tail")); } finally { closeSync(descriptor); }
      })),
      /path changed before its bytes were read/u
    );
    assert.throws(
      () => readAttestedRegularFileSync(path, afterOpenSync(() => { truncateSync(path, 8); })),
      /path changed before its bytes were read/u
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("file readers reject atomic replacement and rename-away-and-restore ABA substitution of the pathname", async () => {
  const root = await fixtureRoot("fulmar-attested-file-aba.");
  try {
    const path = join(root, "artifact");
    const displaced = join(root, "displaced");
    await writeFile(path, "original", { mode: 0o600 });
    await assert.rejects(
      readAttestedRegularFile(path, {
        maximumBytes: 64,
        afterChunk: async () => {
          await rename(path, displaced);
          await writeFile(path, "attacker", { mode: 0o600 });
        }
      }),
      /changed while its bytes were read/u
    );
    await rm(path, { force: true });
    await rename(displaced, path);
    await assert.rejects(
      readAttestedRegularFile(path, {
        maximumBytes: 64,
        afterOpen: async () => {
          await rename(path, displaced);
          await writeFile(path, "original", { mode: 0o600 });
          await rm(path);
          await rename(displaced, path);
          await utimes(path, new Date(1), new Date(1));
        }
      }),
      /path changed before its bytes were read|changed while its bytes were read/u
    );
    assert.throws(
      () => readAttestedRegularFileSync(path, {
        maximumBytes: 64,
        afterOpen: () => {
          renameSync(path, displaced);
          const descriptor = openSync(path, "w", 0o600);
          try { writeSync(descriptor, Buffer.from("attacker")); } finally { closeSync(descriptor); }
        }
      }),
      /path changed before its bytes were read/u
    );
    await rm(path, { force: true });
    await rename(displaced, path);
    assert.equal(readAttestedRegularFileSync(path, { maximumBytes: 64 }).bytes.toString("utf8"), "original");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("directory guards and isolated publication bind every child side effect to the reviewed directory vnode", async () => {
  const root = await fixtureRoot("fulmar-attested-publish.");
  try {
    const directory = join(root, "output");
    await mkdir(directory, { mode: 0o700 });
    const originalWorkingDirectory = process.cwd();
    publishAttestedRegularFileSync(directory, "published", "reviewed", {
      publishMode: "upsert", fileMode: 0o600, maximumBytes: 64
    });
    publishAttestedRegularFileSync(directory, "second", "reviewed", {
      publishMode: "create", fileMode: 0o600, maximumBytes: 64
    });
    assert.equal(process.cwd(), originalWorkingDirectory);
    assert.equal(
      (await readAttestedRegularFile(join(directory, "published"), { maximumBytes: 64 })).bytes.toString("utf8"),
      "reviewed"
    );
    assert.equal(
      readAttestedRegularFileSync(join(directory, "second"), { maximumBytes: 64 }).bytes.toString("utf8"),
      "reviewed"
    );
    assert.throws(
      () => publishAttestedRegularFileSync(directory, "second", "replacement", {
        publishMode: "create", maximumBytes: 64
      }),
      /destination already exists/u
    );
    assert.equal(
      readAttestedRegularFileSync(join(directory, "second"), { maximumBytes: 64 }).bytes.toString("utf8"),
      "reviewed"
    );
    assert.throws(
      () => publishAttestedRegularFileSync(directory, "../escape", "blocked", { maximumBytes: 64 }),
      /safe leaf name/u
    );

    const testFile = fileURLToPath(import.meta.url);
    const runProbe = async (phase, publishMode = "create") => {
      const probeDirectory = join(root, `probe-${phase}`);
      await mkdir(probeDirectory, { mode: 0o700 });
      const child = spawnSync(process.execPath, [
        testFile, "--publication-worker-probe", phase, probeDirectory, publishMode
      ], {
        cwd: originalWorkingDirectory,
        env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", LANG: "C", LC_ALL: "C" },
        encoding: "utf8",
        timeout: 10_000,
        maxBuffer: 1024 * 1024
      });
      assert.equal(child.status, 0, child.stderr);
      assert.equal(child.signal, null);
      assert.equal(child.stderr, "");
      assert.equal(process.cwd(), originalWorkingDirectory);
      return JSON.parse(child.stdout);
    };

    let probe = await runProbe("after-anchor-directory-swap");
    assert.match(probe.error, /exact reviewed publication directory/u);
    assert.deepEqual(probe.canonicalEntries, []);
    assert.deepEqual(probe.displacedEntries, []);

    probe = await runProbe("after-write-directory-swap");
    assert.match(probe.error, /exact reviewed publication directory/u);
    assert.deepEqual(probe.canonicalEntries, []);
    assert.equal(probe.displacedDestination, "reviewed");

    probe = await runProbe("after-commit-directory-swap");
    assert.match(probe.error, /exact reviewed publication directory/u);
    assert.deepEqual(probe.canonicalEntries, []);
    assert.equal(probe.displacedDestination, "reviewed");

    probe = await runProbe("after-commit-aba");
    assert.equal(probe.error, null);
    assert.equal(probe.canonicalDestination, "reviewed");
    assert.equal(probe.displacedEntries, null);

    probe = await runProbe("destination-substitute");
    assert.match(probe.error, /exact publication file/u);
    assert.equal(probe.canonicalDestination, "attacker");
    assert.equal(probe.canonicalAside, "reviewed");

    probe = await runProbe("destination-same-inode-mutate");
    assert.match(probe.error, /unexpected published bytes/u);
    assert.equal(probe.canonicalDestination, "attacker");

    probe = await runProbe("committed-same-inode-mutate");
    assert.match(probe.error, /unexpected published bytes/u);
    assert.equal(probe.canonicalDestination, "attacker");

    probe = await runProbe("existing-destination", "create");
    assert.match(probe.error, /destination already exists/u);
    assert.equal(probe.canonicalDestination, "original");

    probe = await runProbe("upsert-existing", "upsert");
    assert.equal(probe.error, null);
    assert.equal(probe.canonicalDestination, "reviewed");
    assert.equal(process.cwd(), originalWorkingDirectory);

    assert.throws(
      () => withAttestedDirectorySync(directory, {}, () => {
        writeFileSync(join(directory, "late-artifact"), "unreviewed", { mode: 0o600 });
      }),
      /changed during traversal/u
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
test("synchronous directory guard rejects symbolic, replaced, swapped and ABA directories", async () => {
  const root = await fixtureRoot("fulmar-attested-sync-directory.");
  try {
    const directory = join(root, "evidence");
    const displaced = join(root, "displaced");
    const attacker = join(root, "attacker");
    const symbolic = join(root, "symbolic");
    await mkdir(directory, { mode: 0o700 });
    await mkdir(attacker, { mode: 0o700 });
    await symlink(directory, symbolic);
    assert.throws(
      () => withAttestedDirectorySync(symbolic, {}, () => undefined),
      /ELOOP|symbolic|too many levels|not a directory/iu
    );
    let traversed = false;
    assert.throws(
      () => withAttestedDirectorySync(directory, {
        afterOpen: () => {
          renameSync(directory, displaced);
          mkdirSync(directory, { mode: 0o700 });
        }
      }, () => { traversed = true; }),
      /path changed before traversal/u
    );
    assert.equal(traversed, false);
    rmdirSync(directory);
    renameSync(displaced, directory);
    assert.throws(
      () => withAttestedDirectorySync(directory, {}, () => {
        renameSync(directory, displaced);
        symlinkSync(attacker, directory);
      }),
      /changed during traversal/u
    );
    await rm(directory, { force: true });
    await rename(displaced, directory);
    assert.throws(
      () => withAttestedDirectorySync(directory, {}, () => {
        renameSync(directory, displaced);
        mkdirSync(directory, { mode: 0o700 });
        rmdirSync(directory);
        renameSync(displaced, directory);
      }),
      /changed during traversal/u
    );
    const value = withAttestedDirectorySync(directory, { requireOwnerControlledMode: true }, ({ metadata }) => metadata.ino);
    assert.equal(typeof value, "bigint");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
