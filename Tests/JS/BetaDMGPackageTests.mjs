// These tests wrap one tiny, explicitly ad-hoc signed fixture app. They never
// execute that app, sign a production candidate, use a signing identity, access
// Keychain, or qualify a DMG for public distribution. Image operations are
// sequential, against images created inside this invocation's private directory.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, copyFile, link, lstat, mkdir, mkdtemp, open, readFile, readdir, realpath, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { createDMG, parseArguments, verifyDMG } from "../../scripts/prepare-beta-dmg.mjs";

const project = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const releaseIdentity = JSON.parse(await readFile(join(project, "Config/ReleaseIdentity.json"), "utf8"));
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const EXPECTED_OUTPUTS = ["Fulmar.dmg", "SHA256SUMS.txt", "dmg-binding.json"];

function run(executable, args, root) {
  const result = spawnSync(executable, args, {
    cwd: root,
    env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", HOME: root, TMPDIR: root, LANG: "C", LC_ALL: "C" },
    encoding: "utf8",
    timeout: 30_000,
    maxBuffer: 1024 * 1024
  });
  assert.equal(result.error, undefined, "fixture command must complete within its bound");
  assert.equal(result.signal, null, "fixture command must not be interrupted");
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return result;
}

async function absent(path) {
  await assert.rejects(lstat(path), { code: "ENOENT" });
}

async function plistReceipt(root, bytes) {
  const directory = await mkdtemp(join(root, "attachment-receipt."));
  const path = join(directory, "receipt.plist");
  await writeFile(path, bytes, { flag: "wx", mode: 0o600 });
  return JSON.parse(run("/usr/bin/plutil", ["-convert", "json", "-o", "-", path], root).stdout);
}

async function matchingAttachments(root, image) {
  const info = await plistReceipt(root, run("/usr/bin/hdiutil", ["info", "-plist"], root).stdout);
  assert.ok(Array.isArray(info.images), "hdiutil must return its image inventory");
  return info.images.filter((entry) => entry["image-path"] === image);
}

function exactMountedDevice(entities, mount) {
  assert.ok(Array.isArray(entities));
  const mounted = entities.filter((entry) => entry["mount-point"] !== undefined);
  assert.equal(mounted.length, 1, "only the exact fixture mount may be detached");
  assert.equal(mounted[0]["mount-point"], mount);
  // The attach receipt need not list the whole disk first. Identify the device
  // attached at our exact mount, then compare that same entity with fresh info.
  const device = mounted[0]["dev-entry"];
  assert.match(device, /^\/dev\/disk[0-9]+(?:s[0-9]+)?$/u);
  return device;
}

function containsMountedDescendantFailure(error, depth = 0) {
  if (depth > 8 || !(error instanceof Error)) return false;
  return error.message.includes("Unexpected mounted descendant")
    || (error instanceof AggregateError && error.errors.some((cause) => containsMountedDescendantFailure(cause, depth + 1)));
}

async function verifyNoMountedDescendants(root) {
  // Refuse recursive cleanup if a wrapper defect left an attached volume. Do
  // not cross that device boundary or attempt to detach an unrecorded device.
  const original = await lstat(root);
  assert.ok(original.isDirectory() && !original.isSymbolicLink());
  async function visit(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      const current = await lstat(path);
      assert.equal(current.dev, original.dev, "fixture cleanup refuses a still-mounted descendant");
      if (current.isDirectory() && !current.isSymbolicLink()) await visit(path);
    }
  }
  await visit(root);
}

async function fixture() {
  const root = await realpath(await mkdtemp(join(tmpdir(), "fulmar-beta-dmg-fixture.")));
  await chmod(root, 0o700);
  const source = join(root, "source");
  const app = join(source, "Fulmar.app");
  const contents = join(app, "Contents");
  const executable = join(contents, "MacOS", "LocalHarness");
  await mkdir(join(contents, "MacOS"), { recursive: true, mode: 0o755 });
  await mkdir(join(contents, "Resources"), { mode: 0o755 });
  for (const path of [source, app, contents, join(contents, "MacOS"), join(contents, "Resources")]) {
    await chmod(path, 0o755);
  }
  await copyFile("/usr/bin/true", executable);
  await chmod(executable, 0o755);
  await writeFile(join(contents, "Resources", "fixture.txt"), "Only a DMG transport fixture; never execute or distribute.\n", { mode: 0o644 });
  const info = {
    CFBundleDevelopmentRegion: "en",
    CFBundleDisplayName: releaseIdentity.productDisplayName,
    CFBundleExecutable: "LocalHarness",
    CFBundleIdentifier: releaseIdentity.bundleIdentifier,
    CFBundleInfoDictionaryVersion: "6.0",
    CFBundleName: releaseIdentity.productDisplayName,
    CFBundlePackageType: "APPL",
    CFBundleShortVersionString: releaseIdentity.appVersion,
    CFBundleVersion: String(releaseIdentity.appBuild),
    LSMinimumSystemVersion: releaseIdentity.minimumMacOS
  };
  const infoPath = join(contents, "Info.plist");
  await writeFile(infoPath, `${JSON.stringify(info)}\n`, { mode: 0o644 });
  run("/usr/bin/plutil", ["-convert", "xml1", infoPath], root);
  run("/usr/bin/codesign", ["--force", "--sign", "-", "--timestamp=none", app], root);
  run("/usr/bin/codesign", ["--verify", "--deep", "--strict", app], root);
  const archive = join(root, "Fulmar.app.zip");
  run("/usr/bin/ditto", ["-c", "-k", "--sequesterRsrc", "--keepParent", app, archive], root);
  await chmod(archive, 0o600);
  const archiveBytes = await readFile(archive);
  const expectedArchiveSHA256 = hash(archiveBytes);
  const outputParent = join(root, "outputs");
  const workParent = join(root, "verify-work");
  await mkdir(outputParent, { mode: 0o700 });
  await mkdir(workParent, { mode: 0o700 });
  return { root, app, archive, archiveBytes, expectedArchiveSHA256, outputParent, workParent };
}

function rememberRoot(roots, hook) {
  return async (event) => {
    assert.equal(typeof event.root, "string");
    const current = await lstat(event.root);
    assert.ok(current.isDirectory() && !current.isSymbolicLink());
    assert.equal(current.uid, process.getuid());
    assert.equal(current.mode & 0o777, 0o700);
    roots.add(event.root);
    await hook?.(event);
  };
}

async function retired(roots) {
  for (const root of roots) await absent(root);
}

test("private beta DMG arguments require one exact command, operand set, digest and absolute path", () => {
  const archive = "/private/tmp/fulmar-dmg-argument-fixture/Fulmar.app.zip";
  const dmg = "/private/tmp/fulmar-dmg-argument-fixture/Fulmar.dmg";
  const output = "/private/tmp/fulmar-dmg-argument-fixture/output";
  const workParent = "/private/tmp/fulmar-dmg-argument-fixture/work";
  const zipSHA = hash("synthetic ZIP argument, not a candidate");
  const dmgSHA = hash("synthetic DMG argument, not a candidate");
  const create = ["create", archive, zipSHA, output];
  const verify = ["verify", dmg, dmgSHA, archive, zipSHA, workParent];
  assert.deepEqual(parseArguments(create), { command: "create", archive, expectedArchiveSHA256: zipSHA, output });
  assert.deepEqual(parseArguments(verify), { command: "verify", dmg, expectedDMGSHA256: dmgSHA, archive, expectedArchiveSHA256: zipSHA, workParent });
  const invalid = [
    [], ["package", ...create.slice(1)], create.slice(0, -1), [...create, "extra"],
    verify.slice(0, -1), [...verify, "extra"],
    ["create", "relative.zip", zipSHA, output], ["create", archive, zipSHA, "relative-output"],
    ["create", archive, zipSHA.toUpperCase(), output], ["create", archive, zipSHA.slice(1), output],
    ["create", archive, "g".repeat(64), output], ["create", archive, "", output],
    ["verify", "relative.dmg", dmgSHA, archive, zipSHA, workParent],
    ["verify", dmg, dmgSHA, "relative.zip", zipSHA, workParent],
    ["verify", dmg, dmgSHA, archive, zipSHA, "relative-work"],
    ["verify", dmg, "g".repeat(64), archive, zipSHA, workParent],
    ["verify", dmg, dmgSHA, archive, zipSHA.toUpperCase(), workParent]
  ];
  for (const args of invalid) assert.throws(() => parseArguments(args));
});

test("private beta DMG preserves one signed fixture through bounded create, verify and failure cleanup", { timeout: 300_000 }, async (context) => {
  assert.equal(process.platform, "darwin", "the native DMG fixture requires macOS");
  const files = await fixture();
  const createOptions = (name, overrides = {}) => ({ archive: files.archive, expectedArchiveSHA256: files.expectedArchiveSHA256, output: join(files.outputParent, name), ...overrides });
  try {
    await context.test("wrong digest and linked archive fail before image creation", async () => {
      const roots = new Set();
      let imageCreateEntered = false;
      const observers = { afterArchiveSnapshot: rememberRoot(roots), beforeImageCreate: () => { imageCreateEntered = true; } };
      const wrong = createOptions("wrong-digest", { expectedArchiveSHA256: "0".repeat(64) });
      await assert.rejects(createDMG(wrong, observers));
      await absent(wrong.output);
      const symbolic = join(files.root, "linked.zip");
      await symlink(files.archive, symbolic);
      const linked = createOptions("linked-input", { archive: symbolic });
      await assert.rejects(createDMG(linked, observers));
      await absent(linked.output);
      const hardLinked = join(files.root, "hard-linked.zip");
      await link(files.archive, hardLinked);
      try {
        const hard = createOptions("hard-linked-input", { archive: hardLinked });
        await assert.rejects(createDMG(hard, observers));
        await absent(hard.output);
      } finally {
        await unlink(hardLinked);
      }
      assert.equal(imageCreateEntered, false);
      await retired(roots);
    });

    await context.test("an existing output is preserved without image creation", async () => {
      const options = createOptions("existing-output");
      await mkdir(options.output, { mode: 0o700 });
      const sentinel = join(options.output, "owner.txt");
      await writeFile(sentinel, "existing owner data\n", { mode: 0o600 });
      let imageCreateEntered = false;
      await assert.rejects(createDMG(options, { beforeImageCreate: () => { imageCreateEntered = true; } }));
      assert.equal(imageCreateEntered, false);
      assert.deepEqual(await readdir(options.output), ["owner.txt"]);
      assert.equal(await readFile(sentinel, "utf8"), "existing owner data\n");
    });

    await context.test("an injected pre-image failure retires its private staging without output", async () => {
      const options = createOptions("injected-before-image");
      const roots = new Set();
      let invoked = false;
      await assert.rejects(createDMG(options, {
        beforeImageCreate: rememberRoot(roots, () => {
          invoked = true;
          throw new Error("synthetic pre-image failure");
        })
      }), /synthetic pre-image failure/u);
      assert.equal(invoked, true, "the intended boundary must actually be reached");
      await absent(options.output);
      await retired(roots);
    });

    const accepted = createOptions("accepted");
    let expectedDMGSHA256;
    await context.test("create and recipient verification retain the input binding and private-only status", async () => {
      const roots = new Set();
      const binding = await createDMG(accepted, { beforePublish: rememberRoot(roots) });
      assert.deepEqual((await readdir(accepted.output)).sort(), EXPECTED_OUTPUTS);
      const bindingBytes = await readFile(join(accepted.output, "dmg-binding.json"));
      assert.deepEqual(JSON.parse(bindingBytes), binding);
      assert.equal(binding.type, "fulmar-private-dmg-wrapper");
      assert.equal(binding.publicBetaQualified, false);
      assert.equal(binding.reproducibleDMGBytes, false);
      assert.equal(binding.version, releaseIdentity.appVersion);
      assert.equal(binding.build, releaseIdentity.appBuild);
      assert.deepEqual(binding.candidate, { file: "Fulmar.app.zip", sha256: files.expectedArchiveSHA256 });
      const dmgBytes = await readFile(join(accepted.output, "Fulmar.dmg"));
      expectedDMGSHA256 = hash(dmgBytes);
      assert.deepEqual(binding.image, { file: "Fulmar.dmg", bytes: dmgBytes.length, sha256: expectedDMGSHA256 });
      const sums = await readFile(join(accepted.output, "SHA256SUMS.txt"), "utf8");
      assert.deepEqual(sums.trimEnd().split("\n").sort(), [
        `${expectedDMGSHA256}  Fulmar.dmg`,
        `${hash(bindingBytes)}  dmg-binding.json`
      ].sort());
      for (const name of EXPECTED_OUTPUTS) {
        const stat = await lstat(join(accepted.output, name));
        assert.ok(stat.isFile() && !stat.isSymbolicLink());
        assert.equal(stat.nlink, 1);
        assert.equal(stat.uid, process.getuid());
      }
      await retired(roots);
      await verifyDMG({ dmg: join(accepted.output, "Fulmar.dmg"), expectedDMGSHA256, archive: files.archive, expectedArchiveSHA256: files.expectedArchiveSHA256, workParent: files.workParent });
      assert.deepEqual(await readdir(files.workParent), [], "verification must detach and retire its own workspace");
    });

    await context.test("a modified DMG fails its independent expected digest without residual workspace", async () => {
      assert.match(expectedDMGSHA256, /^[a-f0-9]{64}$/u, "the successful DMG must have been produced");
      const damaged = join(files.root, "damaged.dmg");
      await copyFile(join(accepted.output, "Fulmar.dmg"), damaged);
      const handle = await open(damaged, "r+");
      try {
        const byte = Buffer.alloc(1);
        assert.equal((await handle.read(byte, 0, 1, 0)).bytesRead, 1);
        byte[0] ^= 1;
        assert.equal((await handle.write(byte, 0, 1, 0)).bytesWritten, 1);
      } finally {
        await handle.close();
      }
      await assert.rejects(verifyDMG({ dmg: damaged, expectedDMGSHA256, archive: files.archive, expectedArchiveSHA256: files.expectedArchiveSHA256, workParent: files.workParent }));
      assert.deepEqual(await readdir(files.workParent), []);
    });

    await context.test("post-snapshot external ZIP mutation cannot replace the app being wrapped", async () => {
      const external = join(files.root, "mutable-external.zip");
      await copyFile(files.archive, external);
      const options = createOptions("snapshot-preserved", { archive: external });
      const roots = new Set();
      let invoked = false;
      const binding = await createDMG(options, {
        afterArchiveSnapshot: rememberRoot(roots, async ({ archive }) => {
          assert.notEqual(archive, external, "the hook must identify a private snapshot");
          assert.equal(hash(await readFile(archive)), files.expectedArchiveSHA256);
          await writeFile(external, "synthetic external ZIP replacement after admission\n", { mode: 0o600 });
          invoked = true;
        })
      });
      assert.equal(invoked, true);
      assert.notEqual(hash(await readFile(external)), files.expectedArchiveSHA256);
      const bytes = await readFile(join(options.output, "dmg-binding.json"));
      assert.deepEqual(JSON.parse(bytes), binding);
      assert.deepEqual(binding.candidate, { file: "Fulmar.app.zip", sha256: files.expectedArchiveSHA256 });
      assert.equal(binding.publicBetaQualified, false);
      const image = join(options.output, "Fulmar.dmg");
      await verifyDMG({ dmg: image, expectedDMGSHA256: hash(await readFile(image)), archive: files.archive, expectedArchiveSHA256: files.expectedArchiveSHA256, workParent: files.workParent });
      assert.deepEqual(await readdir(files.workParent), []);
      await retired(roots);
    });

    await context.test("an injected pre-publication failure leaves no published output", async () => {
      const options = createOptions("injected-before-publish");
      const roots = new Set();
      let invoked = false;
      await assert.rejects(createDMG(options, {
        beforePublish: rememberRoot(roots, () => {
          invoked = true;
          throw new Error("synthetic pre-publication failure");
        })
      }), /synthetic pre-publication failure/u);
      assert.equal(invoked, true, "the completed roundtrip must reach publication admission");
      await absent(options.output);
      await retired(roots);
    });

    await context.test("cleanup retains an unexpected mounted fixture filesystem without traversing it", async () => {
      const options = createOptions("unexpected-mount");
      const image = join(accepted.output, "Fulmar.dmg");
      const imageSHA = hash(await readFile(image));
      let retainedRoot;
      let mountedPath;
      let fixtureApp;
      let attachedDevice;
      let attachAttempted = false;
      let injected = false;
      let observedRejection;
      try {
        await assert.rejects(createDMG(options, {
          beforeImageCreate: async ({ root, app }) => {
            retainedRoot = root;
            fixtureApp = app;
            mountedPath = join(root, "unexpected-fixture-mount");
            await mkdir(mountedPath, { mode: 0o700 });
            assert.deepEqual(await matchingAttachments(files.root, image), [], "the owned fixture image must not already be attached");
            attachAttempted = true;
            const receipt = await plistReceipt(files.root, run("/usr/bin/hdiutil", [
              "attach", image, "-readonly", "-nobrowse", "-noautoopen", "-owners", "on",
              "-mountpoint", mountedPath, "-plist"
            ], files.root).stdout);
            attachedDevice = exactMountedDevice(receipt["system-entities"], mountedPath);
            const current = await matchingAttachments(files.root, image);
            assert.equal(current.length, 1);
            assert.equal(exactMountedDevice(current[0]["system-entities"], mountedPath), attachedDevice);
            injected = true;
            throw new Error("synthetic failure after attaching a different owned fixture image");
          }
        }), (error) => {
          observedRejection = error;
          return error instanceof AggregateError && containsMountedDescendantFailure(error);
        });
        assert.equal(injected, true, observedRejection.errors[0]?.stack
          ?? "the mounted-filesystem cleanup boundary must actually be reached");
        await absent(options.output);
        assert.ok((await lstat(retainedRoot)).isDirectory(), "cleanup must retain the enclosing private root");
        assert.notEqual((await lstat(mountedPath)).dev, (await lstat(retainedRoot)).dev);
        run(process.execPath, [join(project, "scripts", "verify-release-tree.mjs"), files.app, fixtureApp], files.root);
        run(process.execPath, [join(project, "scripts", "verify-release-tree.mjs"), files.app, join(mountedPath, "Fulmar.app")], files.root);
        assert.equal(hash(await readFile(image)), imageSHA, "the mounted readonly fixture image must remain unchanged");
      } finally {
        // Preabsence plus exact image path, private mount point and fresh device
        // receipt establish ownership. Never detach a preexisting or unrelated
        // image, and never reuse a device number without rechecking the image.
        if (attachAttempted) {
          const current = await matchingAttachments(files.root, image);
          assert.ok(current.length <= 1, "ambiguous attachment is retained for inspection");
          if (current.length === 1) {
            const device = exactMountedDevice(current[0]["system-entities"], mountedPath);
            if (attachedDevice !== undefined) assert.equal(device, attachedDevice);
            const wholeDevice = device.match(/^(\/dev\/disk[0-9]+)(?:s[0-9]+)?$/u)[1];
            assert.ok(current[0]["system-entities"].some((entry) => entry["dev-entry"] === wholeDevice),
              "the whole disk must belong to the freshly matched fixture image");
            run("/usr/bin/hdiutil", ["detach", wholeDevice], files.root);
          }
          assert.deepEqual(await matchingAttachments(files.root, image), []);
        }
        if (retainedRoot !== undefined) {
          await verifyNoMountedDescendants(retainedRoot);
          await rm(retainedRoot, { recursive: true });
          await absent(retainedRoot);
        }
      }
    });
    assert.equal(hash(await readFile(files.archive)), files.expectedArchiveSHA256, "the shared original fixture ZIP must remain unchanged");
  } finally {
    await verifyNoMountedDescendants(files.root);
    await rm(files.root, { recursive: true, force: true });
  }
});
