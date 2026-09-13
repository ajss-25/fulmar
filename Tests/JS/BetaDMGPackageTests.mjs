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
import { createDMG, createImageWithBusyRecovery, exactWholeDisk, formatDMGError, parseArguments, proveCreateRetrySafe, verifyDMG } from "../../scripts/prepare-beta-dmg.mjs";

const project = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const releaseIdentity = JSON.parse(await readFile(join(project, "Config/ReleaseIdentity.json"), "utf8"));
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const EXPECTED_OUTPUTS = ["Fulmar.dmg", "SHA256SUMS.txt", "dmg-binding.json"];
const PRIVATE_INSTALL = "Fulmar — private DMG packaging preview\n\nThis disk image has not been qualified for public distribution.\nDo not install this engineering artifact as a public beta.\nThe Applications shortcut is a packaging preview only.\n\nThe app inside is copied unchanged from the explicitly bound candidate ZIP.\nSigning/notarisation, licensing and installation/provider acceptance are separate release checks.\n";

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

test("private beta DMG arguments require one exact command, operand set, digest and absolute path", async () => {
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
  for (const args of [create, verify]) {
    assert.deepEqual(parseArguments([...args, "--profile", "nonnotarized-beta"]), { ...parseArguments(args), releaseProfile: "nonnotarized-beta" });
    for (const profile of ["private", "beta", "stable", "nonnotarized", "", "NONNOTARIZED-BETA"]) {
      assert.throws(() => parseArguments([...args, "--profile", profile]));
    }
    assert.throws(() => parseArguments(["--profile", "nonnotarized-beta", ...args]));
    assert.throws(() => parseArguments([...args, "--profile", "nonnotarized-beta", "--profile", "nonnotarized-beta"]));
    assert.throws(() => parseArguments([...args, "--profile"]));
  }
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

  // Exercise the production retry coordinator without native commands, mounts,
  // environment switches or extra test topology. Every proof shares one clock.
  const busy = { code: 1, signal: null, stdout: "", stderr: "hdiutil: create failed - Resource busy\n" };
  const success = { code: 0, signal: null, stdout: "created fixture", stderr: "" };
  let clock = 0, attempts = 0, proofs = 0;
  const budgets = [], sleeps = [], recovered = [];
  const result = await createImageWithBusyRecovery({
    now: () => clock,
    sleep: async (ms) => { sleeps.push(ms); clock += ms; },
    attempt: async (budget) => { budgets.push(budget()); clock += 100; return ++attempts < 3 ? busy : success; },
    proveRetrySafe: async (budget) => { proofs += 1; budgets.push(budget()); clock += 1000; },
    recovered: (event) => recovered.push(event)
  });
  assert.equal(result, success);
  assert.equal(attempts, 3); assert.equal(proofs, 2);
  assert.deepEqual(sleeps, [250, 500]);
  assert.ok(budgets.every((value, index) => value <= 180_000 && (index === 0 || value < budgets[index - 1])));
  assert.equal(recovered.length, 1); assert.equal(recovered[0].attempts, 3);
  assert.match(recovered[0].firstFailure.message, /hdiutil: create failed - Resource busy/u);

  for (const rejected of [
    { ...busy, code: 2 }, { ...busy, signal: "SIGTERM" },
    { ...busy, stderr: "hdiutil: create failed - Permission denied" },
    { ...busy, stderr: "hdiutil: create failed - Resource busy\nadditional diagnostic" }
  ]) {
    let calls = 0;
    await assert.rejects(createImageWithBusyRecovery({
      now: () => 0, attempt: async () => { calls += 1; return rejected; },
      sleep: async () => assert.fail("non-matching native failures cannot sleep"),
      proveRetrySafe: async () => assert.fail("non-matching native failures cannot retry")
    }), /hdiutil create failed/u);
    assert.equal(calls, 1);
  }
  for (const phase of ["attempt", "proof", "delay", "proof-deadline", "exhaustion"]) {
    let ticks = 0, calls = 0, proofCalls = 0;
    const injected = new Error(`synthetic ${phase} failure`);
    let failure;
    await assert.rejects(createImageWithBusyRecovery({
      now: () => ticks,
      sleep: async (ms) => { ticks += phase === "delay" ? 180_000 : ms; },
      attempt: async () => { calls += 1; if (phase === "attempt") throw injected; return busy; },
      proveRetrySafe: async (budget) => {
        proofCalls += 1;
        if (phase === "proof") throw injected;
        if (phase === "proof-deadline") ticks += 180_000;
        budget();
      }
    }), (error) => { failure = error; return true; });
    if (phase === "attempt") assert.equal(failure, injected, "native timeout/interruption errors retain their identity");
    else {
      assert.ok(failure instanceof AggregateError);
      assert.match(failure.errors[0].message, /hdiutil: create failed - Resource busy/u);
      if (phase === "proof") assert.equal(failure.errors[1], injected);
      if (phase.includes("deadline") || phase === "delay") assert.match(formatDMGError(failure), /deadline/u);
    }
    assert.equal(calls, phase === "exhaustion" ? 3 : 1);
    assert.equal(proofCalls, phase === "attempt" || phase === "delay" ? 0 : phase === "exhaustion" ? 2 : 1);
  }

  const mount = "/private/fixture/mount";
  const whole = { "dev-entry": "/dev/disk42" };
  const mounted = { "dev-entry": "/dev/disk42s1", "mount-point": mount };
  assert.equal(exactWholeDisk([mounted, whole], mount), "/dev/disk42");
  assert.equal(exactWholeDisk([whole, mounted], mount), "/dev/disk42");
  for (const entities of [[mounted], [mounted, whole, whole], [mounted, mounted, whole], [{ ...mounted, "mount-point": "/foreign" }, whole], [{ ...mounted, "dev-entry": "/dev/disk43s1" }, whole]]) {
    assert.throws(() => exactWholeDisk(entities, mount));
  }
  const inner = new Error("exact native detach cause");
  const nested = new AggregateError([new AggregateError([inner], "detach"), new Error("cleanup")], "outer");
  inner.cause = nested;
  assert.match(formatDMGError(nested), /exact native detach cause/u);
  assert.ok(formatDMGError(new AggregateError(Array.from({ length: 100 }, () => new Error("x".repeat(20_000))), "bounded")).length <= 32_768);
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
        beforeImageCreate: rememberRoot(roots, async ({ root, app, imageSource }) => {
          invoked = true;
          const archive = join(root, "Fulmar.app.zip");
          const dmg = join(root, "Fulmar.dmg");
          const bound = {
            root, app, imageSource, archive, dmg, expectedArchiveSHA256: files.expectedArchiveSHA256,
            archiveIdentity: await lstat(archive, { bigint: true }),
            rootIdentity: await lstat(root, { bigint: true }), sourceIdentity: await lstat(imageSource, { bigint: true })
          };
          const deadline = process.hrtime.bigint() + 180_000_000_000n;
          const budget = () => {
            const remaining = Number((deadline - process.hrtime.bigint()) / 1_000_000n);
            assert.ok(remaining >= 50, "all real retry proofs share one monotonic budget");
            return remaining;
          };
          await proveCreateRetrySafe(bound, budget);
          await writeFile(dmg, "partial image must not be overwritten", { flag: "wx", mode: 0o600 });
          await assert.rejects(proveCreateRetrySafe(bound, budget), /Output already exists/u);
          assert.equal(await readFile(dmg, "utf8"), "partial image must not be overwritten");
          await unlink(dmg);
          await assert.rejects(proveCreateRetrySafe({ ...bound, archiveIdentity: { ...bound.archiveIdentity, ino: bound.archiveIdentity.ino + 1n } }, budget), /Private ZIP identity changed/u);
          await assert.rejects(proveCreateRetrySafe({ ...bound, expectedArchiveSHA256: "0".repeat(64) }, budget), /Private ZIP digest changed/u);
          const extra = join(imageSource, "unplanned.txt");
          await writeFile(extra, "unexpected fixture", { flag: "wx", mode: 0o600 });
          await assert.rejects(proveCreateRetrySafe(bound, budget), /Unexpected image source contents/u);
          await unlink(extra);
          const shortcut = join(imageSource, "Applications");
          await unlink(shortcut); await symlink("/private/foreign", shortcut);
          await assert.rejects(proveCreateRetrySafe(bound, budget), /Applications shortcut was changed/u);
          await unlink(shortcut); await symlink("/Applications", shortcut);
          const instructions = join(imageSource, "INSTALL.txt");
          await writeFile(instructions, "incorrect profile instructions");
          await assert.rejects(proveCreateRetrySafe(bound, budget), /Installation notice does not match/u);
          await writeFile(instructions, PRIVATE_INSTALL);
          const resource = join(imageSource, "Fulmar.app", "Contents", "Resources", "fixture.txt");
          const bytes = await readFile(resource);
          await writeFile(resource, "changed candidate app");
          await assert.rejects(proveCreateRetrySafe(bound, budget));
          await writeFile(resource, bytes);
          await proveCreateRetrySafe(bound, budget);
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
      const binding = await createDMG(accepted, {
        beforePublish: rememberRoot(roots),
        beforeImageCreate: async ({ imageSource }) => {
          assert.equal(await readFile(join(imageSource, "INSTALL.txt"), "utf8"), PRIVATE_INSTALL, "the default private notice remains byte-identical");
        }
      });
      assert.deepEqual((await readdir(accepted.output)).sort(), EXPECTED_OUTPUTS);
      const bindingBytes = await readFile(join(accepted.output, "dmg-binding.json"));
      assert.deepEqual(JSON.parse(bindingBytes), binding);
      assert.equal(binding.type, "fulmar-private-dmg-wrapper");
      assert.equal(Object.hasOwn(binding, "releaseProfile"), false);
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

    await context.test("explicit non-notarised wrapper stays unqualified and rejects both cross-profile images", async () => {
      const options = createOptions("nonnotarized-beta", { releaseProfile: "nonnotarized-beta" });
      const roots = new Set();
      let installText;
      const binding = await createDMG(options, {
        beforePublish: rememberRoot(roots),
        beforeImageCreate: async ({ imageSource }) => {
          installText = await readFile(join(imageSource, "INSTALL.txt"), "utf8");
          assert.notEqual(installText, PRIVATE_INSTALL);
          assert.match(installText, /not Apple-notarised/u);
          assert.match(installText, /Clean installations only/u);
          assert.match(installText, /in-app updater to be disabled/u);
          assert.match(installText, /Do not disable system security controls/u);
          assert.match(installText, /wrapper alone does not qualify/u);
        }
      });
      assert.deepEqual((await readdir(options.output)).sort(), EXPECTED_OUTPUTS);
      assert.equal(binding.type, "fulmar-nonnotarized-beta-dmg-wrapper");
      assert.equal(binding.releaseProfile, "nonnotarized-beta");
      assert.equal(binding.publicBetaQualified, false);
      assert.equal(binding.reproducibleDMGBytes, false);
      const bindingBytes = await readFile(join(options.output, "dmg-binding.json"));
      assert.deepEqual(JSON.parse(bindingBytes), binding);
      assert.deepEqual(binding.candidate, { file: "Fulmar.app.zip", sha256: files.expectedArchiveSHA256 });
      const image = join(options.output, "Fulmar.dmg");
      const imageBytes = await readFile(image);
      assert.deepEqual(binding.image, { file: "Fulmar.dmg", bytes: imageBytes.length, sha256: hash(imageBytes) });
      assert.equal(await readFile(join(options.output, "SHA256SUMS.txt"), "utf8"), `${binding.image.sha256}  Fulmar.dmg\n${hash(bindingBytes)}  dmg-binding.json\n`);
      const verification = { dmg: image, expectedDMGSHA256: binding.image.sha256, archive: files.archive, expectedArchiveSHA256: files.expectedArchiveSHA256, workParent: files.workParent };
      assert.deepEqual(await verifyDMG({ ...verification, releaseProfile: "nonnotarized-beta" }), {
        verified: true, publicBetaQualified: false, candidateSHA256: files.expectedArchiveSHA256,
        dmgSHA256: binding.image.sha256, releaseProfile: "nonnotarized-beta"
      });
      await assert.rejects(verifyDMG(verification), /Installation notice does not match the requested DMG profile/u);
      await assert.rejects(verifyDMG({ ...verification, dmg: join(accepted.output, "Fulmar.dmg"), expectedDMGSHA256, releaseProfile: "nonnotarized-beta" }), /Installation notice does not match the requested DMG profile/u);
      for (const releaseProfile of [null, "beta", "stable", "unknown", false]) {
        const invalid = createOptions("invalid-profile", { releaseProfile });
        await assert.rejects(createDMG(invalid), /usage:/u);
        await absent(invalid.output);
        await assert.rejects(verifyDMG({ ...verification, releaseProfile }), /usage:/u);
      }
      const tampered = createOptions("tampered-nonnotarized-notice", { releaseProfile: "nonnotarized-beta" });
      await assert.rejects(createDMG(tampered, {
        beforeImageCreate: rememberRoot(roots, async ({ imageSource }) => {
          await writeFile(join(imageSource, "INSTALL.txt"), `${installText}Unreviewed additional instruction.\n`);
        })
      }), /Installation notice does not match the requested DMG profile/u);
      await absent(tampered.output);
      await retired(roots);
      assert.deepEqual(await readdir(files.workParent), [], "cross-profile rejection must still detach and retire each verification workspace");
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
        // Match the source-gate emergency cleanup: -x must refuse to traverse
        // the owned mounted filesystem even when surrounding staging is retired.
        const cleanup = spawnSync("/bin/rm", ["-rf", "-x", "--", retainedRoot], {
          cwd: files.root, env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" },
          encoding: "utf8", timeout: 30_000, maxBuffer: 1024 * 1024
        });
        assert.equal(cleanup.error, undefined);
        assert.equal(cleanup.signal, null);
        assert.notEqual(cleanup.status, 0, "a mounted descendant must remain, not be recursively traversed");
        assert.ok((await lstat(retainedRoot)).isDirectory());
        assert.notEqual((await lstat(mountedPath)).dev, (await lstat(retainedRoot)).dev);
        run(process.execPath, [join(project, "scripts", "verify-release-tree.mjs"), files.app, join(mountedPath, "Fulmar.app")], files.root);
        assert.equal(hash(await readFile(image)), imageSHA, "emergency cleanup cannot modify the mounted image");
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
