// Private DMG wrapper, NOT a public-release qualifier. The existing ZIP remains
// the candidate identity. This tool never builds, signs, installs or launches an
// app, and never reads credentials. Expected digests are explicit trusted inputs,
// not values obtained from a sidecar. The public asset contract is unchanged.
import { createHash, randomUUID } from "node:crypto";
import { chmod, link, lstat, mkdir, mkdtemp, open, readdir, readlink, realpath, rm, symlink } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { readAttestedRegularFile, sha256AttestedRegularFile, withAttestedDirectory } from "./attested-regular-file.mjs";
import { runBoundedCommand } from "./prepare-dsh-upgrade.mjs";

const PROJECT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const USAGE = "usage: prepare-beta-dmg.mjs create <candidate.zip> <expected-zip-sha256> <new-private-output-directory> | verify <image.dmg> <expected-dmg-sha256> <candidate.zip> <expected-zip-sha256> <private-work-parent>";
const DIGEST = /^[a-f0-9]{64}$/u;
const INSTALL = "Fulmar — private DMG packaging preview\n\nThis disk image has not been qualified for public distribution.\nDo not install this engineering artifact as a public beta.\nThe Applications shortcut is a packaging preview only.\n\nThe app inside is copied unchanged from the explicitly bound candidate ZIP.\nSigning/notarisation, licensing and installation/provider acceptance are separate release checks.\n";
const MAXIMUM = 8 * 1024 * 1024 * 1024;
let interrupted = false;

function absolute(value) {
  if (typeof value !== "string" || !isAbsolute(value) || resolve(value) !== value
      || /[\x00-\x1f\x7f]/u.test(value) || value.length > 4096) throw new Error(USAGE);
  return value;
}
function digest(value) {
  if (typeof value !== "string" || !DIGEST.test(value)) throw new Error(USAGE);
  return value;
}
export function parseArguments(args) {
  if (args[0] === "create" && args.length === 4) {
    return { command: "create", archive: absolute(args[1]), expectedArchiveSHA256: digest(args[2]), output: absolute(args[3]) };
  }
  if (args[0] === "verify" && args.length === 6) {
    return { command: "verify", dmg: absolute(args[1]), expectedDMGSHA256: digest(args[2]), archive: absolute(args[3]), expectedArchiveSHA256: digest(args[4]), workParent: absolute(args[5]) };
  }
  throw new Error(USAGE);
}

function environment(root) {
  return { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", HOME: join(root, "home"), TMPDIR: `${root}/`, LANG: "en_US.UTF-8", LC_CTYPE: "UTF-8" };
}
async function command(root, executable, args, cleanup = false) {
  if (interrupted && !cleanup) throw new Error("DMG operation interrupted");
  return runBoundedCommand(executable, args, {
    environment: environment(root), timeoutMS: 180_000,
    maximumStandardOutputBytes: 8 * 1024 * 1024, maximumStandardErrorBytes: 1024 * 1024,
    label: "private DMG packaging"
  });
}
async function script(root, name, args) {
  return command(root, process.execPath, [join(PROJECT, "scripts", name), ...args]);
}
async function jsonPlist(root, value) {
  const target = join(root, `plist-${randomUUID()}.plist`);
  await writeNew(target, value);
  return JSON.parse((await command(root, "/usr/bin/plutil", ["-convert", "json", "-o", "-", target], true)).stdout);
}
async function writeNew(target, value) {
  const handle = await open(target, "wx", 0o600);
  try { await handle.writeFile(value); await handle.sync(); } finally { await handle.close(); }
}
async function absent(target) {
  try { await lstat(target); } catch (error) { if (error.code === "ENOENT") return; throw error; }
  throw new Error(`Output already exists; it was not changed: ${target}`);
}
async function snapshot(root, input, leaf, expected) {
  absolute(input); digest(expected);
  if (await realpath(input) !== input) throw new Error("Input must use a canonical path, not a symbolic alias");
  const target = join(root, leaf);
  const result = JSON.parse((await script(root, "snapshot-regular-file.mjs", [input, target, String(MAXIMUM)])).stdout);
  if (result.bytes === 0 || result.sha256 !== expected) throw new Error(`Expected digest mismatch for ${leaf}`);
  return target;
}
async function identity() {
  if (process.platform !== "darwin") throw new Error("Private DMG wrapping requires macOS");
  const item = await readAttestedRegularFile(join(PROJECT, "Config/ReleaseIdentity.json"), { maximumBytes: 65536 });
  const release = JSON.parse(item.bytes);
  const runtime = await sha256AttestedRegularFile(process.execPath, { maximumBytes: 256 * 1024 * 1024 });
  if (runtime.sha256 !== release.runtime.nodeSHA256) throw new Error("Use the exact reviewed bundled Node runtime");
  return release;
}
async function sameTree(root, left, right) {
  const original = await lstat(left);
  const copied = await lstat(right);
  if (!original.isDirectory() || !copied.isDirectory() || original.uid !== process.getuid()
      || copied.uid !== original.uid || (original.mode & 0o7777) !== (copied.mode & 0o7777)) throw new Error("App root type, owner or mode changed");
  return script(root, "verify-release-tree.mjs", [left, right]);
}
async function admittedApp(root, archive, release, observers) {
  await observers.afterArchiveSnapshot?.({ root, archive });
  await script(root, "verify-zip-entries.mjs", [archive]);
  const extracted = join(root, "extracted");
  await mkdir(extracted, { mode: 0o700 });
  await command(root, "/usr/bin/ditto", ["-x", "-k", "--noqtn", archive, extracted]);
  if (JSON.stringify(await readdir(extracted)) !== JSON.stringify([release.applicationBundleName])) throw new Error("ZIP must contain only Fulmar.app");
  const app = join(extracted, release.applicationBundleName);
  await sameTree(root, app, app);
  await script(root, "verify-zip-entries.mjs", [archive, app]);
  const info = JSON.parse((await command(root, "/usr/bin/plutil", ["-convert", "json", "-o", "-", join(app, "Contents/Info.plist")])).stdout);
  if (info.CFBundleIdentifier !== release.bundleIdentifier || info.CFBundleShortVersionString !== release.appVersion
      || String(info.CFBundleVersion) !== String(release.appBuild) || info.CFBundleName !== release.productDisplayName
      || info.LSMinimumSystemVersion !== release.minimumMacOS) throw new Error("App identity does not match this reviewed checkout");
  await command(root, "/usr/bin/codesign", ["--verify", "--deep", "--strict", app]);
  return app;
}

// hdiutil can attach an image even if its command subsequently fails. Find only
// this invocation's exact private image; never detach by volume name or a disk
// number remembered without checking its current backing image.
async function attachedImage(root, dmg) {
  const output = await command(root, "/usr/bin/hdiutil", ["info", "-plist"], true);
  const info = await jsonPlist(root, output.stdout);
  const matches = (info.images ?? []).filter((item) => item["image-path"] === dmg);
  if (matches.length > 1) throw new Error("More than one attachment references this private image; retained for inspection");
  return matches[0];
}
async function detachExact(root, dmg, mount) {
  const item = await attachedImage(root, dmg);
  if (!item) return;
  const entities = item["system-entities"] ?? [];
  const mounts = entities.filter((entry) => entry["mount-point"] !== undefined);
  if (mounts.length !== 1 || mounts[0]["mount-point"] !== mount) throw new Error(`Unexpected image mount; retained for inspection: ${root}`);
  const device = entities[0]?.["dev-entry"];
  if (typeof device !== "string" || !/^\/dev\/disk[0-9]+$/u.test(device)) throw new Error("Image device identity is unavailable; no device was detached");
  await command(root, "/usr/bin/hdiutil", ["detach", device], true);
  if (await attachedImage(root, dmg)) throw new Error(`Image still attached; retained for inspection: ${root}`);
}
async function roundTrip(root, dmg, app) {
  await command(root, "/usr/bin/hdiutil", ["verify", dmg]);
  if (await attachedImage(root, dmg)) throw new Error("Private image was already attached; no cleanup authority was acquired");
  const mount = join(root, "mount");
  await mkdir(mount, { mode: 0o700 });
  let failure;
  try {
    await command(root, "/usr/bin/hdiutil", ["attach", dmg, "-readonly", "-nobrowse", "-noautoopen", "-verify", "-noignorebadchecksums", "-mount", "required", "-owners", "on", "-mountpoint", mount, "-plist"]);
    const attached = await attachedImage(root, dmg);
    const mounted = attached?.["system-entities"]?.filter((entry) => entry["mount-point"] !== undefined);
    if (mounted?.length !== 1 || mounted[0]["mount-point"] !== mount) throw new Error("Image was not attached at the exact private mount point");
    const diskInfo = await jsonPlist(root, (await command(root, "/usr/sbin/diskutil", ["info", "-plist", mount])).stdout);
    if (diskInfo.WritableVolume !== false || diskInfo.WritableMedia !== false || diskInfo.GlobalPermissionsEnabled !== true
        || diskInfo.MountPoint !== mount || diskInfo.DeviceNode !== mounted[0]["dev-entry"]) throw new Error("Image mount is not read-only with owners enabled at the recorded device");
    const names = await readdir(mount);
    const permitted = new Set(["Fulmar.app", "Applications", "INSTALL.txt", ".fseventsd", ".Trashes", ".HFS+ Private Directory Data\r"]);
    if (names.some((name) => !permitted.has(name)) || !["Fulmar.app", "Applications", "INSTALL.txt"].every((name) => names.includes(name))) throw new Error("Unexpected disk image contents");
    for (const name of names.filter((item) => item.startsWith("."))) {
      if (!(await lstat(join(mount, name))).isDirectory()) throw new Error("Unexpected filesystem metadata object");
    }
    if (!(await lstat(join(mount, "Applications"))).isSymbolicLink() || await readlink(join(mount, "Applications")) !== "/Applications") throw new Error("Applications shortcut was changed");
    const instructions = await readAttestedRegularFile(join(mount, "INSTALL.txt"), { maximumBytes: 8192 });
    if (instructions.bytes.toString("utf8") !== INSTALL) throw new Error("Private installation notice was changed");
    const recovered = join(root, "recovered.app");
    await sameTree(root, app, join(mount, "Fulmar.app"));
    await command(root, "/usr/bin/ditto", ["--noqtn", join(mount, "Fulmar.app"), recovered]);
    await sameTree(root, app, recovered);
    await command(root, "/usr/bin/codesign", ["--verify", "--deep", "--strict", recovered]);
  } catch (error) { failure = error; }
  try { await detachExact(root, dmg, mount); }
  catch (error) { throw new AggregateError(failure ? [failure, error] : [error], `DMG detach failed; private work retained: ${root}`); }
  if (failure) throw failure;
}

async function retireOwned(directory, before) {
  const now = await lstat(directory, { bigint: true });
  if (!now.isDirectory() || now.dev !== before.dev || now.ino !== before.ino || now.uid !== before.uid
      || (now.mode & 0o777n) !== 0o700n) throw new Error(`Private output identity changed; not removed: ${directory}`);
  // Checking only our expected image is insufficient: a different image could
  // have been mounted inside this directory. Never traverse another filesystem
  // during cleanup, and never follow a link while proving that boundary.
  let entries = 0;
  async function sameFilesystem(parent) {
    for (const item of await readdir(parent, { withFileTypes: true })) {
      if (++entries > 1_000_000) throw new Error("Private cleanup entry bound exceeded; directory retained");
      const child = join(parent, item.name);
      const metadata = await lstat(child, { bigint: true });
      if (metadata.dev !== now.dev) throw new Error(`Unexpected mounted descendant; private directory retained: ${directory}`);
      if (metadata.isDirectory()) await sameFilesystem(child);
    }
  }
  await sameFilesystem(directory);
  const final = await lstat(directory, { bigint: true });
  if (final.dev !== now.dev || final.ino !== now.ino || final.uid !== now.uid || final.mode !== now.mode) throw new Error("Private cleanup root changed; directory retained");
  await rm(directory, { recursive: true });
}
async function workspace(parent, operation) {
  return withAttestedDirectory(absolute(parent), {
    label: "private DMG work parent", requirePrivateMode: true, requireCanonicalPath: true, allowContentMutation: true
  }, async () => {
    const root = await mkdtemp(join(parent, ".fulmar-dmg-"));
    await chmod(root, 0o700);
    const before = await lstat(root, { bigint: true });
    await mkdir(join(root, "home"), { mode: 0o700 });
    let value, failure;
    try { value = await operation(root); } catch (error) { failure = error; }
    try {
      // A live/ambiguous image is never recursively traversed by cleanup.
      if (await attachedImage(root, join(root, "Fulmar.dmg"))) throw new Error(`Private disk image remains attached: ${root}`);
      await retireOwned(root, before);
    } catch (error) { throw new AggregateError(failure ? [failure, error] : [error], `Private DMG cleanup incomplete: ${root}`); }
    if (failure) throw failure;
    return value;
  });
}

export async function createDMG(options, observers = {}) {
  const { archive, expectedArchiveSHA256, output } = parseArguments(["create", options.archive, options.expectedArchiveSHA256, options.output]);
  const release = await identity();
  await absent(output);
  return workspace(dirname(output), async (root) => {
    const zipped = await snapshot(root, archive, "Fulmar.app.zip", expectedArchiveSHA256);
    const app = await admittedApp(root, zipped, release, observers);
    const imageSource = join(root, "image-source");
    await mkdir(imageSource, { mode: 0o700 });
    await command(root, "/usr/bin/ditto", ["--noqtn", app, join(imageSource, "Fulmar.app")]);
    await sameTree(root, app, join(imageSource, "Fulmar.app"));
    await symlink("/Applications", join(imageSource, "Applications"));
    await writeNew(join(imageSource, "INSTALL.txt"), INSTALL);
    await observers.beforeImageCreate?.({ root, app, imageSource });
    const dmg = join(root, "Fulmar.dmg");
    await command(root, "/usr/bin/hdiutil", ["create", "-srcfolder", imageSource, "-srcowners", "any", "-noanyowners", "-noskipunreadable", "-fs", "HFS+", "-volname", "Fulmar Beta Preview", "-format", "UDZO", "-nospotlight", dmg]);
    await observers.afterImageCreate?.({ root, dmg });
    await roundTrip(root, dmg, app);
    const image = await sha256AttestedRegularFile(dmg, { maximumBytes: MAXIMUM });
    const binding = {
      schemaVersion: 1, type: "fulmar-private-dmg-wrapper", publicBetaQualified: false,
      version: release.appVersion, build: release.appBuild,
      candidate: { file: "Fulmar.app.zip", sha256: expectedArchiveSHA256 },
      image: { file: "Fulmar.dmg", bytes: image.bytes, sha256: image.sha256 },
      verified: ["candidate-zip-digest", "app-identity", "code-signature-integrity", "read-only-image-roundtrip", "app-tree-bytes-types-modes-links"],
      notProven: ["Developer ID distribution trust", "notarisation", "licensing clearance", "physical installation", "providers", "permission persistence"],
      reproducibleDMGBytes: false
    };
    await observers.beforePublish?.({ root, output, staging: imageSource });
    if (interrupted) throw new Error("DMG operation interrupted before output");
    // mkdir is exclusive: never replace an existing destination, even an empty
    // directory created concurrently. This private output is NOT the public
    // atomic-asset publisher. An uncatchable kill can leave incomplete residue.
    await mkdir(output, { mode: 0o700 });
    const outputIdentity = await lstat(output, { bigint: true });
    try {
      await link(dmg, join(output, "Fulmar.dmg"));
      const bindingBytes = `${JSON.stringify(binding, null, 2)}\n`;
      await writeNew(join(output, "dmg-binding.json"), bindingBytes);
      await writeNew(join(output, "SHA256SUMS.txt"), `${image.sha256}  Fulmar.dmg\n${createHash("sha256").update(bindingBytes).digest("hex")}  dmg-binding.json\n`);
    } catch (error) {
      try { await retireOwned(output, outputIdentity); }
      catch (cleanupError) { throw new AggregateError([error, cleanupError], "Private output failed and could not be retired"); }
      throw error;
    }
    return binding;
  });
}

export async function verifyDMG(options, observers = {}) {
  const args = parseArguments(["verify", options.dmg, options.expectedDMGSHA256, options.archive, options.expectedArchiveSHA256, options.workParent]);
  const release = await identity();
  return workspace(args.workParent, async (root) => {
    const archive = await snapshot(root, args.archive, "Fulmar.app.zip", args.expectedArchiveSHA256);
    const dmg = await snapshot(root, args.dmg, "Fulmar.dmg", args.expectedDMGSHA256);
    const app = await admittedApp(root, archive, release, observers);
    await roundTrip(root, dmg, app);
    return { verified: true, publicBetaQualified: false, candidateSHA256: args.expectedArchiveSHA256, dmgSHA256: args.expectedDMGSHA256 };
  });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.once("SIGINT", () => { interrupted = true; });
  process.once("SIGTERM", () => { interrupted = true; });
  try {
    const args = parseArguments(process.argv.slice(2));
    const result = args.command === "create" ? await createDMG(args) : await verifyDMG(args);
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    if (error instanceof AggregateError) for (const cause of error.errors) process.stderr.write(`${cause.message}\n`);
    process.exitCode = 1;
  }
}
