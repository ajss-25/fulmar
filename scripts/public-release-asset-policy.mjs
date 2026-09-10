// Exact public release asset policy for the stable and beta profiles, and the
// beta material admission step that binds the distributed third-party material
// bytes to the reviewed source through the existing packager verifier.
//
// - Policy (pure): the stable package is exactly nine assets, eight of them
//   listed in SHA256SUMS.txt. The beta package is exactly twelve, eleven listed:
//   the nine plus the verified delivery-material archive, its sha256sum sidecar
//   and its binding, whose basenames derive only from the tracked provenance
//   record's `outputDirectoryName` (`<root>.tar`, `<root>.tar.sha256`,
//   `<root>.binding.json`). Names are always emitted in C-locale byte order,
//   which is the order SHA256SUMS.txt uses. Nothing here accepts a name from an
//   operand, so arbitrary or unrelated files can never become beta assets.
// - Admission (`admit-materials`): snapshots the three material files from the
//   operator's private package directory through attested descriptors into a
//   private destination, requires the sidecar to name the expected digest for
//   the archive, runs the existing `verify-archive` on the SNAPSHOT archive and
//   SNAPSHOT binding with the externally supplied expected digest and source
//   commit (the external path is never consulted again), and finally requires
//   the verified binding to record HTTPS-authoritative acquisition for both
//   material inputs. Fixture (`local-fixture`) or otherwise non-authoritative
//   material is refused for distribution. The receipt names the admitted bytes;
//   callers copy exactly those snapshot files into the distributed package.
// - The expected digest and source commit are operands supplied from the
//   operator's independently reviewed release record and checkout. A sidecar or
//   binding downloaded beside the archive is payload to be checked, never the
//   source of the expected digest.
// - No environment variable selects or relaxes anything. The optional
//   `observers` argument holds in-process function values only (the CLI passes
//   none): `afterMaterialSnapshot`, plus the packager's `afterSnapshotOpened`,
//   `afterSnapshotAdmitted` and `beforeExtraction`, so deterministic tests can
//   observe or interrupt admission at exact points. An observer can only observe,
//   throw (fail closed) or end the process; it cannot skip a check.
// - A verified, admitted archive is one engineering step. It is not a
//   corresponding-source offer, not legal clearance, and closes no obligation.
import { createHash } from "node:crypto";
import { constants, realpathSync } from "node:fs";
import { lstat, open, readFile, realpath, rm } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { consumeAttestedRegularFile } from "./attested-regular-file.mjs";
import { verifyArchive } from "./package-libvips-delivery-materials.mjs";
import { PUBLIC_RELEASE_PROFILE_NAMES } from "./public-release-profile-policy.mjs";
import { loadProvenance } from "./stage-libvips-delivery-materials.mjs";

const USAGE = [
  "usage: public-release-asset-policy.mjs names <stable|beta> [provenance.json]",
  "       public-release-asset-policy.mjs checksum-names <stable|beta> [provenance.json]",
  "       public-release-asset-policy.mjs admit-materials <provenance.json> <material-package-directory> <expected-archive-sha256> <source-commit> <new-private-destination-directory-contents> <private-unpack-parent>"
].join("\n");
const SHA256 = /^[a-f0-9]{64}$/u;
const COMMIT = /^[a-f0-9]{40}$/u;
// The same bounded directory-name contract the packager applies to the root.
const DIRECTORY_NAME = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,199}$/u;
const MAXIMUM_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024;
const MAXIMUM_BINDING_BYTES = 4 * 1024 * 1024;
const MAXIMUM_SIDECAR_BYTES = 1024;
const CHUNK_BYTES = 1024 * 1024;
const OBSERVER_NAMES = Object.freeze(["afterMaterialSnapshot", "afterSnapshotOpened", "afterSnapshotAdmitted", "beforeExtraction"]);
const PASSTHROUGH_OBSERVER_NAMES = Object.freeze(["afterSnapshotOpened", "afterSnapshotAdmitted", "beforeExtraction"]);

export const CHECKSUM_LIST_NAME = "SHA256SUMS.txt";
export const STABLE_PACKAGE_ASSET_NAMES = Object.freeze(byteOrder([
  "Fulmar.app.zip",
  "Fulmar.app.zip.sha256",
  "Fulmar.dSYMs.zip",
  "LICENSE",
  "LocalHarness.sbom.cdx.json",
  "THIRD_PARTY_NOTICES.md",
  "release-manifest.json",
  "static-security-summary.json",
  CHECKSUM_LIST_NAME
]));
export const STABLE_CHECKSUM_ENTRY_NAMES = Object.freeze(STABLE_PACKAGE_ASSET_NAMES.filter((name) => name !== CHECKSUM_LIST_NAME));

function fail(message) {
  throw new Error(message);
}

function byteOrder(names) {
  return [...names].sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
}

export function resolveAssetProfile(profile) {
  if (typeof profile !== "string" || !PUBLIC_RELEASE_PROFILE_NAMES.includes(profile)) {
    fail(`unknown public release profile: ${typeof profile === "string" ? profile : typeof profile}`);
  }
  return profile;
}

export function requireMaterialRootName(rootName) {
  if (typeof rootName !== "string" || !DIRECTORY_NAME.test(rootName)) fail("material root name must satisfy the packager's bounded directory-name contract");
  return rootName;
}

// The three beta material asset basenames for one provenance-derived root.
export function materialAssetNames(rootName) {
  requireMaterialRootName(rootName);
  return Object.freeze([`${rootName}.binding.json`, `${rootName}.tar`, `${rootName}.tar.sha256`]);
}

// Every top-level asset of one profile's package, in C-locale byte order.
export function packageAssetNames(profile, rootName) {
  if (resolveAssetProfile(profile) === "stable") return STABLE_PACKAGE_ASSET_NAMES;
  const material = materialAssetNames(rootName);
  for (const name of material) {
    if (STABLE_PACKAGE_ASSET_NAMES.includes(name)) fail(`material asset name collides with a stable asset: ${name}`);
  }
  return Object.freeze(byteOrder([...STABLE_PACKAGE_ASSET_NAMES, ...material]));
}

// Every SHA256SUMS.txt entry of one profile's package, in the order it is written.
export function checksumEntryNames(profile, rootName) {
  return Object.freeze(packageAssetNames(profile, rootName).filter((name) => name !== CHECKSUM_LIST_NAME));
}

// The material root comes only from the tracked provenance record.
export async function loadMaterialRootName(provenanceArgument) {
  const provenance = await loadProvenance(provenanceArgument);
  return requireMaterialRootName(provenance.delivery.outputDirectoryName);
}

// Both material inputs of a distributable set must have been acquired over HTTPS
// from their authoritative origins; a binding that records anything else (the
// test fixture transport, or a relabelled authority flag) is refused here even
// though the packager carries such records truthfully for private use.
export function requireAuthoritativeAcquisition(binding) {
  const acquisition = binding?.acquisition;
  const records = [["upstream", acquisition?.upstreamSource], ["crates", acquisition?.rustCrates]];
  const shown = records.map(([label, record]) => `${label} ${typeof record?.transport === "string" ? record.transport : "unknown"}${record?.authoritative === true ? "" : ", NOT authoritative"}`).join("; ");
  for (const [, record] of records) {
    if (!record || typeof record !== "object" || record.transport !== "https" || record.authoritative !== true) {
      fail(`material acquisition is not HTTPS-authoritative (${shown}); fixture or non-authoritative material cannot become a distributed beta asset`);
    }
  }
  return Object.freeze({ upstream: "https", crates: "https", authoritative: true });
}

function normalizeObservers(observers) {
  if (observers === undefined) return Object.freeze({});
  if (!observers || typeof observers !== "object" || Array.isArray(observers)) fail("observers must be one object of function values");
  for (const [name, value] of Object.entries(observers)) {
    if (!OBSERVER_NAMES.includes(name) || typeof value !== "function") fail(`observers may only carry function values named ${OBSERVER_NAMES.join(", ")}`);
  }
  return Object.freeze({ ...observers });
}

async function requirePrivateDirectory(path, label) {
  if (typeof path !== "string" || !isAbsolute(path)) fail(`${label} must be one absolute path`);
  const details = await lstat(path);
  if (!details.isDirectory() || details.isSymbolicLink()) fail(`${label} is not a real directory`);
  if (await realpath(path) !== path) fail(`${label} must not traverse aliases or symbolic links`);
  if (typeof process.getuid === "function" && details.uid !== process.getuid()) fail(`${label} is not owned by the current user`);
  if ((details.mode & 0o077) !== 0) fail(`${label} is not owner-private (mode 0700 required)`);
  return details;
}

async function requireOwnerControlledDirectory(path, label) {
  if (typeof path !== "string" || !isAbsolute(path)) fail(`${label} must be one absolute path`);
  const details = await lstat(path);
  if (!details.isDirectory() || details.isSymbolicLink()) fail(`${label} is not a real directory`);
  if (await realpath(path) !== path) fail(`${label} must not traverse aliases or symbolic links`);
  if (typeof process.getuid === "function" && details.uid !== process.getuid()) fail(`${label} is not owned by the current user`);
  if ((details.mode & 0o022) !== 0) fail(`${label} is writable by other users`);
  return details;
}

// One attested read of `source` into a new private `destination`, hashing the
// bytes as they are written. The destination is what is verified and shipped.
async function snapshotMaterialFile(source, destination, maximumBytes, label, observers) {
  const hash = createHash("sha256");
  const handle = await open(destination, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  let written = 0;
  let completed = false;
  try {
    const consumed = await consumeAttestedRegularFile(source, {
      label,
      minimumBytes: 1,
      maximumBytes,
      requireCurrentUser: true,
      requireSingleLink: true,
      requireCanonicalPath: true,
      chunkBytes: CHUNK_BYTES,
      afterOpen: observers.afterSnapshotOpened === undefined ? undefined : async ({ canonical }) => observers.afterSnapshotOpened(Object.freeze({ externalPath: canonical, label }))
    }, async (chunk, offset) => {
      hash.update(chunk);
      const { bytesWritten } = await handle.write(chunk, 0, chunk.byteLength, offset);
      if (bytesWritten !== chunk.byteLength) fail(`${label} snapshot write was short`);
      written += bytesWritten;
    });
    await handle.sync();
    if (written !== consumed.bytes) fail(`${label} snapshot size differs from the attested source size`);
    const copied = await handle.stat({ bigint: true });
    if (!copied.isFile() || copied.nlink !== 1n || Number(copied.size) !== written || (copied.mode & 0o777n) !== 0o600n) {
      fail(`${label} snapshot did not retain the required private regular-file shape`);
    }
    completed = true;
    return Object.freeze({ bytes: written, sha256: hash.digest("hex") });
  } finally {
    await handle.close();
    if (!completed) await rm(destination, { force: true }).catch(() => {});
  }
}

// Admits one private material package for distribution. Returns the receipt
// describing the admitted (snapshot) bytes now present in `destinationDirectory`.
export async function admitMaterialPackage({ provenancePath, packageDirectory, expectedSHA256, sourceCommit, destinationDirectory, unpackParent }, observerArgument) {
  const observers = normalizeObservers(observerArgument);
  if (!SHA256.test(expectedSHA256 ?? "")) fail("expected material archive digest must be one lowercase SHA-256 taken from the reviewed release record");
  if (!COMMIT.test(sourceCommit ?? "")) fail("source commit must be one full 40-hex commit of the trusted checkout");
  if (typeof provenancePath !== "string" || !isAbsolute(provenancePath)) fail("provenance record path must be absolute");
  await requireOwnerControlledDirectory(packageDirectory, "material package directory");
  await requirePrivateDirectory(destinationDirectory, "material admission destination");
  await requirePrivateDirectory(unpackParent, "material unpack parent");
  const root = await loadMaterialRootName(provenancePath);
  const [bindingName, archiveName, sidecarName] = materialAssetNames(root);
  const plan = [
    { key: "archive", name: archiveName, maximumBytes: MAXIMUM_ARCHIVE_BYTES },
    { key: "binding", name: bindingName, maximumBytes: MAXIMUM_BINDING_BYTES },
    { key: "sidecar", name: sidecarName, maximumBytes: MAXIMUM_SIDECAR_BYTES }
  ];
  const files = {};
  for (const { key, name, maximumBytes } of plan) {
    const source = join(packageDirectory, name);
    const destination = join(destinationDirectory, name);
    let details;
    try {
      details = await lstat(source);
    } catch (error) {
      if (error?.code === "ENOENT") fail(`material package is missing ${name}`);
      throw error;
    }
    if (details.isSymbolicLink() || !details.isFile()) fail(`material package entry is not a regular file: ${name}`);
    const snapshot = await snapshotMaterialFile(source, destination, maximumBytes, `material ${key} ${name}`, observers);
    files[key] = Object.freeze({ name, path: destination, bytes: snapshot.bytes, sha256: snapshot.sha256 });
  }
  await observers.afterMaterialSnapshot?.(Object.freeze({ destinationDirectory, files: Object.freeze({ ...files }) }));
  // The externally supplied digest is compared first, with a message that names
  // the frequent confusion: the app candidate digest is a different artefact.
  if (files.archive.sha256 !== expectedSHA256) {
    fail(`material archive SHA-256 is ${files.archive.sha256}, not the expected ${expectedSHA256}; the expected digest must be the material archive digest from the reviewed release record, not the app candidate digest, and nothing was extracted`);
  }
  const sidecar = await readFile(files.sidecar.path, "utf8");
  if (sidecar !== `${expectedSHA256}  ${archiveName}\n`) fail(`material sidecar ${sidecarName} does not name the expected digest for ${archiveName} in sha256sum format`);
  const unpackDirectory = join(unpackParent, `material-unpack.${process.pid}.${createHash("sha256").update(`${Date.now()}:${files.archive.sha256}`).digest("hex").slice(0, 16)}`);
  const passthrough = {};
  for (const name of PASSTHROUGH_OBSERVER_NAMES) if (observers[name] !== undefined) passthrough[name] = observers[name];
  const verified = await verifyArchive(provenancePath, files.archive.path, files.binding.path, expectedSHA256, sourceCommit, unpackDirectory, passthrough);
  if (verified.snapshotSHA256 !== expectedSHA256 || verified.archiveSHA256 !== expectedSHA256) fail("material archive verification did not bind the expected digest");
  if (!verified.extractedFrom.startsWith(`${unpackParent}/`)) fail("material archive verification extracted outside the private unpack parent");
  let binding;
  try {
    binding = JSON.parse(await readFile(files.binding.path, "utf8"));
  } catch (error) {
    fail(`admitted binding could not be re-read: ${error.message}`);
  }
  const authority = requireAuthoritativeAcquisition(binding);
  if (binding.sourceCommit !== sourceCommit || binding.archive?.sha256 !== expectedSHA256 || binding.archive?.fileName !== archiveName) fail("admitted binding does not name the expected digest, archive and source commit");
  await rm(unpackDirectory, { recursive: true, force: true });
  return Object.freeze({
    schemaVersion: 1,
    root,
    sourceCommit,
    expectedSHA256,
    archive: files.archive,
    binding: files.binding,
    sidecar: files.sidecar,
    acquisition: authority,
    verifiedFiles: verified.fileCount,
    statement: "Admitted bytes are the private snapshots named above; the external package path was not consulted after the snapshots were taken. Verification proves archive identity and binding consistency only; it is not a source offer, not a release asset qualification and not legal clearance."
  });
}

function isEntryPoint() {
  try {
    return process.argv[1] !== undefined && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
}

if (isEntryPoint()) {
  process.umask(0o077);
  const [command, ...operands] = process.argv.slice(2);
  if (operands.some((operand) => typeof operand !== "string" || operand.length === 0 || operand.startsWith("--"))) {
    process.stderr.write(`${USAGE}\n`);
    process.exit(64);
  }
  try {
    if ((command === "names" || command === "checksum-names") && (operands.length === 1 || operands.length === 2)) {
      const profile = resolveAssetProfile(operands[0]);
      let root;
      if (profile === "beta") {
        if (operands.length !== 2) fail("the beta profile requires the tracked provenance record operand");
        root = await loadMaterialRootName(operands[1]);
      } else if (operands.length === 2) {
        // A stable listing may name the record for symmetry; the names ignore it.
        await loadMaterialRootName(operands[1]);
      }
      const names = command === "names" ? packageAssetNames(profile, root) : checksumEntryNames(profile, root);
      process.stdout.write(`${names.join("\n")}\n`);
    } else if (command === "admit-materials" && operands.length === 6) {
      const [provenancePath, packageDirectory, expectedSHA256, sourceCommit, destinationDirectory, unpackParent] = operands;
      const receipt = await admitMaterialPackage({
        provenancePath: resolve(provenancePath),
        packageDirectory,
        expectedSHA256,
        sourceCommit,
        destinationDirectory,
        unpackParent
      });
      process.stdout.write(`${JSON.stringify(receipt)}\n`);
    } else {
      process.stderr.write(`${USAGE}\n`);
      process.exit(64);
    }
  } catch (error) {
    process.stderr.write(`public-release-asset-policy: ${error?.message ?? String(error)}\n`);
    process.exit(1);
  }
}
