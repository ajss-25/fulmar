// Prepares and verifies the private, checkout-local cache of verified Rust crate
// notice materials that the generated third-party notices bind for the
// redistributed sharp-libvips binary (see docs/LIBVIPS_CORRESPONDING_SOURCE.md).
//
// Contract:
// - The cache lives at one literal owner-controlled path inside the checkout,
//   build/third-party-notice-materials/<crate manifest outputDirectoryName>.
//   The literal is bound to the tracked crate manifest, so a manifest change
//   fails here instead of silently reusing an older cache namespace.
// - `prepare` runs only from the clean source bootstrap. It creates the private
//   containing directory (0700) when absent, refuses an unsafe pre-existing
//   path instead of chmod-following it, reuses an existing cache only after
//   complete verification, and acquires an absent cache over HTTPS through the
//   existing acquisition tool in a child process that inherits no environment
//   at all (no loader, proxy, CA store, credential or registry setting). An
//   existing invalid or stale cache fails with its exact path and the recovery
//   instruction; nothing is overwritten or deleted automatically.
// - `verify` runs from every release-script caller. It accepts only the exact
//   literal path it was handed, re-verifies every cache byte against the
//   tracked manifests and requires the recorded acquisition to be transport
//   https and authoritative. It never acquires, falls back or downloads.
// - The cache is an internal build input. It never enters the compiler-only
//   source snapshot, the app runtime or a public asset, and neither its
//   presence nor the notices rendered from it is a corresponding-source offer
//   or legal clearance.
import { spawnSync } from "node:child_process";
import { realpathSync, writeSync } from "node:fs";
import { lstat, mkdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { withAttestedDirectory } from "./attested-regular-file.mjs";
import { loadManifest, verifyMaterials } from "./prepare-libvips-source-materials.mjs";

const USAGE = "usage: prepare-third-party-notice-materials.mjs prepare <project-root> | verify <project-root> <materials-directory>";
const BUILD_DIRECTORY_NAME = "build";
const CACHE_DIRECTORY_NAME = "third-party-notice-materials";
const MATERIALS_DIRECTORY_NAME = "sharp-libvips-1.3.2-rust-crate-materials";
const CRATE_MANIFEST = "Config/SharpLibvipsRustProvenance.json";
const NOTICE_MANIFEST = "Config/SharpLibvipsRustNoticeMaterials.json";
const ACQUISITION_TOOL = "scripts/prepare-libvips-source-materials.mjs";
const BOOTSTRAP = "scripts/bootstrap-source-checkout.sh";
// Exactly the bootstrap's `env -i` lane: nothing ambient reaches acquisition.
const ACQUISITION_ENVIRONMENT = Object.freeze({
  PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
  LANG: "C",
  LC_ALL: "C",
  TMPDIR: "/private/tmp"
});
const ACQUISITION_TIMEOUT_MILLISECONDS = 30 * 60 * 1000;

class CacheError extends Error {}

function fail(message) {
  throw new CacheError(message);
}

function log(message) {
  process.stderr.write(`${message}\n`);
}

function recovery(materials) {
  return `inspect it with "${ACQUISITION_TOOL} verify ${CRATE_MANIFEST} ${materials} --notice-materials ${NOTICE_MANIFEST}", remove it deliberately if it is stale, then rerun ${BOOTSTRAP}; nothing is overwritten or deleted automatically`;
}

// Descriptor-based admission through the repository's attested-directory
// helper: a real directory reached without any alias or symbolic link, owned
// by the current user, never group- or world-writable and, when required,
// owner-private (0700).
async function attestDirectory(path, label, requirePrivateMode) {
  await withAttestedDirectory(path, {
    label,
    requireCurrentUser: true,
    requireCanonicalPath: true,
    requireOwnerControlledMode: true,
    requirePrivateMode
  });
}

// Returns "absent" for a missing path; attests an existing real directory and
// refuses a symbolic link, a non-directory or an unsafe directory with its
// exact path, without changing anything.
async function existingDirectory(path, label, requirePrivateMode) {
  let details;
  try {
    details = await lstat(path);
  } catch (error) {
    if (error?.code === "ENOENT") return "absent";
    throw error;
  }
  if (details.isSymbolicLink()) fail(`${label} is a symbolic link, which the release cache refuses: ${path}; remove it deliberately`);
  if (!details.isDirectory()) fail(`${label} is not a directory: ${path}; remove it deliberately`);
  try {
    await attestDirectory(path, label, requirePrivateMode);
  } catch (error) {
    fail(`${label} is unsafe (${error.message}): ${path}; correct or remove it deliberately instead of relying on a mode change`);
  }
  return "present";
}

async function ensureDirectory(path, label, { create, requirePrivateMode }) {
  if (await existingDirectory(path, label, requirePrivateMode) === "present") return;
  if (!create) fail(`${label} is absent: ${path}; run ${BOOTSTRAP} first`);
  await mkdir(path, { mode: 0o700 });
  await attestDirectory(path, label, true);
}

// Binds the literal cache name to the tracked crate manifest before any path
// under build/ is touched.
async function bindTrackedManifests(root) {
  const manifestPath = join(root, CRATE_MANIFEST);
  const { manifest } = await loadManifest(manifestPath);
  if (manifest.provenanceStatuses === undefined) fail(`${CRATE_MANIFEST} is not the rust-crate materials manifest`);
  if (manifest.outputDirectoryName !== MATERIALS_DIRECTORY_NAME) {
    fail(`${CRATE_MANIFEST} names its output directory ${manifest.outputDirectoryName}, not the literal ${MATERIALS_DIRECTORY_NAME} bound by this script and the release scripts; update them together`);
  }
  return {
    manifestPath,
    noticeManifestPath: join(root, NOTICE_MANIFEST),
    itemCount: manifest.items.length,
    totalBytes: manifest.totalBytes
  };
}

// Complete verification against the tracked manifests, then the production
// requirement taken from the returned verified state, never from a grep or an
// unchecked JSON field: the recorded acquisition must be HTTPS and
// authoritative. Fixture output (transport local-fixture) is refused here even
// though the verifier and the renderers accept it elsewhere.
async function verifyCache(materials, bound, label) {
  let verified;
  try {
    verified = await verifyMaterials(bound.manifestPath, materials, bound.noticeManifestPath);
  } catch (error) {
    fail(`${label} is invalid or stale: ${materials}: ${error.message}; ${recovery(materials)}`);
  }
  if (verified.transport !== "https" || verified.authoritative !== true) {
    fail(`${label} records transport ${verified.transport} (NOT authoritative): ${materials}; the release cache must be acquired over HTTPS, so remove it deliberately and rerun ${BOOTSTRAP}`);
  }
  const notice = verified.noticeMaterials;
  log(`verified notice-material cache ${materials}: transport https (authoritative); ${verified.manifest.items.length} items (${verified.manifest.totalBytes} bytes); inventory sha256:${verified.inventorySHA256}; checksum list sha256:${verified.sumsSHA256}; RUST_CRATE_NOTICES.md sha256:${verified.rustNoticesSHA256}; external notice material ${notice.relativePath} (sha256:${notice.sha256}; established ${notice.summary.established.length}, unresolved ${notice.summary.unresolved.length})`);
  return verified;
}

// The only network step, and only from `prepare`: the existing acquisition
// tool, run by this same pinned interpreter with an explicit empty-of-ambient
// environment, publishes the cache atomically or leaves nothing behind.
function acquireCache(root, materials, bound) {
  log(`notice-material cache absent: ${materials}; acquiring ${bound.itemCount} crate materials (${bound.totalBytes} bytes) over HTTPS from the hosts pinned in ${CRATE_MANIFEST}, binding ${NOTICE_MANIFEST}, through ${ACQUISITION_TOOL} in a child process that inherits no environment (transport https). This cache is an internal build input, not a corresponding-source offer.`);
  const result = spawnSync(process.execPath, [
    join(root, ACQUISITION_TOOL),
    "acquire",
    bound.manifestPath,
    materials,
    "--transport", "https",
    "--notice-materials", bound.noticeManifestPath
  ], {
    cwd: root,
    env: ACQUISITION_ENVIRONMENT,
    stdio: ["ignore", "ignore", "inherit"],
    timeout: ACQUISITION_TIMEOUT_MILLISECONDS
  });
  if (result.error) fail(`HTTPS acquisition could not run (${result.error.message}); no cache was published at ${materials}`);
  if (result.status !== 0 || result.signal !== null) {
    fail(`HTTPS acquisition failed (${result.signal === null ? `status ${result.status}` : `signal ${result.signal}`}); no cache was published at ${materials}; rerun ${BOOTSTRAP} when the pinned hosts are reachable`);
  }
}

async function main(argv) {
  const [command, rootArgument, materialsArgument, ...rest] = argv;
  const usageError = rest.length !== 0 || rootArgument === undefined
    || (command === "prepare" ? materialsArgument !== undefined : command !== "verify" || materialsArgument === undefined);
  if (usageError) fail(USAGE);
  const root = resolve(rootArgument);
  await withAttestedDirectory(root, {
    label: "project root",
    requireCurrentUser: true,
    requireCanonicalPath: true,
    allowContentMutation: true
  });
  const bound = await bindTrackedManifests(root);
  const buildDirectory = join(root, BUILD_DIRECTORY_NAME);
  const cacheDirectory = join(buildDirectory, CACHE_DIRECTORY_NAME);
  const materials = join(cacheDirectory, MATERIALS_DIRECTORY_NAME);
  if (command === "verify" && resolve(materialsArgument) !== materials) {
    fail(`the materials operand ${resolve(materialsArgument)} is not the literal checkout-local cache ${materials}`);
  }
  const create = command === "prepare";
  await ensureDirectory(buildDirectory, "build output root", { create, requirePrivateMode: false });
  await ensureDirectory(cacheDirectory, "notice-material cache directory", { create, requirePrivateMode: true });
  const state = await existingDirectory(materials, "notice-material cache", true);
  if (state === "present") {
    await verifyCache(materials, bound, "existing notice-material cache");
    return;
  }
  if (!create) {
    fail(`notice-material cache is absent: ${materials}; run ${BOOTSTRAP} (which acquires it over HTTPS) before this step; release scripts never acquire, download or fall back to unbound notices`);
  }
  acquireCache(root, materials, bound);
  if (await existingDirectory(materials, "acquired notice-material cache", true) !== "present") {
    fail(`HTTPS acquisition reported success but published no cache at ${materials}`);
  }
  await verifyCache(materials, bound, "acquired notice-material cache");
}

function isEntryPoint() {
  try {
    return process.argv[1] !== undefined && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
}

if (isEntryPoint()) {
  try {
    await main(process.argv.slice(2));
  } catch (error) {
    const detail = error instanceof CacheError ? error.message : (error?.stack ?? String(error));
    writeSync(2, `notice-material cache: ${detail}\n`);
    process.exitCode = 1;
  }
}
