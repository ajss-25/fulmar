// Packages one verified sharp-libvips delivery-material directory (the output of
// scripts/stage-libvips-delivery-materials.mjs) into a single deterministic
// ustar archive with a SHA-256 sidecar and a concise machine-readable binding,
// and verifies such an archive for a recipient who holds only the archive, the
// binding, an externally supplied expected digest and an independently trusted
// checkout of the exact source commit.
//
// Contract:
// - Explicit operands only; nothing is inferred from the environment. The
//   archive tool is the system /usr/bin/tar (bsdtar/libarchive) run with an
//   explicit minimal environment in ustar format with owner 0:0, empty user and
//   group names, no extended attributes, ACLs, file flags or AppleDouble
//   metadata, and one fixed modification time applied to an invocation-owned
//   copy of the verified set (the inputs are never modified). Two packagings of
//   one verified set therefore yield byte-identical archives with the same
//   bsdtar/libarchive build; the binding records that tool version.
// - The archive is plain ustar without compression: every upstream input is
//   already a compressed archive, the byte count is bounded by the delivery
//   set's own limits, and nothing can expand on extraction beyond the archive's
//   own size. Nested archives stay opaque: nothing is extracted from them,
//   configured, built or executed.
// - The input set is established by the stager's own `verify` before any byte
//   is copied. The created archive is listed, unpacked into invocation-owned
//   staging and verified again by the same stager verifier before publication.
// - The three outputs (`<root>.tar`, `<root>.tar.sha256`, `<root>.binding.json`)
//   are published atomically into one new directory under a private canonical
//   parent. A failure removes only this invocation's staging and leaves the
//   inputs and any existing output untouched. Nothing is ever overwritten.
// - `verify-archive` checks the externally supplied expected digest, the
//   binding's source-commit/cohort/manifest/inventory bindings against the
//   recipient's trusted checkout, and the exact archive listing BEFORE any
//   extraction; unpacks only into a fresh private directory; and then runs the
//   stager verifier on the unpacked root against the tracked manifests. The
//   archive-contained manifests, the sidecar and the binding are payload to be
//   checked, never trust roots: the expected digest must come from a trusted
//   release record, not from a checksum file downloaded beside the archive.
// - Local-fixture / non-authoritative acquisition flags are carried into the
//   binding and the summary truthfully; no option can relabel them.
// - Packaging a private archive completes one engineering step only. It is not
//   a corresponding-source offer, not a release asset, not legal clearance and
//   closes no provenance obligation.
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { constants, realpathSync } from "node:fs";
import { access, chmod, lstat, lutimes, mkdir, open, readdir, realpath, rename, rmdir, unlink } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadManifest } from "./prepare-libvips-source-materials.mjs";
import { loadProvenance, verify as verifyDeliverySet } from "./stage-libvips-delivery-materials.mjs";

const USAGE = [
  "usage: package-libvips-delivery-materials.mjs package <provenance.json> <verified-delivery-directory> <new-output-directory> <source-commit>",
  "       package-libvips-delivery-materials.mjs verify-archive <provenance.json> <archive.tar> <binding.json> <expected-archive-sha256> <source-commit> <new-unpack-directory>"
].join("\n");
const GENERATOR = "scripts/package-libvips-delivery-materials.mjs";
const BINDING_TYPE = "fulmar-libvips-delivery-materials-archive-binding";
const TAR = "/usr/bin/tar";
const TAR_ENVIRONMENT = Object.freeze({ PATH: "/usr/bin:/bin:/usr/sbin:/sbin", LANG: "C", LC_ALL: "C", TZ: "UTC" });
const TAR_TIMEOUT_MILLISECONDS = 15 * 60 * 1000;
const TAR_OUTPUT_BYTES = 16 * 1024 * 1024;
const TAR_CREATE_OPTIONS = Object.freeze(["--format", "ustar", "--no-recursion", "--null", "--no-xattrs", "--no-mac-metadata", "--no-acls", "--no-fflags", "--numeric-owner", "--uid", "0", "--gid", "0"]);
const TAR_EXTRACT_OPTIONS = Object.freeze(["--no-same-owner", "--keep-old-files", "--no-xattrs", "--no-mac-metadata", "--no-acls", "--no-fflags"]);
// 2000-01-01T00:00:00Z: one fixed, obviously synthetic member timestamp.
const ARCHIVE_MTIME_EPOCH_SECONDS = 946684800;
const FILE_MODE = 0o600;
const DIRECTORY_MODE = 0o700;
const USTAR_NAME_LIMIT = 100;
const USTAR_PREFIX_LIMIT = 155;
const MAXIMUM_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024;
const MAXIMUM_MEMBERS = 4096;
const MAXIMUM_BINDING_BYTES = 4 * 1024 * 1024;
const CHUNK_BYTES = 1024 * 1024;
const SHA256 = /^[a-f0-9]{64}$/u;
const COMMIT = /^[a-f0-9]{40}$/u;
const DIRECTORY_NAME = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,199}$/u;
const REQUIRED_SET_FILES = Object.freeze(["DELIVERY_INVENTORY.json", "DELIVERY_STATUS.md", "SHA256SUMS"]);

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function fail(message) {
  throw new Error(message);
}

function byCodePoint(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function assertSafeRelativePath(value, label) {
  if (typeof value !== "string" || value.length === 0 || value.length > 1024 || isAbsolute(value) || value.includes("\\") || /[\0\r\n]/u.test(value)) {
    fail(`${label} must be one bounded POSIX relative path`);
  }
  if (value.split("/").some((segment) => segment.length === 0 || segment === "." || segment === "..")) fail(`${label} contains an unsafe path segment`);
  return value;
}

function requireExactKeys(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort(byCodePoint).join("\0") !== [...keys].sort(byCodePoint).join("\0")) {
    fail(`${label} has an unexpected shape (expected exactly: ${keys.join(", ")})`);
  }
}

async function boundedRegularBytes(path, maximumBytes, label) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size <= 0n || before.size > BigInt(maximumBytes)) {
      fail(`${label} is not one bounded, unlinked regular file`);
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeNs !== after.mtimeNs || BigInt(bytes.byteLength) !== after.size) {
      fail(`${label} changed while it was being read`);
    }
    return bytes;
  } finally {
    await handle?.close();
  }
}

// Streams one large regular file through SHA-256 without holding it in memory.
async function hashRegularFile(path, maximumBytes, label) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size <= 0n || before.size > BigInt(maximumBytes)) {
      fail(`${label} is not one bounded, unlinked regular file`);
    }
    const hash = createHash("sha256");
    let read = 0n;
    for await (const chunk of handle.createReadStream({ autoClose: false, highWaterMark: CHUNK_BYTES })) {
      hash.update(chunk);
      read += BigInt(chunk.byteLength);
    }
    const after = await handle.stat({ bigint: true });
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeNs !== after.mtimeNs || read !== after.size) {
      fail(`${label} changed while it was being read`);
    }
    return { sha256: hash.digest("hex"), size: Number(before.size) };
  } finally {
    await handle?.close();
  }
}

async function requireCanonicalDirectory(path, label) {
  const details = await lstat(path);
  if (!details.isDirectory() || details.isSymbolicLink()) fail(`${label} is not a real directory`);
  if (await realpath(path) !== path) fail(`${label} must not traverse aliases or symbolic links`);
  return details;
}

// A private parent for new outputs: canonical, owned by this user and writable
// by nobody else. Everything created inside it is 0700/0600.
async function requirePrivateDirectory(path, label) {
  const details = await requireCanonicalDirectory(path, label);
  if (typeof process.getuid === "function" && details.uid !== process.getuid()) fail(`${label} is not owned by the current user`);
  if ((details.mode & 0o022) !== 0) fail(`${label} is writable by other users; a private destination is required`);
}

async function requireCanonicalRegularFile(path, label) {
  const details = await lstat(path);
  if (!details.isFile() || details.isSymbolicLink()) fail(`${label} is not a regular file`);
  if (await realpath(path) !== path) fail(`${label} must not traverse aliases or symbolic links`);
}

// Resolves one operand that must name a NEW path under a private canonical
// parent, returning the canonical destination, its parent and its name.
async function requireNewPrivateDestination(argument, label) {
  const destination = resolve(argument);
  const parent = dirname(destination);
  const name = basename(destination);
  if (!DIRECTORY_NAME.test(name)) fail(`${label} name is invalid: ${name}`);
  await requirePrivateDirectory(parent, `${label} parent directory`);
  try {
    await lstat(destination);
    fail(`${label} already exists; verify it or remove it deliberately instead of overwriting: ${destination}`);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  return { destination, parent, name };
}

async function writeExclusive(root, relativePath, bytes) {
  const segments = relativePath.split("/");
  let directory = root;
  for (const segment of segments.slice(0, -1)) {
    directory = join(directory, segment);
    await mkdir(directory, { mode: DIRECTORY_MODE, recursive: false }).catch((error) => { if (error?.code !== "EEXIST") throw error; });
  }
  const handle = await open(join(root, ...segments), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, FILE_MODE);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function syncDirectories(root) {
  const handle = await open(root, constants.O_RDONLY);
  try { await handle.sync(); } finally { await handle.close(); }
  for (const entry of await readdir(root, { withFileTypes: true })) {
    if (entry.isDirectory()) await syncDirectories(join(root, entry.name));
  }
}

// Removes this invocation's own staging tree without following links. A hostile
// archive may have left a directory without traversal rights; restoring 0700 on
// a real directory owned by this invocation is the only mode change made.
async function removeTree(root) {
  let details;
  try {
    details = await lstat(root);
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw error;
  }
  if (details.isDirectory() && !details.isSymbolicLink()) {
    await chmod(root, DIRECTORY_MODE).catch(() => {});
    for (const entry of await readdir(root)) await removeTree(join(root, entry));
    await rmdir(root);
  } else {
    await unlink(root);
  }
}

// Every unpacked entry must be a real directory of mode 0700 or a regular file
// of mode 0600, exactly as the packager stores them; anything else is refused
// before the stager verifier reads the tree. Directory modes are checked before
// the directory is entered, so an untraversable directory fails closed cleanly.
async function requireUnpackedModes(root, label) {
  let entries = 0;
  async function visit(directory, relative) {
    const details = await lstat(directory);
    if (details.isSymbolicLink() || !details.isDirectory()) fail(`${label} is not a real directory: ${relative}`);
    if ((details.mode & 0o777) !== DIRECTORY_MODE) fail(`${label} directory mode is not 0700: ${relative}`);
    for (const entry of (await readdir(directory)).sort(byCodePoint)) {
      entries += 1;
      if (entries > MAXIMUM_MEMBERS) fail(`${label} carries more than ${MAXIMUM_MEMBERS} entries`);
      const path = join(directory, entry);
      const relativePath = `${relative}/${entry}`;
      const child = await lstat(path);
      if (child.isSymbolicLink()) fail(`${label} carries a symbolic link: ${relativePath}`);
      if (child.isDirectory()) {
        await visit(path, relativePath);
      } else if (child.isFile()) {
        if ((child.mode & 0o777) !== FILE_MODE) fail(`${label} file mode is not 0600: ${relativePath}`);
      } else {
        fail(`${label} carries a special file: ${relativePath}`);
      }
    }
  }
  await visit(root, basename(root));
}

function runTar(args, label, cwd) {
  const result = spawnSync(TAR, args, {
    cwd,
    env: TAR_ENVIRONMENT,
    stdio: ["ignore", "pipe", "pipe"],
    encoding: "utf8",
    maxBuffer: TAR_OUTPUT_BYTES,
    timeout: TAR_TIMEOUT_MILLISECONDS
  });
  if (result.error) fail(`${label}: ${TAR} could not run (${result.error.message})`);
  if (result.status !== 0 || result.signal !== null) {
    fail(`${label}: ${TAR} failed (${result.signal === null ? `status ${result.status}` : `signal ${result.signal}`}): ${String(result.stderr ?? "").trim().slice(0, 2000)}`);
  }
  return result.stdout;
}

async function tarVersion() {
  await access(TAR, constants.X_OK).catch(() => fail(`${TAR} is not an executable archive tool`));
  const line = runTar(["--version"], "archive tool version").split("\n")[0].trim();
  if (line.length === 0 || line.length > 200 || /[\0\r]/u.test(line)) fail("archive tool did not report a bounded version line");
  return line;
}

// ---------------------------------------------------------------------------
// Member plan: the root directory, every intermediate directory and every
// verified file, in one deterministic code-point order (a parent always sorts
// before its children because it is a proper prefix). Directory entries are
// listed with a trailing slash, exactly as bsdtar lists them.

function assertUstarName(entry) {
  if (entry.length <= USTAR_NAME_LIMIT) return;
  for (let index = entry.indexOf("/"); index !== -1 && index <= USTAR_PREFIX_LIMIT; index = entry.indexOf("/", index + 1)) {
    const nameLength = entry.length - index - 1;
    if (nameLength > 0 && nameLength <= USTAR_NAME_LIMIT) return;
  }
  fail(`archive member does not fit the ustar name and prefix fields: ${entry}`);
}

function planMembers(root, files) {
  if (!DIRECTORY_NAME.test(root)) fail(`archive root directory name is invalid: ${root}`);
  const directories = new Set();
  for (const path of files) {
    assertSafeRelativePath(path, "delivery file path");
    const segments = path.split("/");
    for (let depth = 1; depth < segments.length; depth += 1) directories.add(segments.slice(0, depth).join("/"));
  }
  for (const path of files) if (directories.has(path)) fail(`delivery file path collides with a directory: ${path}`);
  const nested = [
    ...[...directories].map((path) => ({ path, kind: "directory" })),
    ...files.map((path) => ({ path, kind: "file" }))
  ].sort((left, right) => byCodePoint(left.path, right.path));
  const entries = [{ path: root, kind: "directory" }, ...nested.map((entry) => ({ path: `${root}/${entry.path}`, kind: entry.kind }))];
  if (entries.length > MAXIMUM_MEMBERS) fail(`archive would carry more than ${MAXIMUM_MEMBERS} members`);
  const listing = entries.map((entry) => (entry.kind === "directory" ? `${entry.path}/` : entry.path));
  for (const name of listing) assertUstarName(name);
  return { entries, listing, directories: [...directories].sort(byCodePoint) };
}

function expectedFilesOf(expected) {
  return [...expected.entries()].map(([path, entry]) => ({ path, size: entry.size, sha256: entry.sha256 })).sort((left, right) => byCodePoint(left.path, right.path));
}

// Copies every verified file into an invocation-owned payload tree (re-hashing
// each one), then applies the fixed timestamp bottom-up so the archive's
// metadata depends only on the verified content.
async function materializePayload(deliveryDirectory, payloadRoot, expected, directories) {
  await mkdir(payloadRoot, { mode: DIRECTORY_MODE });
  for (const { path, size, sha256: digest } of expectedFilesOf(expected)) {
    const bytes = await boundedRegularBytes(join(deliveryDirectory, ...path.split("/")), Math.max(size, 1), `delivery file ${path}`);
    if (bytes.byteLength !== size || sha256(bytes) !== digest) fail(`delivery file drifted between verification and packaging: ${path}`);
    await writeExclusive(payloadRoot, path, bytes);
  }
  const epoch = new Date(ARCHIVE_MTIME_EPOCH_SECONDS * 1000);
  for (const path of expected.keys()) await lutimes(join(payloadRoot, ...path.split("/")), epoch, epoch);
  const deepestFirst = [...directories].sort((left, right) => right.split("/").length - left.split("/").length || byCodePoint(left, right));
  for (const directory of deepestFirst) await lutimes(join(payloadRoot, ...directory.split("/")), epoch, epoch);
  await lutimes(payloadRoot, epoch, epoch);
}

function createArchive(payloadParent, listPath, archivePath) {
  runTar(["-c", ...TAR_CREATE_OPTIONS, "-T", listPath, "-f", archivePath], "archive creation", payloadParent);
}

function listArchive(archivePath) {
  const output = runTar(["-t", "-f", archivePath], "archive listing");
  if (output.length === 0 || !output.endsWith("\n")) fail("archive listing is empty or unterminated");
  const names = output.split("\n").slice(0, -1);
  if (names.length > MAXIMUM_MEMBERS) fail(`archive lists more than ${MAXIMUM_MEMBERS} members`);
  return names;
}

function requireExactListing(archivePath, expectedListing) {
  const names = listArchive(archivePath);
  for (const name of names) {
    if (name.length === 0 || name.startsWith("/") || name.includes("\\") || /[\0\r]/u.test(name)
        || name.replace(/\/$/u, "").split("/").some((segment) => segment.length === 0 || segment === "." || segment === "..")) {
      fail(`archive carries an unsafe member name: ${JSON.stringify(name)}`);
    }
  }
  if (names.length !== expectedListing.length || names.some((name, index) => name !== expectedListing[index])) {
    const unexpected = names.filter((name) => !expectedListing.includes(name));
    const missing = expectedListing.filter((name) => !names.includes(name));
    fail(`archive listing does not equal the bound member set${unexpected.length > 0 ? `; unexpected: ${unexpected.slice(0, 8).map((name) => JSON.stringify(name)).join(", ")}` : ""}${missing.length > 0 ? `; missing: ${missing.slice(0, 8).map((name) => JSON.stringify(name)).join(", ")}` : ""}${unexpected.length === 0 && missing.length === 0 ? "; member order differs" : ""}`);
  }
}

function extractArchive(archivePath, directory) {
  runTar(["-x", ...TAR_EXTRACT_OPTIONS, "-C", directory, "-f", archivePath], "archive extraction");
}

// Unpacks into an existing empty private directory and runs the stager's
// verifier on the single root it must contain. Returns the verified state.
async function unpackAndVerify(provenanceArgument, archivePath, directory, root) {
  extractArchive(archivePath, directory);
  const entries = await readdir(directory, { withFileTypes: true });
  if (entries.length !== 1 || entries[0].name !== root || !entries[0].isDirectory() || entries[0].isSymbolicLink()) {
    fail(`unpacked archive does not contain exactly the single root directory ${root}`);
  }
  const unpackedRoot = join(directory, root);
  await requireCanonicalDirectory(unpackedRoot, "unpacked root");
  await requireUnpackedModes(unpackedRoot, "unpacked archive");
  return verifyDeliverySet(provenanceArgument, unpackedRoot);
}

function requireSameFiles(left, right, label) {
  const render = (files) => files.map(({ path, size, sha256: digest }) => `${digest} ${size} ${path}`).join("\n");
  if (render(left) !== render(right)) fail(`${label} does not equal the verified delivery inventory`);
}

// ---------------------------------------------------------------------------
// Binding: exact source commit, redistributed binary, tracked manifest digests,
// staged delivery inventory and archive identity. No timestamps, no private
// paths, no legal conclusion.

function renderBinding(verified, sourceCommit, plan, archive, toolVersion) {
  const { provenance, inputs, inventory, expected } = verified;
  const files = expectedFilesOf(expected);
  const root = provenance.delivery.outputDirectoryName;
  const binding = {
    schemaVersion: 1,
    bindingType: BINDING_TYPE,
    generator: GENERATOR,
    purpose: "Binds one private source-materials archive to the exact source commit, redistributed binary, tracked manifests and staged delivery inventory it was packaged from, so that a recipient holding an independently trusted checkout can verify it. It is not a corresponding-source offer, not a release asset and not legal clearance; no obligation is closed by it.",
    sourceCommit,
    component: inventory.component,
    binary: inventory.binary,
    trackedBindings: {
      provenanceRecord: { path: provenance.relativePath, sha256: provenance.sha256 },
      sourceMaterials: { path: provenance.delivery.sourceMaterials, sha256: inputs.upstream.manifestSHA256 },
      rustCrateMaterials: { path: provenance.delivery.rustCrateMaterials, sha256: inputs.crates.manifestSHA256 },
      rustNoticeMaterials: { path: provenance.delivery.rustNoticeMaterials, sha256: inputs.crates.noticeMaterials.sha256 },
      accompanyingDocumentation: { path: provenance.delivery.documentation.path, sha256: inputs.documentSHA256 }
    },
    acquisition: {
      upstreamSource: { transport: inputs.upstream.transport, authoritative: inputs.upstream.authoritative, itemCount: inputs.upstream.manifest.items.length, totalBytes: inputs.upstream.manifest.totalBytes },
      rustCrates: { transport: inputs.crates.transport, authoritative: inputs.crates.authoritative, itemCount: inputs.crates.manifest.items.length, totalBytes: inputs.crates.manifest.totalBytes }
    },
    status: inventory.status,
    deliverySet: {
      rootDirectory: root,
      fileCount: files.length,
      totalBytes: files.reduce((total, file) => total + file.size, 0),
      inventory: { path: "DELIVERY_INVENTORY.json", sha256: verified.inventorySHA256 },
      statusRecord: { path: "DELIVERY_STATUS.md", sha256: verified.statusSHA256 },
      checksumList: { path: "SHA256SUMS", sha256: verified.sumsSHA256 },
      files
    },
    archive: {
      fileName: `${root}.tar`,
      format: "ustar",
      compression: "none",
      size: archive.size,
      sha256: archive.sha256,
      memberCount: plan.entries.length,
      directoryCount: plan.entries.filter((entry) => entry.kind === "directory").length,
      fileCount: plan.entries.filter((entry) => entry.kind === "file").length,
      metadata: {
        uid: 0,
        gid: 0,
        uname: "",
        gname: "",
        mtimeEpochSeconds: ARCHIVE_MTIME_EPOCH_SECONDS,
        fileMode: "0600",
        directoryMode: "0700",
        tool: TAR,
        toolVersion,
        createOptions: [...TAR_CREATE_OPTIONS]
      },
      sidecar: { fileName: `${root}.tar.sha256`, format: "sha256sum" }
    },
    statement: "A privately packaged material-delivery preparation set. Its hashes matching this binding proves only that the archive carries exactly the verified staged bytes; it does not prove a rebuild, dylib incorporation, legal completeness of corresponding source, a public offer, or legal clearance. The expected archive digest must be taken from a trusted release record, not from files downloaded beside the archive."
  };
  return `${JSON.stringify(binding, null, 2)}\n`;
}

// ---------------------------------------------------------------------------
// package

async function packageArchive(provenanceArgument, deliveryArgument, outputArgument, sourceCommit) {
  if (!COMMIT.test(sourceCommit ?? "")) fail("source commit must be one full 40-hex commit");
  const toolVersion = await tarVersion();
  const provenance = await loadProvenance(provenanceArgument);
  const deliveryDirectory = resolve(deliveryArgument);
  await requireCanonicalDirectory(deliveryDirectory, "delivery directory");
  const { destination, parent, name } = await requireNewPrivateDestination(outputArgument, "output directory");
  if (deliveryDirectory === destination || destination.startsWith(`${deliveryDirectory}/`) || deliveryDirectory.startsWith(`${destination}/`)) {
    fail("output directory must not overlap the delivery directory");
  }
  // The exact input set is established by the stager's own verifier.
  const verified = await verifyDeliverySet(provenanceArgument, deliveryDirectory);
  const root = provenance.delivery.outputDirectoryName;
  const plan = planMembers(root, [...verified.expected.keys()].sort(byCodePoint));
  const payloadBytes = expectedFilesOf(verified.expected).reduce((total, file) => total + file.size, 0);
  const staging = join(parent, `.${name}.staging.${process.pid}.${randomBytes(8).toString("hex")}`);
  await mkdir(staging, { mode: DIRECTORY_MODE });
  let published = false;
  try {
    const payloadParent = join(staging, "payload");
    const publish = join(staging, "publish");
    const check = join(staging, "check");
    for (const directory of [payloadParent, publish, check]) await mkdir(directory, { mode: DIRECTORY_MODE });
    await materializePayload(deliveryDirectory, join(payloadParent, root), verified.expected, plan.directories);
    const listPath = join(staging, "members.list");
    await writeExclusive(staging, "members.list", Buffer.from(`${plan.entries.map((entry) => entry.path).join("\0")}\0`, "utf8"));
    const archiveName = `${root}.tar`;
    const archivePath = join(publish, archiveName);
    createArchive(payloadParent, listPath, archivePath);
    requireExactListing(archivePath, plan.listing);
    const archive = await hashRegularFile(archivePath, MAXIMUM_ARCHIVE_BYTES, "created archive");
    // Round trip: the archive must unpack to exactly the verified set before it
    // is published, through the same verifier a recipient will run.
    const unpacked = await unpackAndVerify(provenanceArgument, archivePath, check, root);
    requireSameFiles(expectedFilesOf(unpacked.expected), expectedFilesOf(verified.expected), "unpacked archive tree");
    if (unpacked.inventorySHA256 !== verified.inventorySHA256) fail("unpacked delivery inventory digest differs from the verified input");
    const bindingText = renderBinding(verified, sourceCommit, plan, archive, toolVersion);
    await writeExclusive(publish, `${root}.binding.json`, Buffer.from(bindingText, "utf8"));
    await writeExclusive(publish, `${archiveName}.sha256`, Buffer.from(`${archive.sha256}  ${archiveName}\n`, "utf8"));
    const rehashed = await hashRegularFile(archivePath, MAXIMUM_ARCHIVE_BYTES, "created archive");
    if (rehashed.sha256 !== archive.sha256 || rehashed.size !== archive.size) fail("created archive changed before publication");
    const names = (await readdir(publish)).sort(byCodePoint);
    if (names.join("\0") !== [archiveName, `${archiveName}.sha256`, `${root}.binding.json`].sort(byCodePoint).join("\0")) fail("publication directory carries unexpected entries");
    await syncDirectories(publish);
    await rename(publish, destination);
    published = true;
    const authoritative = verified.inputs.upstream.authoritative && verified.inputs.crates.authoritative;
    process.stderr.write(`packaged ${plan.entries.filter((entry) => entry.kind === "file").length} files (${payloadBytes} bytes) as ${destination}/${archiveName} (${archive.size} bytes, sha256:${archive.sha256}, ustar, ${plan.entries.length} members, mtime ${ARCHIVE_MTIME_EPOCH_SECONDS}, ${toolVersion}); binding ${root}.binding.json sha256:${sha256(Buffer.from(bindingText, "utf8"))}; source commit ${sourceCommit}; upstream ${verified.inputs.upstream.transport}${verified.inputs.upstream.authoritative ? "" : " (NOT authoritative)"}, crates ${verified.inputs.crates.transport}${verified.inputs.crates.authoritative ? "" : " (NOT authoritative)"}; acquisition ${authoritative ? "authoritative" : "NOT authoritative"}; unresolved notices ${verified.inputs.crates.noticeMaterials.summary.unresolved.length}; not a source offer, not a release asset, not legal clearance\n`);
  } finally {
    await removeTree(staging);
  }
}

// ---------------------------------------------------------------------------
// verify-archive

async function trackedDigest(projectRoot, relativePath, label) {
  assertSafeRelativePath(relativePath, label);
  const absolute = join(projectRoot, ...relativePath.split("/"));
  if (await realpath(absolute) !== absolute) fail(`${label} must not traverse aliases or symbolic links: ${relativePath}`);
  return sha256(await boundedRegularBytes(absolute, MAXIMUM_BINDING_BYTES * 2, label));
}

// Validates the binding as untrusted payload against the recipient's trusted
// checkout: exact shape, the externally supplied digest, the source commit,
// the provenance component, every tracked manifest digest and the binary cohort.
async function loadBinding(bindingArgument, provenance, expectedSHA256, sourceCommit, archiveSize) {
  const bindingPath = resolve(bindingArgument);
  await requireCanonicalRegularFile(bindingPath, "binding");
  const bytes = await boundedRegularBytes(bindingPath, MAXIMUM_BINDING_BYTES, "binding");
  const text = bytes.toString("utf8");
  if (text.includes("\0") || text.includes("\r") || Buffer.from(text, "utf8").compare(bytes) !== 0) fail("binding is not canonical UTF-8 text");
  let binding;
  try { binding = JSON.parse(text); }
  catch (error) { fail(`binding is not valid JSON: ${error.message}`); }
  requireExactKeys(binding, ["acquisition", "archive", "binary", "bindingType", "component", "deliverySet", "generator", "purpose", "schemaVersion", "sourceCommit", "statement", "status", "trackedBindings"], "binding");
  if (binding.schemaVersion !== 1 || binding.bindingType !== BINDING_TYPE || binding.generator !== GENERATOR) fail("binding has an unsupported type or schema");
  if (typeof binding.purpose !== "string" || !/not legal clearance/u.test(binding.purpose)) fail("binding purpose must state that it is not legal clearance");
  if (binding.sourceCommit !== sourceCommit) fail(`binding names source commit ${String(binding.sourceCommit).slice(0, 40)}, not the trusted checkout's ${sourceCommit}`);
  requireExactKeys(binding.archive, ["compression", "directoryCount", "fileCount", "fileName", "format", "memberCount", "metadata", "sha256", "sidecar", "size"], "binding archive");
  if (binding.archive.sha256 !== expectedSHA256) fail("binding archive digest differs from the externally supplied expected digest");
  if (binding.archive.size !== archiveSize) fail("binding archive size differs from the archive file");
  if (binding.archive.format !== "ustar" || binding.archive.compression !== "none") fail("binding names an unsupported archive format");
  requireExactKeys(binding.archive.metadata, ["createOptions", "directoryMode", "fileMode", "gid", "gname", "mtimeEpochSeconds", "tool", "toolVersion", "uid", "uname"], "binding archive metadata");
  if (binding.archive.metadata.uid !== 0 || binding.archive.metadata.gid !== 0 || binding.archive.metadata.uname !== "" || binding.archive.metadata.gname !== ""
      || binding.archive.metadata.mtimeEpochSeconds !== ARCHIVE_MTIME_EPOCH_SECONDS || binding.archive.metadata.fileMode !== "0600" || binding.archive.metadata.directoryMode !== "0700") {
    fail("binding archive metadata does not describe the deterministic ustar contract");
  }
  const root = provenance.delivery.outputDirectoryName;
  if (binding.archive.fileName !== `${root}.tar`) fail(`binding names archive ${String(binding.archive.fileName).slice(0, 200)}, not ${root}.tar`);
  requireExactKeys(binding.component, ["buildCommit", "id", "lockfilePath", "openObligations", "packageName", "version"], "binding component");
  if (binding.component.id !== provenance.component.id || binding.component.packageName !== provenance.component.packageName
      || binding.component.version !== provenance.component.version || binding.component.buildCommit !== provenance.component.buildCommit
      || JSON.stringify(binding.component.openObligations) !== JSON.stringify(provenance.component.openObligations)) {
    fail("binding component does not match the trusted provenance record");
  }
  requireExactKeys(binding.trackedBindings, ["accompanyingDocumentation", "provenanceRecord", "rustCrateMaterials", "rustNoticeMaterials", "sourceMaterials"], "binding trackedBindings");
  const expectedTracked = {
    provenanceRecord: { path: provenance.relativePath, sha256: provenance.sha256 },
    sourceMaterials: { path: provenance.delivery.sourceMaterials },
    rustCrateMaterials: { path: provenance.delivery.rustCrateMaterials },
    rustNoticeMaterials: { path: provenance.delivery.rustNoticeMaterials },
    accompanyingDocumentation: { path: provenance.delivery.documentation.path }
  };
  for (const [key, expectation] of Object.entries(expectedTracked)) {
    const record = binding.trackedBindings[key];
    requireExactKeys(record, ["path", "sha256"], `binding trackedBindings ${key}`);
    if (record.path !== expectation.path) fail(`binding trackedBindings ${key} names ${String(record.path).slice(0, 200)}, not ${expectation.path}`);
    const digest = expectation.sha256 ?? await trackedDigest(provenance.projectRoot, expectation.path, `tracked ${key}`);
    if (record.sha256 !== digest) fail(`binding trackedBindings ${key} digest does not match the trusted checkout (${expectation.path})`);
  }
  const crateManifest = await loadManifest(join(provenance.projectRoot, ...provenance.delivery.rustCrateMaterials.split("/")));
  if (JSON.stringify(binding.binary) !== JSON.stringify(crateManifest.manifest.binary)) fail("binding binary cohort does not match the trusted crate manifest");
  requireExactKeys(binding.deliverySet, ["checksumList", "fileCount", "files", "inventory", "rootDirectory", "statusRecord", "totalBytes"], "binding deliverySet");
  if (binding.deliverySet.rootDirectory !== root) fail(`binding names delivery root ${String(binding.deliverySet.rootDirectory).slice(0, 200)}, not ${root}`);
  if (!Array.isArray(binding.deliverySet.files) || binding.deliverySet.files.length === 0 || binding.deliverySet.files.length > MAXIMUM_MEMBERS
      || binding.deliverySet.fileCount !== binding.deliverySet.files.length) {
    fail("binding deliverySet files must be one bounded list matching fileCount");
  }
  const paths = new Set();
  let total = 0;
  for (const file of binding.deliverySet.files) {
    requireExactKeys(file, ["path", "sha256", "size"], "binding deliverySet file");
    assertSafeRelativePath(file.path, "binding deliverySet file path");
    if (paths.has(file.path) || !SHA256.test(file.sha256 ?? "") || !Number.isSafeInteger(file.size) || file.size < 0) fail(`binding deliverySet file is malformed or duplicated: ${file.path}`);
    paths.add(file.path);
    total += file.size;
  }
  if (binding.deliverySet.totalBytes !== total) fail("binding deliverySet totalBytes does not equal the sum of its files");
  for (const required of REQUIRED_SET_FILES) if (!paths.has(required)) fail(`binding deliverySet omits ${required}`);
  for (const key of ["inventory", "statusRecord", "checksumList"]) requireExactKeys(binding.deliverySet[key], ["path", "sha256"], `binding deliverySet ${key}`);
  const files = [...binding.deliverySet.files].map(({ path, size, sha256: digest }) => ({ path, size, sha256: digest })).sort((left, right) => byCodePoint(left.path, right.path));
  return { path: bindingPath, sha256: sha256(bytes), binding, files, root };
}

async function verifyArchive(provenanceArgument, archiveArgument, bindingArgument, expectedSHA256, sourceCommit, unpackArgument) {
  if (!SHA256.test(expectedSHA256 ?? "")) fail("expected archive digest must be one lowercase SHA-256");
  if (!COMMIT.test(sourceCommit ?? "")) fail("source commit must be one full 40-hex commit");
  const toolVersion = await tarVersion();
  const provenance = await loadProvenance(provenanceArgument);
  const archivePath = resolve(archiveArgument);
  await requireCanonicalRegularFile(archivePath, "archive");
  // 1. The externally supplied digest, before anything else is trusted.
  const archive = await hashRegularFile(archivePath, MAXIMUM_ARCHIVE_BYTES, "archive");
  if (archive.sha256 !== expectedSHA256) fail(`archive SHA-256 is ${archive.sha256}, not the expected ${expectedSHA256}; nothing was extracted`);
  // 2. The binding, as payload checked against the trusted checkout.
  const bound = await loadBinding(bindingArgument, provenance, expectedSHA256, sourceCommit, archive.size);
  // 3. The exact member listing, before extraction.
  const plan = planMembers(bound.root, bound.files.map((file) => file.path));
  if (bound.binding.archive.memberCount !== plan.entries.length || bound.binding.archive.fileCount !== bound.files.length
      || bound.binding.archive.directoryCount !== plan.entries.length - bound.files.length) {
    fail("binding archive member counts do not match its delivery inventory");
  }
  requireExactListing(archivePath, plan.listing);
  // 4. Unpack only into a fresh private directory, then run the stager verifier.
  const { destination, parent, name } = await requireNewPrivateDestination(unpackArgument, "unpack directory");
  if (archivePath.startsWith(`${destination}/`) || bound.path.startsWith(`${destination}/`)) fail("unpack directory must not contain the archive or the binding");
  const staging = join(parent, `.${name}.unpack.${process.pid}.${randomBytes(8).toString("hex")}`);
  await mkdir(staging, { mode: DIRECTORY_MODE });
  let published = false;
  try {
    const verified = await unpackAndVerify(provenanceArgument, archivePath, staging, bound.root);
    requireSameFiles(expectedFilesOf(verified.expected), bound.files, "binding deliverySet");
    if (bound.binding.deliverySet.inventory.sha256 !== verified.inventorySHA256 || bound.binding.deliverySet.statusRecord.sha256 !== verified.statusSHA256
        || bound.binding.deliverySet.checksumList.sha256 !== verified.sumsSHA256) {
      fail("binding deliverySet record digests do not match the unpacked, verified set");
    }
    const rehashed = await hashRegularFile(archivePath, MAXIMUM_ARCHIVE_BYTES, "archive");
    if (rehashed.sha256 !== expectedSHA256) fail("archive changed while it was being verified");
    await syncDirectories(staging);
    await rename(staging, destination);
    published = true;
    const { inputs } = verified;
    const authoritative = inputs.upstream.authoritative && inputs.crates.authoritative;
    process.stderr.write(`verified archive ${archivePath} (${archive.size} bytes, sha256:${archive.sha256}) against source commit ${sourceCommit} and binding ${bound.path} (sha256:${bound.sha256}); unpacked ${verified.expected.size} files to ${destination}/${bound.root} and re-verified them against the tracked manifests; upstream ${inputs.upstream.transport}${inputs.upstream.authoritative ? "" : " (NOT authoritative)"}, crates ${inputs.crates.transport}${inputs.crates.authoritative ? "" : " (NOT authoritative)"}; acquisition ${authoritative ? "authoritative" : "NOT authoritative"}; unresolved notices ${inputs.crates.noticeMaterials.summary.unresolved.length}; dylib incorporation ${inputs.crates.manifest.provenanceStatuses.incorporatedIntoShippedBinary}; archive tool ${toolVersion}${toolVersion === bound.binding.archive.metadata.toolVersion ? "" : ` (binding recorded ${bound.binding.archive.metadata.toolVersion}; byte-identical re-packaging is only claimed for that build)`}; not a legal conclusion\n`);
  } finally {
    if (!published) await removeTree(staging);
  }
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
  if (operands.some((operand) => typeof operand !== "string" || operand.length === 0 || operand.startsWith("--"))) fail(USAGE);
  if (command === "package" && operands.length === 4) {
    await packageArchive(...operands);
  } else if (command === "verify-archive" && operands.length === 6) {
    await verifyArchive(...operands);
  } else {
    fail(USAGE);
  }
}

export { packageArchive, verifyArchive };
