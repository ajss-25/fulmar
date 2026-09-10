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
//   bsdtar/libarchive build; the binding records that tool version. A different
//   tool version on the verifying host is reported, not rejected: byte-identical
//   re-packaging is only claimed for the recorded build.
// - The archive is plain POSIX ustar without compression, and that is enforced
//   rather than assumed: before anything is extracted, the stream is walked
//   header by header and must contain exactly the planned members in the planned
//   order — regular files and directories only, POSIX ustar magic/version, octal
//   numeric fields, owner 0:0, empty user/group names, the fixed mtime, modes
//   0600/0700, sizes equal to the bound inventory, zero padding, the two
//   end-of-archive blocks and only zero padding after them. Compressed streams
//   (gzip, bzip2, xz, zstd, lz4, compress), pax/GNU extension records, sparse
//   members, links, special files, duplicate or escaping names and base-256
//   numeric encodings are refused at that point, so nothing unsupported can
//   reach the system tar, and the bytes the system tar will write are exactly
//   the validated member sizes (bounded per member and in total). The system tar
//   is relied on only to extract a stream already proven to be that narrow
//   subset; nested upstream archives stay opaque (nothing is extracted from
//   them, configured, built or executed).
// - The input set is established by the stager's own `verify` before any byte
//   is copied. The created archive is validated, listed, unpacked into
//   invocation-owned staging and verified again by the same stager verifier
//   before publication.
// - The three outputs (`<root>.tar`, `<root>.tar.sha256`, `<root>.binding.json`)
//   are published atomically into one new directory under a private canonical
//   parent. A failure removes only this invocation's staging and leaves the
//   inputs and any existing output untouched. Nothing is ever overwritten.
// - `verify-archive` binds every consumer to the bytes it hashed: the external
//   archive is read once, through an attested open descriptor whose identity is
//   checked before, during and after the read, into one private snapshot inside
//   invocation-owned staging; the snapshot's digest must equal the externally
//   supplied expected digest before anything else happens, and the format walk,
//   the listing and the extraction all consume that snapshot — the external
//   path is never reopened. The binding is then validated as untrusted payload:
//   exact shape, every fixed path name and declaration, the source commit, the
//   component, the binary cohort, the tracked manifest digests, the acquisition
//   counts and the status facts against the recipient's trusted checkout before
//   extraction, and the acquisition transports, status object, component and
//   inventory against the independently verified material after it. The
//   archive-contained manifests, the sidecar and the binding are payload to be
//   checked, never trust roots: the expected digest must come from a trusted
//   release record, not from a checksum file downloaded beside the archive.
//   `sourceCommit` is compared with the operand the recipient supplies from
//   their trusted checkout (`git rev-parse HEAD` of a clean verified clone); the
//   tool does not authenticate that checkout or the export itself — the tracked
//   digests are what bind the content.
// - Local-fixture / non-authoritative acquisition flags are carried into the
//   binding and the summary truthfully; no option can relabel them.
// - The optional in-process `observers` argument holds function values only
//   (`afterSnapshotOpened`, `afterSnapshotAdmitted`, `beforeExtraction`,
//   `beforePublish`). The CLI passes none and no environment variable can
//   enable them; they exist so deterministic tests can interrupt or observe the
//   tool at exact points. They cannot skip a check: an observer may only observe,
//   throw (which fails closed) or end the process.
// - Packaging a private archive completes one engineering step only. It is not
//   a corresponding-source offer, not a release asset, not legal clearance and
//   closes no provenance obligation.
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { constants, realpathSync } from "node:fs";
import { access, chmod, lstat, lutimes, mkdir, open, readdir, realpath, rename, rmdir, unlink } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
import { consumeAttestedRegularFile } from "./attested-regular-file.mjs";
import { loadManifest, loadRustNoticeMaterials } from "./prepare-libvips-source-materials.mjs";
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
const TAR_BLOCK = 512;
const MAXIMUM_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024;
// The stager's own per-file and per-set limits: no validated member may exceed
// them, so extraction can never write more than these bounds.
const MAXIMUM_MEMBER_BYTES = 256 * 1024 * 1024;
const MAXIMUM_PAYLOAD_BYTES = 1024 * 1024 * 1024;
const MAXIMUM_MEMBERS = 4096;
const MAXIMUM_BINDING_BYTES = 4 * 1024 * 1024;
const CHUNK_BYTES = 1024 * 1024;
const SHA256 = /^[a-f0-9]{64}$/u;
const COMMIT = /^[a-f0-9]{40}$/u;
const DIRECTORY_NAME = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,199}$/u;
const LEGAL_CONCLUSION = /cleared|compliant|legally (?:sufficient|satisfied)/iu;
const INVENTORY_NAME = "DELIVERY_INVENTORY.json";
const STATUS_NAME = "DELIVERY_STATUS.md";
const SUMS_NAME = "SHA256SUMS";
const REQUIRED_SET_FILES = Object.freeze([INVENTORY_NAME, STATUS_NAME, SUMS_NAME]);
const STATUS_KIND = "material-delivery-preparation-set";
const COMPRESSION_MAGICS = Object.freeze([
  { name: "gzip", bytes: [0x1f, 0x8b] },
  { name: "compress", bytes: [0x1f, 0x9d] },
  { name: "bzip2", bytes: [0x42, 0x5a, 0x68] },
  { name: "xz", bytes: [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00] },
  { name: "zstd", bytes: [0x28, 0xb5, 0x2f, 0xfd] },
  { name: "lz4", bytes: [0x04, 0x22, 0x4d, 0x18] },
  { name: "zip", bytes: [0x50, 0x4b, 0x03, 0x04] },
  { name: "7z", bytes: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] }
]);

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

function isSafeMemberName(name) {
  if (typeof name !== "string" || name.length === 0 || name.length > 1024 || name.startsWith("/") || name.includes("\\") || /[\0\r\n]/u.test(name)) return false;
  return !name.replace(/\/$/u, "").split("/").some((segment) => segment.length === 0 || segment === "." || segment === "..");
}

function requireExactKeys(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort(byCodePoint).join("\0") !== [...keys].sort(byCodePoint).join("\0")) {
    fail(`${label} has an unexpected shape (expected exactly: ${keys.join(", ")})`);
  }
}

function boundedString(value, minimum, maximum, label) {
  if (typeof value !== "string" || value.trim() !== value || value.length < minimum || value.length > maximum || /[\0\r\n]/u.test(value)) {
    fail(`${label} must be one bounded single-line string`);
  }
  return value;
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
// (The pre-extraction format walk already guarantees this for a validated
// snapshot; this remains as defence in depth on the bytes the system tar wrote.)
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
// Member plan

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

// The byte count every planned member must declare: the bound inventory size
// for a regular file, zero for a directory. Keyed by listing name.
function plannedSizes(plan, files) {
  const byPath = new Map(files.map((file) => [file.path, file.size]));
  const sizes = new Map();
  plan.entries.forEach((entry, index) => {
    const name = plan.listing[index];
    if (entry.kind === "directory") {
      sizes.set(name, 0);
      return;
    }
    const size = byPath.get(entry.path.slice(entry.path.indexOf("/") + 1));
    if (!Number.isSafeInteger(size) || size < 0) fail(`planned member has no bound size: ${name}`);
    sizes.set(name, size);
  });
  return sizes;
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

// The system tar's own reading of the (already format-validated) stream must
// agree with the plan; a disagreement means the two readers differ and the
// stream is refused rather than trusted to either.
function requireExactListing(archivePath, expectedListing) {
  const names = listArchive(archivePath);
  for (const name of names) {
    if (!isSafeMemberName(name)) fail(`archive carries an unsafe member name: ${JSON.stringify(name)}`);
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

// ---------------------------------------------------------------------------
// Format enforcement: a header-by-header walk of the stream before anything is
// extracted. The stream must be exactly the planned plain POSIX ustar members.

function isZero(bytes) {
  for (const byte of bytes) if (byte !== 0) return false;
  return true;
}

function nulTerminated(header, start, length) {
  const field = header.subarray(start, start + length);
  const end = field.indexOf(0);
  return field.subarray(0, end === -1 ? length : end).toString("latin1");
}

// POSIX ustar numeric fields are leading-space-tolerant octal digits terminated
// by space or NUL. Base-256 (high bit set) and any other encoding is refused.
function octalField(header, start, length, member, name, { allowEmpty = false } = {}) {
  const field = header.subarray(start, start + length);
  const text = field.toString("latin1");
  if ((field[0] & 0x80) !== 0 || !/^ *[0-7]*[ \0]*$/u.test(text)) {
    fail(`${member} carries a non-octal ${name} field; base-256 and other extended encodings are refused`);
  }
  const digits = text.replace(/[ \0]+$/u, "").replace(/^ +/u, "");
  if (digits.length === 0) {
    if (allowEmpty) return 0;
    fail(`${member} carries an empty ${name} field`);
  }
  const value = Number.parseInt(digits, 8);
  if (!Number.isSafeInteger(value)) fail(`${member} carries an out-of-range ${name} field`);
  return value;
}

function headerChecksum(header) {
  let sum = 0;
  for (let index = 0; index < TAR_BLOCK; index += 1) sum += index >= 148 && index < 156 ? 0x20 : header[index];
  return sum;
}

// Walks `path` and proves it is exactly the planned plain ustar stream: a
// compression or container signature, a non-ustar header, an unsupported member
// type, an unsafe or unplanned name, a wrong mode/owner/name/time/link/device
// field, a non-octal or unexpected size, truncated payload or padding, missing
// end-of-archive blocks or bytes after them all fail closed. `sizes` maps every
// planned listing name to the byte count its member must declare. Returns the
// member and payload counts so callers can report what was proven.
async function validateUstarSnapshot(path, plan, sizes, label) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const details = await handle.stat({ bigint: true });
    if (!details.isFile() || details.nlink !== 1n) fail(`${label} is not one unlinked regular file`);
    const total = Number(details.size);
    const block = Buffer.alloc(TAR_BLOCK);
    const readExact = async (position, length) => {
      const { bytesRead } = await handle.read(block, 0, length, position);
      if (bytesRead !== length) fail(`${label} could not be read at offset ${position}`);
      return block.subarray(0, length);
    };
    const signature = await readExact(0, Math.min(8, total));
    for (const { name, bytes } of COMPRESSION_MAGICS) {
      if (signature.byteLength >= bytes.length && bytes.every((byte, index) => signature[index] === byte)) {
        fail(`${label} is a compressed stream (${name}); only a plain ustar stream is accepted`);
      }
    }
    if (total < TAR_BLOCK * 2 || total % TAR_BLOCK !== 0 || total > MAXIMUM_ARCHIVE_BYTES) fail(`${label} is not a whole-block tar stream (${total} bytes)`);
    let offset = 0;
    let index = 0;
    let payloadBytes = 0;
    for (;;) {
      if (offset + TAR_BLOCK > total) fail(`${label} ends without end-of-archive blocks`);
      const header = Buffer.from(await readExact(offset, TAR_BLOCK));
      offset += TAR_BLOCK;
      if (isZero(header)) {
        if (offset + TAR_BLOCK > total) fail(`${label} ends without end-of-archive blocks`);
        if (!isZero(await readExact(offset, TAR_BLOCK))) fail(`${label} carries a non-zero block after its first end-of-archive block`);
        offset += TAR_BLOCK;
        while (offset < total) {
          const length = Math.min(TAR_BLOCK, total - offset);
          if (!isZero(await readExact(offset, length))) fail(`${label} carries non-zero bytes after its end-of-archive blocks`);
          offset += length;
        }
        if (index !== plan.entries.length) fail(`${label} ends after ${index} members; ${plan.entries.length} were planned`);
        return { members: index, payloadBytes, bytes: total };
      }
      const member = `${label} member ${index}`;
      if (index >= MAXIMUM_MEMBERS) fail(`${label} carries more than ${MAXIMUM_MEMBERS} members`);
      const magic = header.subarray(257, 263).toString("latin1");
      const version = header.subarray(263, 265).toString("latin1");
      if (magic !== "ustar\0" || version !== "00") {
        fail(`${member} is not a POSIX ustar header (magic ${JSON.stringify(magic)}, version ${JSON.stringify(version)}); GNU, pax and other tar variants are refused`);
      }
      if (octalField(header, 148, 8, member, "checksum") !== headerChecksum(header)) fail(`${member} carries an invalid header checksum`);
      const type = header.subarray(156, 157).toString("latin1");
      const prefix = nulTerminated(header, 345, USTAR_PREFIX_LIMIT);
      const rawName = nulTerminated(header, 0, USTAR_NAME_LIMIT);
      const name = prefix.length === 0 ? rawName : `${prefix}/${rawName}`;
      const shown = JSON.stringify(name);
      if (type !== "0" && type !== "5") fail(`${member} (${shown}) has unsupported type ${JSON.stringify(type)}; only regular files and directories are accepted`);
      if (!isSafeMemberName(name)) fail(`${member} carries an unsafe member name ${shown}`);
      if (index >= plan.entries.length) fail(`${member} (${shown}) is beyond the ${plan.entries.length} planned members`);
      const planned = plan.entries[index];
      const plannedName = plan.listing[index];
      if (name !== plannedName) fail(`${member} is ${shown}, not the planned ${JSON.stringify(plannedName)}`);
      if ((type === "5") !== (planned.kind === "directory")) fail(`${member} (${shown}) is stored as a ${type === "5" ? "directory" : "regular file"}, but a ${planned.kind} is planned`);
      const mode = octalField(header, 100, 8, member, "mode") & 0o7777;
      const requiredMode = planned.kind === "directory" ? DIRECTORY_MODE : FILE_MODE;
      if (mode !== requiredMode) fail(`${member} (${shown}) has mode ${mode.toString(8).padStart(4, "0")}, not the required ${requiredMode.toString(8).padStart(4, "0")}`);
      if (octalField(header, 108, 8, member, "uid") !== 0 || octalField(header, 116, 8, member, "gid") !== 0) fail(`${member} (${shown}) is not stored with owner 0:0`);
      if (!isZero(header.subarray(265, 329))) fail(`${member} (${shown}) carries a user or group name; the contract stores none`);
      if (octalField(header, 136, 12, member, "mtime") !== ARCHIVE_MTIME_EPOCH_SECONDS) fail(`${member} (${shown}) does not carry the fixed modification time ${ARCHIVE_MTIME_EPOCH_SECONDS}`);
      if (!isZero(header.subarray(157, 257))) fail(`${member} (${shown}) carries a link name`);
      if (octalField(header, 329, 8, member, "devmajor", { allowEmpty: true }) !== 0 || octalField(header, 337, 8, member, "devminor", { allowEmpty: true }) !== 0) fail(`${member} (${shown}) carries device numbers`);
      if (!isZero(header.subarray(500, 512))) fail(`${member} (${shown}) carries non-zero header padding`);
      const size = octalField(header, 124, 12, member, "size");
      const expectedSize = sizes.get(plannedName);
      if (size !== expectedSize) fail(`${member} (${shown}) declares ${size} bytes, not the bound inventory size ${expectedSize}`);
      if (size > MAXIMUM_MEMBER_BYTES) fail(`${member} (${shown}) exceeds the per-member bound of ${MAXIMUM_MEMBER_BYTES} bytes`);
      payloadBytes += size;
      if (payloadBytes > MAXIMUM_PAYLOAD_BYTES) fail(`${label} payload exceeds the bound of ${MAXIMUM_PAYLOAD_BYTES} bytes`);
      const padding = size % TAR_BLOCK === 0 ? 0 : TAR_BLOCK - (size % TAR_BLOCK);
      if (offset + size + padding > total) fail(`${member} (${shown}) payload or padding is truncated`);
      if (padding > 0 && !isZero(await readExact(offset + size, padding))) fail(`${member} (${shown}) carries non-zero padding after its payload`);
      offset += size + padding;
      index += 1;
    }
  } finally {
    await handle?.close();
  }
}

// Unpacks into an existing empty private directory and runs the stager's
// verifier on the single root it must contain. The marker line is written
// immediately before the system tar runs, so a log shows exactly which bytes
// reached extraction. Returns the verified state.
async function unpackAndVerify(provenanceArgument, archivePath, directory, root, description) {
  process.stderr.write(`extracting ${description} into ${directory}\n`);
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

const OBSERVER_NAMES = Object.freeze(["afterSnapshotOpened", "afterSnapshotAdmitted", "beforeExtraction", "beforePublish"]);

// In-process observation points for deterministic tests. Function values only;
// the CLI never passes any and nothing in the environment can supply them.
function normalizeObservers(observers) {
  if (observers === undefined) return Object.freeze({});
  if (!observers || typeof observers !== "object" || Array.isArray(observers)) fail("observers must be one object of function values");
  for (const [name, value] of Object.entries(observers)) {
    if (!OBSERVER_NAMES.includes(name) || typeof value !== "function") fail(`observers may only carry function values named ${OBSERVER_NAMES.join(", ")}`);
  }
  return Object.freeze({ ...observers });
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

async function packageArchive(provenanceArgument, deliveryArgument, outputArgument, sourceCommit, observerArgument) {
  const observers = normalizeObservers(observerArgument);
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
  const files = expectedFilesOf(verified.expected);
  const plan = planMembers(root, files.map((file) => file.path));
  const payloadBytes = files.reduce((total, file) => total + file.size, 0);
  const staging = join(parent, `.${name}.staging.${process.pid}.${randomBytes(8).toString("hex")}`);
  await mkdir(staging, { mode: DIRECTORY_MODE });
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
    // The created stream must itself satisfy the format the verifier enforces;
    // a system tar writing anything else fails closed here, before publication.
    const walked = await validateUstarSnapshot(archivePath, plan, plannedSizes(plan, files), "created archive");
    requireExactListing(archivePath, plan.listing);
    const archive = await hashRegularFile(archivePath, MAXIMUM_ARCHIVE_BYTES, "created archive");
    process.stderr.write(`validated created archive: ${walked.members} plain ustar members, ${walked.payloadBytes} payload bytes, ${walked.bytes} stream bytes\n`);
    // Round trip: the archive must unpack to exactly the verified set before it
    // is published, through the same verifier a recipient will run.
    const unpacked = await unpackAndVerify(provenanceArgument, archivePath, check, root, `created archive ${archivePath} for the pre-publication round trip`);
    requireSameFiles(expectedFilesOf(unpacked.expected), files, "unpacked archive tree");
    if (unpacked.inventorySHA256 !== verified.inventorySHA256) fail("unpacked delivery inventory digest differs from the verified input");
    const bindingText = renderBinding(verified, sourceCommit, plan, archive, toolVersion);
    await writeExclusive(publish, `${root}.binding.json`, Buffer.from(bindingText, "utf8"));
    await writeExclusive(publish, `${archiveName}.sha256`, Buffer.from(`${archive.sha256}  ${archiveName}\n`, "utf8"));
    const rehashed = await hashRegularFile(archivePath, MAXIMUM_ARCHIVE_BYTES, "created archive");
    if (rehashed.sha256 !== archive.sha256 || rehashed.size !== archive.size) fail("created archive changed before publication");
    const names = (await readdir(publish)).sort(byCodePoint);
    if (names.join("\0") !== [archiveName, `${archiveName}.sha256`, `${root}.binding.json`].sort(byCodePoint).join("\0")) fail("publication directory carries unexpected entries");
    await syncDirectories(publish);
    // The exact pre-publication point: every output exists in staging and
    // nothing is visible at the destination yet.
    await observers.beforePublish?.(Object.freeze({ staging, publish }));
    await rename(publish, destination);
    const authoritative = verified.inputs.upstream.authoritative && verified.inputs.crates.authoritative;
    process.stderr.write(`packaged ${plan.entries.filter((entry) => entry.kind === "file").length} files (${payloadBytes} bytes) as ${destination}/${archiveName} (${archive.size} bytes, sha256:${archive.sha256}, ustar, ${plan.entries.length} members, mtime ${ARCHIVE_MTIME_EPOCH_SECONDS}, ${toolVersion}); binding ${root}.binding.json sha256:${sha256(Buffer.from(bindingText, "utf8"))}; source commit ${sourceCommit}; upstream ${verified.inputs.upstream.transport}${verified.inputs.upstream.authoritative ? "" : " (NOT authoritative)"}, crates ${verified.inputs.crates.transport}${verified.inputs.crates.authoritative ? "" : " (NOT authoritative)"}; acquisition ${authoritative ? "authoritative" : "NOT authoritative"}; unresolved notices ${verified.inputs.crates.noticeMaterials.summary.unresolved.length}; not a source offer, not a release asset, not legal clearance\n`);
  } finally {
    await removeTree(staging);
  }
}

// ---------------------------------------------------------------------------
// verify-archive

// Copies the external archive into `snapshotPath` through one attested open
// descriptor (identity checked before, during and after the read; no follow of
// links, single link, current owner, canonical path), hashing the bytes as they
// are written. The externally supplied digest must match or nothing else runs.
async function snapshotArchive(externalPath, snapshotPath, expectedSHA256, observers) {
  const hash = createHash("sha256");
  const handle = await open(snapshotPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, FILE_MODE);
  let written = 0;
  try {
    const consumed = await consumeAttestedRegularFile(externalPath, {
      label: "archive",
      minimumBytes: TAR_BLOCK * 2,
      maximumBytes: MAXIMUM_ARCHIVE_BYTES,
      requireCanonicalPath: true,
      chunkBytes: CHUNK_BYTES,
      afterOpen: observers.afterSnapshotOpened === undefined ? undefined : async ({ canonical }) => observers.afterSnapshotOpened(Object.freeze({ externalPath: canonical }))
    }, async (chunk, offset) => {
      hash.update(chunk);
      const { bytesWritten } = await handle.write(chunk, 0, chunk.byteLength, offset);
      if (bytesWritten !== chunk.byteLength) fail("archive snapshot write was short");
      written += bytesWritten;
    });
    await handle.sync();
    if (written !== consumed.bytes) fail("archive snapshot size differs from the attested archive size");
    const archiveSHA256 = hash.digest("hex");
    if (archiveSHA256 !== expectedSHA256) fail(`archive SHA-256 is ${archiveSHA256}, not the expected ${expectedSHA256}; nothing was extracted`);
    return { archiveSHA256, bytes: written };
  } finally {
    await handle.close();
  }
}

async function trackedDigest(projectRoot, relativePath, label) {
  assertSafeRelativePath(relativePath, label);
  const absolute = join(projectRoot, ...relativePath.split("/"));
  if (await realpath(absolute) !== absolute) fail(`${label} must not traverse aliases or symbolic links: ${relativePath}`);
  return sha256(await boundedRegularBytes(absolute, MAXIMUM_BINDING_BYTES * 2, label));
}

async function trackedPath(projectRoot, relativePath, label) {
  assertSafeRelativePath(relativePath, label);
  const absolute = join(projectRoot, ...relativePath.split("/"));
  if (await realpath(absolute) !== absolute) fail(`${label} must not traverse aliases or symbolic links: ${relativePath}`);
  return absolute;
}

// Validates the binding as untrusted payload against the recipient's trusted
// checkout, before extraction: exact shape of every record, the externally
// supplied digest and archive size, the source commit, every fixed path name
// and format declaration, the deterministic metadata, the component, every
// tracked manifest digest, the binary cohort, the acquisition counts and
// transport/authority consistency, the status facts (against the trusted crate
// and notice manifests and the provenance record) and the delivery-set record
// consistency. The recorded tool version is reported later, not rejected.
async function loadBinding(bindingPath, provenance, expectedSHA256, sourceCommit, archiveSize) {
  const bytes = await boundedRegularBytes(bindingPath, MAXIMUM_BINDING_BYTES, "binding");
  const text = bytes.toString("utf8");
  if (text.includes("\0") || text.includes("\r") || Buffer.from(text, "utf8").compare(bytes) !== 0) fail("binding is not canonical UTF-8 text");
  let binding;
  try { binding = JSON.parse(text); }
  catch (error) { fail(`binding is not valid JSON: ${error.message}`); }
  requireExactKeys(binding, ["acquisition", "archive", "binary", "bindingType", "component", "deliverySet", "generator", "purpose", "schemaVersion", "sourceCommit", "statement", "status", "trackedBindings"], "binding");
  if (binding.schemaVersion !== 1 || binding.bindingType !== BINDING_TYPE || binding.generator !== GENERATOR) fail("binding has an unsupported type or schema");
  boundedString(binding.purpose, 16, 2000, "binding purpose");
  boundedString(binding.statement, 16, 2000, "binding statement");
  if (!/not legal clearance/u.test(binding.purpose)) fail("binding purpose must state that it is not legal clearance");
  if (LEGAL_CONCLUSION.test(text)) fail("binding must not read as a legal conclusion");
  if (binding.sourceCommit !== sourceCommit) fail(`binding names source commit ${String(binding.sourceCommit).slice(0, 40)}, not the trusted checkout's ${sourceCommit}`);
  // Archive identity and format declarations.
  requireExactKeys(binding.archive, ["compression", "directoryCount", "fileCount", "fileName", "format", "memberCount", "metadata", "sha256", "sidecar", "size"], "binding archive");
  if (binding.archive.sha256 !== expectedSHA256) fail("binding archive digest differs from the externally supplied expected digest");
  if (binding.archive.size !== archiveSize) fail("binding archive size differs from the archive file");
  if (binding.archive.format !== "ustar" || binding.archive.compression !== "none") fail("binding names an unsupported archive format");
  for (const key of ["memberCount", "directoryCount", "fileCount"]) {
    if (!Number.isSafeInteger(binding.archive[key]) || binding.archive[key] < 0 || binding.archive[key] > MAXIMUM_MEMBERS) fail(`binding archive ${key} is not one bounded count`);
  }
  requireExactKeys(binding.archive.metadata, ["createOptions", "directoryMode", "fileMode", "gid", "gname", "mtimeEpochSeconds", "tool", "toolVersion", "uid", "uname"], "binding archive metadata");
  const metadata = binding.archive.metadata;
  if (metadata.uid !== 0 || metadata.gid !== 0 || metadata.uname !== "" || metadata.gname !== "" || metadata.mtimeEpochSeconds !== ARCHIVE_MTIME_EPOCH_SECONDS
      || metadata.fileMode !== "0600" || metadata.directoryMode !== "0700" || metadata.tool !== TAR || !isDeepStrictEqual(metadata.createOptions, [...TAR_CREATE_OPTIONS])) {
    fail("binding archive metadata does not describe the deterministic ustar contract");
  }
  boundedString(metadata.toolVersion, 1, 200, "binding archive metadata toolVersion");
  const root = provenance.delivery.outputDirectoryName;
  if (binding.archive.fileName !== `${root}.tar`) fail(`binding names archive ${String(binding.archive.fileName).slice(0, 200)}, not ${root}.tar`);
  requireExactKeys(binding.archive.sidecar, ["fileName", "format"], "binding archive sidecar");
  if (binding.archive.sidecar.fileName !== `${root}.tar.sha256` || binding.archive.sidecar.format !== "sha256sum") fail(`binding archive sidecar must declare ${root}.tar.sha256 in sha256sum format`);
  // Component, tracked manifests and binary cohort against the trusted checkout.
  requireExactKeys(binding.component, ["buildCommit", "id", "lockfilePath", "openObligations", "packageName", "version"], "binding component");
  if (!isDeepStrictEqual(binding.component, {
    id: provenance.component.id,
    packageName: provenance.component.packageName,
    version: provenance.component.version,
    lockfilePath: provenance.component.lockfilePath,
    buildCommit: provenance.component.buildCommit,
    openObligations: provenance.component.openObligations
  })) {
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
  const sourceManifest = await loadManifest(await trackedPath(provenance.projectRoot, provenance.delivery.sourceMaterials, "tracked sourceMaterials"));
  const crateManifest = await loadManifest(await trackedPath(provenance.projectRoot, provenance.delivery.rustCrateMaterials, "tracked rustCrateMaterials"));
  if (crateManifest.manifest.provenanceStatuses === undefined || sourceManifest.manifest.provenanceStatuses !== undefined) fail("the trusted checkout's material manifests are not a corresponding-source manifest and a rust-crate manifest");
  if (!isDeepStrictEqual(binding.binary, crateManifest.manifest.binary)) fail("binding binary cohort does not match the trusted crate manifest");
  const notice = await loadRustNoticeMaterials(await trackedPath(provenance.projectRoot, provenance.delivery.rustNoticeMaterials, "tracked rustNoticeMaterials"), crateManifest.manifest, crateManifest.manifestPath);
  // Status facts against the trusted manifests and provenance record.
  requireExactKeys(binding.status, ["dylibIncorporation", "historicalCompilation", "kind", "openObligations", "statement", "unresolvedNoticeCount"], "binding status");
  if (binding.status.kind !== STATUS_KIND) fail(`binding status kind must be ${STATUS_KIND}`);
  boundedString(binding.status.statement, 16, 2000, "binding status statement");
  if (binding.status.dylibIncorporation !== "unverified") fail("binding status dylibIncorporation must remain unverified; this tool establishes no incorporation");
  const statuses = crateManifest.manifest.provenanceStatuses;
  if (binding.status.dylibIncorporation !== statuses.incorporatedIntoShippedBinary || binding.status.historicalCompilation !== statuses.compiledInHistoricalBuild) {
    fail("binding status does not match the trusted crate manifest's provenance statuses");
  }
  if (binding.status.unresolvedNoticeCount !== notice.summary.unresolved.length) {
    fail(`binding status unresolvedNoticeCount ${JSON.stringify(binding.status.unresolvedNoticeCount)} does not match the trusted notice-materials manifest (${notice.summary.unresolved.length})`);
  }
  if (!isDeepStrictEqual(binding.status.openObligations, provenance.component.openObligations)) fail("binding status openObligations do not match the trusted provenance record");
  // Acquisition facts against the trusted manifests; transport and authority
  // must agree with each other here and with the verified material later.
  requireExactKeys(binding.acquisition, ["rustCrates", "upstreamSource"], "binding acquisition");
  for (const [key, manifest] of [["upstreamSource", sourceManifest.manifest], ["rustCrates", crateManifest.manifest]]) {
    const record = binding.acquisition[key];
    requireExactKeys(record, ["authoritative", "itemCount", "totalBytes", "transport"], `binding acquisition ${key}`);
    if (!["https", "local-fixture"].includes(record.transport)) fail(`binding acquisition ${key} names an unknown transport`);
    if (record.authoritative !== (record.transport === "https")) fail(`binding acquisition ${key} authoritative flag contradicts its transport`);
    if (record.itemCount !== manifest.items.length) fail(`binding acquisition ${key} itemCount ${JSON.stringify(record.itemCount)} does not match the trusted manifest (${manifest.items.length})`);
    if (record.totalBytes !== manifest.totalBytes) fail(`binding acquisition ${key} totalBytes ${JSON.stringify(record.totalBytes)} does not match the trusted manifest (${manifest.totalBytes})`);
  }
  // Delivery set: bounded, ordered, internally consistent file records.
  requireExactKeys(binding.deliverySet, ["checksumList", "fileCount", "files", "inventory", "rootDirectory", "statusRecord", "totalBytes"], "binding deliverySet");
  if (binding.deliverySet.rootDirectory !== root) fail(`binding names delivery root ${String(binding.deliverySet.rootDirectory).slice(0, 200)}, not ${root}`);
  if (!Array.isArray(binding.deliverySet.files) || binding.deliverySet.files.length === 0 || binding.deliverySet.files.length > MAXIMUM_MEMBERS
      || binding.deliverySet.fileCount !== binding.deliverySet.files.length) {
    fail("binding deliverySet files must be one bounded list matching fileCount");
  }
  const digests = new Map();
  let total = 0;
  let previous;
  for (const file of binding.deliverySet.files) {
    requireExactKeys(file, ["path", "sha256", "size"], "binding deliverySet file");
    assertSafeRelativePath(file.path, "binding deliverySet file path");
    if (digests.has(file.path) || !SHA256.test(file.sha256 ?? "") || !Number.isSafeInteger(file.size) || file.size < 0 || file.size > MAXIMUM_MEMBER_BYTES) {
      fail(`binding deliverySet file is malformed, out of bounds or duplicated: ${file.path}`);
    }
    if (previous !== undefined && byCodePoint(previous, file.path) >= 0) fail("binding deliverySet files are not listed in code-point order");
    previous = file.path;
    digests.set(file.path, file.sha256);
    total += file.size;
  }
  if (binding.deliverySet.totalBytes !== total || total > MAXIMUM_PAYLOAD_BYTES) fail("binding deliverySet totalBytes does not equal the bounded sum of its files");
  for (const required of REQUIRED_SET_FILES) if (!digests.has(required)) fail(`binding deliverySet omits ${required}`);
  for (const [key, fileName] of [["inventory", INVENTORY_NAME], ["statusRecord", STATUS_NAME], ["checksumList", SUMS_NAME]]) {
    const record = binding.deliverySet[key];
    requireExactKeys(record, ["path", "sha256"], `binding deliverySet ${key}`);
    if (record.path !== fileName) fail(`binding deliverySet ${key} must name ${fileName}`);
    if (record.sha256 !== digests.get(fileName)) fail(`binding deliverySet ${key} digest disagrees with its file entry`);
  }
  if (binding.archive.fileCount !== binding.deliverySet.fileCount) fail("binding archive fileCount does not equal its deliverySet fileCount");
  const files = binding.deliverySet.files.map(({ path, size, sha256: digest }) => ({ path, size, sha256: digest }));
  return { path: bindingPath, sha256: sha256(bytes), binding, files, root };
}

async function verifyArchive(provenanceArgument, archiveArgument, bindingArgument, expectedSHA256, sourceCommit, unpackArgument, observerArgument) {
  const observers = normalizeObservers(observerArgument);
  if (!SHA256.test(expectedSHA256 ?? "")) fail("expected archive digest must be one lowercase SHA-256");
  if (!COMMIT.test(sourceCommit ?? "")) fail("source commit must be one full 40-hex commit");
  const toolVersion = await tarVersion();
  const provenance = await loadProvenance(provenanceArgument);
  const archivePath = resolve(archiveArgument);
  await requireCanonicalRegularFile(archivePath, "archive");
  const bindingPath = resolve(bindingArgument);
  await requireCanonicalRegularFile(bindingPath, "binding");
  const { destination, parent, name } = await requireNewPrivateDestination(unpackArgument, "unpack directory");
  if (archivePath.startsWith(`${destination}/`) || bindingPath.startsWith(`${destination}/`)) fail("unpack directory must not contain the archive or the binding");
  const staging = join(parent, `.${name}.unpack.${process.pid}.${randomBytes(8).toString("hex")}`);
  await mkdir(staging, { mode: DIRECTORY_MODE });
  try {
    const snapshotDirectory = join(staging, "snapshot");
    const tree = join(staging, "tree");
    for (const directory of [snapshotDirectory, tree]) await mkdir(directory, { mode: DIRECTORY_MODE });
    // 1. One attested read of the external archive into a private snapshot; the
    //    externally supplied digest gates everything else. From here on every
    //    step consumes the snapshot and the external path is never reopened.
    const snapshotPath = join(snapshotDirectory, "snapshot.tar");
    const admitted = await snapshotArchive(archivePath, snapshotPath, expectedSHA256, observers);
    const snapshot = await hashRegularFile(snapshotPath, MAXIMUM_ARCHIVE_BYTES, "archive snapshot");
    if (snapshot.sha256 !== expectedSHA256 || snapshot.size !== admitted.bytes) fail("archive snapshot does not reproduce the admitted bytes");
    await observers.afterSnapshotAdmitted?.(Object.freeze({ snapshotPath, snapshotSHA256: snapshot.sha256, externalPath: archivePath }));
    process.stderr.write(`admitted snapshot of ${archivePath} (${snapshot.size} bytes, sha256:${snapshot.sha256}) into private staging; the external path is not consulted again\n`);
    // 2. The binding, as payload checked against the trusted checkout.
    const bound = await loadBinding(bindingPath, provenance, expectedSHA256, sourceCommit, snapshot.size);
    // 3. Format enforcement and the exact member listing, on the snapshot,
    //    before anything is extracted.
    const plan = planMembers(bound.root, bound.files.map((file) => file.path));
    if (bound.binding.archive.memberCount !== plan.entries.length || bound.binding.archive.fileCount !== bound.files.length
        || bound.binding.archive.directoryCount !== plan.entries.length - bound.files.length) {
      fail("binding archive member counts do not match its delivery inventory");
    }
    const walked = await validateUstarSnapshot(snapshotPath, plan, plannedSizes(plan, bound.files), "archive");
    requireExactListing(snapshotPath, plan.listing);
    // 4. Extract the validated snapshot into staging, then the stager verifier.
    await observers.beforeExtraction?.(Object.freeze({ snapshotPath }));
    const verified = await unpackAndVerify(provenanceArgument, snapshotPath, tree, bound.root, `validated snapshot ${snapshotPath} (${walked.members} members, ${walked.payloadBytes} payload bytes)`);
    // 5. The binding's remaining facts against the independently verified set.
    requireSameFiles(expectedFilesOf(verified.expected), bound.files, "binding deliverySet");
    if (bound.binding.deliverySet.inventory.sha256 !== verified.inventorySHA256 || bound.binding.deliverySet.statusRecord.sha256 !== verified.statusSHA256
        || bound.binding.deliverySet.checksumList.sha256 !== verified.sumsSHA256) {
      fail("binding deliverySet record digests do not match the unpacked, verified set");
    }
    if (!isDeepStrictEqual(bound.binding.status, verified.inventory.status)) fail("binding status does not equal the verified delivery status record");
    if (!isDeepStrictEqual(bound.binding.component, verified.inventory.component)) fail("binding component does not equal the verified delivery inventory component");
    const { inputs } = verified;
    for (const [key, input, shown] of [["upstreamSource", inputs.upstream, "upstream"], ["rustCrates", inputs.crates, "crates"]]) {
      const record = bound.binding.acquisition[key];
      if (record.transport !== input.transport || record.authoritative !== input.authoritative) {
        fail(`binding acquisition does not match the verified material set (${shown} ${input.transport}, ${input.authoritative ? "authoritative" : "NOT authoritative"})`);
      }
    }
    await syncDirectories(tree);
    await rename(tree, destination);
    const authoritative = inputs.upstream.authoritative && inputs.crates.authoritative;
    process.stderr.write(`verified archive ${archivePath} (${snapshot.size} bytes, sha256:${snapshot.sha256}) against source commit ${sourceCommit} and binding ${bound.path} (sha256:${bound.sha256}); unpacked ${verified.expected.size} files to ${destination}/${bound.root} and re-verified them against the tracked manifests; upstream ${inputs.upstream.transport}${inputs.upstream.authoritative ? "" : " (NOT authoritative)"}, crates ${inputs.crates.transport}${inputs.crates.authoritative ? "" : " (NOT authoritative)"}; acquisition ${authoritative ? "authoritative" : "NOT authoritative"}; unresolved notices ${inputs.crates.noticeMaterials.summary.unresolved.length}; dylib incorporation ${inputs.crates.manifest.provenanceStatuses.incorporatedIntoShippedBinary}; archive tool ${toolVersion}${toolVersion === bound.binding.archive.metadata.toolVersion ? "" : ` (binding recorded ${bound.binding.archive.metadata.toolVersion}; byte-identical re-packaging is only claimed for that build)`}; not a legal conclusion\n`);
    return Object.freeze({
      archiveSHA256: admitted.archiveSHA256,
      snapshotSHA256: snapshot.sha256,
      snapshotBytes: snapshot.size,
      extractedFrom: snapshotPath,
      unpackedRoot: join(destination, bound.root),
      fileCount: verified.expected.size
    });
  } finally {
    // The snapshot and any partial tree are this invocation's own; the
    // published tree has already been renamed out when verification succeeded.
    await removeTree(staging);
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
