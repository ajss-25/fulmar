import { constants } from "node:fs";
import { createHash } from "node:crypto";
import { lstat, open } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const firstPartyLicensePaths = Object.freeze({
  license: "LICENSE",
  metadata: "Config/ProjectLicense.json"
});

const limits = Object.freeze({
  licenseBytes: 1024 * 1024,
  metadataBytes: 16 * 1024,
  schemaBytes: 64 * 1024,
  spdxListBytes: 32 * 1024,
  spdxExpressionCharacters: 256,
  displayNameCharacters: 128,
  displayNameBytes: 512
});
const schemaPath = fileURLToPath(new URL("./first-party-license-v1.schema.json", import.meta.url));
const spdxListPath = fileURLToPath(new URL("./first-party-spdx-v1.json", import.meta.url));
// Updated only after the reviewed schema file changes deliberately.
const schemaSHA256 = "203b4a2596d73dddd7fa1a2e968003b8aae44833558d5ca2a8202b53a953e7db";
// Fulmar deliberately supports a small reviewed subset instead of silently
// accepting any identifier-shaped token. Updating it requires reviewing the
// upstream SPDX list and deliberately rebinding this digest.
const spdxListSHA256 = "e319e0037c903b7994401e58749d9cccd9d37a7d469b20674065b335a74019d4";
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

function effectiveUID(fallback) {
  return typeof process.geteuid === "function" ? process.geteuid() : fallback;
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size
    && left.mode === right.mode && left.uid === right.uid && left.nlink === right.nlink
    && left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs;
}

async function assertPrivateDirectory(path, label) {
  const details = await lstat(path);
  if (!details.isDirectory() || details.isSymbolicLink() || details.uid !== effectiveUID(details.uid)
      || (details.mode & 0o022) !== 0) {
    throw new Error(`${label} must be a real owner-controlled directory`);
  }
}

async function pathPresence(path) {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

async function readPrivateRegularFile(path, maximumBytes, label) {
  const before = await lstat(path);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1
      || before.uid !== effectiveUID(before.uid) || (before.mode & 0o022) !== 0
      || before.size <= 0 || before.size > maximumBytes) {
    throw new Error(`${label} must be one bounded, owner-controlled regular file with no links`);
  }
  let handle;
  try {
    // O_NOFOLLOW plus descriptor fstat before/after binds every consumed byte.
    // codeql[js/file-system-race]
    handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const opened = await handle.stat();
    if (!opened.isFile() || opened.nlink !== 1 || !sameIdentity(before, opened)) {
      throw new Error(`${label} changed identity before it was read`);
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (!sameIdentity(opened, after) || bytes.length !== opened.size) {
      throw new Error(`${label} changed while it was read`);
    }
    return bytes;
  } finally {
    await handle?.close();
  }
}

function decodeUTF8(bytes, label) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new Error(`${label} must be valid UTF-8 text`);
  }
  if (text.includes("\0")) throw new Error(`${label} must not contain NUL bytes`);
  return text;
}

function tokenizeSPDX(expression) {
  const tokens = [];
  let cursor = 0;
  while (cursor < expression.length) {
    const character = expression[cursor];
    if (character === " ") {
      cursor += 1;
      continue;
    }
    if (character === "(" || character === ")") {
      tokens.push(character);
      cursor += 1;
      continue;
    }
    const match = /^[A-Za-z0-9][A-Za-z0-9.+:-]*/u.exec(expression.slice(cursor));
    if (!match) throw new Error("first-party licence metadata has an invalid SPDX expression");
    tokens.push(match[0]);
    cursor += match[0].length;
  }
  return tokens;
}

function validateSPDXExpression(expression, identifiers) {
  if (typeof expression !== "string" || expression.length < 1
      || expression.length > limits.spdxExpressionCharacters || expression.trim() !== expression
      || /[\u0000-\u001f\u007f-\u009f]/u.test(expression)) {
    throw new Error("first-party licence metadata has an invalid SPDX expression");
  }
  const tokens = tokenizeSPDX(expression);
  let cursor = 0;
  const isOperator = (token) => token === "AND" || token === "OR" || token === "WITH";

  function identifier(kind) {
    const token = tokens[cursor];
    if (!token || token === "(" || token === ")" || isOperator(token) || token.length > 128) {
      throw new Error("first-party licence metadata has an invalid SPDX expression");
    }
    const documentReference = /^DocumentRef-[A-Za-z0-9][A-Za-z0-9.-]{0,63}:LicenseRef-[A-Za-z0-9][A-Za-z0-9.-]{0,63}$/u;
    const licenseReference = /^LicenseRef-[A-Za-z0-9][A-Za-z0-9.-]{0,127}$/u;
    const valid = kind === "exception"
      ? identifiers.exceptions.has(token)
      : identifiers.licenses.has(token) || licenseReference.test(token) || documentReference.test(token);
    if (!valid) {
      throw new Error("first-party licence metadata names an unknown or unsupported SPDX identifier");
    }
    cursor += 1;
    return { simple: true };
  }

  function primary() {
    if (tokens[cursor] !== "(") return identifier("license");
    cursor += 1;
    expressionNode();
    if (tokens[cursor] !== ")") throw new Error("first-party licence metadata has an invalid SPDX expression");
    cursor += 1;
    return { simple: false };
  }

  function withNode() {
    const left = primary();
    if (tokens[cursor] === "WITH") {
      if (!left.simple) throw new Error("first-party licence metadata has an invalid SPDX expression");
      cursor += 1;
      identifier("exception");
    }
  }

  function andNode() {
    withNode();
    while (tokens[cursor] === "AND") {
      cursor += 1;
      withNode();
    }
  }

  function expressionNode() {
    andNode();
    while (tokens[cursor] === "OR") {
      cursor += 1;
      andNode();
    }
  }

  expressionNode();
  if (tokens.length === 0 || cursor !== tokens.length) {
    throw new Error("first-party licence metadata has an invalid SPDX expression");
  }
}

function validateMetadata(text, licenseDigest, identifiers) {
  const topLevelKeys = new Set();
  let depth = 0;
  for (let cursor = 0; cursor < text.length;) {
    const character = text[cursor];
    if (character === "{") { depth += 1; cursor += 1; continue; }
    if (character === "}") { depth -= 1; cursor += 1; continue; }
    if (character !== '"') { cursor += 1; continue; }
    const start = cursor;
    cursor += 1;
    while (cursor < text.length) {
      if (text[cursor] === "\\") { cursor += 2; continue; }
      if (text[cursor] === '"') { cursor += 1; break; }
      cursor += 1;
    }
    let lookahead = cursor;
    while (text[lookahead] === " " || text[lookahead] === "\t"
        || text[lookahead] === "\n" || text[lookahead] === "\r") lookahead += 1;
    if (depth === 1 && text[lookahead] === ":") {
      let key;
      try { key = JSON.parse(text.slice(start, cursor)); } catch { continue; }
      if (topLevelKeys.has(key)) throw new Error("first-party licence metadata contains a duplicate key");
      topLevelKeys.add(key);
    }
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error("first-party licence metadata must be valid JSON");
  }
  const expectedKeys = ["displayName", "licenseFile", "licenseSHA256", "schemaVersion", "spdxExpression"];
  if (!value || typeof value !== "object" || Array.isArray(value)
      || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(expectedKeys)
      || value.schemaVersion !== 1 || value.licenseFile !== "LICENSE") {
    throw new Error("first-party licence metadata does not match the bounded v1 schema");
  }
  validateSPDXExpression(value.spdxExpression, identifiers);
  if (typeof value.displayName !== "string" || value.displayName.length < 1
      || value.displayName.length > limits.displayNameCharacters
      || Buffer.byteLength(value.displayName, "utf8") > limits.displayNameBytes
      || value.displayName.trim() !== value.displayName
      || /[\u0000-\u001f\u007f-\u009f]/u.test(value.displayName)) {
    throw new Error("first-party licence metadata has an invalid display name");
  }
  if (typeof value.licenseSHA256 !== "string" || !/^[0-9a-f]{64}$/u.test(value.licenseSHA256)
      || value.licenseSHA256 !== licenseDigest) {
    throw new Error("first-party licence metadata does not bind the exact LICENSE SHA-256");
  }
  return Object.freeze({ ...value });
}

async function validatePinnedSchema() {
  const bytes = await readPrivateRegularFile(schemaPath, limits.schemaBytes, "first-party licence schema");
  if (sha256(bytes) !== schemaSHA256) throw new Error("first-party licence schema digest mismatch");
  const schema = JSON.parse(decodeUTF8(bytes, "first-party licence schema"));
  if (schema?.additionalProperties !== false || schema?.properties?.licenseFile?.const !== "LICENSE"
      || schema?.properties?.schemaVersion?.const !== 1
      || schema?.properties?.licenseSHA256?.pattern !== "^[0-9a-f]{64}$") {
    throw new Error("first-party licence schema has an unsupported contract");
  }
}

async function validatePinnedSPDXList() {
  const bytes = await readPrivateRegularFile(
    spdxListPath,
    limits.spdxListBytes,
    "first-party supported SPDX identifier list"
  );
  if (sha256(bytes) !== spdxListSHA256) {
    throw new Error("first-party supported SPDX identifier-list digest mismatch");
  }
  let value;
  try {
    value = JSON.parse(decodeUTF8(bytes, "first-party supported SPDX identifier list"));
  } catch {
    throw new Error("first-party supported SPDX identifier list must be valid JSON");
  }
  const expectedKeys = ["exceptionIds", "licenseIds", "schemaVersion", "source", "sourceURL"];
  if (!value || typeof value !== "object" || Array.isArray(value)
      || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(expectedKeys)
      || value.schemaVersion !== 1
      || value.source !== "Fulmar supported subset of SPDX License List 3.28.0"
      || value.sourceURL !== "https://spdx.org/licenses/"
      || !Array.isArray(value.licenseIds) || !Array.isArray(value.exceptionIds)
      || value.licenseIds.length < 1 || value.licenseIds.length > 512
      || value.exceptionIds.length < 1 || value.exceptionIds.length > 256) {
    throw new Error("first-party supported SPDX identifier list has an unsupported contract");
  }
  const validateList = (entries, label) => {
    if (entries.some((entry) => typeof entry !== "string"
        || !/^[A-Za-z0-9][A-Za-z0-9.-]{0,127}$/u.test(entry))
        || new Set(entries).size !== entries.length
        || JSON.stringify(entries) !== JSON.stringify([...entries].sort())) {
      throw new Error(`first-party supported SPDX ${label} list is invalid, duplicated, or unsorted`);
    }
    return new Set(entries);
  };
  return Object.freeze({
    licenses: validateList(value.licenseIds, "licence"),
    exceptions: validateList(value.exceptionIds, "exception")
  });
}

export async function resolveFirstPartyLicense(projectRootArgument, { requireSelected = false } = {}) {
  const projectRoot = resolve(projectRootArgument);
  await assertPrivateDirectory(projectRoot, "project root");
  await assertPrivateDirectory(join(projectRoot, "Config"), "project Config directory");
  await validatePinnedSchema();
  const spdxIdentifiers = await validatePinnedSPDXList();
  const licensePath = join(projectRoot, firstPartyLicensePaths.license);
  const metadataPath = join(projectRoot, firstPartyLicensePaths.metadata);
  const [licensePresent, metadataPresent] = await Promise.all([
    pathPresence(licensePath),
    pathPresence(metadataPath)
  ]);
  if (!licensePresent && !metadataPresent) {
    if (requireSelected) {
      throw new Error("public distribution requires owner-selected LICENSE and Config/ProjectLicense.json");
    }
    return Object.freeze({ state: "unlicensed-private", projectRoot, licensePath, metadataPath });
  }
  if (licensePresent !== metadataPresent) {
    throw new Error("LICENSE and Config/ProjectLicense.json must either both exist or both be absent");
  }
  const [licenseBytes, metadataBytes] = await Promise.all([
    readPrivateRegularFile(licensePath, limits.licenseBytes, "top-level LICENSE"),
    readPrivateRegularFile(metadataPath, limits.metadataBytes, "first-party licence metadata")
  ]);
  const licenseText = decodeUTF8(licenseBytes, "top-level LICENSE");
  if (licenseText.trim().length === 0) throw new Error("top-level LICENSE must not be empty");
  const digest = sha256(licenseBytes);
  const metadata = validateMetadata(
    decodeUTF8(metadataBytes, "first-party licence metadata"),
    digest,
    spdxIdentifiers
  );
  return Object.freeze({
    state: "selected",
    projectRoot,
    licensePath,
    metadataPath,
    licenseBytes,
    licenseSHA256: digest,
    spdxExpression: metadata.spdxExpression,
    displayName: metadata.displayName
  });
}

export async function verifyBundledFirstPartyLicense(projectRoot, bundledLicensePath, options = {}) {
  const policy = await resolveFirstPartyLicense(projectRoot, options);
  const present = await pathPresence(bundledLicensePath);
  if (policy.state === "unlicensed-private") {
    if (present) throw new Error("an unlicensed private build must not bundle first-party LICENSE bytes");
    return policy;
  }
  if (!present) throw new Error("a selected first-party licence is missing from the app bundle");
  const bundled = await readPrivateRegularFile(bundledLicensePath, limits.licenseBytes, "bundled first-party LICENSE");
  if (!bundled.equals(policy.licenseBytes)) {
    throw new Error("bundled first-party LICENSE does not match the owner-selected source bytes");
  }
  return policy;
}

export async function bundleFirstPartyLicense(projectRoot, bundledLicensePath) {
  const policy = await resolveFirstPartyLicense(projectRoot);
  const present = await pathPresence(bundledLicensePath);
  if (present) throw new Error("refusing to replace a pre-existing bundled first-party LICENSE path");
  if (policy.state === "unlicensed-private") return policy;
  await assertPrivateDirectory(dirname(bundledLicensePath), "app Resources directory");
  let handle;
  try {
    handle = await open(
      bundledLicensePath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0),
      0o600
    );
    await handle.writeFile(policy.licenseBytes);
    await handle.sync();
    await handle.chmod(0o644);
  } finally {
    await handle?.close();
  }
  return verifyBundledFirstPartyLicense(projectRoot, bundledLicensePath);
}

function publicPolicy(policy) {
  return policy.state === "selected"
    ? {
        state: policy.state,
        licenseFile: "LICENSE",
        licenseSHA256: policy.licenseSHA256,
        spdxExpression: policy.spdxExpression,
        displayName: policy.displayName
      }
    : { state: policy.state };
}

async function main() {
  const [action, projectRoot, ...argumentsList] = process.argv.slice(2);
  if (!action || !projectRoot) {
    throw new Error("usage: first-party-license-policy.mjs <state|bundle|verify-bundle> <project-root> [bundled-LICENSE] [--require-selected]");
  }
  let policy;
  if (action === "state" && (argumentsList.length === 0
      || (argumentsList.length === 1 && argumentsList[0] === "--require-selected"))) {
    const requireSelected = argumentsList[0] === "--require-selected";
    policy = await resolveFirstPartyLicense(projectRoot, { requireSelected });
  } else if (action === "bundle" && argumentsList.length === 1) {
    policy = await bundleFirstPartyLicense(projectRoot, resolve(argumentsList[0]));
  } else if (action === "verify-bundle" && (argumentsList.length === 1
      || (argumentsList.length === 2 && argumentsList[1] === "--require-selected"))) {
    const requireSelected = argumentsList[1] === "--require-selected";
    policy = await verifyBundledFirstPartyLicense(projectRoot, resolve(argumentsList[0]), { requireSelected });
  } else {
    throw new Error("invalid first-party licence policy action or arguments");
  }
  process.stdout.write(`${JSON.stringify(publicPolicy(policy))}\n`);
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  await main();
}
