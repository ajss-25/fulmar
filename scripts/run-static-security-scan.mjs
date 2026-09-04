#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  loadPinnedRuleManifest,
  materializePinnedSemgrepRules
} from "./pinned-semgrep-rules.mjs";
import {
  publishAttestedRegularFileSync,
  readAttestedRegularFileSync
} from "./attested-regular-file.mjs";

const expectedNodeVersion = "v22.23.1";
const maximumReportBytes = 64 * 1_024 * 1_024;
const maximumSummaryBytes = 512 * 1_024;
const maximumTextEntries = 20_000;
const maximumTextAggregateBytes = 512 * 1_024 * 1_024;
const maximumArgumentBytes = 192 * 1_024;
const forbiddenLaunchEnvironment = Object.freeze([
  "NODE_OPTIONS", "NODE_PATH", "NODE_EXTRA_CA_CERTS", "OPENSSL_CONF",
  "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
  "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
  "http_proxy", "https_proxy", "all_proxy", "no_proxy",
  "NPM_CONFIG_PROXY", "NPM_CONFIG_HTTPS_PROXY", "NPM_CONFIG_CAFILE",
  "npm_config_proxy", "npm_config_https_proxy", "npm_config_cafile",
  "SEMGREP_APP_TOKEN", "SEMGREP_URL", "SEMGREP_APP_URL", "SEMGREP_COOKIES_PATH",
  "PYTHONPATH", "PYTHONHOME", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
  "LD_PRELOAD", "LD_LIBRARY_PATH"
]);
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

function failure(message) {
  throw new Error(`Static security scan failed: ${message}`);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function compareText(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function safeRelativePath(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 4_096
    && !value.startsWith("/") && !value.includes("\\")
    && value.split("/").every((part) => part.length > 0 && part !== "." && part !== "..")
    && !/[\u0000-\u001f\u007f]/u.test(value);
}

function validateOwnerAndMode(details, relativePath) {
  const effectiveUID = typeof process.geteuid === "function" ? BigInt(process.geteuid()) : details.uid;
  if (details.uid !== effectiveUID || (details.mode & 0o022n) !== 0n) {
    failure(`secret-scan input is not owner-controlled: ${relativePath}`);
  }
}

function readStableRegularFile(path, relativePath, maximumBytes) {
  // Open-first through the synchronous attested reader: the no-follow
  // descriptor's metadata is the reviewed shape (owner-controlled, single
  // link, bounded) and the pathname is re-attested around the read.
  let input;
  try {
    input = readAttestedRegularFileSync(path, {
      label: `secret-scan input ${relativePath}`,
      minimumBytes: 0,
      maximumBytes,
      requireCurrentUser: true,
      requireOwnerControlledMode: true,
      requireSingleLink: true
    });
  } catch (error) {
    if (error?.code === "ENOENT") throw error;
    if (/not owned by the current user|group- or world-writable/u.test(error?.message ?? "")) {
      failure(`secret-scan input is not owner-controlled: ${relativePath}`);
    }
    failure(`secret-scan input is unsafe or exceeds its byte limit: ${relativePath}`);
  }
  return input.bytes;
}

function isText(bytes) {
  if (bytes.includes(0)) return false;
  try {
    utf8Decoder.decode(bytes);
    return true;
  } catch {
    return false;
  }
}

function directoryChanged(before, after) {
  return before.dev !== after.dev || before.ino !== after.ino || before.mode !== after.mode
    || before.uid !== after.uid || before.nlink !== after.nlink || before.mtimeNs !== after.mtimeNs;
}

export function collectSecretTextFiles(projectRootArgument, roots, maximumTargetBytes, binaryExclusions = []) {
  const projectRoot = resolve(projectRootArgument);
  if (!Array.isArray(roots) || roots.length === 0
      || !Number.isSafeInteger(maximumTargetBytes) || maximumTargetBytes < 1
      || !Array.isArray(binaryExclusions)) {
    failure("secret-scan coverage boundary is invalid");
  }
  const reviewedBinary = new Map(binaryExclusions.map((entry) => [entry.path, entry]));
  if (reviewedBinary.size !== binaryExclusions.length) failure("binary scan exclusion identity is duplicated");
  const consumedBinary = new Set();
  const entries = [];
  const identities = new Set();
  let aggregateBytes = 0;
  let visited = 0;

  const visit = (relativePath) => {
    if (!safeRelativePath(relativePath)) failure(`unsafe secret-scan path: ${relativePath}`);
    const identity = relativePath.normalize("NFC").toLocaleLowerCase("en-US");
    if (identities.has(identity)) failure(`duplicate secret-scan path identity: ${relativePath}`);
    identities.add(identity);
    visited += 1;
    if (visited > maximumTextEntries) failure("secret-scan entry limit exceeded");

    const path = join(projectRoot, relativePath);
    const details = lstatSync(path, { bigint: true });
    validateOwnerAndMode(details, relativePath);
    if (details.isSymbolicLink()) failure(`linked secret-scan input is not permitted: ${relativePath}`);
    if (details.isDirectory()) {
      const children = readdirSync(path).sort(compareText);
      for (const child of children) visit(`${relativePath}/${child}`);
      const after = lstatSync(path, { bigint: true });
      if (!after.isDirectory() || directoryChanged(details, after)) {
        failure(`secret-scan directory changed while enumerating: ${relativePath}`);
      }
      return;
    }
    if (!details.isFile() || details.nlink !== 1n) {
      failure(`special secret-scan input is not permitted: ${relativePath}`);
    }
    const bytes = readStableRegularFile(path, relativePath, maximumTargetBytes);
    if (!isText(bytes)) {
      const review = reviewedBinary.get(relativePath);
      if (!review || review.sha256 !== sha256(bytes)) {
        failure(`unreviewed non-text source input: ${relativePath}`);
      }
      consumedBinary.add(relativePath);
      return;
    }
    aggregateBytes += bytes.length;
    if (aggregateBytes > maximumTextAggregateBytes) failure("secret-scan aggregate byte limit exceeded");
    entries.push(Object.freeze({ path: relativePath, bytes: bytes.length, sha256: sha256(bytes) }));
  };

  for (const root of roots) visit(root);
  entries.sort((left, right) => compareText(left.path, right.path));
  const argumentBytes = entries.reduce((total, entry) => total + Buffer.byteLength(entry.path) + 1, 0);
  if (argumentBytes > maximumArgumentBytes) failure("secret-scan argument-byte limit exceeded");
  if (consumedBinary.size !== reviewedBinary.size) failure("binary scan exclusion is stale");
  return Object.freeze(entries);
}

function exactSinglePathLine(bytes, prefix, label) {
  if (!isText(bytes)) failure(`${label} is not UTF-8 text`);
  const text = utf8Decoder.decode(bytes);
  if (!text.startsWith(prefix)) failure(`${label} is malformed`);
  const remainder = text.slice(prefix.length);
  const value = remainder.endsWith("\n") ? remainder.slice(0, -1) : remainder;
  if (value.length === 0 || value.includes("\n") || value.includes("\r")
      || value.trim() !== value || /[\u0000-\u001f\u007f]/u.test(value)) {
    failure(`${label} is malformed`);
  }
  return value;
}

function validateGitWorktreeFile(projectRoot) {
  const gitFile = join(projectRoot, ".git");
  const pointer = exactSinglePathLine(
    readStableRegularFile(gitFile, ".git", 4_096),
    "gitdir: ",
    "Git worktree pointer"
  );
  const metadataCandidate = resolve(projectRoot, pointer);
  let metadataDetails;
  try {
    metadataDetails = lstatSync(metadataCandidate, { bigint: true });
  } catch {
    failure("Git worktree pointer target is unavailable");
  }
  validateOwnerAndMode(metadataDetails, "Git worktree pointer target");
  if (!metadataDetails.isDirectory() || metadataDetails.isSymbolicLink()) {
    failure("Git worktree pointer target is outside the reviewed metadata shape");
  }
  const metadataDirectory = realpathSync(metadataCandidate);
  if (basename(dirname(metadataDirectory)) !== "worktrees"
      || metadataDirectory === projectRoot
      || metadataDirectory.startsWith(`${projectRoot}/`)) {
    failure("Git worktree pointer target is outside the reviewed metadata shape");
  }

  const reciprocal = exactSinglePathLine(
    readStableRegularFile(join(metadataDirectory, "gitdir"), "Git worktree reciprocal metadata", 4_096),
    "",
    "Git worktree reciprocal metadata"
  );
  const reciprocalPath = resolve(metadataDirectory, reciprocal);
  let reciprocalDetails;
  try {
    reciprocalDetails = lstatSync(reciprocalPath, { bigint: true });
  } catch {
    failure("Git worktree pointer does not have an exact reciprocal reference");
  }
  if (!reciprocalDetails.isFile() || reciprocalDetails.isSymbolicLink()
      || realpathSync(reciprocalPath) !== gitFile) {
    failure("Git worktree pointer does not have an exact reciprocal reference");
  }

  const commonPointer = exactSinglePathLine(
    readStableRegularFile(join(metadataDirectory, "commondir"), "Git worktree common metadata", 4_096),
    "",
    "Git worktree common metadata"
  );
  const commonCandidate = resolve(metadataDirectory, commonPointer);
  let commonDetails;
  try {
    commonDetails = lstatSync(commonCandidate, { bigint: true });
  } catch {
    failure("Git worktree common metadata target is unavailable");
  }
  validateOwnerAndMode(commonDetails, "Git worktree common metadata target");
  if (!commonDetails.isDirectory() || commonDetails.isSymbolicLink()) {
    failure("Git worktree common metadata target is outside the reviewed metadata shape");
  }
  const commonDirectory = realpathSync(commonCandidate);
  if (commonDirectory !== dirname(dirname(metadataDirectory))) {
    failure("Git worktree common metadata target is outside the reviewed metadata shape");
  }
}

export function enforceTopLevelCoverage(projectRootArgument, secretScanTargets, excludedEntries,
  vendorGeneratedEntries, vendorGeneratedPrefixes) {
  const projectRoot = realpathSync(resolve(projectRootArgument));
  if (![secretScanTargets, excludedEntries, vendorGeneratedEntries, vendorGeneratedPrefixes]
    .every(Array.isArray)) {
    failure("top-level source coverage policy is malformed");
  }
  const coveredTopLevel = new Set(secretScanTargets
    .filter((target) => safeRelativePath(target) && !target.includes("/")));
  const excluded = new Set(excludedEntries);
  const vendorCovered = new Set(secretScanTargets
    .filter((target) => target.startsWith("VendorRuntime/"))
    .map((target) => target.slice("VendorRuntime/".length)));
  const generated = new Set(vendorGeneratedEntries);

  for (const name of readdirSync(projectRoot).sort(compareText)) {
    if (!safeRelativePath(name) || name.includes("/")) failure("project root contains an unsafe entry name");
    const path = join(projectRoot, name);
    const details = lstatSync(path, { bigint: true });
    validateOwnerAndMode(details, name);
    if (details.isSymbolicLink()) failure(`linked top-level entry is not permitted: ${name}`);
    if (coveredTopLevel.has(name)) {
      if (name === "LICENSE" && !details.isFile()) {
        failure("the optional top-level LICENSE must be a regular file");
      }
      continue;
    }
    if (excluded.has(name)) {
      if (name === ".git" && details.isFile()) {
        validateGitWorktreeFile(projectRoot);
        continue;
      }
      if (!details.isDirectory()) failure(`excluded top-level entry is not a directory: ${name}`);
      continue;
    }
    if (name !== "VendorRuntime") failure(`uncovered top-level source entry: ${name}`);
    if (!details.isDirectory()) failure("VendorRuntime must be a real directory");
    for (const child of readdirSync(path).sort(compareText)) {
      if (!safeRelativePath(child) || child.includes("/")) {
        failure("VendorRuntime contains an unsafe top-level entry name");
      }
      if (vendorCovered.has(child)) continue;
      const isGenerated = generated.has(child) || vendorGeneratedPrefixes.some((prefix) =>
        child.startsWith(prefix) && child.length > prefix.length
      );
      if (!isGenerated) failure(`uncovered VendorRuntime source entry: ${child}`);
      const childDetails = lstatSync(join(path, child), { bigint: true });
      validateOwnerAndMode(childDetails, `VendorRuntime/${child}`);
      if (!childDetails.isDirectory() || childDetails.isSymbolicLink()) {
        failure(`generated VendorRuntime entry is not a real directory: ${child}`);
      }
    }
  }
}

export function resolvePresentSecretScanTargets(projectRootArgument, declaredTargets) {
  const projectRoot = resolve(projectRootArgument);
  if (!Array.isArray(declaredTargets) || declaredTargets.length === 0) {
    failure("secret-scan target declaration is malformed");
  }
  const present = [];
  for (const target of declaredTargets) {
    if (!safeRelativePath(target)) failure("secret-scan target declaration is malformed");
    try {
      lstatSync(join(projectRoot, target));
      present.push(target);
    } catch (error) {
      if (target === "LICENSE" && error?.code === "ENOENT") continue;
      throw error;
    }
  }
  return Object.freeze(present);
}

function occurrences(source, needle) {
  let count = 0;
  let offset = source.indexOf(needle);
  while (offset >= 0) {
    count += 1;
    offset = source.indexOf(needle, offset + needle.length);
  }
  return count;
}

function verifyReviewedRuntimeWebSocket(projectRoot, result) {
  const relativePath = "Resources/RuntimeSecurityPreload.mjs";
  const source = readFileSync(join(projectRoot, relativePath), "utf8");
  const loopbackTemplate = "`ws:" + "//${request.headers.host}`";
  const expectedGuard = [
    "const webSocketOrigin = /^127\\.0\\.0\\.1:\\d{1,5}$/.test(request?.headers?.host ?? \"\")",
    `    ? ${loopbackTemplate}`,
    "    : \"'none'\";"
  ].join("\n");
  const matchedLine = source.split("\n")[result.start.line - 1]?.trim();
  return result.path === relativePath
    && result.check_id === "javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket"
    && matchedLine === `? ${loopbackTemplate}`
    && occurrences(source, expectedGuard) === 1
    && occurrences(source, loopbackTemplate) === 1;
}

function readBoundedJSON(path, label) {
  const bytes = readStableRegularFile(path, label, maximumReportBytes);
  if (bytes.length === 0) failure(`${label} is empty`);
  try {
    return { bytes, value: JSON.parse(utf8Decoder.decode(bytes)) };
  } catch {
    failure(`${label} is not valid UTF-8 JSON`);
  }
}

function normalizedScannedPaths(report, scanName) {
  if (!report || typeof report !== "object" || Array.isArray(report)
      || !Array.isArray(report.results) || !Array.isArray(report.errors)
      || !Array.isArray(report.skipped_rules)
      || !report.paths || typeof report.paths !== "object" || Array.isArray(report.paths)
      || !Array.isArray(report.paths.scanned) || !Array.isArray(report.paths.skipped)) {
    failure(`${scanName} Semgrep report has an unsupported schema`);
  }
  if (report.skipped_rules.length > 0) failure(`${scanName} Semgrep report skipped one or more rules`);
  const paths = report.paths.scanned.map((path) => {
    if (!safeRelativePath(path)) failure(`${scanName} Semgrep report contains an unsafe scanned path`);
    return path;
  }).sort(compareText);
  if (new Set(paths).size !== paths.length) failure(`${scanName} Semgrep report repeats a scanned path`);
  return paths;
}

function reportWarningIdentity(scanName, warning) {
  if (!warning || typeof warning !== "object" || Array.isArray(warning)
      || !safeRelativePath(warning.path) || warning.level !== "warn"
      || !Number.isSafeInteger(warning.code) || warning.code < 0) {
    failure(`${scanName} Semgrep report contains an unidentifiable warning`);
  }
  const rule = [
    Array.isArray(warning.type) ? warning.type[0] : warning.type,
    warning.rule_id,
    warning.check_id,
    warning.code
  ]
    .find((value) => typeof value === "string" && value.length > 0 && value.length <= 512);
  if (!rule || /[\u0000-\u001f\u007f]/u.test(rule)) {
    failure(`${scanName} Semgrep report contains a warning without an exact rule identity`);
  }
  return { scan: scanName, path: warning.path, rule, level: warning.level, code: warning.code };
}

export function enforceReportWarnings(reports, allowlist, sourceEntries) {
  if (!Array.isArray(reports) || !Array.isArray(allowlist) || !Array.isArray(sourceEntries)) {
    failure("Semgrep warning policy input is malformed");
  }
  const sourceDigests = new Map(sourceEntries.map((entry) => [entry.path, entry.sha256]));
  const allowed = new Map(allowlist.map((entry) => [
    `${entry.scan}\u0000${entry.path}\u0000${entry.rule}`,
    entry
  ]));
  const consumed = new Set();
  const reviewed = [];
  for (const { name, report } of reports) {
    for (const warning of report.errors) {
      if (warning?.level === "error") {
        failure(`${name} Semgrep report contains an execution error`);
      }
      const identity = reportWarningIdentity(name, warning);
      const key = `${identity.scan}\u0000${identity.path}\u0000${identity.rule}`;
      const entry = allowed.get(key);
      if (!entry || consumed.has(key) || sourceDigests.get(identity.path) !== entry.sourceSha256
          || identity.level !== entry.level || identity.code !== entry.code) {
        failure(`unreviewed Semgrep report warning: ${identity.path} ${identity.rule}`);
      }
      consumed.add(key);
      reviewed.push(Object.freeze({ ...identity, reason: entry.reason, sourceSha256: entry.sourceSha256 }));
    }
  }
  const stale = [...allowed.keys()].filter((key) => !consumed.has(key));
  if (stale.length > 0) failure("Semgrep report warning allowlist contains a stale entry");
  return Object.freeze(reviewed);
}

export function enforceExactSecretCoverage(expectedEntries, scannedPaths, skippedPaths) {
  if (!Array.isArray(expectedEntries) || !Array.isArray(scannedPaths) || !Array.isArray(skippedPaths)) {
    failure("secret-scan coverage report is malformed");
  }
  if (skippedPaths.length > 0) failure("Semgrep skipped one or more exact secret-scan targets");
  const expected = expectedEntries.map((entry) => entry.path).sort(compareText);
  const actual = [...scannedPaths].sort(compareText);
  if (expected.length !== actual.length || expected.some((path, index) => path !== actual[index])) {
    failure("Semgrep did not scan the exact full-text secret target set");
  }
}

function runSemgrep({ semgrep, environment, projectRoot, reportPath, configPath, targets, maximumTargetBytes,
  scanUnknownExtensions = false, excludeRuleIds = [] }) {
  const argumentsList = [
    "scan", "--config", configPath, "--no-rewrite-rule-ids", "--metrics=off",
    "--disable-version-check", "--no-git-ignore", "--verbose",
    "--max-target-bytes", String(maximumTargetBytes),
    "--json-output", reportPath
  ];
  if (scanUnknownExtensions) argumentsList.push("--scan-unknown-extensions");
  for (const ruleID of excludeRuleIds) argumentsList.push("--exclude-rule", ruleID);
  argumentsList.push(...targets);
  const scan = spawnSync(semgrep, argumentsList, {
    cwd: projectRoot,
    env: environment,
    encoding: "utf8",
    maxBuffer: maximumReportBytes
  });
  if (scan.error || scan.signal || scan.status !== 0) {
    failure(`Semgrep execution returned ${String(scan.status)}\n${(scan.stderr || scan.stdout).trim()}`);
  }
  return readBoundedJSON(reportPath, `Semgrep report ${reportPath}`);
}

export function removeStaleSummary(summaryPath) {
  let details;
  try {
    details = lstatSync(summaryPath, { bigint: true });
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw error;
  }
  const effectiveUID = typeof process.geteuid === "function" ? BigInt(process.geteuid()) : details.uid;
  if (!details.isFile() || details.isSymbolicLink() || details.nlink !== 1n
      || details.uid !== effectiveUID || (details.mode & 0o022n) !== 0n) {
    failure("canonical static-security summary is unsafe");
  }
  // Do not unlink after a pathname identity check: no portable Node API can make
  // that check and deletion one operation. The publication worker safely upserts
  // this admitted descriptor-bound file after the scan succeeds.
}

export function writeCanonicalSummary(projectRoot, summary) {
  const directory = join(projectRoot, "build");
  if (!existsSync(directory)) mkdirSync(directory, { mode: 0o700 });
  const destination = join(directory, "static-security-summary.json");
  const payload = Buffer.from(`${JSON.stringify(summary, null, 2)}\n`, "utf8");
  if (payload.length < 2 || payload.length > maximumSummaryBytes) {
    failure("canonical static-security summary exceeds its byte limit");
  }
  // The isolated synchronous worker binds an existing safe summary descriptor
  // before rewriting it, or creates the destination with O_EXCL. It never
  // performs pathname-based cleanup.
  try {
    publishAttestedRegularFileSync(directory, basename(destination), payload, {
      label: "canonical static-security summary directory",
      publishMode: "upsert",
      fileMode: 0o644,
      maximumBytes: maximumSummaryBytes,
      requireCurrentUser: true,
      requireOwnerControlledMode: true,
      requireCanonicalPath: false
    });
  } catch (error) {
    if (/not owned by the current user|group- or world-writable|canonical|symbolic|ELOOP|ENOTDIR|not one directory/iu
      .test(error?.message ?? "")) {
      failure(`canonical static-security summary directory is unsafe: ${error?.message ?? error}`);
    }
    throw error;
  }
  return { bytes: payload.length, sha256: sha256(payload), path: "build/static-security-summary.json" };
}

async function main() {
  if (process.version !== expectedNodeVersion) {
    failure(`expected Node ${expectedNodeVersion}, found ${process.version}`);
  }
  if (process.execArgv.length !== 0 || process.argv.length !== 2) {
    failure("Node loader flags and runner arguments are not permitted");
  }
  const unsafeLaunchKeys = forbiddenLaunchEnvironment.filter((name) => Object.hasOwn(process.env, name));
  if (unsafeLaunchKeys.length > 0) {
    failure(`unsafe launch environment: ${unsafeLaunchKeys.join(", ")}`);
  }

  const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const semgrep = process.env.SEMGREP_BIN;
  if (typeof semgrep !== "string" || !semgrep.startsWith("/") || !existsSync(semgrep)) {
    failure("the clean launcher did not provide Semgrep");
  }
  const summaryPath = join(projectRoot, "build", "static-security-summary.json");
  removeStaleSummary(summaryPath);
  const temporary = mkdtempSync(join(tmpdir(), "fulmar-semgrep-"));
  const ruleManifestPath = join(projectRoot, "Config", "SemgrepRules.json");
  const semgrepEnvironment = {
    PATH: process.env.PATH ?? "/usr/bin:/bin:/usr/sbin:/sbin",
    HOME: temporary,
    TMPDIR: temporary,
    LANG: "C",
    LC_ALL: "C",
    SEMGREP_APP_TOKEN: "",
    SEMGREP_SEND_METRICS: "off",
    SEMGREP_ENABLE_VERSION_CHECK: "0",
    SEMGREP_LOG_FILE: join(temporary, "semgrep.log"),
    SEMGREP_SETTINGS_FILE: join(temporary, "settings.yml"),
    SEMGREP_VERSION_CACHE_PATH: join(temporary, "semgrep-version.json")
  };
  if (existsSync("/etc/ssl/cert.pem")) semgrepEnvironment.SSL_CERT_FILE = "/etc/ssl/cert.pem";

  try {
    const manifest = await loadPinnedRuleManifest(ruleManifestPath);
    enforceTopLevelCoverage(
      projectRoot,
      manifest.secretScanTargets,
      manifest.topLevelExcludedEntries,
      manifest.vendorRuntimeGeneratedEntries,
      manifest.vendorRuntimeGeneratedPrefixes
    );
    const secretScanTargets = resolvePresentSecretScanTargets(
      projectRoot,
      manifest.secretScanTargets
    );
    for (const target of [...manifest.scanTargets, ...secretScanTargets]) {
      const info = lstatSync(join(projectRoot, target));
      if ((!info.isDirectory() && !info.isFile()) || info.isSymbolicLink()) {
        failure(`scan target is missing or linked: ${target}`);
      }
    }
    const textBefore = collectSecretTextFiles(
      projectRoot,
      secretScanTargets,
      manifest.maximumTargetBytes,
      manifest.binaryScanExclusions
    );
    const version = spawnSync(semgrep, ["--version"], {
      cwd: projectRoot,
      env: semgrepEnvironment,
      encoding: "utf8",
      maxBuffer: 4 * 1_024 * 1_024
    });
    if (version.error || version.signal || version.status !== 0) {
      failure(`Semgrep is unavailable (${(version.stderr || version.stdout).trim()})`);
    }
    if (version.stdout.trim() !== manifest.engineVersion) {
      failure(`expected Semgrep ${manifest.engineVersion}, found ${version.stdout.trim()}`);
    }

    const pinned = await materializePinnedSemgrepRules(manifest, temporary);
    const defaultRule = pinned.materials.find((material) => material.id === "semgrep-default");
    const secretRule = pinned.materials.find((material) => material.id === "semgrep-secrets");
    if (!defaultRule || !secretRule) failure("reviewed Semgrep rule material is incomplete");

    const defaultReport = runSemgrep({
      semgrep,
      environment: semgrepEnvironment,
      projectRoot,
      reportPath: join(temporary, "default-report.json"),
      configPath: defaultRule.path,
      targets: manifest.scanTargets,
      maximumTargetBytes: manifest.maximumTargetBytes
    });
    const secretLanguageReport = runSemgrep({
      semgrep,
      environment: semgrepEnvironment,
      projectRoot,
      reportPath: join(temporary, "secret-language-report.json"),
      configPath: secretRule.path,
      targets: textBefore.map((entry) => entry.path),
      maximumTargetBytes: manifest.maximumTargetBytes
    });
    const secretTextReport = runSemgrep({
      semgrep,
      environment: semgrepEnvironment,
      projectRoot,
      reportPath: join(temporary, "secret-text-report.json"),
      configPath: secretRule.path,
      targets: textBefore.map((entry) => entry.path),
      maximumTargetBytes: manifest.maximumTargetBytes,
      scanUnknownExtensions: true,
      excludeRuleIds: manifest.secretLanguageSpecificRuleIds
    });

    const defaultPaths = normalizedScannedPaths(defaultReport.value, "default");
    const secretLanguagePaths = normalizedScannedPaths(secretLanguageReport.value, "secrets-language");
    const secretTextPaths = normalizedScannedPaths(secretTextReport.value, "secrets-text");
    enforceExactSecretCoverage(textBefore, secretTextPaths, secretTextReport.value.paths.skipped);
    const reviewedWarnings = enforceReportWarnings([
      { name: "default", report: defaultReport.value },
      { name: "secrets-language", report: secretLanguageReport.value },
      { name: "secrets-text", report: secretTextReport.value }
    ], manifest.reportWarningAllowlist, textBefore);

    const reviewedFindings = [];
    const blocking = [];
    for (const result of [
      ...defaultReport.value.results,
      ...secretLanguageReport.value.results,
      ...secretTextReport.value.results
    ]) {
      if (!result || typeof result !== "object" || Array.isArray(result)
          || !safeRelativePath(result.path) || !result.start || !Number.isSafeInteger(result.start.line)
          || typeof result.check_id !== "string") {
        failure("Semgrep report contains a malformed finding");
      }
      if (verifyReviewedRuntimeWebSocket(projectRoot, result)) reviewedFindings.push(result);
      else blocking.push(result);
    }
    if (reviewedFindings.length > 1) {
      failure(`the loopback WebSocket exception appeared ${reviewedFindings.length} times; expected at most one`);
    }
    if (blocking.length > 0) {
      const findingSummary = blocking.map((result) =>
        `${result.path}:${result.start.line} ${result.check_id}`
      ).join("\n");
      failure(`${blocking.length} unreviewed finding(s) remain:\n${findingSummary}`);
    }

    const textAfter = collectSecretTextFiles(
      projectRoot,
      secretScanTargets,
      manifest.maximumTargetBytes,
      manifest.binaryScanExclusions
    );
    const settledSecretScanTargets = resolvePresentSecretScanTargets(
      projectRoot,
      manifest.secretScanTargets
    );
    if (JSON.stringify(secretScanTargets) !== JSON.stringify(settledSecretScanTargets)) {
      failure("secret-scan target presence changed while Semgrep was running");
    }
    if (JSON.stringify(textBefore) !== JSON.stringify(textAfter)) {
      failure("secret-scan inputs changed while Semgrep was running");
    }
    const coveragePayload = Buffer.from(
      textAfter.map((entry) => `${entry.path}\u0000${entry.bytes}\u0000${entry.sha256}\n`).join(""),
      "utf8"
    );
    const ruleEvidence = pinned.materials.map((material) => ({
      id: material.id,
      digestMode: material.digestMode,
      digest: material.digest,
      rawDigest: material.rawDigest,
      byteCount: material.byteCount,
      ruleCount: material.ruleCount
    }));
    const summary = {
      schemaVersion: 1,
      passed: true,
      engineVersion: manifest.engineVersion,
      coverage: {
        roots: [...settledSecretScanTargets],
        excludedTopLevelEntries: [...manifest.topLevelExcludedEntries],
        excludedVendorRuntimeEntries: [...manifest.vendorRuntimeGeneratedEntries],
        excludedVendorRuntimePrefixes: [...manifest.vendorRuntimeGeneratedPrefixes],
        reviewedBinaryExclusions: [...manifest.binaryScanExclusions],
        textFileCount: textAfter.length,
        textFileBytes: textAfter.reduce((total, entry) => total + entry.bytes, 0),
        sha256: sha256(coveragePayload),
        files: textAfter
      },
      scans: {
        default: {
          reportSha256: sha256(defaultReport.bytes),
          scannedPathCount: defaultPaths.length,
          rawFindingCount: defaultReport.value.results.length,
          reviewedWarningCount: defaultReport.value.errors.length
        },
        secretsLanguageSpecific: {
          reportSha256: sha256(secretLanguageReport.bytes),
          scannedPathCount: secretLanguagePaths.length,
          rawFindingCount: secretLanguageReport.value.results.length,
          reviewedWarningCount: secretLanguageReport.value.errors.length
        },
        secretsFullText: {
          reportSha256: sha256(secretTextReport.bytes),
          scannedPathCount: secretTextPaths.length,
          rawFindingCount: secretTextReport.value.results.length,
          reviewedWarningCount: secretTextReport.value.errors.length,
          excludedLanguageSpecificRules: [...manifest.secretLanguageSpecificRuleIds]
        }
      },
      reviewedFindings: reviewedFindings.map((result) => ({
        path: result.path,
        line: result.start.line,
        rule: result.check_id,
        reason: "Authenticated exact-port loopback WebSocket guard is structurally verified."
      })),
      reviewedReportWarnings: reviewedWarnings,
      unreviewedFindingCount: 0,
      rules: ruleEvidence
    };
    const evidence = writeCanonicalSummary(projectRoot, summary);
    process.stdout.write(
      `Static security scan passed: ${textAfter.length} source text file(s) received the secrets rules, `
      + `${reviewedFindings.length} structurally verified finding, ${reviewedWarnings.length} exact reviewed `
      + `report warning(s), 0 unreviewed findings; canonical summary ${evidence.path} `
      + `${evidence.sha256}/${evidence.bytes}.\n`
    );
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    await main();
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
