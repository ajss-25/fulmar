#!/usr/bin/env node

import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { chmod, open } from "node:fs/promises";
import https from "node:https";
import { join, resolve } from "node:path";
import { readAttestedRegularFile } from "./attested-regular-file.mjs";

const MANIFEST_MAXIMUM_BYTES = 64 * 1024;
const RULE_MAXIMUM_BYTES = 4 * 1024 * 1024;
const FETCH_TIMEOUT_MILLISECONDS = 70_000;
const ENGINE_VERSION = "1.135.0";
const EXACT_BYTES_DIGEST = "exact-bytes-v1";
const YAML_RULE_BLOCK_SET_DIGEST = "yaml-top-level-rule-block-set-v1";
const YAML_RULE_BLOCK_DOMAIN = Buffer.from(
  "Fulmar Semgrep YAML top-level rule-block set v1\0",
  "utf8"
);
const SCAN_TARGETS = Object.freeze([
  "Package.swift", "Makefile", "Config", "Sources", "Tools", "Resources", "scripts", "Tests"
]);
const SECRET_SCAN_TARGETS = Object.freeze([
  "Package.swift", "Makefile", ".gitattributes", ".gitignore", ".github",
  "LICENSE", "README.md", "CHANGELOG.md", "CONTRIBUTING.md", "SECURITY.md", "SUPPORT.md",
  "docs", "Config", "Sources", "Tools", "Resources", "scripts", "Tests",
  "VendorRuntime.inventory.json", "VendorRuntime/package.json", "VendorRuntime/package-lock.json"
]);
const MAXIMUM_TARGET_BYTES = 16 * 1024 * 1024;
const TOP_LEVEL_EXCLUDED_ENTRIES = Object.freeze([
  ".git", ".build", "build", "recovered-duplicates"
]);
const VENDOR_RUNTIME_GENERATED_ENTRIES = Object.freeze([
  ".npm-cache", "node-v22.23.1-darwin-arm64", "node_modules"
]);
const VENDOR_RUNTIME_GENERATED_PREFIXES = Object.freeze([
  ".node-bootstrap.", ".fulmar-materialize-"
]);
const BINARY_SCAN_EXCLUSIONS = Object.freeze([
  Object.freeze({
    path: "Resources/FulmarAppIcon.png",
    reason: "Reviewed raster application icon; its exact bytes are not a source text surface.",
    sha256: "0266694b0a44bcb3f3500ab543c9a8f96540bdfd95333caddf9d74002a3fae43"
  })
]);
const SECRET_LANGUAGE_SPECIFIC_RULE_IDS = Object.freeze([
  "go.jwt-go.security.jwt.hardcoded-jwt-key",
  "java.java-jwt.security.jwt-hardcode.java-jwt-hardcoded-secret",
  "javascript.express.security.audit.express-session-hardcoded-secret.express-session-hardcoded-secret",
  "javascript.express.security.express-jwt-hardcoded-secret.express-jwt-hardcoded-secret",
  "javascript.jose.security.jwt-hardcode.hardcoded-jwt-secret",
  "javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret",
  "javascript.passport-jwt.security.passport-hardcode.hardcoded-passport-secret",
  "python.boto3.security.hardcoded-token.hardcoded-token",
  "ruby.lang.security.hardcoded-http-auth-in-controller.hardcoded-http-auth-in-controller",
  "terraform.aws.security.aws-provider-static-credentials.aws-provider-static-credentials",
  "terraform.aws.security.aws-lambda-environment-credentials.aws-lambda-environment-credentials",
  "ruby.lang.security.hardcoded-secret-rsa-passphrase.hardcoded-secret-rsa-passphrase",
  "yaml.kubernetes.security.secrets-in-config-file.secrets-in-config-file",
  "kotlin.gradle.security.build-gradle-password-hardcoded.build-gradle-password-hardcoded",
  "terraform.lang.security.rds-insecure-password-storage-in-source-code.rds-insecure-password-storage-in-source-code"
]);
const RULE_IDENTITIES = Object.freeze({
  "semgrep-default": Object.freeze({
    pathname: "/c/p/default",
    format: "yaml",
    contentType: "text/yaml",
    digestMode: YAML_RULE_BLOCK_SET_DIGEST,
    minimumRuleCount: 1_000
  }),
  "semgrep-secrets": Object.freeze({
    pathname: "/c/p/secrets",
    format: "yaml",
    contentType: "text/yaml",
    digestMode: YAML_RULE_BLOCK_SET_DIGEST,
    minimumRuleCount: 50
  })
});

function fail(message) {
  throw new Error(`Pinned Semgrep rules: ${message}`);
}

function exactKeys(value, expected, label) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail(`${label} has an unsupported schema`);
  }
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

async function readBoundedRegular(path, maximumBytes) {
  // Open-first: the no-follow descriptor is opened before any shape decision,
  // its metadata is the reviewed shape, and the pathname is re-attested around
  // the read so a swapped file cannot be substituted for the reviewed inode.
  let input;
  try {
    input = await readAttestedRegularFile(path, {
      label: "pinned Semgrep rule input",
      minimumBytes: 1,
      maximumBytes,
      requireCurrentUser: false,
      requireSingleLink: true
    });
  } catch (error) {
    if (error?.code === "ENOENT") throw error;
    fail(`unsafe input file: ${path}`);
  }
  return input.bytes;
}

function validateRuleDescriptor(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail("rule descriptor is not an object");
  exactKeys(value, [
    "id", "url", "sha256", "digestMode", "byteCount", "ruleCount", "format", "contentType"
  ], "rule descriptor");
  const expected = RULE_IDENTITIES[value.id];
  if (!expected) fail("rule descriptor has an unknown identity");
  let url;
  try { url = new URL(value.url); }
  catch { fail(`${value.id} URL is invalid`); }
  if (url.protocol !== "https:" || url.hostname !== "semgrep.dev" || url.port !== ""
      || url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== ""
      || url.pathname !== expected.pathname || value.format !== expected.format
      || value.contentType !== expected.contentType
      || value.digestMode !== expected.digestMode
      || !/^[a-f0-9]{64}$/u.test(value.sha256)
      || !Number.isSafeInteger(value.byteCount) || value.byteCount < 1
      || value.byteCount > RULE_MAXIMUM_BYTES
      || !Number.isSafeInteger(value.ruleCount)
      || value.ruleCount < expected.minimumRuleCount) {
    fail(`${value.id} descriptor is outside the reviewed boundary`);
  }
  return Object.freeze({ ...value });
}

function safeRelativePath(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 4_096
    && !value.startsWith("/") && !value.includes("\\")
    && value.split("/").every((part) => part.length > 0 && part !== "." && part !== "..")
    && !/[?*\[\]]/u.test(value)
    && !/[\u0000-\u001f\u007f]/u.test(value);
}

function validateReportWarningAllowlist(value) {
  if (!Array.isArray(value) || value.length > 64) {
    fail("report warning allowlist is not a bounded array");
  }
  const identities = new Set();
  return Object.freeze(value.map((entry) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      fail("report warning allowlist entry is not an object");
    }
    exactKeys(entry, [
      "scan", "path", "rule", "level", "code", "reason", "sourceSha256"
    ], "report warning allowlist entry");
    if (!["default", "secrets-language", "secrets-text"].includes(entry.scan) || !safeRelativePath(entry.path)
        || typeof entry.rule !== "string" || entry.rule.length < 1 || entry.rule.length > 512
        || /[\u0000-\u001f\u007f]/u.test(entry.rule)
        || entry.level !== "warn" || !Number.isSafeInteger(entry.code) || entry.code < 0
        || typeof entry.reason !== "string" || entry.reason.length < 20 || entry.reason.length > 1_024
        || /[\u0000\r\u007f]/u.test(entry.reason)
        || !/^[a-f0-9]{64}$/u.test(entry.sourceSha256)) {
      fail("report warning allowlist entry is outside the exact reviewed boundary");
    }
    const identity = `${entry.scan}\u0000${entry.path}\u0000${entry.rule}`;
    if (identities.has(identity)) fail("report warning allowlist has a duplicate identity");
    identities.add(identity);
    return Object.freeze({ ...entry });
  }));
}

export function parsePinnedRuleManifest(bytes) {
  let value;
  try { value = JSON.parse(Buffer.from(bytes).toString("utf8")); }
  catch { fail("manifest is not valid JSON"); }
  if (!value || typeof value !== "object" || Array.isArray(value)) fail("manifest is not an object");
  exactKeys(value, [
    "schemaVersion", "engineVersion", "reviewedAt", "ruleLicenseURL",
    "distributionPolicy", "scanTargets", "secretScanTargets", "maximumTargetBytes",
    "topLevelExcludedEntries", "vendorRuntimeGeneratedEntries",
    "vendorRuntimeGeneratedPrefixes", "binaryScanExclusions", "secretLanguageSpecificRuleIds",
    "reportWarningAllowlist", "rules"
  ], "manifest");
  if (value.schemaVersion !== 3 || value.engineVersion !== ENGINE_VERSION
      || !/^20\d{2}-\d{2}-\d{2}$/u.test(value.reviewedAt)
      || value.ruleLicenseURL !== "https://semgrep.dev/legal/rules-license/"
      || value.distributionPolicy !== "Rules are fetched for the scan and are not redistributed by Fulmar."
      || !Array.isArray(value.scanTargets)
      || value.scanTargets.length !== SCAN_TARGETS.length
      || value.scanTargets.some((target, index) => target !== SCAN_TARGETS[index])
      || !Array.isArray(value.secretScanTargets)
      || value.secretScanTargets.length !== SECRET_SCAN_TARGETS.length
      || value.secretScanTargets.some((target, index) => target !== SECRET_SCAN_TARGETS[index])
      || value.maximumTargetBytes !== MAXIMUM_TARGET_BYTES
      || !Array.isArray(value.topLevelExcludedEntries)
      || value.topLevelExcludedEntries.length !== TOP_LEVEL_EXCLUDED_ENTRIES.length
      || value.topLevelExcludedEntries.some((entry, index) => entry !== TOP_LEVEL_EXCLUDED_ENTRIES[index])
      || !Array.isArray(value.vendorRuntimeGeneratedEntries)
      || value.vendorRuntimeGeneratedEntries.length !== VENDOR_RUNTIME_GENERATED_ENTRIES.length
      || value.vendorRuntimeGeneratedEntries.some((entry, index) => entry !== VENDOR_RUNTIME_GENERATED_ENTRIES[index])
      || !Array.isArray(value.vendorRuntimeGeneratedPrefixes)
      || value.vendorRuntimeGeneratedPrefixes.length !== VENDOR_RUNTIME_GENERATED_PREFIXES.length
      || value.vendorRuntimeGeneratedPrefixes.some((prefix, index) => prefix !== VENDOR_RUNTIME_GENERATED_PREFIXES[index])
      || !Array.isArray(value.binaryScanExclusions)
      || JSON.stringify(value.binaryScanExclusions) !== JSON.stringify(BINARY_SCAN_EXCLUSIONS)
      || !Array.isArray(value.secretLanguageSpecificRuleIds)
      || value.secretLanguageSpecificRuleIds.length !== SECRET_LANGUAGE_SPECIFIC_RULE_IDS.length
      || value.secretLanguageSpecificRuleIds.some((id, index) => id !== SECRET_LANGUAGE_SPECIFIC_RULE_IDS[index])
      || !Array.isArray(value.rules) || value.rules.length !== Object.keys(RULE_IDENTITIES).length) {
    fail("manifest identity or coverage boundary changed");
  }
  const reportWarningAllowlist = validateReportWarningAllowlist(value.reportWarningAllowlist);
  const rules = value.rules.map(validateRuleDescriptor);
  if (new Set(rules.map((rule) => rule.id)).size !== rules.length
      || rules.some((rule) => !Object.hasOwn(RULE_IDENTITIES, rule.id))) {
    fail("manifest rule identities are missing or duplicated");
  }
  return Object.freeze({
    ...value,
    scanTargets: Object.freeze([...value.scanTargets]),
    secretScanTargets: Object.freeze([...value.secretScanTargets]),
    topLevelExcludedEntries: Object.freeze([...value.topLevelExcludedEntries]),
    vendorRuntimeGeneratedEntries: Object.freeze([...value.vendorRuntimeGeneratedEntries]),
    vendorRuntimeGeneratedPrefixes: Object.freeze([...value.vendorRuntimeGeneratedPrefixes]),
    binaryScanExclusions: Object.freeze(value.binaryScanExclusions.map((entry) => Object.freeze({ ...entry }))),
    secretLanguageSpecificRuleIds: Object.freeze([...value.secretLanguageSpecificRuleIds]),
    reportWarningAllowlist,
    rules: Object.freeze(rules)
  });
}

export async function loadPinnedRuleManifest(path) {
  return parsePinnedRuleManifest(await readBoundedRegular(resolve(path), MANIFEST_MAXIMUM_BYTES));
}

function unsigned32(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    fail("rule material exceeds its length framing boundary");
  }
  const bytes = Buffer.allocUnsafe(4);
  bytes.writeUInt32BE(value);
  return bytes;
}

function exactUTF8(bytes, label) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail(`${label} is not valid UTF-8`);
  }
}

function yamlRuleBlockSet(bytes) {
  const text = exactUTF8(bytes, "semgrep-default");
  if (!text.startsWith("rules:\n- ")) {
    fail("semgrep-default does not have the reviewed rules document prefix");
  }
  const starts = [...text.matchAll(/^- /gmu)].map((match) => match.index);
  if (starts.length === 0 || starts[0] !== "rules:\n".length) {
    fail("semgrep-default has an unsupported top-level rule layout");
  }
  const rules = starts.map((start, index) => {
    const block = Buffer.from(text.slice(start, starts[index + 1] ?? text.length), "utf8");
    const ids = block.toString("utf8").split("\n")
      .filter((line) => /^(?:- id|  id): /u.test(line))
      .map((line) => line.replace(/^(?:- id|  id): /u, ""));
    if (ids.length !== 1 || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,511}$/u.test(ids[0])) {
      fail("semgrep-default rule block has a missing, duplicate, or unsafe top-level identity");
    }
    return Object.freeze({ id: ids[0], idBytes: Buffer.from(ids[0], "utf8"), block });
  });
  const sorted = rules.toSorted((left, right) => Buffer.compare(left.idBytes, right.idBytes));
  const digest = createHash("sha256");
  digest.update(YAML_RULE_BLOCK_DOMAIN);
  digest.update(unsigned32(sorted.length));
  for (const rule of sorted) {
    digest.update(unsigned32(rule.idBytes.length));
    digest.update(unsigned32(rule.block.length));
    digest.update(rule.idBytes);
    digest.update(rule.block);
  }
  return Object.freeze({
    digest: digest.digest("hex"),
    ids: Object.freeze(sorted.map((rule) => rule.id))
  });
}

function reviewedRuleEvidence(descriptor, bytes) {
  if (descriptor.format === "json") {
    let value;
    try { value = JSON.parse(bytes.toString("utf8")); }
    catch { fail(`${descriptor.id} is not valid JSON`); }
    if (!value || typeof value !== "object" || Array.isArray(value)
        || !Array.isArray(value.rules)) fail(`${descriptor.id} has no rules array`);
    return Object.freeze({
      digest: descriptor.digestMode === EXACT_BYTES_DIGEST ? sha256(bytes) : fail("unsupported JSON digest mode"),
      ids: Object.freeze(value.rules.map((rule) => rule?.id))
    });
  }
  const ruleSet = yamlRuleBlockSet(bytes);
  return Object.freeze({
    digest: descriptor.digestMode === EXACT_BYTES_DIGEST ? sha256(bytes) : ruleSet.digest,
    ids: ruleSet.ids
  });
}

export function validatePinnedRuleBytes(descriptor, bytes) {
  const material = Buffer.from(bytes);
  if (material.length !== descriptor.byteCount) {
    fail(`${descriptor.id} byte count changed: expected ${descriptor.byteCount}, found ${material.length}`);
  }
  const rawDigest = sha256(material);
  const reviewed = reviewedRuleEvidence(descriptor, material);
  const ids = reviewed.ids;
  if (ids.length !== descriptor.ruleCount || ids.some((id) => typeof id !== "string" || id.length === 0)
      || new Set(ids).size !== ids.length) {
    fail(`${descriptor.id} rule count or identities changed`);
  }
  if (reviewed.digest !== descriptor.sha256) {
    fail(`${descriptor.id} reviewed content checksum changed: expected ${descriptor.sha256}, found ${reviewed.digest}`);
  }
  return Object.freeze({
    id: descriptor.id,
    digestMode: descriptor.digestMode,
    digest: reviewed.digest,
    rawDigest,
    byteCount: material.length,
    ruleCount: ids.length
  });
}

export function fetchPinnedRule(descriptor) {
  return new Promise((resolvePromise, rejectPromise) => {
    let settled = false;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      callback(value);
    };
    const request = https.get(descriptor.url, {
      agent: false,
      headers: {
        Accept: descriptor.contentType,
        "User-Agent": `Semgrep/${ENGINE_VERSION}`,
        "X-Semgrep-Scan-ID": "00000000-0000-0000-0000-000000000000"
      },
      minVersion: "TLSv1.2",
      rejectUnauthorized: true
    }, (response) => {
      if (response.statusCode !== 200) {
        response.resume();
        finish(rejectPromise, new Error(`Pinned Semgrep rules: ${descriptor.id} returned HTTP ${String(response.statusCode)}`));
        return;
      }
      const mediaType = String(response.headers["content-type"] ?? "").split(";", 1)[0].trim().toLowerCase();
      if (mediaType !== descriptor.contentType) {
        response.resume();
        finish(rejectPromise, new Error(`Pinned Semgrep rules: ${descriptor.id} returned unexpected content type`));
        return;
      }
      const declaredLength = response.headers["content-length"];
      if (declaredLength !== undefined && Number(declaredLength) !== descriptor.byteCount) {
        response.resume();
        finish(rejectPromise, new Error(`Pinned Semgrep rules: ${descriptor.id} returned an unexpected content length`));
        return;
      }
      const chunks = [];
      let count = 0;
      response.on("data", (chunk) => {
        if (settled) return;
        count += chunk.length;
        if (count > descriptor.byteCount || count > RULE_MAXIMUM_BYTES) {
          response.destroy();
          finish(rejectPromise, new Error(`Pinned Semgrep rules: ${descriptor.id} exceeded its exact byte bound`));
          return;
        }
        chunks.push(chunk);
      });
      response.on("end", () => {
        if (settled) return;
        try {
          const bytes = Buffer.concat(chunks);
          const evidence = validatePinnedRuleBytes(descriptor, bytes);
          finish(resolvePromise, { bytes, evidence });
        } catch (error) {
          finish(rejectPromise, error);
        }
      });
      response.on("error", (error) => finish(rejectPromise, error));
    });
    request.setTimeout(FETCH_TIMEOUT_MILLISECONDS, () => {
      request.destroy(new Error(`Pinned Semgrep rules: ${descriptor.id} download timed out`));
    });
    request.on("error", (error) => finish(rejectPromise, error));
  });
}

async function writeExclusive(path, bytes) {
  const handle = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
  await chmod(path, 0o600);
}

export async function materializePinnedSemgrepRules(manifest, destination) {
  const materials = [];
  for (const descriptor of manifest.rules) {
    const { bytes, evidence } = await fetchPinnedRule(descriptor);
    const extension = descriptor.format === "json" ? "json" : "yml";
    const path = join(destination, `${descriptor.id}.${extension}`);
    await writeExclusive(path, bytes);
    materials.push(Object.freeze({ path, ...evidence }));
  }
  return Object.freeze({ manifest, materials: Object.freeze(materials) });
}
