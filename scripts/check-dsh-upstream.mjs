import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { validateTargetVersion } from "./prepare-dsh-upgrade.mjs";
import {
  fetchOfficialGitHubPromotionObservation,
  loadVerifiedDSHPromotionProvenanceAtRoot
} from "./verify-dsh-promotion-provenance.mjs";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const projectRoot = resolve(scriptDirectory, "..");
const registryOrigin = "https://registry.npmjs.org";
const distTagsURL = `${registryOrigin}/-/package/@deepseek-ai%2Fdsh/dist-tags`;
const observedTags = ["alpha", "latest", "next"];
const maximumResponseBytes = 1024 * 1024;
const githubAPIOrigin = "https://api.github.com";
const githubOrigin = "https://github.com";
const githubRepository = "deepseek-ai/deepseek-harness";
const githubReleaseIndexURL = `${githubAPIOrigin}/repos/${githubRepository}/releases?per_page=100&page=1`;
const githubTagIndexURL = `${githubAPIOrigin}/repos/${githubRepository}/tags?per_page=100&page=1`;
const maximumGitHubReleaseIndexBytes = 4 * 1024 * 1024;
const maximumGitHubTagIndexBytes = 1024 * 1024;
const maximumGitHubIndexEntries = 100;

function byteOrder(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function assertExactKeys(value, expected, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)
      || JSON.stringify(Object.keys(value).sort(byteOrder))
        !== JSON.stringify([...expected].sort(byteOrder))) {
    throw new Error(`${label} does not match the reviewed schema`);
  }
}

function validateNote(value, label) {
  if (typeof value !== "string" || value.length < 1 || value.length > 1000
      || /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/u.test(value)) {
    throw new Error(`${label} is invalid`);
  }
  return value;
}

function validateGitHubDSHTag(value) {
  if (typeof value !== "string" || !value.startsWith("dsh-v")) {
    throw new Error("official GitHub DSH tag is invalid");
  }
  const version = validateTargetVersion(value.slice("dsh-v".length));
  if (value !== `dsh-v${version}`) throw new Error("official GitHub DSH tag is invalid");
  return version;
}

function validateGitHubVersionIdentity(versionValue, value, label) {
  const version = validateTargetVersion(versionValue);
  assertExactKeys(
    value,
    ["tag", "releaseObjectAPIURL", "releaseURL", "commitSHA"],
    label
  );
  const tag = `dsh-v${version}`;
  if (value.tag !== tag) throw new Error(`${label} has an unexpected tag`);
  const releaseObjectPrefix = `${githubAPIOrigin}/repos/${githubRepository}/releases/`;
  const releaseObjectID = typeof value.releaseObjectAPIURL === "string"
    && value.releaseObjectAPIURL.startsWith(releaseObjectPrefix)
    ? value.releaseObjectAPIURL.slice(releaseObjectPrefix.length)
    : "";
  const hasReleaseObject = value.releaseObjectAPIURL !== null;
  const hasReleaseURL = value.releaseURL !== null;
  if (hasReleaseObject !== hasReleaseURL) {
    throw new Error(`${label} has an incomplete release identity`);
  }
  const hasRelease = hasReleaseObject;
  if (hasRelease && (!/^[1-9][0-9]{0,19}$/u.test(releaseObjectID)
      || value.releaseURL !== `${githubOrigin}/${githubRepository}/releases/tag/${encodeURIComponent(tag)}`)) {
    throw new Error(`${label} has an unexpected release identity`);
  }
  if (value.commitSHA !== null
      && (typeof value.commitSHA !== "string" || !/^[a-f0-9]{40}$/u.test(value.commitSHA))) {
    throw new Error(`${label} has an invalid tag commit`);
  }
  if (!hasRelease && value.commitSHA === null) {
    throw new Error(`${label} does not identify a release or tag`);
  }
  return { version, ...value };
}

function validateAcknowledgement(value, reviewedPin) {
  assertExactKeys(
    value,
    ["schemaVersion", "registryOrigin", "reviewedPin", "tags", "officialGitHub"],
    "tracked DSH upstream acknowledgement"
  );
  if (value.schemaVersion !== 2 || value.registryOrigin !== registryOrigin
      || value.reviewedPin !== reviewedPin) {
    throw new Error("tracked DSH upstream acknowledgement is invalid or belongs to another pin");
  }
  assertExactKeys(
    value.officialGitHub,
    ["apiOrigin", "repository", "releaseIndexURL", "tagIndexURL", "versions"],
    "tracked official GitHub acknowledgement"
  );
  if (value.officialGitHub.apiOrigin !== githubAPIOrigin
      || value.officialGitHub.repository !== githubRepository
      || value.officialGitHub.releaseIndexURL !== githubReleaseIndexURL
      || value.officialGitHub.tagIndexURL !== githubTagIndexURL
      || value.officialGitHub.versions === null
      || typeof value.officialGitHub.versions !== "object"
      || Array.isArray(value.officialGitHub.versions)
      || Object.keys(value.officialGitHub.versions).length > maximumGitHubIndexEntries) {
    throw new Error("tracked official GitHub acknowledgement is invalid");
  }
  const dispositions = new Set(["assessed-not-promoted", "observed-not-promoted", "promoted"]);
  let promotedCount = 0;
  for (const [version, entry] of Object.entries(value.officialGitHub.versions)) {
    assertExactKeys(
      entry,
      ["tag", "releaseObjectAPIURL", "releaseURL", "commitSHA", "disposition", "note"],
      `tracked official GitHub acknowledgement for ${version}`
    );
    validateGitHubVersionIdentity(version, {
      tag: entry.tag,
      releaseObjectAPIURL: entry.releaseObjectAPIURL,
      releaseURL: entry.releaseURL,
      commitSHA: entry.commitSHA
    }, `tracked official GitHub acknowledgement for ${version}`);
    if (!dispositions.has(entry.disposition)) {
      throw new Error(`tracked official GitHub acknowledgement for ${version} is invalid`);
    }
    validateNote(entry.note, `tracked official GitHub acknowledgement note for ${version}`);
    if (entry.disposition === "promoted") {
      promotedCount += 1;
      if (version !== reviewedPin) {
        throw new Error(`official GitHub acknowledgement cannot mark unpinned ${version} as promoted`);
      }
    } else if (version === reviewedPin) {
      throw new Error("the reviewed DSH pin must be the one promoted official GitHub version");
    }
  }
  if (promotedCount !== 1 || !Object.hasOwn(value.officialGitHub.versions, reviewedPin)) {
    throw new Error("tracked official GitHub acknowledgement must identify one promoted reviewed pin");
  }
  return value;
}

async function boundedRegularJSON(path, maximumBytes = 1024 * 1024) {
  const before = await lstat(path);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1
      || before.size < 2 || before.size > maximumBytes) {
    throw new Error("upstream acknowledgement input is not a bounded regular file");
  }
  const data = await readFile(path);
  const after = await lstat(path);
  if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size
      || after.nlink !== 1 || data.length !== before.size) {
    throw new Error("upstream acknowledgement input changed while it was read");
  }
  return JSON.parse(data.toString("utf8"));
}

export function validateDistTags(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("npm dist-tags response is not an object");
  }
  const tags = {};
  for (const name of observedTags) {
    if (!(name in value)) throw new Error(`npm dist-tags response omitted ${name}`);
    tags[name] = validateTargetVersion(value[name]);
  }
  return Object.fromEntries(Object.entries(tags).sort(([left], [right]) => left.localeCompare(right)));
}

export function evaluateUpstreamAcknowledgements(tagsValue, acknowledgement, reviewedPin) {
  const tags = validateDistTags(tagsValue);
  const pin = validateTargetVersion(reviewedPin);
  const validatedAcknowledgement = validateAcknowledgement(acknowledgement, pin);
  if (validatedAcknowledgement.tags === null
      || typeof validatedAcknowledgement.tags !== "object"
      || Array.isArray(validatedAcknowledgement.tags)
      || JSON.stringify(Object.keys(acknowledgement.tags).sort()) !== JSON.stringify(observedTags)) {
    throw new Error("tracked DSH upstream acknowledgement is invalid or belongs to another pin");
  }
  const mismatches = [];
  const dispositions = new Set(["assessed-not-promoted", "observed-not-promoted", "promoted"]);
  for (const name of observedTags) {
    const entry = acknowledgement.tags[name];
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)
        || !dispositions.has(entry.disposition)
        || typeof entry.note !== "string" || entry.note.length < 1 || entry.note.length > 1000
        || /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/u.test(entry.note)) {
      throw new Error(`tracked DSH acknowledgement for ${name} is invalid`);
    }
    const acknowledgedVersion = validateTargetVersion(entry.version);
    if (acknowledgedVersion !== tags[name]) {
      mismatches.push({ tag: name, acknowledgedVersion, observedVersion: tags[name] });
    }
    if (entry.disposition === "promoted" && acknowledgedVersion !== reviewedPin) {
      throw new Error(`DSH acknowledgement cannot mark unpinned ${name} as promoted`);
    }
  }
  const payload = {
    schemaVersion: 1,
    registryOrigin,
    reviewedPin,
    tags,
    mismatches
  };
  const canonical = JSON.stringify(payload);
  return {
    ...payload,
    observationSHA256: createHash("sha256").update(canonical, "utf8").digest("hex")
  };
}

export async function fetchUpstreamDistTags(fetchImplementation = globalThis.fetch) {
  if (typeof fetchImplementation !== "function") throw new Error("HTTPS fetch is unavailable");
  const response = await fetchImplementation(distTagsURL, {
    method: "GET",
    redirect: "error",
    cache: "no-store",
    signal: AbortSignal.timeout(20_000),
    headers: { Accept: "application/json" }
  });
  if (response.url !== distTagsURL || response.status !== 200) {
    throw new Error("npm dist-tags request did not return the exact registry resource");
  }
  const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (contentType !== "application/json") throw new Error("npm dist-tags response was not JSON");
  const declaredLength = response.headers.get("content-length");
  if (declaredLength !== null
      && (!/^[0-9]+$/u.test(declaredLength) || Number(declaredLength) > maximumResponseBytes)) {
    throw new Error("npm dist-tags response exceeded its declared bound");
  }
  const chunks = [];
  let bytes = 0;
  for await (const chunk of response.body) {
    bytes += chunk.length;
    if (bytes > maximumResponseBytes) throw new Error("npm dist-tags response exceeded its body bound");
    chunks.push(chunk);
  }
  return validateDistTags(JSON.parse(Buffer.concat(chunks, bytes).toString("utf8")));
}

async function fetchBoundedOfficialGitHubArray(
  url,
  maximumBytes,
  fetchImplementation
) {
  if (typeof fetchImplementation !== "function") throw new Error("HTTPS fetch is unavailable");
  const response = await fetchImplementation(url, {
    method: "GET",
    redirect: "error",
    cache: "no-store",
    signal: AbortSignal.timeout(20_000),
    headers: {
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28"
    }
  });
  if (response.url !== url || response.status !== 200) {
    throw new Error("official GitHub index request did not return the exact reviewed resource");
  }
  const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (contentType !== "application/json" && contentType !== "application/vnd.github+json") {
    throw new Error("official GitHub index response was not JSON");
  }
  const declaredLength = response.headers.get("content-length");
  if (declaredLength !== null
      && (!/^[0-9]+$/u.test(declaredLength) || Number(declaredLength) > maximumBytes)) {
    throw new Error("official GitHub index response exceeded its declared bound");
  }
  if (response.headers.get("link")?.includes('rel="next"')) {
    throw new Error("official GitHub DSH index exceeded its one-page review bound");
  }
  if (!response.body) throw new Error("official GitHub index response omitted its body");
  const chunks = [];
  let bytes = 0;
  for await (const chunk of response.body) {
    bytes += chunk.length;
    if (bytes > maximumBytes) {
      throw new Error("official GitHub index response exceeded its body bound");
    }
    chunks.push(chunk);
  }
  const value = JSON.parse(Buffer.concat(chunks, bytes).toString("utf8"));
  if (!Array.isArray(value) || value.length > maximumGitHubIndexEntries) {
    throw new Error("official GitHub DSH index is not one bounded array");
  }
  return value;
}

function normalizeOfficialGitHubReleases(value) {
  const releases = new Map();
  for (const release of value) {
    if (release === null || typeof release !== "object" || Array.isArray(release)
        || typeof release.tag_name !== "string") {
      throw new Error("official GitHub release index contains an invalid entry");
    }
    if (!release.tag_name.startsWith("dsh-v")) continue;
    const version = validateGitHubDSHTag(release.tag_name);
    const identity = validateGitHubVersionIdentity(version, {
      tag: release.tag_name,
      releaseObjectAPIURL: release.url,
      releaseURL: release.html_url,
      commitSHA: null
    }, `official GitHub release ${release.tag_name}`);
    if (release.draft !== false || releases.has(version)) {
      throw new Error("official GitHub DSH release index contains a draft or duplicate version");
    }
    releases.set(version, identity);
  }
  return releases;
}

function normalizeOfficialGitHubTags(value) {
  const tags = new Map();
  for (const entry of value) {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)
        || typeof entry.name !== "string") {
      throw new Error("official GitHub tag index contains an invalid entry");
    }
    if (!entry.name.startsWith("dsh-v")) continue;
    const version = validateGitHubDSHTag(entry.name);
    const commitSHA = entry.commit?.sha;
    if (typeof commitSHA !== "string" || !/^[a-f0-9]{40}$/u.test(commitSHA)
        || entry.commit?.url !== `${githubAPIOrigin}/repos/${githubRepository}/commits/${commitSHA}`
        || tags.has(version)) {
      throw new Error("official GitHub DSH tag index contains an invalid or duplicate tag");
    }
    tags.set(version, { tag: entry.name, commitSHA });
  }
  return tags;
}

export async function fetchOfficialGitHubDSHVersions(fetchImplementation = globalThis.fetch) {
  const [releaseValues, tagValues] = await Promise.all([
    fetchBoundedOfficialGitHubArray(
      githubReleaseIndexURL,
      maximumGitHubReleaseIndexBytes,
      fetchImplementation
    ),
    fetchBoundedOfficialGitHubArray(
      githubTagIndexURL,
      maximumGitHubTagIndexBytes,
      fetchImplementation
    )
  ]);
  const releases = normalizeOfficialGitHubReleases(releaseValues);
  const tags = normalizeOfficialGitHubTags(tagValues);
  const versions = [...new Set([...releases.keys(), ...tags.keys()])].sort(byteOrder);
  return Object.fromEntries(versions.map((version) => {
    const release = releases.get(version);
    const tag = tags.get(version);
    if (!release && !tag) {
      throw new Error("official GitHub DSH version union lost its source identity");
    }
    if (release && tag && release.tag !== tag.tag) {
      throw new Error("official GitHub release and tag indexes disagree");
    }
    return [version, {
      tag: release?.tag ?? tag?.tag,
      releaseObjectAPIURL: release?.releaseObjectAPIURL ?? null,
      releaseURL: release?.releaseURL ?? null,
      commitSHA: tag?.commitSHA ?? null
    }];
  }));
}

export function evaluateOfficialGitHubAcknowledgements(
  observedVersionsValue,
  acknowledgement,
  reviewedPin,
  promotionRecord
) {
  const pin = validateTargetVersion(reviewedPin);
  const validatedAcknowledgement = validateAcknowledgement(acknowledgement, pin);
  if (observedVersionsValue === null || typeof observedVersionsValue !== "object"
      || Array.isArray(observedVersionsValue)
      || Object.keys(observedVersionsValue).length > maximumGitHubIndexEntries) {
    throw new Error("observed official GitHub DSH versions are invalid");
  }
  const observedVersions = {};
  for (const version of Object.keys(observedVersionsValue).sort(byteOrder)) {
    const identity = validateGitHubVersionIdentity(
      version,
      observedVersionsValue[version],
      `observed official GitHub DSH version ${version}`
    );
    observedVersions[version] = {
      tag: identity.tag,
      releaseObjectAPIURL: identity.releaseObjectAPIURL,
      releaseURL: identity.releaseURL,
      commitSHA: identity.commitSHA
    };
  }

  const promoted = validatedAcknowledgement.officialGitHub.versions[pin];
  if (promotionRecord?.repository !== githubRepository
      || promotionRecord?.npm?.version !== pin
      || promoted.tag !== promotionRecord?.github?.tag
      || promoted.releaseObjectAPIURL !== promotionRecord?.github?.releaseObjectAPIURL
      || promoted.releaseURL !== promotionRecord?.github?.releaseURL
      || promoted.commitSHA !== promotionRecord?.github?.commitSHA) {
    throw new Error("official GitHub acknowledgement does not match promoted DSH provenance");
  }

  const acknowledgedVersions = validatedAcknowledgement.officialGitHub.versions;
  const versionNames = [...new Set([
    ...Object.keys(observedVersions),
    ...Object.keys(acknowledgedVersions)
  ])].sort(byteOrder);
  const mismatches = [];
  for (const version of versionNames) {
    const acknowledged = acknowledgedVersions[version] ? {
      tag: acknowledgedVersions[version].tag,
      releaseObjectAPIURL: acknowledgedVersions[version].releaseObjectAPIURL,
      releaseURL: acknowledgedVersions[version].releaseURL,
      commitSHA: acknowledgedVersions[version].commitSHA
    } : null;
    const observed = observedVersions[version] ?? null;
    if (JSON.stringify(acknowledged) !== JSON.stringify(observed)) {
      mismatches.push({ version, acknowledged, observed });
    }
  }
  const payload = {
    schemaVersion: 1,
    apiOrigin: githubAPIOrigin,
    repository: githubRepository,
    releaseIndexURL: githubReleaseIndexURL,
    tagIndexURL: githubTagIndexURL,
    versions: observedVersions,
    mismatches
  };
  return {
    ...payload,
    observationSHA256: createHash("sha256")
      .update(JSON.stringify(payload), "utf8")
      .digest("hex")
  };
}

async function main() {
  if (process.argv.length !== 2) throw new Error("check-dsh-upstream accepts no arguments");
  const [identity, acknowledgement, promotion, tags, githubVersions] = await Promise.all([
    boundedRegularJSON(join(projectRoot, "Config/ReleaseIdentity.json")),
    boundedRegularJSON(join(projectRoot, "Config/DSHUpstreamAcknowledgements.json")),
    loadVerifiedDSHPromotionProvenanceAtRoot(projectRoot),
    fetchUpstreamDistTags(),
    fetchOfficialGitHubDSHVersions()
  ]);
  const reviewedPin = validateTargetVersion(identity?.runtime?.deepseekHarnessVersion);
  const observation = evaluateUpstreamAcknowledgements(tags, acknowledgement, reviewedPin);
  const githubDiscovery = evaluateOfficialGitHubAcknowledgements(
    githubVersions,
    acknowledgement,
    reviewedPin,
    promotion.record
  );
  const githubPromotion = await fetchOfficialGitHubPromotionObservation(promotion.record);
  process.stdout.write(`${JSON.stringify({ ...observation, githubDiscovery, githubPromotion }, null, 2)}\n`);
  if (observation.mismatches.length > 0
      || githubDiscovery.mismatches.length > 0
      || githubPromotion.mismatches.length > 0) {
    process.exitCode = 2;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`DSH upstream check failed: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
