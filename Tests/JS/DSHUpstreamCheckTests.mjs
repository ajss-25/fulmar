import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import {
  evaluateOfficialGitHubAcknowledgements,
  evaluateUpstreamAcknowledgements,
  fetchOfficialGitHubDSHVersions,
  fetchUpstreamDistTags,
  validateDistTags
} from "../../scripts/check-dsh-upstream.mjs";

const root = process.cwd();
const repository = "deepseek-ai/deepseek-harness";
const githubAPIOrigin = "https://api.github.com";
const githubOrigin = "https://github.com";
const releaseIndexURL = `${githubAPIOrigin}/repos/${repository}/releases?per_page=100&page=1`;
const tagIndexURL = `${githubAPIOrigin}/repos/${repository}/tags?per_page=100&page=1`;

const tags = {
  next: "0.1.1-rc.2",
  latest: "0.1.1-rc.2",
  alpha: "0.1.2-alpha.4"
};
const acknowledgement = {
  schemaVersion: 2,
  registryOrigin: "https://registry.npmjs.org",
  reviewedPin: "0.1.1-rc.1",
  tags: {
    alpha: { version: tags.alpha, disposition: "observed-not-promoted", note: "Separate review required." },
    latest: { version: tags.latest, disposition: "assessed-not-promoted", note: "Review blocked." },
    next: { version: tags.next, disposition: "assessed-not-promoted", note: "Review blocked." }
  },
  officialGitHub: {
    apiOrigin: githubAPIOrigin,
    repository,
    releaseIndexURL,
    tagIndexURL,
    versions: {
      "0.1.1-rc.1": {
        tag: "dsh-v0.1.1-rc.1",
        releaseObjectAPIURL: `${githubAPIOrigin}/repos/${repository}/releases/374224613`,
        releaseURL: `${githubOrigin}/${repository}/releases/tag/dsh-v0.1.1-rc.1`,
        commitSHA: "5".repeat(40),
        disposition: "promoted",
        note: "The exact reviewed promotion."
      },
      "0.1.1-rc.2": {
        tag: "dsh-v0.1.1-rc.2",
        releaseObjectAPIURL: `${githubAPIOrigin}/repos/${repository}/releases/374388128`,
        releaseURL: `${githubOrigin}/${repository}/releases/tag/dsh-v0.1.1-rc.2`,
        commitSHA: "b".repeat(40),
        disposition: "assessed-not-promoted",
        note: "A newer official GitHub release that is not shipped."
      }
    }
  }
};
const promotion = {
  repository,
  npm: { version: "0.1.1-rc.1" },
  github: {
    tag: "dsh-v0.1.1-rc.1",
    releaseObjectAPIURL: `${githubAPIOrigin}/repos/${repository}/releases/374224613`,
    releaseURL: `${githubOrigin}/${repository}/releases/tag/dsh-v0.1.1-rc.1`,
    commitSHA: "5".repeat(40)
  }
};
const acknowledgedGitHubIdentities = Object.fromEntries(
  Object.entries(acknowledgement.officialGitHub.versions).map(([version, entry]) => [version, {
    tag: entry.tag,
    releaseObjectAPIURL: entry.releaseObjectAPIURL,
    releaseURL: entry.releaseURL,
    commitSHA: entry.commitSHA
  }])
);

test("upstream DSH acknowledgements are deterministic and expose tag drift", () => {
  const accepted = evaluateUpstreamAcknowledgements(tags, acknowledgement, "0.1.1-rc.1");
  assert.deepEqual(accepted.tags, { alpha: tags.alpha, latest: tags.latest, next: tags.next });
  assert.deepEqual(accepted.mismatches, []);
  assert.match(accepted.observationSHA256, /^[a-f0-9]{64}$/u);

  const changed = evaluateUpstreamAcknowledgements(
    { ...tags, alpha: "0.1.2-alpha.5" },
    acknowledgement,
    "0.1.1-rc.1"
  );
  assert.deepEqual(changed.mismatches, [{
    tag: "alpha",
    acknowledgedVersion: "0.1.2-alpha.4",
    observedVersion: "0.1.2-alpha.5"
  }]);
  assert.notEqual(changed.observationSHA256, accepted.observationSHA256);
});

test("upstream DSH acknowledgement rejects malformed tags, stale pins, and false promotion", () => {
  for (const invalid of [null, {}, { ...tags, alpha: "latest" }, { ...tags, next: "^0.1.1" }]) {
    assert.throws(() => validateDistTags(invalid), /dist-tags|exact semantic version/u);
  }
  assert.throws(
    () => evaluateUpstreamAcknowledgements(tags, acknowledgement, "0.1.0-rc.8"),
    /another pin/u
  );
  const falsePromotion = structuredClone(acknowledgement);
  falsePromotion.tags.alpha.disposition = "promoted";
  assert.throws(
    () => evaluateUpstreamAcknowledgements(tags, falsePromotion, "0.1.1-rc.1"),
    /cannot mark unpinned/u
  );

  const falseGitHubPromotion = structuredClone(acknowledgement);
  falseGitHubPromotion.officialGitHub.versions["0.1.1-rc.2"].disposition = "promoted";
  assert.throws(
    () => evaluateOfficialGitHubAcknowledgements(
      acknowledgedGitHubIdentities,
      falseGitHubPromotion,
      "0.1.1-rc.1",
      promotion
    ),
    /cannot mark unpinned/u
  );
});

test("upstream DSH fetch requires the exact JSON registry response and a bounded body", async () => {
  const response = (body, { url = "https://registry.npmjs.org/-/package/@deepseek-ai%2Fdsh/dist-tags", status = 200, type = "application/json" } = {}) => ({
    url,
    status,
    headers: new Headers({ "content-type": type, "content-length": String(Buffer.byteLength(body)) }),
    body: ReadableStream.from([Buffer.from(body)])
  });
  assert.deepEqual(await fetchUpstreamDistTags(async () => response(JSON.stringify(tags))), {
    alpha: tags.alpha,
    latest: tags.latest,
    next: tags.next
  });
  await assert.rejects(
    fetchUpstreamDistTags(async () => response(JSON.stringify(tags), { url: "https://example.com/tags" })),
    /exact registry resource/u
  );
  await assert.rejects(
    fetchUpstreamDistTags(async () => response("<html>", { type: "text/html" })),
    /not JSON/u
  );
});

test("official GitHub acknowledgements expose release-only and tag-only DSH versions without promoting them", () => {
  const accepted = evaluateOfficialGitHubAcknowledgements(
    acknowledgedGitHubIdentities,
    acknowledgement,
    "0.1.1-rc.1",
    promotion
  );
  assert.deepEqual(accepted.mismatches, []);
  assert.match(accepted.observationSHA256, /^[a-f0-9]{64}$/u);

  const releaseOnly = {
    tag: "dsh-v0.1.2-alpha.4",
    releaseObjectAPIURL: `${githubAPIOrigin}/repos/${repository}/releases/380633709`,
    releaseURL: `${githubOrigin}/${repository}/releases/tag/dsh-v0.1.2-alpha.4`,
    commitSHA: null
  };
  const discovered = evaluateOfficialGitHubAcknowledgements(
    { ...acknowledgedGitHubIdentities, "0.1.2-alpha.4": releaseOnly },
    acknowledgement,
    "0.1.1-rc.1",
    promotion
  );
  assert.deepEqual(discovered.mismatches, [{
    version: "0.1.2-alpha.4",
    acknowledged: null,
    observed: releaseOnly
  }]);

  const explicitlyAcknowledged = structuredClone(acknowledgement);
  explicitlyAcknowledged.officialGitHub.versions["0.1.2-alpha.4"] = {
    ...releaseOnly,
    disposition: "observed-not-promoted",
    note: "Observed from the independent GitHub release index; not promoted."
  };
  assert.deepEqual(evaluateOfficialGitHubAcknowledgements(
    { ...acknowledgedGitHubIdentities, "0.1.2-alpha.4": releaseOnly },
    explicitlyAcknowledged,
    "0.1.1-rc.1",
    promotion
  ).mismatches, []);

  const tagOnly = {
    tag: "dsh-v0.1.2-alpha.5",
    releaseObjectAPIURL: null,
    releaseURL: null,
    commitSHA: "c".repeat(40)
  };
  explicitlyAcknowledged.officialGitHub.versions["0.1.2-alpha.5"] = {
    ...tagOnly,
    disposition: "observed-not-promoted",
    note: "Observed from the independent GitHub tag index; not promoted."
  };
  assert.deepEqual(evaluateOfficialGitHubAcknowledgements(
    {
      ...acknowledgedGitHubIdentities,
      "0.1.2-alpha.4": releaseOnly,
      "0.1.2-alpha.5": tagOnly
    },
    explicitlyAcknowledged,
    "0.1.1-rc.1",
    promotion
  ).mismatches, []);
});

test("official GitHub discovery is bounded, redirect-denying, and validates release and tag identity", async () => {
  const release = (version, id) => ({
    tag_name: `dsh-v${version}`,
    url: `${githubAPIOrigin}/repos/${repository}/releases/${id}`,
    html_url: `${githubOrigin}/${repository}/releases/tag/dsh-v${version}`,
    draft: false
  });
  const tag = (version, sha) => ({
    name: `dsh-v${version}`,
    commit: {
      sha,
      url: `${githubAPIOrigin}/repos/${repository}/commits/${sha}`
    }
  });
  const response = (url, value, {
    status = 200,
    type = "application/json",
    declaredLength,
    link,
    body = true
  } = {}) => {
    const bytes = Buffer.from(JSON.stringify(value));
    const headers = new Headers({
      "content-type": type,
      "content-length": declaredLength ?? String(bytes.length)
    });
    if (link !== undefined) headers.set("link", link);
    return {
      url,
      status,
      headers,
      body: body ? ReadableStream.from([bytes]) : null
    };
  };
  const releases = [release("0.1.1-rc.1", 374224613), release("0.1.0-rc.8", 373166049)];
  const gitTags = [tag("0.1.1-rc.1", "5".repeat(40)), tag("0.1.2-alpha.5", "c".repeat(40))];
  const validFetch = async (url, options) => {
    assert.equal(options.redirect, "error");
    assert.equal(options.cache, "no-store");
    if (url === releaseIndexURL) return response(url, releases);
    if (url === tagIndexURL) return response(url, gitTags);
    assert.fail(`unexpected URL ${url}`);
  };
  assert.deepEqual(await fetchOfficialGitHubDSHVersions(validFetch), {
    "0.1.0-rc.8": {
      tag: "dsh-v0.1.0-rc.8",
      releaseObjectAPIURL: `${githubAPIOrigin}/repos/${repository}/releases/373166049`,
      releaseURL: `${githubOrigin}/${repository}/releases/tag/dsh-v0.1.0-rc.8`,
      commitSHA: null
    },
    "0.1.1-rc.1": {
      tag: "dsh-v0.1.1-rc.1",
      releaseObjectAPIURL: `${githubAPIOrigin}/repos/${repository}/releases/374224613`,
      releaseURL: `${githubOrigin}/${repository}/releases/tag/dsh-v0.1.1-rc.1`,
      commitSHA: "5".repeat(40)
    },
    "0.1.2-alpha.5": {
      tag: "dsh-v0.1.2-alpha.5",
      releaseObjectAPIURL: null,
      releaseURL: null,
      commitSHA: "c".repeat(40)
    }
  });

  const hostileFetch = (releaseValue, tagValue, releaseOptions = {}, tagOptions = {}) =>
    fetchOfficialGitHubDSHVersions(async (url) => url === releaseIndexURL
      ? response(releaseOptions.url ?? url, releaseValue, releaseOptions)
      : response(tagOptions.url ?? url, tagValue, tagOptions));
  await assert.rejects(
    hostileFetch(releases, gitTags, { url: "https://example.com/redirected" }),
    /exact reviewed resource/u
  );
  await assert.rejects(
    hostileFetch(releases, gitTags, { link: `<${releaseIndexURL}&page=2>; rel="next"` }),
    /one-page review bound/u
  );
  await assert.rejects(
    hostileFetch(Array.from({ length: 101 }, (_, index) => ({ tag_name: `other-${index}` })), gitTags),
    /bounded array/u
  );
  await assert.rejects(
    hostileFetch([release("latest", 1)], gitTags),
    /exact semantic version/u
  );
  await assert.rejects(
    hostileFetch([{ ...release("0.1.1-rc.1", 1), html_url: "https://example.com/spoof" }], gitTags),
    /unexpected release identity/u
  );
  await assert.rejects(
    hostileFetch([{ ...release("0.1.1-rc.1", 1), html_url: null }], gitTags),
    /incomplete release identity/u
  );
  await assert.rejects(
    hostileFetch(releases, [tag("0.1.1-rc.1", "5".repeat(40)), tag("0.1.1-rc.1", "5".repeat(40))]),
    /duplicate tag/u
  );
  await assert.rejects(
    hostileFetch(releases, [{ ...tag("0.1.1-rc.1", "5".repeat(40)), commit: {
      sha: "5".repeat(40), url: "https://example.com/spoof"
    } }]),
    /invalid or duplicate tag/u
  );
  await assert.rejects(
    hostileFetch(releases, gitTags, { type: "text/html" }),
    /not JSON/u
  );
  await assert.rejects(
    hostileFetch(releases, gitTags, { declaredLength: String(5 * 1024 * 1024) }),
    /declared bound/u
  );
  await assert.rejects(
    hostileFetch(
      releases,
      [{ ...gitTags[0], padding: "x".repeat(1024 * 1024) }],
      {},
      { declaredLength: "0" }
    ),
    /body bound/u
  );
  await assert.rejects(
    hostileFetch(releases, gitTags, { body: false }),
    /omitted its body/u
  );
});

test("tracked GitHub acknowledgements bind the only promoted version to promotion provenance", async () => {
  const [trackedAcknowledgement, trackedPromotion] = await Promise.all([
    readFile(join(root, "Config/DSHUpstreamAcknowledgements.json"), "utf8").then(JSON.parse),
    readFile(join(root, "Config/DSHPromotionProvenance.json"), "utf8").then(JSON.parse)
  ]);
  const observed = Object.fromEntries(
    Object.entries(trackedAcknowledgement.officialGitHub.versions).map(([version, entry]) => [version, {
      tag: entry.tag,
      releaseObjectAPIURL: entry.releaseObjectAPIURL,
      releaseURL: entry.releaseURL,
      commitSHA: entry.commitSHA
    }])
  );
  assert.deepEqual(evaluateOfficialGitHubAcknowledgements(
    observed,
    trackedAcknowledgement,
    trackedAcknowledgement.reviewedPin,
    trackedPromotion
  ).mismatches, []);
  assert.deepEqual(
    Object.entries(trackedAcknowledgement.officialGitHub.versions)
      .filter(([, entry]) => entry.disposition === "promoted")
      .map(([version]) => version),
    ["0.1.1-rc.1"]
  );
  assert.equal(trackedAcknowledgement.tags.alpha.version, "0.1.2-alpha.5");
  assert.deepEqual(
    trackedAcknowledgement.officialGitHub.versions["0.1.2-alpha.5"],
    {
      tag: "dsh-v0.1.2-alpha.5",
      releaseObjectAPIURL: "https://api.github.com/repos/deepseek-ai/deepseek-harness/releases/381145530",
      releaseURL: "https://github.com/deepseek-ai/deepseek-harness/releases/tag/dsh-v0.1.2-alpha.5",
      commitSHA: "db6bdc3576c2d4e7c965e8e3ed0c2a731eed87f5",
      disposition: "observed-not-promoted",
      note: trackedAcknowledgement.officialGitHub.versions["0.1.2-alpha.5"].note
    }
  );
});
