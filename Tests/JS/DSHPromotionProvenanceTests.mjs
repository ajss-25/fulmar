import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import {
  exactDSHCohortFromLock,
  fetchOfficialGitHubPromotionObservation,
  validatePromotionAgainstInputs,
  validatePromotionRecordShape,
  verifyDSHPromotionProvenanceAtRoot
} from "../../scripts/verify-dsh-promotion-provenance.mjs";

const project = resolve(import.meta.dirname, "../..");
const readJSON = async (relative) => JSON.parse(await readFile(join(project, relative), "utf8"));

async function productionInputs() {
  const [record, releaseIdentity, packageLock, packageLockBytes, runtimeManifest, vendorPatchManifest] = await Promise.all([
    readJSON("Config/DSHPromotionProvenance.json"),
    readJSON("Config/ReleaseIdentity.json"),
    readJSON("VendorRuntime/package-lock.json"),
    readFile(join(project, "VendorRuntime/package-lock.json")),
    readJSON("VendorRuntime/package.json"),
    readJSON("Config/VendorRuntimePatches.json")
  ]);
  return { record, releaseIdentity, packageLock, packageLockBytes, runtimeManifest, vendorPatchManifest };
}

function githubResponse(url, value, { status = 200, contentType = "application/json", declaredLength } = {}) {
  const body = Buffer.from(JSON.stringify(value), "utf8");
  return {
    url,
    status,
    headers: new Headers({
      "content-type": contentType,
      "content-length": declaredLength ?? String(body.length)
    }),
    body: ReadableStream.from([body])
  };
}

function officialFixture(record, { body = undefined, annotated = false } = {}) {
  const releaseBody = body ?? "reviewed release notes";
  const refURL = `${record.github.apiOrigin}/repos/${record.repository}/git/refs/tags/${encodeURIComponent(record.github.tag)}`;
  const annotatedSHA = "a".repeat(40);
  const annotatedURL = `${record.github.apiOrigin}/repos/${record.repository}/git/tags/${annotatedSHA}`;
  const commitURL = `${record.github.apiOrigin}/repos/${record.repository}/git/commits/${record.github.commitSHA}`;
  const responses = new Map([
    [record.github.releaseAPIURL, {
      url: record.github.releaseObjectAPIURL,
      html_url: record.github.releaseURL,
      tag_name: record.github.tag,
      draft: false,
      body: releaseBody
    }],
    [refURL, {
      ref: `refs/tags/${record.github.tag}`,
      url: refURL,
      object: annotated
        ? { sha: annotatedSHA, type: "tag", url: annotatedURL }
        : { sha: record.github.commitSHA, type: "commit", url: commitURL }
    }]
  ]);
  if (annotated) {
    responses.set(annotatedURL, {
      sha: annotatedSHA,
      tag: record.github.tag,
      object: { sha: record.github.commitSHA, type: "commit", url: commitURL }
    });
  }
  return async (url) => {
    assert.ok(responses.has(url), `unexpected official GitHub URL ${url}`);
    return githubResponse(url, responses.get(url));
  };
}

test("tracked DSH promotion record binds the exact release pin, lock, cohort, npm artifact, and GitHub source", async () => {
  const result = await verifyDSHPromotionProvenanceAtRoot(project);
  assert.deepEqual(result, {
    version: "0.1.1-rc.1",
    cohortPackageCount: 188,
    cohortSHA256: "88ab9ba14bf22e172f1d330ad1aa7064fa855b37c803838da3a646d8d12e40e5",
    lockSHA256: "408c97b76eb20998fc7fbf7b86d6ff901cab59061e5a72114ee429cdc4b8d6be",
    githubTag: "dsh-v0.1.1-rc.1",
    githubCommitSHA: "528c682e061696f5a160f363f236ecbf53cbd006",
    releaseNotesSHA256: "48e4c1b31b2265d86ae0f168a1eb77c53dd587ef18bc2716b2cc99c54c17e0ff"
  });

  const cli = spawnSync(process.execPath, [join(project, "scripts/verify-dsh-promotion-provenance.mjs"), project], {
    encoding: "utf8",
    env: { PATH: "/usr/bin:/bin" }
  });
  assert.equal(cli.status, 0, cli.stderr);
  assert.match(cli.stdout, /Verified promoted DSH 0\.1\.1-rc\.1: 188 exact cohort packages/u);
});

test("DSH promotion schema rejects unreviewed fields and malformed immutable identities", async () => {
  const { record } = await productionInputs();
  const extra = structuredClone(record);
  extra.github.mutableBranch = "master";
  assert.throws(() => validatePromotionRecordShape(extra), /reviewed schema/u);

  for (const mutate of [
    (value) => { value.npm.version = "latest"; },
    (value) => { value.npm.integrity = "sha256-not-reviewed"; },
    (value) => { value.npm.cohort.packageCount = 0; },
    (value) => { value.github.tag = "dsh-v0.1.1-rc.2"; },
    (value) => { value.github.commitSHA = "528c682"; },
    (value) => { value.github.releaseNotes.byteCount = -1; }
  ]) {
    const changed = structuredClone(record);
    mutate(changed);
    assert.throws(() => validatePromotionRecordShape(changed), /invalid|does not match|not an exact/u);
  }
});

test("DSH promotion validation fails closed on pin, cohort, lock, and patch-provenance drift", async () => {
  const inputs = await productionInputs();
  const validate = (overrides = {}) => validatePromotionAgainstInputs(
    overrides.record ?? inputs.record,
    { ...inputs, ...overrides }
  );

  const changedIdentity = structuredClone(inputs.releaseIdentity);
  changedIdentity.runtime.deepseekHarnessVersion = "0.1.1-rc.2";
  assert.throws(() => validate({ releaseIdentity: changedIdentity }), /release\/runtime pin/u);

  const changedLock = structuredClone(inputs.packageLock);
  changedLock.packages["node_modules/@deepseek-ai/dsh-agent"].version = "0.1.1-rc.2";
  assert.throws(() => validate({ packageLock: changedLock }), /cohort version drifted/u);

  const changedOrigin = structuredClone(inputs.packageLock);
  changedOrigin.packages["node_modules/@deepseek-ai/dsh-agent"].resolved = "https://example.com/dsh-agent.tgz";
  assert.throws(() => validate({ packageLock: changedOrigin }), /cohort origin drifted/u);

  const changedBytes = Buffer.concat([inputs.packageLockBytes, Buffer.from(" ")]);
  assert.throws(() => validate({ packageLockBytes: changedBytes }), /cohort or lock digest/u);

  const changedPatch = structuredClone(inputs.vendorPatchManifest);
  changedPatch.upstreamTarballs[0].integrity = `sha512-${Buffer.alloc(64, 0x55).toString("base64")}`;
  assert.throws(() => validate({ vendorPatchManifest: changedPatch }), /vendored patch record/u);

  const cohort = exactDSHCohortFromLock(inputs.packageLock, inputs.record.npm.version);
  assert.equal(cohort.length, 188);
  assert.equal(cohort[0].package, "@deepseek-ai/dsh");
});

test("bounded official GitHub observation verifies direct and annotated immutable tags", async () => {
  const { record } = await productionInputs();
  const body = "reviewed release notes";
  const expectedDigest = "e747157cd04358755ab78c845794aadb6ff904db1a641ec21ed6ddb8fbd8224b";
  const observedRecord = structuredClone(record);
  observedRecord.github.releaseNotes = {
    source: "github-release-body-utf8",
    byteCount: Buffer.byteLength(body),
    sha256: expectedDigest
  };

  for (const annotated of [false, true]) {
    const observation = await fetchOfficialGitHubPromotionObservation(
      observedRecord,
      officialFixture(observedRecord, { body, annotated })
    );
    assert.deepEqual(observation, {
      tag: observedRecord.github.tag,
      observed: {
        commitSHA: observedRecord.github.commitSHA,
        releaseNotesByteCount: Buffer.byteLength(body),
        releaseNotesSHA256: expectedDigest
      },
      mismatches: []
    });
  }
});

test("official GitHub observation reports mutable-note drift and rejects redirects or oversized responses", async () => {
  const { record } = await productionInputs();
  const changed = await fetchOfficialGitHubPromotionObservation(
    record,
    officialFixture(record, { body: "notes changed after promotion" })
  );
  assert.deepEqual(changed.mismatches, ["releaseNotes.byteCount", "releaseNotes.sha256"]);

  await assert.rejects(
    fetchOfficialGitHubPromotionObservation(record, async (url) => githubResponse(
      "https://example.com/redirected",
      { unsafe: true }
    )),
    /exact reviewed resource/u
  );
  await assert.rejects(
    fetchOfficialGitHubPromotionObservation(record, async (url) => githubResponse(
      url,
      { unsafe: true },
      { declaredLength: String(8 * 1024 * 1024) }
    )),
    /declared bound/u
  );
});

test("PR, push, source, build, release, and daily-observation paths enforce promoted DSH provenance", async () => {
  const [workflow, upstreamWorkflow, makefile, sourceContract, build, release, upstream, patchDocumentation] = await Promise.all([
    readFile(join(project, ".github/workflows/verify-source.yml"), "utf8"),
    readFile(join(project, ".github/workflows/check-upstream-dsh.yml"), "utf8"),
    readFile(join(project, "Makefile"), "utf8"),
    readFile(join(project, "scripts/verify-source-product-contract.mjs"), "utf8"),
    readFile(join(project, "scripts/build-app.sh"), "utf8"),
    readFile(join(project, "scripts/verify-release.sh"), "utf8"),
    readFile(join(project, "scripts/check-dsh-upstream.mjs"), "utf8"),
    readFile(join(project, "docs/VENDORED_PATCHES.md"), "utf8")
  ]);
  assert.match(workflow, /pull_request:[\s\S]*push:[\s\S]*node scripts\/verify-dsh-promotion-provenance\.mjs \./u);
  assert.match(upstreamWorkflow, /^name: Check upstream DSH$/mu);
  assert.match(upstreamWorkflow, /^on:\n  workflow_dispatch:\n  schedule:\n    - cron: "23 5 \* \* \*"$/mu);
  assert.match(upstreamWorkflow, /^permissions:\n  contents: read$/mu);
  assert.match(upstreamWorkflow, /^    runs-on: ubuntu-24\.04$/mu);
  assert.match(upstreamWorkflow, /^    timeout-minutes: 10$/mu);
  assert.match(upstreamWorkflow, /^        uses: actions\/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4\.4\.0$/mu);
  assert.match(upstreamWorkflow, /^          persist-credentials: false$/mu);
  assert.match(upstreamWorkflow, /^        uses: actions\/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4\.4\.0$/mu);
  assert.match(upstreamWorkflow, /^          node-version: 22\.23\.1$/mu);
  assert.match(upstreamWorkflow, /nodeLinuxX64SHA256[\s\S]*sha256sum "\$node_path"[\s\S]*v22\.23\.1/u);
  assert.match(upstreamWorkflow, /^        run: \/bin\/bash -p scripts\/verify-tracked-index\.sh \.$/mu);
  assert.match(upstreamWorkflow, /^        run: node scripts\/check-dsh-upstream\.mjs$/mu);
  assert.doesNotMatch(upstreamWorkflow, /^[ \t]*(?:contents|actions|checks|deployments|id-token|issues|packages|pages|pull-requests|security-events|statuses): write$/mu);
  assert.ok(upstreamWorkflow.indexOf("actions/checkout@")
    < upstreamWorkflow.indexOf("scripts/verify-tracked-index.sh ."));
  assert.ok(upstreamWorkflow.indexOf("scripts/verify-tracked-index.sh .")
    < upstreamWorkflow.indexOf("actions/setup-node@"));
  assert.ok(upstreamWorkflow.indexOf("actions/setup-node@")
    < upstreamWorkflow.indexOf("node scripts/check-dsh-upstream.mjs"));
  assert.match(makefile, /dsh-promotion-provenance-verify:\n\tVendorRuntime\/node-v22\.23\.1-darwin-arm64\/bin\/node scripts\/verify-dsh-promotion-provenance\.mjs \./u);
  for (const target of ["build", "private-release", "release-verify", "deterministic-release-verify", "public-release", "public-release-finalize", "public-assets", "public-distribution-verify"]) {
    assert.match(makefile, new RegExp(`^${target}:.*dsh-promotion-provenance-verify`, "mu"));
  }
  assert.match(sourceContract, /verifyDSHPromotionProvenanceAtRoot\(root\)/u);
  assert.match(build, /verify-source-product-contract\.mjs/u);
  assert.match(release, /verify-source-product-contract\.mjs/u);
  assert.match(sourceContract, /\.github\/workflows\/check-upstream-dsh\.yml/u);
  assert.match(sourceContract, /upstreamDSHWorkflow !== expectedUpstreamDSHWorkflow/u);
  assert.match(sourceContract, /scheduled upstream DSH workflow drifted from its reviewed read-only observer contract/u);
  assert.match(upstream, /fetchOfficialGitHubDSHVersions\(\)/u);
  assert.match(upstream, /evaluateOfficialGitHubAcknowledgements/u);
  assert.match(upstream, /fetchOfficialGitHubPromotionObservation\(promotion\.record\)/u);
  assert.match(patchDocumentation, /privacy revision 1; streamed tool-identity revision 2/u);
  assert.doesNotMatch(patchDocumentation, /streamed tool-identity revision 1/u);
});
