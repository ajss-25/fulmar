// Pure fixture-only tests for the explicit manual-install beta release contract.
//
// Every record here is unmistakably synthetic: candidate digests are hashes of
// the literal string "synthetic-beta-fixture", references point below
// `synthetic-test-fixture/`, and every file lives only in a private temporary
// root created and removed by this module. Nothing here invokes a release or
// build wrapper, a Keychain API, the shared build root, or the installed app.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, link, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import {
  BETA_DISTRIBUTION_CHANNEL,
  BETA_IN_APP_UPDATER_STATE,
  BETA_REQUIRED_GATES,
  BETA_RETAINED_STATE_CLEAN_INSTALL_ONLY,
  BETA_RETAINED_STATE_MIGRATION_GATE,
  BETA_RETAINED_STATE_MIGRATION_QUALIFIED,
  NONNOTARIZED_BETA_REQUIRED_GATES,
  PUBLIC_RELEASE_PROFILE_NAMES,
  PUBLIC_RELEASE_PROFILES,
  STABLE_REQUIRED_GATES,
  resolvePublicReleaseProfile,
  verifyPublicExternalEvidenceBytes
} from "../../scripts/public-release-profile-policy.mjs";
import { privateSignerInspectionArguments, verifyNonnotarizedDMGBinding, verifyPrivateSignerDetails } from "../../scripts/nonnotarized-beta-policy.mjs";

const root = process.cwd();
const externalEvidenceVerifier = join(root, "scripts", "verify-public-external-evidence.mjs");
const operatorPath = join(root, "scripts", "run-public-release.sh");
const distributionVerifierPath = join(root, "scripts", "verify-public-distribution.sh");
const makefilePath = join(root, "Makefile");

const syntheticDigest = (label) => createHash("sha256").update(`synthetic-beta-fixture:${label}`).digest("hex");
const candidateSHA = syntheticDigest("candidate-A");
const otherCandidateSHA = syntheticDigest("candidate-B");
const dmgSHA = syntheticDigest("nonnotarized-dmg");
const signerSHA = syntheticDigest("nonnotarized-signer");
const version = "0.0.1";
const build = 1;

const stableGateNames = Object.freeze([
  "cleanInstallCurrentMacOS",
  "cleanInstallMinimumMacOS",
  "fullGitHistoryAndSecretScan",
  "githubRepositoryControls",
  "legalAndTrademarkClearance",
  "permissionAndAccessibilityMatrix",
  "supportPrivacyAndExportReview",
  "twoVersionNotarizedUpdateRollback"
]);
const betaGateNames = Object.freeze([
  "cleanInstallCurrentMacOS",
  "cleanInstallMinimumMacOS",
  "fullGitHistoryAndSecretScan",
  "githubRepositoryControls",
  "legalAndTrademarkClearance",
  "permissionAndAccessibilityMatrix",
  "supportPrivacyAndExportReview",
  "manualInstallReinstallRecovery",
  "inAppUpdaterDisabledInCandidate",
  "thirdPartyBinaryLicenseMaterials"
]);
const nonnotarizedGateNames = Object.freeze([...betaGateNames, "nonnotarizedRecipientAcceptance"]);

const gateRecord = (gate) => ({
  status: "passed",
  evidenceSHA256: syntheticDigest(`gate:${gate}`),
  reference: `synthetic-test-fixture/${gate}.json`
});
const gates = (names) => Object.fromEntries(names.map((gate) => [gate, gateRecord(gate)]));

const stableEvidence = () => ({
  schemaVersion: 1,
  evidenceType: "fulmar-public-external-evidence",
  version,
  build,
  candidate: { sha256: candidateSHA },
  allRequiredGatesPassed: true,
  gates: gates(stableGateNames)
});

const betaEvidence = (retainedState = BETA_RETAINED_STATE_CLEAN_INSTALL_ONLY) => ({
  schemaVersion: 1,
  evidenceType: "fulmar-public-beta-external-evidence",
  releaseProfile: "beta",
  version,
  build,
  candidate: { sha256: candidateSHA },
  distribution: {
    channel: "manual-install",
    inAppUpdater: "disabled",
    retainedState
  },
  allRequiredGatesPassed: true,
  gates: gates(retainedState === BETA_RETAINED_STATE_MIGRATION_QUALIFIED
    ? [...betaGateNames, "retainedStateMigrationAndRecovery"]
    : betaGateNames)
});

const nonnotarizedEvidence = () => ({
  ...betaEvidence(),
  evidenceType: "fulmar-public-nonnotarized-beta-external-evidence",
  releaseProfile: "nonnotarized-beta",
  candidate: { sha256: candidateSHA, dmgSHA256: dmgSHA, signerCertificateSHA256: signerSHA },
  distribution: { ...betaEvidence().distribution, appleNotarization: "not-notarized" },
  gates: gates(nonnotarizedGateNames)
});

const bytes = (value) => Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
const verify = (value, profile, overrides = {}) => verifyPublicExternalEvidenceBytes(bytes(value), {
  profile,
  expectedSHA256: candidateSHA,
  expectedVersion: version,
  expectedBuild: build,
  ...overrides
});
const verifyNonnotarized = (value = nonnotarizedEvidence(), overrides = {}) => verify(value, "nonnotarized-beta", {
  expectedDMGSHA256: dmgSHA, expectedSignerSHA256: signerSHA, ...overrides
});

test("release profiles are exactly stable, beta and nonnotarized-beta with separately identifiable evidence", () => {
  assert.deepEqual(PUBLIC_RELEASE_PROFILE_NAMES, ["stable", "beta", "nonnotarized-beta"]);
  assert.deepEqual([...STABLE_REQUIRED_GATES], stableGateNames);
  assert.deepEqual([...BETA_REQUIRED_GATES], betaGateNames);
  assert.equal(PUBLIC_RELEASE_PROFILES.stable.evidenceType, "fulmar-public-external-evidence");
  assert.equal(PUBLIC_RELEASE_PROFILES.beta.evidenceType, "fulmar-public-beta-external-evidence");
  assert.notEqual(PUBLIC_RELEASE_PROFILES.stable.evidenceFileName, PUBLIC_RELEASE_PROFILES.beta.evidenceFileName);
  assert.equal(PUBLIC_RELEASE_PROFILES.beta.evidenceFileName, "public-beta-external-evidence.json");
  assert.deepEqual([...NONNOTARIZED_BETA_REQUIRED_GATES], nonnotarizedGateNames);
  assert.equal(PUBLIC_RELEASE_PROFILES["nonnotarized-beta"].evidenceType, "fulmar-public-nonnotarized-beta-external-evidence");
  assert.equal(PUBLIC_RELEASE_PROFILES["nonnotarized-beta"].evidenceFileName, "public-nonnotarized-beta-external-evidence.json");
  assert.equal(new Set(PUBLIC_RELEASE_PROFILE_NAMES.map((name) => PUBLIC_RELEASE_PROFILES[name].evidenceFileName)).size, 3);
  assert.ok(Object.isFrozen(NONNOTARIZED_BETA_REQUIRED_GATES));
  assert.ok(STABLE_REQUIRED_GATES.includes("twoVersionNotarizedUpdateRollback"),
    "the stable contract keeps the two-version notarized updater/rollback record mandatory");
  assert.ok(!BETA_REQUIRED_GATES.includes("twoVersionNotarizedUpdateRollback"),
    "beta replaces the automatic-updater exercise with explicitly named manual records");
  for (const shared of stableGateNames.filter((gate) => gate !== "twoVersionNotarizedUpdateRollback")) {
    assert.ok(BETA_REQUIRED_GATES.includes(shared), `beta preserves ${shared}`);
  }
  assert.equal(BETA_DISTRIBUTION_CHANNEL, "manual-install");
  assert.equal(BETA_IN_APP_UPDATER_STATE, "disabled");
  assert.equal(BETA_RETAINED_STATE_CLEAN_INSTALL_ONLY, "clean-install-only");
  assert.equal(BETA_RETAINED_STATE_MIGRATION_QUALIFIED, "retained-state-migration-qualified");
  assert.equal(BETA_RETAINED_STATE_MIGRATION_GATE, "retainedStateMigrationAndRecovery");
  assert.ok(Object.isFrozen(PUBLIC_RELEASE_PROFILES) && Object.isFrozen(BETA_REQUIRED_GATES));
});

test("the default profile is stable and its behaviour is unchanged", () => {
  assert.equal(resolvePublicReleaseProfile(undefined).name, "stable");
  assert.equal(resolvePublicReleaseProfile(null).name, "stable");
  const result = verify(stableEvidence(), undefined);
  assert.equal(result.profile, "stable");
  assert.equal(result.gateCount, 8);
  assert.equal(result.retainedState, null);
  assert.equal(result.summary, "complete and candidate-bound across all 8 external gates.");
  assert.deepEqual(verify(stableEvidence(), "stable"), result);
  for (const missingGate of stableGateNames) {
    const fixture = stableEvidence();
    delete fixture.gates[missingGate];
    assert.throws(() => verify(fixture, "stable"), /public external evidence is incomplete/u, missingGate);
  }
  const optional = stableEvidence();
  optional.gates.twoVersionNotarizedUpdateRollback.status = "not-applicable";
  assert.throws(() => verify(optional, "stable"), /not closed with bounded evidence: twoVersionNotarizedUpdateRollback/u);
  const relabelled = stableEvidence();
  relabelled.releaseProfile = "stable";
  assert.throws(() => verify(relabelled, "stable"), /public external evidence is incomplete/u,
    "the stable record has no profile field; adding one is an unreviewed shape change");
});

test("unknown, malformed and missing profiles fail closed", () => {
  for (const name of ["", "Beta", "BETA", "stable ", "alpha", "preview", "toString", "__proto__", "constructor", 0, {}]) {
    assert.throws(() => resolvePublicReleaseProfile(name), /unknown public release profile/u, JSON.stringify(name));
    assert.throws(() => verify(betaEvidence(), name), /unknown public release profile/u, JSON.stringify(name));
  }
});

test("stable refuses beta evidence and beta refuses stable evidence", () => {
  assert.throws(() => verify(betaEvidence(), "stable"), /belongs to another release profile; the stable profile refuses it/u);
  assert.throws(() => verify(betaEvidence(), undefined), /belongs to another release profile; the stable profile refuses it/u,
    "the default invocation must never accept beta evidence");
  assert.throws(() => verify(stableEvidence(), "beta"), /belongs to another release profile; the beta profile refuses it/u);
  const disguised = betaEvidence();
  disguised.evidenceType = "fulmar-public-external-evidence";
  assert.throws(() => verify(disguised, "stable"), /belongs to another release profile/u,
    "a beta record relabelled with the stable evidence type still carries releaseProfile");
  const disguisedBeta = stableEvidence();
  disguisedBeta.evidenceType = "fulmar-public-beta-external-evidence";
  assert.throws(() => verify(disguisedBeta, "beta"), /public external evidence is incomplete/u,
    "stable gates relabelled as beta cannot satisfy the beta shape");
  const wrongProfileValue = betaEvidence();
  wrongProfileValue.releaseProfile = "stable";
  assert.throws(() => verify(wrongProfileValue, "beta"), /belongs to another release profile/u);
  const examples = { stable: stableEvidence, beta: betaEvidence, "nonnotarized-beta": nonnotarizedEvidence };
  for (const [source, makeEvidence] of Object.entries(examples)) {
    for (const target of PUBLIC_RELEASE_PROFILE_NAMES.filter((name) => name !== source)) {
      assert.throws(() => verify(makeEvidence(), target, { expectedDMGSHA256: dmgSHA, expectedSignerSHA256: signerSHA }),
        /belongs to another release profile/u, `${source} evidence must never qualify ${target}`);
    }
  }
  assert.throws(() => verify(nonnotarizedEvidence(), undefined), /belongs to another release profile/u,
    "the stable default must never infer the non-notarized profile from evidence");
});

test("a complete beta record passes only with its exact shape", () => {
  const result = verify(betaEvidence(), "beta");
  assert.equal(result.profile, "beta");
  assert.equal(result.gateCount, 10);
  assert.equal(result.retainedState, "clean-install-only");
  assert.deepEqual([...result.gates], betaGateNames);
  assert.equal(result.summary, "complete and candidate-bound across all 10 beta external gates.");

  for (const missingGate of betaGateNames) {
    const fixture = betaEvidence();
    delete fixture.gates[missingGate];
    assert.throws(() => verify(fixture, "beta"), /public external evidence is incomplete/u, `missing ${missingGate}`);
  }
  const withUpdaterRecord = betaEvidence();
  withUpdaterRecord.gates.twoVersionNotarizedUpdateRollback = gateRecord("twoVersionNotarizedUpdateRollback");
  assert.throws(() => verify(withUpdaterRecord, "beta"), /public external evidence is incomplete/u,
    "a stable updater record inside beta evidence is cross-profile evidence");
  for (const [label, mutate, rejection] of [
    ["invalid JSON", null, /not valid JSON/u],
    ["schema drift", (value) => { value.schemaVersion = 2; }, /incomplete/u],
    ["missing releaseProfile", (value) => { delete value.releaseProfile; }, /incomplete/u],
    ["missing distribution", (value) => { delete value.distribution; }, /incomplete/u],
    ["extra top-level field", (value) => { value.notes = "unreviewed"; }, /incomplete/u],
    ["gates not all passed", (value) => { value.allRequiredGatesPassed = false; }, /incomplete/u],
    ["candidate extra field", (value) => { value.candidate.path = "/Applications/Fulmar.app"; }, /incomplete/u],
    ["array gates", (value) => { value.gates = Object.values(value.gates); }, /incomplete/u],
    ["placeholder digest", (value) => { value.gates.manualInstallReinstallRecovery.evidenceSHA256 = "0".repeat(64); }, /not closed with bounded evidence: manualInstallReinstallRecovery/u],
    ["uppercase digest", (value) => { value.gates.manualInstallReinstallRecovery.evidenceSHA256 = syntheticDigest("x").toUpperCase(); }, /not closed/u],
    ["deferred manual recovery", (value) => { value.gates.manualInstallReinstallRecovery.status = "deferred"; }, /not closed with bounded evidence: manualInstallReinstallRecovery/u],
    ["planned recovery", (value) => { value.gates.manualInstallReinstallRecovery.status = "planned"; }, /not closed/u],
    ["overlong reference", (value) => { value.gates.thirdPartyBinaryLicenseMaterials.reference = "r".repeat(201); }, /not closed/u],
    ["newline reference", (value) => { value.gates.thirdPartyBinaryLicenseMaterials.reference = "a\nb"; }, /not closed/u],
    ["padded reference", (value) => { value.gates.thirdPartyBinaryLicenseMaterials.reference = " a"; }, /not closed/u],
    ["extra record field", (value) => { value.gates.cleanInstallMinimumMacOS.note = "skipped in CI"; }, /not closed/u],
    ["missing record field", (value) => { delete value.gates.cleanInstallMinimumMacOS.reference; }, /not closed/u]
  ]) {
    if (mutate === null) {
      assert.throws(() => verifyPublicExternalEvidenceBytes(Buffer.from("{not json", "utf8"), {
        profile: "beta", expectedSHA256: candidateSHA, expectedVersion: version, expectedBuild: build
      }), rejection, label);
      continue;
    }
    const fixture = betaEvidence();
    mutate(fixture);
    assert.throws(() => verify(fixture, "beta"), rejection, label);
  }

  const nonnotarized = verifyNonnotarized();
  assert.equal(nonnotarized.profile, "nonnotarized-beta");
  assert.equal(nonnotarized.gateCount, 11);
  assert.equal(nonnotarized.retainedState, "clean-install-only");
  assert.deepEqual([...nonnotarized.gates], nonnotarizedGateNames);
  assert.equal(nonnotarized.summary, "complete and candidate-bound across all 11 non-notarized beta external gates.");
  for (const missingGate of nonnotarizedGateNames) {
    const fixture = nonnotarizedEvidence();
    delete fixture.gates[missingGate];
    assert.throws(() => verifyNonnotarized(fixture), /incomplete/u, `missing ${missingGate}`);
  }
  for (const [label, mutate] of [
    ["missing profile", (value) => { delete value.releaseProfile; }],
    ["wrong profile", (value) => { value.releaseProfile = "beta"; }],
    ["missing distribution", (value) => { delete value.distribution; }],
    ["missing DMG identity", (value) => { delete value.candidate.dmgSHA256; }],
    ["missing signer identity", (value) => { delete value.candidate.signerCertificateSHA256; }],
    ["extra candidate claim", (value) => { value.candidate.notarized = true; }],
    ["extra top-level claim", (value) => { value.appleApproved = true; }],
    ["no aggregate pass", (value) => { value.allRequiredGatesPassed = false; }],
    ["unproven recipient", (value) => { value.gates.nonnotarizedRecipientAcceptance.status = "planned"; }],
    ["placeholder recipient", (value) => { value.gates.nonnotarizedRecipientAcceptance.evidenceSHA256 = "0".repeat(64); }],
    ["unbounded recipient", (value) => { value.gates.nonnotarizedRecipientAcceptance.reference = "x".repeat(201); }],
    ["extra recipient claim", (value) => { value.gates.nonnotarizedRecipientAcceptance.notarized = true; }],
    ["extra stable updater gate", (value) => { value.gates.twoVersionNotarizedUpdateRollback = gateRecord("twoVersionNotarizedUpdateRollback"); }],
    ["extra migration gate", (value) => { value.gates.retainedStateMigrationAndRecovery = gateRecord("retainedStateMigrationAndRecovery"); }]
  ]) {
    const fixture = nonnotarizedEvidence();
    mutate(fixture);
    assert.throws(() => verifyNonnotarized(fixture), undefined, label);
  }
});

test("beta evidence must prove the updater is disabled and the manual-install channel", () => {
  for (const [label, mutate] of [
    ["updater enabled", (value) => { value.distribution.inAppUpdater = "enabled"; }],
    ["updater deferred", (value) => { value.distribution.inAppUpdater = "disabled-by-default"; }],
    ["updater boolean", (value) => { value.distribution.inAppUpdater = false; }],
    ["automatic channel", (value) => { value.distribution.channel = "in-app-update"; }],
    ["extra distribution key", (value) => { value.distribution.autoUpdateURL = "https://example.invalid"; }],
    ["missing updater key", (value) => { delete value.distribution.inAppUpdater; }]
  ]) {
    const fixture = betaEvidence();
    mutate(fixture);
    assert.throws(() => verify(fixture, "beta"), /does not declare the manual-install, updater-disabled distribution/u, label);
  }
  const notProven = betaEvidence();
  notProven.gates.inAppUpdaterDisabledInCandidate.status = "failed";
  assert.throws(() => verify(notProven, "beta"), /not closed with bounded evidence: inAppUpdaterDisabledInCandidate/u);
  const missingProof = betaEvidence();
  delete missingProof.gates.inAppUpdaterDisabledInCandidate;
  assert.throws(() => verify(missingProof, "beta"), /incomplete/u);
  for (const [key, invalidValues] of [
    ["channel", ["in-app-update", "manual", null]],
    ["inAppUpdater", ["enabled", "disabled-by-default", false]],
    ["retainedState", [BETA_RETAINED_STATE_MIGRATION_QUALIFIED, "upgrade-in-place", "", null]],
    ["appleNotarization", ["notarized", "optional", false, null]]
  ]) {
    for (const invalid of invalidValues) {
      const fixture = nonnotarizedEvidence();
      fixture.distribution[key] = invalid;
      assert.throws(() => verifyNonnotarized(fixture), /must declare manual-install, updater-disabled, clean-install-only and not-notarized/u, `${key}: ${JSON.stringify(invalid)}`);
    }
    const missing = nonnotarizedEvidence();
    delete missing.distribution[key];
    assert.throws(() => verifyNonnotarized(missing), /must declare/u, `missing ${key}`);
  }
  const extra = nonnotarizedEvidence();
  extra.distribution.appleTrustOverride = true;
  assert.throws(() => verifyNonnotarized(extra), /must declare/u);
});

test("retained state is either explicitly clean-install-only or separately qualified", () => {
  const cleanOnly = verify(betaEvidence(BETA_RETAINED_STATE_CLEAN_INSTALL_ONLY), "beta");
  assert.equal(cleanOnly.retainedState, "clean-install-only");
  assert.ok(!cleanOnly.gates.includes("retainedStateMigrationAndRecovery"));

  const qualified = verify(betaEvidence(BETA_RETAINED_STATE_MIGRATION_QUALIFIED), "beta");
  assert.equal(qualified.retainedState, "retained-state-migration-qualified");
  assert.equal(qualified.gateCount, 11);
  assert.ok(qualified.gates.includes("retainedStateMigrationAndRecovery"));
  assert.equal(qualified.summary, "complete and candidate-bound across all 11 beta external gates.");

  const claimedWithoutRecord = betaEvidence(BETA_RETAINED_STATE_MIGRATION_QUALIFIED);
  delete claimedWithoutRecord.gates.retainedStateMigrationAndRecovery;
  assert.throws(() => verify(claimedWithoutRecord, "beta"), /incomplete/u,
    "claiming migration support without its record fails closed");
  const recordWithoutClaim = betaEvidence(BETA_RETAINED_STATE_CLEAN_INSTALL_ONLY);
  recordWithoutClaim.gates.retainedStateMigrationAndRecovery = gateRecord("retainedStateMigrationAndRecovery");
  assert.throws(() => verify(recordWithoutClaim, "beta"), /incomplete/u,
    "a migration record under a clean-install-only declaration is contradictory");
  const unqualifiedRecord = betaEvidence(BETA_RETAINED_STATE_MIGRATION_QUALIFIED);
  unqualifiedRecord.gates.retainedStateMigrationAndRecovery.status = "deferred";
  assert.throws(() => verify(unqualifiedRecord, "beta"), /not closed with bounded evidence: retainedStateMigrationAndRecovery/u);
  for (const state of ["migrate", "upgrade-in-place", "", null, true, "Clean-Install-Only", "clean-install-only "]) {
    const fixture = betaEvidence();
    fixture.distribution.retainedState = state;
    assert.throws(() => verify(fixture, "beta"), /must declare clean-install-only or a separately qualified retained-state migration/u, JSON.stringify(state));
  }
});

test("beta evidence is bound to the exact candidate SHA, version and build", () => {
  for (const [label, overrides] of [
    ["candidate SHA", { expectedSHA256: otherCandidateSHA }],
    ["version", { expectedVersion: "0.0.2" }],
    ["build", { expectedBuild: build + 1 }]
  ]) {
    assert.throws(() => verify(betaEvidence(), "beta", overrides), /public external evidence is stale or belongs to another candidate/u, label);
  }
  for (const [label, overrides] of [
    ["uppercase SHA", { expectedSHA256: candidateSHA.toUpperCase() }],
    ["short SHA", { expectedSHA256: candidateSHA.slice(0, 63) }],
    ["prerelease version string", { expectedVersion: "0.0.1-beta.1" }],
    ["zero build", { expectedBuild: 0 }],
    ["string build", { expectedBuild: "1" }],
    ["fractional build", { expectedBuild: 1.5 }]
  ]) {
    assert.throws(() => verify(betaEvidence(), "beta", overrides), /requires an exact candidate sha256, version and build/u, label);
  }
  const stringBuild = betaEvidence();
  stringBuild.build = String(build);
  assert.throws(() => verify(stringBuild, "beta"), /stale or belongs to another candidate/u,
    "a string build in the record is not the exact integer build");
  for (const [key, value] of [
    ["expectedSHA256", otherCandidateSHA], ["expectedDMGSHA256", syntheticDigest("wrong-dmg")],
    ["expectedSignerSHA256", syntheticDigest("wrong-signer")], ["expectedVersion", "0.0.2"], ["expectedBuild", 2]
  ]) {
    assert.throws(() => verifyNonnotarized(nonnotarizedEvidence(), { [key]: value }), /stale or belongs to another candidate/u, key);
  }
  for (const key of ["expectedDMGSHA256", "expectedSignerSHA256"]) {
    for (const value of [undefined, null, "", "0".repeat(64), candidateSHA.toUpperCase(), candidateSHA.slice(1)]) {
      assert.throws(() => verifyNonnotarized(nonnotarizedEvidence(), { [key]: value }), /independent expected DMG and signer certificate SHA-256 operands/u, `${key}: ${JSON.stringify(value)}`);
    }
  }
});

test("the verifier CLI binds the profile explicitly and keeps owner/mode/link checks", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "fulmar-public-beta-contract-"));
  try {
    await chmod(temporary, 0o700);
    const stablePath = join(temporary, "public-external-evidence.json");
    const betaPath = join(temporary, "public-beta-external-evidence.json");
    const nonnotarizedPath = join(temporary, "public-nonnotarized-beta-external-evidence.json");
    const write = async (path, value, mode = 0o600) => {
      await writeFile(path, `${JSON.stringify(value)}\n`, { mode });
      await chmod(path, mode);
    };
    const run = (arguments_) => spawnSync(process.execPath, [externalEvidenceVerifier, ...arguments_], {
      cwd: root, encoding: "utf8", timeout: 5_000
    });
    const candidate = [candidateSHA, version, String(build)];

    await write(stablePath, stableEvidence());
    await write(betaPath, betaEvidence());
    await write(nonnotarizedPath, nonnotarizedEvidence());

    let result = run([stablePath, ...candidate]);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /^public-external-evidence\.json is complete and candidate-bound across all 8 external gates\.\n$/u);
    result = run([stablePath, ...candidate, "--profile", "stable"]);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /all 8 external gates/u);

    result = run([betaPath, ...candidate, "--profile", "beta"]);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /^public-beta-external-evidence\.json is complete and candidate-bound across all 10 beta external gates\.\n$/u);

    const nonnotarizedOperands = ["--profile", "nonnotarized-beta", "--dmg-sha256", dmgSHA, "--signer-sha256", signerSHA];
    result = run([nonnotarizedPath, ...candidate, ...nonnotarizedOperands]);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /^public-nonnotarized-beta-external-evidence\.json is complete and candidate-bound across all 11 non-notarized beta external gates\.\n$/u);
    for (const [sourcePath, profileOperands] of [
      [stablePath, nonnotarizedOperands], [betaPath, nonnotarizedOperands],
      [nonnotarizedPath, []], [nonnotarizedPath, ["--profile", "stable"]], [nonnotarizedPath, ["--profile", "beta"]]
    ]) {
      result = run([sourcePath, ...candidate, ...profileOperands]);
      assert.notEqual(result.status, 0, "CLI evidence must not cross profiles");
      assert.match(result.stderr, /belongs to another release profile/u);
    }
    for (const operands of [
      ["--profile", "nonnotarized-beta"],
      ["--profile", "nonnotarized-beta", "--dmg-sha256", dmgSHA],
      ["--profile", "nonnotarized-beta", "--signer-sha256", signerSHA, "--dmg-sha256", dmgSHA],
      ["--profile", "nonnotarized-beta", "--dmg-sha256", dmgSHA, "--signer-sha256", "0".repeat(64)],
      ["--profile", "nonnotarized-beta", "--dmg-sha256", syntheticDigest("wrong-cli-dmg"), "--signer-sha256", signerSHA],
      ["--profile", "nonnotarized-beta", "--dmg-sha256", dmgSHA, "--signer-sha256", syntheticDigest("wrong-cli-signer")],
      [...nonnotarizedOperands, "--signer-sha256", signerSHA],
      ["--profile", "beta", "--dmg-sha256", dmgSHA, "--signer-sha256", signerSHA],
      ["--profile", "stable", "--dmg-sha256", dmgSHA, "--signer-sha256", signerSHA]
    ]) {
      result = run([nonnotarizedPath, ...candidate, ...operands]);
      assert.notEqual(result.status, 0, `invalid independent operands: ${JSON.stringify(operands)}`);
    }
    await write(nonnotarizedPath, nonnotarizedEvidence(), 0o644);
    result = run([nonnotarizedPath, ...candidate, ...nonnotarizedOperands]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /not owner-private/u);
    await write(nonnotarizedPath, nonnotarizedEvidence());
    const nonnotarizedLink = join(temporary, "nonnotarized-second-link.json");
    await link(nonnotarizedPath, nonnotarizedLink);
    result = run([nonnotarizedPath, ...candidate, ...nonnotarizedOperands]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /must not be hard linked/u);
    await rm(nonnotarizedLink);

    result = run([betaPath, ...candidate]);
    assert.notEqual(result.status, 0, "the default invocation must refuse beta evidence");
    assert.match(result.stderr, /belongs to another release profile; the stable profile refuses it/u);
    result = run([stablePath, ...candidate, "--profile", "beta"]);
    assert.notEqual(result.status, 0, "the beta profile must refuse stable evidence");
    assert.match(result.stderr, /belongs to another release profile; the beta profile refuses it/u);

    for (const [label, arguments_, rejection] of [
      ["unknown profile", [betaPath, ...candidate, "--profile", "alpha"], /unknown public release profile: alpha/u],
      ["empty profile", [betaPath, ...candidate, "--profile", ""], /unknown public release profile/u],
      ["missing profile value", [betaPath, ...candidate, "--profile"], /usage: verify-public-external-evidence\.mjs/u],
      ["joined profile flag", [betaPath, ...candidate, "--profile=beta"], /usage: verify-public-external-evidence\.mjs/u],
      ["profile before operands", ["--profile", "beta", betaPath, ...candidate], /usage: verify-public-external-evidence\.mjs/u],
      ["duplicate profile", [betaPath, ...candidate, "--profile", "beta", "--profile", "beta"], /usage: verify-public-external-evidence\.mjs/u],
      ["missing operands", [betaPath, candidateSHA, version], /usage: verify-public-external-evidence\.mjs/u],
      ["non-integer build", [betaPath, candidateSHA, version, "1.0", "--profile", "beta"], /usage: verify-public-external-evidence\.mjs/u],
      ["stale SHA", [betaPath, otherCandidateSHA, version, String(build), "--profile", "beta"], /stale or belongs to another candidate/u],
      ["stale version", [betaPath, candidateSHA, "0.0.2", String(build), "--profile", "beta"], /stale or belongs to another candidate/u],
      ["stale build", [betaPath, candidateSHA, version, String(build + 1), "--profile", "beta"], /stale or belongs to another candidate/u]
    ]) {
      result = run(arguments_);
      assert.notEqual(result.status, 0, label);
      assert.match(result.stderr, rejection, label);
    }

    const noRecovery = betaEvidence();
    delete noRecovery.gates.manualInstallReinstallRecovery;
    await write(betaPath, noRecovery);
    result = run([betaPath, ...candidate, "--profile", "beta"]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /public external evidence is incomplete/u);

    const updaterOn = betaEvidence();
    updaterOn.distribution.inAppUpdater = "enabled";
    await write(betaPath, updaterOn);
    result = run([betaPath, ...candidate, "--profile", "beta"]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /updater-disabled distribution/u);

    await writeFile(betaPath, "{not json\n", { mode: 0o600 });
    await chmod(betaPath, 0o600);
    result = run([betaPath, ...candidate, "--profile", "beta"]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /not valid JSON/u);

    await write(betaPath, betaEvidence(), 0o644);
    result = run([betaPath, ...candidate, "--profile", "beta"]);
    assert.notEqual(result.status, 0, "non-private beta evidence must fail closed");
    assert.match(result.stderr, /not owner-private/u);

    await write(betaPath, betaEvidence());
    const secondLink = join(temporary, "second-link.json");
    await link(betaPath, secondLink);
    result = run([betaPath, ...candidate, "--profile", "beta"]);
    assert.notEqual(result.status, 0, "hard-linked beta evidence must fail closed");
    assert.match(result.stderr, /must not be hard linked/u);
    await rm(secondLink);

    await rm(betaPath);
    result = run([betaPath, ...candidate, "--profile", "beta"]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /public external evidence is missing for the exact candidate/u);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("nonnotarized pure helpers require the reviewed certificate bytes and exact unqualified DMG binding", () => {
  // codesign's optional certificate prefix must be attached to its option;
  // a separate token is interpreted as another signing target.
  const prefix = "/synthetic-test-fixture/private space/certificate-";
  const target = "/synthetic-test-fixture/Fulmar.app";
  assert.deepEqual(privateSignerInspectionArguments(prefix, target),
    ["-dvvv", `--extract-certificates=${prefix}`, target]);
  // These are labelled fixture bytes, not a DER certificate or a real signing
  // identity. Only pure parsing and digest comparison are exercised here.
  const certificate = Buffer.from("synthetic-beta-fixture:NOT-A-CERTIFICATE:private-signer");
  const certificateSHA = createHash("sha256").update(certificate).digest("hex");
  const details = "Executable=/synthetic-test-fixture/Fulmar.app\nCodeDirectory v=20500 size=120 flags=0x10000(runtime) hashes=1+7 location=embedded\nAuthority=Fulmar Synthetic Fixture\nTeamIdentifier=not set\n";
  assert.doesNotThrow(() => verifyPrivateSignerDetails(details, certificate, certificateSHA));
  for (const [label, invalidDetails, invalidCertificate, expectedSHA] of [
    ["no runtime", details.replace("flags=0x10000(runtime)", "flags=0x0(none)"), certificate, certificateSHA],
    ["ad-hoc", `${details}Signature=adhoc\n`, certificate, certificateSHA],
    ["no authority", details.replace("Authority=Fulmar Synthetic Fixture\n", ""), certificate, certificateSHA],
    ["Developer ID", details.replace("Authority=Fulmar Synthetic Fixture", "Authority=Developer ID Application: Synthetic Fixture"), certificate, certificateSHA],
    ["not a details string", null, certificate, certificateSHA],
    ["wrong bytes", details, Buffer.from("synthetic-beta-fixture:different-certificate"), certificateSHA],
    ["not Buffer", details, certificate.toString("utf8"), certificateSHA],
    ["empty certificate", details, Buffer.alloc(0), certificateSHA],
    ["oversize certificate", details, Buffer.alloc(65537), certificateSHA],
    ["different expected signer", details, certificate, signerSHA],
    ["placeholder expected signer", details, certificate, "0".repeat(64)],
    ["uppercase expected signer", details, certificate, certificateSHA.toUpperCase()],
    ["missing expected signer", details, certificate, undefined]
  ]) {
    assert.throws(() => verifyPrivateSignerDetails(invalidDetails, invalidCertificate, expectedSHA), undefined, label);
  }

  const binding = () => ({
    schemaVersion: 1, type: "fulmar-nonnotarized-beta-dmg-wrapper", releaseProfile: "nonnotarized-beta", publicBetaQualified: false,
    version, build,
    candidate: { file: "Fulmar.app.zip", sha256: candidateSHA },
    image: { file: "Fulmar.dmg", bytes: 4096, sha256: dmgSHA },
    verified: ["candidate-zip-digest", "app-identity", "code-signature-integrity", "read-only-image-roundtrip", "app-tree-bytes-types-modes-links"],
    notProven: ["Developer ID distribution trust", "notarisation", "licensing clearance", "physical installation", "providers", "permission persistence"],
    reproducibleDMGBytes: false
  });
  assert.doesNotThrow(() => verifyNonnotarizedDMGBinding(binding(), candidateSHA, dmgSHA));
  for (const [label, mutate] of [
    ["old private type", (value) => { value.type = "fulmar-private-dmg-wrapper"; }],
    ["old private missing profile", (value) => { delete value.releaseProfile; }],
    ["wrong profile", (value) => { value.releaseProfile = "beta"; }],
    ["claimed public qualification", (value) => { value.publicBetaQualified = true; }],
    ["claimed reproducibility", (value) => { value.reproducibleDMGBytes = true; }],
    ["wrong schema", (value) => { value.schemaVersion = 2; }],
    ["extra field", (value) => { value.appleApproved = true; }],
    ["invalid version", (value) => { value.version = "0.0.1-beta"; }],
    ["invalid build", (value) => { value.build = "1"; }],
    ["zero build", (value) => { value.build = 0; }],
    ["wrong ZIP filename", (value) => { value.candidate.file = "subdir/Fulmar.app.zip"; }],
    ["wrong ZIP digest", (value) => { value.candidate.sha256 = otherCandidateSHA; }],
    ["extra candidate field", (value) => { value.candidate.bytes = 4096; }],
    ["wrong DMG filename", (value) => { value.image.file = "other.dmg"; }],
    ["wrong DMG digest", (value) => { value.image.sha256 = otherCandidateSHA; }],
    ["extra image field", (value) => { value.image.qualified = true; }],
    ["zero image bytes", (value) => { value.image.bytes = 0; }],
    ["fractional image bytes", (value) => { value.image.bytes = 0.5; }],
    ["unsafe image bytes", (value) => { value.image.bytes = Number.MAX_SAFE_INTEGER + 1; }],
    ["missing verification proof", (value) => { value.verified = []; }],
    ["extra verification claim", (value) => { value.verified.push("notarisation"); }],
    ["changed verification order", (value) => { value.verified.reverse(); }],
    ["omitted limitations", (value) => { value.notProven = []; }],
    ["extra limitation", (value) => { value.notProven.push("synthetic-extra-limitation"); }]
  ]) {
    const fixture = binding();
    mutate(fixture);
    assert.throws(() => verifyNonnotarizedDMGBinding(fixture, candidateSHA, dmgSHA), undefined, label);
  }
  for (const value of [null, [], "binding"]) {
    assert.throws(() => verifyNonnotarizedDMGBinding(value, candidateSHA, dmgSHA));
  }
  for (const invalid of ["0".repeat(64), "", undefined, candidateSHA.toUpperCase()]) {
    assert.throws(() => verifyNonnotarizedDMGBinding(binding(), invalid, dmgSHA));
    assert.throws(() => verifyNonnotarizedDMGBinding(binding(), candidateSHA, invalid));
  }
});

test("finalize stays non-building and refuses a changed candidate under either profile", async () => {
  // Policy level: evidence bound to candidate A never qualifies candidate B.
  assert.throws(() => verify(betaEvidence(), "beta", { expectedSHA256: otherCandidateSHA }), /stale or belongs to another candidate/u);
  assert.throws(() => verify(stableEvidence(), "stable", { expectedSHA256: otherCandidateSHA }), /stale or belongs to another candidate/u);

  // Operator level: the profile changes only the evidence file, verifier operands
  // and messages. Fresh mode is the only builder; finalize revalidates the retained
  // immutable candidate and then binds evidence, assets and distribution to it.
  const operator = await readFile(operatorPath, "utf8");
  assert.match(operator, /RELEASE_PROFILE="stable"/u, "stable is the default profile");
  assert.match(operator, /--profile\)/u);
  assert.match(operator, /stable\|beta\|nonnotarized-beta\) RELEASE_PROFILE="\$2"/u);
  assert.match(operator, /accepts only the exact release profiles stable or beta/u);
  assert.doesNotMatch(operator, /FULMAR_PUBLIC_RELEASE_PROFILE|RELEASE_PROFILE="\$\{[A-Z_]+:-/u,
    "the profile is never read from the environment");
  assert.match(operator, /PUBLIC_EXTERNAL_EVIDENCE="\$BUILD_DIR\/public-external-evidence\.json"/u);
  assert.match(operator, /if \[\[ "\$RELEASE_PROFILE" != "stable" \]\]; then\n\s+PUBLIC_EXTERNAL_EVIDENCE="\$BUILD_DIR\/public-beta-external-evidence\.json"\n\s+EVIDENCE_PROFILE_ARGUMENTS=\(--profile "\$RELEASE_PROFILE"\)/u);
  assert.match(operator, /verify-public-external-evidence\.mjs" \\\n\s+"\$PUBLIC_EXTERNAL_EVIDENCE" "\$CANDIDATE_SHA256" "\$CANDIDATE_VERSION" "\$CANDIDATE_BUILD" \\\n\s+"\$\{EVIDENCE_PROFILE_ARGUMENTS\[@\]\}"/u);
  assert.match(operator, /DISTRIBUTION_PROFILE_ARGUMENTS=\("\$\{EVIDENCE_PROFILE_ARGUMENTS\[@\]\}"\)/u);
  assert.match(operator, /verify-public-distribution\.sh" \\\n\s+"\$PUBLIC_ASSETS" "\$PUBLIC_EXTERNAL_EVIDENCE" "\$\{DISTRIBUTION_PROFILE_ARGUMENTS\[@\]\}"/u);
  assert.equal(operator.match(/run_public_build\n/gu)?.length, 1, "exactly one build invocation exists");
  const freshBlock = operator.slice(operator.lastIndexOf('if [[ "$MODE" == "fresh" ]]; then'), operator.lastIndexOf("\nverify_public_candidate\n"));
  assert.match(freshBlock, /run_static_scan\n\s+run_public_build\n\s+retain_public_candidate\nelse\n\s+print "Finalizing the retained public candidate without rebuilding it\."/u);
  assert.ok(operator.lastIndexOf("verify_public_candidate\n") < operator.lastIndexOf("verify-public-external-evidence.mjs"),
    "the retained candidate is revalidated before evidence is consulted");
  assert.ok(operator.lastIndexOf("verify-public-external-evidence.mjs") < operator.lastIndexOf("prepare-public-release-assets.sh"));
  assert.ok(operator.lastIndexOf("prepare-public-release-assets.sh") < operator.lastIndexOf("verify-public-distribution.sh"));
  assert.match(operator, /Public BETA release qualification passed[^\n]*in-app updater disabled[^\n]*not stable qualification[^\n]*No upload or publication was performed/u);
  assert.match(operator, /complete the eight manual gates/u, "the stable pause text is preserved");
  assert.match(operator, /complete the ten manual beta gates/u);
  assert.match(operator, /make public-beta-release-finalize/u);
  assert.doesNotMatch(operator, /(?:\bgh[ \t]+release\b|\/usr\/bin\/curl|\bupload[ \t]+[^.]*asset|\bgit[ \t]+tag\b|notarytool[ \t]+submit)/u,
    "neither profile uploads, tags or submits from the operator");

  const distribution = await readFile(distributionVerifierPath, "utf8");
  assert.match(distribution, /RELEASE_PROFILE="stable"/u);
  assert.match(distribution, /stable\|beta\|nonnotarized-beta\) RELEASE_PROFILE="\$2"/u);
  assert.match(distribution, /DEFAULT_PUBLIC_EXTERNAL_EVIDENCE="\$PROJECT_DIR\/build\/public-external-evidence\.json"/u);
  assert.match(distribution, /DEFAULT_PUBLIC_EXTERNAL_EVIDENCE="\$PROJECT_DIR\/build\/public-beta-external-evidence\.json"/u);
  assert.match(distribution, /verify-public-external-evidence\.mjs" \\\n\s+"\$PUBLIC_EXTERNAL_EVIDENCE" "\$PUBLIC_CANDIDATE_SHA256" "\$PUBLIC_VERSION" "\$PUBLIC_BUILD" \\\n\s+"\$\{EVIDENCE_PROFILE_ARGUMENTS\[@\]\}"/u);
  assert.ok(distribution.lastIndexOf("verify-public-external-evidence.mjs") < distribution.lastIndexOf("Public BETA distribution verification passed"));
  assert.ok(distribution.lastIndexOf("verify-public-external-evidence.mjs") < distribution.lastIndexOf("Public distribution verification passed"));
  assert.match(distribution, /must contain exactly the nine reviewed release assets/u, "the stable nine-asset topology is unchanged");
  assert.match(distribution, /Public beta package must contain exactly the twelve reviewed beta release assets/u,
    "the beta package is the nine stable assets plus the verified material archive, sidecar and binding");
  assert.match(distribution, /The beta profile requires --material-sha256 and --source-commit/u);
  assert.match(distribution, /Material operands are accepted only with --profile beta/u);
  assert.match(distribution, /admit-materials "\$PROVENANCE_RECORD" "\$SNAPSHOT"/u,
    "the verifier admits the checksum-verified material snapshots, never the external package path");
  assert.doesNotMatch(distribution, /FULMAR_PUBLIC_RELEASE_PROFILE|FULMAR_BETA_MATERIAL|MATERIAL_SHA256="\$\{[A-Z_]+:-/u,
    "the material operands are never read from the environment");

  // The operator validates the beta material operands before any signing or
  // build step and forwards them verbatim to the preparer and the verifier.
  assert.match(operator, /ASSET_PROFILE_ARGUMENTS=\(--profile "\$RELEASE_PROFILE" --material-package "\$MATERIAL_PACKAGE" --material-sha256 "\$MATERIAL_SHA256" --source-commit "\$SOURCE_COMMIT_OPERAND"\)/u);
  assert.match(operator, /MATERIAL_VERIFY_ARGUMENTS=\(--material-sha256 "\$MATERIAL_SHA256" --source-commit "\$SOURCE_COMMIT_OPERAND"\)/u);
  assert.match(operator, /prepare-public-release-assets\.sh" \\\n\s+"\$ARCHIVE" "\$MANIFEST" "\$PUBLIC_ASSETS" \\\n\s+"\$CANDIDATE_SHA256" "\$CANDIDATE_VERSION" "\$CANDIDATE_BUILD" \\\n\s+"\$\{ASSET_PROFILE_ARGUMENTS\[@\]\}"/u);
  assert.match(operator, /verify-public-distribution\.sh" \\\n\s+"\$PUBLIC_ASSETS" "\$PUBLIC_EXTERNAL_EVIDENCE" "\$\{DISTRIBUTION_PROFILE_ARGUMENTS\[@\]\}" \\\n\s+"\$\{MATERIAL_VERIFY_ARGUMENTS\[@\]\}"/u);
  assert.match(operator, /Material operands are accepted only with --profile beta/u, "stable refuses beta-only operands");
  assert.ok(operator.indexOf("The beta profile requires --material-package") < operator.indexOf("security find-identity"),
    "material operands are validated before the signing identity is even consulted");
  assert.match(operator, /"\$MATERIAL_SHA256" == "\$CANDIDATE_SHA256" \]\]; then\n\s+print -u2 "The expected material digest equals the retained app candidate digest/u,
    "the app ZIP digest can never stand in for the material digest");

  const makefile = await readFile(makefilePath, "utf8");
  assert.match(makefile, /^public-release: dsh-promotion-provenance-verify\n\t\/bin\/zsh -f scripts\/run-public-release\.sh$/mu);
  assert.match(makefile, /^public-release-finalize: dsh-promotion-provenance-verify\n\t\/bin\/zsh -f scripts\/run-public-release\.sh --finalize$/mu);
  assert.match(makefile, /^public-distribution-verify: dsh-promotion-provenance-verify\n\t\/bin\/zsh -f scripts\/verify-public-distribution\.sh$/mu, "the stable verifier recipe carries no material operands");
  const betaOperands = '--material-package "\\$\\(BETA_MATERIAL_PACKAGE\\)" --material-sha256 "\\$\\(BETA_MATERIAL_SHA256\\)" --source-commit "\\$\\(BETA_SOURCE_COMMIT\\)"';
  assert.match(makefile, new RegExp(`^public-beta-release: dsh-promotion-provenance-verify\\n\\t/bin/zsh -f scripts/run-public-release\\.sh --profile beta ${betaOperands}$`, "mu"));
  assert.match(makefile, new RegExp(`^public-beta-release-finalize: dsh-promotion-provenance-verify\\n\\t/bin/zsh -f scripts/run-public-release\\.sh --profile beta ${betaOperands} --finalize$`, "mu"));
  assert.match(makefile, new RegExp(`^public-beta-assets: dsh-promotion-provenance-verify\\n[\\s\\S]*?prepare-public-release-assets\\.sh \\\\\\n[\\s\\S]*?--profile beta ${betaOperands}$`, "mu"));
  assert.match(makefile, /^public-beta-external-evidence-verify: frozen-candidate-check$/mu);
  assert.match(makefile, /public-beta-external-evidence\.json" "\$\$candidate_sha" "\$\$version" "\$\$build" --profile beta$/mu);
  assert.match(makefile, /^public-beta-distribution-verify: dsh-promotion-provenance-verify\n\t\/bin\/zsh -f scripts\/verify-public-distribution\.sh --profile beta --material-sha256 "\$\(BETA_MATERIAL_SHA256\)" --source-commit "\$\(BETA_SOURCE_COMMIT\)"$/mu);
  assert.match(makefile, /^unexport BETA_MATERIAL_PACKAGE BETA_MATERIAL_SHA256 BETA_SOURCE_COMMIT$/mu,
    "make variables reach the scripts only as explicit operands, never through the environment");
  const phony = makefile.match(/^\.PHONY: (.*)$/mu)?.[1].split(" ") ?? [];
  for (const target of ["public-beta-release", "public-beta-release-finalize", "public-beta-assets", "public-beta-external-evidence-verify", "public-beta-distribution-verify"]) {
    assert.ok(phony.includes(target), `${target} is declared .PHONY`);
  }
});
