// Pure release-profile policy for public external evidence.
//
// Three explicit, separately identifiable profiles exist:
//
// - `stable`: the existing schema v1 record with exactly eight mandatory passed
//   gates, including `twoVersionNotarizedUpdateRollback`. Its shape, names and
//   strictness are unchanged; it remains the default when no profile is named.
// - `beta`: the owner-accepted manual-install/manual-update beta. It carries its
//   own evidence type, an explicit `releaseProfile`, a bounded `distribution`
//   declaration, and its own exact gate set. The automatic-updater exercise is
//   replaced by honest manual install/reinstall/recovery evidence plus proof that
//   the in-app updater is disabled in the exact candidate. Manual replacement is
//   never treated as proof of automatic recovery.
// - `nonnotarized-beta`: an explicit persistent-private-certificate, manual
//   download profile. No Apple trust is claimed; exact DMG/signer identities and
//   real recipient acceptance are required in addition to the beta gates.
//
// Cross-profile evidence, unknown or malformed profiles, stale candidates and
// unbounded records fail closed. This module performs no I/O; callers attest the
// evidence file before handing its bytes here.

const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const VERSION_PATTERN = /^\d+\.\d+\.\d+$/u;
const PLACEHOLDER_DIGEST = "0".repeat(64);

const STABLE_EVIDENCE_TYPE = "fulmar-public-external-evidence";
const BETA_EVIDENCE_TYPE = "fulmar-public-beta-external-evidence";
const NONNOTARIZED_BETA_EVIDENCE_TYPE = "fulmar-public-nonnotarized-beta-external-evidence";

// Gates shared by all profiles: clean installation on both OS bounds,
// history scanning, repository controls, legal/trademark, permissions and
// support/privacy/export review are never relaxed for a beta.
const SHARED_GATES = Object.freeze([
  "cleanInstallCurrentMacOS",
  "cleanInstallMinimumMacOS",
  "fullGitHistoryAndSecretScan",
  "githubRepositoryControls",
  "legalAndTrademarkClearance",
  "permissionAndAccessibilityMatrix",
  "supportPrivacyAndExportReview"
]);

export const STABLE_REQUIRED_GATES = Object.freeze([
  ...SHARED_GATES,
  "twoVersionNotarizedUpdateRollback"
]);

// Beta-only gates. `manualInstallReinstallRecovery` records the documented manual
// download/verify/install, quit/reinstall and manual-rollback workflow exercised on
// the exact notarized candidate. `inAppUpdaterDisabledInCandidate` records proof
// that the exact candidate exposes no updater entry point. Neither record claims
// that manual replacement proves automatic recovery.
// `thirdPartyBinaryLicenseMaterials` keeps the redistributed-binary licence
// obligation (libvips and any other bundled binary) as its own closed gate.
export const BETA_REQUIRED_GATES = Object.freeze([
  ...SHARED_GATES,
  "manualInstallReinstallRecovery",
  "inAppUpdaterDisabledInCandidate",
  "thirdPartyBinaryLicenseMaterials"
]);

// This third profile does not claim Apple trust. The extra recipient gate must
// record the browser-downloaded DMG's real quarantine/Open Anyway behaviour,
// helper/XPC/Keychain authorisation and relaunch, not only a copied-app launch.
export const NONNOTARIZED_BETA_REQUIRED_GATES = Object.freeze([
  ...BETA_REQUIRED_GATES,
  "nonnotarizedRecipientAcceptance"
]);

// Retained-state migration is unqualified today. A beta must either declare the
// explicit clean-install-only restriction or additionally close the
// `retainedStateMigrationAndRecovery` gate with real evidence. Nothing here
// deletes, migrates or fabricates private state.
export const BETA_RETAINED_STATE_CLEAN_INSTALL_ONLY = "clean-install-only";
export const BETA_RETAINED_STATE_MIGRATION_QUALIFIED = "retained-state-migration-qualified";
export const BETA_RETAINED_STATE_MIGRATION_GATE = "retainedStateMigrationAndRecovery";

export const BETA_DISTRIBUTION_CHANNEL = "manual-install";
export const BETA_IN_APP_UPDATER_STATE = "disabled";

export const PUBLIC_RELEASE_PROFILES = Object.freeze({
  stable: Object.freeze({
    name: "stable",
    evidenceType: STABLE_EVIDENCE_TYPE,
    evidenceFileName: "public-external-evidence.json",
    topLevelKeys: Object.freeze([
      "schemaVersion", "evidenceType", "version", "build", "candidate",
      "allRequiredGatesPassed", "gates"
    ]),
    requiredGates: STABLE_REQUIRED_GATES,
    successNoun: "external gates"
  }),
  beta: Object.freeze({
    name: "beta",
    evidenceType: BETA_EVIDENCE_TYPE,
    evidenceFileName: "public-beta-external-evidence.json",
    topLevelKeys: Object.freeze([
      "schemaVersion", "evidenceType", "releaseProfile", "version", "build", "candidate",
      "distribution", "allRequiredGatesPassed", "gates"
    ]),
    requiredGates: BETA_REQUIRED_GATES,
    successNoun: "beta external gates"
  }),
  "nonnotarized-beta": Object.freeze({
    name: "nonnotarized-beta",
    evidenceType: NONNOTARIZED_BETA_EVIDENCE_TYPE,
    evidenceFileName: "public-nonnotarized-beta-external-evidence.json",
    topLevelKeys: Object.freeze([
      "schemaVersion", "evidenceType", "releaseProfile", "version", "build", "candidate",
      "distribution", "allRequiredGatesPassed", "gates"
    ]),
    requiredGates: NONNOTARIZED_BETA_REQUIRED_GATES,
    successNoun: "non-notarized beta external gates"
  })
});

export const PUBLIC_RELEASE_PROFILE_NAMES = Object.freeze(Object.keys(PUBLIC_RELEASE_PROFILES));

export function resolvePublicReleaseProfile(name) {
  if (name === undefined || name === null) return PUBLIC_RELEASE_PROFILES.stable;
  if (typeof name !== "string" || !Object.prototype.hasOwnProperty.call(PUBLIC_RELEASE_PROFILES, name)) {
    throw new Error(`unknown public release profile: ${String(name).slice(0, 64)}`);
  }
  return PUBLIC_RELEASE_PROFILES[name];
}

export function validateCandidateIdentity({ expectedSHA256, expectedVersion, expectedBuild }) {
  if (!SHA256_PATTERN.test(expectedSHA256 ?? "") || !VERSION_PATTERN.test(expectedVersion ?? "")
      || !Number.isSafeInteger(expectedBuild) || expectedBuild < 1) {
    throw new Error("public external evidence verification requires an exact candidate sha256, version and build");
  }
}

const exactKeys = (candidate, expected) => candidate && typeof candidate === "object"
  && !Array.isArray(candidate)
  && JSON.stringify(Object.keys(candidate).sort()) === JSON.stringify([...expected].sort());

function isBoundedReference(reference) {
  return typeof reference === "string" && reference.length >= 1 && reference.length <= 200
    && reference.trim() === reference && !/[\r\n\0]/u.test(reference);
}

function gateRecordIsClosed(evidence) {
  return exactKeys(evidence, ["status", "evidenceSHA256", "reference"])
    && evidence.status === "passed" && SHA256_PATTERN.test(evidence.evidenceSHA256 ?? "")
    && evidence.evidenceSHA256 !== PLACEHOLDER_DIGEST
    && isBoundedReference(evidence.reference);
}

function otherProfileClaimed(value, profile) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const otherTypes = PUBLIC_RELEASE_PROFILE_NAMES
    .filter((name) => name !== profile.name)
    .map((name) => PUBLIC_RELEASE_PROFILES[name].evidenceType);
  if (otherTypes.includes(value.evidenceType)) return true;
  if (Object.prototype.hasOwnProperty.call(value, "releaseProfile")
      && value.releaseProfile !== profile.name) {
    return true;
  }
  return false;
}

function requiredGatesFor(profile, value) {
  if (profile.name === "nonnotarized-beta") {
    if (!exactKeys(value.distribution, ["channel", "inAppUpdater", "retainedState", "appleNotarization"])
        || value.distribution.channel !== BETA_DISTRIBUTION_CHANNEL
        || value.distribution.inAppUpdater !== BETA_IN_APP_UPDATER_STATE
        || value.distribution.retainedState !== BETA_RETAINED_STATE_CLEAN_INSTALL_ONLY
        || value.distribution.appleNotarization !== "not-notarized") {
      throw new Error("non-notarized beta evidence must declare manual-install, updater-disabled, clean-install-only and not-notarized");
    }
    return profile.requiredGates;
  }
  if (profile.name !== "beta") return profile.requiredGates;
  const distribution = value.distribution;
  if (!exactKeys(distribution, ["channel", "inAppUpdater", "retainedState"])
      || distribution.channel !== BETA_DISTRIBUTION_CHANNEL
      || distribution.inAppUpdater !== BETA_IN_APP_UPDATER_STATE) {
    throw new Error("public beta external evidence does not declare the manual-install, updater-disabled distribution");
  }
  if (distribution.retainedState === BETA_RETAINED_STATE_CLEAN_INSTALL_ONLY) {
    return profile.requiredGates;
  }
  if (distribution.retainedState === BETA_RETAINED_STATE_MIGRATION_QUALIFIED) {
    return Object.freeze([...profile.requiredGates, BETA_RETAINED_STATE_MIGRATION_GATE]);
  }
  throw new Error("public beta external evidence must declare clean-install-only or a separately qualified retained-state migration");
}

// Verifies parsed evidence bytes against one explicit profile and exact candidate.
// Returns a frozen summary; throws on every rejection. Error messages for the
// stable profile are unchanged from the original verifier.
export function verifyPublicExternalEvidenceBytes(bytes, options) {
  const profile = resolvePublicReleaseProfile(options?.profile);
  validateCandidateIdentity(options ?? {});
  const { expectedSHA256, expectedVersion, expectedBuild } = options;
  const nonnotarized = profile.name === "nonnotarized-beta";
  if (nonnotarized && (![options.expectedDMGSHA256, options.expectedSignerSHA256].every(
    (digest) => SHA256_PATTERN.test(digest ?? "") && digest !== PLACEHOLDER_DIGEST
  ))) {
    throw new Error("non-notarized beta verification requires independent expected DMG and signer certificate SHA-256 operands");
  }
  let value;
  try {
    value = JSON.parse(Buffer.from(bytes).toString("utf8"));
  } catch {
    throw new Error("public external evidence is not valid JSON");
  }
  if (otherProfileClaimed(value, profile)) {
    throw new Error(`public external evidence belongs to another release profile; the ${profile.name} profile refuses it`);
  }
  if (!exactKeys(value, profile.topLevelKeys) || value.schemaVersion !== 1
      || value.evidenceType !== profile.evidenceType
      || value.allRequiredGatesPassed !== true
      || !exactKeys(value.candidate, nonnotarized ? ["sha256", "dmgSHA256", "signerCertificateSHA256"] : ["sha256"])
      || (profile.name !== "stable" && value.releaseProfile !== profile.name)) {
    throw new Error("public external evidence is incomplete or belongs to another candidate");
  }
  const requiredGates = requiredGatesFor(profile, value);
  if (!exactKeys(value.gates, requiredGates)) {
    throw new Error("public external evidence is incomplete or belongs to another candidate");
  }
  if (value.version !== expectedVersion || value.build !== expectedBuild
      || value.candidate.sha256 !== expectedSHA256
      || (nonnotarized && (value.candidate.dmgSHA256 !== options.expectedDMGSHA256
        || value.candidate.signerCertificateSHA256 !== options.expectedSignerSHA256))) {
    throw new Error("public external evidence is stale or belongs to another candidate");
  }
  for (const gate of requiredGates) {
    if (!gateRecordIsClosed(value.gates[gate])) {
      throw new Error(`public external gate is not closed with bounded evidence: ${gate}`);
    }
  }
  return Object.freeze({
    profile: profile.name,
    gateCount: requiredGates.length,
    gates: Object.freeze([...requiredGates]),
    retainedState: profile.name !== "stable" ? value.distribution.retainedState : null,
    summary: `complete and candidate-bound across all ${requiredGates.length} ${profile.successNoun}.`
  });
}
