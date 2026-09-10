# Public beta release contract — manual-install macOS beta

This document describes the **source implementation** of an explicit, separately
identifiable release profile for a downloadable macOS beta that is installed and
updated manually. It is a release-control record, not legal advice, not release
notes, and not evidence that any candidate has passed it. No beta candidate has
been qualified under this contract, no release or tag exists, and nothing here
changes the stable public contract.

MIT source publication and an installable beta are separate outputs. Publishing
the source does not publish a binary; qualifying a beta binary does not alter the
source-only gates in `docs/PUBLIC_RELEASE_READINESS.md`.

## Two profiles, one verifier

| | `stable` (default) | `beta` |
| --- | --- | --- |
| Selection | Default four-operand invocation; `make public-release`, `make public-release-finalize`, `make public-external-evidence-verify`, `make public-distribution-verify` | Explicit `--profile beta` operand; `make public-beta-release`, `make public-beta-release-finalize`, `make public-beta-external-evidence-verify`, `make public-beta-distribution-verify` |
| Evidence file | owner-private `build/public-external-evidence.json` | owner-private `build/public-beta-external-evidence.json` |
| `evidenceType` | `fulmar-public-external-evidence` | `fulmar-public-beta-external-evidence` |
| Extra top-level fields | none | `releaseProfile: "beta"`, `distribution` |
| Mandatory records | exactly eight, including `twoVersionNotarizedUpdateRollback` | exactly ten (eleven if retained-state migration is separately qualified); see below |
| Automatic updater | two-version notarized update/rollback exercise required | must be **disabled** in the exact candidate and proven so; no updater exercise is required or accepted |
| Release assets | exactly nine; `SHA256SUMS.txt` lists the other eight | exactly twelve: the nine plus the verified third-party material archive, its `.tar.sha256` sidecar and its `.binding.json`; `SHA256SUMS.txt` lists the other eleven; see "Beta release assets" |
| Material operands | none accepted | `--material-package`, `--material-sha256` and `--source-commit` required by the operator and the preparer; `--material-sha256` and `--source-commit` required by the distribution verifier |

The profile is never inferred from evidence contents, a file name, or the
environment. The stable verifier refuses beta evidence and the beta verifier
refuses stable evidence, whatever their completeness. An unknown, empty,
differently cased or duplicated profile operand is a usage error. The policy is
implemented in `scripts/public-release-profile-policy.mjs` and exercised through
`scripts/verify-public-external-evidence.mjs`, `scripts/run-public-release.sh` and
`scripts/verify-public-distribution.sh`.

## Beta evidence shape (schema v1)

```json
{
  "schemaVersion": 1,
  "evidenceType": "fulmar-public-beta-external-evidence",
  "releaseProfile": "beta",
  "version": "<exact manifest version>",
  "build": <exact integer manifest build>,
  "candidate": { "sha256": "<exact release-manifest sha256>" },
  "distribution": {
    "channel": "manual-install",
    "inAppUpdater": "disabled",
    "retainedState": "clean-install-only"
  },
  "allRequiredGatesPassed": true,
  "gates": { "<gate>": { "status": "passed", "evidenceSHA256": "<sha256>", "reference": "<bounded>" } }
}
```

`distribution` has exactly those three keys. `channel` must be `manual-install`
and `inAppUpdater` must be `disabled`; any other value, including a boolean or an
"enabled" declaration, fails. `retainedState` must be either
`clean-install-only` or `retained-state-migration-qualified`.

Required gate records, all with exactly `status`, `evidenceSHA256` and
`reference` and the same bounds as the stable contract:

- preserved from stable: `cleanInstallCurrentMacOS`, `cleanInstallMinimumMacOS`,
  `fullGitHistoryAndSecretScan`, `githubRepositoryControls`,
  `legalAndTrademarkClearance`, `permissionAndAccessibilityMatrix`,
  `supportPrivacyAndExportReview`;
- `manualInstallReinstallRecovery` — the documented manual download, checksum
  verification, first install, quit, same-version reinstall, and manual rollback
  to a retained previous app were exercised on the exact notarized candidate on a
  clean Mac, and the retained record identifies each step and its outcome;
- `inAppUpdaterDisabledInCandidate` — the exact candidate exposes no
  user-reachable updater entry point (no main-menu, status-item, Settings,
  context-menu or keyboard-shortcut action) and its retained
  `installVerifiedUpdate(_:)` selector is hard-disabled behind the reviewed
  `verifiedInAppUpdatesEnabled = false` guard, which only shows an
  "In-app updates are not available in this build" alert; the record identifies
  how the guard was checked on the exact commit (source contract and identity
  surface test), how the shipped bytes were bound to that commit (the
  watchdog-wrapped frozen-candidate check) and how the UI was traversed on the
  candidate. The selector's existence is a fact, not a finding; a string search
  of the binary proves nothing either way (`docs/BETA_DOWNLOAD_ACCEPTANCE.md`
  section 3);
- `thirdPartyBinaryLicenseMaterials` — the redistributed-binary licence
  obligations recorded in `Config/ThirdPartyBinaryProvenance.json` were reviewed
  for the exact shipped payload and either closed with retained material or
  explicitly accepted by the owner with legal review;
- `retainedStateMigrationAndRecovery` — required **only** when `retainedState`
  is `retained-state-migration-qualified`, and rejected when it is
  `clean-install-only`.

Missing, extra, deferred, planned, placeholder-digest, linked, non-private,
candidate-stale or cross-profile records fail closed, exactly as in the stable
contract. A `twoVersionNotarizedUpdateRollback` record inside beta evidence is
cross-profile evidence and fails.

## What the beta records do and do not prove

Manual replacement of the app by a person, followed by a manual rollback to a
retained copy, proves that the documented manual workflow works for that person
on that Mac. It does **not** prove automatic recovery, power-loss safety of any
updater transaction, or that the disabled in-app updater would behave correctly
if enabled. The stable contract keeps those claims behind
`twoVersionNotarizedUpdateRollback`; the beta contract makes no such claim and
release copy must not imply one.

`inAppUpdaterDisabledInCandidate` proves that the exact shipped bytes offer no
user-reachable updater entry point and carry the hard-disabled guard on the
retained selector. It is not a code-review substitute, does not qualify the
retained updater source, and does not claim the selector is absent.

## Beta release assets

The beta package is exactly twelve assets: the nine stable assets, unchanged,
plus the verified third-party material archive `<root>.tar`, its `sha256sum`
sidecar `<root>.tar.sha256` and its binding `<root>.binding.json`, where
`<root>` is the tracked provenance record's `outputDirectoryName`
(`sharp-libvips-1.3.3-delivery-materials` today) and never an operand. The
material files are the exact outputs of
`scripts/package-libvips-delivery-materials.mjs package` for the release's
source commit (`docs/LIBVIPS_CORRESPONDING_SOURCE.md`, "Delivery archive").
`SHA256SUMS.txt` lists the other eleven assets in C-locale byte order; the
stable list keeps its eight. The exact names and order come from one policy,
`scripts/public-release-asset-policy.mjs` (`names`/`checksum-names`), used by
the preparer and the verifier; arbitrary or unrelated files are refused, and
neither profile silently accepts the other's count.

Three explicit operands carry the material facts. `make public-beta-release`,
`make public-beta-release-finalize` and `make public-beta-assets` take
`BETA_MATERIAL_PACKAGE` (the private package directory), `BETA_MATERIAL_SHA256`
(the material archive digest) and `BETA_SOURCE_COMMIT` (this checkout's HEAD),
and pass them as `--material-package`, `--material-sha256` and `--source-commit`;
`make public-beta-distribution-verify` takes the last two. The operator validates
them before signing, building or verifying anything and forwards them verbatim
through its clean child invocations; they are refused under the stable profile,
are never read from the environment, and the `unexport`ed make variables reach
the scripts only as operands.

Trust roots: the expected material digest comes from the operator's
independently reviewed release record and the source commit from the operator's
trusted checkout. The sidecar, the checksum list and the binding that travel
beside the archive are payload to be checked, never the source of the expected
digest — whoever can replace the archive can replace them. Preparation and
verification snapshot the material files through attested descriptors, run the
existing `verify-archive` on those snapshots (never on an external path that
could be swapped afterwards) with the operand digest and commit, require the
checkout to be exactly that commit with no modified tracked file, and require
the binding to record HTTPS-authoritative acquisition for both material inputs;
fixture or non-authoritative material is refused for distribution, and only the
admitted snapshot bytes are copied into the package. The app candidate is bound
by SHA/version/build exactly as before, and the material digest may never equal
the candidate digest: they are different artefacts. The archive digest is not
committed to the source tree (that would bind an artefact to a commit that
embeds it); it belongs in the trusted release record. Verified material closes
no licensing, source-offer or relinking obligation
(`thirdPartyBinaryLicenseMaterials` stays an owner/legal gate).

## Retained state

Retained-state migration is unqualified. A beta evidence record must therefore
either declare `clean-install-only` or additionally close
`retainedStateMigrationAndRecovery` with real evidence. Under
`clean-install-only`:

- the beta is offered only for Macs with no prior Fulmar Application Support,
  Keychain items, or Harness backups, and the installation guide says so;
- nothing in this contract deletes, moves, quarantines or rewrites existing
  private state, and no tooling may "prepare" a clean install by doing so;
- existing users are **not** told they can upgrade safely; they are told the
  beta is not for their Mac until a migration path is qualified.

Whether the product itself should detect existing retained state and refuse to
start under the beta profile is a runtime decision outside this contract; the
policy here is implementable purely by documentation and owner process, and
Codex owns any runtime enforcement.

## Operator flow

1. Package the verified material set for this exact source commit
   (`scripts/package-libvips-delivery-materials.mjs package …`), record its
   archive SHA-256 in the reviewed release record, and keep the private package
   directory. This is source material, not an app.
2. `make public-beta-release BETA_MATERIAL_PACKAGE=… BETA_MATERIAL_SHA256=…
   BETA_SOURCE_COMMIT=…` with the same three Developer ID/notary variables as
   the stable operator. A fresh run, when those variables are configured, really
   does run the static scan, one signed and timestamped hardened-runtime build,
   the Apple notarization submission, stapling, retention and candidate
   verification, then pauses with its own exit 78 (shown by make as `Error 78`)
   and prints the immutable candidate identity and the beta gate list. Malformed
   or missing material operands stop it before any of that.
3. Complete the ten (or eleven) manual gates against that exact candidate.
   Create owner-private `build/public-beta-external-evidence.json`. Run
   `make public-beta-external-evidence-verify`.
4. `make public-beta-release-finalize` with the same material operands.
   Finalize never builds, re-signs, re-notarizes or changes the candidate; it
   revalidates the retained source inventory, archive, Apple records, signer,
   tree and stapled ticket, verifies the beta evidence for the exact
   SHA/version/build, creates the twelve-asset beta package if none is retained
   (admitting the material as described above) or revalidates a retained one,
   and runs the distribution verifier with `--profile beta --material-sha256 …
   --source-commit …`. A retained package whose material does not match the
   operands fails with that error; it is never silently rebuilt or replaced.
5. Nothing uploads, tags, releases, signs on its own or submits to Apple.

The success message names the profile ("Public BETA release qualification
passed …") and states that it is not stable qualification. Stable messages are
unchanged.

## Not covered by this contract

- Selecting a distinct beta version/build (release identity), updater or
  migration product code, entitlements, signing, CI, or repository settings.
- Any live provider, LM Studio, physical inference or thermal qualification.
- Legal clearance of redistributed third-party binaries; see
  `Config/ThirdPartyBinaryProvenance.json` for what is bound and what is open.
