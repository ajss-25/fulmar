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
- `inAppUpdaterDisabledInCandidate` — the exact candidate exposes no updater
  menu item, automation entry point, or programmatic selector, and the record
  identifies how that was checked on the shipped bytes;
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

`inAppUpdaterDisabledInCandidate` proves absence of an entry point in the exact
shipped bytes. It is not a code-review substitute and does not qualify the
retained updater source.

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

1. `make public-beta-release` with the same three Developer ID/notary variables
   as the stable operator. It runs the identical static scan, single signed and
   notarized build, retention and candidate verification, then pauses with exit
   78 and prints the immutable candidate identity and the beta gate list.
2. Complete the ten (or eleven) manual gates against that exact candidate.
   Create owner-private `build/public-beta-external-evidence.json`. Run
   `make public-beta-external-evidence-verify`.
3. `make public-beta-release-finalize`. Finalize never builds; it revalidates the
   retained source inventory, archive, Apple records, signer, tree and stapled
   ticket, verifies the beta evidence for the exact SHA/version/build, creates
   or revalidates the unchanged nine-asset package, and runs the distribution
   verifier with `--profile beta`.
4. Nothing uploads, tags, releases, signs on its own or submits to Apple.

The success message names the profile ("Public BETA release qualification
passed …") and states that it is not stable qualification. Stable messages are
unchanged.

## Not covered by this contract

- Selecting a distinct beta version/build (release identity), updater or
  migration product code, entitlements, signing, CI, or repository settings.
- Any live provider, LM Studio, physical inference or thermal qualification.
- Legal clearance of redistributed third-party binaries; see
  `Config/ThirdPartyBinaryProvenance.json` for what is bound and what is open.
