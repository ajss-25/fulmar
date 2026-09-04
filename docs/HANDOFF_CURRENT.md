# Current qualification handoff

Updated: 2026-09-03 (Europe/London)

## Release decision and immutable identity

- Source identity: Fulmar `1.2.36` build `156`, Apple silicon, macOS `15.0` minimum.
- Runtime pin: Node `22.23.1`; DeepSeek Harness and MCP client `0.1.1-rc.1`.
- Intended release lane: MIT-licensed **source beta**, explicitly not a generally
  supported binary download.
- Installed `/Applications/Fulmar.app` remains Fulmar `1.2.16` build `136`. It stayed
  closed and was not replaced, modified, or used for this qualification.
- No build-156 candidate, Developer ID signature, notarisation ticket, or public
  binary archive existed when this source was frozen for the final gates.

## Release-triage corrections

- Bound provider consent to the exact authentication mode as well as provider,
  boundary, origin, and credential reference. Consent schemas 1 and 2 migrate by
  revoking ambiguous grants; schema 3 is current.
- Separated DSH's non-catalog `declared` flag from raw user-profile presence. Built-in
  OpenAI/Anthropic overrides now project their exact raw protocol/authentication;
  custom keyless routes fail closed; catalog-ID no-auth profiles cannot inherit a
  stored or ambient credential; Ollama authentication remains immutable.
- Added a deliberately narrow `unauthenticated: true` runtime path for literal
  loopback/RFC1918/IPv6-ULA endpoints. It rejects every custom header and credential
  reference, bypasses stored/ambient discovery, and emits no provider auth header for
  the three reviewed protocols.
- Made native custom-profile editing lossless by accepting only the exact simple
  profile/model shape Fulmar renders. Advanced or externally managed DSH profiles
  remain usable but must be edited in Harness settings.
- Closed the provider-profile transaction race: settings profile and revision are
  captured before a Keychain write, a concurrent edit produces a typed conflict, the
  concurrent profile is preserved, and a newly created credential is rolled back.
- Extended the reviewed Ollama descriptor seam to pin explicit-no-auth and native-
  editing flags. Forged variants fail before any service call.
- Made official Ollama discovery portable across `/Applications`, the authenticated
  account's `~/Applications`, and fixed Homebrew shims without trusting `HOME` or
  ambient `PATH`.
- Repaired clean runtime reconstruction. Thirteen exact before/after-hash-bound
  patches now include the pi-ai adapter, types, both READMEs, and all three protocol
  clients. After the later dependency remediations below, the regenerated
  VendorRuntime inventory contains 38,501 entries and 394,622,078 file bytes; its
  JSON SHA-256 is
  `c7fadd8654139a93429e09dbbf99739ed6868b2d99e68b186c248a59bb46d019`.
- Remediated the transitive `qs` advisories (GHSA-x5fp-wj9c-mxmx, GHSA-4mjr-xmp4-gh2g)
  by moving its single lock descriptor to registry `6.16.0` (evidence under ignored
  `build/release-triage/qs-6.16.0-*`); the production dependency audit then still
  reported the `fast-uri` finding remediated next.
- Remediated the transitive `fast-uri` advisory set (GHSA-f65p-4m7j-42xc,
  GHSA-fph4-wmhf-6fwf, GHSA-jqff-g426-hqxp, GHSA-5jgf-p345-68v8) by moving the single
  lock descriptor from `3.1.5` to registry `3.1.6` — no direct dependency, override,
  or audit waiver; `ajv` `8.20.0` (`^3.0.1`) remains its only dependent and `qs`
  stays at `6.16.0`. Reviewed lock SHA-256
  `408c97b76eb20998fc7fbf7b86d6ff901cab59061e5a72114ee429cdc4b8d6be`, derived
  install lock `db499d7c7398de70d339f5b4f628af648912c29e41c0fd17d044f9f7901e1f65`.
  The runtime was rebuilt only through the pinned materializer and the production
  dependency audit now reports zero findings; advisory probes, lock staging and
  reconstruction evidence live under ignored `build/release-triage/fast-uri-3.1.6-*`.
- Added the owner-selected MIT licence and strict digest-bound metadata for original
  Fulmar source. Third-party licence, icon/name, trademark, privacy, and export review
  remain separate gates.
- Aligned contributor, brand, pull-request, and clean-build guidance with that MIT
  selection; the source contract now rejects stale no-licence copy and requires the
  documented pinned Semgrep `1.135.0` prerequisite.
- Rebound the AppKit lifetime guard to the same 1,445-function topology as the frozen
  Swift plan after the first canonical run exposed its stale pre-auth-change count;
  every AppKit/actor subcount remained at its independently reviewed value.
- Rebound the provider-centre presentation regression to the current, more actionable
  endpoint guidance after the second canonical Swift run exposed its retired
  “normalized HTTPS endpoint” assertion. The regression now requires the HTTPS,
  literal local/private HTTP, and forbidden-URL-component guidance instead of merely
  accepting any changed text.

## Focused evidence completed before the final full gates

- All changed Swift sources and the complete test target compile warning-clean under
  Apple Swift 6.3.3 with the standalone Command Line Tools Testing framework paths.
- Custom-provider transaction selection: 12/12 passed, including concurrent-profile
  preservation and credential rollback.
- Provider/model/consent/Ollama-preflight selection: 86/86 passed across three suites,
  including deterministic 8/16/24/32/48/64/96 GiB policy branches.
- Focused JavaScript release/auth/licence/runner/vendor selections passed. The final
  vendor bootstrap selection is 10/10, including exact clean-anchor drift rejection.
- A genuinely empty dependency directory was materialized with pinned Node/npm and
  all thirteen patches; after the `fast-uri` remediation a second independent
  materialization reproduced the checked inventory exactly, and its 32,632-entry
  `node_modules` prefix (209,438,418 file bytes) was byte-identical to the tree in
  place.
- The read-only DSH watcher passed on 2026-09-04 after acknowledging the new upstream
  state: npm `latest`/`next` now point to observed-not-promoted `0.1.2-rc.1` (official
  prerelease 381777538, tag `dsh-v0.1.2-rc.1`, commit
  `a66e4702047846cdaa10c66c9d3df3951f5ea70d`, published 2026-09-03), `alpha` remains
  `0.1.2-alpha.5`, and every observed official GitHub tag/release plus the promoted
  `0.1.1-rc.1` provenance matched its acknowledgement. Fulmar stays pinned to
  `0.1.1-rc.1`; no DSH upgrade is part of this release.

## Frozen test topology

- JavaScript: 666 exact lifecycle tests, 641 top-level tests; expected source result
  619 passed plus 47 reviewed skips, and expected candidate result 620 passed plus
  46 reviewed skips.
- Swift: 1,445 exact function specifiers; sorted-specifier SHA-256
  `242833714f5486eb52adf376427c95f8f7c3a5e306b101bed0f3b29db2fc4dea`.

These are fail-closed ledgers, not passing results. The canonical full JavaScript and
Swift gates must execute after this source freeze. Any subsequent source, test,
dependency, build-policy, licence, or tracked-document change invalidates the freeze
and requires new topology plus full gates.

The public release branch supplies the eventual commit/tree identity. Each release
decision must separately retain its exact tracked-index proof, complete-history scans,
and hosted-CI evidence; this tracked handoff does not pre-claim those external results.

## DSH update and portability policy

Fulmar never hot-wraps the newest DSH package. A watcher may discover a release, and
the upgrade assessor may stage it under ignored `build/`, but promotion requires an
exact cohort review, reapplication or retirement of every patch, complete regression
qualification, a new Fulmar version/build, and whole-app rollback evidence. The
installed and vendored runtime remains `0.1.1-rc.1`; alpha.5 is observed, not promoted.

Cloud provider routes do not inherit local RAM or thermal policy. The exact qualified
`qwen3.8:27b-mlx` contract requires at least 48 GiB. Other safely named Ollama models
may use fixed Compatibility mode only after live tool/context/non-thinking metadata
and the conservative `2 × installed model bytes + 4 GiB` host-memory admission. Those
branches are deterministic policy coverage, not a claim that every model, endpoint,
or hardware tier has been physically qualified.

## Gates still open at source freeze

- Canonical full JavaScript and 1,445-function Swift suites against the final source.
  The `darwin-fix` cycle (2026-09-02, logs under `build/release-triage/`) passed the
  complete 615-test JavaScript gate and reached 1,299/1,445 Swift functions before
  `stopBarrierPreservesTheLatestExactInferenceOrRecoveryLaunchMode` failed. That test
  built its controller without an admitted private Application Support root, so under
  the isolated qualification home the `/tmp` alias failed root admission and
  `prepareAndStart` returned `.failed` before the stop generation could latch the
  replacement mode; production behaviour was the intended fail-closed contract. The
  test-only correction admits an exact private root like its sibling tests. Because a
  tracked test byte changed, the `darwin-fix` inventory was superseded; the source-only
  preview cycle authorised on 2026-09-02 re-froze the inventory and passed both
  complete gates (615 JavaScript tests, 1,445 Swift functions; the
  `source-preview-semgrep-final-*` logs). The subsequent `qs` `6.16.0` and `fast-uri`
  `3.1.6` remediations changed tracked lock, configuration, test and inventory bytes
  after those gates, so that freeze is superseded in turn; the `fast-uri` cycle
  re-freezes the inventory and repeats both complete gates, retaining all evidence
  under ignored `build/release-triage/` rather than in this document.
- Frozen candidate assembly, deterministic release verification, static scan,
  dependency audit, SBOM/notices, archive and source/candidate identity verification.
- Candidate-bound local Qwen/full-hardware, UI/menu-bar, permission/accessibility,
  install/rollback, and live-provider success testing.
- A clean public Git index/history, independent secret scans, hosted CI, repository
  controls, support contact, and third-party/legal/trademark review.
- Developer ID signing, notarisation/stapling, minimum/current clean Macs, and the
  two-version power-loss/update matrix required before any binary download.

No test suite proves zero defects. Claims must remain limited to retained evidence for
the exact immutable source and candidate identities.
