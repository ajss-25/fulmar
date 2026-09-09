# Current qualification handoff

Updated: 2026-09-09 (Europe/London)

## Release decision and immutable identity

- Source identity: Fulmar `1.2.36` build `156`, Apple silicon, macOS `15.0` minimum.
- Runtime pin: Node `22.23.1`; DeepSeek Harness and MCP client `0.1.1-rc.1`.
- Current reconstruction: fourteen hash-bound runtime patches; 38,501 VendorRuntime
  entries / 394,622,662 file bytes, plus the verified Rust notice-material cache.
- Intended release lane: MIT-licensed **source beta**, explicitly not a generally
  supported binary download.
- Installed `/Applications/Fulmar.app` is Fulmar `1.2.36` build `156`, built from
  `d40a1ee107743bdc29ff0b7ee04e16af6c5de59c` and signed with the existing stable local
  identity. It passed the bounded acceptance below. There is no Developer ID
  signature, notarisation ticket or qualified public binary download.

## Latest local acceptance

The retained private record `build/native-profile-stdin-fix-2026-09-09/ACCEPTANCE-STATUS.md`
binds these results to source `d40a1ee` (tree
`d18466f6af522e8ede151a3f9caeb9446aad830e`), before the source-publication documentation
updates:

- Complete Swift gate: 1,455/1,455 functions plus 12 attestation scenarios,
  warning-clean, deployment target 15.0.
- Complete candidate JavaScript gate: 902 tests, 856 passed, 46 intentional skips,
  zero failures. Static security scan: zero unreviewed findings.
- Frozen candidate and installed-candidate checks, bundled native profile preparation,
  runtime lease checks and the isolated DSH/RPC canary passed.
- Physical acceptance on the 48 GB Apple M5 Pro: native startup reached Ready;
  actual Qwen 3.8 27B MLX inference used Write and Read and returned the verified
  marker; normal quit drained the app's processes; relaunch reached Ready without
  a repeated Keychain or recovery prompt.

This closes the reproduced native profile-preparation failure on that Mac. The
single small task does not qualify sustained thermals, all tools, live cloud
providers, other hardware, physical macOS 15 support or future Keychain persistence
across rebuilds/locked states. The final public source commit needs its own clean
checkout, history/index and hosted-CI evidence; these local results do not pre-claim it.

## Earlier release-triage corrections

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
  VendorRuntime inventory at that stage contained 38,501 entries and 394,622,078 file bytes; its
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
- Replaced npm CLI's failing audit transport without changing the audited graph. The
  gate still derives production-only semantics from the npm 10.9.8-bundled Arborist,
  but posts bounded sorted package/version batches directly to npm's official Bulk
  Advisory route, recognises the registry's documented unlabelled-gzip response,
  validates every response and never uses the retired Quick Audit route. A current
  npm Bulk service outage can leave the first request open without response bytes, so
  a narrowly admitted secondary route now discards earlier zero-finding npm batches
  and restarts the complete graph against OSV QueryBatch only after one npm batch
  exhausts two retryable availability attempts. OSV is permitted only for canonical
  SHA-512-bound public npm tarballs; the route never follows an npm advisory, TLS or
  semantic failure and never mixes authorities. The summary binds graph,
  public-provenance, batch and response digests as well as the existing lock,
  registry, Node/npm and zero-finding identities.
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
- The DSH watcher records newer releases as observed, not promoted. Current
  acknowledgements and watch results are maintained in `docs/UPSTREAM_DSH_UPGRADES.md`.
  Fulmar stays pinned to `0.1.1-rc.1`; no DSH upgrade is part of this release.

## Frozen test topology

- JavaScript: 902 exact lifecycle tests, 690 top-level tests; expected source result
  855 passed plus 47 reviewed skips, and expected candidate result 856 passed plus
  46 reviewed skips.
- Swift: 1,455 exact function specifiers; sorted-specifier SHA-256
  `4971265b754b0f5a9ccecea1b40aecbff53417ded0d7896fc90e2102d552a605`
  (1,448 / `5787c3b14a…` plus the four startup Keychain-UX correction tests —
  missing-key verification without creation, the typed missing-key startup
  failure, the authorization advisory surviving the later catalog refresh, and
  one-attempt device-trust authorization with stale and post-shutdown callbacks
  — plus the three authorization-failure routing tests that drive AppDelegate's
  retry, recovery-folder and post-shutdown dialogs through the interaction
  seam). The independently built `DeviceAttestationAuthorityTests` executable
  target is 12 scenarios, whose interaction-policy scenario substitutes both the
  policy primitives and the wrapped operation and makes no Keychain call.

These are fail-closed ledger expectations. The local candidate results above passed
on `d40a1ee`; a later source, dependency, policy or documentation revision has a new
source identity and requires its own release evidence. Test additions or removals
also require an explicitly reviewed topology update.

The public release branch supplies the eventual commit/tree identity. Each release
decision must separately retain its exact tracked-index proof, complete-history scans,
and hosted-CI evidence; this tracked handoff does not pre-claim those external results.

## DSH update and portability policy

Fulmar never hot-wraps the newest DSH package. A watcher may discover a release, and
the upgrade assessor may stage it under ignored `build/`, but promotion requires an
exact cohort review, reapplication or retirement of every patch, complete regression
qualification, a new Fulmar version/build, and whole-app rollback evidence. The
installed and vendored runtime remains `0.1.1-rc.1`; newer observed releases and their
acknowledgements are listed in `docs/UPSTREAM_DSH_UPGRADES.md`.

Cloud provider routes do not inherit local RAM or thermal policy. The exact qualified
`qwen3.8:27b-mlx` contract requires at least 48 GiB. Other safely named Ollama models
may use fixed Compatibility mode only after live tool/context/non-thinking metadata
and the conservative `2 × installed model bytes + 4 GiB` host-memory admission. Those
branches are deterministic policy coverage, not a claim that every model, endpoint,
or hardware tier has been physically qualified.

## Gates still open for publication

- Source preview: final clean-checkout reconstruction/build, complete source gates,
  exact public index/history scans and hosted results on the public candidate.
  Preserve all five protected-main checks (`static-analysis`, `codeql-javascript`,
  `macos`, `minimum-macos-candidate`, `CodeQL`) and retain repository-control evidence.
- Binary distribution: remaining candidate-bound hardware, UI/menu-bar,
  permission/accessibility, clean-install and live-provider success matrices;
  Developer ID signing, notarisation/stapling and minimum/current clean Macs.
- The 29 libvips component notice entries and Rust notice cache are bound, while
  corresponding-source delivery, relinking and legal clearance remain open. See
  `docs/LIBVIPS_CORRESPONDING_SOURCE.md`.
- The stable binary profile additionally requires the two-version power-loss/update
  matrix. The separate manual-install beta profile requires its own recovery and
  updater-disabled evidence (`docs/PUBLIC_BETA_RELEASE_CONTRACT.md`).

No test suite proves zero defects. Claims must remain limited to retained evidence for
the exact immutable source and candidate identities.
