# Public release readiness — Fulmar 1.2.36 build 156

**Decision for build 156 on 2026-09-03: candidate for an explicitly labelled public
MIT source beta; NO-GO for a public binary download.** Source publication still
requires the final clean-index/history/CI review described below. The repository must
not promise that strangers can safely install a downloadable app without the binary
gates below.

This is a release-control record, not legal advice and not a claim that passing every
automated test proves the absence of defects.

## Source repository gates

| Gate | Current evidence | Decision |
| --- | --- | --- |
| Explicit project licence | The owner selected MIT for original Fulmar source. Top-level `LICENSE` and strict `Config/ProjectLicense.json` bind exact SHA-256 `599a408a33e7d465ff51ce08f1b18c1799dae3e1af09694af999c85b519260dc`; the build/SBOM/public-asset policy rejects drift | Pass for first-party source terms. This does not relicense third-party material or replace legal advice |
| Clean checkout reconstruction | The 13 checksum-bound patches were independently materialized from the pinned npm tree on 2026-09-02 (repeated after the `fast-uri` `3.1.6` lock remediation) and the resulting 32,632-entry `node_modules` prefix matched the checked inventory byte-for-byte. The eventual public branch must repeat bootstrap, source gates, and build from its clean clone | Pass for local reconstruction; hosted clean-clone CI remains required before promoting the draft branch |
| Upstream DSH pin | The exact `0.1.1-rc.1` runtime is reviewed, promotion-provenance-bound and inventory-bound. The read-only watcher currently observes npm `latest`/`next` at observed-not-promoted `0.1.2-rc.1` (official prerelease 381777538, tag `dsh-v0.1.2-rc.1`, commit `a66e4702047846cdaa10c66c9d3df3951f5ea70d`, published 2026-09-03, the first 0.1.2 release candidate) and `alpha` at `0.1.2-alpha.5`; official alpha.5 release 381145530 binds tag `dsh-v0.1.2-alpha.5` to commit `db6bdc3576c2d4e7c965e8e3ed0c2a731eed87f5` and fixes upgrade startup/session-title loss from rc.2 or alpha.3. Neither rc.1 nor alpha.5 has completed an exact-cohort assessment. The corrected `0.1.2-alpha.3` assessment verified an exact 215-package first-party cohort and registry signature, but still found the changed guarded-MCP peer contract and upstream request-identifier behavior Fulmar removes; no later alpha has been promoted or silently assessed as equivalent. No installed or vendored files were changed | Keep `0.1.1-rc.1` for this candidate. Alpha.5 additionally requires retained-state migrations from both affected source versions plus startup and session-title integrity; every newer tag requires its own cumulative exact-cohort privacy/runtime/migration/provider/tool/rollback qualification and a whole new Fulmar release, never a package-only or installed-runtime update |
| CI | Workflow permissions are read-only by default; checkout credentials are not persisted; every GitHub-owned action is exact-SHA-pinned. The first-index gate runs before downloaded code. The source includes an active reviewed hosted image/Xcode/SDK/toolchain pin, hash-locked Python/Semgrep closure, two-root unsigned reproducibility, content-bound artifact transport, an exact macOS 15 consumer, and JavaScript/TypeScript-only CodeQL. See `docs/CI_SECURITY.md` | Implementation and focused tests exist. Exact-candidate promotion additionally requires all four `Verify source` jobs, the separate GitHub CodeQL app check, and `Check upstream DSH` to pass on the real repository. Those external results are retained as release evidence rather than pre-claimed by this file. CodeQL does not scan Swift |
| Repository size | Prospective source is about 22 MB after ignored products; no required source file approaches GitHub's 100 MiB ordinary-file limit | Pass for source layout; recheck the actual Git index before first push |
| Generated runtime | Node, `node_modules`, `.build`, and release products are ignored and must be reconstructed; they must never be added to ordinary Git history | Pass by policy; enforce in the first index and CI |
| Secret scan | Checksum-verified Gitleaks and TruffleHog scans of the existing public repository's reachable history found no secret, and the proposed source index has received a separate manual review | **Final evidence pending:** repeat both scanners after the candidate commit exists and cover every reachable branch and tag before publication |
| Third-party source materials | Exact package-path notices and licence overrides are generated and tested. The previously unresolved `@earendil-works/pi-ai` 0.82.1 entry is now bound to its upstream MIT terms, exact provenance and Fulmar modification record. The source repository does not contain the generated libvips binary payload | Pass for the source-preview licence inventory. A built app redistributes additional third-party binaries and has separate obligations below; this is not legal advice |
| Branding | Fulmar's independent-project disclosure exists. The owner authorizes the Fulmar name and current generated icon for this source preview without asserting originality, exclusivity, registration, affiliation, or formal trademark clearance | Owner-accepted source-preview risk. A formal legal opinion is not claimed, and binary/public-marketing review remains separate |
| Public contribution operations | Security, support, contribution guidance, issue forms, and a pull-request checklist exist. Private vulnerability reporting, secret scanning/push protection, Dependabot, GitHub-owned SHA-pinned Actions, protected `main` with four workflow contexts, and immutable `v*` tags are configured | Before release, require the exact hosted results, add the separate GitHub CodeQL app check without weakening the four workflow contexts, and retain final app-ID/source-revision binding, history rescans, collaborator/app/webhook review and settings evidence |

## Binary distribution gates

| Gate | Required evidence | Status |
| --- | --- | --- |
| Frozen candidate | Exact build 156 app and dSYM archives, byte counts, SHA-256 values, release manifest, source-input inventory, runtime inventory, SBOM, notices, dependency audit, and retained verifier log all identify one immutable artifact | Open |
| Apple trust | Every nested executable and the app use one Developer ID Application team, secure timestamp, and hardened runtime; helper identifiers and exact expected/empty entitlement sets are verified; Apple's machine-readable Accepted submission and matching issue-free log are retained; the ticket is stapled; Gatekeeper accepts online and offline | Open. The source verifier now enforces the artifact checks, but no Developer ID/notary/clean-Mac evidence exists for this candidate |
| Hardened-runtime exceptions | The bundled Node executable currently requests JIT, unsigned executable memory, and disabled library validation; all other helpers/native modules must carry no entitlement and the app must carry only its reviewed microphone/speech set | **Security-review gate:** exercise the Developer ID build with each Node exception removed independently, keep only demonstrated requirements, and explicitly accept any remaining exception before distribution |
| Clean installation | Download, archive expansion, first launch, quit/relaunch, uninstall/data-retention disclosure, and reinstall pass on a non-developer Mac | Open |
| Supported OS | Full pass on the declared minimum macOS 15 plus the current supported macOS release; every bundled Mach-O architecture and load-command minimum must remain at or below that declaration | Open |
| Upgrade/rollback | Implement a durable two-phase replacement whose exact new app returns nonce-bound identity and authenticated Harness health before commit; automatically roll back missing/invalid health and recover or safely surface every power-loss boundary; then exercise install, state migration, failure rollback, app rollback, and DSH-state rollback across two notarized builds from the same team | **Blocker.** Source now contains the journal/health/replay core and deterministic fault tests, but the interval after moving the old app and before placing the candidate has no reachable post-reboot in-bundle recovery process. A separately signed recovery authority/design plus two-version Developer ID/notarized/stapled clean-Mac and physical-power-loss evidence remain absent; the menu stays disabled |
| Permissions/accessibility | Allow and deny paths for Screen Recording, microphone, speech, notifications, login/background scheduling; keyboard, VoiceOver, contrast, Reduce Motion/Transparency, window sizes, and multiple displays | Open |
| Local route | Clean model-store pull of official `qwen3.8:27b-mlx`; official stable Ollama 0.33.2 through the 0.33.x series only (newer series fail closed until a later Fulmar qualification); exact manifest SHA-256 `5642e97495e1a088883805981563dcdc4a040c2f53388b7a41d1f24d3622cf7e`; fresh task on a 48 GB host; plus one separately labelled unqualified Compatibility-model admission/refusal matrix; tools, cancellation, continuation, missing/changed-model recovery, no-download behavior, thermal behavior, quit cleanup, and exact model/hardware evidence on the frozen artifact | Final-candidate evidence required |
| DeepSeek live route | Successful text, harmless tool, cancellation, authentication, quota/error, boundary switch, and secret non-leakage using a disposable funded test account | Open; a no-credit error is not a success-path qualification |
| Historical provider errors | A bounded atomic pre-start migration/quarantine must prevent pre-bridge raw provider errors/request IDs from entering active history, backup, restore, export, or support flows; every interruption boundary must preserve either the exact old private state or the complete sanitized/quarantined state | **Blocker for retained-state upgrades.** Bridge 1.2.1 prevents new raw error persistence, sanitizes successful and failed ordinary/subagent history at the Host API and browser, guards an already-in-flight older-page prepend, and clears/reloads an already-open pre-bridge window. Native transcript export ignores failure events, raw Harness-log export is disabled, and support reports do not read sessions. It does not rewrite old files; build 156 public qualification is therefore clean-install-only |
| Other providers | Per-provider live qualification before claiming support; fixtures establish protocol shape only | Open for every claimed live route |
| Third-party binary obligations | A downloadable app includes `@img/sharp-libvips-darwin-arm64`/libvips binary material whose LGPL/GPL notice, corresponding-source and relinking obligations must be satisfied for the exact shipped payload | **NO-GO.** The source inventory records the package and its upstream manifest, but the current binary package does not yet include the complete reviewed licence/source/relink material required for distribution |
| Support/privacy/legal | Public privacy notice, support scope, private vulnerability contact, first-party terms, source third-party inventory, accepted known limitations, Apple privacy-manifest scope, encryption/export-compliance review, and binary name/icon/third-party decisions | Source-facing support and security paths exist. Binary-specific legal, privacy-manifest/export and formal mark review remain open |

The separate `make private-install-qualified` coordinator is intentionally outside the
distributed app and can safely atomically replace two bundles signed by this Mac's
persistent private identity. That improves this owner's local update workflow; it does
include a durable pre-swap journal and explicit local resume/finalize/cancel/retire
operations, but it does not provide Developer ID trust, notarization, a clean-Mac
installer, a remotely recoverable public updater, or evidence for any public
binary-distribution row above. Cancelled/retired bundles and records are archived, not
deleted, and remain an owner-managed disk-retention responsibility.

## Clean-Mac acceptance matrix

The private extracted-layout verifier is not a clean-user installation test. Before a
binary is published, record all of these against the exact final archive on a Mac that
has no source checkout, Xcode/Swift toolchain, Fulmar Keychain items, prior Fulmar
Application Support, local signing certificate, or reconstructed VendorRuntime:

1. Download the immutable release asset normally so quarantine remains intact; verify
   the sidecar checksum, expand it using the documented user flow, and reject any
   archive or Gatekeeper warning that requires `xattr`, control-click, or a security
   bypass.
2. Launch once online and once with the network unavailable. The offline run must
   prove the stapled ticket is usable, not merely that Gatekeeper found Apple's online
   ticket. Record `stapler validate`, `spctl` assessment, signer team, version/build,
   archive SHA-256, and the Apple submission/log evidence.
3. Exercise a standard non-developer user, first-run empty state, missing Ollama,
   supported official Ollama/model, compatible-model refusal/admission, DeepSeek
   credential absent/invalid/quota/success, and local-to-cloud-to-local boundary
   transitions without any development files or inherited configuration.
   Prove the source Mac contains no prior Fulmar Application Support or backups; a
   cloned/restored DSH home is an upgrade test and cannot count as clean installation.
4. Deny and then separately allow microphone, speech, Screen Recording,
   notifications, launch-at-login, and background schedules. Quit/relaunch and
   log out/in; unrelated features must remain usable after every denial.
5. Quit and verify every app-owned DSH/Ollama/helper process exits. Disable both
   service registrations in the UI, remove the app, log out/in, and prove no Fulmar
   process relaunches. Confirm the documented retained data and Keychain items remain
   until the user deliberately removes them, while shared `~/.ollama` remains intact.
6. Reinstall the same version with retained state, then perform the supported update
   and rollback matrix using two same-team notarized versions. A fresh-state reinstall
   and a retained-state reinstall are separate cases.

Repeat the first-launch/core-task/quit checks on the declared minimum macOS 15 and the
current supported macOS release. A rebuilt app for the second Mac does not count; both
machines must consume the same manifest-bound archive.

## Required GitHub settings

These controls are outside the source tree. The repository now has private
vulnerability reporting, secret scanning and push protection, Dependabot alerts and
automated security updates, read-only workflow defaults, GitHub-owned SHA-pinned
Actions only, protected `main` with the four source-workflow contexts required, and
immutable `v*` tags. Retain screenshots or an exported settings record before source
publication. Still review every collaborator, deploy key, environment secret, webhook,
GitHub App and ruleset identifier, and retain the first real hosted results.

- protect the default branch; require pull-request review and passing source CI;
- restrict Actions permissions to read by default and approve any future write scope
  per job;
- keep secret scanning/push protection, Dependabot alerts, JavaScript/TypeScript
  CodeQL results, and private vulnerability reporting enabled; do not describe Swift
  as CodeQL-scanned;
- prevent force pushes and deletion of the protected release branch;
- use immutable release tags and never replace an asset under an existing version;
- publish a verified private security contact and issue-moderation path;
- review every collaborator, deploy key, environment secret, webhook, and installed
  GitHub App before the source preview is tagged.

## Required release assets

A public **binary** release must be a GitHub **draft** until the exact release verifier
and manual gates pass. The final binary release should contain:

- `Fulmar.app.zip`, Developer ID signed, notarized, and stapled before the final
  archive is created, plus the ordinary-user `Fulmar.app.zip.sha256` sidecar;
- `LICENSE`, matching the exact source and signed-app bytes;
- `SHA256SUMS.txt` covering the other eight assets in the exact nine-asset release
  package;
- the exact manifest-bound `static-security-summary.json`, whose complete path/size/
  SHA-256 coverage must match the frozen source-input inventory;
- the app's artifact-derived SBOM and generated notice-material inventory (neither is
  legal clearance);
- concise release notes, supported macOS/architecture, known limitations, update and
  rollback instructions, and the qualification-evidence record;
- source generated by GitHub from the same immutable tag.

The private release record must also retain `notarization-submission.json` and
`notarization-log.json` from Apple. They are qualification evidence rather than
ordinary download assets: the submission must be `Accepted`, both records must name
the same job UUID, and the completed log must contain no unresolved issue. Review the
records for personal/account metadata before deciding whether to publish them.

The final private review directory must also contain owner-private
`build/public-external-evidence.json`. It is not a download asset and the tooling does
not generate it. Its strict v1 record binds the exact release-manifest SHA-256,
version, and build, sets `allRequiredGatesPassed` only after review, and contains
exactly these eight gate records:

- `cleanInstallCurrentMacOS`
- `cleanInstallMinimumMacOS`
- `fullGitHistoryAndSecretScan`
- `githubRepositoryControls`
- `legalAndTrademarkClearance`
- `permissionAndAccessibilityMatrix`
- `supportPrivacyAndExportReview`
- `twoVersionNotarizedUpdateRollback`

Each gate record has exactly `status: "passed"`, the lowercase SHA-256 of its retained
evidence, and a bounded non-secret `reference` identifying where that evidence is
held. Missing, deferred, placeholder, malformed, linked, non-private, or candidate-
stale records fail closed. Run `make public-external-evidence-verify` after recording
the real results. `make public-distribution-verify` independently repeats this check
against the manifest inside the reviewed package before emitting its success marker.
Passing this structural check proves record completeness and candidate binding; it
does not prove that a reference is truthful, replace human/legal review, or authorize
publication.

## Fail-closed public-release operator

`make public-release` is the only build-producing public operator path. It requires
the exact `LOCAL_HARNESS_SIGN_IDENTITY` Developer ID Application common name, an
explicit owner-controlled `LOCAL_HARNESS_SIGNING_KEYCHAIN`, and a
`LOCAL_HARNESS_NOTARY_PROFILE`. It forces `LOCAL_HARNESS_SIGN_TIMESTAMP=1`, runs the
static scan, builds once, submits that archive to Apple, retains and validates the
Accepted receipt and issue-free log, staples the app, regenerates the ZIP, runs the
full-hardware candidate verifier, and retains its candidate-specific evidence.

The operator then validates both the app and the app inside the regenerated ZIP as
the same timestamped, hardened-runtime, stapled Developer ID candidate. If the eight
manual external gates are not yet recorded for that exact manifest SHA/version/build,
it exits non-successfully and prints the immutable candidate identity. Complete those
tests without rebuilding, create the owner-private
`build/public-external-evidence.json`, and run `make public-release-finalize` with the
same three signing variables. Finalization revalidates the retained source inventory,
archive, full-hardware evidence, Apple records, signer, app tree, and stapled ticket;
it never builds. Only then does it create (or revalidate) the nine-asset directory and
run `make public-distribution-verify`'s underlying verifier. Neither target uploads,
creates a GitHub release, or authorizes publication.

The website should link to the versioned GitHub release page or serve byte-identical
assets over HTTPS with the same published SHA-256. It must not host a separately built
copy, a mutable “latest” binary without a visible version, or instructions to bypass
Gatekeeper with `xattr`, control-click workarounds, or disabled security checks.

## Pre-publication history and index audit

Run these checks only after the real Git repository exists and before the first public
push:

1. Inspect `git status --ignored` and `git ls-files`; generated runtimes, builds,
   archives, logs, recovered duplicates, local editor state, certificates, and secret
   files must not be tracked.
2. Reject every tracked blob larger than 100 MiB and review unusually large binaries,
   archives, databases, images, and generated JSON.
3. Run at least two independent secret scanners over the complete history, then
   manually review provider-key, authorization-header, certificate/private-key,
   personal-path, email, and endpoint matches. Fake security fixtures must be exact,
   documented exceptions rather than broad path exclusions.
4. Review commit authors, messages, branches, tags, issues, pull requests, release
   assets, and deleted-file history for credentials or private workspace content.
5. Build from a fresh clone with no pre-existing VendorRuntime, Keychain item, app
   support state, or local signing identity; compare the reconstructed inventory and
   rerun all source tests.

If an actual secret ever entered history, revoke it first. Rewriting history without
revocation is not remediation.

## Go/no-go rule

Public source reuse is **GO** only after the source-licence, clean-checkout, final-
history scan, hosted-CI, and repository-control rows are closed. Public binary distribution is
**GO** only when every binary row is closed against the same immutable archive and no
unaccepted critical/high security or data-loss issue remains. Any artifact rebuild,
runtime patch, signer change, entitlement change, minimum-OS change, or provider
transport change reopens the affected gates.
