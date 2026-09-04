# Upstream DeepSeek Harness upgrades

Fulmar does not hot-swap DeepSeek Harness inside a working installation. DSH is
part of the signed, inventoried application runtime, so every upstream change is
delivered as a complete Fulmar release with deterministic rollback.

The daily read-only GitHub workflow independently checks npm's `latest`, `next`, and
`alpha` channels and the first bounded page of official GitHub releases and tags
against `Config/DSHUpstreamAcknowledgements.json`. A GitHub-only release or tag is
therefore visible even while every npm dist-tag is unchanged, and every newly observed
version requires an explicit tracked disposition before the job can pass. The watcher
also re-observes the exact official GitHub release and immutable tag named by
`Config/DSHPromotionProvenance.json`, including the full commit and exact UTF-8
release-note body digest. Discovery never promotes a version: a changed npm tag,
unacknowledged GitHub version, promoted tag target, or promoted release-note body
fails the observation job. The watcher never edits the runtime pin, opens a pull
request, or publishes an app.

As observed on 2026-09-04, Fulmar remains pinned to reviewed `0.1.1-rc.1`;
npm `latest`/`next` advanced on 2026-09-03 to observed-but-not-promoted
`0.1.2-rc.1`, the first 0.1.2 release candidate (official GitHub prerelease
381777538, tag `dsh-v0.1.2-rc.1`, commit
`a66e4702047846cdaa10c66c9d3df3951f5ea70d`), which cumulates the alpha-series
changes since `0.1.1-rc.2` and has not been staged or assessed; npm `alpha`
advanced on 2026-09-02 to observed-but-not-promoted `0.1.2-alpha.5`. Its official GitHub release was subsequently published on
2026-09-02 at commit `db6bdc3576c2d4e7c965e8e3ed0c2a731eed87f5` and fixes an
upgrade bug that could prevent startup or remove session titles from the list when
upgrading from `0.1.1-rc.2` or `0.1.2-alpha.3`. Fulmar records that upstream fact but
has not staged or assessed the exact alpha.5 cohort, and it makes no compatibility or
promotion inference. The latest completed exact-cohort assessment remains the separate
`0.1.2-alpha.3` cohort. A dist-tag or GitHub-release observation is deliberately not a
compatibility claim. GitHub marks every current DSH release, including
`0.1.2-rc.1`, as a prerelease; npm's `latest` tag therefore identifies its default
package channel, not a stable Fulmar dependency.

Official upstream records:

- [DeepSeek Harness releases](https://github.com/deepseek-ai/deepseek-harness/releases)
- [`dsh-v0.1.1-rc.2`](https://github.com/deepseek-ai/deepseek-harness/releases/tag/dsh-v0.1.1-rc.2)
- [`dsh-v0.1.2-alpha.1`](https://github.com/deepseek-ai/deepseek-harness/releases/tag/dsh-v0.1.2-alpha.1)
- [`dsh-v0.1.2-alpha.4`](https://github.com/deepseek-ai/deepseek-harness/releases/tag/dsh-v0.1.2-alpha.4)
- [`dsh-v0.1.2-alpha.5`](https://github.com/deepseek-ai/deepseek-harness/releases/tag/dsh-v0.1.2-alpha.5)
- [`dsh-v0.1.2-rc.1`](https://github.com/deepseek-ai/deepseek-harness/releases/tag/dsh-v0.1.2-rc.1)
- [DeepSeek Harness safety notice](https://github.com/deepseek-ai/deepseek-harness/blob/main/SAFETY.md)

The upstream safety notice describes Harness as experimental developer-preview
software that has not undergone a security audit. Fulmar's qualification and sandbox
controls reduce specific reviewed risks; they do not turn an upstream prerelease into
production-ready software or guarantee isolation.

## Known compatibility breakpoints

The `0.1.1-rc.2` release changes DeepSeek image handling to prefer the Files API,
reuse uploaded files, and perform model-specific image preprocessing. A promotion must
therefore requalify provider endpoint and credential isolation, upload and reuse
lifecycle, attachment retention and redaction, cancellation, error handling, gateways,
and the no-credit and funded DeepSeek paths. A text-only provider fixture is not proof
of that image-upload path.

The alpha line is cumulative. Qualifying only the latest release-note delta is not
enough; every earlier alpha boundary remains in the promotion matrix:

| First introduced | Upstream boundary that must not be skipped | Required Fulmar evidence |
| --- | --- | --- |
| `0.1.2-alpha.1` | Official DeepSeek requests include enabled plugin package names and versions by default, with a setting to disable the disclosure | Prove the shipped setting is off unless separately consented; inspect text, image, tool, retry, subagent and continuation requests; prove package metadata does not enter history, logs, support reports or unrelated providers |
| `0.1.2-alpha.1` | Optional incremental Session-log upload was added to official DeepSeek requests and defaults off | Prove it stays off in empty, imported, restored and cloned homes and cannot be enabled by profile/default drift; if ever offered, require separate explicit consent, redaction, retention and revocation evidence |
| `0.1.2-alpha.1` | Plugins can add provider-login configuration | Requalify Keychain references, login callbacks, cancellation, credential replacement/removal, provider switching, sanitized errors and the rule that verification never silently selects a cloud route |
| `0.1.2-alpha.1` | Network Web UI access requires a one-time token in the launch URL | Prove the token is single-use, bounded and stripped from browser history, logs, diagnostics, navigation, referrers and external URLs; requalify launch, reconnect and stale-token failure |
| `0.1.2-alpha.1` | Legacy ApiProxy was removed in favor of `@Remote`, and all applications start through Profiles | Requalify the authenticated preloader, Web/RPC bridge, Headless/ACP/SDK/profile startup, local plugin composition, cancellation and exact-child shutdown |
| `0.1.2-alpha.1` | Public `WebFetch` became default and does not request approval for each public request | Prove every shipped Profile exposes only Fulmar's approved-fetch composition and exact egress policy; exercise DNS rebinding, redirects, credentials, private/link-local addresses, content limits, cancellation and denial without a Bash fallback |
| `0.1.2-alpha.2` | Connection retry/UI state, Remote gateway errors, web-search endpoint diagnostics and Session-event behavior changed | Requalify reconnect identity, retry bounds, provider-error/request-ID redaction, disabled search, event replay/export and long-session ordering |
| `0.1.2-alpha.3` | The optional SQLite Session backend was removed | Exercise empty, JSON-log, imported, restored and cloned state before any retained-state migration claim; refuse an unsupported old backend without destroying it |
| `0.1.2-alpha.4` | Parent and continuable child Agents use bidirectional `send_message` instead of one-way `report` | Requalify subagent delivery, queued user work, cancellation, automatic continuation, exact parent/child routing and durable history |
| `0.1.2-alpha.4` | `Session.events` is replaced by `seq`, `eventAt()`, and `snapshotEvents()`, with distinct sequence/offset types | Requalify pagination, live prepend/append, exports, compaction, recovery, sanitized history and cloned-state reads without offset confusion |
| `0.1.2-alpha.4` | Profile tool defaults changed; custom-model discovery reuses Profile request headers; long-session UI/navigation changed | Requalify exact `web_fetch`/`workflow` exposure per Profile, prove discovery sends no credential or unrelated header to a different origin, and rerun Web/RPC/DOM, accessibility and long-history performance gates |
| `0.1.2-alpha.5` | Upgrading from `0.1.1-rc.2` or `0.1.2-alpha.3` could prevent the app from starting or make session titles disappear from the list | Requalify both named source-version migrations with retained and empty state; prove startup, session-title preservation/recovery, list ordering, restart, interruption safety and rollback before treating the fix as compatible |

These changes touch privacy, network egress, authentication, provider discovery,
continuation and subagent behavior, history/security bridges, export and cloned-state
paths, tool allowlists, and Web/RPC/DOM compatibility. Promotion must exercise every
row against the exact staged cohort.

## Prepare, never overwrite

Run:

```sh
VendorRuntime/node-v22.23.1-darwin-arm64/bin/node \
  scripts/prepare-dsh-upgrade.mjs <exact-version>
```

The command resolves the exact registry version with lifecycle scripts disabled,
requires every first-party DSH package to use that exact version, verifies the root
tarball metadata signature against the reviewed npm key, records registry and lockfile
integrity, inventories every first-party package tree, compares dependencies and
sensitive DSH files, checks Fulmar's guarded-MCP peer contract, scans for the DeepSeek
stable identifier/session headers removed by the privacy patch, and runs an npm audit.
It atomically publishes one immutable observation under
`build/dsh-upgrades/<version>/<lock-sha256>/<observation-sha256>/`.

It never changes `VendorRuntime`, the release pin, or the installed application.

Registry staging is only the first input to review. Before promotion, separately bind
the exact immutable official GitHub release tag and commit, capture a digest of the
release notes reviewed at that time, and reconcile them with the exact signed npm
artifact. Release notes can be edited after publication, and npm metadata for a package
may not expose a Git commit, so neither channel alone proves source-to-artifact
correspondence. The recorded commit and release-note digest must remain part of the
versioned review evidence; a changed tag, artifact, note digest, or cohort starts a new
assessment.

`Config/DSHPromotionProvenance.json` is the tracked promotion authority for the DSH
runtime that Fulmar actually ships. Its schema binds the release pin, root npm tarball
and SHA-512 integrity, the complete exact-version first-party cohort and lock digest,
the official `dsh-v<version>` tag, full 40-character commit, release URL, and exact
GitHub release-body byte count/SHA-256. It currently records only the promoted
`0.1.1-rc.1` runtime; an observation or staging report for `rc.2`/`alpha.*` is not a
promotion record. Run the local fail-closed gate with:

```sh
make dsh-promotion-provenance-verify
```

Pull requests and pushes run that local validation without trusting the network. The
separate daily observer performs bounded, redirect-denying requests only to the exact
npm resource and official GitHub release/tag indexes in the tracked acknowledgement,
then separately reads the promoted release/tag resources in the provenance record.
It refuses pagination rather than silently observing only part of an upstream index.
Release-note text is mutable even when GitHub calls a release immutable, so
note-digest drift deliberately reopens review rather than silently changing historical
evidence.

## Promotion gates

Promotion is a reviewed source change, not a package-manager update:

1. Review the generated source/dependency report and the upstream release notes; bind
   the official immutable release tag and exact commit plus the reviewed note digest
   in `Config/DSHPromotionProvenance.json`. Never copy a later release's values into
   that record before the complete cohort has actually passed every gate below.
2. Reapply or deliberately retire every entry in `VENDORED_PATCHES.md`; prove the
   stable anonymous ID and internal session headers remain absent.
3. Update the exact DSH dependency in `VendorRuntime/package.json`, produce a clean
   lockfile with lifecycle scripts disabled, and inspect every dependency change.
4. Update local plugin compatibility metadata only after its APIs are reviewed.
5. Regenerate `VendorRuntime.inventory.json`, third-party notices, dependency audit,
   runtime inventories, SBOM, and the centralized `Config/ReleaseIdentity.json` pin.
6. Build a new app version. Never reuse a build number or mutate a released archive.
7. Run the complete release verifier, real local-Qwen generation, provider protocol
   matrix, DSH Web/RPC and tool canaries, realistic multi-file build, empty-state and
   cloned-state migration, cancellation, sandbox, credential and rollback tests.
8. Install only the signed/notarized whole-app candidate. Keep the previous app and
   pre-upgrade state snapshot until authenticated readiness and a rollback rehearsal.

For `0.1.2-alpha.5`, the cumulative matrix must exercise paginated session reads and
exports through `seq`/`eventAt()`/`snapshotEvents()`, parent/child `send_message`, queued
user work and automatic continuation, every Profile's exact `web_fetch`/`workflow`
exposure, exact-origin model-discovery headers, and retained-state upgrades from both
`0.1.1-rc.2` and `0.1.2-alpha.3` with startup and session-title integrity. For
`0.1.1-rc.2` or later, it must exercise actual Files API image upload/reuse rather
than infer compatibility from chat.

## Release channels

- **Stable:** only fully qualified, signed and notarized whole-app releases.
- **Beta:** the same security gates, plus new DSH/runtime canaries before promotion.
- **Development:** local candidates and reports; never offered by the updater.

The app's existing runtime migration and rollback machinery remains the last line of
defence. An upstream DSH version is never considered compatible merely because it
starts or renders its web page. Fulmar never updates DSH inside an installed app: the
only supported delivery is a new versioned Fulmar build whose complete runtime,
signature, inventories and qualification evidence are rolled out together, with the
previous version and state snapshot retained for tested rollback.
