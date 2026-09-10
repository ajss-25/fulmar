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

As observed on 2026-09-10T15:39Z, Fulmar remains pinned to reviewed `0.1.1-rc.1`,
including guarded MCP. The 0.1.5 line has since reached release candidates on the
default channels: npm `latest` now points to observed-but-not-promoted `0.1.5-rc.1`
(published 2026-09-10T03:12:53.293Z) and npm `next` to observed-but-not-promoted
`0.1.5-rc.2` (published 2026-09-10T14:57:10.790Z), while npm `alpha` still points to
observed-but-not-promoted `0.1.5-alpha.2`. Both replaced the previously acknowledged
`0.1.2-rc.1` on those two channels.

The corresponding official GitHub prereleases are `0.1.5-rc.1` (release 385978363,
tag `dsh-v0.1.5-rc.1`, commit
`183f08e9c6dde7e36cd2318eaee70b0da08fb35e`, published
2026-09-10T03:09:00Z) and `0.1.5-rc.2` (release 386391166,
tag `dsh-v0.1.5-rc.2`, commit
`fb2c4b9e698e30edb738bca4cf0618587db7d203`, published
2026-09-10T15:09:34Z). They follow the previously recorded `0.1.3-alpha.2`
(release 384129524, tag `dsh-v0.1.3-alpha.2`, commit
`82a5fd61a7cf5c293cec4bdff68f455398d685e9`, published
2026-09-07T13:59:29Z), `0.1.5-alpha.1` (release 384887562,
tag `dsh-v0.1.5-alpha.1`, commit
`5dda764ed3aa172535a7967b06ff95d9cbfe536a`, published
2026-09-08T16:16:04Z), and `0.1.5-alpha.2` (release 385585674,
tag `dsh-v0.1.5-alpha.2`, commit
`b2e3b2a0125854567a4a5fcba75782e42fe84901`, published
2026-09-09T14:23:10Z). The ledger records read-only npm metadata and official
GitHub release/tag observations; none of these cohorts has been staged, assessed,
promoted or shipped. The latest completed exact-cohort assessment remains the
separate `0.1.2-alpha.3` cohort, and the promotion record still identifies only
`0.1.1-rc.1`, whose official release and immutable tag were re-observed unchanged at
commit `528c682e061696f5a160f363f236ecbf53cbd006` in the same run. npm's `latest` tag
identifies its default package channel; a release candidate reaching it does not
establish stability, an end-of-life deadline for the pin, or Fulmar compatibility.

These observations retain the earlier `0.1.3-alpha.1` SessionHandle/session-lock
and Session format v2 boundaries. Upstream `0.1.3-alpha.2` reports reconnect and
long-session performance fixes; those statements do not establish compatibility
with Fulmar. `0.1.5-alpha.1` adds Session format V3 and breaking Agent/Inbox API
changes. V3 preserves the original logs when migrating supported history, but
upgraded sessions cannot be read by an older runtime. Rollback therefore requires
the retained pre-upgrade state snapshot and previous app; pointing the previous
app at V3 state is not a supported rollback. All cumulative boundaries below
remain prerequisites for a future exact-cohort assessment.

The `0.1.5-alpha.2` notes add file previews/delivery and detailed feedback, provider
Base URL validation and settings repair, repeated-cursor MCP pagination rejection,
and breaking Web panel/minimal-Profile changes. These are upstream change reports,
not proof of a vulnerability in Fulmar's guarded routes or proof that an upgrade is
safe. The checked official notes and public advisories did not identify a mandatory
migration or end-of-life deadline for the pin; that is not a security clearance.

`0.1.5-rc.1` promotes that cumulative alpha line to a release candidate rather than
introducing a separate migration path: its notes restate Session format V3 without
downgrade reads, the lifecycle-owned `SessionHandle` and per-Session lock, explicit
Agent passing with a type-only `Inbox`, changed SDK/Headless/ACP and minimal-Profile
tool defaults, and repeated-cursor MCP rejection, and add a `DeepSeek-V41-Flash`
adapter used by default for new Sessions, arbitrary Web uploads with Sidebar
previews and explicit file delivery, environment proxy variables honoured on all
outbound requests, dynamic system prompts gated on declared model support, and
feedback submissions that carry conversation content. `0.1.5-rc.2` adds only a
feedback confirmation dialog that retains entered text on failure and delivered-file
card presentation changes, and therefore inherits every `0.1.5-rc.1` boundary.
Reaching npm `latest` and `next` changes the channel these candidates occupy, not
their qualification state for Fulmar.

Official upstream records:

- [DeepSeek Harness releases](https://github.com/deepseek-ai/deepseek-harness/releases)
- [`dsh-v0.1.1-rc.2`](https://github.com/deepseek-ai/deepseek-harness/releases/tag/dsh-v0.1.1-rc.2)
- [`dsh-v0.1.2-alpha.1`](https://github.com/deepseek-ai/deepseek-harness/releases/tag/dsh-v0.1.2-alpha.1)
- [`dsh-v0.1.2-alpha.4`](https://github.com/deepseek-ai/deepseek-harness/releases/tag/dsh-v0.1.2-alpha.4)
- [`dsh-v0.1.2-alpha.5`](https://github.com/deepseek-ai/deepseek-harness/releases/tag/dsh-v0.1.2-alpha.5)
- [`dsh-v0.1.2-rc.1`](https://github.com/deepseek-ai/deepseek-harness/releases/tag/dsh-v0.1.2-rc.1)
- [`dsh-v0.1.3-alpha.1`](https://github.com/deepseek-ai/deepseek-harness/releases/tag/dsh-v0.1.3-alpha.1)
- [`dsh-v0.1.3-alpha.2`](https://github.com/deepseek-ai/deepseek-harness/releases/tag/dsh-v0.1.3-alpha.2)
- [`dsh-v0.1.5-alpha.1`](https://github.com/deepseek-ai/deepseek-harness/releases/tag/dsh-v0.1.5-alpha.1)
- [`dsh-v0.1.5-alpha.2`](https://github.com/deepseek-ai/deepseek-harness/releases/tag/dsh-v0.1.5-alpha.2)
- [`dsh-v0.1.5-rc.1`](https://github.com/deepseek-ai/deepseek-harness/releases/tag/dsh-v0.1.5-rc.1)
- [`dsh-v0.1.5-rc.2`](https://github.com/deepseek-ai/deepseek-harness/releases/tag/dsh-v0.1.5-rc.2)
- [npm DSH channel metadata](https://registry.npmjs.org/-/package/@deepseek-ai%2Fdsh/dist-tags)
- [DeepSeek Harness safety notice](https://github.com/deepseek-ai/deepseek-harness/blob/master/SAFETY.md)
- [Official public security advisories](https://github.com/deepseek-ai/deepseek-harness/security/advisories)

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
| `0.1.3-alpha.1` | Lifecycle-owned SessionHandle/session-lock API, Session format v2 migration, arbitrary file uploads, proxy/model-discovery changes and a known performance regression | Requalify handle and lock ownership, retained-state migration, attachment confinement/retention, exact-origin credentials and proxy behavior, provider discovery and long-session performance |
| `0.1.3-alpha.2` | Web reconnect and long-session performance fixes; continuable-subagent queue/Steer/Stop behavior and on-demand reads beyond a reference preview | Prove authenticated reconnect, bounded retries, ordering and single delivery, queue edit/send races, exact subagent cancellation, history authorization and measured long-session responsiveness/memory |
| `0.1.3-alpha.2` | Feedback can submit without continuing chat and includes relevant conversation content; upstream says ordinary chat does not trigger this reporting | Prove explicit consent, exact submitted content and endpoint, redaction and retention; prove ordinary chat does not report feedback and recheck the earlier package-metadata disclosure and optional Session-log upload controls |
| `0.1.3-alpha.2` | SDK/Headless/ACP default to read/write/edit; persona splits into prefix/suffix; ordinary subprocess handles lose pid | Requalify each shipped Profile's confined tools and guarded MCP, persona migration, lifecycle ownership and exact-child cleanup without relying on a removed handle field |
| `0.1.5-alpha.1` | Session format V3 creates new logs while preserving originals, records system prompts in history, migrates legacy PTC/code references, and does not support downgrade reads | Exercise custom readers, sanitized history/export and prompt disclosure, supported source-state migrations and interruption recovery; rehearse rollback using the previous app with a retained pre-upgrade snapshot, never by reading V3 with the old runtime |
| `0.1.5-alpha.1` | Agent must be passed explicitly after removal of ctx.agent; Inbox is a type-only interface accessed through agent.inbox, with hasPending/claim removed from public API; continuable-subagent ownership changes | Requalify every local plugin's Agent/Inbox calls, parent/child routing, pending-message ownership, queue/Steer/cancellation and root-only scheduling against the exact cohort |
| `0.1.5-alpha.1` | Dynamic system prompts require declared model support; Sidebar replaces Detail; absolute-path image rendering, paused-goal resume, project-root discovery and native fs-ext dependency behavior change | Requalify provider capability gating, Web/RPC/DOM and accessibility, path confinement including out-of-workspace images, user-owned goal resume, instruction-root errors, and the complete native dependency inventory/build |
| `0.1.5-alpha.2` | Sidebar previews and explicit file delivery, detailed feedback, custom-provider Base URL validation/settings repair, repeated-cursor MCP rejection preserving the last valid tool set, and fs-ext installation fixes | Requalify preview/open/reveal path confinement, consent and content redaction, exact-origin discovery and credentials, guarded MCP startup/resync/cancellation, and the complete native dependency inventory; reported fixes do not establish pinned exposure or promotion readiness |
| `0.1.5-alpha.2` | Web panels move to sidebar.panellist/main with conversation slots on main; webminimal/Python sdkminimal default to shell-only, editor tools need opt-in, persistent Bash reports exit/timeout, and experimental Agent Teams needs explicit Profile opt-in | Requalify local Web/RPC/DOM plugins, every shipped Profile's exact tools, subprocess termination, subagent guidance and opt-in boundaries while retaining all earlier V3, Agent/Inbox, privacy and rollback requirements |
| `0.1.5-rc.1` | A new `DeepSeek-V41-Flash` (`deepseek-flash`) adapter becomes the default model for new Sessions unless the configuration file names a model explicitly, and supports in-history system-prompt updates | Prove Fulmar's pinned V4 catalog, model selection and configured-model precedence are unchanged for new and restored Sessions; requalify text, image, thinking and tool replay against the exact adapter rather than assuming the previous default |
| `0.1.5-rc.1` | All outbound requests honour `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and `NO_PROXY` from the startup environment | Requalify Fulmar's egress policy and approved fetch-only surface under set, empty, malformed and conflicting proxy variables; prove no provider, telemetry or local-session request escapes the reviewed origin policy through an inherited proxy |
| `0.1.5-rc.1` | Dynamic system-prompt updates without invalidating KV cache when the configured model declares support | Prove capability gating cannot be asserted by an untrusted provider response, and requalify prompt disclosure in sanitized history, exports and support reports |
| `0.1.5-rc.2` | Feedback likes and dislikes are confirmed through a dialog and retain entered text when submission fails; delivered-file cards and conversation spacing change | Prove explicit consent per submission, the exact submitted content and endpoint, retention of failed drafts, and that ordinary chat still reports nothing; requalify delivered-file rendering and path confinement with the earlier feedback-content disclosure boundary |

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

For `0.1.2-alpha.5` or later, the cumulative matrix must exercise paginated session reads and
exports through `seq`/`eventAt()`/`snapshotEvents()`, parent/child `send_message`, queued
user work and automatic continuation, every Profile's exact `web_fetch`/`workflow`
exposure, exact-origin model-discovery headers, and retained-state upgrades from both
`0.1.1-rc.2` and `0.1.2-alpha.3` with startup and session-title integrity. For
`0.1.1-rc.2` or later, it must exercise actual Files API image upload/reuse rather
than infer compatibility from chat.

For `0.1.5-alpha.1`, also exercise the intervening SessionHandle/v2 boundaries,
reconnect and long-session fixes, feedback and metadata privacy controls, explicit
Agent/Inbox ownership, V3 readers and prompt history, and rollback from a preserved
pre-upgrade snapshot. Release-note observations alone do not satisfy those gates.

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
