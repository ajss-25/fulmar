# Product specification — Fulmar 1.2.36 build 156

## Charter

- **Product:** Fulmar 1.2 for macOS.
- **Owner and public maintainer:** ajss-25.
- **Release class:** private-use candidate; public pipeline prepared but not cleared.
- **Purpose:** make DeepSeek Harness a dependable native desktop for both private
  local models and intentionally selected API/network providers while preserving a
  visible, enforceable data boundary.
- **Primary local target:** Ollama with `qwen3.8:27b-mlx` on a 48 GB Apple-silicon
  Mac.

Fulmar is independent. It is not an official DeepSeek, OpenAI, Anthropic,
Ollama, Alibaba, or Qwen product and does not claim proprietary-app feature parity.

## Product principles

1. “Local” is an enforced destination, not a label attached to a model.
2. A boundary change starts fresh; context never follows a model switch silently.
3. Provider, Workspace, Skills, MCP, and recovery decisions use typed identities and
   exact scopes rather than display strings.
4. Secrets are Keychain references; serialized settings are non-secret.
5. Untrusted code/data is inert, bounded, fingerprinted, and reviewed before use.
6. Tool and recovery actions are previewable, permissioned, and reversible where the
   filesystem permits.
7. Heavy resources start on demand and expose their cost.
8. Upstream DSH stays replaceable behind a small authenticated transport.
9. Test evidence is configuration-specific and never presented as proof of perfection.

## Users and journeys

- **Private worker:** selects Ollama/Qwen, sees **On this Mac**, and works without a
  DeepSeek API key or cloud-provider egress.
- **API user:** configures a DeepSeek, OpenAI, Anthropic, or compatible provider,
  confirms the exact origin and context categories, and gets a fresh task.
- **Harness power user:** uses upstream sessions, tools, permissions, traces, Skills,
  and local MCP inside one confined Workspace.
- **Quick Chat user:** presses `Option-Space`, chooses a route, streams a real DSH
  conversation, answers tool questions, copies the last reply, or exports safely.
- **History user:** searches a task, reads its bounded transcript, continues it after
  route verification, renames it, branches its latest completed state, archives it
  without deletion, or exports Markdown/JSON.
- **Operator:** reviews performance, model residency, schedules, trust, privacy,
  activity, logs, update state, Harness backups, and workspace checkpoints without
  using Terminal.

## Functional scope

### Harness shell and sessions

- Native main window, toolbar model picker, menus, shortcuts, restoration, zoom/find,
  readiness/error states, and authenticated non-persistent WebView.
- Real DSH-backed Quick Chat with text/image prompts, streaming, reasoning selection,
  tool/question approvals, cancellation, on-device dictation, speech synthesis, copy,
  and export.
- Native Task History with search, bounded transcript, continuation, rename, branch,
  archive, and privacy-aware export.
- Bounded automatic continuation after a foreground root turn reaches its provider
  output limit, with preserved completed work, user-input priority, explicit source
  labelling, and full reissue of any cut-off tool/edit request.
- One authoritative Workspace for every interactive and scheduled DSH session.
- Clear native **Chat** and **Agent Workspace** entry points, a searchable Command
  Center, plus intent-grouped General, Models, Privacy, and Advanced settings.
  Engineering names remain in diagnostics only.

### Providers and credentials

- Live DSH catalog for Ollama, DeepSeek, OpenAI, Anthropic, and configured compatible
  providers/models.
- Separate opaque provider/model identifiers; capability display does not infer
  support when DSH reports it as unknown.
- Transactional default selection across DSH settings, typed native preferences,
  origin consent, and Strict Local mode.
- On-device, local-network, and cloud classifications; unknown routes default cloud.
- Exact scheme/host/port allowlist; HTTPS required for non-local cloud endpoints;
  malformed/wildcard hosts and literal link-local, metadata, or multicast addresses
  rejected. Cloud hostnames retain normal HTTPS DNS/CDN behavior.
- Keychain credential CRUD and verified migration from the legacy DSH credential file.
- Provider credential activation returns to a zero-inference control plane. It never
  makes the provider/model the default or sends inference automatically; the user
  must select a model, review the exact boundary, and choose **Use for New Tasks**.
- If the selected Ollama prerequisite is missing, untrusted, changed, or not ready,
  launch a separately authenticated, zero-provider-origin repair control plane with
  only catalog/settings/credential administration. Keep prompts, sessions, history,
  schedules, Skills, MCP, and the Ollama readiness marker blocked until a repaired
  local or cloud route survives an exact-identity restart and topology verification.
- A missing selected local model exposes **Choose Installed Local Model** without
  opening task admission. The chooser never defaults to the first catalog row and
  never downloads or substitutes weights. Exact `qwen3.8:27b-mlx` receives the
  release-qualified Fast/Balanced/Deep and reasoning contract. Every other installed
  model is unqualified and requires bounded `/api/show` validation for completion,
  tools, no model-specific thinking, and context metadata between 8,192 and 1,048,576
  tokens plus physical-memory admission at twice its installed size plus a 4 GiB
  reserve before a fixed text/tool
  Compatibility route (8K context / 2K output) can be committed.
- Fresh main/Quick Chat sessions after provider or privacy-boundary changes.
- Current DeepSeek V4 Flash/Pro/Vision catalog, thinking-state replay, tool-call
  replay, and upstream search wire contracts are upgrade-gated against the pinned
  DSH runtime. Upstream DeepSeek-native search is disabled in this candidate even
  for a consented DeepSeek cloud route: conversation-provider consent never grants
  a separate search disclosure. `web_search` remains hidden until an independently
  configured search route and its consent, credential, cost, cancellation, and
  transport boundaries pass qualification.

### Trust, tools, and content

- Existing DSH plugin trust by complete descriptor-relative installed-content
  fingerprint, including built-in-name override detection; strict declaration/tree
  count, depth, path, per-file, aggregate-byte, and monotonic-deadline limits;
  no-follow rejection of links/special objects; and bounded private approval state.
- Pre-launch private DSH-home verification with an exact v3/privacy-epoch-1 receipt.
  Clean installs never probe `~/.dsh`; historical homes are preserved opaquely, and
  only an explicit settings-only decision may copy exact bounded no-follow
  `settings.json`/`settings.yaml` files under one monotonic deadline.
- Native Skills quarantine, bounded inert import, inspection, per-Workspace policy,
  changed-content revocation, read-only activation, and local-only/ask/allow external
  disclosure. Its trust database is a strict, owner-only, no-follow document capped at
  8 MiB; mutations publish only after a 0600 fsynced atomic replacement. Package,
  audit, and active-catalog scans stream through aggregate entry budgets and a
  monotonic deadline, including empty-directory floods.
- Native local-stdio MCP registration, explicit review/approval/revoke/remove,
  executable/interpreter/entry-point/config/project fingerprints, named credential
  references, provider-bound enablement, per-call native approval, and resource limits.
- Remote HTTP/SSE MCP intentionally unavailable in 1.2.36.
- Confined file tools with default-deny roots, traversal/symlink/hard-link protection,
  minimal child environments, and native-child network/private-store restrictions.
- Confirmed external-link handoff to the default browser, with no agent-control bridge,
  plus hostile-download staging for downloads initiated by Harness.

### Desktop workflows

- Activity Center, completion notifications, privacy ledger, diagnostics, redacted
  logs, and adaptive Performance Center. Activity history is an owner-only, no-follow,
  atomic local document capped at 500 rows and 4 MiB, with 512-byte titles and 16 KiB
  details; an unsafe, malformed, oversized, or unwritable store is shown as unavailable
  and no unpersisted mutation is published as saved.
  The privacy ledger likewise uses an exact owner-private directory chain and
  descriptor-relative 0600 file operations. First creation and bounded rotation fsync
  staged bytes, atomically rename by directory descriptor, prove the installed inode,
  and fsync the parent; a post-rename durability failure adopts the committed counts
  and fails closed until relaunch. Attachment retention deletes only after a 64 KiB
  no-follow ownership receipt is read against one stable inode and its exact migration
  schema/source inside the private app-owned Harness home.
- Fast 32K/4K, Balanced 48K/8K, and Deep 64K/16K local context/output profiles with
  bounded keep-alive for exact qualified `qwen3.8:27b-mlx`; other admitted Ollama
  models receive only fixed Compatibility 8K/2K. All local routes use one generation
  at a time and the same thermal admission policy.
- Local Models for installed/running state, size, memory, safe unload/default controls,
  and automatic first-use loading. Pull/delete stays in Ollama so this app never mutates
  the shared model library behind another Ollama client.
- Appshot review/crop/redaction/on-device OCR and safe attachment injection.
- Artifact preview, Finder reveal, annotations, comparison, and secure downloads.
- Local knowledge selection with explicit warning before external-model disclosure.
  Store construction is constant-time and never materializes or scans the library on
  the AppKit launch path. The first visible/useful request coalesces onto one serial
  utility-queue bootstrap with distinct idle/loading/ready/unavailable states and an
  explicit retry. Existing Roots, Objects, Recovery, and deferred Trash are inspected
  through owner-private, no-follow descriptor streams with fixed entry, raw-byte,
  filename, depth, decoded-text, chunk, posting, and monotonic-deadline budgets. A
  timeout/cancel/failure publishes no partial in-memory index. Deleted-item cleanup
  begins only after readiness, is independently bounded, and exposes a retryable issue
  without making the last trusted library unavailable.
  Create, edit, delete, and clear use one owner-private generation-bound mutation
  journal: prior catalog/object paths are durably evacuated, replacement paths and
  their parent directories are fsynced, and only then is a durable commit marker
  written. Relaunch rolls back every uncommitted journal and retains every committed
  journal; a fully validated later generation safely retires a historical committed
  journal left by interrupted cleanup. An in-process rollback ambiguity makes the
  store unavailable instead of publishing a false saved/failed state.
- One-time/recurring schedules, per-route unattended consent, optional background
  wake helper, common Workspace, and Task Inbox results. Inbox and occurrence-journal
  directories are inspected with streaming entry/deadline budgets; a read, topology,
  flood, or deadline failure is surfaced as unavailable rather than an empty Inbox.

### Continuity and recovery

- Bounded automatic workspace checkpoint before each new main task and Quick Chat
  turn; no-follow streaming traversal/copy under fixed path, count, byte, and monotonic
  deadline limits; manual named checkpoints; generated/secret exclusions.
- Preview-bound transactional restore with explicit modified/added-file decisions,
  integrity checks, and rollback.
- Separate secret-excluding DSH state backups, pre-runtime-upgrade snapshots, startup
  recovery, fail-closed bounded/private upgrade state, verified signed updates, and
  app rollback helper.
- Crash-consistent first-use DSH import through a durable private sibling transaction,
  strict receipt validation, atomic install, and bounded relaunch recovery.
- Pinned dependencies, CycloneDX SBOM, nested signatures, and release manifest.
- A default-deny auxiliary-capability broker contract keeps general web search, image
  generation, transcription, speech, and connectors on independent typed routes.
  A future cloud capability must have its own exact endpoint grant and Keychain
  reference; conversation-provider consent is structurally unavailable to that
  policy.
- Exact public HTTPS page retrieval is available through `web_fetch` without a cloud
  key. Every URL requires an approval, cannot redirect, cannot address IP/private/
  reserved hosts, is limited to text/HTML/JSON/XML and 2 MiB, and cannot fall back to
  Bash or another network path. `web_search` is hidden when no configured search
  provider can execute it.

## Non-goals for 1.2.36

- Recreating proprietary ChatGPT/Claude account sync, cloud memory, remote execution,
  realtime cloud voice, or every private desktop feature.
- Automatic migration of an active conversation between providers.
- Automatic screen, microphone, speech, notifications, login, scheduler, SSH-agent,
  Skill, MCP, plugin, site, network, or cloud consent.
- Remote HTTP/SSE MCP, agent-controlled browsing, or a generic shell-based MCP launcher.
- Enabling credentialed general search, image, audio, connector, or another separate
  cloud capability for a local Qwen conversation before its disclosure/consent UI,
  ledger record, cancellation, cost limits, and isolated transport have passed
  qualification. Approved key-free page retrieval is the bounded exception described
  above; the credentialed routes remain disabled.
- Claiming the Mac is offline when only the DSH/tool boundary is confined.
- Recovering excluded, generated, oversized, unsupported, or changed-during-scan files.
- Public binary distribution with an ad-hoc signature, unresolved libvips obligations,
  or unresolved formal name clearance.
- Claiming live cloud-provider validation without credentials or zero-defect software.

## Acceptance criteria

### Functional

- A clean launch from the Dock reaches Ready on a new random authenticated origin.
- Local Qwen completes a DSH task without DeepSeek onboarding or a cloud key.
- A local-Qwen task containing a public HTTPS URL can request an approved bounded page
  fetch without a DeepSeek key; denial/failure is reported and never retried by shell.
- DeepSeek/OpenAI/Anthropic and compatible catalog routes can be configured by
  reference, selected transactionally, and restricted to one exact origin.
- A provider/boundary switch cannot retain the old main or Quick Chat session.
- Main, Quick Chat, schedules, sandbox, Skills, MCP, and recovery resolve the same
  canonical Workspace.
- Task History rename/branch/archive/export and Quick Chat copy/export behave as
  documented; attachment bytes never enter exports.
- Changed Skill or MCP material loses approval; disallowed boundary combinations are
  withheld; every MCP tool call requires native approval and respects limits.
- Remote MCP cannot be configured or reached through the 1.2.36 adapter.
- Secure download staging rejects/flags disguised or mismatched content and does not
  silently overwrite a destination.
- Workspace restore requires a current preview, never overwrites symlink/type
  conflicts, and returns the original state after an injected mid-restore failure.
- Scheduled work executes from the authoritative Workspace and external unattended
  work cannot run without stored route-specific consent.

### Security and reliability

- Unauthenticated HTTP/WS, bad Host, wrong process identity, outside-origin
  navigation, non-consented provider egress, outside-Workspace filesystem access,
  native-child egress, and common private-store reads fail closed.
- API keys and MCP secret values do not appear in serializable provider/trust state,
  child-wide ambient environment, backups, manifests, or default exports.
- Legacy credentials are deleted only after Keychain read-back.
- App quit stops owned DSH and the exact app-owned Ollama PID, follows the model-unload
  preference, and never terminates an unrelated Ollama service.
- Upgrade failure can restore the prior app and DSH state; workspace restore has its
  own independent transactional rollback.

### Performance and evidence

- Balanced is the documented 48 GB default; preset settings reach request-level
  Ollama options and app-owned server configuration where applicable.
- Streaming remains cancellable and bounded; performance telemetry reports measured
  values rather than promises.
- All automated 1.2.36 tests, runtime/security canaries, simulated-provider contracts,
  the credential-free packaged DeepSeek/OpenAI Responses/Anthropic/custom protocol
  matrix, packaging checks, and the required manual matrix pass before private release.
- Credentialed live tests are required before a specific cloud provider is relied on,
  but are not a prerequisite for local-only private use.

## Release boundary

Build 156 is a candidate until the 1.2.36 checklist and evidence table are completed.
An MIT source preview may publish only after its final history/secret scans,
repository controls and hosted source workflows pass. The owner authorizes the Fulmar
name and current icon for that limited source-preview lane without claiming formal
trademark clearance. Public **binary** distribution is a separate gate requiring exact
libvips LGPL/GPL compliance, Developer ID/notarization, binary mark/privacy/export
review, clean-machine/minimum-OS testing, accessibility/permission exercises, and a
two-version notarized update rehearsal.
