# Test plan and release evidence — Fulmar 1.2.36 build 156

## Evidence rule

This document distinguishes **planned coverage** from **executed evidence**. A test
name, source file, or command is not a pass. Record the date, OS/hardware, exact app,
Node/DSH/Ollama/model versions, archive hash, command, result, and any skipped case.
Passing tests demonstrate the exercised paths and fixtures; they cannot prove that no
defects exist.

Build 133 automated qualification completed on 2026-08-28. The exact installed app
also completed a one-time approved public-page fetch through the real local Qwen route
without DeepSeek search credentials or a shell-network fallback. The full command
transcript was observed in the qualification task but was not retained as a repository
log, so a public-release candidate still requires one frozen rerun captured with
`tee`; the append-only ledger records this limitation explicitly.

The structured append-only ledger, including pre-candidate results and explicit
blocked/deferred rows, is [QUALIFICATION_EVIDENCE.md](QUALIFICATION_EVIDENCE.md).

## Automated source and unit gates

The warnings-as-errors build and Swift suite must cover:

### Transport, confinement, and environment

- 256-bit URL-safe token generation and uniqueness.
- authenticated HTTP request/cookie creation and unauthenticated HTTP/WS rejection.
- peer, Host, nonce, PID, CSP, and exact-origin WebView navigation policy.
- minimal DSH/tool/MCP child environments; absence of unrelated cloud keys and SSH
  agent by default; fixed non-secret Ollama marker only after the native supervisor
  verifies the exact app-owned PID/listener, and never in cloud/provider-repair mode.
- exact sandbox-runner grammar; Workspace/read-only Skills/temp roots; traversal,
  symlink, hard-link, outside-read/write, native-child egress, and private-store denial;
  exact sensitive-store denials are also generated for a canonical owner-safe POSIX
  account home outside `/Users`, while linked or writable custom-home paths fail closed.
- no silent fallback when requested confinement cannot start.
- Connected mode admits only the exact-origin guarded Fetch path: Request and init
  authority overrides, custom resolver/agent/dispatcher/socket/TLS material, implicit
  redirects, raw TCP/TLS/non-loopback HTTP(S)/HTTP2, wrong ports, and oversized
  declared or chunked responses fail closed; exact literal-loopback Ollama remains.
- composed DeepSeek requests neither create a stable anonymous-user file nor expose
  stable installation/internal session headers; the transport strips reintroduced
  identifier headers before the provider boundary.
- DeepSeek upgrade contract verifies V4 defaults, reasoning-content/tool-call replay,
  Keychain credential references, the disabled upstream native-search endpoint/model
  contract for future separately consented compatibility, and Fulmar's generated
  fetch-only Standard composition. A normal DeepSeek provider consent does not expose
  `web_search` in this candidate.
- The read-only DSH observer compares npm dist-tags and independently discovered
  official GitHub release/tag identities with explicit tracked acknowledgements.
  Fixtures cover GitHub-only releases and tags, redirects, pagination, oversized or
  malformed indexes, spoofed identities, duplicate versions, release-only/tag-only
  records, and false promotion. A source-contract test pins the exact scheduled
  workflow, read-only permissions, action revisions, Node digest gate, tracked-index
  gate, observer command, and execution order.

### Provider and session switching

- opaque provider/model IDs remain separate, including punctuation.
- catalog mapping, capability unknown states, endpoint normalization and data-boundary
  inference.
- HTTP only for canonical loopback/private-network literals; HTTPS for cloud; invalid
  credentials-in-URL, wildcard/malformed hosts, and literal link-local, metadata, or
  multicast endpoints rejected.
- exact provider/scheme/host/port/credential-reference consent; endpoint or credential
  edit invalidates the grant; legacy origin-only grants are revoked on migration;
  unknown route fails closed as cloud.
- DSH `agent-default-model` revision conflict retry and typed settings migration.
- direct Keychain replacement/removal re-describes readiness after success and
  apply-then-response-loss; removal is classified as applied/not-applied only when the
  readiness bit proves it, write-only replacement ambiguity stays visible, and an
  active removed/uncertain provider restarts into fail-closed readiness.
- one transaction commits DSH default, native route, consent, and Strict Local; every
  injected failure rolls back or reports incomplete rollback while egress stays closed.
- catalogue removal/settings-read failure leaves Quick Chat with no selection rather
  than falling back to row zero; Send stays disabled until an explicit transaction
  commits a route, including when two provider IDs share one approved origin.
- a refreshed text-only/unknown-capability route clears queued images, and the send
  boundary independently rejects any incompatible images that survive a UI race.
- main WebView requests a fresh session after restart; Quick Chat cancels/clears the
  old session; old task IDs are not reused across a boundary.
- asynchronous catalogue refresh retains the exact verified History session route or
  fails closed without selection; `medium`, `high`, and `xhigh` reasoning effort is
  preserved exactly until the user explicitly changes the reasoning control, with no
  fallback to another route's stored effort.
- Task History continuation rechecks route availability and asks again for an external
  boundary.
- auxiliary web/image/audio/connector policy cannot accept conversation-provider
  consent; endpoint/capability/boundary drift, duplicate grants, on-device endpoint
  smuggling, and LAN/cloud mismatch all fail closed.
- composed local-Qwen tool inventory hides unavailable `web_search`, exposes one
  approved `web_fetch`, and a public-URL task produces an exact-URL ask instead of a
  missing DeepSeek-key failure or Bash/curl fallback;
- approved page fetch rejects HTTP, custom ports, embedded credentials, IP literals,
  local/private/reserved DNS/TLS destinations, redirects and binary MIME; caps textual
  content at 2 MiB; and proves the exact-host capability cannot escape one operation.

### Conversations, history, and export

- streaming order/correlation, final response, interruption, cancellation, approval
  and question mapping, invalid/stale event rejection, prompt/attachment limits.
- a deterministic provider forces `max-tokens`, then proves both the packaged Web
  client and native Quick Chat follow the exact identified plugin-source follow-up
  without another user prompt, retain every earlier segment, keep later tool approvals
  and questions attached to the same native operation, reach completion, yield to
  queued user work, exclude subagents, and stop at the fixed continuation safety
  budget. A terminal summary that also reaches `max-tokens`, plus aborted, blocked,
  interrupted, unknown, and spoofed-source endings, must remain bounded and actionable
  rather than being presented as Ready. A missing, throwing, or stalled continuation
  plugin must fail through its short continuation-specific deadline, cancel only the
  exact owned session, and never leave native Chat or a schedule waiting for the full
  task timeout. Scheduled results retain every completed continuation segment under
  one aggregate response-byte limit.
- session list/detail bounds, exact route metadata, rename validation, branch sequence,
  archive result, search/debounce/error/empty states.
- Markdown/JSON export determinism; control-character handling; detected-secret and
  structure-only redaction; explicit full-text option; title/session/time/route/name/
  digest controls.
- attachment metadata bounds and base64-size accounting; no file paths or attachment
  bytes; output byte/message limits; owner-only atomic new-file write; no overwrite;
  cancellation leaves no file.
- host model-preparation and `llm/stream` sanitization precede DSH retry and `turn/end`
  persistence and map
  missing credential, Keychain recovery/busy, auth 401/403, quota 402/429, transient
  rate limit, 5xx, transport, timeout, empty/closed stream, missing adapter, context,
  model-configuration, abort, downstream throw, and unknown failures to finite copy;
  hostile messages/codes/request IDs/paths/URLs are absent from the persisted fixture.
- the dependency-free browser classifier has byte-for-byte semantic parity over the
  same matrix. A source compatibility tripwire pins the reviewed DSH 0.1.1-rc.1
  `SessionRuntime.manager.api`, outer `{ result }`, ordinary/subagent history calls,
  mux/Host envelope shapes, and connection callback's late property lookup. Real-shaped
  live and history/reload fixtures must reach the DSH-facing handlers only after
  sanitization. Ordinary and subagent history are independently sanitized at the Host
  API before transport; a pre-registered live callback uses late method lookup, while
  an already-open pre-bridge window is synchronously emptied and resynced under a
  64-session cap. The exact pinned `SessionRuntime` is exercised with a hostile
  pre-bridge request already in flight: its stale generation cannot install, while
  only the replacement request through wrapped history may repopulate the window.
  A 65-session fixture fails closed and restores wrapped transports.
- native Task History projects only direct `user/message` and `assistant/message`
  text; raw legacy failure/retry/end events never enter Markdown/JSON transcript
  export. DSH's byte-verbatim raw Harness-log export is fail-closed without invoking
  the underlying reader. This is an export/display boundary, not an on-disk migration.

### Local knowledge and memory

- construction on the main actor performs no directory creation, filesystem scan,
  document decode, or index build; a synchronous first-use request on that actor fails
  immediately with the typed background-required result.
- multiple first-use callers coalesce behind one serial bootstrap; cancellation
  completes every waiter, retry is explicit, and a mutation arriving during bootstrap
  executes only after the complete trusted snapshot is published.
- Root, Objects, and Recovery scans reject excessive entries/raw bytes/aggregate name
  bytes, overlong names, symlinks, FIFOs, hard links, permissive or non-owner nodes,
  sparse oversized files, replacement/identity drift, future schema, and deterministic
  deadline expiry without publishing a partial index or changing hostile bytes.
- decoded libraries enforce the exact production 4,096-document/128-MiB limits plus
  per-document extraction/chunk limits and aggregate chunk/posting limits. Scaled
  boundary fixtures exercise exact-cap success and one-over failure without writing or
  publishing the rejected item.
- Quick Chat performs lazy knowledge loading/search/indexing off the main actor and
  presents a loading state. Empty, loading, ready, and unavailable/corrupt remain
  distinguishable; the Knowledge window offers explicit load retry.
- Trash traversal/deletion starts only after ready, uses independent entry/byte/name/
  depth/deadline limits, never withholds the last trusted index, surfaces failure, and
  clears the issue only after an explicit bounded retry succeeds.
- create/update/delete/clear journal tests inject failure and simulated process loss
  after durable manifest, each object evacuation/replacement, catalog evacuation/
  replacement, Objects/Root directory fsync, rollback start/restore, and commit-marker
  fsync. Returned failures preserve exact prior catalog/object bytes; incomplete
  rollback is typed unavailable; relaunch rolls back uncommitted state and keeps only a
  durably marked commit. A failed post-commit cleanup followed by a later mutation and
  relaunch proves the newer validated generation remains authoritative while the
  historical committed journal is safely retired.

### Skills and plugins

- inert import rejects symlinks, special files, path escape, unsafe store, excessive
  depth/files/file bytes/total bytes, malformed `SKILL.md`, and duplicate limits.
- the Skills trust document uses `O_NOFOLLOW|O_NONBLOCK`, rejects non-regular,
  non-owner, linked, permissive, malformed/future-schema, over-count, and sparse or
  streamed-over-8-MiB state before use, and rechecks exact identity after its bounded
  read. A 0600 temp is fsynced and atomically renamed inside the private Security
  directory; injected pre-rename failure preserves exact prior bytes and in-memory
  state, while injected post-rename durability failure adopts the exact committed
  bytes, reports storage unavailable, and never exposes stale memory as authoritative;
  policy/skill state.
- bundle collection, Packages audit, and Active validation stream directory entries
  without whole-directory allocation and share explicit aggregate-entry and monotonic
  deadline budgets; empty-directory floods and a scripted deadline fail closed.
- imported bytes/fingerprint match review; executable permission is not trusted;
  project identity and policy are bounded.
- changed/missing/invalid content revokes activation; only reviewed skills enter a
  newly materialized read-only catalog.
- local-only/ask-every-time/persistent-allow external disclosure and one-session
  approvals; boundary switches never reuse stale activation.
- DSH community plugin complete-content fingerprint and built-in-name override rules;
  hostile empty/deep/oversized trees, declaration count/bytes, symlink and FIFO
  rejection, monotonic deadline, bounded private approval state, and repeated-audit
  descriptor accounting.
- private DSH-home preparation accepts the reviewed profile/migration while rejecting
  oversized mutable profile files, giant legacy files, empty-directory floods,
  excessive depth/path bytes, links/special objects, and deterministic deadline expiry;
  failed migration leaves neither a receipt nor partial top-level state.

### MCP

- only `stdio`; remote/SSE/HTTP transports cannot decode, validate, or activate.
- absolute executable, owner/permissions, content hash, absolute shebang interpreter,
  reviewed script/package arguments, configuration, and project device/inode identity.
- rejection of shells, `/usr/bin/env`, nested/dynamic interpreters, inline eval flags,
  unreviewed runtime entry points, newline/NUL/oversized argv, and secret-like args.
- environment allowlist and credential-reference grammar; forbidden ambient variables;
  disclosure categories; exact provider/boundary enablement.
- approval/revoke/remove and automatic revocation after executable/interpreter/script/
  config/project changes.
- startup/call timeout, discovered-tool count, output-byte cap, reconnect cap,
  duplicate namespaces, native per-tool approval, cancellation/disposal, minimal child
  environment, Workspace boundary, loopback and private-store restrictions.
- missing credential and server crash errors are bounded, redacted, recoverable, and
  never converted into an unconfined launch.

### Browser and downloads

- external-link confirmation shows the exact normalized HTTPS URL, cancel performs no
  handoff, approval uses only the default system browser, and no agent bridge exists.
- sanitized names, private unique staging, size cap, no-follow regular-file checks,
  collision-safe destination.
- passive signatures (PDF/image/JSON/text/ZIP containers), executable formats, scripts,
  installers, archives, active web content, empty/unknown input, mismatched extension/
  MIME/signature, misleading passive suffix, and generic MIME behavior.
- quarantine attribute required; digest/metadata/content revalidation catches mutation
  or replacement between download, review, and save; rejected/cancelled transfers are
  cleaned up.

### Workspace and state recovery

- canonical root/device/inode binding and owner-only separate storage.
- snapshot ordering/hashes/permissions plus secret/generated/dependency/special-object
  exclusions and file/entry/depth/path/per-file/total/stored/manifest/checkpoint limits.
- descriptor-relative streaming over an empty-directory flood, fixed-chunk capture,
  checkpoint-catalog entry caps, and deterministic monotonic deadline expiry.
- changed-during-scan detection, checkpoint integrity, automatic rotation without
  evicting manual checkpoints, and safe deletion.
- preview added/modified/deleted classifications and conflict types; live-state
  fingerprint and stale-preview rejection.
- separate overwrite-modified/remove-added choices; retain unapproved changes;
  symlink/directory/nonregular/obstructed-parent refusal.
- mid-apply failures restore all pre-restore bytes/permissions/times; rollback failure
  is distinct and visible.
- DSH-state backup secret exclusions, quarantine-before-restore, and copy-failure
  rollback remain independent of Workspace Recovery.
- Backup format 4 proves exact-schema/HMAC binding of manifest, catalog, publication
  receipt, create/delete journal, and restore journal to provider-history privacy epoch
  1. A v1/v2/receiptless source fails before backup-root creation or Keychain access; a
  historical destination fails before quarantine; old/mixed roots and journals remain
  byte-identical and return the typed privacy-migration requirement rather than an empty
  catalog.
- Legacy Harness-home import interruption after staging creation, durable content,
  durable receipt, and atomic install; every relaunch converges to one complete home.
  Malformed/oversized/source-mismatched receipts and bounded recovery-tree cleanup
  fail closed.
- serialized utility-queue home/plugin prerequisites leave the main queue responsive;
  typed cancellation and a stale generation both prevent the launch commit; a stop
  requested while a fixture is paused after its first filesystem mutation stays
  pending until that exact worker settles, after which no late home write occurs.
- signed-bundle, Ollama-plan, and complete Harness-plan phase pauses prove the main
  queue remains responsive and the exact stop barrier waits for settlement; the main
  launch commit revalidates captured path and owned-process identities before spawn.
- hostile Ollama model stores exercise entry, depth, UTF-8 path, link, hard-link,
  permissions, monotonic-deadline, and cooperative-cancellation bounds; changing the
  captured store identity before spawn is rejected.
- Skill and MCP launch hashing share the complete Harness monotonic budget. An expired
  or cancelled MCP pass propagates the typed startup error without revoking an otherwise
  unchanged approval. The four real sandbox probes each remain bounded by both their
  five-second ceiling and the shared pass deadline.

### Schedules, performance, and lifecycle

- schedule persistence/migration, recurrence/overdue calculation, exact typed route,
  route/boundary drift, external unattended consent, timeout/cancel/interaction error,
  result permissions, and one-active-run behavior.
- the helper refuses linked/public/special/malformed/oversized storage and more than
  1,000 schedules; adding the 1,001st schedule preserves a readable byte-identical
  1,000-record document; one-shot background idle exit occurs only after work ends.
- schedule request and created session use the exact authoritative Workspace.
- schedule occurrence receipts reconcile crashes after model success, after Inbox
  commit, and before schedule-state commit so a relaunch never executes the same
  occurrence twice.
- background due-only launch completes the noninteractive upgrade/migration gate before
  starting services, reaches bounded identity/topology readiness, promotes once, runs
  due work, then stops exact owned children and exits. Pending recovery and readiness
  timeout leave no heavy process running.
- runtime upgrade state is a no-follow owner-only regular file capped at 64 KiB;
  malformed, oversized, linked, public, or internally inconsistent state fails closed,
  preserves the hostile bytes and authenticated backup catalog, and starts no runtime.
- Runtime upgrade state has an exact six-key versioned epoch-1 schema with explicit
  nulls. A pre-versioned or wrong-epoch document remains byte-identical, protects no
  referenced legacy backup ID, creates no fresh catalog, and returns the typed privacy-
  migration requirement.
- Task Inbox retention enforces newest-first 2,000-record, 256 MiB, and 30-day limits;
  stale private crash temporaries are removed, unknown/link/special entries fail
  closed, per-result and clear-all deletion never follow links, and a failed append
  cannot be reported as a completed/saved activity.
- Inbox startup/count/load and occurrence reconciliation stream directory entries under
  exact aggregate-entry and monotonic-deadline budgets. Hostile entry floods, scan
  timeouts, and read/topology failures return a typed unavailable result, preserve the
  last authoritative count and bytes, and never masquerade as an empty Inbox. The
  independent occurrence semantic ceiling remains exactly 1,000 receipts.
- status count is metadata-only and full Inbox result decoding runs off the main UI
  path with cancellation/generation-safe presentation.
- Activity history loads only one owner/private/no-follow regular file capped at 4 MiB,
  validates at most 500 unique finite records with 512-byte titles and 16 KiB details,
  and durably persists startup interruption recovery. Copy-on-write mutation publishes
  only after a 0600 temp is fsynced and atomically renamed inside an exact 0700
  directory; malformed, oversized, linked, hard-linked, permissive, swapped, and
  injected write/rename failures preserve the prior bytes/snapshot and surface a typed
  unavailable/not-saving UI state.
- privacy-ledger first-create and full-rotation tests inject failure before write,
  before rename, after rename, and before parent-directory fsync. Precommit failures
  preserve exact prior bytes; post-rename failures adopt the exact installed inode,
  fail closed in-process, and an immediate relaunch reads the committed rows. The
  0700 storage chain is opened without path chmod/repair and symlinked or permissive
  nodes are never followed.
- attachment retention first attests an exact 0700 owner chain and reads the 0600,
  single-link ownership receipt with openat/O_NOFOLLOW, a 64 KiB cumulative cap, stable
  descriptor/path identity, finite dates, exact keys, sorted unique allowlisted copied
  entries, and the reviewed legacy source. Sparse oversize, permissive, hard-link,
  symlink, deterministic swap, extra-key, future-version, and source mismatch fixtures
  must preserve every attachment and return unsupported.
- Fast/Balanced/Deep output catalogs are exact and can be selected only for exact
  `qwen3.8:27b-mlx`; native, main-surface, and scheduled sessions are bound to a profile while forks/subagents inherit their parent, and the returned
  `agent/request.maxTokens` matches that profile after downstream route middleware only
  for the exact synchronized local route. Cloud and LAN output proposals are unchanged.
- injected 8/16/24/32/48/64/96 GiB matrices prove the Compatibility admission formula
  (twice installed model bytes plus a 4 GiB reserve), exact-Qwen's independent 48 GiB
  floor, and the absence of any local-memory admission on DeepSeek, OpenAI, Anthropic,
  or custom cloud routes. Settings and Performance Center must hide local presets for
  cloud routes, show fixed Compatibility for alternate Ollama models, and withhold
  qualified-Qwen presets below 48 GiB.
- the reserved local Ollama profile is revision-checked to one safely named installed
  model and the exact app-owned endpoint; stale ports/unreviewed fields are replaced,
  reasoning is explicitly off by default with a reviewed High option, and readiness
  re-reads context/output and topology before sessions are available. The simulated
  provider must observe `reasoning_effort: none` on the default local request.
- bounded `/api/show` fixtures cover malformed responses, unsafe names/architecture,
  duplicate or unsupported capabilities, missing completion/tools/context, short and
  implausibly large contexts, and thinking metadata. Exact Qwen must report its
  reviewed completion/tools/thinking contract and enough context for the selected
  profile. Every alternate model must be non-thinking, completion-and-tools capable,
  and within 8,192...1,048,576 advertised context tokens, then normalize to fixed
  text/tools-only Compatibility 8,192/2,048 with reasoning absent and the profile UI
  disabled. Legacy settings cannot retain Qwen profiles on an alternate model.
- an actual matching `agent/request` resolves DSH exact-model metadata and fails before
  provider I/O on absent, stale, or mismatched context; every runtime rejects another
  provider even when it shares an origin, while cloud/LAN models under the active
  provider are not assigned local context semantics.
- Ollama launches on a fresh reserved port; readiness polls within one 90-second total
  window and sends no HTTP while the signed child has not yet completed exec/bind.
  Before model admission or provider-topology synchronization, the verified listener's
  bounded official `GET /api/version` response must be one stable semantic version in
  the 0.33.x series at or above 0.33.2. Ollama's official v0.32.12 release first added Qwen 3.8 27B and
  the Apple-silicon `27b-mlx` variant, but that older server has not been physically
  qualified by Fulmar. The supported floor is therefore the oldest version exercised
  end to end on the development host, 0.33.2, while frozen-candidate physical generation remains
  its own mandatory row. Later 0.33.x patches remain eligible only while the unchanged
  tags digest, `/api/show` capabilities/context, generation, `/api/ps`, PID/listener,
  and DSH route gates pass. A newer minor or major series fails closed until a new
  Fulmar qualification; version acceptance never substitutes for behavioral evidence.
  The longer bound tolerates macOS reclaiming warm model/GPU resources after a prior
  run without increasing inference concurrency or thermal load; the wait remains
  cancellable and an earlier verified readiness response proceeds immediately.
  Every attempt requires the exact child PID to own that listener, uses a bounded
  well-formed tags response, and re-attests the same boundary after the response; a
  conventional-port decoy is never adopted. Static signature/team/identifier/inode/CDHash and the dynamic
  running-code CDHash requirement must all match. Symlinked/replaced/writable/wrong-team
  executables fail before readiness. The app-owned service receives a private HOME/TMP,
  read-only link/hardlink-safe model store, loopback-only bind/egress Seatbelt profile,
  cloud/history/pruning-off settings, one-model/one-parallel/bounded-queue and selected
  server defaults. Flash Attention and q8 are present only for the exact qualified
  Qwen route and absent for Compatibility models. The extracted-candidate
  `verify-app-owned-ollama-generation.sh` gate must launch that exact supervisor,
  complete one bounded content-free generation with the exact configured model,
  re-attest PID/listener ownership, prove Metal/MLX residency through `/api/ps`, and
  stop the exact child. The independent sandbox matrix proves internet/LAN and
  unrelated-file probes fail.
- missing, wrongly signed, changed, non-starting, or never-ready Ollama is a typed
  local-provider prerequisite failure: exact owned children are stopped, then an
  authenticated no-egress repair runtime exposes only provider catalog/settings/
  credential administration. Sessions, prompts, history, schedules, Skills, MCP,
  and the Ollama readiness marker stay unavailable until an exact repaired route is
  committed, the runtime restarts with a new identity, and topology verification
  promotes that identity. Bundle/runtime/preloader/inventory/tool-sandbox failures
  remain terminal and can never enter this repair path.
- a missing saved local model maps only the eligible topology stages to the explicit
  **Choose Installed Local Model** recovery action. The chooser validates the selected
  live catalog entry and metadata before commit, never defaults to row zero, performs
  no model download/library mutation, and remains unavailable for unrelated security
  or external-provider topology failures.
- DeepSeek/OpenAI/Anthropic credential activation returns to a new authenticated
  zero-provider-origin control plane with prompts/sessions/schedules still closed. A
  separate model selection, exact-boundary review, and **Use for New Tasks** commit is
  required before any inference runtime can start on that provider.
- every native startup/diagnostic/chat request uses declared-length plus cumulative
  chunk bounds, refuses redirects, has a hard completion deadline, and fires its
  completion once. Oversized fixed/chunked bodies and never-finishing Harness health,
  root, and Ollama tags fixtures cannot advance readiness.
- authenticated mux streams retain no more than eight decoded events/8 MiB in their
  event queue (in addition to the bounded 1.25 MiB parser buffer), then fail typed;
  whole-turn event, assistant text, tool, and interactive payload budgets reject many
  individually valid frames, cancel the exact submitted session, and never queue more
  than 1,024 ordered main-actor events. Quick Chat coalesces streaming renders and caps
  retained transcript/tool state.
- telemetry bounds, pruning and adaptive recommendation; exact aggregate telemetry
  schema excludes content and supports user clear; automatic first-use model load,
  protected unload/cancel; quit stops
  owned DSH and owned Ollama, leaves unrelated processes untouched, and honors unload.
- Diagnostics is constructed lazily, never during ordinary window startup; opening or
  refreshing it reads `settings.yaml` through a 256 KiB no-follow regular-file bound,
  rejects invalid UTF-8/oversized model labels, and treats hostile state as unknown.
- overlapping stop/restart/prepare requests retain exact process ownership until exit,
  coalesce one replacement, honor a later Stop/Quit, and reject stale callbacks or a
  premature stopper completion.
- repeated owned-Ollama exits permit only the 1.2/3/8-second bounded retries in one
  60-second window, then fail visibly; a full stable-readiness window resets the
  circuit and Quit/thermal/provider/Stop invalidates every delayed callback.
- the scheduler admission latch closes synchronously before protected transitions and
  Quit; post-quiesce Run Now, due/background work, queue drain, and late checkpoint
  completion cannot write an occurrence journal or reach an executor until verified
  readiness reopens the latch.

### Credential transactions and diagnostic privacy

- Credential create, replace, metadata-less adoption, remove, and foreground repair
  share one fixed owner-only transaction lock and must survive isolated probe-process
  loss after journal durability, value mutation, read-back, metadata commit, final
  value verification, and journal removal. Relaunch must be idempotent and
  yield exactly the prior or committed state; the kernel-managed `flock` must be
  released when the isolated helper process dies. This is controlled SIGKILL
  evidence, not reboot, APFS replay, storage-cache-loss, or physical-power-loss proof.
  The release-mode process gate exercises 24 ordinary high-level, 18 version-two
  foreground adopt/replace/remove, six token-bound malformed metadata-less record
  removals, and twelve file-persistence SIGKILL cases with a file-backed fake value
  store. Replace/remove repair killed immediately after its v2
  journal is durable must restore the original value-free foreground-attention state;
  adoption can commit from that journal because its freshly locked value is itself the
  selected target. Later checkpoints must recover the exact selected repair.
  File-persistence faults around
  temporary write, file fsync, rename, and directory fsync are separate cases.
  Journals must be bounded owner-only single-link
  files with no literal credential bytes; concurrent writers serialize;
  authorization failure preserves prior state; an unexpected third value fails
  closed. These are process-crash and persistence-ordering tests, not a claim that a
  real power-loss filesystem matrix or the final real-Keychain canary has passed.
- Service-log redaction assembles complete logical lines across every split boundary,
  CRLF, invalid UTF-8, interleaved/concurrent streams, oversized input, and multiline
  or unterminated private keys. Reviewed Bearer/label/JSON/URL/JWT/AWS/GitHub/Slack/
  Hugging Face/Google/generic API-token fixtures must never survive. Copy Support
  Report reapplies the redactor idempotently and removes private home/runtime paths.

### Native UI states and accessibility

- Every constructible native auxiliary window plus every Settings tab and Schedules
  is laid out at its declared minimum in Aqua and Dark Aqua; visible controls remain
  within bounds, tables expose table accessibility, and fixed-width content fits or
  scrolls.
- Every visible enabled titled application button or popup has an explicit
  target/action except documented submit-time form values; destructive empty-state
  actions start disabled.
- At 900×600, longest loading, failure, provider-recovery, fresh-session-failure, and
  thermal-cooldown copy fits in Aqua/Dark; stopped spinners are hidden; enabled
  recovery actions are labelled, keyboard reachable, and wired.
- These constructed tests do not qualify the installed route switch. An unlocked
  exact installed candidate must use the real model popup to complete local →
  consented external → local, verify fresh tasks and exact boundary/status labels,
  and record Accessibility/keyboard evidence; otherwise mark Deferred.

## Runtime, integration, and packaging gates

The release pipeline must run the documented make targets plus direct syntax checks
and record their full result. Its canaries must prove:

1. Bundled Node/DSH start without global npm/NVM or the old fixed port.
2. Missing/bad auth and Host fail; authenticated health/root/bootstrap/WS succeed with
   exact identity and policy headers.
3. A candidate-bundled typed client opens authenticated mux and host WebSockets against
   a clean isolated `DSH_HOME`, observes the pinned DeepSeek default, commits and re-reads
   the exact reviewed `ollama/qwen3.8:27b-mlx` profile/default before the first blank
   session, and exercises provider/model/settings, create/select, prompt/cancel,
   list/detail/rename/fork/archive RPCs. It rejects profile-local root/client/typert
   shadows plus missing, linked, or unsafe in-bundle entry points before readiness,
   then byte-compares and executes the served signed client bridge to prove native-bound
   fresh-session allocation and checkpoint-before-send. A deterministic loopback
   provider supplies the bounded turn; no DeepSeek key, onboarding, cloud egress, or
   source `~/.dsh` mutation is permitted.
   A second clean candidate host loads one inert, content-audited local `stdio` MCP plan
   from a non-empty owner-only catalog. The typed model request must expose the exact
   `mcp__security_canary__security_canary` namespace. Authenticated native denial must
   prevent execution; authenticated allow-once must execute exactly once; the returned
   bytes must remain within the reviewed cap; and both exact guard/server PIDs must stop
   when the candidate host is disposed.
   Real streams in both private hosts must create only the exact owner-only bounded
   performance-telemetry document; prompt, response, tool-result, and error markers are
   searched byte-for-byte and must not be retained.
4. Empty state and a private clone of real DSH state both reach Ready; source state is
   byte/metadata unchanged.
   The same gate proves stored and legacy-key-only Hermes fixtures retain the exact
   Hermes route across repeated loads, normalize to Compatibility/no reasoning, and
   never rewrite their stored bytes to the qualified MLX default. A clean settings
   fixture still defaults to the qualified MLX route.
   It also proves that, before any backup-key or plaintext credential migration child
   can execute, unsafe path/layout, link, mode, empty/oversized, bundle-integrity,
   device/inode, and content fixtures fail closed with zero runner invocation. Pre-run
   inode and same-inode content swaps likewise execute nothing; post-run replacement
   rejects all output and cannot populate the backup-key cache or report migration
   success.
5. Local Qwen cold and warm prompts complete and cancellation is bounded.
6. A deterministic DSH tool matrix reads, searches, creates, edits, verifies, and
   invokes an allowed child inside the authoritative Workspace while outside,
   symlink/hard-link, private-store, and egress probes fail.
7. Quick Chat and a schedule perform a small file task in that same Workspace.
8. A simulated loopback OpenAI-compatible provider exercises external-route catalog,
   Keychain reference, exact-origin grant, tool request, streaming, error/cancel,
   switch rollback, and fresh-session paths without real cloud data or cost.
9. A second loopback-only protocol matrix runs through the packaged candidate with
   four separate Keychain references: official DeepSeek chat completions, OpenAI
   Responses, Anthropic Messages, and a hand-declared custom OpenAI-compatible route.
   It verifies protocol-specific auth, attribution and body shape, simple streaming,
   split tool-call framing and tool results, cancellation, terminal 401 and
   DeepSeek-documented 402 insufficient-balance handling,
   exactly bounded 429/5xx retries including eventual recovery, malformed-event
   rejection, declared and chunked aggregate-response byte limits, and secret absence
   from every retained artifact. It requires no live cloud credential or network.
10. A local hostile MCP fixture exercises startup failure, too many tools, oversize
   output, timeout, crash/reconnect, credential absence, native deny/allow, and child
   escape attempts. No remote transport starts.
11. A disposable Workspace exercises capture, preview, approved selective restore, an
   injected mid-restore failure, and exact rollback.
12. Release verification checks the deterministic full VendorRuntime inventory before
    and after copy, independently derives the exact single-authoritative-DSH,
    sanitized-preset, six-plugin unsigned Runtime, permits signing changes only at
    the enumerated Mach-O paths, and checks
    every extracted signed Runtime byte against the release-bound final inventory. It
    also checks exact versions, lockfile, zero unresolved production vulnerability
    findings at test time, populated SBOM/notices, property lists, nested signature,
    manifest, archive SHA-256, exact
    pre-extraction central-directory totals, extracted tree, empty/cloned runtime,
    sandbox/MCP, simulated-provider, and focused quit-barrier tests. Interactive Dock
    quit and relaunch remain manual evidence rather than a headless inference.
13. Pre-install update qualification requires an exact helper readiness frame and EOF only after
    all fail-fast signature/path/attestation checks. Delayed success is accepted within
    the bound; malformed/noisy/early-EOF/crashed/hung helpers are terminated and reaped
    without granting terminal quit authority. This is not public update qualification:
    the exact new app must additionally complete a private nonce-bound identity and
    authenticated Harness-health handshake before commit; every missing/invalid health
    and injected power-loss boundary must recover or restore the prior app; and the full
    flow must pass across two same-team notarized versions on a clean Mac.
14. Deterministic and full-hardware candidate verification reject ad-hoc signing. A
    successful full-hardware run retains an owner-only build-specific evidence set
    bound to the exact identity, manifest, archive byte count/SHA-256 and success
    markers; failure, signal, missing summary, drift, tampering, or an interrupted
    rerun cannot replace a previously valid set with mixed evidence. Public asset
    preparation re-verifies that set plus current source inventory and dependency
    audit.
15. Notarization-evidence validation accepts only bounded private regular JSON with an
    Accepted submission UUID, an Accepted log for the same UUID, and no issues. This
    proves consistency of supplied Apple records only; Developer ID signing, exact
    Apple submission/stapling, Gatekeeper and clean-Mac execution remain separate
    external gates.
16. Candidate UX scope is English-only and has no localization/pseudolocalization
    pass. Clean-state first-run acceptance must complete local setup and external-
    provider setup using current recovery/settings paths; no dedicated onboarding
    assistant is claimed.
17. Private installation is a separate release-fixture lane. It must prove the exact
    fixed candidate/current/stage paths, matching persistent private signer and
    designated requirement, complete byte-tree identity, no running app/bundled
    process, an external non-shipped helper, APFS atomic swap, directory durability,
    owner-private bounded pre-staging preparation, final pre-swap journal and receipt,
    and a retained rollback.
    Receipt-root policy is prefix-neutral: an owner-safe canonical Darwin cache
    fixture outside `/Users` is admitted, while a symlinked home, unsafe home mode,
    extended ACL, or otherwise-safe home below the writable `/private/tmp` ancestry
    is rejected.
    Mutation, signer mismatch, unsafe topology, helper failure before and after swap,
    post-proof failure, receipt/fsync uncertainty, candidate absence, and rollback
    failure are independently injected. Real child processes receive SIGKILL after the
    journal, swap, receipt, cancel/retire lifecycle marker, stage archive, and record
    archive boundaries. Preparation, opaque-abandonment, journal, receipt, and lifecycle persistence receive real
    SIGKILL after temp creation, partial-file fsync, complete-file fsync, immediately
    before exclusive rename, and after rename before directory fsync. Opaque-stage
    record-directory archival uses a separate durable parent sentinel so the
    rename-before-parent-fsync boundary remains discoverable and explicitly replayable. Explicit
    reconciliation archives partial evidence without deletion, preserves and
    idempotently reconciles a canonical-plus-stale temp, and rejects malformed,
    linked, hardlinked, wrongly owned or permissioned, duplicate, extra, or
    archive-collision artifacts. Candidate absence during an otherwise
    unreconstructable pre-swap journal write preserves the temp and fails closed.
    Explicit reconcile/resume/finalize/cancel/retire replay is idempotent;
    cancellation and retirement use `RENAME_EXCL` plus parent fsync, preserve both
    bundles, reject collision/symlink/hardlink/mode/extra/ABA states, block later
    installation while incomplete, and unblock it only after proven archive completion.
    A real frozen candidate fixture must pass deterministic proof. Ordinary runs
    explicitly skip only the four
    allowlisted release-fixture cases—two private-install proofs plus the extracted
    scheduler-helper and update-archive preflights—rather than silently returning;
    the release run supplies both exact fixtures and requires all four to execute.
18. Public-distribution success additionally requires one owner-private, bounded,
    single-link external-evidence record bound to the exact manifest SHA/version/build.
    Its schema admits exactly eight named external gates and exact passing
    status/digest/reference records. Missing gates, stale identity, placeholder
    digests, extra fields, malformed JSON, unsafe modes, links, or an inferred overall
    pass fail closed. The verifier checks structural completeness and binding only; it
    never manufactures evidence or turns a human, legal, clean-Mac, GitHub, or
    accessibility assertion into proof.

## Manual private matrix

| Scenario | Expected result |
| --- | --- |
| Dock cold launch | Main window reaches Ready; new random endpoint/token; existing state loads |
| Ollama/Qwen | Boundary says On this Mac; no DeepSeek key/onboarding; cold then warm answer and tool task succeed |
| Missing/alternate/legacy local model | Missing saved model shows explicit chooser with no substitution/download; exact Qwen retains qualified controls; stored Hermes remains Hermes and is labelled unqualified; admitted alternates pass conservative installed-size/RAM admission and are fixed at 8K/2K; oversized/thinking/tool-less/short-context models are refused |
| Local → simulated/cloud route | Warning names exact origin and disclosure; runtime restarts; new main and Quick Chat sessions are empty |
| Cloud credential activation | Saving/verifying the key returns to control-plane-only readiness; no route is selected and no inference runs until model, exact boundary, and **Use for New Tasks** are separately committed |
| Installed model switcher / boundary cycle | On an unlocked desktop, the exact installed build uses the real Provider and model popup for local → consented external → local; disclosures, fresh empty tasks, model/status baseline, keyboard and VoiceOver actions pass. Record Deferred until executed; static target/action tests do not count. |
| External → local | Exact external allowlist disappears; Strict Local returns; fresh sessions begin |
| Failed route switch | Previous route remains coherent; no newly opened origin; clear error |
| Provider Settings | Credential writes/read/removal use Keychain reference path; UI never displays persisted plaintext after save |
| Native navigation/settings | Chat and Agent Workspace are visible; General/Models/Privacy/Advanced tabs fit at minimum size and are keyboard/VoiceOver reachable |
| Quick Chat | Stream, approve/deny tool, answer question, cancel, Copy Last Reply, redacted export, full-export confirmation |
| Output-limit continuity | Force a multi-segment task in Agent Workspace and native Quick Chat; Fulmar continues without a manual “continue”, preserves every prior output segment and later native interaction, remains cancellable, yields to newer user work, and surfaces its terminal safety bound without looping |
| Task History | Search/read/continue; rename; branch latest completed state; archive hides without delete; export |
| Skills | Import/review/enable; local use; ask/deny external use; mutation blocks until re-review |
| MCP | Register/review/approve local stdio; deny/allow one call; mutation revokes; remote endpoint cannot be added |
| External-link/download | Exact URL confirmation and system-browser handoff; safe preview; disguised/changed download cannot preview/save silently |
| Workspace Recovery | Manual checkpoint; preview; selective restore; stale preview forces refresh; DSH restarts safely |
| Schedules | Local Run Now writes result/file in shared Workspace; external unattended route is blocked until explicit consent |
| Performance | Profiles update limits; Deep warns about cost; resident model and measured memory/TTFT/rate are visible |
| Permissions | Screen/mic deny is clear and nonpersistent; user-approved Appshot and on-device dictation work |
| Quit/relaunch | Owned DSH and owned Ollama exit; an unrelated decoy/service survives; unload preference applies; next launch uses new auth and Ollama identities/ports |

## Credentialed external-provider matrix

Run only with user-supplied non-production test credentials, low spend limits, and
non-sensitive fixtures. Repeat for DeepSeek, OpenAI, Anthropic, and each custom
endpoint intended for use:

- exact endpoint/TLS and displayed boundary;
- credential save/read/remove without log/export exposure;
- model catalog and simple streaming chat;
- bounded tool call and native approval;
- cancellation, invalid key, rate-limit, unavailable model, provider error, timeout,
  and retry behavior;
- provider dashboard cost/log review and deletion/retention expectations.

Without those keys, mark every live provider row **not run**. A simulated adapter test
does not establish live provider compatibility.

## Manual permission and public-only matrix

Screen Recording, microphone, speech, notifications, login-item, background-schedule,
minimum-macOS, VoiceOver/accessibility, clean-Mac Gatekeeper, notarization, and
two-version update flows require explicit user/environment action. Record **deferred**
rather than **pass** when permission or credentials are unavailable.

## Build 132 evidence record

These results refer to the frozen 1.2.12 (132) archive with SHA-256
`bac37a0135b164e038a61de753dc74cedab7605c326c9cd151c219ac06e2e23e` and retained
release log `build/qualification-1.2.12-132-final.log` (SHA-256
`6f2a5bd306b941a214ebe508a24265b181b2fc5c5ebfb7ccb254301e1efced59`).

| Evidence | Result | Date/environment | Artifact/log reference |
| --- | --- | --- | --- |
| Warnings-as-errors build and Swift suite | Pass — 653/653 in 23 suites | 2026-08-27; macOS 26.6.2, Apple M5 Pro, 48 GB | Final log |
| JS/runtime syntax and dependency audit | Pass — 157/157; 0 unresolved production vulnerabilities | 2026-08-27; same host | Final log; 511 npm paths |
| Credential helper/migration | Pass — 6/6 real-Keychain canaries | 2026-08-27; same host | Final log |
| Empty and cloned-state security canaries | Pass | 2026-08-27; isolated homes | Final log |
| App-owned Ollama real generation + GPU residency | Pass | 2026-08-27; Ollama 0.33.0; exact local model | Final log; content-free evidence |
| Local Qwen completion/tool/shared-Workspace matrix | Pass | 2026-08-27; `qwen3.8:27b-mlx` | Final log plus installed-app exact-response, cancel, and disposable file-tool smoke |
| Simulated provider switch/egress/fresh-session matrix | Pass | 2026-08-27; loopback fixtures | Final log |
| Candidate DeepSeek/OpenAI Responses/Anthropic/custom protocol matrix | Pass — protocol fixtures | 2026-08-27; credential-free loopback | Final log; not a live-provider claim |
| Skills/MCP hostile matrices | Pass | 2026-08-27; candidate-bundled runtime | Final log |
| Export/external-link/download/recovery/schedule matrices | Pass — automated; Recovery also interactive | 2026-08-27; same host | Final log; disposable Recovery restore verified |
| Package/signature/SBOM/manifest/install/quit/relaunch | Pass for private ad-hoc build | 2026-08-27; installed `/Applications/Fulmar.app` | Final log; exact-copy install; 1.2.11 (131) rollback preserved; installed close/reopen 0.159 s; exact owned DSH PID stopped on Quit; relaunch reached Ready |
| Manual private UI/permission checks | Partial — core windows and repaired sheets exercised; OS permission matrix deferred | 2026-08-27; interactive user session | About showed 1.2.12 (132); main/Chat/Recovery exercised; Screen Recording, microphone, speech, notifications, login item and background scheduling not enabled for this run |
| Live DeepSeek/OpenAI/Anthropic/custom providers | Partial/Not run | 2026-08-27 | DeepSeek authentication/error path reached the provider but the test account returned insufficient balance; no paid completion/tool/cancel claim. OpenAI, Anthropic and custom live routes not run |
| Developer ID/notarization/clean-Mac/two-version update | Not run — public credentials/environment unavailable | — | — |
## Live macOS status-item acceptance

The status-item release gate is intentionally a live macOS test rather than a
bitmap or unit assertion. Run all four candidate targets—`make status-item-live`,
`make status-item-normal-actions`, `make status-item-headless-handoff`, and
`make status-item-physical-background-handoff`—and then all four
`installed-status-item-*` equivalents after exact-copy installation. Every
target first binds the app to the current ReleaseIdentity, source inventory, release
manifest, archive, candidate tree, full vendored runtime inventory, and recorded
toolchain while holding the same private lock used by assembly and release verification.
It rechecks source/runtime/toolchain after compiling its unique private helper and keeps
the lock until the live test exits. An installed target additionally requires a
byte-identical candidate/installed tree. A stale app cannot supply evidence. The tests
require Accessibility access for the terminal or automation host that launches them.

The direct script defaults to a three-launch developer smoke using the app's
`--status-item-acceptance` mode; the checked-in `make status-item-live` release target
passes an explicit cycle count of twenty and never rebuilds the candidate. Before and
during every launch, the gate reads the candidate bundle
identifier and fails closed if either NSWorkspace or a complete BSD process scan finds
any declared Fulmar main executable, regardless of app path. Bundled RuntimeLease and
Node children are deliberately not app peers and have separate runtime-orphan gates. It
records the exact PID plus kernel start time and
accepts termination only after kernel disappearance or proven PID replacement.

On every cycle the gate requires exactly one accessibility item named `Fulmar menu`,
then requires five continuous seconds of stable, non-zero placement in a Quartz
display's top band. It rejects Control Center's compact left-edge parking sentinel,
including the ambiguous case where a second display is arranged directly below the
primary. The gate activates the item through a real AXPress, verifies `Open Fulmar`,
`Chat`, `Settings…`, and `Quit Fulmar`, activates `Quit Fulmar`, and waits for the
recorded kernel process identity to end. Raw-signal cleanup is permitted only when the
current PID still matches both the captured start identity and exact target path.

The normal-action target launches without an acceptance argument, activates the exact
application, polls boundedly for production-menu enablement, opens and closes Agent
Workspace, Chat, and Settings, and requires each result to be an active, focused,
onscreen main window before using the real protected Quit path. It never creates a task
or requests inference. The fast headless target proves the two-process lifecycle with a
synthetic accessory that owns no runtime or scheduled work. It is not evidence for a
real background workload: before release, both the candidate and installed disposable-
state physical targets must start the ordinary `--background-schedule` path, reach
authenticated runtime/topology, perform its protected stop, hand off to a full
foreground app, and leave no helper or app-owned Ollama CLI process. Each target must
also prove that the signed-in user's Fulmar state boundary remained unchanged.

`HarnessWindowToolbarLayoutTests` renders the real macOS 26 controller in Aqua and
Dark Aqua at 900 and 1280 points across all status colours and text lengths, compares
global toolbar control centres and identical-glyph ink centres in one coordinate system,
and proves the pre-fix full-height label fails. Run `make toolbar-render-macos26`; that
release target fails on any other major OS, while ordinary cross-platform unit runs
report the two render tests as explicitly skipped. Candidate and installed screenshots
remain required, as does a visual/keyboard run of the exact archive on minimum macOS 15;
macOS 26 rendering is not minimum-OS evidence.

The two apparent build-136 third-cycle failures were invalid evidence: one overlapped
the installed build 135 and the other overlapped a temporary build 136. The former
gate checked only the exact app path and treated LaunchServices disappearance as
process exit, so it missed both same-bundle/autosave collisions. Once every peer was
stopped, the unmodified private build and a kernel-identity variant each passed 10/10
immediate launches. A separate clean 54-launch matrix found no placement advantage
from the private priority factory, so the current source uses only public AppKit.

AX placement and a pressable menu prove the functional accessibility surface, not
pixel compositing. `NSStatusItem.isVisible`, its window visibility, and candidate-owned
CGWindow data cannot distinguish every Control Center-hidden state. Before public
release, perform a separate human/screenshot check with Screen Recording permission,
plus macOS 26 System Settings → Menu Bar → Allow in the Menu Bar, crowded/notched,
multi-display, Spaces, sleep/wake, dock/undock, and clamshell checks.

The negative gate must also be run with another installed Fulmar copy active. It must
refuse before launch, report that peer's PID and canonical executable path, and leave
the peer running.
