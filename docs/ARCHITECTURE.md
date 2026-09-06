# Architecture — Fulmar 1.2.36 build 156

## Runtime topology

```text
Fulmar.app
├─ Native AppKit control plane
│  ├─ main Harness window ── non-persistent authenticated WKWebView
│  ├─ Quick Chat / Task History / Models & Providers / Performance
│  ├─ Skills / MCP / Schedules / Recovery / Backups / Diagnostics
│  └─ confirmed system-browser handoff + secure Harness download staging
├─ app-owned DSH child
│  ├─ bundled Node 22.23.1 + DSH 0.1.1-rc.1
│  ├─ random 127.0.0.1 port + per-launch token/nonce
│  ├─ HTTP/WebSocket authentication and exact-origin preload
│  ├─ provider-specific exact-origin egress policy
│  ├─ confined native filesystem tools
│  └─ guarded local-stdio MCP adapter
├─ Keychain credential helper
├─ private credential-migration XPC service
├─ optional scheduler helper
└─ verified update helper

Inference targets
├─ app-owned Ollama on a fresh PID-verified 127.0.0.1 port ── installed local models
└─ one consented provider origin ── DeepSeek / OpenAI / Anthropic / compatible
```

## Menu-bar placement compatibility

Fulmar owns exactly one retained `NSStatusItem` for the lifetime of the foreground
app and creates it only through AppKit's documented `statusItem(withLength:)` API.
A clean macOS 26 experiment exercised public/private factories, with and without
autosave identity, across 54 launches and found no placement benefit from the former
private priority selector. Fulmar therefore has no private AppKit ABI dependency.

The item has the public autosave identity `Fulmar.MenuBar.v2`, so AppKit and Control
Center persist the user's Fulmar visibility choice without reusing the generic `Item-0`
identity seen in stale development records. v2 supersedes a v1 record that Control
Center restored at its off-screen parking coordinate during the build-146 cold-launch
soak. Fulmar never visibility-pulses the item. During the bounded launch-settlement
window, it uses only its own AppKit button-window geometry to distinguish a real top
placement from Control Center's off-screen parking frame. If AppKit still reports the
item visible, Fulmar may detach and recreate it at most twice; `isVisible == false` is
always respected as a user choice. Once termination is irreversible, Fulmar detaches
the autosave identity and then synchronously removes the retained item. This prevents
Fulmar's own quit from being persisted as a hidden choice while preserving a removal
the user made during runtime.

macOS has final control over menu-bar placement. On macOS 26, users can select Fulmar
under System Settings → Menu Bar → Allow in the Menu Bar. AppKit explicitly permits
`isVisible` to remain true while an item is temporarily hidden for space, so the Dock
icon, application menus, and main window remain authoritative. Settings and Help both
offer a direct recovery path to Menu Bar settings.

The release-only `--status-item-acceptance` mode constructs the production app menu,
status item, artwork, accessibility identity, and status menu without starting WebKit,
DSH, Ollama, schedules, notifications, or thermal polling. The checked-in live gate
rejects every running process with the same bundle identifier across all app paths,
requires a complete BSD process inventory, records the launched PID's kernel start
identity, and treats only kernel exit or PID identity replacement as termination. Each
cycle requires five continuous seconds of top-band AX placement using Quartz display
bounds, presses the real item, checks the required menu actions, and quits the exact
launched PID through that menu. The default smoke uses three cycles; release
qualification uses at least twenty. AX placement and interaction do not prove rendered
pixels, so a human or Screen Recording-enabled screenshot check remains separate.

Fulmar never adopts an arbitrary loopback service. It reserves a fresh port,
starts Ollama itself, verifies that exact child PID owns the listener and that its tags
response is well formed, then gives DSH only that exact origin. DSH and this Ollama
process are terminated with the app. Model weights load on use, not at system login.
Before launch, one shared resolver validates the official Ollama identifier, Developer
Team, strict code signature, canonical path, inode, owner, mode, and CDHash; readiness
revalidates both file and running-process identity. Ollama and its runner descendants
inherit a dedicated Seatbelt profile with private HOME/TMP, a validated read-only model
store, loopback-only bind/egress, and disabled cloud behavior.

## One authoritative Workspace

`HarnessController.workspaceDirectory()` owns the canonical private Workspace under
Application Support. The main Harness session, Quick Chat, scheduled conversations,
filesystem sandbox, Skills project identity, MCP project identity, and Workspace
Recovery all receive that exact URL. This removes the former failure mode in which a
native task could ask DSH to work in one directory while the sandbox authorized a
different directory.

The runtime receives one writable workspace root and the active reviewed Skills root
as read-only. Traversal, symbolic-link escape, pre-existing hard-link aliases,
unreviewed roots, and malformed sandbox invocations fail closed.

## Authenticated Harness transport

At launch the app asks the OS for a loopback port and creates URL-safe 256-bit token
and nonce values. A preload module patches Node networking before DSH starts. Every
HTTP and WebSocket request must authenticate, except the single bootstrap exchange
that turns the token into an HttpOnly, SameSite cookie. Unexpected peer/Host values
are rejected. The native app also verifies the health nonce and child PID before
displaying the UI.

Response headers and Content Security Policy limit connections to the exact random
HTTP and WebSocket origins. The WebView uses an in-memory data store and cannot adopt
another process merely because it answers on an old or familiar port.

## Provider control plane

DSH remains authoritative for provider/model catalogs, per-session routing, and the
`agent-default-model` setting. Native code keeps provider and model identifiers as
separate opaque values; it does not split IDs on punctuation.

A provider switch is a transaction:

1. normalize and classify the configured endpoint;
2. obtain consent for the exact external origin and exact credential reference when required;
3. update DSH's default using revision-aware mutation and one conflict retry;
4. persist the typed native selection;
5. activate Strict Local only for the on-device route;
6. restart DSH with either loopback-only access or one external origin;
7. start a fresh Harness session and clear Quick Chat's old session.

Failure restores the previous DSH default, native selection, consent state, and
privacy mode where possible; an incomplete rollback leaves network access fail-closed
and requires a restart. Editing a provider endpoint or credential reference invalidates
the grant. Version-1 origin-only grants are migrated by revoking them and requiring one
fresh provider activation; they are never silently broadened. Unknown providers are
treated as cloud until an explicit descriptor proves a narrower boundary.

Provider credentials are references. The consent record contains only the bounded
reference name needed to bind approval; the helper resolves its value from
this-device-only Keychain storage when DSH requests it. Secret values do not enter
serializable route or consent objects. The fixed local Ollama marker is intentionally
non-secret.
Credential activation is not a model switch: after save/readiness verification, the
protected mutation returns to a freshly authenticated, zero-provider-origin control
plane with inference admission closed. The user must then choose a catalog model,
review the exact boundary, and commit **Use for New Tasks** before the seven-step
provider-switch transaction above can run.

Local route admission reads bounded metadata from the already verified app-owned
Ollama `/api/show` endpoint. Exact `qwen3.8:27b-mlx` must report the qualified
thinking/tool/context contract before it receives the Fast/Balanced/Deep profile.
Another installed model must report completion, tools, no model-specific thinking,
and a context within the reviewed bounds, then pass an installed-size/RAM floor of
twice its weight bytes plus a 4 GiB reserve; it is normalized to text-and-tools-only
Compatibility 8K/2K regardless of saved legacy settings. A missing saved model keeps
admission closed and exposes an installed-model chooser. There is no row-zero default,
model substitution, pull, download, or model-library mutation in this control plane.
In particular, the Hermes tag used by earlier private builds remains the exact saved
Hermes route after upgrade and receives Compatibility/no-reasoning normalization; it
is never reinterpreted as consent to select or load the qualified MLX tag. Only a
brand-new settings document defaults to the qualified route.

Backup authentication and first-use plaintext credential migration run before the
ordinary controller-wide runtime verification point, so each owns an equivalent local
trust gate. Production migration never launches the bundled Node executable, migration
script, YAML pathname, or credential-helper pathname. The app descriptor-reads and
pins the complete 74-module YAML graph, opens the source, its parent and the persistent
lease as no-follow kernel capabilities, then sends only those handles and bounded bytes
to an embedded private XPC service. The app sets an exact designated-requirement plus
CDHash requirement on its `NSXPCConnection`; the service applies the matching exact app
requirement before accepting messages. Request, nested file-identity and response JSON
use canonical exact-key schemas with fixed byte limits; unknown keys, alternate types,
duplicates and noncanonical encodings fail closed before migration code runs. The
service validates the capabilities again,
evaluates the admitted CommonJS graph in JavaScriptCore, performs journaled Keychain
transactions, re-reads every value, and scrubs only the exact source descriptor.
Its monotonic deadline first requests typed cancellation and then hard-stops a stuck
JavaScriptCore/Keychain operation; the app-owned persistent lease survives service death
and transaction recovery remains idempotent on the next attempt.

The migration service and the ordinary credential helper deliberately share one signed
designated requirement so existing Keychain ACLs continue across the transition. The
app still pins the service's exact current CDHash, and release verification proves both
the requirement equality and that the service imports no process-launch APIs. All file
identities, bundle integrity and graph pins are rechecked before success is admitted.
The legacy pathname runner remains only as an explicitly injected non-production test
seam outside a packaged app; it is never selected by the production component locator.

In Connected mode, the preloader exposes one outbound provider primitive: a normalized
Fetch request to the exact consented origin. The Request is rebuilt from a reviewed
standard option set, redirects are manual, authority and transport/TLS overrides are
rejected, and streamed or declared responses are capped at 16 MiB. Direct external
TCP, TLS, HTTP(S), HTTP/2, UDP, custom DNS resolvers, and Unix sockets are denied. The
only direct HTTP stream admitted is the exact literal-loopback Ollama origin; it cannot
be reinterpreted as a grant to a private-network or cloud host.

Specific page retrieval uses a separate one-shot capability rather than the active
model provider's origin grant. The signed `web-fetch-safe` adapter asks through DSH's
approval service for the exact normalized public HTTPS URL. The preload then admits
only that hostname while the guarded Fetch is in flight, injects a public-address-only
DNS lookup, rechecks the connected address, blocks redirects, and bounds the response.
No capability reaches Bash, MCP, arbitrary plugins, or later requests. Credentialed
general search remains unadvertised until its own route is configured and qualified.

The pinned DeepSeek adapter carries one documented local privacy patch: it does not
create or send the upstream stable installation UUID or internal Harness session ID.
The Fetch boundary independently strips both headers. See
[VENDORED_PATCHES.md](VENDORED_PATCHES.md) for the upgrade and verification contract.

## Session, history, and export paths

Quick Chat creates and streams real DSH sessions, receives typed tool/question events,
and uses DSH cancellation and approvals. Task History obtains bounded session lists
and transcripts through RPC. Rename and fork mutate DSH session state; archive is a
durable workspace hide, not deletion. Continuing an archived or historical task is a
deliberate action and rechecks whether its exact provider/model is routable.

For a foreground root task whose balanced DSH turn ends with `max-tokens`, the
performance plugin schedules a new identified Agent follow-up after event delivery.
It resumes the unfinished user request, asks for a cut-off tool/edit call to be issued
again in full, yields to queued user input, resets after a normal user turn, and has a
fixed continuation budget. Subagent turns are excluded because their parent agent
owns settlement. This preserves DSH's durable event ordering and avoids mutating or
reopening the already-completed partial turn.

Markdown and JSON export use a bounded projection that cannot contain attachment
bytes or file paths. Privacy modes can redact detected secrets, all content, IDs,
timestamps, route metadata, attachment names, and digests. Output is written as a new
owner-only file; an existing destination is not silently overwritten.

## Skills and MCP activation

Skill import never executes package code. It validates the tree, copies ordinary
files into a private quarantine, strips executable trust, and fingerprints the exact
content. Project policy binds enablement and external-disclosure choice to that
fingerprint. Each runtime launch atomically materializes only permitted skills into a
fresh read-only catalog; changed content, a new project, or a boundary change prevents
reuse of stale activation.

MCP 1.1 supports local `stdio` only. The trust record binds the executable,
non-dynamic absolute shebang interpreter, reviewed script/package arguments, literal
argv, project filesystem identity, disclosure classification, and allowed provider
boundaries. Secret-like command arguments, shell executables, dynamic `/usr/bin/env`
shebangs, ambient-environment overrides, and unreviewed runtime entry points are
rejected.

The guarded adapter resolves named credentials at activation, starts the server as a
confined child with a minimal environment, bounds startup and call time, limits tool
count and result bytes, applies reconnect limits, and routes every MCP tool through
the native approval seam. Remote HTTP/SSE MCP is intentionally absent. Enabling it in
a future version requires a new origin, authentication, privacy, and cancellation
design rather than a configuration toggle.

## Browser and downloads

External Harness links display the exact HTTPS address for confirmation, then leave
the app for the user's default browser. Fulmar deliberately does not embed a
general browser because a WebKit DNS preflight cannot be cryptographically bound to
the socket WebKit later opens. The default browser is outside the agent-control bridge.

Downloads enter a private per-transfer directory through no-follow file descriptors
and size limits. Filename extension, reported MIME type, and content signature are
cross-checked. Active, executable, mismatched, or unknown content is not silently
previewed. The stager applies macOS quarantine, records a digest and metadata, and
revalidates the file before an explicit collision-safe save.

## Workspace and runtime recovery

The change journal captures bounded content snapshots before new main tasks and Quick
Chat turns. It excludes generated/dependency trees and likely credentials. Manifests
bind canonical Workspace identity, file hashes, permissions, and limits. Its
descriptor-relative no-follow traversal streams directory entries and file
hash/capture chunks beneath one monotonic deadline, with fixed path, depth, count,
per-file, and aggregate-byte ceilings. Automatic checkpoints rotate without evicting
manual ones.

A restore is two-phase: preview computes changes/conflicts and a live-state
fingerprint; apply rejects stale previews and requires separate options for replacing
modified files and removing files added since the checkpoint. Symlinks and type
obstructions are never overwritten. A private rollback journal restores the
pre-restore state if any operation fails.

Harness-state backup/restore remains separate because it protects current-privacy-epoch
DSH state rather than workspace source files. Format 4 binds manifests, catalogs,
receipts, and crash journals to provider-history privacy epoch 1. Creation requires the
current Harness-home receipt before backup-root creation or Keychain access; restore
requires a format-4 snapshot and a current-or-absent destination. Older/mixed backup or
runtime-migration state is a typed foreground-recovery condition, not an empty catalog.
`StateBackupManager.privacyEpochPreflight` and
`RuntimeMigrationCoordinator.privacyEpochPreflight` are detection-only: they open the
owner-private namespaces without following links, request no Keychain item, and create
nothing. The mutating coordinator may be constructed only after the home and backup
gates; a clean missing Migration directory is created lazily when current state is first
persisted.

First-use legacy import never writes into the live Harness home. It streams reviewed
entries into a private sibling directory, fsyncs each file, nested directory, strict
bounded ownership receipt, staging root, and containing directory, then installs the
whole home with one same-directory rename. Relaunch validates and resumes a complete
staging transaction, or boundedly removes an incomplete one before rebuilding it.
All expensive launch prerequisites are serialized on a utility queue rather than
AppKit's main thread: signed-bundle checks, official Ollama signature resolution and
bounded descriptor-relative model-store traversal, home preparation, plugin audit,
Skill materialization/hashing, MCP executable and reviewed-entry-point hashing, and
the four real sandbox probes. Bundle, Ollama, and complete Harness preparation use
fixed 30/20/60-second monotonic passes; nested operations share the pass deadline and
cannot reset it. Each sandbox probe has an additional five-second ceiling. The visible
startup state remains on main; stop/quit cooperatively cancels the active pass and
retains its exact worker token until the submitted closure has fully returned. The
public stop barrier cannot publish or authorize restore/backup/update while that
closure can still mutate state. Immediately before `Process.run()`, main performs only
the startup-generation check and cheap captured path plus owned-Ollama PID/listener
identity revalidation.

## Performance and resource ownership

Context and output deliberately use different ownership scopes. For the selected
on-device Ollama route, context is app-wide adapter/model metadata: readiness performs a
revision-checked replacement of the reserved `ollama` profile with one selected model
and the exact app-owned endpoint, then mutates only that model's live performance
fields, re-reads the committed values, and reloads provider topology before exposing
the main Harness surface or scheduler. The host performance plugin then
calls `ctx.llm.resolveModelInfo(provider, model, signal)` for every matching actual
`agent/request` and fails closed before provider I/O unless the resolved context matches.
This makes DSH compaction and request-context records use the selected capacity rather
than merely exporting an environment hint.

The Fast/Balanced/Deep values and reviewed reasoning metadata belong only to exact
`qwen3.8:27b-mlx`. An admitted alternate model is normalized to a fixed 8,192-token
context, 2,048-token output, 120-second keep-alive, concurrency one, and no reasoning
field. This normalization occurs during selection decoding and topology synchronization
so an old settings document cannot re-enable a qualified-Qwen profile for an unknown
model.

Output is per session for the exact synchronized on-device route. Native-created,
main-surface-created and scheduled sessions carry an admitted profile identity; forks and
subagents inherit the admitted parent profile. The plugin lets downstream route
middleware resolve first and then returns the profile's conversation `maxTokens` only
when that resolved route exactly matches the locally synchronized model. Cloud and LAN
routes retain the provider middleware's output proposal byte-for-byte, so a local tuning
profile can never exceed a remote model's hard capacity. Concurrent local sessions can
therefore have different output caps, but DSH exposes no per-request context field and
they share the one adapter context. The selected local model's configured `maxTokens`
also supplies a safe default to DSH calls outside the conversation waterfall.

Keep-alive and Ollama runner allocation remain server concerns. The app-owned Ollama
environment enables one loaded model, one parallel generation, a bounded queue,
disabled cloud/history/pruning behavior, and the selected server defaults. Flash
Attention and q8 KV cache are enabled only for the exact release-qualified Qwen route;
Compatibility models inherit neither. Native Ollama API paths
send applicable request hints. A separately running Ollama service is never adopted
and can coexist, but may consume duplicate model memory. Cloud and LAN routes are not assigned the
local context profile and retain provider hard limits. Performance Center samples
host/Ollama state and recent latency/throughput telemetry; it does not claim a measured
benchmark before measurement.

The DSH observer can persist only a versioned aggregate record: bounded route labels,
profile, start/completion/first-token timing, output-token count/source, outcome, and a
coarse failure category. Both writer and reader enforce an exact-key schema, owner-only
regular-file storage, 100 rows, 24 hours, and 256 KiB. Content-bearing fields are not
representable. Clearing history unlinks only the fixed validated spool node and
recreates an empty private file.

## Scheduler and owned-process lifecycle

The launchd helper is an inert wake detector, not a resident Harness service. It opens
the fixed schedule file with no-follow/nonblocking flags, requires owner-only regular
storage and private ancestors, validates the supported schema within 5 MiB/1,000
schedules, and launches the app only when an enabled task is due. A background launch
waits for all prepared/running work to finish and then consumes a one-shot idle callback
so recursive quit cannot occur.

DSH/Ollama stop and restart requests are serialized around one captured process
generation. References and Ready state remain owned until every exact process actually
exits; a premature stopper completion fails closed. Overlapping restart requests
coalesce to one replacement, while a later explicit Stop or Quit cancels that
replacement. Stale port and termination callbacks cannot publish an old generation.

Unexpected owned-Ollama exits have a separate bounded circuit: at most three
backed-off replacements in 60 seconds, reset only after a complete stable-readiness
window. Exhaustion blocks inference with a repair message. An explicit Stop, provider
transition, thermal trip, or Quit invalidates any delayed callback before the
exact-process stop barrier runs.

## State, secrets, and release chain

Private app state lives under `~/Library/Application Support/Local Harness`; DSH uses
an app-owned Harness home. Keychain holds credentials. Operational documents use
owner-only permissions and atomic replacement where implemented.

Release assembly bootstraps its verifier from a system-checked Node digest and checks
the deterministic `VendorRuntime.inventory.json` before and after copy. It derives
the exact unsigned app Runtime from that reviewed inventory, the sanitizer contract,
drops the identity-checked npm-tree DSH self-copy and its executable link so there is
exactly one CLI/composition/preset discovery root, and adds exactly six local plugin
source sets. Only the enumerated Mach-O files may change
during inside-out signing; the final per-entry Runtime inventory and every inventory
artifact digest are bound into the archive release manifest. Archive qualification
re-derives the unsigned mapping and scans the extracted signed Runtime byte-for-byte.
The build also creates an SBOM and can notarize/staple when valid Apple credentials
are supplied. Public updates require a newer build with the same bundle identity and
Developer Team, a valid nested signature, and Gatekeeper acceptance. Private builds
have no Developer Team and cannot enter that path. Their separate external installer
requires current candidate-bound full qualification, a matching persistent private
certificate/designated requirement, exact bundle and byte-tree proofs, stopped app
processes, an immutable owner-private pre-swap journal, an atomic APFS exchange,
post-swap proof, and a durable private receipt. A post-proof failure swaps back; a
receipt write whose rename/fsync outcome may be durable preserves the swapped pair and
journal so read-only inspection can classify it without guessing. Explicit idempotent
resume/finalize operations complete interrupted transactions. Explicit cancel/retire
operations first fsync a lifecycle marker, then use descriptor-relative `RENAME_EXCL`
and parent-directory fsyncs to archive the exact stage and complete record directory.
Power loss at either rename is replayable, neither active app nor retained stage is
deleted, and later private installation remains blocked until the active transaction
is completely archived. Old archives remain on disk for owner review. Neither
installer executable is shipped inside the app, and the public updater remains
disabled.

The private receipt root is relative to the configured macOS login home, not a
hard-coded `/Users` prefix. A nonstandard home is admitted only after canonical
no-symlink resolution and a full ancestry proof: every component is a real directory,
is root/current-user-owned, and is not group/world writable; the home, `Library`, and
`Application Support` are current-user-owned, and the nonstandard ancestry is free of
extended ACLs. The model-tool sandbox independently derives the POSIX account home
under the same ancestry policy and emits exact denials for Keychain, messaging, mail,
browser, cloud-credential, and SSH data there while retaining the broad conventional
`/Users/<name>` denials.
