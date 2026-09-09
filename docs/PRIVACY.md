# Privacy model — Fulmar 1.2.36 build 156

## Data boundaries

Fulmar distinguishes three destinations and never treats the model name alone
as a privacy guarantee:

| Boundary | Example | Runtime network policy | User decision |
| --- | --- | --- | --- |
| On this Mac | Ollama/Qwen on `127.0.0.1` | Loopback only | Default |
| Local network | User-declared private OpenAI-compatible endpoint | One exact private-network origin | Explicit consent |
| Cloud | DeepSeek, OpenAI, Anthropic, or other internet endpoint | One exact HTTPS origin | Explicit consent |

Changing boundary restarts the authenticated runtime and starts a fresh main Harness
session; Quick Chat discards its current session. Existing history is retained but is
not automatically injected into the new route. Reopening an external task requires a
fresh route and boundary check.

Consent is bound to provider ID, boundary, scheme, host, and port. Changing the
endpoint invalidates it. An unknown provider fails closed as cloud. A cloud model may
receive prompts, attached files/images, conversation context, approved skill
instructions/resources, tool arguments/results, knowledge context, and local MCP
results for that task; the confirmation text is therefore broader than “send this
message.”

## Data flow by feature

| Feature | Destination | Persistence and controls |
| --- | --- | --- |
| Main sessions and tools | App-owned DSH on authenticated loopback, then selected inference route | DSH local state; exact provider boundary and native approval UX |
| Quick Chat | Real DSH session using selected route | Transcript in memory plus DSH session; new session on route switch; copy/export are explicit |
| Scheduled prompts | Selected route, possibly unattended | Local definition/result files; external schedules need specific unattended consent and use the authoritative Workspace; results have bounded retention and explicit delete controls |
| Provider credentials | macOS Keychain | Values remain this-device-only. A private per-account transaction record stores the reference, type, operation, and SHA-256 equality digests—never credential bytes—until create/replace/adopt/remove is committed or recovered; configuration metadata stores references only. |
| Skills | Private quarantine, then read-only active catalog | Per-Workspace fingerprint and local-only/ask-every-time/allowed external disclosure |
| MCP | Approved local stdio child | Trust metadata only; credential references; every tool call requires native approval; remote MCP disabled |
| Workspace recovery | Application Support outside the Workspace | Bounded local content checkpoints; generated trees and likely secret files excluded |
| Conversation export | User-selected local file | Markdown/JSON; no attachment bytes; redaction choice shown before save |
| Appshot/OCR | In-memory review and Apple Vision on this Mac | Only reviewed final image persists after Add to Chat; timed retention |
| Dictation/speech | Apple on-device speech APIs / local synthesizer | Input text only; no app-owned audio file |
| External link | Default macOS browser after confirmation | Leaves Fulmar; browser profile/network policy belong to the user's browser; no agent bridge |
| Approved page fetch | One exact public HTTPS URL after per-call approval | No cookies/credentials/referrer, no redirects, public-address DNS/TLS checks, textual content only, 2 MiB cap; result becomes task context |
| Harness download | Private staging, then explicit destination | Byte-limited, signature/MIME checked, quarantined, digest revalidated |
| Logs and support report | Application Support / explicit clipboard copy | Private rotated logs buffer complete per-stream lines before redaction; reviewed credential/token/private-key patterns are removed. Copy Support Report reapplies the redactor and removes private home/runtime paths. Prompt bodies remain excluded from the privacy ledger; redaction is best effort and the user must review before sharing. |
| Performance history | Application Support | At most 100 aggregate rows/24 hours/256 KiB; exact schema excludes content and secrets; user-clearable |
| Harness backups | Application Support | Secret-classified files excluded; Keychain never copied |

### Provider-error retention boundary

The client-security bridge version 1.2.0 replaces provider-owned error messages,
codes, request identifiers, URLs, and paths with a finite app-owned diagnostic at model
preparation and stream boundaries, before DSH retry and `turn/end` persistence. It
preserves only an allowlisted category plus a
validated HTTP status and bounded retry delay. The Host API sanitizes ordinary and
subagent legacy history before transport. A second browser boundary sanitizes legacy
live/replayed `assistant/chunk`, `llm/retry`, `turn/end`, compaction, and Host
agent-error frames; it synchronously clears and reloads any already-open pre-bridge
window under a fixed resident-session cap. Native Task History and its transcript export
project only direct human/model text message events; provider-failure events are not
exported. DSH's separate raw Harness-log download is fail-closed because it exports the
stored JSONL bytes verbatim; use Task History transcript export instead. The support
report does not read DSH session files.

Provider-history privacy epoch 1 closes the retained-home side of this boundary before
runtime admission. A v1/v2 receipt or receiptless `HarnessHome` is moved as one opaque
directory into authenticated recovery; Fulmar does not enumerate or parse its child
namespace. The user may copy only exact bounded `O_NOFOLLOW` settings files, or start
clean. Sessions, storages, attachments, profiles, Skills, and unknown provider state
remain only in the preserved home. A genuinely absent app home never imports `~/.dsh`.
Browser replay sanitization remains defense in depth, not a substitute for this durable
epoch boundary. Historical preserved copies are still sensitive and must not be
published or attached to an issue.

Harness backup format 4 is the first format bound to this boundary. Every authenticated
manifest, catalog, publication receipt, create/delete journal, and restore journal
contains `providerHistoryPrivacyEpoch: 1` and is decoded with an exact schema. Backup
creation first validates a v3/epoch-1 Harness-home receipt, before creating backup
storage or requesting the Keychain authentication key. Restore accepts only a
format-4/epoch-1 snapshot and a live destination that is either absent or already
v3/epoch 1. Older or mixed backup roots and interrupted journals are preserved and
reported as requiring foreground privacy migration; they are never rediscovered into a
new catalog. Runtime migration state has its own exact version plus epoch field, so an
old pending backup identifier cannot silently become a current protected rollback point.

## Credential transaction privacy

Credential values remain in Keychain. Before create, replace, adoption, or remove,
the helper writes a bounded 0600 journal inside an exact 0700 directory and serializes
that reference with a per-account lock. The journal records identifiers,
operation/type, and SHA-256 equality digests so relaunch can choose only the observed
prior or committed state; it never stores credential bytes. A pending recovery may
read the exact Keychain item noninteractively. Authorization failure or an unexpected
third value fails closed and preserves the journal for repair rather than presenting
an unattended password prompt or overwriting the value. The journal is removed after
durable reconciliation; its digests are private derived metadata, not proof that the
record is safe to publish.

## Strict Local and exact-origin egress

Strict Local confines the DSH process, its native children, and confined tools to
loopback while denying common private stores. It does not disconnect macOS, terminate
an independently running Ollama service, protect against a compromised same-user
process, or make the user's separate default browser offline.

The app-owned Ollama instance is a separate constrained boundary. Fulmar accepts
only the strict official macOS signature and fixed identifier/team, binds the canonical
file identity to the listener-owning PID, gives it a private HOME/TMP, mounts the
validated link-free model tree read-only, disables Ollama cloud behavior, and applies
a sandbox that permits only loopback networking. Its internal MLX/Metal runner uses a
dynamic loopback port, so the Ollama sandbox necessarily permits loopback connections
beyond the public app-owned API port. A compromised signed Ollama build could therefore
probe other loopback services, but cannot use this profile for LAN/internet egress or
read arbitrary files in the user's home directory.

PID/listener proof occurs before the origin is exposed and around readiness; ordinary
HTTP does not authenticate the accepting PID on every later prompt connection. A
targeted hostile same-UID process could theoretically rebind the random port after the
owned child exits and before shutdown is observed. This is an explicit residual under
the trusted-account boundary, not a per-request PID-authentication claim.

Selecting a consented network/cloud route intentionally turns off loopback-only mode
for the inference transport, but it does not provide general internet access: the
preload allowlist contains one normalized origin for the active provider. Local MCP
children remain stdio and confined; remote MCP transports are not enabled.

The external inference transport accepts only a normalized guarded Fetch request. It
forces redirects to be returned to the adapter instead of followed, rejects
caller-supplied Host/authority, resolver, agent, dispatcher, socket, and TLS-trust
overrides, keeps platform certificate verification, and bounds the aggregate response
at 16 MiB. Direct external raw TCP/TLS/HTTP(S)/HTTP2 access is denied. Exact
literal-loopback HTTP remains available for the reviewed Ollama route.

An approved page fetch does not reuse conversation-provider consent. The model must
name one URL through `web_fetch`; the Harness approval sheet discloses the normalized
URL for that call. A signed adapter receives a short-lived exact-host capability from
the preload. HTTPS on the standard port, public DNS/TLS addresses, no embedded
credentials, no redirects, no browser cookies, textual media and a 2 MiB body cap are
enforced. The capability ends with that request. General search is not shown when its
separate provider is unavailable, and the model is instructed not to retry through a
shell or language runtime. Approved page text can contain hostile instructions and is
sent to the selected model as tool output; approval is an egress decision, not a claim
that the page is trustworthy.

The pinned DeepSeek adapter is privacy-hardened not to create or transmit the
upstream stable anonymous installation identifier. The guarded inference transport
also removes both `x-deepseek-harness-user-id` and the internal
`x-deepseek-harness-session-id` from provider requests as a second boundary check.
Providers still receive the request content the user approved, authentication and
protocol headers, normal network metadata, and a product/version user agent.

## Skills and MCP disclosure

An enabled skill may contain instructions or reference material that becomes model
context. Local-only skills are withheld from external routes. Ask Every Time approval
lasts only for the current app session. Persistent external allowance remains bound
to the reviewed fingerprint and Workspace.

An approved MCP server executes locally, but its tool arguments and returned material
may be visible to the active model. The MCP policy records data kinds, destination
classification, and exact provider boundaries. Credentials pass by named reference
through a reduced child environment; they are not stored in MCP JSON or argv.

Fingerprinting and native approval do not establish that code is benevolent. The user
must review and trust the executable and entry point. A fully compromised local
account can bypass application-level privacy controls.

## Retention and deletion

- Appshots: 7 days by default, configurable to at least 1 day.
- App-managed attachments: configurable retention, with a 30-day preference.
- Harness WebView cookies/cache: memory-only and cleared on quit or through Settings.
- Logs: size-rotated current/previous private files.
- Credential transaction journals persist only while reconciliation is pending;
  successful commit/recovery removes them. A failed-closed journal remains privately
  until repair.
- Performance history: at most 100 records, no record older than 24 hours, and at
  most 256 KiB total. **Clear Performance History** replaces only the fixed app-owned
  spool with a new empty owner-only file.
- Automatic workspace checkpoints: up to 12, within the total checkpoint/storage
  limits; oldest automatic entries rotate first. Manual checkpoints are not silently
  evicted.
- Task Inbox: newest 2,000 results, no more than 256 MiB total, and no result older
  than 30 days. **Delete Result** and **Clear Inbox** remove private result files after
  confirmation; schedules themselves are unchanged.
- Task archive: hides the task durably; it is not deletion.
- Automatic application rollback copies: the exact rollback created by the current
  verified update plus the two newest earlier valid automatic copies. Manually named,
  invalid, linked, foreign-owned, signature-mismatched, or raced recovery apps are not
  automatically removed.
- Schedules, notes, activity, privacy events, trust records, DSH history,
  backups, and manual recovery checkpoints persist until explicitly removed or
  replaced by their documented retention/restore workflows.

Performance rows may contain provider/model labels, profile, timestamps and durations,
time-to-first-token, output token count/source, completion/cancellation/failure state,
and a coarse failure category. The writer and reader reject every other field,
including prompt, response, raw error, task/session, workspace, tool, URL, header, and
credential data.

## Backups, checkpoints, exports, and secrets

Harness backups and workspace checkpoints exclude known credential/environment names,
private-key/certificate extensions, and other classified secret paths. Workspace
checkpoints also omit generated dependency/build trees. Keychain values are never
included.

Harness backups are integrity-authenticated so Fulmar can detect tampering, but they
are not encrypted archives. They may contain chats, attachments, and durable
tool-output spills retained by Harness. Keep backup files private and do not publish
or attach them to an issue. Authentication proves integrity and origin; it does not
make their contents confidential from someone who can read the backup files.

These are path-based protections. A secret inside an innocently named source or chat
message cannot be classified reliably. Detected-secret export redaction and log
redaction are best-effort patterns, not a mathematical guarantee. Review any file
before sharing it outside the Mac; choose structure-only export when transcript text
is unnecessary.

## External communication not covered by inference consent

Confirmed external links use the default browser and are outside Fulmar's
network boundary. Developer operations such as
fetching dependencies, Apple notarization, or checking for a verified update can
contact external services and are outside a model request. The 1.2.36 candidate
does not claim that live DeepSeek, OpenAI, Anthropic, or custom cloud requests were
tested unless separate credentialed evidence is recorded in the test plan.

## Apple privacy-manifest scope

The current source does not contain `PrivacyInfo.xcprivacy`. This is an explicit
review state, not evidence that Fulmar has no privacy-relevant behavior. Apple's
current required-reason API declaration applies to iOS, iPadOS, tvOS, visionOS, and
watchOS rather than macOS, while privacy-manifest data-collection declarations cover
all Apple platforms. The present release plan is direct Developer ID distribution,
not an App Store Connect submission. The absence of a manifest therefore is not being
used as a substitute for this privacy notice or treated as proof that Apple has
reviewed the data model.

Before an App Store route, SDK change, or Apple policy change, the owner must repeat
an executable-by-executable and third-party-SDK privacy-manifest audit and have the
result reviewed. An empty manifest must not be added merely to make the bundle look
complete; any declaration has to match actual collection, tracking domains, and API
use. See Apple's current [privacy-manifest file documentation](https://developer.apple.com/documentation/bundleresources/privacy-manifest-files)
and [required-reason API scope](https://developer.apple.com/documentation/bundleresources/describing-use-of-required-reason-api).
