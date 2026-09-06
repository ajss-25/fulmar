# Operations and recovery — Fulmar 1.2.36 build 156

## Everyday operation

Open Fulmar from the Dock. **Ready · Private runtime** means the app-owned DSH
process passed token, origin, nonce, and PID checks; it does not by itself mean the
selected inference provider is local. Check the model/boundary label:

- **On this Mac** — Ollama/Qwen; Strict Local loopback policy.
- **Local network** — one consented private-network origin.
- **Cloud** — one consented HTTPS provider origin.

When switching back to an on-device model after a warm or interrupted run, macOS may
need tens of seconds to reclaim the previous model/GPU allocation. Fulmar waits for up
to 90 seconds for its exact signed Ollama child to become ready, while doing no model
work during that wait. The wait is cancellable and finishes immediately once ownership
and readiness are verified; it is not a request to run the model harder.

Use the full Harness window for agent work or `Option-Space` for Quick Chat. Both use
the same DSH runtime and authoritative Workspace. **Copy Last Reply** copies only the
latest assistant text. **Export Conversation** offers recommended detected-secret
redaction, structure-only export, or an additional confirmation for full text.

When a task includes a public HTTPS link, the model may call `web_fetch` and Fulmar
shows the exact normalized page for approval. Approve only pages you intend to place
into the task context. Fulmar sends no browser cookies, follows no redirects, and
rejects private-network targets. If retrieval is denied or fails, the model should
report that result; it must not retry with Bash or curl. General web search is not
available until a separate provider is configured through a future qualified UI.

## Choosing a provider

1. Open **Models & Providers** and refresh the live Harness catalog.
2. Configure a provider through **Provider Settings**. Fulmar stores supported
   key references through its Keychain service. Saving or verifying a credential
   leaves Fulmar in a zero-inference provider control plane; it does not select a
   provider/model or send a model request.
3. Select a model. For network/cloud routes, verify the exact scheme, host, and port
   in the warning; cancel if it is unexpected.
4. Choose **Use for New Tasks**. The app updates Harness and native state as one
   transaction, restarts the runtime, and starts fresh sessions.

For a custom provider, the native editor supports exactly three reviewed protocols:
**OpenAI Chat Completions**, **OpenAI Responses**, and **Anthropic Messages**. Enter
each model on its own line as:

`model ID | display name | text,image | context tokens | max output tokens`

Use `text` instead of `text,image` for a text-only model. Audio and video are not
supported on this authoring path and are rejected. Context must be 1,024 through
16,777,216 tokens, and maximum output must be 256 through that model's context limit.
Record the exact endpoint model's real supported values. These fields are capabilities,
not a way to make a server accept a larger request. Saving writes the profile into
DSH, re-reads the live settings, and fails the transaction unless the provider,
models, capabilities, context, and maximum-output values round-trip exactly. That is
configuration verification only: no endpoint request is made until a test task runs.

Credential mode requires an `apiKeyEnv` bearer-style API-key reference; store its
value through Fulmar's credential service. Explicit no-authentication mode is limited
to literal loopback, RFC 1918, and IPv6 ULA addresses and suppresses Authorization and
API-key headers. It is rejected for hostnames and cloud origins. Custom profiles cannot supply
arbitrary request headers or query parameters, a proxy, a custom certificate
authority, or mutual TLS. Plain HTTP is permitted only for a literal loopback or
private address; public origins must use HTTPS.

For OpenAI Chat Completions and OpenAI Responses, enter the API prefix before the
SDK-appended resource path (commonly `/v1`). For Anthropic Messages, the base must
stop before `/v1` because its SDK appends `/v1/messages`; Fulmar rejects the doubled
path before mutating credentials or settings.

A user-declared loopback or private-address endpoint is a **Local network** route, not
an app-owned **On this Mac** route. The user owns its server lifecycle and capacity.
It does not receive Fulmar's managed Ollama process ownership, model-size/RAM
admission, Metal/MLX tuning, thermal throttling, or automatic unload protections.

Do not expect an open local conversation to continue automatically after switching to
DeepSeek, OpenAI, Anthropic, or another endpoint. Use Task History to reopen it
deliberately. If a switch fails, the previous route should remain active; if rollback
is reported incomplete, restart the app and review **Models & Providers** before
sending data.

No live cloud route is usable without an appropriate credential and provider account.
Provider billing, retention, rate limits, terms, and outages are outside Fulmar.

If the saved local model is absent, task admission remains closed and the recovery
screen offers **Choose Installed Local Model**. Fulmar reads only the app-owned Ollama
catalog and bounded `/api/show` metadata before committing the choice. It does not
select row zero, silently substitute a model, or pull/download/delete weights. If no
suitable model is listed, install one through Ollama and refresh.
Alternate thinking-capable Ollama models are rejected: Fulmar does not infer an
unreviewed model's reasoning dialect or guess how to disable it.

## Workspace, history, and recovery

The app uses one private Application Support `Workspace`; interactive and scheduled
tasks no longer create a second Quick Chat directory. Use Task History to:

- rename a task;
- branch from its latest completed sequence into a new task;
- archive it from active history without deleting the underlying session;
- export Markdown or JSON without attachment bytes; or
- continue it after the current provider/model and boundary are revalidated.

Before a new main task or Quick Chat turn, Fulmar captures an automatic
workspace checkpoint. If that checkpoint cannot be captured safely, the turn is
paused rather than proceeding without recovery coverage.

Use **Workspace Recovery** to make a manual named checkpoint or preview a restore.
The preview lists added, modified, and deleted recoverable files. Replacing a modified
file and removing a newly added file are separate opt-ins. A changed preview becomes
stale and must be regenerated. Symlinks, type conflicts, corrupt stored data, and
Workspace identity changes block the restore. DSH is stopped during apply and
restarted afterwards; a failed apply attempts to restore the exact pre-apply state.

Generated/dependency trees, likely secret paths, files above 16 MiB, workspaces above
the configured 256 MiB recoverable-content limit, and unsupported filesystem objects
are not checkpointed. Workspace Recovery does not replace source control.

## Skills

Open **Skills**, select an inert bundle, inspect its description, fingerprint, file
count, bytes, and risk flags, then import it. Enable it for the current Workspace only
after review. Choose one external-disclosure policy:

- **Local only** — never materialized for a cloud/network route.
- **Ask every time** — one-session confirmation before external activation.
- **Allowed** — persistently permitted for external sessions while fingerprint and
  Workspace identity remain unchanged.

Use **Verify** after any source update. A mismatch revokes use; re-import and review
the new bytes. **Apply & Restart** materializes only the permitted reviewed subset and
forces a fresh Harness session.

## MCP servers

The MCP center accepts only a local stdio server with an absolute executable,
literal arguments, reviewed runtime entry-point files, project-relative working
directory, credential references, provider/boundary enablement, disclosure categories,
and explicit limits. Review, approve, revoke, and remove are native operations.

Every MCP tool call still requires native approval. Treat the displayed arguments and
data destination as the real request; deny anything unexpected. Executable,
interpreter, reviewed file, configuration, project identity, or provider-policy
changes revoke trust.

Remote HTTP/SSE MCP is intentionally disabled. Do not work around this with a shell,
port-forwarder, or generic network wrapper; that bypasses the reviewed privacy model.
An approved local server remains third-party code and should be sourced and audited
accordingly.

## Schedules

Schedules can be one-time or recurring and execute through the same DSH conversation
service and Workspace as interactive tasks. A non-local schedule requires explicit
unattended consent for its exact stored route/boundary; route drift blocks execution.
Results/errors are owner-only files in Task Inbox.

While Fulmar is open it checks overdue work itself. Background scheduling is
optional and off by default; enabling it registers a lightweight launch agent that
wakes the app when required. It does not keep Qwen loaded. Sleep may delay a task; an
overdue check runs after wake rather than discarding it.

The scheduler has an application-wide admission latch. Backup, restore, provider/model
changes, security changes, update installation, and Quit close it synchronously before
their first wait. Run Now, due timers, background wakes, queue drains, and late
workspace-checkpoint callbacks remain inert until a newly authenticated provider
topology explicitly reopens scheduling.

## Local performance and resource use

Exact `qwen3.8:27b-mlx` is Fulmar's release-qualified local route. Use **Balanced ·
48K / 8K output** for routine 27B work on the 48 GB Mac. **Fast · 32K / 4K output**
lowers latency and output budget. **Deep · 64K / 16K output** increases KV-cache memory
and can be much slower; use it only when long context is needed. The selected local context is app-wide
for the exact Ollama model; per-task and scheduled profiles can choose different output
caps, but cannot assign different contexts concurrently to the same route. All profiles
serialize local generations one at a time.

Local Qwen sends an explicit reasoning-off value by default. This is materially
different from omitting the setting: omission lets Ollama choose the model's default,
which can delay the first tool call and increase heat. Enable **Reason deeply** only
when the extra inference time is wanted; Fulmar then sends the model's reviewed High
effort. This local default does not rewrite DeepSeek or other cloud routes.

Every other installed Ollama model is unqualified. **Use Compatibility Mode** first
verifies that its current metadata advertises completion, tools, no model-specific
thinking mode, and context metadata between 8,192 and 1,048,576 tokens. If admitted, Fulmar forces a text-and-tools-only
8,192-context / 2,048-output profile, disables Fast/Balanced/Deep and reasoning
controls, and rechecks the model before route startup. Compatibility is a conservative
minimum contract, not a promise that every DSH agent works with that model.

The deterministic 8/16/24/32/48/64/96 GiB matrix verifies this admission formula and
the separate exact-Qwen 48 GiB floor. It is not physical testing on seven Macs.
Current physical local-inference evidence is limited to the documented 48 GB Apple M5
Pro, so operators on other Apple-silicon generations or memory tiers must treat
latency, peak memory, thermal behavior, and output quality as unqualified.

Before interactive or scheduled sessions are admitted, Fulmar replaces the
reserved `ollama` profile with one exact selected installed model and this launch's
app-owned endpoint, then revision-checks that model's context/output defaults and
reloads the route catalog. Unreviewed headers, stale ports, and sibling routes cannot
survive in this reserved profile. Every matching agent request then calls DSH exact-model resolution; a
context mismatch fails before Ollama network I/O. The session-bound output profile is
written as the final `maxTokens` proposal after route middleware only for that exact
local route. Every inference runtime is also locked to the one native-selected
provider, so an old task cannot silently cross to another provider that happens to
share an endpoint. Remote routes retain their provider's proposed output limit and may
select another model exposed by that same verified provider; switching providers still
requires the full stop, consent, synchronize, and fresh-runtime transaction.

Fulmar always starts the Ollama process it uses on a fresh loopback port and applies
one loaded model plus the selected server limits. Flash Attention and q8 KV cache are
applied only to the exact release-qualified Qwen manifest; Compatibility models do not
inherit those model-specific settings.
It accepts only the official strict macOS signature, revalidates the canonical child
identity, and runs it with private HOME/TMP, read-only access to the validated existing
model store, loopback-only networking, and cloud/history/pruning disabled. It never
seizes or adopts an existing service. A separately running Ollama can coexist,
but unload it if two services would otherwise hold duplicate model weights.
Native Ollama operations send request hints where supported. Cloud and LAN routes are
not rewritten with local context or output settings; their provider capabilities remain
authoritative. Performance
Center distinguishes configured DSH limits from measured memory, prompt ingestion,
generation rate, and TTFT.

Launch at login is off. Opening Local Models starts the lightweight app-owned service
on demand; Qwen weights load only when used. Unload-on-quit is on by default, and quit
terminates the exact Ollama PID the app started without touching another service.
Fulmar never downloads or removes models; those operations remain in Ollama.

If the app-owned Ollama process exits unexpectedly, Fulmar stops the remaining exact
runtime generation before retrying. Recovery waits 1.2, 3, then 8 seconds and permits
no more than three attempts in 60 seconds. Further exits leave the runtime blocked so
a damaged or incompatible Ollama install cannot create an endless process/heat loop.
Quit, thermal protection, provider changes, and an explicit service stop cancel any
pending retry.

## Browser, attachments, and downloads

External links show their exact HTTPS address before opening in the default macOS
browser. That browser is outside Fulmar and may use its normal cookies,
extensions, DNS, and network configuration. The agent cannot control it.

A download initiated by Harness is staged privately and assessed before preview/save. Review any
content/MIME warning. Active, executable, installer, archive, or suspicious content
is never equivalent to a passive artifact simply because of its name. macOS
quarantine remains attached to saved output. Do not disable quarantine to make a file
open.

## Permissions and first-launch decisions

The app remains usable for typed local work if Screen Recording, microphone, speech,
notifications, launch at login, or background scheduling are denied. Grant each only
when using the corresponding feature. Appshot cancel/denial must leave no capture
file. Dictation requires on-device recognition.

If legacy credentials are detected, **Move and Verify** is recommended. Cancellation
or failure leaves the source untouched. Do not manually delete it until read-back
verification succeeds.

Keychain-backed provider secrets have a separate private metadata marker under the
application-support root. Routine catalogue checks with no pending transaction read
only that marker. After an interrupted credential mutation, recovery performs one
bounded noninteractive Keychain read to reconcile its private journal; authorization
failure is surfaced to Models & Providers and never summons a background password
prompt. The local Ollama marker never launches the credential helper. When an older
build left an exact Fulmar Keychain item without
its marker, Fulmar adopts and replaces it atomically when the current signing identity
is already authorized. A changed development signature fails immediately without a
background password prompt and preserves the old item and marker. If macOS still
requires one-time authorization, remove only that exact legacy Fulmar credential in
Keychain Access, then save it again in **Models & Providers**. Do not delete or recreate
unrelated Keychain items.

## Diagnostics and incident response

Diagnostics reports runtime versions, endpoint state, and redacted recent logs. If
DSH does not reach Ready:

1. confirm bundled Node `22.23.1` and DSH `0.1.1-rc.1`;
2. use **Restart Local Services** once;
3. keep the restrictive boundary enabled rather than hiding a confinement failure;
4. revoke recently changed Skills, MCP servers, or plugins;
5. restore the named DSH safety snapshot if startup migration recovery appears.

For unexpected provider egress, stop sending prompts and quit the app, which
terminates owned DSH. Reopen on Ollama/Strict Local, inspect exact origin consent,
revoke third-party integrations, preserve redacted diagnostics, and restore state or
Workspace only after previewing the relevant checkpoint.

Logs are pattern-redacted, not guaranteed secret-free. Inspect them before sharing.
If Workspace restore reports rollback failure, do not run further agents in that
directory; preserve it, make a filesystem copy outside the app, and inspect manually.

## Harness-state backup and app rollback

Harness-state backups protect current-privacy-epoch DSH state and exclude classified
secrets; Workspace Recovery protects source files. Use the correct system. State
restore quarantines current DSH state before copying a snapshot and rolls it back on
copy failure. Backups use authenticated manifests, receipts, crash-recovery journals,
bounded no-follow traversal, private storage, and a stopped-runtime permit revalidated
at namespace commit boundaries. Format 4 and every transaction are bound to provider-
history privacy epoch 1. A pre-format-4/mixed backup root or old runtime-migration state
stops startup and backup access for foreground recovery; do not rename it into a fresh
catalog. Keychain credentials are unaffected.

For an app update problem, restore the retained `.app` and matching pre-upgrade DSH
snapshot as described in [Update and rollback](UPDATE_AND_ROLLBACK.md). A fully
qualified private candidate is installed only with `make private-install-qualified`;
`make private-rollback-status` is read-only and classifies the exact journal, active
app, stage/archive, optional frozen candidate, and receipt. It prints one precise next
operation when recovery is incomplete: `make private-recovery-resume`,
`make private-recovery-finalize`, `make private-recovery-cancel`, or
`make private-rollback-retire`. If status reports an interrupted record write, first run
`make private-recovery-reconcile`; it archives the exact owner-private temp without
deleting evidence and restores only a repeatedly proven record. The commands repeat stopped-process and byte/signature
proofs under the installer lock. Cancel/retire archive the exact stage and complete
record directory with durable exclusive renames; they delete neither app. Retained
archives consume disk and require later owner review. This local atomic workflow is
separate from the disabled public updater and never relaxes the Developer ID,
notarization, same-team, or clean-Mac gates.
