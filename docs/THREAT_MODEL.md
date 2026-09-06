# Threat model — Fulmar 1.2.36 build 156

## Protected assets

- Harness conversations, task history, Workspace files, goals, plans, traces,
  schedules, knowledge, exports, artifacts, and recovery points.
- Prompts, attachments, skill material, MCP arguments/results, and model responses.
- Provider/API credentials, SSH identities, browser cookies, mail/messages, cloud
  configuration, and private keys accessible to the macOS account.
- Screen and microphone content.
- Provider consent, trust decisions, update identity, backups, and rollback material.

## Trust boundaries

The native app and its bundled signed helpers/runtime are trusted for the private
installation. Pinned DSH is trusted but prerelease. Ollama and the logged-in account
are trusted only to the degree required by this single-user deployment.

Community DSH plugins, imported Skills, MCP executables, model output, web content,
downloads, update archives, configured external endpoints, and arbitrary services on
local ports are untrusted until the specific control for that boundary permits them.
User approval narrows authority; it does not turn third-party code into trusted code.

## Threats and controls

| Threat | Controls | Residual risk |
| --- | --- | --- |
| Local page/process drives DSH | Random port/token, HTTP/WS authentication, peer/Host validation, bootstrap cookie, nonce/PID identity | Same-user process or compromised account remains powerful |
| Harness event flood exhausts memory or starves AppKit | 1 MiB frame and 1.25 MiB parser-buffer bounds, at most eight decoded mux events/8 MiB event-buffer ceiling, whole-turn event/text/tool/interaction budgets, 1,024-event main-actor queue, ordered 64-event drains, coalesced transcript rendering, and exact-session cancellation on overflow | A valid response at the configured limits can still be expensive to render or process |
| Replaced or compromised Ollama gains ambient user authority | Fixed official signature/team/identifier, canonical inode/CDHash binding, exact child PID/listener checks before exposure and around readiness, private HOME/TMP, validated read-only model store, loopback-only bind/egress sandbox, cloud disabled | A correctly signed malicious/compromised Ollama build can read admitted model/system/app files and contact unrelated loopback services needed by its dynamic runner architecture. After verification, a targeted same-UID process could theoretically rebind the random TCP port if the child exits before a prompt connection; raw HTTP cannot authenticate the accepting PID. A compromised same-user account/process is outside this deployment boundary. |
| Embedded UI navigates to attacker content | Exact-origin non-persistent WebView; external links redirected | Upstream UI executes within its authenticated origin |
| Private task is accidentally sent to cloud | Visible boundary labels, exact-origin consent, transactional switch, fresh sessions, route check on history continuation | User can intentionally approve the wrong destination or paste data manually |
| Saving an API key silently activates cloud inference | Credential activation returns to a fresh zero-provider-origin control plane with task admission closed; model choice, boundary review, and **Use for New Tasks** are separate | The user can still deliberately select and approve the wrong provider/model |
| Provider endpoint or credential reference changes after approval | Consent bound to provider/boundary/scheme/host/port and the exact Keychain reference name; edited endpoint/reference invalidates the grant; legacy origin-only grants are revoked | DNS/TLS and provider operations remain external dependencies; the reference name is non-secret metadata |
| Catalogue drift visually selects an uncommitted provider | Quick Chat restores only an exact transaction-committed route, never row zero; Send fails closed without that route; incompatible queued images are cleared and rechecked at send | User must explicitly select again after a provider/model is removed or renamed |
| Missing, legacy, or unfamiliar local model is silently substituted or receives unsafe Qwen settings | Explicit installed-model recovery chooser; no row-zero default or download; stored and legacy Hermes selections retain their exact tag with Compatibility/no-reasoning normalization; exact Qwen identity plus metadata gate for qualified settings; unknown models require bounded live completion/tools/non-thinking/context metadata and fixed 8K/2K text/tool Compatibility mode | An admitted alternate model remains unqualified and can behave differently during DSH agent workflows |
| History refresh mixes saved context into another model/effort | Active verified session route outranks the default during refresh; send rechecks route preparation; exact saved reasoning effort persists until explicit change | A deliberate model change starts a clean Quick Chat conversation |
| Provider correlates Harness installation/session IDs | DeepSeek adapter omits stable user/session fields; guarded Fetch strips both headers again | Provider still sees normal request/network metadata and its own account/API-key identity |
| Failed provider switch creates split state | One transaction for consent, DSH default, typed selection, and Strict Local; rollback and fail-closed egress | Incomplete rollback requires restart and operator review |
| One-way credential RPC applies before its response is lost | Re-describe write-only readiness after every set/remove; never promise value rollback; reconcile provable removal/not-removal, label replacement ambiguity, and restart an active uncertain/removed route into control-plane-only readiness | A configured readiness bit cannot distinguish old from replacement secret, so the user may need to replace/verify again |
| Process death interrupts a Keychain credential mutation | Fixed owner-only global lock; bounded private journal; exact before/target digests; post-mutation and post-metadata read-back; atomic metadata; idempotent recovery; explicit foreground adopt/replace/remove for an unexpected third value | Release-mode SIGKILL evidence uses a file-backed fake value store, not real Keychain or physical power loss; raw equality digests permit offline guesses of low-entropy values |
| Another unsandboxed process running as the same macOS user invokes or replaces a credential component | Agent/tool sandboxes deny the helper and private store; background calls are noninteractive. Legacy plaintext migration is an embedded mutually authenticated XPC service: the app pins the service's exact CDHash and designated requirement, the service pins the exact app peer, source/parent/lease cross only as file capabilities, the descriptor-read 74-module graph runs in JavaScriptCore, and no Node/helper pathname is launched. Service/helper designated requirements are equal solely to preserve Keychain ACL compatibility | The ordinary general-purpose credential helper still has no authenticated caller channel and can return Keychain bytes to another same-user process whose access is admitted by the item's ACL. That separate helper API remains outside the compromised-same-user boundary pending conversion of every runtime credential operation to authenticated IPC |
| Tool escapes Workspace | One canonical root, validated sandbox grammar, symlink/traversal/hard-link controls, minimal environment | `sandbox-exec` is legacy and must be retested on macOS updates |
| Tool tries to outlive its task | Runner-owned process group, parent-death monitor, bounded TERM/KILL, and direct `setsid`/`setpgid` denial | macOS has no entitlement-free job object; a hostile program can still attempt process-group detachment through alternate spawn APIs. Any survivor remains inside the inherited filesystem/network/private-store sandbox, but cleanup is best-effort outside the leased process group. Use a VM/container backend for hostile arbitrary binaries. |
| Plugin exfiltrates, steals credentials, or stalls trust review with hostile filesystem content | Block by default; descriptor-relative no-follow scan; fixed declaration/tree count, depth, path, file, aggregate-byte, and monotonic-time bounds; non-approvable identities for empty/oversized/link/special content; complete installed-content fingerprint; changed-code revocation; bounded private approval store; child egress/private-store guards | Approved plugin still runs code and can access authorized files; local filesystem calls are trusted to obey the kernel's descriptor and deadline semantics |
| Hostile mutable profile or historical DSH tree stalls startup, exposes retained provider errors, leaves a crash-partial live home, or races recovery | App-owned isolated home; exact v3/privacy-epoch-1 admission; absent homes never probe `~/.dsh`; historical homes and pre-epoch staged/published outputs move as opaque directory capabilities without child enumeration; only two exact bounded no-follow settings files can cross after explicit consent; authenticated format-1 journals upgrade deterministically to Start Clean; unknown/future staging is retained fail-closed; HMAC journal, fixed lease, fsynced receipt, atomic rename, and published-until-ack recovery | A selected settings file can itself contain sensitive provider configuration and remains user-approved data; local filesystem calls can still block in the kernel; a compromised same-user account remains outside the boundary |
| Signed-bundle, model-store, Skill, MCP, or sandbox launch preparation stalls the UI or completes after a stop | One serialized utility prerequisite worker; fixed 30/20/60-second monotonic pass budgets; descriptor-relative no-follow model scan; streamed Skill/MCP hashes; bounded child probes; stop awaits exact worker settlement; generation, path, and owned PID/listener identities are rechecked immediately before spawn | Security-framework and filesystem calls may remain inside an uninterruptible kernel operation until they return; a compromised same-user account remains outside the boundary |
| Malicious Skill injects instructions or leaks context | Inert bounded import, fingerprint, per-project activation, read-only catalog, cloud disclosure policy, fresh boundary sessions | Model can still follow harmful reviewed text; semantic safety is not proven |
| MCP executes arbitrary shell/code | Local stdio only, no shell command, exact executable/interpreter/entry-point fingerprints, provider/project binding | Approved executable may be malicious or contain dependencies outside fingerprint scope |
| MCP leaks secrets or floods runtime | Credential references, reduced environment, native per-tool approval, time/tool/output/reconnect limits, filesystem/network confinement | Allowed tool result can be sent to an allowed cloud model; denial-of-service within limits remains possible |
| Remote MCP expands egress invisibly | HTTP/SSE MCP intentionally disabled | Feature absent; future enablement needs a new threat review |
| External link or download attacks the app | Confirmed links hand off to the default browser outside the agent boundary; Harness downloads use private staging, content checks, quarantine, and revalidation | The user's default browser has its own cookies/extensions/network policy; parsing/previewing allowed downloaded formats retains platform risk |
| Model abuses page retrieval for SSRF, tracking, downloads, or an unapproved network fallback | Per-call exact-URL approval; HTTPS/443 only; public hostname and resolved-address checks; no redirects, cookies, credentials or referrer; textual MIME allowlist; 2 MiB cap; shell fallback prohibition; general search hidden when unavailable | An approved public page sees the user's IP and can return prompt-injection content; DNS/TLS ecosystem compromise remains residual |
| Capture leaks secrets | Explicit OS permission/action, password-app exclusion, memory-only raw image, crop/redact/review | User may capture a sensitive app not recognized by the exclusion list |
| Hostile workspace tree stalls or exhausts checkpoint capture | Descriptor-relative no-follow streaming walk; entry/depth/path/file/aggregate and one monotonic deadline budget; fixed-chunk hash/copy; bounded checkpoint catalog | A local filesystem call can still block inside the kernel; excluded/oversized/generated files are not recoverable |
| Recovery overwrites good work | Preview fingerprint, stale-preview rejection, separate overwrite/remove choices, symlink/type conflict rejection, transactional rollback | Excluded/oversized/generated files are not recoverable; disk failure can defeat rollback |
| Corrupt or hostile upgrade state is mistaken for a first launch | Owner-only/no-follow regular state, 64 KiB and schema bounds, consistency validation, durable atomic replacement; any malformed/link/public/oversized state blocks runtime startup without creating another backup | Disk or filesystem failure can require manual recovery from the authenticated backup catalog |
| Backup/checkpoint/export leaks secrets | Path exclusions, no Keychain export, owner-only files, optional transcript redaction | Innocently named files and arbitrary prose cannot be classified completely |
| Logs leak secrets | Token/labelled-secret/URL credential redaction, control stripping, rotation | Unlabelled secret text can remain |
| Malicious update replaces app | Nested signature, exact bundle ID, same Developer Team, higher build, Gatekeeper, backups/rollback | Ad-hoc private build cannot establish same-team update identity |
| Replaced app does not actually launch or power loss interrupts replacement | Durable authenticated phase journal; exact direct-child PID plus private nonce/socket; native acknowledgement only after authenticated runtime/provider health; bounded stop/rollback; deterministic replay or fail-closed recovery surface | **Open public blocker:** the source transaction still lacks two-real-Developer-ID/notarized/stapled clean-Mac power-loss and rollback evidence |
| Private local replacement installs stale, altered, or differently signed code, or power loss strands an ambiguous exchange/record write | Separate external installer requires current retained full-hardware evidence, exact source/archive/manifest/candidate proof, matching persistent private certificate and designated requirement, stopped app processes, no-follow byte-tree equality, an immutable fsynced pre-swap journal, one atomic exchange, post-proof, and a durable receipt. Physical proof classifies pre-swap/post-swap/committed states; explicit idempotent recovery completes them. Interrupted temp records are bounded and owner-private; explicit reconciliation archives their exact inode with `RENAME_EXCL` and reconstructs only repeatedly proven state. Cancel/retire fsync an immutable lifecycle marker, archive the exact stage and complete records, and never delete an active or retained app. Incomplete records/stages block later installation. | A malicious same-user race cannot be eliminated without a privileged immutable staging owner; retained record/app archives consume disk and require owner review; the private identity is not Developer ID or public trust evidence |
| 27B model exhausts memory or stalls | Fast/Balanced/Deep caps, one generation, one loaded model when app-owned, bounded queue/output, cancellation, unload-on-quit | Deep context remains inherently expensive and completion time is model/workload dependent |
| Frequent schedules exhaust disk or freeze Task Inbox | Result age/count/aggregate-byte retention after every append, private regular-file topology, metadata-only status count, off-main body decoding, confirmed delete/clear controls | Disk failure can still prevent saving a just-completed result; the activity then reports an explicit save failure |

## Security invariants

1. Never adopt a service solely because it answers on a familiar port.
2. Never expose launch tokens in displayed URLs, persisted logs, or broad child
   environments.
3. Never silently broaden egress: on-device is loopback; external inference is one
   consented origin; remote MCP is disabled.
4. Never reuse a conversation automatically across a provider/data-boundary change.
5. Never serialize provider or MCP secret values when a Keychain reference will do.
6. Never authorize one Workspace path while asking DSH to operate in another.
7. Never activate changed Skill, plugin, MCP executable/interpreter/entry point, or
   replaced project identity under an old approval.
8. Never execute an MCP definition as a shell string or allow a remote transport by
   inference.
9. Never preview or save a download as passive solely because of its filename.
10. Never apply Workspace Recovery from a stale preview, replace a symlink/type
    obstruction, or proceed without rollback material.
11. Never delete legacy credentials before Keychain read-back succeeds.
12. Never install an update that cannot prove signer, identity, freshness, and
    Gatekeeper status.
13. Never fingerprint or approve a community plugin by following a link, opening a
    special object, exceeding the fixed audit budget, or accepting unbounded or
    non-private approval state.
14. Never launch DSH after private-home preparation exceeds its deadline or encounters
    linked, special, oversized, over-deep, overlong, or over-count legacy/profile state.
15. Never advertise an unusable web tool, reuse model-provider consent for page egress,
    follow a page redirect, fetch a private/reserved address, or retry web access through
    a shell after denial or failure.

## Residual and out-of-scope risk

Protection from a compromised macOS account, kernel, correctly signed Ollama process, approved MCP or
plugin binary, malicious signed app bundle, provider, DNS/TLS ecosystem, or supply
chain is out of scope. Full-disk encryption, OS patching, account authentication,
physical security, provider terms/data retention, and source review remain owner
responsibilities.

The Ollama listener proof is a launch/readiness ownership control, not a claim that
every later TCP connection cryptographically authenticates its accepting PID. Closing
the same-UID post-verification rebind race would require an app-owned authenticated
proxy or transport that proves the accepted socket belongs to the signed child before
forwarding any request body. This private single-user release treats that race as a
named residual rather than implying a guarantee the HTTP protocol cannot provide.

Automated and manual tests reduce known risk but cannot prove absence of all defects.
Cloud-provider correctness, billing, rate limits, tool compatibility, and privacy
require credentialed tests against each chosen provider before relying on that route.

The 2026-08-29 Semgrep gate pins engine 1.135.0 with 1,074 `p/default` rules and
52 `p/secrets` rules. Secrets remain exact-byte pinned; default uses a length-framed
rule-block-set digest that ignores only top-level rule ordering while binding every
byte inside each unique rule. Byte count, content type, rule count, HTTPS origin, and
scan targets remain exact. Fulmar does not redistribute those packs; the scanner uses
a private temporary directory, disables metrics and account credentials, and fails
closed on unreviewed content drift. The run reported one insecure-WebSocket match
and no other finding. That single finding is a structurally checked exception for the
authenticated exact-port `127.0.0.1` runtime CSP construction, protected by random
authentication, peer/Host checks, nonce/PID identity, and exact port scope. It does
not permit cleartext WebSockets to a LAN or cloud host and must be re-reviewed if the
loopback transport contract changes.
