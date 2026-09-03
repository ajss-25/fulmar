# Fulmar 1.2

Fulmar is an **unofficial, independent native macOS app** for
[DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (DSH). It wraps the
DSH agent runtime in a signed-bundle-verified, sandboxed desktop host so that private
local Ollama/Qwen work and explicitly consented cloud-API work each get their own
clearly labelled privacy boundary. Fulmar is **not affiliated with, endorsed by, or
supported by DeepSeek, OpenAI, Anthropic, Ollama, Alibaba, or the Qwen project.**
Third-party names identify compatibility only.

The 1.2.36 candidate is build 156. The visible product was renamed from Local Harness;
stable legacy technical identifiers (bundle ID, Keychain services, Application Support
folder) remain in place so existing conversations, settings, credentials, schedules,
backups and rollback continue to resolve. See
[Brand and release identity](docs/BRAND_AND_RELEASE_IDENTITY.md). Fulmar does not
promise feature parity with proprietary desktop applications or freedom from defects.

> **Public-release status — source preview, not a supported download.** The proposed
> first public tag is `v1.2.36-preview.1`. It is an MIT-licensed **source preview**:
> reviewers and developers can build and run it from source. There is no Developer ID
> signed or Apple-notarised binary; a locally built app is ad-hoc signed and macOS
> Gatekeeper will refuse it by default (see
> [Preview binary and Gatekeeper](docs/PREVIEW_BINARY_GATEKEEPER.md)). Clean-Mac install
> testing, the manual permission/accessibility matrix, live paid-provider tests, icon and
> trademark clearance, and hosted CI are open gates listed in
> [public-release readiness](docs/PUBLIC_RELEASE_READINESS.md) and
> [known limitations](docs/KNOWN_LIMITATIONS.md).

> **Upstream safety boundary:** [DeepSeek describes Harness](https://github.com/deepseek-ai/deepseek-harness/blob/main/SAFETY.md) as experimental
> developer-preview software that has not undergone a security audit. Fulmar's
> native process, network, approval, backup, and disclosure controls reduce risk;
> they cannot make model-generated code or an approved third-party plugin harmless.
> Keep backups, grant the least access needed, and review commands and extensions.

## Contents

- [What Fulmar is and what DSH is](#what-fulmar-is-and-what-dsh-is)
- [Where your data goes](#where-your-data-goes)
- [Requirements](#requirements)
- [Support matrix](#support-matrix)
- [Quick start](#quick-start)
- [Safety features you will notice](#safety-features-you-will-notice)
- [Build from source](#build-from-source)
- [Preview limitations](#preview-limitations)
- [Reporting bugs and security issues](#reporting-bugs-and-security-issues)
- [Project identity and licence](#project-identity-and-licence)
- [Detailed reference](#model-and-data-boundary-choices) (everything below the quick guide)

## What Fulmar is and what DSH is

**DeepSeek Harness (DSH)** is DeepSeek's open-source agent runtime: a Node.js program
that runs conversations, tools (shell, files, web fetch), Skills and MCP servers against a
language model, with a browser-based UI. On its own it is a developer-preview command-line
project.

**Fulmar** is a native Swift/AppKit macOS application that bundles an exact, reviewed DSH
release (`0.1.1-rc.1` on Node `22.23.1`) and runs it as a private, authenticated loopback
service inside the app. Fulmar adds what a desktop user needs and DSH does not provide:

- a native window, menus, shortcuts, Quick Chat, Task History, schedules and diagnostics;
- an **app-owned, sandboxed Ollama process** for on-device models, with memory admission,
  adaptive thermal protection and exact-process cleanup;
- **per-boundary consent** before any request can leave the Mac, and a fresh session
  whenever the boundary changes;
- Keychain-only credential storage, native approval for every MCP tool call, bounded
  downloads, workspace recovery checkpoints and redacted logs/backups.

Fulmar exposes a security-reviewed **subset** of DSH. Community plugin management,
generic credential-backed web search, remote HTTP/SSE MCP, Code runtime, Workflow and
Ralph are intentionally not exposed in this release.

## Where your data goes

| Route | Runs where | What stays on this Mac | When data leaves the Mac |
| --- | --- | --- | --- |
| **On this Mac** (Ollama, default) | An Ollama process that Fulmar starts, verifies and owns on a random `127.0.0.1` port | Prompts, attachments, tool output, history, workspace files, model weights | Never for inference. Only a tool you approve (an exact HTTPS page fetch, a Skill or MCP server you allowed for external use, or a link you open in your browser) can disclose data |
| **Local network** (a compatible endpoint you declare on a loopback/RFC 1918/IPv6-ULA address) | Your own server | Everything except the request you consented to send | To that one exact origin, after explicit consent; it does **not** inherit Fulmar's Ollama sandbox, RAM or thermal protections |
| **Cloud** (DeepSeek API, OpenAI, Anthropic, or a custom HTTPS endpoint) | The provider's service | Credentials (macOS Keychain), history, settings, backups | The task content, attachments, conversation context, approved Skill/MCP results and tool arguments for that task go to the one consented origin |

Privacy properties that hold on every route: credentials are stored only in the macOS
Keychain and referenced by name; changing provider or boundary restarts the runtime and
starts a fresh session (no silent context carry-over); Harness backups exclude Keychain
values and classified secret files; logs and support reports are pattern-redacted (best
effort, not a guarantee); Fulmar never pulls, downloads, deletes or substitutes model
weights; Fulmar itself contains no analytics, telemetry-upload or crash-reporting
service and its in-app updater is hard-disabled in this release, so the only outbound
connections are the provider origin you consented to, a page fetch you approved, and
developer-time dependency downloads. Details: [Privacy model](docs/PRIVACY.md) and
[Threat model](docs/THREAT_MODEL.md). Data locations and deletion:
[Public installation and removal → Uninstall and retained data](docs/PUBLIC_INSTALLATION.md#uninstall-and-retained-data).

## Requirements

| Item | Requirement | Notes |
| --- | --- | --- |
| Mac | Apple silicon (arm64) | Intel Macs are not supported and the build refuses x86_64 |
| macOS | 15.0 or later (declared minimum) | Every bundled executable is verified against 15.0. All physical testing so far ran on macOS 26.6.2; macOS 15 itself has not been physically tested |
| Disk | About 410 MB for the built app, plus your Ollama models (`qwen3.8:27b-mlx` is about 17 GiB) and a source build tree of several GB | Models live in Ollama's shared `~/.ollama/models`, which Fulmar never modifies |
| Memory (on-device route) | **48 GB** of physical memory for the only release-qualified local model, `qwen3.8:27b-mlx` | Fulmar refuses that route below 48 GB. Any other Ollama model is admitted only in Compatibility mode when the Mac has at least **twice the model's installed size plus 4 GiB** free of the model itself (for example a 4 GB model needs ≥ 12 GB) — a conservative policy floor, not a performance promise |
| Memory (cloud routes) | No local model memory needed | Cloud routes ignore local RAM/thermal policy |
| Ollama (on-device route only) | Official signed Ollama macOS app, stable **0.33.2 through 0.33.x** | Installed in `/Applications`, `~/Applications`, or a Homebrew shim location; 0.34+ fails closed until qualified |
| Building from source | Xcode Command Line Tools (Swift 6.3 toolchain), Python 3 with Semgrep exactly `1.135.0`, network access for the one-time checksum-verified Node/npm reconstruction | See [Build from source](#build-from-source) |

## Support matrix

Fulmar deliberately distinguishes four tiers; see [docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md)
for the full table and the evidence behind each row.

| Tier | Meaning | In this preview |
| --- | --- | --- |
| 1 — Qualified | Exercised end to end on real hardware with retained evidence | Apple M5 Pro, 48 GB, macOS 26.6.2, official Ollama 0.33.x, `qwen3.8:27b-mlx` (the qualified route); the complete automated source gates for build 156 |
| 2 — Protocol-simulated | Verified against credential-free fixtures of the wire protocol, never against a live paid account | DeepSeek API text/tools/stream/cancel/error shapes; OpenAI Chat Completions, OpenAI Responses and Anthropic Messages custom routes. DeepSeek's live *error* path was reached once with a no-credit key; a successful live DeepSeek chat is **not** qualified |
| 3 — Expected compatible, not hardware-tested | Policy is implemented and unit-tested, but no physical run exists | Other Apple-silicon Macs and memory sizes (8–96 GiB thresholds are injected tests); macOS 15.0 minimum; other Ollama models via Compatibility mode (text and tools only, 8K/2K); other OpenAI-compatible servers |
| 4 — Unsupported / unqualified | Refused, disabled, or outside the design | Intel Macs; Ollama 0.34+ or non-official builds; thinking-capable alternate Ollama models; remote HTTP/SSE MCP; arbitrary provider protocols, proxies, custom CAs, mTLS; App Store distribution; any "every model works" claim |

## Quick start

1. **Build Fulmar from source** (there is no supported download yet) — see
   [Build from source](#build-from-source). The app is assembled at
   `/private/tmp/LocalHarnessBuild/Fulmar.app`; copy it to `/Applications` yourself if
   you want to keep it. Because it is only ad-hoc signed, macOS will refuse the first
   launch; read [Preview binary and Gatekeeper](docs/PREVIEW_BINARY_GATEKEEPER.md)
   before deciding whether to allow it.
2. **For on-device work**, install the official Ollama macOS app (0.33.x) and pull the
   qualified model: `ollama pull qwen3.8:27b-mlx` (needs a 48 GB Mac). Ollama's normal
   service does not need to be running; Fulmar starts its own confined copy on a random
   port. Open Fulmar, keep the default **Ollama (Local)** route, and choose the installed
   model. Any other installed model must be admitted through **Use Compatibility Mode**.
3. **For the DeepSeek API**, open **Models & Providers → DeepSeek → API Key…** and paste
   a key from a test account with credit. The key goes to the macOS Keychain and is
   never shown again. Saving a key does **not** switch routes: pick the DeepSeek model,
   read the destination/disclosure summary, then choose **Use for New Tasks**.
4. **For an OpenAI-compatible or Anthropic-compatible endpoint**, add a custom provider
   with exactly one reviewed protocol (OpenAI Chat Completions, OpenAI Responses or
   Anthropic Messages), the base URL, an `apiKeyEnv` credential reference (or explicit
   no-auth for a loopback/private address), and one model per line as
   `model ID | display name | text,image | context tokens | max output tokens`.
5. **Skills and MCP servers** are opt-in, fingerprinted, and approved individually;
   every MCP tool call asks for native approval. Do not treat them as a plugin store.
6. Grant Screen Recording, microphone, speech, notifications, login or background
   scheduling permissions only when you want the related feature.

Step-by-step detail, including first-run symptoms, lives in
[Getting started](docs/GETTING_STARTED.md) and [Troubleshooting](docs/TROUBLESHOOTING.md).

## Safety features you will notice

- **MCP and tool approval.** Only local `stdio` MCP servers launched as literal
  executable + argument arrays are supported; the executable, interpreter, entry files,
  configuration and workspace are fingerprinted, credentials are Keychain references, and
  every discovered tool call passes through native approval with output-size, startup and
  reconnect limits. Changing any fingerprinted file revokes approval.
- **Thermal protection (on-device route only).** Fulmar samples macOS thermal pressure
  every two seconds. Fair/unknown pressure or four minutes of sustained generation enters
  **Eco mode** (later local outputs capped at 2,048 tokens, five seconds of rest between
  generations) without interrupting the running turn; serious or critical pressure stops
  the app-owned Harness/Ollama processes and starts a 90-second/10-minute cooldown; a
  15-minute continuously constrained fail-safe also stops work. Cloud routes are
  unaffected. See [Thermal safety](docs/THERMAL_SAFETY.md).
- **Automatic continuation.** When a foreground task hits its output limit (including the
  Eco cap), Fulmar records the completed segment and queues a visibly labelled DSH
  follow-up that continues the same task — it never fabricates a missing fragment or
  pretends you typed "continue". Your own next message always wins, subagents stay under
  their parent, and a fixed twelve-follow-up budget ends with one progress summary.
- **Exact-origin egress and fresh sessions** on every provider or boundary change; a
  random authenticated loopback port and bearer token per launch; bounded, quarantined
  downloads; workspace recovery checkpoints before each task; and an approved-per-page
  `web_fetch` with no general web search.

## Build from source

Requirements: Apple-silicon Mac, macOS 15 or later, Xcode Command Line Tools, Python 3
with `semgrep==1.135.0` on `PATH` (for example `pipx install semgrep==1.135.0`), and
network access for the one-time, checksum-verified runtime reconstruction. The large
Node and dependency trees are deliberately not stored in Git.

```sh
umask 022
git clone https://github.com/ajss-25/fulmar.git fulmar && cd fulmar
semgrep --version                     # must report 1.135.0
zsh scripts/bootstrap-source-checkout.sh   # pinned Node 22.23.1, DSH 0.1.1-rc.1, 13 verified patches, inventory check
make tracked-index-policy
make source-contract-test
make deepseek-contract-test
make runtime-inventory-verify
make dependency-audit                 # contacts the public npm registry, credential-free
make static-security-scan
FULMAR_SWIFT_BUILD_JOBS=2 /usr/bin/caffeinate -dimsu zsh scripts/run-swift-tests.sh   # 1,445 isolated functions
zsh scripts/run-js-tests.sh --test Tests/JS/*.mjs      # 652 tests (605 pass, 47 reviewed skips)
LOCAL_HARNESS_REQUIRE_STABLE_SIGNING=0 LOCAL_HARNESS_SIGN_IDENTITY=- LOCAL_HARNESS_SIGN_TIMESTAMP=0 make build
./scripts/run-with-watchdog.sh --seconds 1800 --max-rss-bytes 8589934592 --rss-grace-seconds 15 \
  --emergency-rss-bytes 17179869184 --label "Fulmar frozen-candidate check" -- /usr/bin/make frozen-candidate-check
```

Never run `npm ci` directly against `VendorRuntime/package-lock.json`: the bootstrap
derives the install-only lock, applies the thirteen hash-bound runtime patches and
verifies the complete `VendorRuntime.inventory.json`. The Swift gate builds with
warnings as errors and takes minutes on a warm cache and considerably longer cold; run
it and the JavaScript gate sequentially, not concurrently. The full gate list, expected
counts and the private/release targets you should **not** run for a preview are in
[Getting started](docs/GETTING_STARTED.md), [Test plan](docs/TEST_PLAN.md) and the
[detailed reference](#build-and-qualification) below.

## Preview limitations

- No signed or notarised binary; no in-app updater (the menu is hard-disabled); no
  App Store build. Install by building from source and copying the app yourself.
- English-only UI and documentation; no first-run assistant.
- Only `qwen3.8:27b-mlx` on a 48 GB Mac is a qualified local model; everything else is
  Compatibility mode (8K context / 2K output, text and tools only) or refused.
- No successful live DeepSeek/OpenAI/Anthropic request has been qualified; protocol
  fixtures only. Live use requires your own funded account and your own verification.
- Physical testing so far comes from one Apple M5 Pro on macOS 26.6.2. macOS 15,
  lower-memory Macs and other chips are policy-tested only.
- Redaction of logs, exports and backups is pattern-based; review before sharing.
- The full list, including the same-user credential-helper boundary and the
  clean-install-only status for retained older state, is in
  [Known limitations](docs/KNOWN_LIMITATIONS.md).

## Reporting bugs and security issues

Read [SUPPORT.md](SUPPORT.md) and the
[bug-report diagnostic checklist](docs/BUG_REPORT_CHECKLIST.md), then
[open a GitHub issue](https://github.com/ajss-25/fulmar/issues/new/choose) using the template.
Include the Fulmar version/build, macOS version, chip and RAM, the
route (on this Mac / local network / cloud), model tag and non-secret steps. Use the app's
sanitized **Diagnostics** report and read it before attaching. Never post API keys,
prompts, workspace files, private endpoint URLs or unreviewed logs. Vulnerabilities go
through [GitHub private vulnerability reporting](https://github.com/ajss-25/fulmar/security/advisories/new)
as described in [SECURITY.md](SECURITY.md).

Candidate changes are recorded in the [changelog](CHANGELOG.md); the proposed preview
release notes are in [docs/RELEASE_NOTES_v1.2.36-preview.1.md](docs/RELEASE_NOTES_v1.2.36-preview.1.md).
The separate [public-release readiness record](docs/PUBLIC_RELEASE_READINESS.md)
explains why the current source candidate and locally signed app are not yet a general
download, and the [public installation and removal guide](docs/PUBLIC_INSTALLATION.md)
documents checksum verification, first run, uninstall, and intentionally retained data
for a future release that passes the separate public-distribution gate.

## Project identity and licence

The canonical public repository is [ajss-25/fulmar](https://github.com/ajss-25/fulmar).
The public maintainer identity and first-party copyright/licence holder are **ajss-25**.
Original Fulmar source is released under the MIT License; see [LICENSE](LICENSE).
Ordinary bugs belong in [GitHub Issues](https://github.com/ajss-25/fulmar/issues/new/choose),
while suspected vulnerabilities must use
[private vulnerability reporting](https://github.com/ajss-25/fulmar/security/advisories/new).
No API key, private prompt, workspace content, or unreviewed diagnostic log should be
posted to a public issue.

The [first-party licence policy](docs/FIRST_PARTY_LICENSE_POLICY.md) requires `LICENSE`
and its exact `Config/ProjectLicense.json` metadata to be present and digest-matched
for this source-preview state. A partial, unsafe, or substituted state stops every
production build. Third-party components retain their own terms; generated SBOM and
notice files are inventory evidence, not legal or trademark clearance.

---

The rest of this document is the detailed engineering reference.

## Model and data-boundary choices

- **On this Mac:** an Ollama process started and owned by Fulmar on a fresh
  random `127.0.0.1` port. The official `qwen3.8:27b-mlx` manifest
  SHA-256 `5642e97495e1a088883805981563dcdc4a040c2f53388b7a41d1f24d3622cf7e`
  is the only
  release-qualified local model and receives Fulmar's Fast, Balanced, and Deep
  profiles plus reviewed reasoning controls. Another safely named installed Ollama
  model is unqualified and can be admitted only after its bounded `/api/show`
  metadata reports completion, tool use, no model-specific thinking mode, and at
  a context between 8,192 and 1,048,576 tokens. Its installed size must also leave
  conservative headroom on the host: twice the model bytes plus 4 GiB. It then runs text-and-tools-only with a fixed Compatibility
  profile of 8,192 context / 2,048 output; Fulmar does not infer Qwen capabilities
  from the model name. The app verifies the exact child PID owns that listener before
  DSH starts. It never adopts a service merely because port 11434 answers. No DeepSeek
  API key is required. Ollama 0.32.12 was the first upstream release with Qwen 3.8
  27B and `27b-mlx`, but Fulmar admits only stable Ollama 0.33.2 through the
  latest patch in the 0.33.x series. A 0.34-or-newer server fails closed until a
  later Fulmar release qualifies that series; version syntax alone is not evidence
  of compatibility. The
  executable must be the official, strictly valid Ollama
  macOS signature (`ai.ollama.ollama`, Team `3MU9H2V9Y9`); its canonical file identity
  is bound to the child process and revalidated. DSH receives the fixed, non-secret
  `OLLAMA_API_KEY=local-ollama` readiness marker; that marker is not a cloud credential.
  Fulmar discovers the official bundle only at `/Applications/Ollama.app` or the
  authenticated POSIX account's `~/Applications/Ollama.app`, plus the two fixed
  package-manager shim locations; ambient PATH and HOME are never searched. This
  release uses that account's standard `~/.ollama/models` store. Selecting a custom
  model-store folder in Fulmar is not yet supported.
- **Cloud:** built-in DeepSeek, OpenAI, and Anthropic routes when configured with the
  user's own credentials.
- **Compatible endpoints:** user-defined routes created in Fulmar's native provider
  editor using exactly one of three reviewed wire protocols: **OpenAI Chat
  Completions**, **OpenAI Responses**, or **Anthropic Messages**. This is not a claim
  of arbitrary provider or model compatibility. Loopback, private-network, and cloud
  endpoints are classified separately; unknown routes fail closed as cloud routes.

Each custom model is entered as
`model ID | display name | text,image | context tokens | max output tokens`.
Only text and image input are supported by this custom-provider path; audio and video
declarations are rejected.
`context tokens` must be 1,024 through 16,777,216; `max output tokens` must be 256
through that model's context limit. Enter the endpoint model's real supported limits,
not desired budgets: Fulmar writes them into DSH, reads the live settings back, and
refuses to present a custom provider as configured unless its provider and model
configuration round-trips exactly. That check does not contact the endpoint.
This proves only the stored configuration; it does not contact or certify the endpoint.
Credential mode requires an `apiKeyEnv` bearer-style API-key reference resolved
through Fulmar's credential service. Explicit no-authentication mode is available only
for literal loopback, RFC 1918, and IPv6 ULA addresses and suppresses Authorization
and API-key headers; hostnames and cloud origins are rejected. Custom profiles cannot add arbitrary
headers or query parameters, a proxy, a custom certificate authority, or mutual TLS.
Plain HTTP is accepted only for a literal loopback or private address; public origins
must use HTTPS. OpenAI protocol bases normally end in `/v1`; Anthropic Messages bases
must stop before `/v1` because its SDK appends `/v1/messages`.

A user-declared local endpoint is a consented **Local network** route. It does not
receive Fulmar's managed Ollama lifecycle, model-size/RAM admission, Metal/MLX tuning,
or thermal protection. The only alternate Ollama models admitted by the managed route
are models whose live metadata reports completion and tools without model-specific
thinking; Fulmar does not infer or accept an alternate thinking-capable model's
reasoning dialect.

### Portability and qualification boundary

| Route or host | What Fulmar permits | What the current evidence proves |
| --- | --- | --- |
| Apple-silicon Mac, macOS 15 or later | The declared application platform | Automated architecture/deployment checks exist, but the exact candidate still needs clean-machine testing on macOS 15. Intel Macs are not supported |
| Exact `qwen3.8:27b-mlx` digest on an admitted host | Fast/Balanced/Deep, reviewed reasoning controls, app-owned Ollama RAM and thermal protection | This is the only release-qualified local model contract. Its admission floor is 48 GiB of physical memory; current physical inference evidence comes from one 48 GB Apple M5 Pro |
| Another installed Ollama model | Fixed Compatibility mode only after live completion/tools/non-thinking/context and conservative RAM checks | The injected 8/16/24/32/48/64/96 GiB tests prove policy thresholds, not performance on seven physical Macs or complete agent behavior for that model |
| DeepSeek, OpenAI, Anthropic, or a custom compatible endpoint | Exact-origin, credential-reference-bound provider selection | Credential-free fixtures prove the reviewed protocol shapes. A named provider is live-qualified only when the release evidence records successful account-backed text, tool, cancellation, and error tests |
| User-declared loopback or private-network compatible server | Treated as an explicitly consented `Local network` route, never as Fulmar-owned on-device inference | It does not inherit the app-owned Ollama process, RAM-admission, Metal/MLX, or thermal-safety claims and needs endpoint-specific qualification |

“Available in the selector,” “passes Compatibility admission,” and “release-qualified”
are deliberately different claims. Fulmar must not be described as supporting every
local model, every OpenAI-compatible server, every cloud account, or every Mac.

A macOS account may use a securely provisioned login home outside `/Users`. Fulmar
does not assume the conventional prefix: the private installer and model-tool sandbox
accept a canonical nonstandard home only when its complete ancestry is made of real
directories owned by root or the current account and none is group/world writable.
The home itself, and the private installer's `Library` and `Application Support`, must
be owned by the current account. Nonstandard-home ancestry must also be free of
extended ACLs; conventional `/Users/<name>` homes retain normal macOS deny ACLs.
Symlink aliases, writable mount ancestry, unsafe ownership, extended ACLs, and
noncanonical paths fail closed before receipt writes or sandboxed tool launch. This
is a path-safety contract, not physical qualification of every mobile, network, or
external-volume home configuration.

The native model switcher reads the live DSH provider/model catalog and commits the
default provider and model as one transaction. A network or cloud route requires
confirmation of its exact normalized origin. Only that origin is opened for the
active route. Consent is also bound to the exact Keychain credential reference
(the reference name, never its secret value), so changing either the endpoint or
credential reference invalidates consent. A failed switch rolls the app, Harness
default, consent, and privacy mode back together.
Catalogue refreshes never silently select the first available row: Quick Chat remains
disabled unless the exact transaction-committed route is still present. If a refreshed
model loses image capability, queued images are removed before any request can begin.
If the selected local model is missing, Fulmar keeps task admission closed and offers
**Choose Installed Local Model**. It reads the app-owned Ollama catalog and validates
the chosen model before committing it. Fulmar never pulls, downloads, deletes, or
silently substitutes model weights; use Ollama to manage the shared model library.
An upgrade preserves the exact older `qwen3.8:27b-hermes` selection and runs it only
through conservative Compatibility settings; it does not silently retarget that
selection to `qwen3.8:27b-mlx`. The MLX route remains the default only for a new profile
or after an explicit model choice.

Saving or verifying a DeepSeek or other cloud credential does not make that provider
the inference route. Fulmar returns to its zero-inference provider control plane; the
user must choose a model, review the exact destination and disclosure boundary, and
select **Use for New Tasks**. Only that separate transaction can start a fresh runtime
on the new route.

Changing provider or crossing a data boundary restarts the authenticated runtime and
starts a fresh main Harness session. Quick Chat also clears its current session.
Prompt, tool, and skill context from a local task is therefore not silently carried
into a cloud task, or vice versa. Existing tasks remain available in Task History and
can be reopened deliberately with a boundary warning.

Credentials are named by reference in configuration and resolved from the macOS
Keychain at runtime. A private `CredentialMetadata` index records only which references
were written by the current stable helper. One fixed owner-only transaction lock keeps
catalogue reads and mutations coherent without creating an unbounded lock file per
reference. Routine catalogue checks with no pending transaction read only that private
metadata index. After an interrupted credential mutation, recovery performs one bounded
noninteractive Keychain read to reconcile the journal; authorization or ambiguous-value
states are exposed as a value-free marker and require an explicit foreground choice in
Models & Providers. Background work never summons a password prompt. The fixed local
Ollama marker bypasses Keychain entirely. This is process-crash recovery, not a claim of
physical-power-loss or APFS-replay qualification.
Fulmar does not intentionally serialize provider
credential values into consent, model settings, MCP definitions, logs, backups, or
exports. The provider settings page uses the same credential service. Arbitrary
secrets pasted into ordinary prompts or files remain subject to the redaction limits
described below.

## Desktop features

- Full DeepSeek Harness UI in a native macOS window with authenticated loopback
  transport, a non-persistent WebView, native toolbar, menus, shortcuts, and status.
- Searchable **Command Center** (`Command-K`) for every major feature, visible
  **Chat** and **Agent Workspace** navigation, and tabbed General, Models, Privacy,
  and Advanced settings.
- Quick Chat backed by real DSH sessions, with streaming, tool approvals, questions,
  cancellation, attachments, optional reasoning, on-device dictation, spoken replies,
  `Option-Space`, **Copy Last Reply**, and privacy-aware Markdown/JSON export.
  Continuing a History task preserves its exact provider, model, and reasoning effort
  until the user explicitly changes a control.
- One authoritative private `Workspace` shared by main Harness tasks, Quick Chat,
  schedules, native file confinement, Skills, MCP, and workspace recovery.
- Native Models & Providers, Local Models, Performance Center, Activity Center,
  Diagnostics, Privacy Dashboard, Task History, Skills, MCP Servers, Backups,
  Workspace Recovery, Schedules, and Task Inbox.
- Adaptive thermal protection for app-owned local inference. Fulmar monitors the
  authenticated DSH running-session state and macOS thermal pressure without
  retaining prompt or response content. Warm or sustained work automatically enters
  Eco mode: the active local request keeps running, later local outputs are capped at
  2K tokens, and five seconds of rest is inserted between local generations. Normal
  temperature has no arbitrary wall-clock shutdown. Serious or critical pressure,
  and only a bounded 15-minute continuously constrained fail-safe, close admissions
  and stop the exact app-owned Harness/Ollama processes. Cloud routes are unchanged.
- An unexpected owned-Ollama exit uses only three delayed recovery attempts in a
  60-second window (1.2, 3, then 8 seconds). Repeated crashes stop recovery and leave
  agent work visibly blocked instead of churning processes, memory, and heat. Quit,
  thermal shutdown, provider changes, and explicit Stop invalidate a pending retry.
- Safer 48 GB presets: Fast is 32K context / 4K output, Balanced is 48K / 8K,
  and Deep is 64K / 16K. All keep local concurrency at one. Warm, unavailable,
  serious, or critical thermal readings recommend Fast, while adaptive Eco mode and
  the emergency circuit breaker remain authoritative regardless of the profile.
  Settings and Performance Center expose those presets only for the exact qualified
  Qwen route on a host that meets its 48 GB admission floor. Alternate Ollama models
  show fixed Compatibility guidance; cloud and network routes show no local-profile
  recommendation because their request limits are independent of local RAM and heat.
- A foreground task that reaches its model output limit continues automatically from
  the saved turn instead of asking the user to type “continue”. Fulmar uses a fresh,
  visibly identified DSH follow-up, preserves completed work, yields to any queued
  user message, and stops after a fixed safety budget. A cut-off tool or file edit is
  requested again in full; partial tool calls are never fabricated or replayed.
- Task History search and continuation plus rename, branch-at-latest-completed-state,
  archive-without-delete, and transcript export. Exports never embed attachment bytes
  and offer detected-secret, structure-only, or explicitly confirmed full-text modes.
- Appshots with explicit Screen Recording permission, crop, permanent redaction,
  optional on-device OCR, review-before-attach, private storage, and retention limits.
- Artifact Quick Look, annotations, Finder reveal, version comparison, and hostile
  download staging with byte limits, private descriptors, content-signature/MIME
  checks, quarantine metadata, revalidation, and explicit save.
- Confirmed external links open in the user's default macOS browser, outside the agent
  boundary. Fulmar does not claim DNS/socket isolation that WebKit cannot bind.
  Downloads initiated by Harness still use private staged inspection and explicit save.
- Persistent schedules with explicit unattended external-provider consent. Scheduled
  tasks now use the same authoritative Workspace as interactive tasks. The optional
  background helper is disabled by default and does not keep a model resident. It
  reads only the fixed private schedule document, refuses links/special files,
  malformed or oversized data, and more than 1,000 schedules, wakes only for a due
  enabled task, then exits after the run queue becomes idle. Task Inbox results are
  newest-first and bounded to 2,000 records, 256 MB, and 30 days; individual results
  or the entire Inbox can be deleted, and full result bodies load off the main UI.
  A synchronous admission latch blocks Run Now, due/background work, and late
  checkpoint callbacks throughout every protected runtime or restore transition.

## Skills and MCP

Skills are imported as inert data into a private quarantine. Symlinks and unsupported
entries are rejected; file count, depth, and byte limits apply; executable bits are
not trusted. An exact bundle fingerprint is bound to a project-specific policy.
Changing the files revokes activation. Each enabled skill is classified as local
only, ask every time before external use, or allowed for external sessions. Only the
reviewed subset for the active Workspace and provider boundary is materialized into a
read-only runtime catalog.

MCP support in 1.2.36 is deliberately narrower than general-purpose MCP clients:

- local `stdio` servers only; remote HTTP/SSE MCP is intentionally disabled;
- literal executable plus argument arrays, never a shell command;
- exact executable, absolute shebang interpreter, reviewed entry-point files,
  configuration, provider boundary, and Workspace identity are fingerprinted;
- credentials are Keychain references, not command-line secret values;
- every discovered MCP tool call passes through native approval;
- startup, call, discovered-tool, output-size, and reconnect limits are enforced;
- MCP subprocesses inherit a minimal environment and remain inside the Workspace and
  loopback/private-store confinement boundary.

These controls reduce risk but do not make an approved skill or MCP server harmless.
Review its purpose and source before approving it. A local MCP result may still be
sent to a cloud model when that exact model boundary is separately allowed.

## Security, privacy, and recovery defaults

- A new random loopback port and 256-bit bearer token are created at every launch.
  HTTP and WebSocket access require authentication; the embedded UI uses a one-time
  bootstrap to obtain an HttpOnly, SameSite cookie and validates nonce/PID identity.
- Strict Local is on for the app-owned Ollama route. The DSH provider transport can
  reach only the random loopback origin whose exact PID, signature, and listener are
  verified before exposure and around readiness. Tool, MCP, and other
  model-controlled child processes receive no direct network egress, including to
  unrelated loopback services, and are denied common Keychain, mail, messages, browser-profile,
  cloud-credential, and private SSH-key locations. The environment excludes unrelated
  API keys and the SSH agent by default.
- The owned Ollama process and its model-runner descendants also run inside a dedicated
  macOS sandbox: private app-owned HOME/TMP, read-only access to a link-free owner-safe
  `~/.ollama/models` tree, loopback-only bind/egress, cloud features disabled, and no
  access to other user files. Ollama needs arbitrary loopback ports for its private
  Metal/MLX runner children, so unrelated loopback services remain a documented
  dependency-level residual if the signed Ollama binary itself is compromised.
- External providers receive egress only to the one consented origin. Confirmed links
  leave the app for the user's default browser, which is never an agent tool.
- Connected provider traffic is normalized through a guarded `fetch` request with a
  reviewed option set, no caller-controlled authority/agent/resolver/TLS material,
  manual redirects, normal certificate verification, and a 16 MiB aggregate response
  limit. Direct external TCP, TLS, HTTP(S), and HTTP/2 clients are denied; the only
  direct HTTP exception is the exact literal-loopback Ollama origin. The private
  DeepSeek adapter does not create or send upstream's stable installation identifier,
  and the transport strips both that field and internal Harness session identifiers.
- Local and connected conversations expose `web_fetch` only for a specific public
  HTTPS page. Fulmar asks before every page, rejects redirects, credentials, custom
  ports, IP/private/reserved destinations and binary bodies, caps content at 2 MiB,
  and never falls back to shell networking. General `web_search` stays hidden until
  an independently configured search provider is genuinely available.
- Community DSH plugins remain blocked until the complete installed tree is scanned
  descriptor-relatively without following links, within fixed declaration, entry,
  depth, path, file, aggregate-byte, and monotonic-time limits, then fingerprinted
  and approved. Empty, changed, oversized, special-object, or built-in-name override
  trees receive fixed non-approvable blocked identities. The approval store itself
  is a bounded owner-only no-follow regular file.
- The app-owned DSH home is prepared before any service launch under one monotonic
  deadline. Mutable profile inputs use descriptor-relative no-follow bounded reads;
  a genuinely absent home is created empty without probing `~/.dsh`. A v1/v2 or
  receiptless home is preserved as one opaque directory under an authenticated
  transaction: sessions, storage, attachments, profiles, Skills, and unknown children
  are never enumerated or copied, while an explicit settings-only choice may open just
  bounded `O_NOFOLLOW` `settings.json`/`settings.yaml` files. It durably flushes a
  private sibling transaction and exact v3/privacy-epoch-1 receipt before atomic install;
  the next launch deterministically validates/finishes exact current staging; legacy or
  unknown staging and every old published output remain opaque and preserved, while an
  authenticated pre-epoch journal upgrades to Start Clean without inferring import
  consent. Migration and plugin trust audit run on one serialized
  utility worker while the app remains responsive; stop/quit cancels the typed pass
  and waits for that exact submitted closure to settle before exposing a stopped
  filesystem boundary. A main-thread generation gate is rechecked immediately before
  launch.
- The same serialized prerequisite worker owns every expensive launch check: signed
  bundle validation, official Ollama signature resolution, the descriptor-relative
  no-follow model-store walk, Skill materialization and hashing, MCP executable and
  reviewed-argument hashing, and all four real Seatbelt probes. Bundle, Ollama, and
  Harness passes have fixed 30/20/60-second monotonic budgets; the four probes each
  receive at most five seconds without resetting the shared Harness budget. The main
  thread performs only cheap generation, PID/listener, and captured filesystem-identity
  rechecks immediately before `Process.run()`. Stop/quit cancels and awaits the exact
  worker pass, so no old preparation can authorize a later process launch.
- A bounded recovery checkpoint is captured before a new main task or Quick Chat turn.
  A no-follow descriptor walk charges entry, depth, UTF-8 path, file, aggregate-byte,
  and one monotonic deadline budget before retaining content; hashing and private
  checkpoint copies stream in fixed-size chunks. Generated trees and likely secret
  files are excluded. Restore always begins with a fresh preview, requires separate
  consent to overwrite modified files or remove added files, rejects symlink/type
  obstructions, verifies stored hashes, and rolls back the restore transaction on
  failure.
- Harness-state backups exclude credentials and private-key formats. Logs are private,
  rotated, and pattern-redacted, but arbitrary unlabelled secrets cannot be guaranteed
  absent. Conversation export redaction is similarly best effort.
- Performance history contains only bounded route labels, profile, coarse timing,
  token-count source/count, outcome, and failure category. It retains at most 100
  records for 24 hours in a 256 KiB owner-only spool; prompts, responses, errors,
  sessions, workspace paths, tool data, URLs, headers, and credentials are not accepted
  by its schema. It can be cleared from Performance Center.

Strict Local does not disconnect the entire Mac or prove that macOS, signed Ollama,
an approved executable, or another same-user process is uncompromised. Its controls
bound what those components can reach; they do not prove those components benevolent.
The ownership check is not per-connection cryptographic authentication: after a
verified Ollama exit, a targeted same-UID process could theoretically win a rebind race
before a prompt connection. Random ports and immediate Harness shutdown make that an
explicitly accepted trusted-account residual; protecting against hostile same-user
processes would require an accepted-socket-verifying app proxy.

## Performance on a 48 GB Apple-silicon Mac

The release-qualified `qwen3.8:27b-mlx` route uses one generation at a time and
three presets:

Fulmar checks both the exact `/api/tags` manifest digest and the host's physical
memory before starting this route. Macs below 48 GB are refused before local
inference starts; they can use a smaller admitted Compatibility model or a cloud
provider. That is an evidence boundary, not a claim that every 27B model needs the
same amount of memory.

| Profile | Context | Maximum output | Keep-alive | Intended use |
| --- | ---: | ---: | ---: | --- |
| Fast | 32,768 | 4,096 | 2 minutes | Lower latency and lighter work |
| Balanced | 49,152 | 8,192 | 10 minutes | Recommended default for a quantized 27B model |
| Deep | 65,536 | 16,384 | 20 minutes | Long agent tasks; higher memory use and latency |

The reviewed local profile explicitly selects **Reasoning off** by default instead of
leaving Ollama to choose a thinking-capable model's default. This prevents a slow 27B
model from spending an entire thermally bounded output segment thinking before its
first tool call. **Reason deeply** remains available and sends an explicit High effort
when the task benefits from it; cloud providers retain their own advertised reasoning
choices and defaults.

Every other admitted Ollama model uses the fixed **Compatibility · 8K context / 2K
output** profile. The selector verifies current metadata before use, disables
Fast/Balanced/Deep and reasoning controls for that route, and limits it to text and
tools. It also requires physical memory of at least twice Ollama's reported installed
model size plus a 4 GiB system/runtime reserve. Compatibility means the minimum DSH
contract was checked; it is not release
qualification and does not promise that every agent workflow will behave like Qwen.
An alternate model that advertises model-specific thinking is rejected; Fulmar does
not guess how to disable or control an unreviewed reasoning dialect.

For the selected on-device Ollama route, context is an app-wide model capability. Before
the main Harness surface or scheduler can create a session, Fulmar transactionally writes the
selected `contextWindow` and default `maxTokens` to that exact `llm-pi-ai` provider/model,
re-reads the settings, and reloads the live topology. At every matching conversation
request, the reviewed DSH plugin resolves that exact model again and refuses the request
before provider I/O unless DSH reports the selected context. Fast/Balanced/Deep output
caps are separate and are applied per session, including scheduled sessions and
subagents. Concurrent sessions on the same route therefore share one context capacity
but can use different output caps.

Fulmar always owns the Ollama process it uses. Every managed route requests one loaded
model, one parallel generation, a bounded queue, and the selected server defaults.
Flash Attention and the q8 KV cache are enabled only for the exact release-qualified
Qwen route; Compatibility models do not inherit those model-specific settings. Fulmar
disables Ollama cloud/history/pruning behavior for this private child and confines its
filesystem and network authority as described above.
A separately running Ollama.app or command-line server is
not adopted and can coexist on another port; because both services may load models,
stop or unload the unrelated service if duplicate memory use is unwanted. Native
Ollama operations send request hints where supported. Cloud and LAN providers retain their own context and
hard output capabilities, and may reject a request cap they do not support. Performance
Center reports measured behavior. Opening Local Models starts only the app-owned
service on demand; model weights load on the first verified task, not at login. On quit,
the app optionally unloads its models and always terminates only the Ollama PID it owns.

## First use

1. Install the official signed Ollama macOS app and pull the desired local model. Its
   system-wide service does not need to be running; Fulmar starts a separate
   confined service. A modified, ad-hoc, PATH-discovered, or unexpectedly signed
   executable is refused.
2. Open Fulmar and leave the default route on **Ollama (Local)** for private work. If
   the saved model is absent, select **Choose Installed Local Model**; if no suitable
   model is installed, install it in Ollama and refresh. Fulmar does not download one
   automatically. Open **Models & Providers** only when intentionally configuring
   another boundary.
3. If offered, use **Move and Verify** for the legacy Harness credential migration.
   The source is removed only after every Keychain value reads back successfully.
   A cloud credential created by an older ad-hoc build has no metadata marker and is
   treated as unconfigured without prompting; remove that exact legacy item in
   Keychain Access and save it again from **Models & Providers**. Local Qwen remains
   available throughout.
4. Review **Skills** and **MCP Servers** individually; neither should be treated as a
   general plugin marketplace.
5. Grant Screen Recording, microphone, speech, notifications, login, or background
   scheduling permissions only when the related feature is wanted.

## Build and qualification

Requirements are an Apple-silicon Mac, macOS 15 or later, Xcode command-line tools,
and network access for the one-time, checksum-verified runtime reconstruction. The
large Node and dependency trees are deliberately not stored in Git.

```sh
zsh scripts/bootstrap-source-checkout.sh
make test
make runtime-inventory-test
make runtime-inventory-verify
make credential-test
make dependency-audit
# Runs the mandatory static/secret scan, then freezes one stable-signed candidate
make private-release
make web-rpc-canary
# Optional live approved-page retrieval of https://www.darkbloom.dev/
make web-live-canary
# Hosted/low-memory deterministic candidate profile; explicitly not final release qualification
make deterministic-release-verify
make app-owned-ollama-generation
# Final local release profile; requires the physical 48 GB Qwen hardware lane
make release-verify
make cloned-state-security
# Public-only: verify the private, exact-candidate record for all eight external gates
make public-external-evidence-verify
# Only after the exact candidate has current retained full-hardware evidence and Fulmar is closed
make private-install-qualified
# Inspect the prior app retained by that atomic private installation
make private-rollback-status
# If status reports an interrupted transaction, run exactly the instructed operation
make private-recovery-resume       # original app active: complete the swap
make private-recovery-finalize     # candidate active: commit only the missing receipt
make private-recovery-cancel       # original app active: archive the staged candidate
make private-recovery-reconcile    # archive an interrupted record write, then restore proven state
# After several successful real tasks, archive the committed rollback and records
make private-rollback-retire
```

Candidate qualification targets never invoke `build` and therefore cannot silently
replace the artifact they are meant to test. Use `make build-and-smoke` only when a
deliberate fresh private build followed by the bounded frozen-candidate smoke is wanted.
Direct release-verifier use is fail-closed unless it names the reviewed
`--signing-profile private-stable`; the Make targets supply that profile.

The assembled candidate is `/private/tmp/LocalHarnessBuild/Fulmar.app`; release
artifacts are written to `build/`. The build pins DSH `0.1.1-rc.1` and Node `22.23.1`.
`VendorRuntime.inventory.json` is the reviewed source-byte inventory: every directory,
regular file, mode, size/digest, and confined symlink is checked both before and after
copying. Assembly then derives the only permitted Runtime layout (one authoritative
DSH package and CLI, one sanitized preset root, and six local plugins), records the
exact Mach-O signing set, and
binds the final signed Runtime inventory into the release manifest.
The release build is also gated on a fresh Semgrep/secret-scan pass. Its canonical
`static-security-summary.json` is checked against every file descriptor in the exact
`source-build-inputs.json`, and both SHA-256 descriptors are embedded in the candidate
manifest, retained qualification evidence, and public review package. Missing, failed,
stale, or digest-tampered scan evidence stops assembly and verification.
`make dependency-audit` contacts the configured npm registry and must produce a
current, lock-bound, zero-unresolved-finding summary before `make release-verify` can
pass. `make deterministic-release-verify` runs every credential-free candidate,
archive, runtime, sandbox, MCP, native, JavaScript, and simulated-provider/protocol
gate suitable for a standard hosted ARM Mac, but explicitly records the mandatory
physical-Qwen lane as required-not-run. The default `make release-verify` remains the
full-hardware path and cannot silently omit that lane. The release verifier works from
the archive extraction and runs the empty
and cloned runtime, sandbox/MCP, candidate-backed authenticated web/RPC and WebSocket,
simulated-provider, credential-free packaged DeepSeek/OpenAI Responses/Anthropic/custom
protocol matrix, credential, lifecycle, a real app-owned sandboxed Ollama generation
with content-free GPU-residency evidence, and exact Qwen route gates; it does not
replace the documented interactive UI/quit checks. The web/RPC canary starts from an
empty private `DSH_HOME`, commits the exact reviewed Ollama/Qwen bootstrap before the
first session, validates pinned response schemas, rejects profile-local plugin shadows
and malformed bundle targets, and byte-verifies the served native session/checkpoint
bridge before exercising both behaviors. A second clean private host uses a non-empty,
owner-only reviewed `stdio` MCP catalog and proves the exact model-facing namespace,
authenticated deny and allow-once decisions, one execution only, the configured output
bound, and exact guard/server shutdown. Both hosts also require real turn telemetry to
land in the owner-only 100-row/24-hour/256-KiB aggregate schema while proving prompt,
response, tool, and error text is absent byte-for-byte. The canary leaves the user's
`~/.dsh` byte-for-byte and metadata unchanged.
The protocol matrix uses only a random loopback fixture and temporary Keychain
canaries. It verifies provider-specific authentication and request bodies, streaming
and split tool calls, cancellation, terminal authentication errors, bounded retries,
malformed and byte-limited responses, and secret non-leakage without contacting a
cloud provider. It establishes the packaged client protocols, not live-service
compatibility; those rows still require user-supplied test credentials.
The complete matrix is in [the test plan](docs/TEST_PLAN.md), with the active local
inference guard documented in [thermal safety](docs/THERMAL_SAFETY.md). Passing automated
tests is evidence for the exercised configurations, not proof that no defects exist.
Live cloud-provider tests require user-supplied test credentials and are not claimed
without them.

Public distribution additionally requires the owner-private
`build/public-external-evidence.json` record documented in
[public-release readiness](docs/PUBLIC_RELEASE_READINESS.md). The record must bind the
exact manifest SHA/version/build and contain passing, digest-referenced records for all
eight external gates. `make public-external-evidence-verify` is a non-mutating preflight;
`make public-distribution-verify` repeats the same check before it can publish success.
The tooling never creates or upgrades this record from inferred, deferred, or simulated
results.

The fail-closed public operator is deliberately two phase. With an explicit Developer
ID Application common name, signing-Keychain path, and notarytool Keychain profile,
`make public-release` builds, timestamps, notarizes, staples, re-archives, fully
qualifies, and retains one exact candidate. It pauses if candidate-bound manual
evidence is incomplete. After those real gates are recorded, run
`make public-release-finalize`; it revalidates and packages that same byte-for-byte
candidate without rebuilding it, then runs the public-distribution verifier. Neither command
uploads or publishes anything. See [public-release readiness](docs/PUBLIC_RELEASE_READINESS.md)
for the required variables and evidence workflow.

Private installation never uses a blind Finder copy or the disabled public updater.
`make private-install-qualified` rebinds the frozen candidate to current source,
archive, signatures, manifest, and retained full-hardware evidence, then atomically
swaps it with `/Applications/Fulmar.app` through separately built private tools. It
commits an immutable owner-private recovery journal before the swap, swaps back on a
failed post-install proof, and preserves the exact swapped pair when receipt durability
is uncertain. Read-only status deterministically distinguishes original-active,
swapped-awaiting-receipt, committed, incomplete record-write, and incomplete archive
states. Explicit reconcile, resume, finalize, cancel, and retire commands repeat all
proofs under the installer lock. Reconciliation exclusively archives—not deletes—an
owner-private temporary record before reconstructing only the state proven by the
active app, stage, signer, and existing durable records.
Cancellation and retirement atomically archive the exact staged bundle and transaction
records; they never delete either app. Archived bundles and records consume disk until
the owner reviews and removes them. See [Update and rollback](docs/UPDATE_AND_ROLLBACK.md)
before running it; an incomplete or unretired transaction deliberately blocks another
private update.

Public distribution remains blocked until the owner supplies a Developer ID
Application identity and notarization profile, resolves icon/branding rights, and
completes clean-Mac, minimum-macOS, permission, accessibility, and two-version update
tests. The private atomic path is not represented as Developer ID signed, notarized,
stapled, Gatekeeper-qualified, or suitable for general distribution.

## Detailed documents

- [Product specification](docs/PRODUCT_SPEC.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Privacy model](docs/PRIVACY.md)
- [Public installation and removal](docs/PUBLIC_INSTALLATION.md)
- [Public-release readiness](docs/PUBLIC_RELEASE_READINESS.md)
- [Security reporting](SECURITY.md)
- [Support](SUPPORT.md)
- [Contribution policy and current licence status](CONTRIBUTING.md)
- [Fail-closed first-party licence packaging policy](docs/FIRST_PARTY_LICENSE_POLICY.md)
- [Operations and recovery](docs/OPERATIONS.md)
- [Test plan and evidence](docs/TEST_PLAN.md)
- [Static-analysis rule provenance](docs/STATIC_ANALYSIS.md)
- [Hosted CI and repository security](docs/CI_SECURITY.md)
- [Qualification evidence ledger](docs/QUALIFICATION_EVIDENCE.md)
- [Update and rollback](docs/UPDATE_AND_ROLLBACK.md)
- [Upstream DSH upgrades](docs/UPSTREAM_DSH_UPGRADES.md)
- [Brand and release identity](docs/BRAND_AND_RELEASE_IDENTITY.md)
- [RAID log](docs/RAID.md)
- [Release checklist](docs/RELEASE_CHECKLIST.md)
- [Delivery record](docs/DELIVERY_PLAN.md)
