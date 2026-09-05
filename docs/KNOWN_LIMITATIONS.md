# Known limitations — Fulmar 1.2.36 candidate

This file is intentionally blunt. A limitation remains open until evidence from the
exact frozen candidate closes it.

- Fulmar implements a security-reviewed subset of DeepSeek Harness. It supports the
  bundled agent composition, local stdio MCP, reviewed Skills, workspace file/process
  tools, and exact-page approved HTTPS fetch. Upstream community-plugin management,
  generic credential-backed `web_search`, remote HTTP/SSE MCP, Code runtime,
  Workflow, and Ralph are not exposed.
- The official Ollama model `qwen3.8:27b-mlx` at manifest digest
  SHA-256 `5642e97495e1a088883805981563dcdc4a040c2f53388b7a41d1f24d3622cf7e`
  on a Mac with at least 48 GB of physical memory is the only local-model target
  eligible for the qualified Fast/Balanced/Deep profiles. Build 156 still requires
  its frozen full-hardware rerun. A later
  upstream tag digest needs a new Fulmar qualification; tags alone are mutable.
  Other installed Ollama models are explicitly unqualified. Fulmar admits only
  non-thinking completion-and-tools models whose bounded live metadata reports between
  8,192 and 1,048,576 context tokens, then forces text-and-tools-only Compatibility mode at 8K context /
  2K output. The host must also have twice the reported installed model bytes plus a
  4 GiB reserve. This conservative floor reduces memory-thrash risk; it does not
  predict every model's peak use or prove complete DSH agent behavior.
  Fulmar rejects alternate thinking-capable Ollama models rather than inferring an
  unreviewed reasoning dialect or guessing how to disable it.
- Fulmar admits only official stable Ollama 0.33.2 through the 0.33.x series. A
  0.34-or-newer series is deliberately reported as newer but unqualified until a
  later Fulmar release completes the compatibility matrix; it is not accepted merely
  because it is a stable semantic version. This release finds an official Ollama app
  in `/Applications` or the authenticated POSIX account's `~/Applications` directory,
  plus fixed Homebrew shim locations, without searching PATH or trusting HOME.
- The shipping UI uses the current POSIX account's standard `~/.ollama/models` store.
  Its internal release-test seam can validate an explicit alternate store, but users
  cannot yet choose, persist, security-scope, and protectedly restart onto a custom
  model-store folder. Compatibility models in the standard store do not inherit the
  qualified Qwen route's Flash Attention or q8 KV-cache settings.
- Native custom-provider authoring is intentionally limited to exactly **OpenAI Chat
  Completions**, **OpenAI Responses**, and **Anthropic Messages**. It is not an
  arbitrary provider adapter. Every model needs an explicit ID, display name,
  text or text/image capability (audio and video are rejected), real context limit
  from 1,024 through 16,777,216 tokens, and
  real maximum-output limit from 256 through that context limit. Fulmar round-trip
  verifies those values against DSH's live configuration catalog, but does not contact
  the endpoint and cannot prove that a third-party service truthfully implements them.
- A custom profile normally requires a basic bearer-style `apiKeyEnv` credential
  reference. Explicit credential-free operation is limited to literal loopback,
  RFC 1918, and IPv6 ULA addresses and sends no Authorization or API-key header;
  hostnames and cloud origins are rejected. A profile cannot add arbitrary headers or query parameters, a proxy, a custom
  certificate authority, or mutual TLS. Plain HTTP is limited to a literal loopback
  or private address; public origins require HTTPS. Anthropic Messages bases must stop
  before `/v1` because its SDK appends `/v1/messages`. Servers that require
  unsupported authentication or transport customization are not supported.
- A user-declared loopback or private-address server is a **Local network** route and
  remains user-managed. It does not inherit Fulmar's signed Ollama process ownership,
  lifecycle, model-size/RAM admission, Metal/MLX tuning, thermal controls, or unload
  behavior. Every such server still needs endpoint-specific protocol, tool, streaming,
  cancellation, resource, and privacy qualification.
- The 8/16/24/32/48/64/96 GiB admission matrix is deterministic injected-memory
  coverage. It proves policy branching and exact byte thresholds, not behavior on seven
  physical Macs. Current real local-inference evidence is from the documented 48 GB
  Apple M5 Pro; lower-memory Compatibility models and other Apple-silicon generations
  still require candidate-bound physical performance, thermal, and pressure testing.
- Canonical non-`/Users` login homes are structurally supported only when their full
  ancestry is root/current-user-owned, non-group/world-writable, symlink-free, and
  free of extended ACLs. Mobile, network, external-volume, and managed-enterprise
  home layouts have not received candidate-bound physical qualification; a layout
  that cannot meet the fail-closed admission policy is unsupported in this release.
- DeepSeek's request/error path was reached with a no-credit account, but successful
  live DeepSeek chat, tools, and cancellation are not qualified. OpenAI, Anthropic,
  and custom provider protocols use credential-free fixtures unless a release ledger
  explicitly records a live test.
- Provider failures created after client-security bridge 1.2.1 are reduced to a finite
  app-owned diagnostic before retry/session persistence. Legacy ordinary/subagent
  history is sanitized at the Host API and again in the browser; an already-open
  pre-bridge window is synchronously cleared and boundedly reloaded. The candidate
  does not migrate existing DSH session files.
  State retained from an older build may still contain raw provider error text or a
  request identifier, and private Harness backups may contain a copy. Task transcript
  export ignores failure events, raw Harness-log export is disabled, and the support
  report does not read session files, but those facts do not sanitize the durable source.
  Public app-binary distribution is therefore
  clean-install-only until an atomic pre-start/pre-backup migration or quarantine is
  implemented and fault-tested; never share an older DSH state tree or backup.
- A usable source build requires a persistent local signing identity via
  `make private-release`; it is not Developer ID signed or Apple-notarized. Ad-hoc
  builds are compile/review-only and cannot satisfy the packaged credential services'
  shared designated requirement. No build-156 binary has passed a clean non-developer Mac install,
  minimum-macOS matrix, or a two-version notarized update/rollback exercise.
- The retained updater source now requires a nonce-bound healthy launch from the exact
  directly spawned PID/bundle and journals every replacement/health/commit phase, but
  that does not close the public update gate. It has not been exercised across physical
  power loss and two real same-team Developer ID signed, notarized and stapled versions.
  Power loss between moving the old app aside and placing the candidate can also leave
  no in-bundle recovery executable at the application path; the exact rollback and
  authenticated journal survive for manual recovery, but a separately signed external
  recovery authority has not been designed or approved. The menu remains hard-disabled.
- Screen Recording, microphone, speech, notifications, launch-at-login, background
  scheduling, VoiceOver, Increased Contrast, Reduce Motion/Transparency, multiple
  displays, and every allow/deny permission path still require final interactive
  qualification.
- Fulmar-owned native UI and release documentation are English-only in this candidate.
  No localization catalogue or pseudolocalized layout matrix exists; bundled upstream
  DSH locale behavior is not a Fulmar localization claim.
- There is no dedicated first-run setup assistant. Initial setup uses the typed
  provider-recovery screen, Local Models, Models & Providers, and the Getting Started
  guide. Clean-Mac first-run usability remains unqualified.
- Aqua/Dark minimum-layout and action/accessibility metadata are automated, but that
  is not an installed end-to-end Accessibility test. The exact build-156 app still
  must complete a real model-picker local → consented external → local switch, prove
  fresh tasks and boundary labels, and pass keyboard/VoiceOver plus permission/display
  checks.
- Service logs and copied support reports redact reviewed credential forms and private
  paths, including chunk-split values, oversized PEM delimiters, and multiline private
  keys. This remains pattern-based: novel, encoded, low-entropy, or unlabelled secrets
  can be missed. Review every report or log before sharing it.
- Harness backups are integrity-authenticated, not encrypted. They exclude Keychain
  values and known secret-classified paths, but can contain chats, attachments, and
  durable tool-output spills; a secret stored under an innocently named path or inside
  content can therefore be retained. Keep every backup private and never attach one to
  a public issue.
- Interrupted credential writes use private recovery records containing
  reference/type/operation and SHA-256 equality digests, not credential bytes.
  Recovery can perform a noninteractive Keychain read; an ACL denial or unexpected
  out-of-band value fails closed and may require foreground repair. A retained raw
  SHA-256 equality digest can still support offline guessing of a low-entropy value;
  provider API keys are expected to be high entropy, but the journal is not a keyed
  commitment. The isolated SIGKILL gate uses a file-backed fake value store and does
  not prove reboot, APFS replay, storage-cache loss, or physical-power-loss behavior.
- The first-start plaintext migration is now an exact-CDHash-bound private XPC
  service and does not launch Node or the helper by pathname. The signed ordinary
  credential helper is deliberately reachable only through Fulmar's
  confined runtime in the supported design, but it does not cryptographically
  authenticate its same-user caller. Another unsandboxed process already running as
  the same macOS user could invoke it and read a Keychain value that the helper's ACL
  admits. Closing that remaining general helper boundary requires routing every
  runtime credential operation through authenticated IPC/XPC;
  public security claims must not describe the helper as isolation from a compromised
  same-user process.
- The owner selected MIT for original Fulmar source and the exact paired licence files
  are build/SBOM-bound. The source-preview third-party inventory has been reviewed;
  modified `@earendil-works/pi-ai` 0.82.1 is bound to its exact upstream MIT terms and
  modification record. The owner authorizes the Fulmar name and existing generated
  icon for this source preview without claiming originality, exclusivity, registration,
  affiliation, or a formal legal opinion.
- A built app additionally redistributes `@img/sharp-libvips-darwin-arm64`/libvips
  binary material. The notice inventory now binds the upstream component manifest,
  exact component versions, the libvips 8.18.3 LGPL-2.1 text and the SPDX
  LGPL-3.0/GPL-3.0 text, with exact provenance in
  `Config/ThirdPartyBinaryProvenance.json`. Per-component copyright/permissive notice
  texts, corresponding source, relinking/installation-information under code signing,
  and legal clearance remain explicitly open. That binary gate, plus privacy-manifest,
  encryption/export and formal mark review, remains open. A source preview must not be
  presented as a qualified or notarized binary release.
- An explicit manual-install `beta` public-release profile exists in source
  (`docs/PUBLIC_BETA_RELEASE_CONTRACT.md`). It is implementation with synthetic-fixture
  tests, not qualification: no beta candidate, evidence record, version, release or tag
  exists. The beta keeps Apple trust, clean-install, history-scan, repository-control,
  permission, privacy and binary-licence gates, replaces the automatic-updater exercise
  with manual install/reinstall/recovery evidence plus updater-disabled proof, and is
  clean-install-only until retained-state migration is separately qualified. Manual
  replacement is not evidence of automatic recovery.
- Static qualification fetches two content-pinned Semgrep registry packs without
  redistributing them. `p/secrets` is exact-byte pinned; `p/default` tolerates only a
  top-level permutation of byte-identical, uniquely identified rule blocks. Any rule
  content/addition/removal, size, identity, origin, or format change intentionally
  stops the gate until a private full diff and published usage terms are reviewed.
- No test suite can prove that software contains no defects. Release claims are limited
  to the cases and artifact hashes recorded in `docs/QUALIFICATION_EVIDENCE.md`.
