# Support matrix — Fulmar 1.2.36 build 156 (v1.2.36-preview.1)

Fulmar is an unofficial, independent macOS client for DeepSeek Harness and is not
affiliated with or endorsed by DeepSeek, OpenAI, Anthropic, Ollama, Alibaba or the Qwen
project. This matrix states what has actually been exercised. "Available in the
selector", "passes Compatibility admission" and "qualified" are deliberately different
claims, and nothing here implies that every Ollama model or every Mac has been tested.

## Tier definitions

| Tier | Definition | What it does **not** mean |
| --- | --- | --- |
| **1 — Fully qualified** | Exercised end to end on physical hardware with a retained log, or a complete automated gate whose exact counts are recorded in `docs/QUALIFICATION_EVIDENCE.md` / `build/release-triage` evidence | Proof of zero defects, or coverage of other hardware |
| **2 — Protocol-simulated** | The wire protocol, streaming, tools, cancellation, authentication, retry and error shapes are proven against credential-free fixtures | That a live paid account accepted, billed or completed a request |
| **3 — Expected compatible, not hardware-tested** | The policy is implemented and deterministically unit-tested (for example injected memory sizes), but no physical run on that configuration exists | Performance, thermal or usability evidence on that configuration |
| **4 — Unsupported or unqualified** | Refused by the app, disabled by design, or outside the tested envelope | Anything |

## Hardware and operating system

| Configuration | Tier | Evidence and notes |
| --- | --- | --- |
| Apple M5 Pro, 48 GB unified memory, macOS 26.6.2 (25G83), Apple silicon | 1 | The development host. Every physical local-inference, thermal, tool-route and installed-UI record in `docs/QUALIFICATION_EVIDENCE.md` comes from this single machine (builds 132, 133 and 153; build 156's exact frozen candidate has passed the complete automated source and candidate gates and still awaits its own candidate-bound hardware rerun, see Known limitations) |
| Other Apple-silicon Macs (M1–M4 families, other core counts) | 3 | Architecture and deployment-target checks are automated; no physical run |
| Apple-silicon Macs with 8, 16, 24, 32, 64 or 96 GiB | 3 | Memory admission thresholds are proven by injected-memory tests only; the 48 GB floor for the qualified route and the "2 × model size + 4 GiB" Compatibility floor are policy, not measured performance |
| macOS 15.0 (declared minimum) through current | 3 | Each bundled Mach-O declares ≤ 15.0 and this is verified at build; no physical macOS 15 run has been performed |
| Intel Macs | 4 | Not supported; the build and the app refuse x86_64 |
| Managed/enterprise, network, external-volume or mobile home directories | 4 (structurally 3) | Non-`/Users` homes are admitted only when their whole ancestry is root/current-user-owned, non-writable and ACL-free; nothing else is qualified |

## On-device models (app-owned Ollama route)

| Configuration | Tier | Evidence and notes |
| --- | --- | --- |
| Official Ollama.app 0.33.2 – 0.33.x (signed `ai.ollama.ollama`, team `3MU9H2V9Y9`) with exact `qwen3.8:27b-mlx` (manifest SHA-256 `5642e974…2cf7e`) on a ≥ 48 GB Mac | 1 | Fast/Balanced/Deep profiles, reasoning controls, Metal/MLX residency, thermal Eco/emergency behaviour, bash/filesystem/project tool routes and quit cleanup were exercised on the M5 Pro host (Ollama 0.33.2, build 153; the same route is the build-156 contract) |
| `qwen3.8:27b-hermes` (older selection) | 1 for earlier builds, 3 now | Physically exercised on builds 132/133 (Ollama 0.33.0/0.33.1); build 156 preserves an existing Hermes selection but runs it as an unqualified Compatibility route with reasoning disabled |
| Any other installed Ollama model that reports completion + tools, no model-specific thinking mode, 8,192–1,048,576 context, and passes the RAM floor | 3 | Admitted only in fixed **Compatibility** mode (8K context / 2K output, text and tools only, no Fast/Balanced/Deep, no Flash Attention/q8 KV). Admission is policy-tested; behaviour of that model in agent workflows is untested and may be poor |
| Thinking-capable alternate models, models below 8K context, models without tool support | 4 | Refused rather than guessed at |
| Ollama 0.34 or newer, pre-release, Homebrew-built or otherwise non-official binaries, a system Ollama on port 11434 | 4 | Fail closed / never adopted; Fulmar always starts its own verified child |
| Custom Ollama model-store folder | 4 | Not selectable in this release (standard `~/.ollama/models` only) |

## Cloud and network providers

| Route | Tier | Evidence and notes |
| --- | --- | --- |
| DeepSeek API (Chat Completions protocol, V4 catalog: `deepseek-v4-flash`, `deepseek-v4-pro`, `deepseek-v4-flash-vision-exp`) | 2 | Request/stream/tool/cancel/auth/retry/limit fixtures pass. A live request reached DeepSeek once with a **no-credit** key and produced the expected bounded error without leaking the key; a **successful** live chat, tool call or cancellation has not been run and is not claimed |
| OpenAI Responses / OpenAI Chat Completions (built-in OpenAI route and custom endpoints) | 2 | Fixture coverage only; no live account test |
| Anthropic Messages (built-in Anthropic route and custom endpoints) | 2 | Fixture coverage only; no live account test |
| Custom OpenAI-compatible or Anthropic-compatible server on a loopback / RFC 1918 / IPv6-ULA address (**Local network** route) | 3 | Editor structure, round-trip configuration and no-auth rules are tested; the server itself, its model, streaming, tools, cancellation and privacy behaviour must be qualified by you. It does not receive Fulmar's Ollama sandbox, RAM or thermal protections |
| Any other provider protocol, proxies, custom certificate authorities, mutual TLS, arbitrary headers | 4 | Not offered |

## Features

| Feature | Tier | Notes |
| --- | --- | --- |
| Native window, menus, Quick Chat, Task History, Command Center, Settings, Diagnostics, Schedules, Task Inbox | 1 (automated + installed-UI evidence on the M5 Pro host for earlier builds) | Build-156 installed menu/status-item/handoff evidence is still required by the release checklist |
| Local `stdio` MCP servers with native per-call approval | 1 (candidate canaries) | Remote HTTP/SSE MCP is disabled (tier 4) |
| Skills import, fingerprinting, per-Workspace policy | 1 (automated) | Semantic prompt-injection risk remains |
| Approved exact-page `web_fetch` | 1 (candidate + installed real-Qwen canary) | Generic `web_search` is hidden (tier 4) |
| Thermal Eco / emergency circuit breaker | 1 (deterministic suite + physical recovery timing on the host) | Coarse macOS thermal state only |
| Automatic continuation after an output limit | 1 (automated + physical route runs) | Fixed twelve-follow-up budget |
| Screen Recording, microphone, speech, notifications, login item, background schedules, VoiceOver, contrast/motion settings, multiple displays | 3 | Automated layout/metadata coverage exists; the interactive allow/deny matrix is an open manual gate |
| Localisation | 4 | English-only UI and documentation |
| In-app updater | 4 | Hard-disabled; update by replacing the app manually with a backup of the previous one |

## Evidence pointers

- `docs/QUALIFICATION_EVIDENCE.md` — dated physical/candidate ledgers (builds 132, 133, 153).
- `docs/KNOWN_LIMITATIONS.md`, `docs/PUBLIC_RELEASE_READINESS.md` — open gates.
- `docs/RELEASE_NOTES_v1.2.36-preview.1.md` — the automated gate results for the exact
  preview source.
