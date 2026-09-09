# Delivery record — Fulmar 1.2.36 build 156

## Objective

Deliver a secure, high-performance private macOS desktop for DeepSeek Harness that
makes local Qwen a first-class private route, supports deliberately selected
DeepSeek/OpenAI/Anthropic/compatible providers, and adds native history, trust,
recovery, performance, external-link, download, schedule, and export controls.

The current delivery target is an evidence-backed, explicitly labelled MIT source
preview. It is not a claim of proprietary-app parity, official affiliation, a supported
downloadable binary, public notarization, or zero defects.

## Milestones

| Milestone | Deliverables | Exit evidence | Status |
| --- | --- | --- | --- |
| M1 Native baseline | AppKit shell, owned DSH lifecycle, bundled runtime | Clean launch/readiness | Complete in prior release |
| M2 Security foundation | Random authenticated origin, exact WebView, minimal environment, Strict Local filesystem/network guards | HTTP/WS/Host/CSP/identity/sandbox canaries | Complete in prior release; regression required |
| M3 Provider control plane | Live catalog, typed routes, Keychain refs, zero-inference credential activation, exact-origin consent, explicit model/default-route commit, missing-local-model chooser, transactional switch/rollback, fresh boundary sessions | Unit + simulated provider matrix + UI smoke | Implemented in source; build 156 regression required |
| M4 Unified Workspace | Main, Chat, schedules, sandbox, Skills, MCP, and recovery use one canonical root | Live multi-tool and schedule working-directory tests | Implemented and qualified through 1.2.4; regression required |
| M5 Native session UX | Chat approvals/questions/cancel/copy/export; Task History rename/branch/archive/export/continue | RPC contract, export, and live history tests | Implemented and qualified through 1.2.4; regression required |
| M6 Skills and MCP | Inert Skills trust/disclosure; fingerprinted local-stdio MCP with native approval and limits | Mutation/revocation, disclosure, wrapper, hostile-server tests | Implemented and qualified through 1.2.4; regression required |
| M7 Recovery and content safety | Transactional workspace checkpoints/restore; confirmed system-browser handoff; hostile download staging | Injected-failure restore and download/external-link matrices | Implemented and qualified through 1.2.4; regression required |
| M8 48 GB performance | Qualified-Qwen Fast/Balanced/Deep presets; fixed unqualified alternate-model Compatibility 8K/2K after bounded capability inspection; app-owned Ollama tuning, telemetry/recommendation, adaptive Eco mode and emergency thermal stop | Metadata admission/refusal, settings propagation, policy isolation, cancel, load/unload, thermal state machine, measured local canary | Implemented in source; build 156 release regression required |
| M9 Private candidate | Fulmar 1.2.36 build 156 package, complete automated/manual evidence, preserved prior app | Go/no-go checklist signed by owner | In progress |
| M9a Product truth and usability | Tabbed Settings, visible Chat/Agent navigation, searchable Command Center, current release/model contracts, accessibility labels, support report and error-state review | Source/DeepSeek contracts, Swift suite, visual/keyboard smoke | Implemented in source; qualification in progress |
| M9b Capability isolation | Default-deny typed routes for general search/image/audio/connectors; no reuse of conversation consent; one-shot approved public-page fetch | Adversarial policy/runtime tests, local-Qwen public-URL scenario, and source contract | Page fetch implemented; qualification in progress; credentialed capabilities remain disabled |
| M9c Public source preview | MIT source terms; reviewed third-party source inventory; canonical public identity; clean history; two independent secret scans; protected GitHub repository; hosted source workflows | Final all-ref reports, clean-checkout qualification, hosted runs and retained repository settings | In progress; source controls implemented, final GitHub execution evidence pending |
| M10 Credentialed APIs | Live DeepSeek/OpenAI/Anthropic/selected custom endpoint smoke with non-production test keys | Per-provider request/tool/cancel/error evidence and cost review | No funded disposable live-success evidence or quota; not claimed |
| M11 Public binary distribution | Exact binary third-party compliance, approved branding, Developer ID, notarization, clean-Mac/minimum-OS/accessibility/two-version update test | All public-binary checklist items checked | NO-GO: libvips obligations and external trust/manual gates remain open |

## Ownership and RACI

| Workstream | Responsible | Accountable | Consulted/informed |
| --- | --- | --- | --- |
| Scope, privacy policy, provider choice | Project engineering | ajss-25 | Provider terms and upstream documentation |
| App, security, migrations, tests, docs | Project engineering | ajss-25 | DeepSeek Harness, Ollama, Apple platform contracts |
| Cloud test accounts/keys and cost approval | ajss-25 | ajss-25 | Provider account owners |
| Screen/microphone/notification permission exercises | ajss-25 | ajss-25 | macOS privacy UI |
| Source-preview name/icon authorization | ajss-25 | ajss-25 | Formal legal advice not claimed |
| Binary third-party, mark, privacy and export review | ajss-25/legal adviser | ajss-25 | Rights holders as required |
| Developer ID/notarization/public rollout | Release engineering | ajss-25 | Apple Developer services |

## Private definition of done

Fulmar 1.2.36 build 156 is ready for private use only when:

- all source and runtime checks complete without release-blocking warnings or failures;
- local DSH-to-Qwen chat and a representative read/write/edit/search tool matrix pass
  in the authoritative Workspace after a cold app launch;
- local Qwen can retrieve a user-supplied public HTTPS page after exact-URL approval,
  with unavailable general search hidden and no shell-network fallback;
- provider switch/rollback, exact-origin egress, fresh sessions, credentials, Skills,
  MCP, exports, downloads, schedules, and workspace restore pass their automated and
  required manual scenarios;
- quit/relaunch, cloned-state migration, app/state rollback, and the previous installed
  app's recovery path are verified;
- open issues are documented with owner acceptance and no unresolved critical/high
  security or data-loss issue remains; and
- the release checklist records actual evidence rather than inferred completion.

Local-only private use does not require live cloud credentials. A specific API route
is not considered validated until its separate credentialed smoke passes.

## Change control

Any change to the following is security- or data-significant and requires the full
release verifier, cloned-state canary, affected hostile-path tests, RAID review, and
checklist update:

- DSH/Node/Ollama contract or provider endpoint normalization;
- authentication preload, egress allowlist, sandbox grammar, or shared Workspace;
- Keychain schema/helper, provider transaction, or fresh-session trigger;
- plugin/Skill/MCP trust fingerprint, disclosure, approval, limits, or child process;
- external-link handoff, download staging, Appshot persistence, export redaction;
- workspace journal/restore, backup exclusion, schedule execution workspace;
- update/signing/notarization logic or helper entitlements.

Remote MCP, provider-scoped web search, cloud image generation, live cloud voice,
computer use, and cross-device sync are new security/data scopes, not minor settings.
They must not enter 1.2.36 through a waiver or by sharing the conversation provider's
network allowlist.

## Go/no-go authority

ajss-25 makes the private and source-preview release decisions after reviewing the
evidence and known limitations. A public source preview additionally requires final
history/secret scans, repository controls and hosted workflow evidence. Public binary
distribution separately requires binary third-party compliance, security/privacy and
formal mark/export review, Developer ID/notarization, and clean-machine sign-off. A
deadline never converts a failed safety gate into a pass.
