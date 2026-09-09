# Qualification evidence — Fulmar release ledger

This is the append-only evidence ledger for the release candidate. Implementation,
source inspection, and a passing fixture are not a substitute for a pass against the
final archived application. Every final row must identify the archive SHA-256 and a
retained log. A skipped, blocked, or manual-only case stays visible.

## Required record format

| Field | Required value |
| --- | --- |
| Candidate | version/build, archive path, byte count, SHA-256, manifest SHA-256 |
| Environment | date/time zone, macOS build, architecture/hardware, RAM, free disk |
| Runtime | Node, DSH, Ollama, exact model tag and quantization |
| Invocation | exact command/interaction and relevant non-secret configuration |
| Result | Pass, Fail, Blocked, Not run, or Deferred; test counts and duration |
| Evidence | immutable or retained log path/digest; screenshots for manual UI rows |
| Limits | credentials, permissions, hardware, UI, or external services not exercised |

Do not turn a `Blocked`, `Not run`, or `Deferred` row into a pass by inference. A
rerun after any source, dependency, signing, entitlement, runtime, patch, or packaged
plugin change receives a new row and supersedes—never edits—the earlier result.

## Pre-candidate hardening evidence — 2026-08-21

These checks validate source/fixtures on macOS 26.6.2 (25G83), arm64, with bundled
Node 22.23.1 and DSH 0.1.1-rc.1. They do **not** qualify a final archive.

| Gate | Result | Executed coverage | Limitation |
| --- | --- | --- | --- |
| Transactional credential migration | Pass — 6/6 | success; all 12 forward helper failure points; corrupt read-back; source mutation; 16 seeded randomized fixtures; unsafe source permissions | Real Keychain migration against final helper remains in release verifier and requires user consent for legacy data |
| Performance profile host | Pass — 12/12 | catalog/schema, exact model context resolution, per-session output, inheritance, disposal, fail-closed middleware | Live Qwen measurements remain pending |
| Simulated OpenAI fixture | Pass — 1/1 | authenticated catalog, exact model, SSE, tool round trip, 429, fresh context, cancellation, no key in log | Full DSH/preloader integration awaits final candidate |
| Application termination barrier | Pass — automated lifecycle gate | no-unload/unload/grace/failure/timeout plus exact-PID stop barriers; post-Ollama Harness launch failure is reaped before failure, while unrelated processes survive | Interactive Dock/Apple-event quit and fresh-port relaunch remain manual candidate checks |
| Archive inventory/tree verifier fixture | Pass | 32,670 central-directory entries, 337,305,123 exact uncompressed bytes; 32,669 extracted tree entries matched by type/mode/bytes/symlink target | Exercised a prior local archive only; final candidate must rerun |
| Script/runtime syntax | Pass | release, migration, audit, SBOM/notices, archive, provider-fixture scripts | Syntax does not prove runtime behavior |
| Production dependency vulnerability audit | Pass — 0 findings | npm 10.9.8 audited 511 lock-bound dependencies (353 production, 63 optional, 96 peer) against `https://registry.npmjs.org/`; verifier accepted the current report at 2026-08-22T04:39:30.153Z | Pre-candidate report SHA-256 `e6328a7f95e8e8edbd4027709136a738804b03e2b568627721ce139b6f7dae4f`; final frozen archive must regenerate it |
| Semgrep security scan | Reviewed exception — 3 findings, no others | 242 rules, 165 files, approximately 99.9% parsed | All three findings flag authenticated literal `ws://127.0.0.1` use: one generated CSP site and two canary assertions. This is intentional loopback transport under random-token/Host/peer/nonce/PID controls, not external cleartext WebSocket permission |

## Final candidate ledger

This tracked file is itself part of the release source-input inventory. Therefore the
current candidate's results must not be appended here after that candidate is frozen.
Retain each complete attempt under the ignored, owner-controlled `build/` directory,
record its byte count and SHA-256 beside the manifest/archive identity, and preserve
failed, blocked, deferred, and passing attempts separately. A tracked summary may be
appended only in the next source revision, where it becomes history rather than a
mutation of the candidate it describes.

| Gate | Result | Date/environment | Candidate/log reference | Limits or follow-up |
| --- | --- | --- | --- | --- |
| Archive/manifest/tree/signatures/entitlements | Pending | — | — | — |
| Complete Swift and JavaScript suites | Pending | — | — | — |
| Empty + cloned runtime, sandbox, MCP hostile/upstream | Pending | — | — | — |
| Credential helper + transactional real-Keychain canary | Pending | — | — | — |
| Simulated connected provider + exact-origin/fresh-session contract | Pending | — | — | — |
| DeepSeek 402 typed balance failure + exactly one request/no retry | Pending | — | — | Generic provider-failure text is not a pass |
| First-party licence/SBOM state | Pending | — | — | Owner-selected MIT source state is exact paired files; candidate/SBOM/public-copy byte identity still requires final verification |
| App-owned Ollama real generation + Metal/MLX residency | Pending | — | — | Exact extracted-candidate supervisor gate required |
| Exact isolated `qwen3.8:27b-mlx` (SHA-256 `5642e97495e1a088883805981563dcdc4a040c2f53388b7a41d1f24d3622cf7e`) bash/filesystem/project canaries | Pending | — | — | The tag and immutable manifest digest must both match. |
| Dependency audit + SBOM + notices | Pending | — | — | Registry access required |
| Qualified private atomic installation + crash recovery + retained rollback lifecycle | Pending | — | — | Must run only after exact full-hardware evidence is current and all Fulmar processes are stopped; capture real journal/swap/receipt and cancel/retire SIGKILL boundaries plus explicit idempotent recovery. Archives are retained, and the public updater remains disabled |
| Interactive install/quit/relaunch and UI/permission matrix | Pending | — | — | User session required |
| Candidate status: `status-item-live` (20), `status-item-normal-actions`, `status-item-headless-handoff`, and negative peer | Pending | — | — | Must be lock/manifest/source/runtime/toolchain/archive bound; RuntimeLease is not an app peer |
| Installed status: `installed-status-item-live` (20), `installed-status-item-normal-actions`, and `installed-status-item-headless-handoff` | Pending | — | — | Installed tree must equal the candidate |
| Candidate + installed `status-item-physical-background-handoff` | Pending | — | — | Both exact targets must exercise real runtime/topology and protected stop in disposable state; synthetic handoff is not a pass |
| Toolbar baseline: macOS 26 global-coordinate render matrix + candidate/installed screenshots | Pending | — | — | Dedicated gate must run on macOS 26; minimum-macOS 15 visual/keyboard evidence remains separate |
| Live DeepSeek/OpenAI/Anthropic/custom routes | Not run | — | — | User test credentials not supplied |
| Developer ID/notarization/clean-Mac/update | Not run | — | — | Public credentials/environment unavailable |

## Final candidate run — 2026-08-22, 23:12–23:30 BST

This appended record supersedes the pending template rows above for every gate
marked `Pass`; the three explicit deferred/not-run rows remain open.

| Field | Recorded value |
| --- | --- |
| Candidate | Local Harness 1.1.0 (110); `build/Local Harness.app.zip`; 112,782,306 bytes; SHA-256 `4398a03e16aa221eb936a1c951552ae895e3689f6e049624e1dc9bd1dc639dd6` |
| Manifest | `build/release-manifest.json`; SHA-256 `31e93f37591c7beeba965e7ffd64ffc84efcee929d44e8862b48f649749b9d0a` |
| Retained log | `build/qualification-1.1.0-110.log`; 154,347 bytes; SHA-256 `2100807516475013f4b562a49241bc783eb8fa5d865492d2e7a5d5fc879d7177` |
| Environment | macOS 26.6.2 (25G83), arm64; MacBook Pro Mac17,9; Apple M5 Pro, 15 cores; 48 GB RAM; Europe/London |
| Runtime | bundled Node 22.23.1; DeepSeek Harness 0.1.1-rc.1; Ollama 0.32.15; exact model `qwen3.8:27b-hermes`, qwen3_5 family, 27.8B, safetensors, nvfp4 |
| Invocation | `zsh scripts/verify-release.sh "/private/tmp/LocalHarnessBuild/Local Harness.app"` with output retained through a pipefail-protected `tee` |

| Gate | Result | Executed coverage | Limits or follow-up |
| --- | --- | --- | --- |
| Archive/manifest/tree/signatures/entitlements | Pass | 32,656 bounded archive paths; 32,655 extracted bundle entries; 32,633 independently derived Runtime entries; exactly 10 declared Mach-O signing changes; 256 unchanged build inputs | Ad-hoc local signature; no Developer ID or notarization |
| Complete Swift and JavaScript suites | Pass — JavaScript 132/132; Swift 614/614 | Warning-clean native suite plus JavaScript unit, integration, hostile-input, inventory, topology, and runtime-policy coverage | Interactive AppKit behavior remains separate |
| Empty + cloned runtime, sandbox, MCP hostile/upstream | Pass | Authenticated ephemeral runtime; clean and cloned isolated DSH homes; real Seatbelt/process-group matrix; reviewed stdio MCP deny/allow-once/output/disposal; exact child cleanup | Interactive permission prompts not exercised |
| Credential helper + transactional real-Keychain canary | Pass — migration 6/6 | Exact Keychain reference/record bounds; all injected transaction failures; randomized fixtures; readback; source removal; telemetry-lock crash recovery | Used synthetic canary credentials only |
| Simulated connected provider + exact-origin/fresh-session contract | Pass | Exact model/default; catalog/stream/tool request-result topology; bounded error; cancellation; clean sessions; adjacent-origin denial | Simulated endpoint, not a live paid cloud account |
| App-owned Ollama real generation + Metal/MLX residency | Pass | Exact signed supervisor/PID/listener attestation; one bounded real generation; GPU residency; content-free evidence; exact shutdown | Uses the installed Ollama app and model store on this Mac |
| Exact isolated `qwen3.8:27b-hermes` bash/filesystem/project/realistic canaries | Pass — 4/4 | Real Qwen command, write/edit/read, compact project, and polished three-file falling-block build; exact topology, bounded sizes, JavaScript syntax, gameplay-feature, responsive-style, and no-network assertions | Generated content was intentionally not retained |
| Provider protocol matrix | Pass — 4/4 | Official DeepSeek chat completions, OpenAI Responses, Anthropic Messages, and custom OpenAI-compatible shapes; auth; streaming/split tools; cancellation; terminal 401; bounded 429/5xx retry; malformed/oversized rejection; secret suppression | Credential-free local fixtures prove protocols, not live service availability |
| Candidate web/RPC + performance telemetry | Pass | 17 typed methods, 87 mux frames, 15 host frames, 4 adversarial resolution probes, 2 bridge proofs, 5 MCP proofs, 8 content-free telemetry rows; exact local default before first blank session | No interactive visual inspection |
| Dependency audit + SBOM + notices | Pass | 511 exact npm paths plus Node and five local packages; zero unresolved production vulnerabilities; audit artifact SHA-256 `e6328a7f95e8e8edbd4027709136a738804b03e2b568627721ce139b6f7dae4f` | Audit evidence timestamp 2026-08-22T04:39:30.153Z |
| Interactive install/quit/relaunch and UI/permission matrix | Deferred | Automated lifecycle, readiness, update-helper, and native window-construction tests passed | Requires a user-driven Dock/Apple-event session; candidate was not installed over the existing app |
| Live DeepSeek/OpenAI/Anthropic/custom routes | Not run | Protocol matrix passed without real credentials | User API credentials were not supplied; no claim of live cloud acceptance or billing behavior |
| Developer ID/notarization/clean-Mac/two-version update | Not run | Archive updater/preflight and extracted-candidate update tests passed | Developer ID, notarization profile, second clean Mac, and a prior signed release were unavailable |

## Final candidate icon repair and rerun — 2026-08-22 23:43 to 2026-08-23 00:02 BST

The first candidate used the optional SF Symbol `whale.fill` without a fallback.
On this host that produced a square status item with no artwork: the menu remained
clickable through an invisible gap. The final candidate now draws an original
template terminal glyph in code, assigns an image-only status button and tooltip,
and includes a pixel-level regression that rejects blank or solid artwork. This
record supersedes the prior final run for the exact release artifact.

| Field | Recorded value |
| --- | --- |
| Candidate | Local Harness 1.1.0 (110); `build/Local Harness.app.zip`; 112,783,233 bytes; SHA-256 `6b2f251a95c06c44ed485fc07d616accb0b02e718117246e3d7df78e60c9a617` |
| Manifest | `build/release-manifest.json`; SHA-256 `1b68aec484a1dc8de5b7b0c489790385ff65f8e70ddd1648ce24960942037f62` |
| Passing retained log | `build/qualification-1.1.0-110-iconfix-unsandboxed.log`; 154,503 bytes; SHA-256 `e0c9c31b59818f861e4ce8b933a8b0e2e5c79eccc35d0e89a5b3feed25e19414` |
| Visual evidence | `/private/tmp/local-harness-fixed-open.png`; SHA-256 `463fbe19da48abe28aeb15a7720eacfc485082b35f97b85b10837d9d9caf7bd7`; rebuilt app foregrounded with visible terminal-shaped status item |
| Environment | macOS 26.6.2 (25G83), arm64; MacBook Pro Mac17,9; Apple M5 Pro, 15 cores; 48 GB RAM; Europe/London |
| Runtime | bundled Node 22.23.1; DeepSeek Harness 0.1.1-rc.1; Ollama 0.32.15; exact model `qwen3.8:27b-hermes`, qwen3_5 family, 27.8B, safetensors, nvfp4 |
| Invocation | `zsh scripts/verify-release.sh "/private/tmp/LocalHarnessBuild/Local Harness.app"` outside the outer Codex sandbox, with pipefail-protected retained output |

| Gate | Result | Executed coverage | Limits or follow-up |
| --- | --- | --- | --- |
| Menu-bar visibility | Pass — automated and visual | 18×18 original template artwork rasterized to non-empty bounded pixels; accessibility description; tooltip; image-only button; candidate opened and artwork observed | Full VoiceOver/manual appearance matrix remains user-session work |
| Archive/manifest/tree/signatures/entitlements | Pass | 32,656 bounded archive paths; 32,655 exact extracted bundle entries; 32,633 independently derived Runtime entries; exactly 10 declared Mach-O signing changes; 258 unchanged build inputs | Ad-hoc local signature; no Developer ID or notarization |
| Complete Swift and JavaScript suites | Pass — JavaScript 132/132; Swift 615/615 | Warning-clean native suite plus JavaScript unit, integration, hostile-input, inventory, topology, runtime-policy, and status-artwork coverage | Interactive AppKit behavior remains separately recorded |
| Credential transactions | Pass — 6/6 | Exact Keychain reference/record bounds, injected transaction failures, randomized fixtures, readback, source removal, and telemetry-lock crash recovery | Synthetic canary credentials only |
| Runtime, sandbox, MCP, web/RPC and providers | Pass | Empty/cloned authenticated runtime; real Seatbelt/process groups; reviewed MCP; exact web/RPC topology; DeepSeek, OpenAI Responses, Anthropic, and custom OpenAI-compatible protocol fixtures | Protocol fixtures do not prove a paid cloud account accepts or bills a request |
| App-owned Ollama and exact Qwen routes | Pass — 5/5 | Bounded candidate-owned real generation with exact PID/listener and GPU residency; bash, filesystem, project, and realistic multi-file tool paths using `qwen3.8:27b-hermes` | Local model latency and output quality remain workload-dependent |
| Interactive install/quit/relaunch and UI/permission matrix | Deferred | Candidate launch and menu-bar icon visibility were exercised; automated lifecycle gates passed | Clean install-over-existing-app, Apple-event quit, VoiceOver, and every system permission prompt remain manual |
| Live DeepSeek/OpenAI/Anthropic/custom routes | Not run | Credential-free protocol matrix passed | User API credentials were not supplied |
| Developer ID/notarization/clean-Mac/two-version update | Not run | Archive updater/preflight and extracted-candidate update tests passed | Required before public binary distribution |

### Retained blocked runner attempts

These are not relabelled as passes. `build/qualification-1.1.0-110-iconfix.log`
(SHA-256 `aaa0a01a985f21bf796feb84225824871c91f8e8ffff868220b71737b39bb74f`)
was blocked when the outer sandbox denied three temporary loopback listeners.
`build/qualification-1.1.0-110-iconfix-network.log` (SHA-256
`aee19c0364e4278ff232d16bbb72f77c99f3cce3093f792ba7412c54f79c375b`)
admitted loopback but still blocked nested `sandbox-exec`, producing six issues in
three native tests. The identical artifact subsequently passed every gate outside
that outer sandbox; the two blocked logs remain retained as runner diagnostics.

## Fulmar 1.2.12 build 132 final qualification — 2026-08-27

This record supersedes the earlier candidate records for the exact 1.2.12 (132)
artifact. It includes the authenticated native WebSocket transport repair, real
RFC 6455 loopback regression, non-blocking window-modal Workspace Recovery
confirmations, and the final installed-app interaction pass.

| Field | Recorded value |
| --- | --- |
| Candidate | Fulmar 1.2.12 (132); `build/Fulmar.app.zip`; 112,881,645 bytes; SHA-256 `bac37a0135b164e038a61de753dc74cedab7605c326c9cd151c219ac06e2e23e` |
| Manifest | `build/release-manifest.json`; SHA-256 `a8a10c17cb00f588b262332a01ea97def648712c2c4da64f5a5839f34ab2c16b` |
| Retained log | `build/qualification-1.2.12-132-final.log`; 171,521 bytes; SHA-256 `6f2a5bd306b941a214ebe508a24265b181b2fc5c5ebfb7ccb254301e1efced59` |
| Environment | 2026-08-27 00:43–00:50 BST; macOS 26.6.2 (25G83), arm64; Apple M5 Pro, 15 cores; 48 GB RAM; 372 GiB free at qualification time; Europe/London |
| Runtime | bundled Node 22.23.1; DeepSeek Harness 0.1.1-rc.1; Ollama 0.33.0; exact model `qwen3.8:27b-hermes`, qwen3_5, 27.8B, 262,144 advertised context, NVFP4 |
| Invocation | `set -o pipefail; make release-verify 2>&1 \| tee build/qualification-1.2.12-132-final.log` |

| Gate | Result | Executed coverage | Limits or follow-up |
| --- | --- | --- | --- |
| Frozen archive, manifest, tree, signatures and entitlements | Pass | 32,657 bounded archive paths; 32,656 exact source-bundle entries after extraction; 38,491 reviewed VendorRuntime entries/394,538,676 bytes; 282 unchanged build inputs; exactly 10 declared Mach-O byte changes | Ad-hoc private signature; Developer ID and notarization remain open |
| Complete source and native suites | Pass — JavaScript 157/157; Swift 653/653 in 23 suites | Warning-clean release build; syntax, unit, integration, hostile-input, security, persistence, thermal, lifecycle, transport and UI-controller coverage | Automated results cover exercised cases, not mathematical absence of defects |
| Credential and migration gates | Pass — 6/6 | Real-Keychain canary, exact readback, transactional failures, randomized fixtures, source removal and crash recovery | Synthetic canary secrets; the supplied DeepSeek burn credential was removed after its live error-path test |
| Runtime confinement, sandbox, Skills and MCP | Pass | Empty and cloned private homes, exact process groups, real Seatbelt matrix, bounded stderr/deadlines, stdio MCP deny/allow-once/output/disposal and exact child cleanup | Remote MCP remains intentionally disabled |
| Authenticated Web/RPC and native Quick Chat transport | Pass | 17 typed methods, 142 mux frames, 20 host frames, signed bridge proofs, real WebSocket upgrade regression, bounded stream/cancel/fork/archive, two automatic output-limit continuation turns | Native mux is now WebSocket rather than the obsolete SSE assumption that caused HTTP 426 |
| Provider protocols and switching | Pass — credential-free fixtures | Official DeepSeek Chat Completions, OpenAI Responses, Anthropic Messages and custom OpenAI-compatible request/auth/stream/tool/cancel/retry/error/limit shapes; exact-origin/fresh-session switching | Fixtures establish protocol behavior, not live paid-provider availability |
| Real local inference and tools | Pass | Candidate-owned bounded Qwen generation with exact PID/listener and Metal/MLX residency; exact local model completed bash, filesystem and project routes | Output quality and latency remain workload- and thermal-state-dependent |
| Dependency/SBOM/notices | Pass | 511 npm paths plus Node and five bundled packages; zero unresolved production vulnerabilities at 2026-08-26T12:23:13.626Z | Registry evidence is point-in-time |
| Interactive candidate and installed UI | Pass for exercised paths | Main window; close-all then Finder/Dock-style reopen in 0.165 s candidate/0.159 s installed; About; candidate Quick Chat exact `QUICK_CHAT_OK`; installed Quick Chat exact `INSTALLED_CHAT_OK`; in-flight Stop showed `Stopped` and re-enabled composer; Recovery confirmation appeared immediately as a sheet and cancelled without mutation; all 14 auxiliary window entry points opened with their intended identity | Screen Recording, microphone, speech, notifications, login-item and background-scheduler permission flows deferred |
| Interactive Workspace tool/recovery | Pass | Agent created and verified exact disposable file without manual continuation; Recovery previewed one modified file, explicitly confirmed overwrite, restored exact original bytes, then removed its disposable checkpoint/file | Deleted probe was moved to Trash; no pre-existing Workspace file was changed |
| Private installation and lifecycle | Pass | Exact candidate copied byte-for-byte to `/Applications/Fulmar.app`; About showed 1.2.12 (132); prior 1.2.11 (131) preserved at `build/rollback/Fulmar-1.2.11-131.app`; installed close/reopen took 0.159 s; Quit stopped exact DSH child; fresh launch reached Ready with new app/child PIDs | Rollback copy is local and not a notarized public release |
| Live DeepSeek route | Partial — expected account error handled | A user-supplied non-production key reached DeepSeek and produced the bounded insufficient-balance path without secret display; credential was then removed | No balance was available, so successful live chat/tool/cancel was not run and is not claimed |
| Live OpenAI/Anthropic/custom routes | Not run | Protocol fixtures passed | No live test credentials supplied |
| Public distribution | Not run | Private archive/install verification passed | Original/redistributable icon review, legal review, Developer ID, notarization, clean-Mac/minimum-macOS, VoiceOver/full permission matrix and two-version notarized update remain required |

## Fulmar 1.2.13 build 133 installed qualification — 2026-08-28

This record supersedes earlier build-133 attempts for the exact archive below. The
complete release command passed interactively, but its full stdout/stderr was not
captured to a retained repository log. That evidence gap does not invalidate this
private installation, but it does require a captured frozen rerun before describing a
future public binary as release-qualified.

| Field | Recorded value |
| --- | --- |
| Candidate | Fulmar 1.2.13 (133); `build/Fulmar.app.zip`; 112,888,305 bytes; SHA-256 `05980f8b341773278a9ad9716660a897f4b65d01630354b843cfa36fbde26111` |
| Manifest | `build/release-manifest.json`; SHA-256 `ba2029b3cc460292062df3f1306c3abfecaebee06e3a9bb0792cea409300dbfe` |
| Environment | 2026-08-28 BST; macOS 26.6.2 (25G83), arm64; Apple M5 Pro; 48 GB RAM; Europe/London |
| Runtime | bundled Node 22.23.1; DeepSeek Harness 0.1.1-rc.1; Ollama 0.33.1; exact model `qwen3.8:27b-hermes` |
| Invocation | `make release-verify`, then the candidate and installed live-web canaries, formal byte-tree comparison, nested signature verification, Accessibility inspection, and one real installed-Qwen exact-page task |
| Transcript limitation | Full release output was observed in the Codex task but not retained as a local log; rerun with pipefail-protected `tee` before public distribution |

| Gate | Result | Executed coverage | Limits or follow-up |
| --- | --- | --- | --- |
| Frozen archive, manifest, tree, signatures and entitlements | Pass | 32,660 bounded archive paths; 32,659 exact bundle entries; 32,636 exact Runtime entries; 287 unchanged build inputs; 10 declared Mach-O signing changes; installed `/Applications/Fulmar.app` matched the candidate byte-for-byte | Private local signing identity; Developer ID and notarization remain open |
| Complete source and native suites | Pass — JavaScript 165/165; Swift 655/655 in 23 suites | Source/runtime contracts, adversarial unit/integration/security/persistence/thermal/lifecycle/UI-controller coverage and warning-clean build | Passing exercised cases cannot prove mathematical absence of defects |
| Runtime, sandbox, Keychain, Skills and MCP | Pass | Real Seatbelt and process-group isolation, bounded stderr/deadlines, credential transactions/migration, six reviewed local plugins, stdio MCP deny/allow-once/output/disposal, and exact child cleanup | System permission-prompt matrix remains manual |
| Provider switching and protocols | Pass — credential-free fixtures | Official DeepSeek Chat Completions, OpenAI Responses, Anthropic Messages, custom OpenAI-compatible routes, exact-origin switching, retry/error/cancel/tool shapes and private identifier suppression | No live paid provider request; the DeepSeek account had no credit |
| Approved public-page fetch | Pass — candidate, installed, and real Qwen | Exact one-time HTTPS approval; private-address/redirect/MIME/body/expiry guards; unavailable `web_search` hidden; installed Qwen chose `Fetch https://www.darkbloom.dev/` and returned `FULMAR_REAL_QWEN_WEB_OK` without Search, Bash, curl, or a DeepSeek key | Exact-marker probe did not require a prose citation; citation UX remains a separate row |
| Local inference, thermal behavior and tool completion | Pass | App-owned bounded Qwen generation with Metal/MLX residency; bash, filesystem and three-file project routes; the formerly timing-out project completed after same-turn local post-tool output bounding; automatic continuation remained bounded | Output quality and latency remain workload-, model-, and thermal-state-dependent |
| Installed UI and lifecycle | Pass for exercised paths | App launched from `/Applications`; title was `Fulmar – Qwen 3.8 27B Hermes (Local) · On this Mac`; status was `Ready · On this Mac`; accessible New Session, Explore, Appshot, Chat, Workspace, access-mode and model controls were present | VoiceOver, microphone, Screen Recording, notification and login-item permission flows remain manual |
| Rollback | Pass — preserved | Previous 1.2.13 (133) installation retained at `~/Library/Application Support/Local Harness/Updates/App Backups/Fulmar 1.2.13 build 133 pre-final-tool-completion.app`; nested signature verified | Local rollback only, not a notarized public release |
| Public distribution | Not qualified | Secure update/archive machinery passed automated checks | Requires retained final log, Developer ID, notarization, clean-Mac install/update, and remaining manual permission matrix |

## Fulmar 1.2.33 build 153 superseded hardware qualification — 2026-08-30

Build 153 passed the complete frozen-candidate hardware verifier, but the final
forensic UI/action audit then changed source and tests. Build 154 therefore supersedes
it. This record preserves the exact evidence that exists without relabelling the
missing transcript or deferred live desktop rows as passes.

| Field | Recorded value |
| --- | --- |
| Candidate | Fulmar 1.2.33 (153); `build/Fulmar.app.zip`; 112,147,583 bytes; SHA-256 `dfa0825dea32a51416a579a22a7079123d3c321a72a8b5054d75279855b4a2df` |
| Symbols | `build/Fulmar.dSYMs.zip`; 9,418,286 bytes; SHA-256 `518cd4d78a8078a22cb5761932d3a95957a1898f1fca4d24007348e9250746d0` |
| Manifest | `build/release-manifest.json`; 1,640 bytes; SHA-256 `af6c38df3139322b8978f5f475172fbc26994e5e6949d94fece2e8609ee5d9a8` |
| Source inventory | 425 inputs; SHA-256 `6f507ab8039e36fe971dbf59f086912c6c8042bc873f5df0f5ec90ba6a596316` |
| Hardware summary | `build/ci-evidence-summary.json`; 2,580 bytes; SHA-256 `85c3ea5017c6bc5a78de78927eda385540e1eeedf18de231248898d2aab9ea4d` |
| Transcript limitation | The full output was observed in the Codex task but was not retained as a local build-specific log. Build 154 adds fail-closed transcript retention and must rerun. |
| Environment | macOS 26.6.2 (25G83), arm64; Apple M5 Pro; 48 GB RAM; Europe/London |
| Runtime | bundled Node 22.23.1; DeepSeek Harness 0.1.1-rc.1; Ollama 0.33.2; exact model `qwen3.8:27b-mlx` |

| Gate | Result | Executed coverage | Limits or follow-up |
| --- | --- | --- | --- |
| Frozen archive and complete source suites | Pass | 32,660 extracted entries; JavaScript 357/357; Swift 833/833 in 26 suites; 425 inputs unchanged at completion; signatures, entitlements, inventories, SBOM, notices, dependency and static-security gates passed | No retained full transcript; superseded by changed source |
| Runtime/provider/security matrix | Pass | Empty/cloned authenticated runtime, Seatbelt/process groups, credential transactions, MCP, Web/RPC, DeepSeek/OpenAI/Anthropic/custom protocol fixtures, error/retry/cancel/secret bounds | Credential-free fixtures do not prove successful paid cloud inference |
| Real local hardware and tools | Pass | Candidate-owned Qwen generation with GPU residency; full DSH Bash, filesystem and project routes; 120–121 second continuously nominal recovery after every workload | Content-free evidence; output quality remains nondeterministic |
| Toolbar render matrix | Pass — 2/2 | Actual macOS 26 light/dark/minimum/normal status-model optical alignment; legacy full-height negative control rejected | Minimum macOS 15 visual row remains external |
| Live status/menu/action/handoff | Deferred | Gate bound itself to exact build 153, then refused to run because the desktop was at `com.apple.loginwindow` | Not a pass or candidate failure; build 154 must run unlocked |
| Installation | Not run | Existing Fulmar 1.2.16 build 136 remained installed and untouched | Build 154 must qualify before manual replacement |
| Public distribution | Not qualified | Private local signing only | Licence/legal, Git history, Developer ID, notarization, clean-Mac/minimum-OS, permission matrix and updater journal remain open |
