# Changelog

All notable Fulmar changes will be recorded here. Dates identify source candidates;
they do not imply that a downloadable binary is signed, notarized, or publicly
qualified. See `docs/QUALIFICATION_EVIDENCE.md` for exact test evidence.

## 1.2.36 (build 156) — 2026-09-02 — public source preview candidate (v1.2.36-preview.1)

Same Fulmar product version/build and runtime pin as the candidate below, with
dependency, licence, source-release reproducibility, CI and public-documentation
hardening. These changes alter release tooling, tests and tracked source bytes but do
not add a new end-user product feature:

- Moves the `qs` lock descriptor from 6.15.3 to 6.16.0 (GHSA-x5fp-wj9c-mxmx,
  GHSA-4mjr-xmp4-gh2g) and the `fast-uri` lock descriptor from 3.1.5 to 3.1.6
  (GHSA-f65p-4m7j-42xc, GHSA-fph4-wmhf-6fwf, GHSA-jqff-g426-hqxp,
  GHSA-5jgf-p345-68v8). Neither package is a direct dependency; no override or audit
  waiver was added, `ajv` 8.20.0 remains `fast-uri`'s only dependent, the runtime was
  rebuilt only through the pinned materialiser, and the production dependency audit
  reports zero findings. Reviewed lock SHA-256
  `408c97b76eb20998fc7fbf7b86d6ff901cab59061e5a72114ee429cdc4b8d6be`; regenerated
  `VendorRuntime.inventory.json` holds 38,501 entries / 394,622,078 bytes.
- Adds public-preview documentation: README front matter for first-time readers,
  `docs/SUPPORT_MATRIX.md`, `docs/TROUBLESHOOTING.md`,
  `docs/PREVIEW_BINARY_GATEKEEPER.md`, `docs/BUG_REPORT_CHECKLIST.md`,
  `docs/RELEASE_NOTES_v1.2.36-preview.1.md`, and consistent unofficial-status wording.
- Completes the source-preview third-party inventory for modified
  `@earendil-works/pi-ai` 0.82.1 by binding its exact upstream MIT terms, origin,
  normalization and Fulmar modification record. Public binary distribution remains
  blocked on the separate libvips LGPL/GPL notice/source/relink obligations.
- Adds source-bound hosted macOS image/Xcode/SDK/tool identity, an exact macOS 15
  consumer of the macOS 26 candidate, two-root unsigned build comparison, complete
  hash-locked Python/Semgrep closures, and content-bound GitHub artifact transport.
  Each control fails closed; implemented/focused-test status is not represented as a
  successful hosted run.
- Adds JavaScript/TypeScript-only CodeQL and public repository policy for private
  vulnerability reporting, secret scanning/push protection, Dependabot, SHA-pinned
  GitHub-owned Actions, protected `main` checks and immutable `v*` tags. Swift is not
  represented as CodeQL-scanned.
- Records the canonical `ajss-25/fulmar` repository, `ajss-25` maintainer/licence-holder
  identity and private vulnerability-reporting channel. The DSH/Node pins, deployment
  target and Fulmar version/build remain unchanged; the expanded release-test topology
  must be recorded from the final qualification run rather than copied from an earlier
  freeze.

## 1.2.36 (build 156) — 2026-09-01 — release candidate

- Makes public-distribution verification require one owner-private record containing
  all eight exact-candidate external gates. Missing, stale, deferred, placeholder,
  malformed, linked, non-private, or extra records now fail before the public success
  marker; a separate Make preflight exposes the same non-mutating check. The tooling
  never creates external evidence or infers it from automated fixtures.
- Keeps native Quick Chat subscribed across the exact source-labelled automatic-
  continuation turns after `max-tokens`, preserving each completed segment and all
  later approval/question events. Direct queued user work still wins, the terminal
  safety-summary turn cannot loop, and aborted, blocked, interrupted, unknown, or
  budget-exhausted endings are no longer presented as Ready.
- Adds a short native follow-up-publication deadline, exact-session cancellation when
  the packaged continuation is missing or stalled, race-safe priority for durable human
  turns, and complete multi-segment scheduled output under one aggregate response cap.
- Makes every transition back to the Normal local workload a verified persistence
  boundary. A failed write now keeps new local admissions and memory-pressure holds
  closed, prevents cooldown restart and green Ready, and remains visibly retryable
  without stopping an already-running turn. A blocked local Ready publication can no
  longer promote the endpoint, reopen the browser or schedules, release protected
  holds, acknowledge health/handoff, or succeed a readiness waiter; background
  promotion uses the same gate. Provider repair and cloud/custom routes remain
  available through retained local cooling, lock, and policy-repair state. A thermal
  block racing foreground Ready now defers final publication against the exact runtime
  generation and endpoint, finalizes it once after verified recovery, and exact-stops
  and restarts if that identity changed instead of stranding a control-plane-only
  endpoint or publishing stale Ready.
- Adds a separate local-only atomic installer for an already qualified private
  candidate. It re-verifies current source/archive/evidence, builds external tools in
  an isolated environment, requires the installed and candidate bundles to share the
  persistent private certificate and designated requirement, proves every byte before
  and after an APFS swap, and commits an immutable fsynced recovery journal before the
  exchange. Process death before/after the exchange and indeterminate receipt fsync are
  classified from exact physical proofs. Interrupted journal, receipt, and lifecycle
  temp writes are separately detected; explicit reconciliation archives their exact
  owner-private inode without deletion and reconstructs only repeatedly proven state.
  Real SIGKILL coverage now exercises temp creation, partial and complete file fsync,
  pre-rename, and post-rename/pre-directory-fsync boundaries for all three records;
  stale canonical-plus-temp evidence is retained, and unsafe ownership, links,
  duplicate temps, malformed leaves, archive collisions, and candidate absence fail
  closed without discarding evidence.
  A separate immutable preparation is committed before staging, so copy, disk-full,
  write, or fsync failure cannot leave an unexplained stage. Ordinary persistence
  errors retain their exact zero/partial temp for explicit reconciliation.
  Explicit idempotent resume/finalize/cancel/retire operations recover or archive the
  bound stage and records without deleting either app, unblocking later qualified
  private updates. The public updater remains disabled.
- Moves CI signing credentials and runtime bearer material through owner-only,
  already-unlinked descriptors, removes runtime authentication values from child
  environments, zeroizes consumed bytes, and expands adversarial descriptor, process,
  fixture-artifact, and real-Keychain coverage.
- Strengthens retained release evidence with descriptor-bound no-follow reads and
  directory identity/child-set revalidation, and freezes the complete Swift Testing
  topology so a missing, renamed, duplicated, newly skipped, or unselected test fails
  qualification instead of disappearing silently.
- Hardens every provider-failure boundary before retry, persistence, replay, and UI
  presentation. Successful and failed ordinary/subagent history now share fixed
  Host/browser sanitization, already-open sessions are cleared and reloaded, and a
  pre-bridge older-page request is guarded through its late completion. Raw Harness-log
  export remains disabled; retained pre-Fulmar session files are not rewritten.
- Preserves an explicitly stored or legacy-selected `qwen3.8:27b-hermes` route across
  upgrades instead of silently retargeting it to different MLX weights. Hermes is
  decoded and persisted as an unqualified Compatibility route with reasoning disabled;
  the qualified MLX route remains only the new-user default and explicit model choice.
- Moves backup-key and plaintext-credential migration behind the same executable trust
  boundary as runtime startup. The packaged app verifies its complete bundle before
  first use, accepts only canonical owner/root non-writable bounded Node, script,
  helper, and YAML files at their exact bundle locations, pins device/inode/SHA-256,
  and revalidates every component after the bounded child exits before admitting its
  output. A packaged app can no longer fall back to build products in the working
  directory.
- Replaces credential-record object serialization with bounded descriptor-only
  normalization and app-owned typed failures. Accessors, `toJSON`, symbols, sparse or
  non-enumerable entries, cycles, shared references, invalid numbers, and oversized
  graphs are rejected without reflecting plugin/helper diagnostics or credential text.
- Adds one bounded secure scavenger for empty DSH spill/subprocess directories while
  preserving non-empty, linked, special, changed, or unknown temporary artifacts.
- Centralizes Provider Center error copy, adds hostile-error regression coverage,
  qualifies the main Schedule window at its declared Aqua/Dark minimum, and visibly
  discloses that authenticated Harness backups are not encrypted and can contain chats,
  attachments, and durable tool-output spills.
- Adds a first-party signed Swift Testing host and fail-closed event ledger that counts
  nested suites and selected functions exactly, including adversarial unknown,
  duplicate, missing, late, cancelled, skipped, failed, and unanchored records.
- Adds authenticated update journaling, nonce/PID/signature-bound post-install health,
  deterministic replay primitives, bounded candidate termination, and lifecycle-safe
  cleanup. The update UI remains hard-disabled: reboot between the two app renames still
  requires a separately signed out-of-bundle recovery authority and real notarized
  two-version power-loss qualification.

## 1.2.35 (build 155) — 2026-08-31 — release candidate

- Corrects the credential process-crash qualification claim: the earlier 32-case gate
  covered ordinary create/replace/metadata-less-adopt/remove and persistence boundaries,
  but did not execute the version-two foreground repair methods. The gate now adds all
  18 adopt/replace/remove repair checkpoints, proving that a pre-mutation replace/remove
  kill restores explicit attention, adoption safely commits its freshly locked target,
  and every later kill recovers the exact selected repair.

## 1.2.34 (build 154) — 2026-08-30 — release candidate

- Supersedes build 153 after the final controller-wiring and minimum-window audit
  exposed five native UI defects: Activity double-click lacked an explicit target;
  two Quick Chat state controls lacked actionable click routes; Knowledge export and
  clear controls began enabled before empty-state evaluation; Task Inbox clipped a
  fixed-width table without a horizontal scroller; and MCP Review declared no minimum.
- Adds Aqua/Dark Aqua minimum-geometry and action-wiring coverage across every shipped
  native window or sheet that can be opened from Fulmar, including formerly private
  comparison, editor, Inbox, and approval surfaces. The fixes preserve public API and
  keep destructive empty-selection actions disabled.
- Restricts default-browser handoff to normalized credential-free HTTPS URLs, proves
  that cancellation performs no handoff, and adds exact-source citation guidance after
  an approved page fetch. Plain HTTP and embedded-credential destinations now fail
  closed.
- Makes full-hardware release verification retain an owner-only, build-specific log
  and candidate-bound checksum record. Verifier, recorder, candidate-drift, failure,
  signal, hidden-temporary cleanup, and zsh exit-status behavior are regression tested.

## 1.2.33 (build 153) — 2026-08-30 — release candidate

- Supersedes build 152 after the ordinary status-menu action gate exposed an
  incorrect verifier assumption: AppKit presents the Agent Workspace's fixed title
  and intentional model/boundary subtitle to Accessibility as one dynamic title.
- Keeps the production disclosure unchanged and narrows acceptance matching to the
  exact stable title for every window except the Agent Workspace. That one window may
  be either exactly `Fulmar` or `Fulmar – <nonblank subtitle>` and must still be the
  onscreen, main, focused window owned by the active exact candidate process. Chat and
  Settings remain exact-title checks, and close verification uses the same rule.
- Adds positive and adversarial matcher tests plus a controller test proving the
  stable `Fulmar` title and local/cloud model-boundary subtitles. Both candidate and
  installed copies must pass the corrected normal-action gate before qualification.

## 1.2.32 (build 152) — 2026-08-30 — release candidate

- Supersedes build 151 after the pre-freeze audit found that its real
  background-schedule-to-foreground test could not prove that the replacement
  foreground process retained the disposable user profile selected for the scheduler.
- Adds a release-only, explicitly requested physical-handoff acceptance environment.
  It accepts only an owner-controlled real directory directly beneath `/private/tmp`,
  exact private HOME and temporary roots, a canonical read-only Ollama model store,
  and five allowlisted foreground environment values. Malformed, linked, or relocated
  configurations fail closed; ambient secrets are not propagated. Ordinary launches
  do not select or propagate this acceptance environment.
- Adds a frozen-candidate physical gate that starts the ordinary background scheduler,
  reaches one durable due local-Qwen occurrence with real DSH/Ollama descendants,
  activates the protected handoff, verifies the replacement foreground window and
  identity-stable status menu, uses protected Quit, requires exact child cleanup, and
  proves the signed-in user's Fulmar state metadata remained unchanged. The candidate
  and installed copies must each pass this fourth status target before qualification.

## 1.2.31 (build 151) — 2026-08-30 — release candidate

- Supersedes build 150 after the expanded handoff soak exposed a second
  Launch Services observation race on cycle one: the returned running-application
  object briefly reported its default regular activation policy before Fulmar's
  pre-event-loop accessory policy became observable.
- Waits boundedly for the exact PID's current activation policy while requiring that
  it exposes neither an Accessibility status item nor an application window. The
  accessory policy must then remain stable through the pre-reopen dwell; exit,
  disappearance, visible UI, or a non-accessory policy still fails immediately.
- Retains build 150's 20-cycle, settled, fresh-identity status-menu proof. No repeated
  press, policy coercion, automatic retry, or relaxed menu assertion is permitted.

## 1.2.30 (build 150) — 2026-08-30 — release candidate

- Supersedes build 149 after its synthetic accessory-to-foreground handoff gate
  intermittently pressed an Accessibility element while the new bounded status-item
  placement recovery could replace that element. The first run found no menu on the
  stale handle; an unchanged retry passed, confirming the verifier race without
  erasing the original failed qualification attempt.
- Requires the handoff status item to settle, remain the same Accessibility identity
  with stable top-menu-bar geometry for five seconds, and still be the one freshly
  resolved item before one press. The required menu titles, enablement states, exact
  Quit, old-PID exit, and zero-peer proofs remain mandatory.
- Expands the release-bound synthetic handoff gate to 20 consecutive cycles and adds
  source-order regression checks so a retry, repeated press, longer blind timeout, or
  stale item can never be accepted as evidence.

## 1.2.29 (build 149) — 2026-08-30 — release candidate

- Supersedes build 148 after launches 1–14 passed the complete menu-bar proof but
  Control Center intermittently parked launch 15 despite correct v2 persistence and
  one-time visibility initialization.
- Adds a bounded, permission-free placement recovery using only Fulmar's own
  `NSStatusBarButton` window geometry. A persisted `isVisible == false` is respected
  as a user choice; only an item that AppKit calls visible while it is physically
  off the top menu-bar band can be detached and recreated, at most twice.
- Adds AppKit-coordinate tests for visible, off-screen, left-edge parking, overflow,
  and multi-display frames plus source gates for identity, user-choice, permission,
  and retry bounds. The external AX gate remains strict and still rejects every
  parked frame.

## 1.2.28 (build 148) — 2026-08-30 — release candidate

- Supersedes build 147 after its first v2 cold launch proved that macOS can park a
  brand-new autosave identity until the application explicitly initializes public
  `NSStatusItem.isVisible` state.
- Initializes visibility once per v2 identity and records a non-secret preference
  marker only after the public show action. Later launches restore AppKit's autosaved
  choice, so an explicit user hide remains respected rather than being reversed on
  every launch.
- Retains build 147's detach-before-programmatic-removal fix and adds native and
  source-order tests for both halves of the lifecycle. Build 148 remains unqualified
  until the complete live soak and release matrices pass its exact frozen archive.

## 1.2.27 (build 147) — 2026-08-30 — release candidate

- Supersedes build 146 after the real 20-cycle menu-bar gate passed seven complete
  cold launches and then caught Control Center restoring the sole Fulmar item at its
  off-screen parking coordinate on launch eight.
- Moves the public status-item autosave identity from v1 to v2 to discard the damaged
  placement record. Protected Quit now detaches that identity before AppKit removes
  the retained item, so programmatic lifecycle cleanup cannot become a persisted
  hidden preference while an explicit user removal during runtime remains respected.
- Adds a source-order regression gate for identity detachment before both AppKit
  removal paths. Build 147 remains unqualified until the complete release and live
  menu-bar matrices pass against its exact frozen archive.

## 1.2.26 (build 146) — 2026-08-30 — release candidate

- Supersedes every earlier build-145 artifact after the final independent audit found
  that live status evidence was not serialized with candidate assembly and could be
  attached to changed source or a stale candidate.
- Holds the same authenticated build lock through candidate verification, helper
  compilation, and live status execution; re-verifies the vendored runtime,
  toolchain, and current source immediately before launch.
- Detects only each Fulmar bundle's declared main executable as an app peer, so the
  expected `LocalHarnessRuntimeLease` helper is never misclassified as a second app.
- Strengthens normal menu-action proof to require an active application, a focused
  onscreen window, and an exact focused-window identity. Lightweight status cycles
  explicitly disable AppKit automatic menu-item enablement.
- Strengthens the toolbar render matrix with global toolbar-coordinate and global
  glyph-centre comparisons. macOS-26 render tests are explicitly skipped elsewhere,
  while the dedicated release target fails unless it is run on macOS 26.
- Raises the supported Ollama floor to the oldest physically qualified version,
  tightens DeepSeek 402 classification, and validates licence expressions against a
  pinned SPDX subset rather than grammar alone.

## 1.2.25 (build 145) — 2026-08-29 — release candidate

- Aligns the toolbar runtime status and model selector to the same fixed geometry and
  optical baseline, with rendered light/dark and narrow/wide regression coverage,
  a negative control for the former misalignment, and an ordinary-app menu-bar gate
  that opens Agent Workspace, Chat, and Settings before using protected Quit.
- Adds progressive memory-pressure protection alongside thermal controls: warning
  pressure admits cloud work but temporarily holds new local work; critical pressure
  cancels the exact local turn and releases the app-owned model safely.
- Adds a bounded official Ollama `/api/version` admission gate. Upstream 0.32.12
  first introduced Qwen 3.8/MLX, but Fulmar's honest release-qualified floor is
  0.33.2 because that is the oldest version exercised end to end on the development
  host; newer stable releases must still pass every existing model and DSH gate.
- Corrects the qualified Ollama model identity to the raw lowercase 64-hex digest
  returned by the official `/api/tags` wire format. The former `sha256:`-prefixed
  comparison made the real physical-generation gate reject the correct installed
  model; a real wire fixture now prevents that regression.
- Adds a terminal, non-retrying DeepSeek 402 insufficient-balance protocol case to
  the candidate-backed provider matrix, matching the documented response returned by
  an authenticated account with no available credit.
- Adds fail-closed first-party licence packaging without selecting legal terms: an
  unlicensed private build remains explicit, partial or mismatched policy files stop
  every build, and a future owner-selected licence is byte- and digest-bound through
  the signed app, SBOM, and exact nine-file public release set.
- Rebuilds workspace recovery around authenticated checkpoint metadata, bounded and
  cancellable scans, deterministic read-only fallback, atomic owner-only policy state,
  and a global fail-closed mutation guard across main chat, Quick Chat, schedules,
  browser tasks, subagents, and unknown tools.
- Hardens DSH and Ollama crash circuits, streamed tool-call identity, credential and
  migration rollback behavior, public-package verification, CI evidence, provenance,
  signing/timestamp/notarisation gates, and the guarded upstream DSH upgrade workflow.
- Keeps the bundled runtime pinned to reviewed DSH 0.1.1-rc.1. The newer rc.2 remains
  outside this candidate until its changed dependency and guarded-MCP contracts receive
  a separate full qualification.

## 1.2.24 (build 144) — 2026-08-29 — release candidate

- Supersedes build 143 before compilation after the new warning gate's initial
  source/execute guard treated sourcing as a direct CLI invocation and failed closed.
- Uses zsh's explicit evaluation context and regression-tests both sourced-library and
  directly executed gate modes before the production build can begin.

## 1.2.23 (build 143) — 2026-08-29 — superseded before compilation

- Supersedes the interrupted build 142 compile after an independent control review
  proved that linker and `dsymutil` warnings were visible but not machine-enforced.
- Captures the complete SwiftPM and per-product `dsymutil` pipelines, requires both
  the producer and log sink to succeed, and blocks the release on every warning.

## 1.2.22 (build 142) — 2026-08-29 — superseded before packaging

- Supersedes the interrupted build 141 compile after SwiftPM's automatic dSYM step
  proved unable to resolve object files rewritten by the linker's `-oso_prefix`.
- Retains the linker's reproducible mode, sanitized toolchain attestation, serialized
  debug-prefix mappings, relative dSYM executable input, exact symbol topology, and
  all-file privacy scans while returning object references to Apple's supported flow.
- Declared missing-object and no-debug-symbol warnings release-blocking, but build 143's
  independent review found the declaration was not yet machine-enforced; build 142
  therefore never qualified. No native/dSYM/signature/ZIP reproducibility is claimed.

## 1.2.21 (build 141) — 2026-08-29 — superseded before packaging

- Supersedes the interrupted build 140 compile after sandbox-context testing showed
  that `codesign` can return success while emitting an invalid-entitlements warning
  and no XML for the same privately signed bytes.
- Retains entitlement-extraction diagnostics and treats any non-`Executable` stderr,
  empty XML, invalid plist, or value mismatch as a release-blocking failure.

## 1.2.20 (build 140) — 2026-08-29 — superseded before packaging

- Supersedes the interrupted build 139 compile after an independent provenance audit
  showed that the production build still inherited ambient tool lookup and did not
  bind the compiler, linker, SDK, or operating-system build to the release manifest.
- Re-executes production assembly inside an exact allowlisted environment, serializes
  SwiftPM compilation, enables the linker's reproducible mode and relative debug-map
  objects, and records hashes and versions for the selected toolchain and SDK inputs.
- Binds that toolchain record into release-manifest schema 5 and re-verifies it after
  compilation and during extracted-release qualification.

## 1.2.19 (build 139) — 2026-08-29 — superseded before packaging

- Supersedes build 138 after adversarial symbol-archive testing found random Swift
  scratch paths in public dSYM metadata and three DWARF payloads.
- Applies debug-prefix mappings to serialized Swift module information, invokes
  `dsymutil` with a relative binary path, scans every dSYM file for private or
  temporary paths, and requires the exact reviewed dSYM topology and plist schema.
- Adds a permanent seven-mutation dSYM attack matrix before any candidate runtime
  can execute during release qualification.
- Uses supported macOS 26 XML entitlement extraction and the stable-signature-aware
  verifier for the simulated `/Applications` layout.

## 1.2.18 (build 138) — 2026-08-29 — superseded candidate

- Supersedes build 137 after an independent rebuild exposed developer checkout and
  random Swift scratch paths in the six shipped native symbol tables.
- Generates and verifies six UUID-matched dSYM bundles before scratch cleanup, strips
  local/debug symbols from the app before signing, and rejects any surviving `N_SO`,
  `N_OSO`, DWARF section, or private source-checkout prefix from the installed app.
- Publishes the dSYMs only as a separate bounded archive and binds its byte count and
  SHA-256 into release-manifest schema 4; the dSYMs are never installed in the app.

## 1.2.17 (build 137) — 2026-08-29 — superseded candidate

### Changed

- Uses only AppKit's documented status-item factory; a 54-launch isolated matrix found
  no placement benefit from the former private priority selector.
- Adds an in-app Menu Bar settings recovery path for macOS 26, where the user must
  allow Fulmar under System Settings → Menu Bar → Allow in the Menu Bar.
- Corrects the native toolbar's optical baseline so green runtime status and model
  text render level across widths, appearances, colours, and status strings.

### Security and reliability

- Rebuilt the live menu-bar gate around all-bundle peer exclusion, complete fail-closed
  BSD process enumeration, kernel start identity, exact-path cleanup, Quartz display
  geometry, a five-second placement dwell, and configurable release-soak cycles.
- Corrected the forensic record: both apparent build-136 third-cycle failures were
  contaminated by another Fulmar process sharing the same bundle/autosave identity;
  neither was an isolated product failure.
- Added deterministic status-item removal only after termination is irreversible,
  without persisting a hidden visibility preference.

Build 136 remains immutable failed-candidate evidence. Its broader qualification
results remain useful, but source changes and the flawed menu-bar test invalidate it
as a release artifact. Build 137 must be rebuilt and qualified from frozen inputs.

## 1.2.16 (build 136) — 2026-08-29 — release candidate

### Security and reliability

- Corrected the Semgrep default-pack rule count from 1,073 to 1,074 after the release
  gate caught a rule whose identity was not the first key in its YAML mapping.
- Replaced a brittle line counter and raw-order pin with a narrow length-framed digest
  of byte-exact rule blocks. It tolerates only top-level rule ordering while every
  rule byte, ID, count, response size, media type, and HTTPS origin remains bound.
- Compared three retained order variants object-by-object and through full Semgrep
  scans before accepting the unchanged 1,074-rule set; no rule content changed.

Build 135 remains immutable evidence for the prior private candidate. Build 136 must
complete a fresh frozen-candidate qualification before it supersedes that artifact.

## 1.2.15 (build 135) — 2026-08-29 — release candidate

### Added

- Native local/cloud model switching with explicit data-boundary consent.
- Private app-owned Ollama/Qwen operation, performance profiles, adaptive Eco mode,
  thermal safeguards, and bounded automatic continuation.
- Quick Chat, Task History, Workspace Recovery, schedules, Skills, guarded local MCP,
  approved-page retrieval, diagnostics, backups, Appshots, and accessibility support.
- Reproducible runtime reconstruction, deterministic inventories, SBOM/notices,
  dependency auditing, and pinned static-security CI.

### Changed

- Renamed the visible product to Fulmar while retaining legacy technical identifiers
  required to preserve existing settings, Keychain items, schedules, and app data.
- Aligned native toolbar status/model text and made Settings and companion windows
  reachable at their declared minimum sizes.
- Replaced abrupt thermal pauses during ordinary warm work with local-only adaptive
  output limits and inter-generation rest; serious/critical pressure still stops the
  exact app-owned processes.

### Security and reliability

- Bound provider DNS resolution and connected peer addresses to declared cloud,
  local-network, or on-device boundaries to resist rebinding and mixed-answer SSRF.
- Hardened credential, sandbox, plugin, MCP, update, recovery, log-redaction, runtime
  inventory, and child-process lifecycle boundaries with adversarial tests.
- Removed DeepSeek Harness stable installation/session identifiers from the bundled
  direct adapter and strips those headers again at the guarded transport boundary.

### Open public-release gates

- Developer ID signing, Apple notarization, clean-Mac/minimum-macOS qualification,
  permission/accessibility manual testing, successful live DeepSeek qualification,
  project licensing, and final legal/trademark review remain open.
