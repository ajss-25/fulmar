# Release checklist — Fulmar 1.2.36 build 156

This is a candidate checklist. A checked implementation item means the capability is
present in source; it is not release evidence. Qualification items remain unchecked
until their actual output is recorded in [TEST_PLAN.md](TEST_PLAN.md).

## Implemented product scope

- [x] Native Harness shell, toolbar model picker, menus, shortcuts, readiness states.
- [x] One authoritative Workspace for main, Quick Chat, schedules, sandbox, Skills,
  MCP, and recovery.
- [x] Live DSH provider/model catalog with Ollama, DeepSeek, OpenAI, Anthropic, and
  configured compatible routes.
- [x] Exact-origin external consent and transactional default-route commit/rollback.
- [x] Credential activation returns to a zero-inference provider control plane;
  provider/model selection, boundary review, and **Use for New Tasks** remain a
  separate explicit transaction.
- [x] Quick Chat fails closed on catalogue drift with no implicit row-zero route and
  clears/rechecks attachments when model capabilities change.
- [x] Missing local-model recovery offers an explicit installed-model chooser, never
  substitutes row zero, and never downloads or mutates model weights.
- [x] Fresh main and Quick Chat sessions after provider/data-boundary changes.
- [x] Quick Chat streaming, typed approvals/questions, cancel, attachments, voice,
  Copy Last Reply, and privacy-aware export.
- [x] Task History continue, rename, branch, archive-without-delete, and export.
- [x] Bounded, source-labelled automatic continuation after foreground root
  `max-tokens`, with queued-user priority, subagent exclusion, and no partial-tool
  replay.
- [x] Skills inert import, fingerprint trust, project policy, read-only activation,
  and external disclosure modes.
- [x] Local-stdio MCP trust, fingerprints, provider/project binding, named credentials,
  native approvals, resource limits, and reconnect policy.
- [x] Remote HTTP/SSE MCP intentionally disabled.
- [x] Confirmed default-browser handoff and secure staged/quarantined/revalidated Harness downloads.
- [x] Fast/Balanced/Deep 48 GB profiles are restricted to exact qualified
  `qwen3.8:27b-mlx`; alternate installed models require bounded metadata admission
  plus conservative installed-size/RAM admission and receive fixed, unqualified
  text/tools-only Compatibility 8K/2K.
- [x] Adaptive thermal control with local-only Eco output/rest limits, no nominal
  wall-clock shutdown, a continuous-constrained fail-safe, serious/critical
  exact-process stop, persisted cooldown, nominal recovery window, background-
  schedule gating, and fail-closed shutdown verification.
- [x] Transactional Workspace Recovery plus separate DSH-state backup/rollback.
- [x] Route-aware schedules using the authoritative Workspace and explicit external
  unattended consent.
- [x] Private bounded wake helper with due-only launch, 1,000-schedule limit, and
  one-shot idle exit; it never keeps the model resident at login.
- [x] Task Inbox age/count/byte retention, off-main body loading, truthful save
  failures, confirmed per-result/clear-all deletion, and streaming entry/deadline
  budgets for Inbox and occurrence-journal scans with typed unavailable state.
- [x] Content-free bounded performance history with user-controlled clearing.
- [x] Lazy off-main local-knowledge bootstrap with coalesced load/cancel/retry,
  no-follow bounded storage/index inspection, distinct unavailable state, and deferred
  bounded/retryable deleted-item cleanup.
- [x] Serialized exact-process stop/restart ownership with stale-callback rejection.
- [x] Owned-Ollama crash recovery is limited to three backed-off attempts per minute;
  stable readiness resets the circuit, while Quit/thermal/provider/Stop cancels a delay.
- [x] One authoritative packaged DSH root and a guarded exact-origin Fetch transport
  for DeepSeek, OpenAI, Anthropic, and custom compatible routes.
- [x] Local/connected tasks expose approved exact-page `web_fetch`; unavailable
  credential-bound `web_search` is hidden and shell-network fallback is prohibited.
- [x] Per-account credential mutations use a private durable journal, exact read-back,
  atomic metadata commit, bounded locking, idempotent recovery, and fail-closed handling
  of unexpected values without storing credential bytes in the journal.
- [x] Service logs buffer complete per-stream lines and copied support reports reapply
  reviewed credential/private-key/path redaction before sharing.
- [x] Constructed native Settings, Schedule, auxiliary, and workspace recovery/thermal
  states have Aqua/Dark minimum-layout, scrolling, control-action, and accessibility
  coverage.
- [x] Candidate evidence and supplied Apple notary records have exact-candidate,
  privacy, drift, consistency, and issue-free validation guards. These guards do not
  supply a Developer ID, notarization, or public clearance.
- [x] Candidate UX is explicitly English-only and does not claim a dedicated first-run
  onboarding assistant.

## Automated qualification gates

- [ ] Release Swift build completes with warnings treated as errors.
- [ ] The checked-in live status-item gate passes twenty isolated cold launches of the exact
  candidate: one stable top-visible `Fulmar menu`, real AXPress, required menu items,
  exact-PID Quit, and an empty same-bundle process inventory on every cycle.
- [ ] The manifest/source-inventory-bound candidate passes `status-item-normal-actions`
  and `status-item-headless-handoff`: ordinary Open Fulmar, Chat, Settings, protected
  Quit, and the synthetic accessory-to-foreground lifecycle all act on one exact app
  main PID without mistaking its RuntimeLease/Node children for app peers or allowing
  a stale application to supply evidence. Normal windows must be active, focused, and
  intersect a real display.
- [ ] Both `status-item-physical-background-handoff` and its installed equivalent run
  the disposable-state physical `--background-schedule` path, reach real authenticated
  runtime/topology, open normally, complete the protected stop, hand off to one ordinary
  foreground app, and leave no orphaned helper. The synthetic status-item handoff is not
  accepted as this production-workload proof.
- [ ] After exact-copy installation, the installed app separately passes all four status
  targets: twenty-cycle, normal-actions, headless-handoff, and physical-background-
  handoff. Each proves it is byte-identical to the qualified candidate. The negative
  peer test refuses before launch and leaves the existing peer untouched.
- [ ] `make toolbar-render-macos26` passes on an actual macOS 26 host: the light/dark,
  900/1280-point matrix proves global control and glyph centres plus its legacy negative
  control. Candidate and installed screenshots show one baseline. The same archive
  receives a minimum-macOS 15 visual/keyboard check before any across-supported-OS claim.
- [ ] Complete Swift test suite passes with no unexpected issues or skipped critical
  tests; test count and command output recorded.
- [ ] JavaScript/runtime source syntax checks pass.
- [ ] The 14-test runtime-inventory adversarial suite passes; the complete reviewed
  VendorRuntime verifies; unsigned derivation, exact Mach-O signing transition, and
  extracted final Runtime inventory all match their release-manifest-bound artifacts.
- [ ] Credential helper CRUD and legacy migration canary pass; the helper executable
  is relinked before testing, changed-signature background metadata inspection finishes
  without authorization UI, and local Ollama resolve/describe invokes no helper.
- [ ] Sixty isolated credential cases pass: probe processes are SIGKILLed at every
  ordinary create/replace/metadata-less-adopt/remove checkpoint and every version-two
  foreground adopt/replace/remove checkpoint plus every token-bound malformed
  metadata-less record-removal checkpoint, restart to the exact prior, committed,
  or still-attention-required state, release their kernel locks, and pass twelve
  injected temporary-write/file-fsync/rename/directory-fsync persistence cases without
  touching the real Keychain.
- [ ] Complete-line service-log and copied-support-report redaction passes split,
  interleaved, concurrent, oversized, invalid-UTF8, multiline/unterminated-key, token-
  family, idempotence, and private-path fixtures.
- [ ] Every constructible native auxiliary surface, Settings tab, Schedule, and 900×600
  loading/failure/provider/thermal state passes Aqua/Dark geometry, action wiring, and
  accessibility metadata checks.
- [ ] Retained candidate evidence survives failed, signalled, killed, stale, drifted,
  and tampered reruns without deleting or mixing a prior valid set; supplied notary
  records pass bounded private Accepted/matching-UUID/issue-free validation.
- [ ] Exact Node `22.23.1`, DSH `0.1.1-rc.1`, dependency lock, SBOM, notices, and
  production vulnerability audit pass.
- [ ] The first-party licence state is exactly one fail-closed state: both files absent
  and all Fulmar components explicitly unlicensed for private use, or both selected
  files present with a supported SPDX/LicenseRef expression and byte-identical app/SBOM
  binding. Partial, invented-identifier, or digest-mismatched states fail.
- [ ] Authenticated empty-state and cloned-state runtime canaries pass without source
  state mutation.
- [ ] HTTP/WS/Host/CSP/identity and exact-origin provider egress matrices pass.
- [ ] Mux/frame/whole-turn/tool/interaction/main-actor backpressure tests pass,
  including large-frame saturation and exact-session cancellation after transport or
  aggregate overflow.
- [ ] Guarded Fetch authority/transport-option, direct-stream, redirect, TLS-default,
  and 16 MiB response-bound regressions pass.
- [ ] Approved-page fetch unit/runtime matrix passes URL normalization, per-call ask,
  strict-local one-shot egress, DNS/TLS private-address rejection, redirect/MIME/body
  bounds, capability expiry, and absence of unavailable `web_search`.
- [ ] A fresh installed local-Qwen task with a real public HTTPS URL retrieves the
  page after exact one-time approval and performs no DeepSeek-key, `web_search`, or
  Bash/curl fallback.
- [ ] An ordinary installed local-Qwen research answer cites the approved page in its
  prose; the qualification probe deliberately required an exact marker instead.
- [ ] Provider transaction success, conflict retry, cancellation/failure, and rollback
  matrices pass with simulated endpoints, including missing committed routes and two
  provider IDs sharing one origin without implicit fallback.
- [ ] The candidate provider matrix proves DeepSeek 402 is surfaced as a balance-specific
  terminal error with exactly one request and no retry; generic provider-failure wording
  alone must fail the gate.
- [ ] The exact host/browser provider-failure taxonomy parity and pinned DSH frame/history
  compatibility tests pass. Model-preparation failures are sanitized before the agent
  loop can persist them. A hostile failure containing a credential, bearer token,
  private path, URL, environment-key reference, and provider request ID reaches live
  retry/turn-end plus ordinary/subagent history reload with only the finite app-owned
  category, validated status, and bounded retry delay retained.
- [ ] DSH raw Harness-log export remains fail-closed; native Task History transcript
  export contains no provider-failure event or raw diagnostic.
- [ ] Public clean-install evidence begins with no Fulmar Application Support, DSH home,
  or Fulmar backup. Retained-state qualification must prove the provider-history epoch-1
  home transaction plus format-4 backup/catalog/journal and versioned runtime-migration
  gates at every interruption boundary; the browser legacy-row sanitizer alone does not
  close this gate.
- [ ] Direct credential replace/remove success, apply-then-response-loss,
  confirmed-not-applied, and readiness-unavailable cases pass; active removal or
  uncertainty triggers a control-plane-only restart and never claims rollback.
- [ ] Shared-Workspace live tool matrix passes read/search/write/edit/child cases from
  main, Quick Chat, and schedule execution.
- [ ] Fresh-session regression proves old local/cloud task IDs/context are not reused.
- [ ] Skills mutation, disclosure, boundary, activation, limits, and read-only tests
  pass, including hostile trust-state identities/schema/size/count, atomic persistence
  rollback, and bounded/deadline package/audit/active-catalog enumeration.
- [ ] MCP registration/approval/revocation plus hostile startup/tool-count/output/
  timeout/reconnect/child-egress tests pass; remote transports remain rejected.
- [ ] Task History action and Quick Chat/History export tests pass, including redaction,
  attachment exclusion, bounds, permissions, collision/no-overwrite, and cancellation.
- [ ] External-link handoff and secure-download hostile corpus passes URL confirmation,
  extension/MIME/signature mismatch,
  executable, oversize, symlink/swap, quarantine, revalidation, and save cases.
- [ ] Workspace journal snapshot/preview/stale/conflict/integrity/limits/automatic
  rotation and injected-failure rollback tests pass.
- [ ] Schedule route/boundary/consent/timeout/cancel/result and exact Workspace tests
  pass, including bounded Inbox retention, hostile-file deletion, off-main loading,
  scan-flood/deadline/read-failure unavailability without false empty counts,
  unsaved-result activity reporting, background migration/readiness cleanup, and
  crash-consistent occurrence reconciliation without duplicate external runs. The
  synchronous admission latch must reject post-quiesce Run Now/due work and late
  checkpoint callbacks until verified readiness.
- [ ] Runtime-upgrade state rejects malformed, oversized, linked, public, or
  inconsistent bytes without creating a backup or starting a service; durable
  owner-only state replacement and pending-recovery behavior pass.
- [ ] Activity history adversarial gate passes: 500 rows/4 MiB/title/detail limits,
  no-follow/private identity, malformed/sparse/link/hard-link/permissive rejection,
  atomic write/rename failure rollback, durable interrupted-state recovery, and no UI
  publication of unpersisted rows.
- [ ] Privacy retention adversarial gate passes: descriptor-relative 0700/0600 ledger
  first-create and rotation at every pre/post-rename/directory-fsync boundary with
  immediate relaunch, plus strict 64 KiB app-owned Harness receipt attestation against
  permissive, linked, swapped, sparse/oversized, malformed, and future-schema state;
  no rejected fixture deletes an attachment.
- [ ] Local-knowledge adversarial gate passes: main-actor lazy construction and
  background-required first use, coalescing/cancel/retry/concurrent mutation, exact
  document/text/chunk/posting caps, sparse/oversized/flooded/symlink/FIFO/hard-link/
  permissive/future-schema/deadline failures, no partial index publication, and
  deferred Trash failure/retry without delaying readiness. The same gate injects every
  mutation-journal/object/catalog/directory-fsync/rollback/commit boundary and proves
  exact failure bytes plus uncommitted rollback/committed retention after relaunch,
  including a historical committed journal left by failed cleanup before a later commit.
- [ ] Diagnostics remains lazy at app launch and its bounded settings reader rejects
  oversized, linked, malformed, or unsafe model state without blocking the UI.
- [ ] Release archive, manifest hash, nested signature, property lists, and frozen
  private-candidate verifier pass.
- [ ] With Fulmar and all bundled children stopped, `make private-install-qualified`
  re-verifies current retained full-hardware evidence, builds the external coordinator
  and helper with warnings as errors, proves matching private signer plus exact
  candidate/stage/current byte trees, fsyncs the immutable pre-swap recovery journal,
  completes one atomic exchange, writes its owner-only receipt, and leaves the exact
  prior app at the one hidden rollback stage. Run `make private-rollback-status` and
  retain its output.
- [ ] Inject real SIGKILL before swap, after swap, after receipt, after cancel/retire
  marker, after stage archive, and after record-directory archive. Status remains
  read-only and classifies every exact state; the matching explicit resume/finalize/
  cancel/retire command is idempotent. Receipt fsync uncertainty preserves the swapped
  pair, candidate absence remains recoverable, malformed/link/mode/extra/collision/ABA
  records fail closed, and no active app is deleted.
- [ ] After several successful real tasks, run `make private-rollback-retire`; confirm
  the rollback and records were archived, not deleted, and a later qualified private
  update is no longer blocked. Record retained archive disk usage and removal review.
- [ ] Update helper readiness accepts only its exact bounded frame after fail-fast
  validation; delayed, malformed, noisy, EOF, crash, and hang fixtures prove terminal
  quit authority is never inferred from mere process liveness.
- [ ] Cold/warm local Qwen completion and bounded full DSH tool route pass.
- [ ] Default local-Qwen traffic carries explicit `reasoning_effort: none`; enabling
  **Reason deeply** remains an explicit opt-in and cloud reasoning defaults are unchanged.
- [ ] Packaged DSH Web/RPC and native Quick Chat canaries force provider `length` /
  `max-tokens` finishes and prove the task reaches completion through authenticated
  Fulmar follow-ups without user input. Native output segments, approvals, questions,
  queued-user priority, non-success reasons, and the non-looping terminal budget are
  all verified on the exact candidate. Missing/stalled follow-up publication fails on
  the short continuation deadline with exact-session cancellation, and scheduled output
  preserves every segment under its aggregate 2 MiB boundary.
- [ ] Deterministic thermal Eco/policy/transition/persistence/write-batching suite
  passes; the real-Qwen release matrix remains deliberately bounded and does not run
  the former uncontrolled realistic stress canary.
- [ ] Official Ollama signature/team/identifier and running PID/CDHash match; private
  HOME/TMP, read-only model tree, loopback-only bind/egress sandbox denial matrix, and
  extracted-candidate `verify-app-owned-ollama-generation.sh` real generation,
  post-response PID/listener re-attestation, Metal/MLX residency, content-free
  evidence, and exact-child cleanup all pass.
- [ ] Frozen-candidate physical generation and bash/filesystem/project routes record
  official stable Ollama 0.33.2 in the admitted 0.33.x series. Versions below 0.33.2
  and 0.34-or-newer series fail closed; a later series requires a new Fulmar
  qualification rather than being claimed from parser tests.
- [ ] Quit/relaunch stops exact owned DSH/Ollama PIDs, leaves an unrelated process
  untouched, honors unload, and creates new random Harness/Ollama endpoints and auth.
- [ ] Repeated owned-Ollama crash canary proves three delayed attempts then visible
  lockout; Quit and thermal shutdown invalidate a pending retry without a new child.


- [ ] Owner confirms hardware, macOS version, free disk space, Ollama ownership, and
  model quantization in the evidence record.
- [ ] Dock launch, main/Quick Chat/History/Providers/Skills/MCP/Recovery/Performance/
  Schedules windows receive visual and keyboard smoke checks; external-link cancel/open is verified.
- [ ] Local-to-cloud and cloud-to-local warnings show the exact expected origin and
  create fresh empty tasks; test may use a simulated provider if no cloud key exists.
- [ ] On an unlocked desktop, the exact installed candidate's real model popup
  completes local → consented external → local with fresh tasks, exact boundary/status
  labels, keyboard operation, and VoiceOver evidence. Constructed target/action tests
  do not satisfy this row.
- [ ] Missing-qualified-model recovery is exercised from the frozen app: explicit
  installed-model chooser, no row-zero substitution/download, compatible alternate
  8K/2K admission, weight-size/RAM admission and refusal, and tool-less/thinking/
  short-context refusal.
- [ ] User deliberately completes or declines legacy Keychain migration; source-file
  behavior is inspected.
- [ ] User grants Screen Recording and completes Appshot capture/crop/redact/OCR/
  cancel/attach, or records that the permission exercise is deferred.
- [ ] User grants microphone/speech and completes on-device dictation/spoken reply, or
  records that it is deferred.
- [ ] Notifications, launch-at-login, and background scheduler remain opt-in and are
  tested only with explicit user permission.
- [x] A manual Workspace Recovery preview/restore is performed on disposable content,
  and exclusions are understood.
- [ ] Before installation, record the exact currently installed version/build and
  preserve its matching state snapshot. After the candidate passes, record the exact
  candidate version/build actually installed and the retained hidden rollback
  version/build reported by `make private-rollback-status`; do not infer any value from
  source metadata. Keep the stage and receipt together until several real tasks pass,
  then run `make private-rollback-retire` and record the non-destructive archive paths
  before a later private install. Rollback instructions are exercised or dry-run
  reviewed.
- [ ] App and five privileged helpers are non-ad-hoc, have their exact fixed identifiers,
  and resolve to one signing family; the extracted archive passes the same check.
- [ ] Known issues and residual risks are accepted by ajss-25; no unresolved critical or
  high security/data-loss finding remains.

## Optional provider qualification

These do not block local-only private use. They block claiming that the named route is
validated:

- [ ] DeepSeek API live chat/tool/cancel/error smoke using a non-production key.
- [ ] OpenAI API live chat/tool/cancel/error smoke using a non-production key.
- [ ] Anthropic API live chat/tool/cancel/error smoke using a non-production key.
- [ ] Each chosen custom OpenAI-compatible endpoint receives its own origin, TLS,
  model, tools, cancellation, error, and disclosure test.
- [ ] Provider cost, quota, retention, and terms are reviewed by the account owner.

No unchecked provider item may be summarized as passed.

## Public source publication gates

- [x] Owner selected MIT for original Fulmar source; exact top-level `LICENSE` and
  digest-matched `Config/ProjectLicense.json` are present together.
- [x] The source-preview third-party inventory is reviewed. In particular, modified
  `@earendil-works/pi-ai` 0.82.1 is bound to its exact upstream MIT terms, origin,
  normalized digest and Fulmar modification record.
- [x] The owner authorizes the Fulmar name and current generated icon for this source
  preview. Do not claim registered rights, originality, exclusivity, affiliation, or
  formal legal/trademark clearance.
- [x] Canonical repository, `ajss-25` maintainer/licence-holder identity, issue path,
  and private vulnerability-reporting path are documented.
- [x] Private vulnerability reporting, secret scanning and push protection,
  Dependabot, GitHub-owned SHA-pinned Actions, protected `main` with four required
  contexts, and immutable `v*` tags are configured.
- [ ] After the exact candidate commit exists, run Gitleaks and TruffleHog across every
  reachable branch/tag and retain both reports plus the manual index/history review.
- [x] The reviewed hosted toolchain identity is an active source pin and the expected
  GitHub App/repository identity is bound by source and repository controls.
- [ ] Pass both hosted workflows on their real GitHub runners for the exact candidate,
  including all four required `Verify source` job contexts and the separate GitHub
  CodeQL app check. A configured required check is not a passing check.

## Public binary distribution gates

- [ ] Complete the exact built-app third-party licence review. In particular, satisfy
  the `@img/sharp-libvips-darwin-arm64`/libvips LGPL/GPL notice,
  corresponding-source and relinking obligations for the shipped bytes. Source-only
  review does not close this row.
- [ ] Verify the application and all six local-plugin SBOM components carry the
  selected first-party SPDX expression and exact licence SHA-256; verify the signed app
  and exact nine-asset public package contain byte-identical first-party terms.
- [ ] Sign all nested code and app with the owner's Developer ID Application identity;
  require one team, a secure timestamp and hardened runtime on every executable,
  fixed app/helper identifiers, the exact reviewed app/Node entitlements, and no
  entitlements on other helpers or native modules.
- [ ] Prove which Node hardened-runtime exceptions are actually required under
  Developer ID. Remove any unnecessary JIT/unsigned-memory/library-validation
  exception and explicitly accept the residual risk of every exception retained.
- [ ] Submit to Apple; retain and validate the machine-readable `Accepted` receipt and
  matching issue-free notarization log; staple the exact final app; rebuild the ZIP;
  and pass online plus offline Gatekeeper on a clean Mac.
- [ ] Test install/uninstall on a clean non-developer Mac and minimum supported macOS.
- [ ] Complete keyboard, VoiceOver/basic accessibility, contrast, window-state, and all
  permission-denied/allowed flows on supported OS versions.
- [x] Implement nonce-bound exact-new-app PID/identity and authenticated Harness health
  before update commit, plus a durable authenticated replay journal, bounded automatic
  rollback for missing/invalid health, and fail-closed surfaced crash recovery.
- [ ] Add and approve a separately signed recovery authority for power loss after the
  old app leaves the current path but before the candidate arrives; the in-bundle app
  cannot replay that interval after reboot even though rollback/journal bytes survive.
- [ ] Exercise that two-phase in-app update and rollback across two notarized builds
  from the same Developer Team.
- [ ] Reverify published support/escalation, privacy, security, release notes, and
  known issues against the exact binary; complete privacy-manifest-scope,
  encryption/export, binary third-party, and formal name/icon/trademark decisions.
- [ ] Run `make public-release` with the explicit Developer ID identity, signing
  Keychain, and notarytool profile. Preserve the exact candidate identity printed when
  the operator pauses; do not rebuild while collecting its manual evidence.
- [ ] Create the owner-private `build/public-external-evidence.json` only from the
  retained real records for all eight documented external gates. Run
  `make public-external-evidence-verify`; confirm its candidate SHA/version/build match
  the final manifest. Then run `make public-release-finalize` with the same signing
  variables; it must not rebuild and its final distribution verifier must repeat the
  external-evidence check before reporting success. Never populate the record from a
  simulated, deferred, blocked, or inferred result.

Private release cannot be described as notarized while these gates are open. Public
binary distribution must not proceed. These binary gates do not prohibit an accurately
labelled source preview after every source-publication row above passes.
