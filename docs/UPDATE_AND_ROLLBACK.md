# Update and rollback — Fulmar 1.2.36 build 156

## Before replacing the current app

1. Finish or stop active turns and scheduled work.
2. Confirm the authoritative Workspace is healthy and create a manual Workspace
   Recovery checkpoint for recoverable source content.
3. Create a separate Harness-state backup for DSH history/settings.
4. Preserve the installed `.app` with its version/build and record its signature,
   runtime versions, and archive hash if available.
5. Run the build 156 release and cloned-state canaries. Do not install a candidate
   whose evidence is incomplete or whose high-risk gate failed.

Workspace checkpoints and Harness-state backups solve different problems. Neither
contains Keychain credentials, and neither substitutes for preserving the old app.

## Runtime migration

After the app reaches Ready it records the installed DSH version. Before a different
bundled version starts, Fulmar creates a secret-excluding DSH-state snapshot
and a pending migration record. The record clears only after authenticated readiness.
Interrupted or failed startup offers the exact safety snapshot on the next launch.

Do not update a DSH prerelease just because a newer package exists. Review upstream
provider, RPC, WebUI, session/history, plugin, Skill, MCP, sandbox, and state changes;
update the exact pin/lock/SBOM/notices; and rerun the full empty/cloned-state/provider/
security matrix.

Trust decisions are version- and content-sensitive. A runtime update that changes a
community plugin, Skill package, MCP executable/interpreter/entry point, or project
identity must leave it blocked until re-reviewed. Do not migrate fingerprints by
display name.

## Application update verification

The current **Install Verified Update** implementation is hard-disabled and absent
from Fulmar's menus, including in Developer ID builds. The retained, unfinished
implementation can:

1. expand a local archive into a new private staging directory;
2. require exactly one app;
3. validate the complete nested signature;
4. require bundle ID `com.angadjairath.localharness`;
5. require the same Developer Team as the running app;
6. require a higher integer build number;
7. require Gatekeeper acceptance;
8. create a Harness-state safety backup;
9. launch the exact signed helper with a private bounded readiness channel;
10. wait for the helper's one fixed frame and EOF, emitted only after all fail-fast
    path/signature/attestation validation has passed;
11. irreversibly close runtime restart and mutation admission;
12. perform the one authorized Quit so no executable is overwritten in place;
13. remove the exact private staging operation on cancel, failed handoff, rollback,
    or the next update preparation without following linked or raced paths; and
14. retain the rollback created by the current update plus the two newest earlier
    valid automatic rollback apps. Manual or invalidly named recovery copies are
    never deleted by this policy.

Mere helper process liveness is never readiness. Early exit, malformed/noisy output,
timeout, or a hung helper is terminated and reaped without granting Quit authority.
The retained source path now also writes an owner-private HMAC-authenticated journal
before either rename, binding one random nonce to the exact old and staged inode,
CDHash, version, build, team, bundle ID, and three paths. It launches the candidate
executable as an exact direct child with an anonymous socket capability, waits a
bounded 120 seconds, and accepts only that PID's nonce-bound native acknowledgement
after authenticated Harness/provider readiness. Missing or invalid health terminates
the exact process group and restores the retained old app. Health acknowledgement and
commit are separate durable phases; replay chooses rollback before the health decision
and commit after it. A normal launch that encounters an unfinished/torn transaction
starts no runtime and surfaces the authenticated rollback path or a conservative manual
recovery warning. Symlinks, substituted identities, malformed phases and forged journal
bytes fail closed.

This is a strong but incomplete source implementation. Power loss after the old app has
been renamed to its rollback path and before the candidate occupies `/Applications` can
leave no launchable in-bundle executable after reboot. The authenticated record and exact
old app are preserved, but an operator must restore them manually because Fulmar does not
yet install a separately signed, out-of-bundle recovery authority. Journal creation itself
is atomically published from a fully fsynced private preparation directory, so a crash
before publication cannot authorize either rename; safe bounded temporary files from an
interrupted phase rewrite are ignored in favour of the last authenticated journal.

In-app update remains **NO-GO for public distribution** in build 156 and must not
be invoked through a menu, automation, or programmatic selector. The release
gate still requires the fault matrix and end-to-end exercise across two real Developer
ID signed, notarized, stapled versions on a clean Mac; source-state tests and private
ad-hoc identities are not that evidence. It also requires an approved out-of-bundle
recovery design for the interval where the main app path can be absent.
Developer ID builds can additionally be notarized and stapled, but build 156 must not
be described that way unless actual Apple evidence is recorded.

## Manual-install beta profile

The explicit `beta` public-release profile (`docs/PUBLIC_BETA_RELEASE_CONTRACT.md`)
does not enable, exercise or qualify the updater above. It requires proof that the
exact shipped candidate exposes no updater entry point, plus evidence that a person
completed the documented manual download/verify/install, quit, same-version
reinstall and manual rollback to a retained previous app on a clean Mac. That manual
workflow is the beta's only supported replacement route; it does not prove the
automatic journal/health/commit path, power-loss safety, or retained-state
migration, and release copy must not present it as such. Under the beta's
`clean-install-only` declaration existing retained state is neither migrated nor
removed, and existing users are not told they can upgrade. No candidate has been
qualified under that profile.

## Qualified private update to build 156

The current private candidate uses one persistent, code-signing-only identity trusted
in this Mac's login Keychain. That keeps the app/helper designated requirements stable
across private builds and prevents routine launches from asking for Keychain access.
It is not an Apple Developer ID and has no stable Developer Team for the public
Gatekeeper/in-app update path. Private replacement therefore uses the separate,
local-only atomic installer; it does not enable or reuse the public in-app updater:

1. Retain the pre-update Harness-state backup and manual Workspace checkpoint.
2. Run and record the complete 1.2 release verifier, cloned-state canary, local Qwen
   route, simulated provider, Skills/MCP, download, recovery, schedule, and package
   gates on the exact frozen candidate. The retained full-hardware evidence must be
   current and bound to that candidate.
3. Quit Fulmar and confirm its DSH, Ollama, runner, and helper children have exited.
   Do not rename or copy either app while the installer is running.
4. From the reviewed source checkout run `make private-install-qualified`. The command
   re-verifies source, archive, manifest, signatures, tree bytes, and retained evidence;
   builds the two external installer tools with warnings as errors in an isolated
   private environment; proves the candidate and installed app use the same private
   certificate and designated requirement; and performs one APFS atomic swap at the
   fixed `/Applications/Fulmar.app` path. It refuses linked, changed, running, wrongly
   signed, or ambiguously staged inputs. Before requesting the swap it commits a
   bounded, owner-private, no-follow, fsynced preparation journal binding the nonce,
   stage leaf, original, candidate, and signer before staging may mutate a path. A
   second immutable journal binds the exact durable stage before the swap. A failed helper or post-swap proof is
   reconciled and swaps back when necessary. If receipt persistence begins, the rename
   may already be durable even when its parent fsync reports failure; in that case the
   coordinator deliberately preserves the swapped pair and journal for explicit
   recovery instead of creating an opposite app/receipt state.
5. Run `make private-rollback-status`. This command is strictly read-only. A successful
   installation keeps the prior app
   at `/Applications/.Fulmar.install-stage.<nonce>.app` and writes its matching
   owner-only receipt below `~/Library/Application Support/.Fulmar Private Install
   Receipts/`. `~` may be a canonical login home outside `/Users`; its complete
   ancestry must be root/current-user-owned, non-group/world-writable,
   symlink-free, and extended-ACL-free, while the home, `Library`, and
   `Application Support` are current-user-owned. An unsafe custom-home or mount
   layout fails before any receipt mutation. The
   installer also retains the immutable pre-swap journal. Fulmar never deletes that
   rollback automatically.
6. Launch from the Dock and confirm Ready, exact runtime versions, new random
   endpoint/token, Ollama local route, one live local completion/tool task, shared
   Workspace, and Task History.
7. Switch local -> simulated external -> local and verify exact consent, fresh sessions,
   and return to Strict Local.
8. Keep the old app and safety snapshots through several successful sessions.

If status reports an interruption, run only the operation it names:

- `make private-recovery-reconcile` when a journal, receipt, or lifecycle-record write
  was interrupted inside its file/rename durability boundary. Read-only status never
  removes it. The explicit operation rejects links, hardlinks, wrong ownership/mode,
  duplicate or malformed temps, archives the exact temporary inode through
  `RENAME_EXCL` plus parent fsyncs, and reconstructs only the record implied by repeated
  app/stage/signer proofs. A canonical record plus a stale matching temp is reconciled
  idempotently; a destination collision or missing proof (including a required frozen
  candidate) preserves all evidence and fails closed. Partial evidence remains retained
  outside the active records.
- Preparation with no stage may be resumed or cancelled. An exact durable stage with
  no final journal may reconstruct only that journal. A partial or unprovable stage is
  never overwritten, executed, traversed as trusted content, or deleted; it requires
  explicit opaque-stage abandonment and archival.
- `make private-recovery-resume` when the original app is active and the staged
  candidate should be installed. Every stopped-process, inode, tree, signer, and record
  proof is repeated before the helper exchanges the bundles.
- `make private-recovery-finalize` when the candidate is already active and only its
  durable receipt is missing. This writes the proven receipt and never moves an app.
- `make private-recovery-cancel` when the original app is active and the attempted
  update should be abandoned. It archives the exact staged candidate and transaction
  records; it does not delete either bundle.

After the installed candidate has completed several successful real tasks, run
`make private-rollback-retire`. It first commits an immutable lifecycle marker, then
uses descriptor-relative exclusive renames and parent-directory fsyncs to archive the
exact rollback as `/Applications/.Fulmar.private-retired.<nonce>.app` and the complete
record directory below Application Support. Cancellation uses the corresponding
`.Fulmar.private-cancelled.<nonce>.app` archive. A crash before the marker, after the
marker, after the stage rename, or after the record-directory rename is idempotently
classifiable; rerun the same explicit command. Read-only status never resumes or
archives anything implicitly.

Record persistence is also interruption-safe at temp creation, partial-file fsync,
complete-file fsync, pre-rename, and post-rename/pre-directory-fsync boundaries. A
canonical record wins only after its exclusive rename; a retained temp requires the
separate reconciliation command, and ambiguous evidence is never silently removed.
Opaque-stage cancellation also writes and fsyncs an owner-private parent-directory
sentinel before moving the record directory. If the process dies after the exclusive
rename but before its parent fsync, read-only status discovers the exact sentinel plus
archived preparation/abandonment pair and requests the same explicit cancel operation.
That replay revalidates the archive, fsyncs the parent, then removes and fsyncs the
sentinel; it never moves or deletes the active app or abandoned stage.

Archived bundles and record directories are deliberately retained and consume disk.
Review and remove them manually only after keeping a separate backup and confirming
the active app is healthy. The next installation refuses to proceed while any active
stage, journal, receipt, or incomplete lifecycle transaction remains. It can proceed
after proven cancel/retire completion because the old artifacts are in distinct archive
names. Never make an archived bundle visible as a second `Fulmar.app` in `/Applications`;
copies share one stable bundle identifier and Launch Services or an old Dock item can
otherwise open the stale build.

A legacy orphan `.Fulmar.install-stage.*.app` with no exact journal/receipt cannot be
recovered automatically: preserve the app and request manual review. A malicious
same-user process can still race mutable filesystem names; eliminating that residual
requires a privileged immutable staging owner. The coordinator narrows the window with
repeated proofs, descriptor-relative exclusive renames, inode binding, and fsyncs but
does not claim to eliminate same-user compromise.

Creating the private signing identity can require one macOS password approval during
the build setup. Starting Fulmar must not. Cloud credentials created by an older
ad-hoc helper are deliberately treated as unconfigured without reading them; remove
the exact legacy item in Keychain Access and save a replacement in **Models &
Providers**. The Ollama/Qwen route never uses this credential path.

Live cloud provider testing is optional for local-only use and requires the user's own
test credentials. Do not substitute production secrets or infer a pass from simulated
contracts.

## Rollback

1. Quit the failed candidate and all bundled children. Run
   `make private-rollback-status` to identify the exact retained prior app and receipt.
2. Move the failed `/Applications/Fulmar.app` outside `/Applications` for diagnosis,
   then restore the proven hidden stage as `/Applications/Fulmar.app`. Confirm no
   other visible app with the same bundle identifier remains in `/Applications` and
   launch it. Preserve the receipt and failed candidate until diagnosis is complete.
3. If the bundled DSH version changed its state, restore the matching pre-upgrade
   Harness backup. The restore quarantines current state and rolls back the copy if it
   fails.
4. If an agent task damaged Workspace files, use Workspace Recovery from the app
   version that can read that checkpoint. Preview changes, separately approve modified
   overwrites/added removals, and keep a filesystem copy before proceeding.
5. Confirm credentials still resolve from Keychain; app/state/workspace rollback must
   not overwrite or export them.
6. Confirm the old app reaches Ready, selects the intended route, and passes a small
   local tool task before resuming normal work.

If Workspace Recovery itself reports rollback failure, stop automated writes, preserve
the directory and journal, and inspect manually. Repeating the restore can compound
damage.

## Failure record

Record candidate version/build, archive SHA-256, nested signature result, macOS and
hardware, Node/DSH/Ollama/model versions, provider route/origin, selected performance
profile, last trust/config changes, failed test, and redacted diagnostics. Note which
app/state/workspace artifacts were restored.

Never bypass same-team, nested-signature, freshness, Gatekeeper, consent, trust, or
recovery-preview checks to make an update install. A private deadline does not justify
turning a failed safety control into a warning.
