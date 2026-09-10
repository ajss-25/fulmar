# Beta download acceptance runbook — manual-install ZIP beta

This runbook tells the integrator how to take **one** immutable Fulmar candidate
through the manual-install beta profile of `docs/PUBLIC_BETA_RELEASE_CONTRACT.md`
and record honest evidence for its ten gates. It is an instruction set, not
evidence: as of its writing no beta candidate exists, no version/build has been
chosen for one, nothing here has been exercised against signed bytes, and every
value written as `<UNRESOLVED: …>` must be supplied by the person named before
the step can run. A worksheet that still contains such a value is a draft and
never becomes `build/public-beta-external-evidence.json`.

Conventions: a fenced block marked `# runnable` is a command to execute exactly
as written from the exact source checkout; a block marked `# procedure` is an
interactive sequence for a person; `[Owner]`, `[Integrator]` and `[Tester]` name
who must perform a step (`[Tester]` is a person on the clean Mac who is not the
developer of the candidate). Automatic updates remain **disabled** throughout;
this profile is **clean-install-only** unless the retained-state migration gate
is separately closed, which this runbook does not attempt.

What has and has not been checked (10/09/2026 correction lane): the
non-mutating `# runnable` entry points were exercised locally — the bare frozen
verifier fails closed with `requires an authenticated root watchdog` (status
126), GNU Make 3.81 wraps a recipe's `exit 78` as `Error 78` with make status 2,
and the `plutil`/`shasum` invocations run as written. Nothing that builds,
signs, notarizes, stages an upload, queries a Keychain or needs a physical
tester was executed; every `# procedure` block and every step marked `[Owner]`
or `[Tester]` remains unexecuted, and the `security` not-found status (44) is
documented from the tool's behaviour, not from a live query.

## 0. Inputs that do not exist yet

| Input | Owner of the decision | Constraint the existing tooling enforces |
| --- | --- | --- |
| Public beta version and build | `[Integrator]` (Codex) with `[Owner]` | `Config/ReleaseIdentity.json` `appVersion` must equal the built `CFBundleShortVersionString` and match `^\d+\.\d+\.\d+$` (`scripts/verify-public-external-evidence.mjs` `VERSION_PATTERN`; `scripts/prepare-public-release-assets.sh` `'^[0-9]+(\.[0-9]+){2}$'`), so a `-beta` marketing label cannot live in the bundle version and belongs in the release title/notes only; `appBuild` must be an integer distinct from the private build 156 (`scripts/generate-release-manifest.mjs` requires `^\d+$`). Build 156 is the qualified private candidate and must not be reused as the public beta identity. |
| Developer ID Application identity | `[Owner]` | `LOCAL_HARNESS_SIGN_IDENTITY="Developer ID Application: <UNRESOLVED: name> (<UNRESOLVED: 10-character Team ID>)"`, matched exactly and uniquely by `security find-identity -v -p codesigning` in the signing Keychain (`scripts/run-public-release.sh`). An ad-hoc or private self-signed identity is refused and would not be public trust evidence even if accepted. |
| Signing Keychain | `[Owner]` | `LOCAL_HARNESS_SIGNING_KEYCHAIN=<UNRESOLVED: absolute path>` — one owner-controlled regular file (uid = operator, link count 1). The login Keychain is not the intended value; provisioning is the owner's interactive step. |
| notarytool profile | `[Owner]` | `LOCAL_HARNESS_NOTARY_PROFILE=<UNRESOLVED: profile name>` created beforehand with `xcrun notarytool store-credentials` (interactive; Apple ID/app-specific password or App Store Connect API key never appear in this repository, its logs or this runbook). |
| Clean test Macs | `[Owner]` | One Apple-silicon Mac on the current supported macOS and one on macOS 15.x, each with **no** source checkout, Xcode/Swift toolchain, Fulmar Application Support, Fulmar Keychain items, Harness backups, local signing certificate or reconstructed VendorRuntime. A test user account that has never run Fulmar satisfies "no retained state" only if `~/Library/Application Support/Local Harness`, `~/.dsh` and all four Keychain item families in step 5.1 (provider credentials, backup authentication, device attestation, credential-migration receipt) are confirmed absent **before** the test by the scoped predicates there; an unknown Keychain answer is not absence, and nothing is deleted to make the account clean. |
| Disposable funded DeepSeek account | `[Owner]` | A key created for this exercise with a small balance, revoked afterwards. Never a production key, never a key seen in earlier conversation text or logs. |
| Ollama and model on the tester Mac | `[Tester]` | Official Ollama.app 0.33.2–0.33.x and `ollama pull qwen3.8:27b-mlx` (manifest SHA-256 `5642e97495e1a088883805981563dcdc4a040c2f53388b7a41d1f24d3622cf7e`) on a ≥ 48 GB Mac for the qualified route. A smaller Mac may exercise only the labelled Compatibility route with another installed model; that is recorded as Compatibility, never as the qualified route, and no default here requires the owner's 48 GB host. |

## 1. Source gates on the exact candidate commit `[Integrator]`

Run from a clean clone of the exact commit that will be tagged. Record the
commit, the tree and each command's exit status and log digest.

```sh
# runnable — reconstruct the pinned runtime and notice-material cache (HTTPS)
/bin/zsh -f scripts/bootstrap-source-checkout.sh
# runnable — first-index policy, source product contracts, dependency audit
/bin/bash -p scripts/verify-tracked-index.sh .
make source-contract-test
make deepseek-contract-test
make dependency-audit
# runnable — Swift gate FIRST: it compiles the SwiftPM debug product and test
# bundle under .build/ that two JavaScript tests inspect
make test
# runnable — complete JavaScript source gate, after native qualification
# (uses the shared watchdog lock)
/bin/zsh -f scripts/run-js-tests.sh --test Tests/JS/*.mjs
```

The order matters and is the one `scripts/verify-release.sh` uses: the Swift
gate produces the SwiftPM debug products that
`Tests/JS/SwiftPMDeploymentTargetTests.mjs` reads, so on a clean checkout the
JavaScript gate run first fails closed with two deployment-target failures
(observed in the 09/09/2026 lane). Run the Swift gate before the JavaScript
gate; if only the prerequisite is wanted without executing the native suite,
run the same debug build `scripts/run-swift-tests.sh` performs (its
`/usr/bin/swift build --package-path <checkout> --disable-sandbox --jobs <1–4>
--build-tests` invocation with the Command Line Tools framework search path
and `-Xswiftc -warnings-as-errors`, under a private `HOME`/module cache) and
record that no Swift test was executed. Never skip or relabel those two
JavaScript tests. The JavaScript gate
passes only when the wrapper prints `JavaScript event accounting passed` for
the exact frozen topology of the candidate commit and exits 0; read the count
line from the log rather than assuming it.

Stop if any command fails. Do not proceed to a build from a tree with a
failing gate, and do not edit a frozen count or a skip list to make one pass.

## 2. Build, sign, notarize and retain one candidate `[Owner]` + `[Integrator]`

The beta package carries the verified third-party material archive beside the
app (`docs/PUBLIC_BETA_RELEASE_CONTRACT.md`, "Beta release assets"), so the
operator needs three material operands before it will build anything: the
private package directory produced for the exact candidate commit by
`scripts/package-libvips-delivery-materials.mjs package
Config/ThirdPartyBinaryProvenance.json <verified delivery set> <new private
directory> <commit>`, that archive's SHA-256 as recorded in the reviewed release
record (it is the `.tar` digest, **not** the `Fulmar.app.zip` digest and not
read from the package's own sidecar), and the checkout's HEAD commit. Missing,
duplicated or malformed operands stop the operator before the signing identity
is consulted.

```sh
# runnable — the only build-producing beta operator; when the three signing
# variables are configured it really builds, signs, submits to Apple, staples
# and retains one candidate, then pauses with its own exit status 78, which GNU
# make reports as "Error 78" and wraps in make's exit status 2
LOCAL_HARNESS_SIGN_IDENTITY="Developer ID Application: <UNRESOLVED: name> (<UNRESOLVED: TEAMID>)" \
LOCAL_HARNESS_SIGNING_KEYCHAIN="<UNRESOLVED: absolute keychain path>" \
LOCAL_HARNESS_NOTARY_PROFILE="<UNRESOLVED: notarytool profile>" \
make public-beta-release \
  BETA_MATERIAL_PACKAGE="<UNRESOLVED: absolute private material package directory>" \
  BETA_MATERIAL_SHA256="<UNRESOLVED: material archive sha256 from the reviewed release record>" \
  BETA_SOURCE_COMMIT="$(git rev-parse HEAD)"; echo "make status: $?"
```

Expected outcome: static scan, one timestamped hardened-runtime build, Apple
submission, `Accepted` receipt and issue-free log retained as
`build/notarization-submission.json` / `build/notarization-log.json`, stapling,
regenerated `build/Fulmar.app.zip`, the full-hardware candidate verifier, then
the operator's deliberate pause. The pause is recognised only by **all** of:

- the operator (`scripts/run-public-release.sh --profile beta`) printed
  `Retained notarized Fulmar <version> build <build> candidate <sha256> (beta
  profile).` followed by `Public release is intentionally paused: complete the
  ten manual beta gates …`, and nothing after it;
- make printed `make: *** [public-beta-release] Error 78` and `make status: 2`
  — `2` is GNU make's wrapper status for any failing recipe, so a status of 2
  on its own proves nothing; `Error 78` names the operator's status;
- the retained candidate record exists and agrees with the printed values:

```sh
# runnable — retained-candidate evidence that must agree with the pause lines
/usr/bin/plutil -extract sha256 raw -o - build/release-manifest.json
/usr/bin/plutil -extract version raw -o - build/release-manifest.json
/usr/bin/plutil -extract build raw -o - build/release-manifest.json
/usr/bin/shasum -a 256 build/Fulmar.app.zip
```

Any other outcome — a different `Error N`, an operator message about a missing
identity, Keychain, notary profile, static-scan finding or existing asset set,
a status 1, or a status 2 without the pause lines — is a failure to record and
stop on, never "the expected pause". Record the three values verbatim; they
bind every later record. The interactive parts (Keychain unlock, notarytool
authentication) are the owner's. Do **not** rebuild while collecting evidence;
any rebuild produces a different candidate and voids collected records.

```sh
# runnable — candidate byte checks on the retained archive and app. The frozen
# verifier requires the repository's authenticated root watchdog and fails
# closed ("requires an authenticated root watchdog") when run bare; use the
# supported wrapper and target exactly as README.md and docs/TROUBLESHOOTING.md do.
./scripts/run-with-watchdog.sh --seconds 1800 --max-rss-bytes 8589934592 --rss-grace-seconds 15 \
  --emergency-rss-bytes 17179869184 --label "Fulmar frozen-candidate check" -- /usr/bin/make frozen-candidate-check
echo "frozen-candidate check status: $?"
/usr/bin/codesign --verify --deep --strict --verbose=4 /private/tmp/LocalHarnessBuild/Fulmar.app
/usr/bin/xcrun stapler validate /private/tmp/LocalHarnessBuild/Fulmar.app
/usr/bin/shasum -a 256 build/Fulmar.app.zip
```

Each command's own exit status is recorded; the ZIP digest must equal the
candidate `sha256` printed at the pause and read from the manifest above.

## 3. Updater-disabled proof on the shipped bytes `[Integrator]`

Gate: `inAppUpdaterDisabledInCandidate`. What the boundary actually is: the
selector `installVerifiedUpdate(_:)` still exists in
`Sources/LocalHarness/LocalHarnessApp.swift`, behind
`private static let verifiedInAppUpdatesEnabled = false` and the guard
`guard Self.verifiedInAppUpdatesEnabled else { … return }`, which shows the
alert "In-app updates are not available in this build" and performs nothing;
no public menu item is wired to it. The source contract
(`scripts/verify-source-product-contract.mjs`) and
`Tests/JS/ProductIdentitySurfaceTests.mjs` fail closed if the constant, the
guard or the menu-exposure rule changes. The proof therefore has three parts,
and none of them is a string search: absence of the menu title from the binary
would not show that the selector is absent or unreachable (it is neither), and
the guard's alert strings are legitimately present in the shipped executable.

```sh
# runnable — 1. the programmatic boundary and menu-exposure rule on the exact candidate commit
make source-contract-test; echo "source contract status: $?"
/bin/zsh -f scripts/run-js-tests.sh --test Tests/JS/ProductIdentitySurfaceTests.mjs; echo "identity surface status: $?"
# runnable — 2. the shipped bytes are the retained candidate (binds the app under test to the recorded sha256)
./scripts/run-with-watchdog.sh --seconds 1800 --max-rss-bytes 8589934592 --rss-grace-seconds 15 \
  --emergency-rss-bytes 17179869184 --label "Fulmar frozen-candidate check" -- /usr/bin/make frozen-candidate-check
echo "frozen-candidate check status: $?"
/usr/bin/plutil -extract CFBundleExecutable raw -o - /private/tmp/LocalHarnessBuild/Fulmar.app/Contents/Info.plist
test -f /private/tmp/LocalHarnessBuild/Fulmar.app/Contents/MacOS/LocalHarness; echo "main executable present status: $?"
```

Every status is recorded as printed; a non-zero status anywhere is a failure,
not a note. Part 3 is the exact-candidate UI observation on the clean Mac in
step 5 (steps 5–7 and 8–10 there): a person confirms, on the installed copy
whose archive digest equals the recorded candidate `sha256`, that no main-menu
item, status-item menu, Settings pane, context menu or keyboard shortcut offers
an update or "Install Verified Update…" action, and records what was traversed.
Until that observation has been made on the notarized candidate, the record for
this gate says **physical proof pending**; the source contract and the frozen
check are prerequisites, not the proof. The retained helper binary
`LocalHarnessUpdateHelper` is expected to exist (it is part of the reviewed
tree); its presence is not an entry point and must not be recorded as one.

## 4. Third-party binary materials `[Owner]` with legal review

Gate: `thirdPartyBinaryLicenseMaterials`. What exists and what does not:

- Exact per-component notices (29), the Rust crate materials and the two
  established external texts are bound and verified at build time
  (`docs/LIBVIPS_CORRESPONDING_SOURCE.md`).
- The verified delivery set can be packaged privately into one deterministic
  archive with a binding, and a recipient can verify and unpack it against the
  exact source commit (`scripts/package-libvips-delivery-materials.mjs`, same
  document, "Delivery archive"). Under the beta profile that archive, its
  sidecar and its binding are the three additional release assets (twelve in
  all; `docs/PUBLIC_BETA_RELEASE_CONTRACT.md`, "Beta release assets"), admitted
  into the package only after the existing verifier accepts them for the exact
  source commit with the operator-supplied digest and HTTPS-authoritative
  acquisition. This is an engineering step. Shipping the material beside the
  app is not by itself a corresponding-source offer with a duration, not
  relinking information, and not clearance.
- Four crate notices remain **unresolved**; `malloc_buf 0.0.6` has a
  later-revision upstream licence text recorded but not bound. The mechanism and
  duration of the corresponding-source offer, relinking/Installation Information
  under Developer ID signing, and legal clearance are owner/legal decisions.

This gate closes only when the owner records a legal review outcome for the
exact shipped payload and either the retained material or an explicit accepted
disposition for each open item. Do not close it because the archive verifies.

## 5. Clean-Mac acceptance, repeated on both macOS releases `[Tester]`

Gates: `cleanInstallCurrentMacOS`, `cleanInstallMinimumMacOS`,
`permissionAndAccessibilityMatrix`, part of `manualInstallReinstallRecovery`.
Both Macs consume the **same** `Fulmar.app.zip` (same SHA-256); a rebuilt app
does not count.

```sh
# procedure — before anything is installed
1. Prove the Mac is clean with scoped, read-only predicates (no dumps, no
   deletion). Files:
     ls -d ~/Library/Application\ Support/Local\ Harness ~/.dsh; echo "status: $?"
   Both paths must be reported "No such file or directory".
   Keychain: one query per item family, each scoped to the exact service (and
   account where the app uses a fixed one); the names are the ones the shipped
   helpers use (Tools/CredentialHelper, Tools/CredentialBrokerService,
   Tools/CredentialMigrationService, Sources/DeviceAttestationAuthority):
     security find-generic-password -s app.localharness.credentials; echo "status: $?"
       # provider credentials: any account in this service
     security find-generic-password -s com.angadjairath.localharness.backup-authentication -a state-backup-manifest-v2; echo "status: $?"
     security find-generic-password -s com.angadjairath.localharness.device-attestation -a device-attestation-signing-private-v1; echo "status: $?"
     security find-generic-password -s com.angadjairath.localharness.device-attestation -a device-attestation-public-anchor-sha256-v1; echo "status: $?"
     security find-generic-password -s com.angadjairath.localharness.credential-migration-receipt -a receipt-authentication-v1; echo "status: $?"
   Read each outcome literally:
     - status 44 with "The specified item could not be found" is the ONLY
       result that counts as absent;
     - status 0 means the item exists: this Mac is an upgrade test, not a clean
       install — stop, delete nothing, use another Mac or account;
     - any other status or message (locked keychain, interaction not allowed,
       a cancelled prompt, a different error) is UNKNOWN, not absence: stop and
       resolve it (for example unlock the login keychain and re-run the same
       query) before recording anything.
   Never add -w/-g or dump the keychain, and never delete items to make a
   clean account.
2. Record macOS version (sw_vers), model, memory, whether Xcode CLT is present.
```

```sh
# procedure — download, verify, install, first launch
3. Obtain the exact frozen archive over HTTPS **before** anything is published:
   acceptance happens on the candidate, so it cannot require the public release
   page to exist. [Owner] places the retained `build/Fulmar.app.zip` (exact
   bytes, unmodified, sha256 equal to the recorded candidate digest) at an
   authorized owner-controlled HTTPS location that only the acceptance testers
   can reach — for example a private, non-indexed release-draft asset or an
   authenticated HTTPS share — and passes the tester the URL and, separately
   (not beside the file), the expected sha256 from the step-2 record. Nothing
   is uploaded as part of preparing this runbook; the staging upload is the
   owner's action at acceptance time and is itself recorded (location, date,
   who). The tester downloads with Safari so that the quarantine attribute is
   attached exactly as a public download would carry it, then confirms:
     xattr -p com.apple.quarantine ~/Downloads/Fulmar.app.zip   # must print a value
     shasum -a 256 ~/Downloads/Fulmar.app.zip                    # must equal the recorded candidate sha256
   The digest is compared against the value received out of band; a
   `.sha256` file downloaded beside the archive is only a convenience copy of
   the same number and does not authenticate the download. The signature and
   the stapled ticket inside the archive are what Gatekeeper evaluates in step
   5; the byte identity above is what binds this test to the candidate. The
   same archive bytes are used later for the public release page; a re-export
   or re-zip is a different candidate.
4. Expand by double-clicking in Finder; drag Fulmar.app to /Applications. Do not
   run xattr -d, do not control-click "Open Anyway", do not disable Gatekeeper.
5. Online first launch from /Applications. Gatekeeper must accept without a
   workaround. Record:
     spctl --assess --type execute -vv /Applications/Fulmar.app
     codesign -dvvv /Applications/Fulmar.app 2>&1 | grep -E 'Authority=|TeamIdentifier|Timestamp|flags='
   Record the Team ID and that "runtime" appears in flags.
6. Quit Fulmar (Cmd-Q). Turn Wi-Fi off / unplug Ethernet. Launch again: it must
   open without a network trip (stapled ticket). Re-enable the network afterwards.
7. Quit and relaunch online; confirm no repeated first-run, trust or Keychain
   prompt appears that already had an answer.
```

```sh
# procedure — Keychain and permission matrix (allow, deny, later relaunch)
8. Keychain, by item family. The four families in step 1 are distinct services
   with distinct consequences; a grant or denial for one says nothing about the
   others, and the expected outcome of a denial differs per family. macOS
   decides whether a prompt appears at all (a clean first launch usually
   creates items without prompting); record exactly which prompts appeared and
   for which family, and never force one.
   - Device trust (`com.angadjairath.localharness.device-attestation`): read at
     startup before the Harness home is prepared. If macOS prompts and the
     tester chooses Deny or cancels, the runtime is intentionally kept
     STOPPED: Fulmar must state that the permission was cancelled or denied and
     that nothing was changed or reset, offer the explicit foreground action
     "Allow Keychain Access" to decide again, and otherwise stay stopped
     without crashing, looping or re-prompting in the background. Local tasks
     are NOT expected to run in that state and their absence is not a
     failure. Remedy: choose "Allow Keychain Access" in the foreground (or quit
     and relaunch, and answer the prompt); the check is retried by request and
     no credential is read automatically. Record the alert text observed and
     that keeping Fulmar stopped is a bounded, recoverable end state.
   - Provider credentials (`app.localharness.credentials`): exercised only when a
     provider key is entered or read (step 7 of this runbook, or Models &
     Providers). On Deny the app must remain usable for local work and report
     the credential as unconfigured; on a later Allow the credential is stored.
     A provider denial must never be recorded as, or confused with, the
     device-trust outcome above.
   - Backup authentication (`com.angadjairath.localharness.backup-authentication`
     / `state-backup-manifest-v2`): read only when the tester asks to verify or
     restore an authenticated backup, after Fulmar's own explanation that it
     reads the existing key and replaces or deletes nothing. On Deny the backup
     action stops and reports; no item is created, replaced or deleted. Not
     applicable on a clean Mac unless a backup was made during the test.
   - Credential-migration receipt
     (`com.angadjairath.localharness.credential-migration-receipt` /
     `receipt-authentication-v1`): belongs to the legacy plaintext-credential
     migration; not applicable on a clean Mac with no legacy credential file,
     and recorded as such.
   Do not record or promise that "Always Allow" prevents any future prompt;
   macOS may re-prompt after an update or Keychain change.
9. Permissions, each first denied then separately allowed on a later attempt,
   with a quit/relaunch between: microphone, speech recognition, Screen
   Recording (Appshot), notifications, launch at login, background schedules.
   After every denial the unrelated features (task history, local model, quick
   chat, settings) must remain usable. Record the System Settings state after
   each step.
10. Accessibility: keyboard-only navigation of the main window and Settings,
    VoiceOver pass over the model selector and task list, Increase Contrast and
    Reduce Motion/Transparency toggled, window resize to minimum, a second
    display attached/detached. Record what was exercised; leave unexercised
    rows blank rather than inferred.
```

```sh
# procedure — one bounded real local task
11. With official Ollama 0.33.x running and the qualified model present (or the
    Compatibility route explicitly labelled), open a fresh Workspace on
    disposable content and ask for one small write task, e.g. "Create
    notes/acceptance.txt containing the single line ACCEPTANCE-<date>". Then
    verify on disk from Terminal:
      cat "<workspace>/notes/acceptance.txt"
      shasum -a 256 "<workspace>/notes/acceptance.txt"
    and ask the model to read the file back; the reply must match the bytes.
12. Start a second, longer task and cancel it mid-generation; the exact owned
    child must stop (pgrep -fl ollama shows no runaway CPU) and the UI must
    return to idle. Ask for a continuation of a task that hit the output limit
    once, if it occurs; do not force a sustained multi-minute workload on the
    tester Mac.
13. Watch the native thermal indicator during the task; if Eco or the emergency
    stop engages, record it. The owner's host-side thermal probe
    (`scripts/compile-thermal-recovery-probe.sh`, then
    `scripts/wait-for-thermal-recovery.sh --live <probe> app-owned-generation`)
    is a developer-Mac check and is not run on the tester Mac.
14. Quit. Confirm every app-owned process has exited:
      pgrep -fl 'Fulmar|LocalHarness|dsh|ollama'      # expected: no Fulmar-owned rows
    Relaunch once more and confirm the Workspace and Task History survived.
```

## 6. Manual reinstall and recovery `[Tester]`

Gate: `manualInstallReinstallRecovery`. Performed on the exact notarized
candidate after step 5, with the app quit.

```sh
# procedure
1. Retain the installed app outside /Applications:
     mkdir -p ~/Fulmar-retained && ditto /Applications/Fulmar.app ~/Fulmar-retained/Fulmar.app
   (ditto preserves the signature; do not use a plain drag if it would strip
   extended attributes on a foreign volume). Record `codesign --verify --deep
   --strict ~/Fulmar-retained/Fulmar.app` succeeds.
2. Same-version reinstall: verify the same Fulmar.app.zip again (step 5.3),
   expand it, replace /Applications/Fulmar.app with the freshly expanded copy,
   launch, confirm Ready and that existing Workspace/Task History is intact.
3. Manual rollback: quit, move /Applications/Fulmar.app to ~/Fulmar-diagnosis/,
   restore ~/Fulmar-retained/Fulmar.app to /Applications/Fulmar.app, confirm no
   second visible Fulmar.app remains anywhere under /Applications, launch and
   confirm Ready and one small local task. This proves the documented manual
   workflow works for this person on this Mac; it does not prove automatic
   recovery, power-loss safety or the disabled updater, and the record must say
   so in those words.
4. Uninstall per `docs/PUBLIC_INSTALLATION.md` "Uninstall and retained data":
   disable the two service registrations in the UI first, quit, trash the app,
   log out/in, confirm no Fulmar process relaunches, and confirm the documented
   retained data and Keychain items are still present (they are removed only by
   the tester's deliberate choice, after the record is complete).
```

## 7. DeepSeek live route `[Owner]` on a Mac from step 5

Not one of the ten contract gates; recorded as a **supplementary** result. A
mocked reply or a no-credit error is not a success path.

```sh
# procedure
1. Create the disposable key with a small balance. Enter it only through Fulmar
   (Models & Providers), never in Terminal, prompts, files or this record.
2. Select a DeepSeek V4 model, review the exact endpoint/disclosure boundary,
   choose Use for New Tasks. Confirm the local→cloud boundary warning names the
   correct origin and a fresh task is created.
3. Success path: one short chat completion; one harmless tool call (e.g. read
   the acceptance file from step 5.11); one mid-stream cancellation.
4. Failure paths: an invalid key (expect a bounded authentication error with
   no key bytes anywhere in UI or diagnostics); the quota/no-credit error after
   the balance is exhausted or with a zero-balance key.
5. Switch back to the local route; confirm a fresh task and Strict Local state.
6. Revoke the key at the provider. Record model ids, request outcome classes and
   the redacted error texts. Never record the key.
```

LM Studio and any other OpenAI-/Anthropic-compatible server stay **unqualified**
(tier 3/4 in `docs/SUPPORT_MATRIX.md`) unless a person exercises them the same
way; fixture success is not live support and must not be recorded as such.

## 8. Records and the pass-evidence file `[Integrator]`

Work in a draft while collecting:

```text
build/drafts/public-beta-external-evidence.DRAFT.json        # unfilled or partial; never the pass path
build/drafts/beta-acceptance-supplementary-record.DRAFT.json # DeepSeek live route, thermal notes, Compatibility-route notes
```

Every gate record needs `status: "passed"`, the SHA-256 of the retained
evidence file for that gate (a real digest; the verifier rejects `000…0`) and a
bounded `reference` (≤ 200 characters, no secrets). Mapping of this runbook to
the ten records:

| Gate record | Evidence produced by |
| --- | --- |
| `cleanInstallCurrentMacOS` | Step 5 on the current macOS Mac (steps 1–7, 11–14) |
| `cleanInstallMinimumMacOS` | Step 5 on the macOS 15 Mac (same steps, same archive SHA-256) |
| `fullGitHistoryAndSecretScan` | Gitleaks and TruffleHog over every reachable branch/tag of the exact candidate commit, plus the manual index review (`docs/PUBLIC_RELEASE_READINESS.md`) |
| `githubRepositoryControls` | Exported settings record and the five real hosted check results (Codex-owned) |
| `legalAndTrademarkClearance` | Owner/legal record (`docs/BRAND_AND_RELEASE_IDENTITY.md` scope) |
| `permissionAndAccessibilityMatrix` | Step 5.8–5.10 on both Macs |
| `supportPrivacyAndExportReview` | Owner review of `docs/PRIVACY.md`, `SUPPORT.md`, `SECURITY.md`, privacy-manifest scope and export-compliance decision against the exact binary |
| `manualInstallReinstallRecovery` | Step 6 (and 5.3–5.7) on the exact notarized candidate |
| `inAppUpdaterDisabledInCandidate` | Step 3 parts 1–2 (source contract, identity-surface test, watchdog-wrapped frozen check with their statuses) plus the step-5 exact-candidate UI observation; "physical proof pending" until that observation exists |
| `thirdPartyBinaryLicenseMaterials` | Step 4 owner/legal record |

Only when all ten records hold real digests, create the owner-private file
with mode 0600 and exactly the shape in `docs/PUBLIC_BETA_RELEASE_CONTRACT.md`
(`distribution.retainedState` = `clean-install-only` unless the eleventh gate
was really closed), then:

```sh
# runnable — structural verification against the exact candidate, then finalize (no rebuild)
./scripts/run-with-watchdog.sh --seconds 1800 --max-rss-bytes 8589934592 --rss-grace-seconds 15 \
  --emergency-rss-bytes 17179869184 --label "Fulmar beta external-evidence check" -- /usr/bin/make public-beta-external-evidence-verify
LOCAL_HARNESS_SIGN_IDENTITY="…" LOCAL_HARNESS_SIGNING_KEYCHAIN="…" LOCAL_HARNESS_NOTARY_PROFILE="…" \
make public-beta-release-finalize \
  BETA_MATERIAL_PACKAGE="<same private material package as step 2>" \
  BETA_MATERIAL_SHA256="<same material archive sha256 from the reviewed release record>" \
  BETA_SOURCE_COMMIT="$(git rev-parse HEAD)"; echo "make status: $?"
```

Finalize never builds, re-signs, re-notarizes or changes the candidate. It
revalidates the retained archive, Apple records, signer, tree and ticket,
verifies the beta evidence for the exact SHA/version/build, then creates the
twelve-asset beta package if none is retained — admitting the material archive,
sidecar and binding from the private package only after `verify-archive` accepts
their snapshots for the exact source commit with the supplied digest — or
revalidates a retained package, and runs the distribution verifier with
`--profile beta --material-sha256 … --source-commit …`. A retained package whose
material does not match the operands fails with that error and is never
silently rebuilt or replaced. It never uploads, tags or publishes. Its statuses
follow step 2: the operator's own exit 78 (shown by make as `Error 78`, make
status 2) means the evidence file is missing, incomplete or bound to another
candidate or profile — correct the evidence, do not rebuild; any other non-zero
outcome is a failure. Passing it proves record completeness, candidate binding
and material binding; it does not make a reference true and it does not close
`thirdPartyBinaryLicenseMaterials`.

The published beta release therefore carries twelve assets. Testers install
from `Fulmar.app.zip` exactly as in step 5; the three material assets are
third-party source material for reviewers and recipients, are never installed,
and `SHA256SUMS.txt` lists eleven files in a beta release.

## 9. Stop and rollback conditions

Stop the exercise, keep all records, and do not create pass evidence when:

- any step-1 gate fails, or the candidate is rebuilt for any reason (start again
  from step 2 with a new identity record);
- `make public-beta-release` ends without the exact pause lines and the
  agreeing `build/release-manifest.json` (a bare make status 2 or any other
  `Error N` is a failure, not the pause);
- Gatekeeper, `spctl`, `stapler`, or the offline launch requires any workaround;
- the "clean Mac" proves to hold prior Fulmar state, or any step-5.1 Keychain
  predicate returns an unknown outcome (record as upgrade test or unknown, not
  clean install; never delete state);
- a permission denial breaks an unrelated feature, a provider-credential denial
  stops local work, or a device-trust denial crashes, loops or silently
  re-prompts instead of stating the denial and keeping the runtime stopped
  with the foreground "Allow Keychain Access" remedy;
- quit leaves an app-owned process running, or rollback leaves two visible
  `Fulmar.app` bundles;
- the DeepSeek path only ever produces a no-credit or mocked result (record as
  not qualified);
- a key, password or personal path appears in any record — redact at source
  and re-collect.

Tester-Mac rollback is step 6.3 in reverse; no tester data is ever deleted to
recover.
