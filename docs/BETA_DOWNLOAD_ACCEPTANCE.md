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

## 0. Inputs that do not exist yet

| Input | Owner of the decision | Constraint the existing tooling enforces |
| --- | --- | --- |
| Public beta version and build | `[Integrator]` (Codex) with `[Owner]` | `Config/ReleaseIdentity.json` `appVersion` must equal the built `CFBundleShortVersionString` and match `^\d+\.\d+\.\d+$` (`scripts/verify-public-external-evidence.mjs` `VERSION_PATTERN`; `scripts/prepare-public-release-assets.sh` `'^[0-9]+(\.[0-9]+){2}$'`), so a `-beta` marketing label cannot live in the bundle version and belongs in the release title/notes only; `appBuild` must be an integer distinct from the private build 156 (`scripts/generate-release-manifest.mjs` requires `^\d+$`). Build 156 is the qualified private candidate and must not be reused as the public beta identity. |
| Developer ID Application identity | `[Owner]` | `LOCAL_HARNESS_SIGN_IDENTITY="Developer ID Application: <UNRESOLVED: name> (<UNRESOLVED: 10-character Team ID>)"`, matched exactly and uniquely by `security find-identity -v -p codesigning` in the signing Keychain (`scripts/run-public-release.sh`). An ad-hoc or private self-signed identity is refused and would not be public trust evidence even if accepted. |
| Signing Keychain | `[Owner]` | `LOCAL_HARNESS_SIGNING_KEYCHAIN=<UNRESOLVED: absolute path>` — one owner-controlled regular file (uid = operator, link count 1). The login Keychain is not the intended value; provisioning is the owner's interactive step. |
| notarytool profile | `[Owner]` | `LOCAL_HARNESS_NOTARY_PROFILE=<UNRESOLVED: profile name>` created beforehand with `xcrun notarytool store-credentials` (interactive; Apple ID/app-specific password or App Store Connect API key never appear in this repository, its logs or this runbook). |
| Clean test Macs | `[Owner]` | One Apple-silicon Mac on the current supported macOS and one on macOS 15.x, each with **no** source checkout, Xcode/Swift toolchain, Fulmar Application Support, Fulmar Keychain items, Harness backups, local signing certificate or reconstructed VendorRuntime. A test user account that has never run Fulmar satisfies "no retained state" only if `~/Library/Application Support/Local Harness`, `~/.dsh` and the two Keychain services listed in `docs/PUBLIC_INSTALLATION.md` are absent **before** the test; nothing is deleted to make that true. |
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
# runnable — complete JavaScript source gate (uses the shared watchdog lock)
/bin/zsh -f scripts/run-js-tests.sh --test Tests/JS/*.mjs
# runnable — Swift gate
make test
```

Stop if any command fails. Do not proceed to a build from a tree with a
failing gate, and do not edit a frozen count or a skip list to make one pass.

## 2. Build, sign, notarize and retain one candidate `[Owner]` + `[Integrator]`

```sh
# runnable — the only build-producing beta operator; pauses with exit 78
LOCAL_HARNESS_SIGN_IDENTITY="Developer ID Application: <UNRESOLVED: name> (<UNRESOLVED: TEAMID>)" \
LOCAL_HARNESS_SIGNING_KEYCHAIN="<UNRESOLVED: absolute keychain path>" \
LOCAL_HARNESS_NOTARY_PROFILE="<UNRESOLVED: notarytool profile>" \
make public-beta-release
```

Expected outcome: static scan, one timestamped hardened-runtime build, Apple
submission, `Accepted` receipt and issue-free log retained as
`build/notarization-submission.json` / `build/notarization-log.json`, stapling,
regenerated `build/Fulmar.app.zip`, the full-hardware candidate verifier, then
**exit 78** printing `Retained notarized Fulmar <version> build <build>
candidate <sha256> (beta profile)`. Record those three values verbatim; they
bind every later record. The interactive parts (Keychain unlock, notarytool
authentication) are the owner's. Do **not** rebuild while collecting evidence;
any rebuild produces a different candidate and voids collected records.

```sh
# runnable — candidate byte checks on the retained archive and app
/bin/zsh -f scripts/verify-frozen-candidate.sh /private/tmp/LocalHarnessBuild/Fulmar.app
/usr/bin/codesign --verify --deep --strict --verbose=4 /private/tmp/LocalHarnessBuild/Fulmar.app
/usr/bin/xcrun stapler validate /private/tmp/LocalHarnessBuild/Fulmar.app
/usr/bin/shasum -a 256 build/Fulmar.app.zip
```

The ZIP digest must equal the candidate `sha256` printed at the pause.

## 3. Updater-disabled proof on the shipped bytes `[Integrator]`

Gate: `inAppUpdaterDisabledInCandidate`. The source contract already refuses a
public menu item or programmatic selector for the updater
(`scripts/verify-source-product-contract.mjs`); the gate additionally wants the
check made on the exact shipped bytes and recorded.

```sh
# runnable — source contract on the exact commit
make source-contract-test
# runnable — no updater menu title in the shipped main executable (CFBundleExecutable is LocalHarness) or bundled resources
/usr/bin/strings -a /private/tmp/LocalHarnessBuild/Fulmar.app/Contents/MacOS/LocalHarness | /usr/bin/grep -c 'Install Verified Update' ; echo "expected count: 0"
/usr/bin/grep -rl 'Install Verified Update' /private/tmp/LocalHarnessBuild/Fulmar.app/Contents/Resources ; echo "expected: no output (exit 1)"
```

Record the commands, their output and the candidate `sha256`. Then, on the
clean Mac in step 5, a person confirms that no menu, Settings pane or keyboard
shortcut offers an update action. The retained helper binary
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
  document, "Delivery archive"). This is an engineering step. It is not a public
  source offer, not a release asset and not clearance.
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
1. Prove the Mac is clean: in Terminal run
     ls -d ~/Library/Application\ Support/Local\ Harness ~/.dsh 2>&1
     security find-generic-password -s app.localharness.credentials 2>&1 | head -1
     security find-generic-password -s com.angadjairath.localharness.backup-authentication 2>&1 | head -1
   Every command must report "No such file" / "could not be found". If any state
   exists, this Mac is an upgrade test, not a clean install: stop, do not delete
   anything, use another Mac or account.
2. Record macOS version (sw_vers), model, memory, whether Xcode CLT is present.
```

```sh
# procedure — download, verify, install, first launch
3. Download Fulmar.app.zip and Fulmar.app.zip.sha256 with Safari from the
   release page (quarantine must stay intact). Confirm:
     xattr -p com.apple.quarantine ~/Downloads/Fulmar.app.zip   # must print a value
     cd ~/Downloads && shasum -a 256 -c Fulmar.app.zip.sha256    # must print OK
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
8. Keychain: on the first credential-related prompt choose Deny; confirm the app
   remains usable for local work and reports the credential as unconfigured
   rather than crashing. Quit, relaunch, choose Allow on the next prompt. Record
   which of the three item families prompted (device trust, backup
   authentication, provider credentials) — they are distinct services and a
   grant for one is not a grant for the others. Do not record or promise that
   "Always Allow" prevents any future prompt; macOS may re-prompt after an
   update or Keychain change.
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
| `inAppUpdaterDisabledInCandidate` | Step 3 commands plus the step-5 human confirmation |
| `thirdPartyBinaryLicenseMaterials` | Step 4 owner/legal record |

Only when all ten records hold real digests, create the owner-private file
with mode 0600 and exactly the shape in `docs/PUBLIC_BETA_RELEASE_CONTRACT.md`
(`distribution.retainedState` = `clean-install-only` unless the eleventh gate
was really closed), then:

```sh
# runnable — structural verification against the exact candidate, then finalize (no rebuild)
make public-beta-external-evidence-verify
LOCAL_HARNESS_SIGN_IDENTITY="…" LOCAL_HARNESS_SIGNING_KEYCHAIN="…" LOCAL_HARNESS_NOTARY_PROFILE="…" \
make public-beta-release-finalize
```

Finalize revalidates the retained archive, Apple records, signer, tree and
ticket, verifies the beta evidence for the exact SHA/version/build, creates or
revalidates the unchanged nine-asset package and runs the distribution verifier
with `--profile beta`. It never uploads, tags or publishes. Passing it proves
record completeness and candidate binding; it does not make a reference true.

## 9. Stop and rollback conditions

Stop the exercise, keep all records, and do not create pass evidence when:

- any step-1 gate fails, or the candidate is rebuilt for any reason (start again
  from step 2 with a new identity record);
- Gatekeeper, `spctl`, `stapler`, or the offline launch requires any workaround;
- the "clean Mac" proves to hold prior Fulmar state (record as upgrade test, not
  clean install; never delete state);
- a permission denial breaks an unrelated feature, or a Keychain denial crashes
  or loops the app;
- quit leaves an app-owned process running, or rollback leaves two visible
  `Fulmar.app` bundles;
- the DeepSeek path only ever produces a no-credit or mocked result (record as
  not qualified);
- a key, password or personal path appears in any record — redact at source
  and re-collect.

Tester-Mac rollback is step 6.3 in reverse; no tester data is ever deleted to
recover.
