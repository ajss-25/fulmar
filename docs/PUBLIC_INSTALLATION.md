# Public installation and removal

Fulmar is unofficial, independent software and is not affiliated with or endorsed by
DeepSeek, OpenAI, Anthropic, Ollama, Alibaba or the Qwen project.

These instructions apply only to a Fulmar release whose public-distribution gate has
passed. For the current source preview (`v1.2.36-preview.1`) there is no such release:
build the app from source and read `PREVIEW_BINARY_GATEKEEPER.md` before running a
locally certificate-signed preview build. An ad-hoc compile/review build cannot use
the packaged cloud credential service. The **Uninstall and retained data** section below applies
to preview builds as well. The current private candidate is not a public release: it is not Developer ID
signed/notarized, has not passed clean-Mac/minimum-OS qualification, and its updater
transaction has not passed the required two-version real-signed power-loss exercise.
Do not publish the current app archive as an end-user download.

## Download and verify

For an ordinary installation, download only `Fulmar.app.zip` and
`Fulmar.app.zip.sha256` from the same immutable GitHub release. In Terminal, change
to the download directory and run:

```sh
shasum -a 256 -c Fulmar.app.zip.sha256
```

Do not install the app if the Fulmar archive reports anything other than `OK`. Do not bypass Gatekeeper, remove quarantine attributes, or use a checksum copied from a different website or release.

Security reviewers can additionally download `Fulmar.dSYMs.zip`,
`release-manifest.json`, `static-security-summary.json`, `LocalHarness.sbom.cdx.json`,
`THIRD_PARTY_NOTICES.md`, `LICENSE`, and `SHA256SUMS.txt`. Those seven reviewer assets
plus the two ordinary-download assets form the exact nine-asset release set.
`SHA256SUMS.txt` authenticates the other eight files when run with
`shasum -a 256 -c SHA256SUMS.txt`; the manifest-bound dSYM archive
is for crash symbolication and is never installed into the app. The manifest-bound
static-security summary is reviewer evidence and is likewise not installed. The public
verifier also requires the source, signed-app, and release-copy `LICENSE` bytes to match exactly.

## Install and first run

1. Expand `Fulmar.app.zip` and drag `Fulmar.app` into `/Applications`.
2. Open Fulmar normally from Applications. Gatekeeper should accept it without a workaround.
3. Review the privacy boundary before selecting a model. Local Ollama work remains on the Mac; API providers send task content to the selected provider after explicit consent.
4. Grant only the macOS permissions needed for features you choose. Denying microphone, speech, notifications, Screen Recording, or background scheduling should leave unrelated features usable.
5. Configure provider credentials through Fulmar so they are stored in macOS Keychain. Never place API keys in prompts, project files, shell history, or issue reports.

The declared platform is an Apple-silicon Mac running macOS 15 or later; Intel is not
supported. Before publishing a release for that declared range, the same immutable
archive must pass a clean non-developer macOS 15 installation as well as the current
supported macOS release. Automated architecture and deployment-target checks are not a
substitute for those physical installs.

For local work, install models through Ollama before opening Fulmar. Fulmar does not
download, pull, update, or delete model weights. Use official stable Ollama 0.33.2
through the 0.33.x series. Upstream 0.32.12 first introduced the Qwen/MLX model, but
0.33.2 is the oldest version Fulmar has exercised end to end and is therefore the
supported floor. A 0.34-or-newer series fails closed until a later Fulmar release
qualifies it. Run
`ollama pull qwen3.8:27b-mlx`; only that tag with manifest digest
SHA-256 `5642e97495e1a088883805981563dcdc4a040c2f53388b7a41d1f24d3622cf7e`
on a Mac with at least 48 GB of physical memory is the release-qualified route with
Fast/Balanced/Deep profiles. A tag whose digest changed is refused until that exact
artifact is separately qualified in a later Fulmar release. Another installed model is
unqualified and can run only after its live metadata passes Compatibility admission:
completion and tools, no model-specific thinking mode, and context metadata between
8,192 and 1,048,576 tokens. The host must also have at least twice Ollama's reported
installed size plus a 4 GiB system/runtime reserve. That route is text-and-tools-only
and fixed at 8K context / 2K output. If a saved model is
missing, use **Choose Installed Local Model**; Fulmar never substitutes the first model
or downloads one automatically.

For DeepSeek or another API provider, saving and verifying a credential does not make
it the active inference route. Choose the provider's model, review the exact endpoint
and disclosure boundary, and then select **Use for New Tasks**. This explicit action
starts fresh tasks on that provider; it must never be inferred from credential entry.
The packaged DeepSeek, OpenAI, Anthropic, and custom-compatible protocol fixtures do
not prove live account acceptance, billing, quota, retention, output quality, or
provider uptime. Release notes may call a named provider live-qualified only when the
exact release evidence includes successful account-backed text, harmless tool,
cancellation, and expected error-path tests.

Fulmar's model-size admission, owned-process checks, adaptive Eco mode, and emergency
thermal stop apply only to the app-owned Ollama route. A separately configured
loopback or private-network OpenAI-compatible server is a consented **Local network**
provider. It does not receive Fulmar's Ollama RAM, process-ownership, Metal/MLX, or
thermal claims and requires its own endpoint/protocol/tool/cancellation/privacy test.

## Updating safely

Use in-app update only after the release notes identify a fully qualified two-phase
updater. A public updater must retain the prior app, install the candidate, launch that
exact bundle with a private nonce-bound readiness channel, verify application identity
and authenticated runtime health, and only then commit and remove recovery state. A
launch-command success by itself is not proof that the new app started or is usable.
Until that evidence is recorded across two notarized versions, update by the published
manual verified-replacement procedure and preserve the previous app and matching state
backup for rollback.

## Uninstall and retained data

Before removing the app, open **Fulmar Settings → General** and turn off **Launch
Fulmar when I log in**. Then open **Schedules & Task Inbox** and turn off **Run due
tasks even when the main window is closed**. This unregisters Fulmar's login and
background-schedule services while the signed app is still available to perform the
operation. Quit Fulmar, then move `/Applications/Fulmar.app` to the Trash. Removing
the application does **not** automatically remove conversations, workspaces,
settings, backups, schedules, diagnostics, model files, or Keychain credentials.

If you also intend to erase Fulmar data, first export anything you want to retain. Then remove Fulmar-owned data through its privacy/settings controls where available. Review these locations manually before deleting anything:

- `~/Library/Application Support/Local Harness` — **Fulmar Application Support**:
  tasks, configuration, Workspace files, backups, schedules, diagnostics, and private
  Harness state under the stable legacy directory name;
- `~/Library/Preferences/com.angadjairath.localharness.plist` — Fulmar preferences;
- Keychain service `app.localharness.credentials` — provider credentials, and
  `com.angadjairath.localharness.backup-authentication` — backup authentication;
- `~/.dsh` — legacy DeepSeek Harness state. Review it rather than deleting it
  automatically because a standalone Harness installation or an older build may own
  data there;
- `~/Library/WebKit/com.angadjairath.localharness` and
  `~/Library/Caches/com.angadjairath.localharness` — legacy/private embedded-WebKit
  and cache data for this exact bundle identifier.
- `~/Library/Saved Application State/com.angadjairath.localharness.savedState` —
  macOS-managed window restoration data, if the operating system created it.

macOS can retain privacy-permission and Background Items decisions after the app is
removed. Those records are operating-system state rather than Fulmar files. Review
the Fulmar entries in **System Settings → Privacy & Security**, **Notifications**,
and **General → Login Items & Extensions**; remove or reset them there if the intent
is a complete local reset. Never delete a system privacy or background-items database
directly.

`~/.ollama` is shared, Ollama-owned model storage and is **never part of Fulmar
cleanup**. Deleting it may break other applications and require downloading large
models again. Do not recursively delete a parent Library or home directory. Empty the
Trash only after confirming the retained-data choice.

For a reinstall, use a release with a valid published checksum. Existing retained state may be reused only when the new release's migration and update guidance explicitly supports it.
