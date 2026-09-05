# Preview binary and Gatekeeper — Fulmar 1.2.36 build 156 (v1.2.36-preview.1)

## Local signing is required for a usable source build

The documented `make private-release` command creates or reuses **Fulmar Local
Signing**, a persistent self-signed development identity in your login Keychain.
It may require initial macOS authorization; keep the identity for later builds.
It does not install the app, publish a binary, add an Apple Developer ID, or notarise
anything. The credential helper and embedded XPC services require the same
designated requirement, so an ordinary ad-hoc build cannot provide working cloud
credential storage. Do not remove the signature checks.

A compile/review-only app built with
(`LOCAL_HARNESS_REQUIRE_STABLE_SIGNING=0 LOCAL_HARNESS_SIGN_IDENTITY=- LOCAL_HARNESS_SIGN_TIMESTAMP=0 make build`)
is **ad-hoc signed**: it carries a code signature with no certificate, no Apple Developer
ID team, no secure timestamp and no notarisation ticket (`codesign -dv` reports
`Signature=adhoc`, `TeamIdentifier=not set`; `xcrun stapler validate` reports no ticket).
The signature lets macOS verify that the bundle has not changed since it was built; it
says nothing about who built it.

Neither local-signing option supplies a notarisation ticket. Consequences:

- macOS may block it depending on its provenance, quarantine state and security
  policy. A clean-Mac first launch has not been qualified for this candidate. If
  macOS blocks your own reviewed build, follow the per-app guidance below; do not
  disable Gatekeeper system-wide.
- It cannot be delivered through the in-app updater (disabled in this release) or
  through the fail-closed public-distribution path, which requires Developer ID and
  notarisation.
- Any copy you did not build yourself could have been altered after building. A SHA-256
  published next to a download only proves the bytes match what the publisher hashed —
  it does not prove the publisher, and it cannot substitute for notarisation.

## Recommended path: build it yourself

Build the preview from the exact tagged source on your own Mac using
`make private-release` (see the README "Build from source" section). The resulting
app is locally certificate-signed, not Apple-notarised; Gatekeeper still applies.
The build records the source-input inventory, dependency audit and static-scan
evidence in `build/`. Quit any existing copy, retain its bundle and a private state
backup, then place the reviewed build in `/Applications`. The sandboxed credential
services must be able to inspect their sibling helper's signature there; running
the build directly from `/private/tmp` is not the supported credential-service path.

## If macOS blocks your locally signed preview

Understand what you are accepting first: you are telling macOS to trust software that
Apple has not notarised and no Apple Developer ID has signed. If the bundle was
tampered with, Gatekeeper is the control you are switching off for that one app.

Use only Apple's explicit per-app allowance:

1. Copy your reviewed `Fulmar.app` to `/Applications` and double-click it once. If
   macOS shows a verification dialog, choose **Done** (not "Move to Trash").
2. Open **System Settings → Privacy & Security**, scroll to the **Security** section,
   and next to the message about Fulmar choose **Open Anyway**. Authenticate.
3. Launch Fulmar again and confirm the second dialog.

Apple's per-app "Open Anyway" records an exception for that exact bundle only. Do **not**:

- run `xattr -d com.apple.quarantine`, `xattr -cr`, or scripts that strip quarantine;
- run `spctl --master-disable`, `spctl --global-disable`, or otherwise turn Gatekeeper
  off system-wide;
- download Fulmar from any mirror, forum, or package manager that is not the project's
  own versioned release page;
- give the app Screen Recording, microphone, or other permissions until you have decided
  you trust the build.

The project's public-installation guide (`PUBLIC_INSTALLATION.md`) describes the future
Developer ID signed, notarised and stapled release for which none of the above applies.

## Removing the preview and rolling back

- Quit Fulmar; make sure it stopped its own DSH/Ollama processes (Activity Monitor
  shows no `LocalHarness*` helper or Fulmar-owned `ollama` process).
- Before deleting the app, turn off **Launch Fulmar when I log in** and **Run due tasks
  even when the main window is closed** so its login/background registrations are
  removed while the app is still present.
- Move `Fulmar.app` to the Trash. Conversations, settings, backups, schedules,
  Keychain credentials and Ollama models are intentionally retained; the exact
  locations and the deletion procedure are in
  [PUBLIC_INSTALLATION.md → Uninstall and retained data](PUBLIC_INSTALLATION.md#uninstall-and-retained-data).
- To go back to an earlier Fulmar build you kept, quit the app and swap the bundles
  yourself; the disabled in-app updater and its private rollback journal are not used
  by preview builds. Keep the matching Harness-state backup with the app you roll back
  to, and never share those backups.

## Gatekeeper evidence for a locally built preview

The build and frozen-candidate checks record the actual signing state and
absence of a notarisation ticket under the builder's private `build/` evidence. An old
candidate log must not be reused for changed source, and private build logs are not
included in the source package. Even a passing local frozen-candidate check does not
make those app bytes publishable: public binary distribution remains NO-GO until the
libvips LGPL/GPL obligations, Developer ID, notarisation, clean-Mac and update/rollback
gates pass against one exact archive.
