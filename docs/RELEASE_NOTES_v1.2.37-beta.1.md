# Fulmar 1.2.37 beta 1 — candidate notes

**Planned, not published or public-beta-qualified.** App version 1.2.37, build 157;
proposed immutable tag `v1.2.37-beta.1`. Fulmar's own source is MIT licensed;
bundled third-party software retains its own licence terms.

## Candidate scope

- Direct download, manual installation and manual updates; no App Store,
  Developer ID or Apple notarization is claimed.
- Persistent private certificate shared by the app and its helpers; automatic
  updater disabled. Recipients must not import/trust a certificate or disable
  macOS security protections to run it.
- Clean-install-only until separate retained-state migration acceptance exists.
- Apple silicon, declared minimum macOS 15. Actual supported-release claims must
  follow final current/minimum-OS recipient evidence, not deployment metadata alone.

## Included work

The model-budget fix replaces a fixed reserve with a bounded context-proportional
reserve, limits output to available capacity and stops empty automatic
continuations. It preserves model-memory admission, cancellation and continuation
limits. Provider selection remains explicit: Ollama, compatible local endpoints
such as LM Studio, and cloud APIs are distinct routes with their own disclosure
and testing requirements. No model is silently downloaded or substituted.

The runtime remains pinned to DSH/MCP 0.1.1-rc.1 and Node 22.23.1. Observing a newer
upstream release does not promote it into this candidate.

## Evidence and limits

The preceding build-156 candidate passed the complete local JS/Swift gates and
real Qwen2.5:7b Write/Read, Quit and relaunch on a 16 GiB M4 Mini. This is evidence
for that exact private candidate, not a claim that build 157 or a public download
has passed. Live LM Studio/cloud operation, the clean current/minimum-macOS
recipient matrix, manual reinstall/recovery, final material delivery and the
existing binary-distribution obligations must be completed before publication.

There is no supported download link in these candidate notes. Once all required
evidence is bound to the final ZIP/DMG and signer, publish a prerelease with the
fourteen verified assets and link its exact DMG from the installation guide.
