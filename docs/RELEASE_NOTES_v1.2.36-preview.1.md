# Fulmar v1.2.36-preview.1 — release notes (proposed; source preview)

**Status: source-only public preview candidate for owner review. Not a supported
download, not signed with a Developer ID, not notarised.** Fulmar is unofficial,
independent software and is not affiliated with or endorsed by DeepSeek, OpenAI,
Anthropic, Ollama, Alibaba or the Qwen project.

## What this preview is

- Source identity: Fulmar **1.2.36 build 156**, Apple silicon, macOS 15.0 minimum
  (physically tested only on macOS 26.6.2).
- Bundled runtime: DeepSeek Harness `0.1.1-rc.1` (+ DSH MCP client `0.1.1-rc.1`) on
  Node `22.23.1`, reconstructed at bootstrap from `VendorRuntime/package-lock.json`
  with fourteen hash-bound Fulmar patches; nothing generated is stored in Git.
- Licence: original Fulmar source under the MIT License (`LICENSE`); bundled third-party
  components keep their own terms (see the generated SBOM and notices in a built app).

## Changes since the 1.2.36 candidate notes in `CHANGELOG.md`

- Transitive dependency remediation only (no product change):
  `qs` 6.15.3 → **6.16.0** (GHSA-x5fp-wj9c-mxmx, GHSA-4mjr-xmp4-gh2g) and
  `fast-uri` 3.1.5 → **3.1.6** (GHSA-f65p-4m7j-42xc, GHSA-fph4-wmhf-6fwf,
  GHSA-jqff-g426-hqxp, GHSA-5jgf-p345-68v8), each as an exact lock-descriptor update
  with the runtime rebuilt through the pinned materialiser. The production dependency
  audit now reports zero findings with no waivers.
- Public-preview documentation: README front matter, `docs/SUPPORT_MATRIX.md`,
  `docs/TROUBLESHOOTING.md`, `docs/PREVIEW_BINARY_GATEKEEPER.md`,
  `docs/BUG_REPORT_CHECKLIST.md`, these notes, and consistent unofficial-status wording.
- Release-pipeline hardening: pin-bound hosted-Xcode admission, descriptor-attested
  readers, and vnode-anchored synchronous publication for retained security,
  toolchain and reproducibility evidence.
- Startup corrections: explicit device-trust authorization, typed recovery states,
  protected profile preparation and retained-descriptor runtime authentication.
- Exact notices for the 29 libvips component entries, Rust notice-material binding
  and verified bootstrap cache integration. Binary source-offer, relinking and legal
  clearance remain separate open requirements.

## Automated qualification required for this exact source

The public source commit is releasable only after these exact local gates, all four
required workflow jobs, and the separate GitHub CodeQL app check pass. Logs and hashes
are retained outside the tracked source tree; this document does not pre-claim an
unrun result.

| Gate | Result |
| --- | --- |
| Tracked-index policy on the proposed public commit | must pass against the exact committed index |
| Clean-checkout bootstrap (`zsh scripts/bootstrap-source-checkout.sh`) | must reconstruct pinned Node, DSH 0.1.1-rc.1, qs 6.16.0, fast-uri 3.1.6, Hono 4.13.5, js-yaml 4.3.2, sharp 0.35.4, 14 patches, the exact 38,504-entry / 395,128,248-byte VendorRuntime inventory and the verified Rust notice-material cache |
| DSH promotion provenance, source product contract, DeepSeek runtime contract | must pass |
| Production dependency audit (pinned npm 10.9.8 virtual tree; credential-free bounded Bulk Advisory primary; whole-graph OSV QueryBatch secondary authority only after a narrowly retryable batch outage; no Quick Audit route) | must report zero findings and identify one complete authority |
| Static security scan | must report zero unreviewed findings using the content-pinned Semgrep 1.135.0 closure and pinned rules |
| JavaScript gate | 902 exact tests: source profile requires 855 passed / 47 reviewed skips; candidate profile requires 856 passed / 46 reviewed skips, with 0 failures |
| Swift gate | must complete 1,455/1,455 isolated functions, DeviceAttestationAuthorityTests 12/12, warning-clean, with deployment target 15.0 verified |
| GitHub-hosted source checks | Workflow jobs `static-analysis`, `codeql-javascript`, `macos`, and `minimum-macos-candidate`, plus the separate `CodeQL` app check, must all pass on the exact source commit |

Retained local results on 2026-09-09 for source `d40a1ee` passed all 1,455 Swift
functions plus 12 attestation scenarios and the candidate JavaScript gate
(902 tests, 856 passed, 46 intentional skips, no failures). Its installed build 156
also passed native startup, actual Qwen MLX inference with Write and Read tools, quit
cleanup and relaunch without a repeated Keychain or recovery prompt on the 48 GB
M5 Pro. This is bounded acceptance, not a complete thermal, other-hardware,
live-provider or hosted-CI qualification. The final public commit still needs its own
hosted results. See `docs/HANDOFF_CURRENT.md` and `docs/SUPPORT_MATRIX.md`.

## What you can do with it

- Build it from source on an Apple-silicon Mac using the persistent local signing
  identity created/reused by `make private-release` (no paid Apple developer account;
  ad-hoc builds are compile/review-only, not cloud-credential builds; see
  `docs/PREVIEW_BINARY_GATEKEEPER.md`).
- Use the on-device route with official Ollama 0.33.x and `qwen3.8:27b-mlx` on a 48 GB
  Mac (the only qualified local model), or other models in Compatibility mode.
- Use the DeepSeek API or a custom OpenAI/Anthropic-compatible endpoint with your own
  credentials, understanding that live provider behaviour is protocol-simulated only.

## What you should not expect

- A downloadable, notarised app; an in-app updater; Intel support; localisation; a
  first-run assistant; every Ollama model to work; or any live paid-provider guarantee.
- Zero defects. Please report reproducible problems with the checklist in
  `docs/BUG_REPORT_CHECKLIST.md`; report vulnerabilities privately (`SECURITY.md`).

## Open gates before any binary release

Developer ID signing and notarisation, clean-Mac and minimum-macOS installation tests,
the interactive permission/accessibility matrix, live funded provider tests, the
unresolved binary libvips redistribution obligations, formal trademark clearance
beyond the owner's source-preview risk acceptance, and the remaining exact-candidate
hardware matrix (`docs/PUBLIC_RELEASE_READINESS.md`). The stable profile also requires
two-version update/rollback and power-loss recovery; the separate manual-install beta
requires its own install/reinstall/recovery evidence with the updater disabled
(`docs/PUBLIC_BETA_RELEASE_CONTRACT.md`).
