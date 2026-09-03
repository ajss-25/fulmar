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
  with thirteen hash-bound Fulmar patches; nothing generated is stored in Git.
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

## Automated qualification required for this exact source

The public source commit is releasable only after these exact local gates and all four
required GitHub-hosted checks pass. Logs and hashes are retained outside the tracked
source tree; this document does not pre-claim an unrun result.

| Gate | Result |
| --- | --- |
| Tracked-index policy on the proposed public commit | must pass against the exact committed index |
| Clean-checkout bootstrap (`zsh scripts/bootstrap-source-checkout.sh`) | must reconstruct pinned Node, DSH 0.1.1-rc.1, qs 6.16.0, fast-uri 3.1.6, 13 patches, and the exact 38,501-entry / 394,622,078-byte VendorRuntime inventory |
| DSH promotion provenance, source product contract, DeepSeek runtime contract | must pass |
| Production dependency audit (npm 10.9.8, credential-free) | must report zero findings |
| Static security scan | must report zero unreviewed findings using the content-pinned Semgrep 1.135.0 closure and pinned rules |
| JavaScript gate | must complete 653 exact tests: 606 passed, 47 reviewed intentional skips, 0 failures |
| Swift gate | must complete 1,445/1,445 isolated functions, DeviceAttestationAuthorityTests 10/10, warning-clean, with deployment target 15.0 verified |
| GitHub-hosted source checks | `static-analysis`, `codeql-javascript`, `macos`, and `minimum-macos-candidate` must all pass on the exact source commit |

Automated results cover the exercised cases; they do not prove the absence of defects.
The exact build-156 candidate has **not** yet had its own candidate-bound physical
hardware rerun (local inference, thermal, tool routes) — earlier builds on the same
host have, see `docs/QUALIFICATION_EVIDENCE.md` and `docs/SUPPORT_MATRIX.md`.

## What you can do with it

- Build it from source on an Apple-silicon Mac and run it locally (ad-hoc signed; see
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
the interactive permission/accessibility matrix, two-version update/rollback exercise,
live funded provider tests, the unresolved binary libvips redistribution obligations,
formal trademark clearance beyond the owner's source-preview risk acceptance, and the
first exact-candidate hardware rerun (`docs/PUBLIC_RELEASE_READINESS.md`).
