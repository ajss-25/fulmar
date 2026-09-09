# Contributing to Fulmar

Thank you for reviewing Fulmar. This project crosses model-provider, filesystem,
process, Keychain, network, and macOS lifecycle boundaries, so changes need evidence
that matches their risk.

The canonical repository is <https://github.com/ajss-25/fulmar>. The public maintainer
identity and first-party copyright/licence holder are **ajss-25**. Report ordinary
defects through the repository issue forms and suspected vulnerabilities through
[private vulnerability reporting](https://github.com/ajss-25/fulmar/security/advisories/new),
never through a public proof of concept containing private data.

## Before you start

1. Read `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, and
   `docs/UPSTREAM_DSH_UPGRADES.md`.
2. Run `zsh scripts/bootstrap-source-checkout.sh` from a clean checkout. It downloads
   the pinned Node archive, derives the checksum-bound public install lock, installs
   the exact DeepSeek Harness dependency tree with lifecycle scripts disabled,
   reapplies thirteen before/after-hash-bound patches, and verifies the complete runtime
   inventory. Do not run `npm ci` directly against the reviewed provenance lock: its
   historical local-plugin marker is intentionally materialized by the bootstrap.
3. Make the smallest coherent change. Never commit credentials, local model files,
   `.build`, `build`, or reconstructed `VendorRuntime` trees.
4. Run `zsh scripts/run-swift-tests.sh` and
   `zsh scripts/run-js-tests.sh --test Tests/JS/*.mjs`.
5. For release-equivalent evidence, install the content-pinned Python 3.12.3 and
   hash-locked Semgrep 1.135.0 closure with `scripts/install-pinned-semgrep.sh` as
   shown in `docs/GETTING_STARTED.md`, then run `make static-security-scan`. A
   version-only `pipx` installation is acceptable for informal development but is not
   release or hosted-CI evidence. The clean launcher requires Node 22.23.1, prefers
   the reconstructed bundled Node on macOS, and uses the exact setup-node release in
   clean GitHub Ubuntu CI. It
   deliberately removes Node loader paths, proxy settings, custom CA stores, and
   provider/Semgrep credentials before fetching rules; do not bypass that boundary
   with a direct `node scripts/run-static-security-scan.mjs` invocation.
   The command downloads the two registry packs only into a private temporary
   directory and requires the exact reviewed URL, byte count, SHA-256, content type,
   and rule count from `Config/SemgrepRules.json`. It fails if the registry changes
   either pack, if a scan target drifts, or on every unreviewed finding; its sole
   reviewed exception is structurally revalidated rather than hidden from the report.
   Do not update a rule checksum merely to restore CI: inspect the complete rule-pack
   difference and record the new scan evidence first.

Changes to provider egress, credentials, process launch, sandboxing, MCP, Skills,
updates, recovery, retention, or the vendored runtime require hostile-input tests and
an update to the release evidence or threat model. A passing fixture does not justify
claiming a live provider, clean-Mac install, or notarized release was tested.

## Licensing status

The repository owner selected the MIT License for original Fulmar source and has
reviewed the source-preview third-party licence inventory, including the exact
upstream MIT terms for modified `@earendil-works/pi-ai` 0.82.1. By
contributing, you agree that your contribution may be distributed under that licence.
The exact top-level `LICENSE` and matching bounded `Config/ProjectLicense.json` must
remain together as described in `docs/FIRST_PARTY_LICENSE_POLICY.md`; either file by
itself, linked or writable inputs, or a SHA-256 mismatch intentionally stops all
production builds. This project-level licence does not override third-party terms. A
built app additionally carries libvips binary material whose LGPL/GPL notice,
corresponding-source and relinking obligations remain unresolved, so no downloadable
binary is approved by the source-preview decision.
