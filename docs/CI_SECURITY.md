# Hosted CI and repository security

Fulmar's hosted workflow has two distinct purposes: reject unsafe source before
running it, and exercise the deterministic part of candidate qualification. A green hosted run
is useful evidence, but it is not by itself permission to publish a release.

## First-index gate

The first command after each checkout is `scripts/verify-tracked-index.sh`. It uses
only the operating system's Bash, Git, Perl, and basic file tools; downloaded Node,
Semgrep, Swift build products, and repository package code have not run yet. The gate
examines the stage-zero Git index and fails closed for:

- tracked `.build`, `build`, `recovered-duplicates`, generated `VendorRuntime`, or
  unknown top-level content;
- symlinks, gitlinks/submodules, unresolved stages, non-regular blob modes,
  unexpected executable files, and reviewed executable scripts whose executable bit
  was removed;
- absolute, traversal-like, control-character, backslash, invalid-UTF-8, or
  case/Unicode-normalization-colliding paths;
- blobs larger than 100 MiB; and
- filenames conventionally used for credentials, private keys, certificates,
  provisioning profiles, or package-manager authentication.

The policy intentionally returns a non-successful **NOT RUN** result when Git metadata
is absent. It never turns a source export into evidence about an index it cannot
inspect. The gate examines the current index only; it does not scan prior commits,
deleted blobs, reflogs, tags, GitHub settings, or the provenance of imported history.

## Hosted jobs and deterministic candidate profile

The workflow defines four required jobs: `static-analysis`, `codeql-javascript`,
`macos`, and `minimum-macos-candidate`. CodeQL analyzes JavaScript and TypeScript only;
Swift is covered by the warning-clean Swift gate and the repository's targeted
security tests, not by a claimed CodeQL Swift scan.

The separate `Check upstream DSH` workflow is a read-only scheduled/manual observer.
It verifies the exact Node runtime and requires source acknowledgement of every
monitored DSH release channel. It reports drift; it never promotes or installs a newer
Harness package. Both workflows require a real hosted pass before source publication.

The static job verifies exact Node bytes, installs a content-pinned standalone Python
3.12.3 distribution, installs Semgrep 1.135.0 from a complete `--require-hashes`
wheel closure, and runs the source-controlled rule-pack and source-inventory gate.
The two platform locks, Python archive bytes, interpreter bytes, requirements input,
and generated-lock contract are bound by `Config/SemgrepToolchain.json`. A
version-only `pipx install semgrep==1.135.0` is useful for informal development but is
not equivalent release or hosted-CI evidence.

The macOS job verifies ARM64 and at least 6 GiB of free build capacity, reconstructs
the exact inventoried runtime, captures the hosted image/Xcode/SDK/tool identities,
requires them to match the reviewed source pin before compilation, creates a
credential-free production dependency audit, installs the same content-pinned
Semgrep toolchain, and builds only after a fresh source/secret scan has been bound to
the frozen source-input inventory. It then invokes
`make deterministic-release-verify` without rebuilding that candidate. An isolated
unlocked CI Keychain lets Keychain transaction and provider-fixture tests run without
storing a real provider secret. The candidate verifier runs the archive, manifest,
inventory, signature, entitlement, dSYM, SBOM, notice, packaged-policy, JavaScript,
native, credential, runtime, sandbox, MCP, installed-layout, cloned-state, web/RPC,
and simulated provider/protocol gates against the archive extraction.

The production audit loads the attested lock with the npm 10.9.8-bundled Arborist,
applies npm's production-only virtual-tree semantics, and first sends sorted,
byte-bounded batches to the configured registry's official Bulk Advisory endpoint.
Requests are credential-free, do not follow redirects or consult proxy environment
variables, and have per-attempt and whole-operation deadlines. Responses are
independently bounded before and after decompression and must satisfy the complete
advisory schema. The decoder recognises gzip magic because npm's registry can
currently omit `Content-Encoding` and other entity headers from compressed Bulk
Advisory responses; it never uses the retired Quick Audit endpoint.

If, and only if, one Bulk Advisory batch exhausts two attempts because of a bounded
timeout, reachability failure, or retryable HTTP 408/429/5xx response, the audit may
discard any earlier validated zero-finding npm batches and restart the complete graph
against the credential-free OSV QueryBatch API at
`https://api.osv.dev/v1/querybatch`. This secondary-authority route is restricted to
the literal public npm registry and requires every non-development lock node to have
its exact canonical `registry.npmjs.org` tarball URL and SHA-512 integrity. It does
not run after an npm advisory, TLS failure, redirect, malformed response, schema
error, or other semantic failure, and evidence never mixes the two authorities.
Deterministic request hashes, strict result cardinality, pagination rejection,
response hashes, and the public-provenance digest bind the fallback result. A passing
artifact is published only after every requested exact package/version pair has a
validated zero-finding response from one authority.

Candidate-dependent JavaScript tests run with
`FULMAR_CI_REQUIRE_CURRENT_CANDIDATE_TESTS=1`; a missing or stale fixture is a failure,
not a skipped success. The cloned-state gate constructs a non-secret, non-empty prior-
DSH-state fixture, proves its exact nested bytes were copied, and proves the source
fixture remained unchanged.

The deterministic profile explicitly records the physical-Qwen gates as
`required-not-run` in `build/ci-evidence-summary.json`. The normal
`make release-verify` path remains the full-hardware profile and still runs the app-
owned Ollama generation plus Qwen bash, filesystem, and project tool routes. There is
no environment flag that converts the default release gate into a silent skip.

The bounded, path-free JSON evidence is rendered in the GitHub job summary. Five
reviewed candidate files are additionally sent through exact-SHA-pinned GitHub
artifact actions: the candidate archive, release manifest, canonical evidence,
Runtime Mach-O inventory, and a transport record that binds those bytes to the source
commit. No console log, private path, Keychain value, model output, workspace content,
or complete build directory is uploaded. The archive is retained for one day only;
the bounded machine-readable records are retained for review. These CI artifacts are
test inputs and do not constitute an approved public binary release.

## Six implemented reproducibility controls and remaining evidence

The source now implements all six previously identified controls. Implementation and
focused tests do not count as a successful hosted run; each control remains fail-
closed until its stated execution evidence exists.

In short, those controls cover the exact Xcode and related hosted-tool identities, a
macOS 15 ARM consumer, two different checkout roots, the hash-locked Semgrep closure,
two scanners over the complete real Git history, and content-pinned upload/download
evidence transport.

1. **Hosted toolchain identity.** `Config/HostedMacOSToolchainPin.json` and
   `scripts/hosted-macos-toolchain-pin.mjs` source-bind the requested image, exact
   hosted image identity, Xcode, SDK, compiler, linker, and related tools. The initial
   `discovery-required` state uploads a bounded proposal and deliberately fails before
   compilation. A maintainer must review and commit the exact active pin, after which
   a fresh hosted run must verify it.
   Schema 3 preserves the primary identity and permits exactly one complete active
   schema-2 compatibility pin. The reviewed pair is image `20260831.0337.3`
   (macOS `26.6.2` / `25G83`) and image `20260728.0273.1`
   (macOS `26.5.2` / `25F84`); neither is a version range or a mutable fallback.
   Fresh discovery must equal one whole member, including its image and tool
   hashes. The clean capture selects a unique member using the system OS identity,
   uid and Xcode directory, then rechecks that member's complete inventory. Mixing
   fields across members, ambiguous selectors, nested pins and unknown hosted OS
   identities are rejected. Local Command Line Tools remain root-only. A reviewed
   compatibility pin is not qualification evidence: each image still needs a real
   complete hosted run against the candidate source before claiming qualification.
   The clean release toolchain capture inside `scripts/build-app.sh` stays root-only
   except for one pin-bound admission: GitHub's hosted image owns Xcode as the
   `runner` user, so `scripts/toolchain-inventory.mjs` admits a non-root-owned
   developer tree only through the literal tracked active pin — never through an
   environment variable, a caller-supplied uid, or a hosted-mode switch — and only
   when the effective uid, the canonical `xcode-select` developer directory, the SDK
   path, every tool's canonical path, byte count and SHA-256, the OS and tool
   versions and the build controls all equal the pinned inventory, every file is
   owned by root or exactly the pinned uid with no group/world write, and the
   canonical developer-directory, SDK and tool-parent directory chain is attested
   through no-follow descriptors. Tools are hashed through descriptor-attested
   O_NOFOLLOW reads with pathname identity rechecked around the hash, and every
   admitted executable matches its pinned bytes before it is run. This is exact
   reviewed-image provenance with persistent-mutation detection: it detects a
   replaced or drifted image tree, not malicious same-uid or passwordless-sudo
   workflow code on the same runner, and the live GitHub Actions context and image
   identity are bound by the workflow's earlier pin verification step rather than by
   the environment-free build capture.
2. **Exact minimum-macOS consumption.** The `macos-15` ARM job downloads the five
   producer artifacts by immutable artifact ID, requires GitHub's artifact digest,
   revalidates the source/manifest/archive/transport binding, checks every Mach-O
   deployment target and signature, and performs a bounded headless smoke without
   rebuilding the app.
3. **Two-root unsigned reproducibility.** The gate clones one clean committed tree
   into two different-length checkout paths with distinct private scratch roots,
   builds both, and compares all eight native products, their eight matching dSYMs,
   and the path-free unsigned bundle inventory. Signed, notarized, and `ditto` ZIP
   bytes remain immutable hash-bound artifacts rather than claimed reproducible
   outputs.
4. **Scanner closure.** The exact Python archives/interpreters and complete Semgrep
   wheel closures for macOS ARM64 and Linux x64 are source-hash-bound. Installation
   runs in an isolated environment with package hashes, `pip check`, metrics and
   version checks disabled, and no account token. The separately downloaded Semgrep
   rule responses retain their existing exact content/origin/rule-set pins.
5. **Complete-history review.** Gitleaks and TruffleHog are the two independent
   scanners selected for all-ref history review. Their first scan of the existing
   public repository history found no secret; the final candidate commit and every
   reachable branch/tag must be rescanned and the reports retained before source
   publication. A shallow pull-request checkout cannot establish this evidence.
6. **Content-pinned evidence transport.** Exact-SHA-pinned GitHub-owned upload and
   download actions retain and transport only the bounded files described above.
   Artifact IDs, service digests, file digests, source revision, and release-manifest
   identity are checked by the independent consumer.

The source implementation includes an active reviewed hosted-toolchain pin and focused
contract coverage. A public-source decision must still retain a real GitHub-hosted run
for the exact candidate, app-ID/source-revision binding, a final all-ref secret scan,
and the resulting hosted evidence; tracked source alone must never be described as that
external evidence.

The weekly schedule catches runner, registry-audit, runtime-bootstrap, toolchain, and
rule-endpoint drift. The bounded Bulk Advisory audit and its narrowly admitted OSV
secondary-authority route, Python/wheel installation, and external rule fetch are
intentionally network-dependent security observations, not offline reproducibility
claims.

## Repository controls

The public repository has private vulnerability reporting, secret scanning and push
protection, Dependabot alerts and automated security updates, read-only default
workflow permissions, SHA-pinned GitHub-owned Actions only, protected `main` with the
four job contexts above required, and immutable `v*` tags. Branch rules do not make an
unrun workflow green. The exact-candidate hosted run, final app-ID/revision check,
final-history rescan, collaborator/app/webhook review, and retained settings evidence
remain release operations rather than source-code assertions.

## Gates that cannot move to a standard hosted Mac

GitHub's standard Apple-silicon runner does not meet Fulmar's 48 GB local-model
admission contract. Candidate-bound local-model qualification therefore still requires
a physical 48 GB Apple-silicon Mac with the exact reviewed Qwen model and official
Ollama binary for Metal/MLX residency, thermal admission, cancellation, cleanup, and
tool-route tests. Successful live funded cloud-provider routes also remain separate
evidence rather than simulated-protocol claims.

Developer ID signing, Apple notarization/stapling, offline Gatekeeper, clean-Mac
installation, two-version update/rollback and power-loss recovery, interactive
permissions/accessibility/status-item behavior, and the unresolved libvips LGPL/GPL
notice/source/relink obligations are **public-binary** gates. They do not prevent an
accurately labelled MIT source preview once its source-specific history, hosted-CI,
repository-control, and licence evidence is complete.
