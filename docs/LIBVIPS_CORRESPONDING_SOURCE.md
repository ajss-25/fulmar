# libvips combined binary — exact notices and corresponding-source materials

This document records what the repository now binds for the redistributed
`@img/sharp-libvips-darwin-arm64` 1.3.3 combined binary
(`lib/libvips-cpp.8.18.6.dylib`), how that material is verified, and what it
does **not** establish. It is a material record, not legal advice, not a
corresponding-source offer, and not evidence that any beta candidate passed the
`thirdPartyBinaryLicenseMaterials` gate in `docs/PUBLIC_BETA_RELEASE_CONTRACT.md`.
Nothing here changes the first-party MIT licence of Fulmar's own source, and
nothing here describes the third-party binary as MIT.

## What the binary is

The npm tarball (integrity and per-file digests in
`Config/ThirdPartyBinaryProvenance.json`) was produced by the
`lovell/sharp-libvips` repository at tag `v1.3.3`, commit
`6e5971d333377743163edc3ad9e5d0b897abcbc9` (the npm `gitHead`), by running
`build.sh darwin-arm64v8`, which sources `versions.properties` and
`build/posix.sh`. That recipe downloads 28 upstream source archives, applies
four patches and a number of inline `sed` edits, builds every dependency as a
static library, links libvips itself statically into `libvips-cpp`, and packs
the single dylib plus `versions.json` and a licence table into the tarball.
The shipped `README.md` is that licence table under a package heading.

The 09/09/2026 security refresh from sharp 0.35.3 to 0.35.4 changes this native
bundle from 1.3.2 to 1.3.3; it is not only an addon change. Thirteen component
versions change, including libheif 1.23.2 and libvips 8.18.6. The replacement
npm tarball's registry integrity and all six file digests were verified before
binding them. This refresh does not qualify a public binary or close any legal
obligation.

The README names 29 libraries; `versions.json` pins 28 versions. The difference
is `libnsgif`: it is not downloaded or versioned by the recipe because libvips
vendors it at `libvips/foreign/libnsgif` (copied from
`git://git.netsurf-browser.org/libnsgif.git` by `update.sh`, "Last updated
22 Jan 2023"). Its source is the libvips 8.18.6 archive. Neither the libvips
tree nor the recipe records an upstream libnsgif release or commit, so **no
libnsgif version is asserted anywhere in this repository**.

## Part A — exact per-component notices (bound)

`Config/ThirdPartyBinaryProvenance.json` → `components[0].componentNotices`
holds one record per README library (29), each naming the exact pinned
version (or `null` for libnsgif, with the resolution above), the upstream
repository, the full 40-hex revision the version resolves to and how that
resolution was obtained, and one or more notice materials. Every material is a
file under `Resources/ThirdPartyLicenses/`: changed component versions use
`sharp-libvips-1.3.3/`, unchanged versions retain their verified `1.3.2/` paths,
and libvips uses `libvips-8.18.6-LICENSE`. Each is
stored as the exact upstream bytes plus one terminal LF
(`append-terminal-lf-v1`), with the raw upstream SHA-256, the tracked SHA-256,
the upstream origin (commit-pinned forge URL or exact digest-pinned release
archive), and the archive member and archive SHA-256 the bytes were verified
against. On 09/09/2026 all 35 texts for the replacement were compared against
the exact 28 source archives; all matched their bindings. Fifteen version-bound
files were added and historical files preserved. Only libffi's licence text
changed (its copyright year advanced from 2025 to 2026); the shipped README
table was independently verified byte-identical. The 05/09/2026 comparison
against both archive members and upstream revision files belongs to the older
1.3.2 materials, not to a claim that the replacement repeated that second check
for every component.

`scripts/generate-third-party-notices.mjs` follows the
`componentNotices: { manifest, component }` reference in the sharp-libvips
entry of `Config/ThirdPartyLicenseOverrides.json`, re-verifies every material
under the same bounded, alias-free, digest-checked contract as package-level
tracked texts, requires that every manifest library and every pinned version is
covered exactly once, and appends a deterministic section "Exact per-component
notices for redistributed binaries" to the generated notices. Identical texts
(pango/proxy-libintl; librsvg/libvips) are embedded once and cross-referenced.

The same provenance component now also declares `deliveryMaterials`: the
tracked corresponding-source manifest, the tracked crate manifest, the tracked
notice-materials manifest for the six crates without archive licence text, and
the accompanying-documentation statements (`docs/THIRD_PARTY_ACKNOWLEDGEMENTS.md`,
each tied to the bound FTL/IJG material). Because the record declares them,
the generator **requires** an explicit operand
`--rust-crate-materials <verified sharp-libvips-1.3.3-rust-crate-materials directory>`
— the private acquisition produced by `prepare-libvips-source-materials.mjs`
with `--notice-materials` (Part B) — and fails closed, naming that operand,
when it is absent; nothing is inferred from the environment, a directory is
never trusted by its file names alone (every archive is re-hashed and re-framed
and the standalone notices are re-rendered and compared), and the operand is
refused when no component declares a binding. With the operand the generated
notices gain three deterministic sections: "Rust crate notices for redistributed
binaries" (the 161-crate table, the six-crate section with the two exact
external texts and the four unresolved records, and every archive-carried
licence text embedded once per distinct digest: 92 distinct texts across 271
members), "Acknowledgements required in
accompanying documentation" (the exact
FTL and IJG statements and the cairo retained-text clarification, verified
verbatim against the documentation file) and "Delivery material inventory"
(every consumed input and rendered output by SHA-256). The 29-component section
and the first-party licence semantics are unchanged. The operand is wired into
`scripts/build-app.sh` and the other three release call sites from a private
checkout-local cache, see "Packaging integration".

Facts surfaced by the exact texts that the upstream README table does not show,
returned for owner/legal review rather than resolved here:

- cairo is dual-licensed LGPL-2.1 / MPL-1.1; the README says "Mozilla Public
  License 2.0". Both real texts are bound.
- freetype's FTL (§2) and mozjpeg's IJG terms (README.ijg) each require a
  specific acknowledgement in accompanying documentation. The exact wording is
  held in `docs/THIRD_PARTY_ACKNOWLEDGEMENTS.md`; placing it in the shipped
  documentation is Codex integration work, and binding the licence text does not
  by itself place those statements.
- highway (Apache-2.0 / BSD-3) and libultrahdr (MIT / Apache-2.0) are
  dual-licensed; the README names the BSD-3 and MIT options respectively.
- libaom and libwebp carry additional patent-grant files (bound).
- librsvg is Rust. Its statically linked crate dependencies are covered only as
  an explicit approximation (see Part B).

## Part B — corresponding-source materials (identified and pinned, not offered)

`Config/SharpLibvipsSourceMaterials.json` pins, by exact URL, size and SHA-256:

- the 9 build-recipe files of the pinned sharp-libvips commit (build.sh,
  build/posix.sh, versions.properties, the darwin-arm64v8 toolchain and meson
  files, THIRD-PARTY-NOTICES.md, the build scripts' Apache-2.0 LICENSE, the
  npm package manifest and populate-npm-workspace.sh);
- the 4 patches the recipe applies (two revision-pinned gists, one
  GitHub-generated commit patch, one **mutable** pull-request patch — its
  digest was re-verified on 09/09/2026);
- the 28 upstream source archives named by the recipe, each with the full
  upstream revision the version resolves to and how that was established
  (the 13 changed versions were resolved with `git ls-remote`; unchanged
  revision evidence is retained, including the short mozjpeg hash `0826579`).
  The existing HTTPS acquisition tool fetched and verified all 41 replacement
  inputs (161,964,360 bytes); this does not assert a reproducible rebuild.

Every inline `sed`/`cargo`/`meson` modification the recipe performs is listed
in `buildTimeModifications` with its `build/posix.sh` line number.

`scripts/prepare-libvips-source-materials.mjs acquire <manifest> <destination>`
downloads only those URLs over HTTPS, following at most the manifest's redirect
budget and only to hosts each item explicitly allows, streams every byte through
a counter and SHA-256, aborts as soon as the size can no longer match, assembles
everything in a private staging directory and renames it into place only after
every item and the inventory (`INVENTORY.json`, `SHA256SUMS`) are written. A
partial failure removes the staging directory and leaves no destination. The
destination must be named `sharp-libvips-1.3.3-corresponding-source-materials`
and must not already exist. `verify <manifest> <destination>` re-hashes an
existing destination and fails on any drift, extra file, or inventory
inconsistency. Archives are kept opaque: nothing is extracted, configured,
built or run. A `--transport local-fixture:<dir>` mode exists for hermetic tests
only; its output is labelled `"authoritative": false` in the inventory.

Recommended location: `build/libvips-corresponding-source/` inside the ignored
build directory. Nothing under `build/` is tracked.

### Rust crates linked through librsvg (observed compilation bound; incorporation unverified)

The current 1.3.3 record binds librsvg 2.62.91 and 161 registry crate
archives (12,447,806 bytes). Cargo.lock contains 359 packages (SHA-256
`fcca33feb66f75fb02199902cee0a5072cb491020d655463dfeffffc9d626941`),
of which 340 are reachable without target/feature filtering. Its replacement
build log records 159 registry crates plus two
workspace packages compiling; `rustc_version` and `semver` remain retained
approximation-only inputs. The exact Cargo.lock, graph counts, per-crate
observations, build run and job, and tool-version observations are bound in
`Config/SharpLibvipsRustProvenance.json`. The conservative set is those observed
events plus the two retained lock-reachable inputs, not a rerun of Cargo feature
unification or target selection. The npm attestation binds the tarball to
[run 32944387969, job 98102057009](https://github.com/lovell/sharp-libvips/actions/runs/32944387969/job/98102057009)
of 26/08/2026; the raw log retained on 09/09/2026 is 1,298,996 bytes / 13,212
lines, SHA-256 `ab557d76a232c122ad995e62ee189bf387ae629a64c457d7031a410223a74aea`.
None proves incorporation into the shipped 8.18.6 dylib. The current cache and
commands below use 1.3.3.

#### Historical 1.3.2 evidence — reviewed 05–06/09/2026

The following retained account describes the superseded 1.3.2 snapshot only.
References in this historical account to the lockfile and manifest mean their
1.3.2 versions, not the current files. Its run, hashes, graph counts and tool
versions are not carried forward as proof for the replacement 1.3.3 binary.

librsvg 2.62.90 is Rust. Its tarball carries `Cargo.lock` (357 package entries,
sha256 `e91fcc90…`) but no vendored crates; the recipe edits the workspace
manifests (drops the `image` features `gif`/`webp` and the `cairo-rs` features
`pdf`/`ps`), runs `cargo update --workspace`, and meson then runs
`cargo cbuild --locked -p librsvg-c --library-type staticlib` in release mode
with fat LTO, codegen-units 1, opt-level z (`meson/cargo_wrapper.py`). No
`avif` or `pixbuf` feature is enabled because the recipe builds neither dav1d nor
gdk-pixbuf. The workspace package built from `rsvg/Cargo.toml` inside the
`librsvg-2.62.90` archive is `librsvg 2.63.0-beta.0`; `librsvg-c` and the Meson
project version are `2.62.90` (a metadata fact, not a version change).

`Config/SharpLibvipsRustProvenance.json` distinguishes five categories that
must not be equated, each machine-checked:

| Category | Count | Status |
| --- | --- | --- |
| Packages listed in the retained `Cargo.lock` | 357 | exact |
| Reachable from `librsvg-c` in the lockfile graph (target/feature-agnostic) | 338 | exact superset |
| Resolved for `aarch64-apple-darwin` with the recipe's feature edits (simplified resolver over each crate's checksum-verified `Cargo.toml`; dev-dependencies excluded) | 161 = 159 crates.io crates + 2 workspace members | approximation |
| Observed compiling in the retained historical job log (librsvg phase) | 159 = 157 crates.io crates + 2 workspace members | **observed** |
| Incorporated into the shipped dylib (after fat LTO and `-dead_strip`) | — | **unverified** |

Historical evidence bindings:

- The npm provenance attestation (SLSA v1, retrieved 05/09/2026) binds the
  shipped tarball — sha512 equal to the `integrity` pinned in
  `VendorRuntime/package-lock.json` — to GitHub Actions run 28432216836,
  attempt 1, of commit `4da6d14c…` at `refs/tags/v1.3.2`.
- That run's job `build-darwin-arm64v8` (id 84249528353, `macos-15`,
  08:52:28–09:17:03 UTC on 30/06/2026) is the build that produced the dylib.
- Its complete job log was retrieved on 05/09/2026 (23:53:59 UTC) by the Codex
  review lane with normally configured GitHub CLI authentication (GET only)
  and retained as owner-private evidence: 944,166 bytes, 10,027 lines, raw
  sha256 `b7b3362b…`, sealed by a SHA256SUMS manifest (`74c16427…`). The log is
  not committed to source; the manifest binds its digest, line count and the
  per-crate observation.
- In the librsvg phase of that log (lines 8721–8985) 157 registry crates and
  the two workspace packages were observed compiling; every observed registry
  crate is one of the 159 approximated crates, and each such item now carries
  `provenanceStatus: "compiled-per-build-log"` with its log line and timestamp.
  `rustc_version 0.4.1` and `semver 1.0.28` were not observed; they stay
  `resolved-approximation` and are neither removed nor asserted excluded from
  every intermediate artefact. The separate cargo-c installation phase (356
  compile lines) is tool bootstrap, not part of the librsvg dependency set.
- Observed tool versions (version strings, not binary digests): rustc
  `1.98.0-nightly (096694416 2026-06-29)` — the short revision is recorded as
  reported and not expanded — cargo 1.98.0, cargo-c `0.10.23+cargo-0.97.1`,
  Meson 1.11.1, Apple clang 17.0.0 (clang-1700.0.13.5), ld64 1167.5,
  pkg-config 2.5.1. The workspace update printed "Locking 0 packages" and removed
  `color_quant 1.1.0`, `gif 0.14.2`, `image-webp 0.2.4`, matching the documented
  Cargo semantics relied on earlier.

What the log does **not** establish: it is an observed compile-event set, not
the resolved feature graph and not a linkage map. No truncation or cache-hit
markers were found, which is not proof that silent reuse was impossible, and
nothing in it shows which crate code survived fat LTO and dead-stripping into
`libvips-cpp.8.18.3.dylib`. `incorporatedIntoShippedBinary` therefore stays
`unverified`, and the tool refuses a manifest that promotes it.

#### Current 1.3.3 acquisition and notices

`scripts/prepare-libvips-source-materials.mjs acquire Config/SharpLibvipsRustProvenance.json
<parent>/sharp-libvips-1.3.3-rust-crate-materials` acquires the 161 `.crate`
files (≈12 MB, HTTPS to `static.crates.io` only, no redirects), verifies each
against its checksum, reads only the manifest-named licence members through a
bounded tar reader, and renders a deterministic `RUST_CRATE_NOTICES.md` (table
of crates with their provenance status, the crates without licence text, and
every licence text) next to `INVENTORY.json`/`SHA256SUMS`. The reader validates
the complete ustar framing before anything is published: whole 512-byte
blocks only, header checksum and `ustar` magic, complete payload and zero
padding, the two zero end-of-archive blocks, and nothing but zero padding after
them; links, traversal, foreign roots, non-plain entries, oversized output and
excess entries fail closed. (A review on 06/09/2026 found that the earlier
reader accepted a gzip whose only decompressed byte was `0x78` when no notice
members were declared; that defect is fixed and pinned by regression tests
bound to the sealed diagnostic fixtures.) `verify` re-validates the archives
before trusting any inventory metadata. The inventory carries
`historicalBuildProvenance` verbatim from the manifest.

The exact current licence-expression counts are recorded in
`Config/SharpLibvipsRustProvenance.json` (`licenseExpressionSummary`).
MPL-2.0 crates carry a source-availability obligation for
their own files (the pinned `.crate` archives are that source) and Unicode-3.0
crates carry notice requirements; both are owner/legal items.

#### Crates whose archive carries no licence text

Six crates — all observed compiling — carry no licence member in their `.crate`.
`Config/SharpLibvipsRustNoticeMaterials.json` records, for each, the exact
upstream revision the archive was packaged from, the evidence tying the archive
to it, and either exact external material under
`Resources/ThirdPartyLicenses/sharp-libvips-1.3.3/rust/` (labelled external —
never an archive member) or one precise unresolved record:

| Crate | Connection to the packaged revision | Material |
| --- | --- | --- |
| `mutants 0.0.4` (MIT) | `.cargo_vcs_info.json` → `sourcefrog/cargo-mutants` @ `14011d08…`, `mutants_attrs`; `src/lib.rs` byte-identical | **established, external:** repository `LICENSE` at that commit ("Copyright (c) 2021 Martin Pool") |
| `selectors 0.40.0` (MPL-2.0) | `.cargo_vcs_info.json` → `servo/stylo` @ `67faaab3…`, `selectors`; `Cargo.toml.orig`, `lib.rs` and `matching.rs` byte-identical to their upstream counterparts | **established:** archive-contained per-file MPL-2.0 header (all 16 `.rs` members; no package-specific copyright statement inferred) plus **external** MPL-2.0 text from SPDX 3.28.0 (commit `c4a7237e…`); the stylo README at that commit states "Stylo is licensed under MPL 2.0" |
| `block 0.1.6` (MIT) | tag `0.1.6` = `SSheldon/rust-block` @ `47178790…`; README byte-identical | **unresolved:** no licence text, copyright line or licence statement in the archive or the tagged tree; only `license = "MIT"` and `authors = ["Steven Sheldon"]` |
| `malloc_buf 0.0.6` (MIT) | tag `0.0.6` = `SSheldon/malloc_buf` @ `a7811e5f…` | **unresolved** (as above) |
| `objc-foundation 0.1.1` (MIT) | tag `0.1.1` = `SSheldon/rust-objc-foundation` @ `0c157a59…` | **unresolved** (as above) |
| `objc_id 0.1.1` (MIT) | tag `0.1.1` = `SSheldon/rust-objc-id` @ `6527cdf2…`; README byte-identical | **unresolved** (as above) |

For the four unresolved crates a generic MIT text would need a copyright line
the upstream never published for that version, so none is asserted; the
record names the checks performed and the single fallback used (source-file
headers at the tagged revision, none present). Their disposition is an
owner/legal decision.

`prepare-libvips-source-materials.mjs acquire|verify … --notice-materials
Config/SharpLibvipsRustNoticeMaterials.json` binds that manifest to the crate
manifest being processed (it must name it as `crateManifest`), re-verifies every
external text (tracked bytes, size, digest, exact upstream bytes plus one LF,
commit-pinned origin at the connected repository and revision, SPDX text only
for the licence the archive itself designates), re-verifies the
archive-contained `selectors` notice against the `.crate` member's digest and
leading text, refuses anything unbound beside the tracked external files, and
then renders `RUST_CRATE_NOTICES.md` with a "Crates whose archive carries no
licence text" section that shows the two external texts (labelled external,
never as archive members) and the four unresolved records with their exact
status, missing evidence, checks and fallback. `INVENTORY.json` records the
binding (`noticeMaterials`). Without the option the rendering is byte-identical
to the earlier tool; a destination rendered one way is refused by a
verification run the other way, so an incomplete acquisition is never
relabelled as complete.

### Delivery staging (private; not a source offer)

`scripts/stage-libvips-delivery-materials.mjs stage Config/ThirdPartyBinaryProvenance.json
<verified sharp-libvips-1.3.3-corresponding-source-materials> <verified
sharp-libvips-1.3.3-rust-crate-materials> <private parent>/sharp-libvips-1.3.3-delivery-materials`
assembles one deterministic delivery-material directory from inputs that pass
their own current manifest-bound verification (the upstream directory against
the corresponding-source manifest, the crate directory against the crate
manifest **with** the notice-materials manifest): the 41 upstream items and the
161 `.crate` archives with their `INVENTORY.json`/`SHA256SUMS` verbatim, the
complete `RUST_CRATE_NOTICES.md`, the two external notice texts under
`notices/rust-external/` with the notice-materials manifest as their
provenance, the four tracked manifests under `manifests/`,
`docs/THIRD_PARTY_ACKNOWLEDGEMENTS.md` under `notices/`, and a generated
`DELIVERY_INVENTORY.json`, `SHA256SUMS` and concise factual
`DELIVERY_STATUS.md` (preparation set; four notices unresolved; compilation
observed; dylib incorporation unverified; no legal clearance or public source
offer inferred). Every file is re-read and re-hashed before the staging
directory is renamed into place; a failure removes only that staging directory.
The destination must be a new directory under a private canonical parent,
named as the provenance record's `deliveryMaterials.outputDirectoryName`;
existing `local-fixture`/non-authoritative flags are carried forward
truthfully. `verify` re-checks a published set against the tracked manifests
(never against the copies inside it) and rejects deletion, substitution, extra
files, a changed manifest, a truncated archive, links and any edit to the
generated files. Two independent stagings from identical inputs are
byte-identical. No public ZIP/TAR asset, hosting URL or offer mechanism is
created; the nine-asset public contract is unchanged.

### Explicitly unretained or unverifiable

Recorded in the manifests' `unretained` arrays; summarised:

1. **Compile-log coverage** — the retained log gives observed compile events
   (159 registry crates + 2 workspace packages); it is not the resolved feature
   graph, and the absence of truncation/cache markers is not proof that silent
   reuse was impossible. The resolver approximation was cross-checked against
   it (every observed crate is in the set; two set members were not observed).
2. **Rust toolchain.** rustup `nightly` and `cargo install cargo-c --locked`
   at build time; compiler revision and cargo-c version unpinned.
3. **Apple toolchain and system frameworks** of the GitHub Actions macOS runner
   (Xcode clang, SDK, Homebrew pkg-config, Quartz, CoreText): unrecorded.
4. **libnsgif upstream revision**: not recorded by libvips (see above).
5. **Pull-request patch mutability** (libultrahdr #383).
6. **Forge-generated archives** (GitHub/GitLab `archive/` tarballs) are not
   guaranteed byte-stable by those forges.
7. **THIRD-PARTY-NOTICES.md from `main`**: the recipe fetches the licence table
   from the moving `main` branch at build time; the shipped table was verified
   identical to the pinned commit's table, but the build-time origin itself is
   not reproducible.
8. **No rebuild attempted.** Nothing proves that re-running the recipe
   reproduces `libvips-cpp.8.18.6.dylib`, or that a relinked library can be
   substituted under the app's Developer ID signature and hardened runtime.
9. **Binary incorporation.** Fat LTO and dead-stripping mean the crates whose
   code survives in the dylib are a subset of the compiled set; no binary
   inspection was performed, and strings alone would not prove inclusion.

Because of items 8 and 9 (and the four unresolved crate notices),
`Config/ThirdPartyBinaryProvenance.json` keeps `corresponding-source` and
`relinking-and-installation-information` **open**.

## Packaging integration

The current nine-asset public package contract is unchanged. The notice
generation seam is wired; the delivery-set distribution remains Codex/owner
work:

- **Notice generation (wired).** The verified crate materials are an internal
  build input cached at the literal checkout-local path
  `build/third-party-notice-materials/sharp-libvips-1.3.3-rust-crate-materials`
  (the crate manifest's `outputDirectoryName`, bound by
  `scripts/prepare-third-party-notice-materials.mjs`). Only the clean source
  bootstrap (`scripts/bootstrap-source-checkout.sh`, after the complete runtime
  verification) prepares it: `prepare-third-party-notice-materials.mjs prepare`
  creates the private (0700) containing directory, refuses an unsafe
  pre-existing path instead of chmod-following it, reuses an existing cache
  only after complete verification, fails a stale or invalid cache with its
  exact path and recovery instruction (nothing is overwritten or deleted), and
  acquires an absent cache over HTTPS by running the existing
  `prepare-libvips-source-materials.mjs acquire … --transport https --notice-materials Config/SharpLibvipsRustNoticeMaterials.json`
  in a child process that inherits no environment. `scripts/build-app.sh`
  (before any native compilation), `scripts/verify-release.sh`,
  `scripts/prepare-public-release-assets.sh` and
  `scripts/verify-public-distribution.sh` each run
  `prepare-third-party-notice-materials.mjs verify` with the pinned Node, which
  re-verifies every byte against the tracked manifests and requires the
  recorded acquisition to be transport `https` and authoritative (fixture
  output is refused for the production cache), then pass
  `--rust-crate-materials "$RUST_CRATE_MATERIALS"` to the generator, which
  re-verifies at consumption. None of them acquires, downloads or falls back
  to unbound notices. `scripts/verify-two-root-reproducibility.sh` verifies the
  source cache, gives each clean clone an independent byte-preserving copy at
  the identical relative path and verifies it with the clone's own pinned Node
  before either offline build. The cache never enters the compiler-only source
  snapshot, the app runtime, the runtime inventory or a public asset, and its
  presence is not a corresponding-source offer.
- **Delivery set.** `scripts/stage-libvips-delivery-materials.mjs` produces the
  verified `sharp-libvips-1.3.3-delivery-materials/` directory described above;
  deterministic archive packaging (a single ZIP/TAR of that directory) is one
  bounded further step once the owner chooses a distribution mechanism.

Two options for distribution, either of which is a Codex-integrated delta, not
something this record enables on its own:

- **Option A — separate persistent artefact.** Publish the verified
  `sharp-libvips-1.3.3-delivery-materials/` set (the
  `sharp-libvips-1.3.3-corresponding-source-materials/` upstream archives plus
  recipe, patches, `INVENTORY.json`, `SHA256SUMS`; the
  `sharp-libvips-1.3.3-rust-crate-materials/` `.crate` files plus the complete
  `RUST_CRATE_NOTICES.md`, `INVENTORY.json`, `SHA256SUMS` with the
  observed-compilation status carried in the inventory; the external notice
  materials with their provenance manifest; the tracked manifests;
  `DELIVERY_INVENTORY.json`, `SHA256SUMS`, `DELIVERY_STATUS.md`) as a distinct,
  versioned release asset or a stable download location, and have the beta's
  installation guide and the generated notices name that location together
  with the `DELIVERY_INVENTORY.json` SHA-256. This keeps the app package
  unchanged and makes the material available for as long as the location is
  maintained. Delta: one new asset outside the nine, one documented URL/digest
  pair, one owner commitment to keep it available. Exact output counts and
  bytes must come from a fresh staging against the current manifests; the
  historical 1.3.2 staging had 215 files and 175,873,353 bytes and does not
  qualify this replacement set.
- **Option B — ship the inventory, host the archives.** Include only
  `DELIVERY_INVENTORY.json`/`SHA256SUMS` inside the
  app's notices bundle and host the set as in Option A. Delta: one additional
  file in the notices resource, plus Option A's hosting commitment.

In both options the Rust crate set includes the observed compilation set plus
the two retained approximation-only inputs;
which crate code the shipped dylib actually incorporates remains unverified
unless the owner chooses a controlled, pinned replacement build in a
separately approved lane. Neither is performed here.

## Questions for owner/legal review

1. Does the owner intend to rely on LGPL-3.0 §4(d)(1) (shared-library
   mechanism with a user-replaceable library) for `libvips-cpp.8.18.6.dylib`
   under Developer ID signing with hardened runtime? If a user replaces the
   dylib the signature breaks; whether §4(e) Installation Information or GPL-3.0
   §6 applies to this distribution, and whether the answer differs for a
   manual-install beta versus a notarised stable build, needs a legal position,
   not a technical one.
2. How will corresponding source be made available — a written offer, a hosted
   artefact (Option A/B above), or both — and for how long?
3. Are the FTL and IJG acknowledgement statements to be added to the
   installation guide / about text, and where?
4. Is the upstream README's cairo "MPL 2.0" entry to be reported to
   `lovell/sharp-libvips` (the README invites error reports)?
5. Is observed compilation (159 + 2 crates from the retained log) plus the
   two approximation-only crates an acceptable notice basis for a beta, given
   that incorporation into the dylib is unverified, or is a controlled pinned
   replacement build (separately approved; changes runtime bytes) preferred?
   How should the four unresolved Steven Sheldon crate notices be treated?
6. How are the MPL-2.0 crate sources and Unicode-3.0 notices to be made
   available/presented, and where do the FTL and IJG acknowledgements in
   `docs/THIRD_PARTY_ACKNOWLEDGEMENTS.md` go (Codex integration)?

## Reproduction pointers (not executed here)

The complete recipe is the pinned `build.sh` + `build/posix.sh`; the darwin
flavour requires macOS with Xcode clang, Homebrew pkg-config, meson, cmake,
nasm and a Rust toolchain, then `./build.sh darwin-arm64v8`. Because of the
unretained items above, a rebuild is expected to produce a functionally
equivalent but not byte-identical dylib. No rebuild, relink or install was
performed for this record.
