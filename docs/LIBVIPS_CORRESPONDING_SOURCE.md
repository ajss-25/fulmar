# libvips combined binary — exact notices and corresponding-source materials

This document records what the repository now binds for the redistributed
`@img/sharp-libvips-darwin-arm64` 1.3.2 combined binary
(`lib/libvips-cpp.8.18.3.dylib`), how that material is verified, and what it
does **not** establish. It is a material record, not legal advice, not a
corresponding-source offer, and not evidence that any beta candidate passed the
`thirdPartyBinaryLicenseMaterials` gate in `docs/PUBLIC_BETA_RELEASE_CONTRACT.md`.
Nothing here changes the first-party MIT licence of Fulmar's own source, and
nothing here describes the third-party binary as MIT.

## What the binary is

The npm tarball (integrity and per-file digests in
`Config/ThirdPartyBinaryProvenance.json`) was produced by the
`lovell/sharp-libvips` repository at tag `v1.3.2`, commit
`4da6d14c0d59866adfb9d8cf52bcaa53846dc4f6` (the npm `gitHead`), by running
`build.sh darwin-arm64v8`, which sources `versions.properties` and
`build/posix.sh`. That recipe downloads 28 upstream source archives, applies
four patches and a number of inline `sed` edits, builds every dependency as a
static library, links libvips itself statically into `libvips-cpp`, and packs
the single dylib plus `versions.json` and a licence table into the tarball.
The shipped `README.md` is that licence table under a package heading.

The README names 29 libraries; `versions.json` pins 28 versions. The difference
is `libnsgif`: it is not downloaded or versioned by the recipe because libvips
vendors it at `libvips/foreign/libnsgif` (copied from
`git://git.netsurf-browser.org/libnsgif.git` by `update.sh`, "Last updated
22 Jan 2023"). Its source is the libvips 8.18.3 archive. Neither the libvips
tree nor the recipe records an upstream libnsgif release or commit, so **no
libnsgif version is asserted anywhere in this repository**.

## Part A — exact per-component notices (bound)

`Config/ThirdPartyBinaryProvenance.json` → `components[0].componentNotices`
holds one record per README library (29), each naming the exact pinned
version (or `null` for libnsgif, with the resolution above), the upstream
repository, the full 40-hex revision the version resolves to and how that
resolution was obtained, and one or more notice materials. Every material is a
file under `Resources/ThirdPartyLicenses/sharp-libvips-1.3.2/` (libvips reuses
the already-tracked `Resources/ThirdPartyLicenses/libvips-8.18.3-LICENSE`),
stored as the exact upstream bytes plus one terminal LF
(`append-terminal-lf-v1`), with the raw upstream SHA-256, the tracked SHA-256,
the immutable upstream origin (commit-pinned forge URL, or the release archive
where no forge raw URL exists, as for libaom), and the archive member and
archive SHA-256 the bytes were verified against. On 05/09/2026 every tracked
text was compared byte-for-byte against both the pinned release archive member
and the file at the resolved upstream revision; all 35 matched.

`scripts/generate-third-party-notices.mjs` follows the
`componentNotices: { manifest, component }` reference in the sharp-libvips
entry of `Config/ThirdPartyLicenseOverrides.json`, re-verifies every material
under the same bounded, alias-free, digest-checked contract as package-level
tracked texts, requires that every manifest library and every pinned version is
covered exactly once, and appends a deterministic section "Exact per-component
notices for redistributed binaries" to the generated notices. Identical texts
(pango/proxy-libintl; librsvg/libvips) are embedded once and cross-referenced.

Facts surfaced by the exact texts that the upstream README table does not show,
returned for owner/legal review rather than resolved here:

- cairo is dual-licensed LGPL-2.1 / MPL-1.1; the README says "Mozilla Public
  License 2.0". Both real texts are bound.
- freetype's FTL (§2) and mozjpeg's IJG terms (README.ijg) each require a
  specific acknowledgement in accompanying documentation ("Portions of this
  software are copyright © The FreeType Project (www.freetype.org)" and "this
  software is based in part on the work of the Independent JPEG Group").
  Binding the licence text does not by itself place those statements.
- highway (Apache-2.0 / BSD-3) and libultrahdr (MIT / Apache-2.0) are
  dual-licensed; the README names the BSD-3 and MIT options respectively.
- libaom and libwebp carry additional patent-grant files (bound).
- librsvg is Rust. Its statically linked crate dependencies are **not** covered
  (see Part B).

## Part B — corresponding-source materials (identified and pinned, not offered)

`Config/SharpLibvipsSourceMaterials.json` pins, by exact URL, size and SHA-256:

- the 9 build-recipe files of the pinned sharp-libvips commit (build.sh,
  build/posix.sh, versions.properties, the darwin-arm64v8 toolchain and meson
  files, THIRD-PARTY-NOTICES.md, the build scripts' Apache-2.0 LICENSE, the
  npm package manifest and populate-npm-workspace.sh);
- the 4 patches the recipe applies (two revision-pinned gists, one
  GitHub-generated commit patch, one **mutable** pull-request patch — its
  digest is what was observed on 05/09/2026);
- the 28 upstream source archives named by the recipe, each with the full
  upstream revision the version resolves to and how that was established
  (tag peeled with `git ls-remote`; GitHub codeload redirect target or GitLab
  commits API for the three short hashes `0826579`, `d01a94b`, `1acdbed`).
  Four GNOME tarballs were additionally checked against the published
  `.sha256sum` files.

Every inline `sed`/`cargo`/`meson` modification the recipe performs is listed
in `buildTimeModifications` with its `build/posix.sh` line number.

`scripts/prepare-libvips-source-materials.mjs acquire <manifest> <destination>`
downloads only those URLs over HTTPS, following at most the manifest's redirect
budget and only to hosts each item explicitly allows, streams every byte through
a counter and SHA-256, aborts as soon as the size can no longer match, assembles
everything in a private staging directory and renames it into place only after
every item and the inventory (`INVENTORY.json`, `SHA256SUMS`) are written. A
partial failure removes the staging directory and leaves no destination. The
destination must be named `sharp-libvips-1.3.2-corresponding-source-materials`
and must not already exist. `verify <manifest> <destination>` re-hashes an
existing destination and fails on any drift, extra file, or inventory
inconsistency. Archives are kept opaque: nothing is extracted, configured,
built or run. A `--transport local-fixture:<dir>` mode exists for hermetic tests
only; its output is labelled `"authoritative": false` in the inventory.

Recommended location: `build/libvips-corresponding-source/` inside the ignored
build directory. Nothing under `build/` is tracked.

### Explicitly unretained or unverifiable

Recorded in the manifest's `unretained` array; summarised:

1. **Rust crates (librsvg).** The librsvg 2.62.90 tarball ships `Cargo.lock`
   (357 package entries) but no vendored crates; the recipe runs
   `cargo update --workspace` and Cargo fetches crate sources from crates.io at
   build time. The exact crate set statically linked into `libvips-cpp`, its
   sources and its MIT/Apache/BSD notices are not identified here.
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
   reproduces `libvips-cpp.8.18.3.dylib`, or that a relinked library can be
   substituted under the app's Developer ID signature and hardened runtime.

Because of items 1 and 8, `Config/ThirdPartyBinaryProvenance.json` keeps
`corresponding-source` and `relinking-and-installation-information` **open**.

## Proposed packaging integration (for Codex; not applied)

The current nine-asset public package contract is unchanged. Two options,
either of which is a Codex-integrated delta, not something this record enables
on its own:

- **Option A — separate persistent artefact.** Publish the verified
  `sharp-libvips-1.3.2-corresponding-source-materials/` directory (≈162 MB
  of upstream archives plus recipe, patches, `INVENTORY.json`, `SHA256SUMS`)
  as a distinct, versioned release asset or a stable download location, and
  have the beta's installation guide and the generated notices name that
  location together with the `INVENTORY.json` SHA-256. This keeps the app
  package unchanged and makes the material available for as long as the
  location is maintained. Delta: one new asset outside the nine, one
  documented URL/digest pair, one owner commitment to keep it available.
- **Option B — ship the inventory, host the archives.** Include only
  `INVENTORY.json`/`SHA256SUMS` (a few kB) inside the app's notices bundle and
  host the archives as in Option A. Delta: one additional file in the notices
  resource, plus Option A's hosting commitment.

In both options the Rust crate gap (unretained item 1) remains until either
the crate set is reconstructed from the pinned `Cargo.lock` and pinned as
further manifest items, or the owner decides to source the libvips binary
differently.

## Questions for owner/legal review

1. Does the owner intend to rely on LGPL-3.0 §4(d)(1) (shared-library
   mechanism with a user-replaceable library) for `libvips-cpp.8.18.3.dylib`
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
5. Is the librsvg Rust crate gap acceptable for the beta, to be closed by
   crate-set reconstruction, or a reason to build/sourced libvips differently?

## Reproduction pointers (not executed here)

The complete recipe is the pinned `build.sh` + `build/posix.sh`; the darwin
flavour requires macOS with Xcode clang, Homebrew pkg-config, meson, cmake,
nasm and a Rust toolchain, then `./build.sh darwin-arm64v8`. Because of the
unretained items above, a rebuild is expected to produce a functionally
equivalent but not byte-identical dylib. No rebuild, relink or install was
performed for this record.
