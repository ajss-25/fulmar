# Third-party acknowledgements required in accompanying documentation

Some licences bound for the redistributed `@img/sharp-libvips-darwin-arm64`
1.3.3 combined binary (`lib/libvips-cpp.8.18.6.dylib`) require a statement in
the documentation that accompanies the executable, over and above the licence
text itself. This file holds the exact wording so that it can be placed
verbatim. The statements are bound in `Config/ThirdPartyBinaryProvenance.json`
(`deliveryMaterials.accompanyingDocumentation`, each tied to the tracked
notice material it derives from) and `scripts/generate-third-party-notices.mjs`
verifies that this file still carries them verbatim and renders them into the
generated `THIRD_PARTY_NOTICES.md` (section "Acknowledgements required in
accompanying documentation") whenever it runs with `--rust-crate-materials`;
`scripts/stage-libvips-delivery-materials.mjs` copies this file into the
delivery staging set. **Placing the wording in the installation guide or about
text remains Codex integration work and an owner decision**; neither this file
nor its rendering into the notices is legal clearance.

Every required statement below is derived from a licence text tracked under
`Resources/ThirdPartyLicenses/sharp-libvips-1.3.2/` and digest-bound in
`Config/ThirdPartyBinaryProvenance.json`. These FreeType, mozjpeg and cairo
versions and exact archive notice bytes are unchanged in 1.3.3, so their
existing material paths are deliberately retained.

## FreeType (FTL) — required credit

Source: `freetype-2.14.3-FTL.TXT` (The FreeType Project LICENSE, 2006-Jan-27),
section 2 "Redistribution", and its preferred credit wording. The year is the
copyright year of the FreeType 2.14.3 sources actually bundled
(`include/freetype/freetype.h` in the pinned `freetype-VER-2-14-3.tar.gz`:
"Copyright (C) 1996-2026").

> Portions of this software are copyright © 2026 The FreeType Project
> (https://freetype.org). All rights reserved.

## Independent JPEG Group (IJG, via mozjpeg) — required statement

Source: `mozjpeg-0826579-README.ijg`, LEGAL ISSUES, condition (2): "If only
executable code is distributed, then the accompanying documentation must state
that …".

> This software is based in part on the work of the Independent JPEG Group.

The IJG text also names the copyright holders of the libjpeg code mozjpeg is
based on ("This software is copyright (C) 1991-2020, Thomas G. Lane, Guido
Vollbeding"); the full text is embedded in the generated notices.

## cairo — licence label versus retained texts

The upstream sharp-libvips licence table (the shipped `README.md`, tracked
digest `47083f1a…`) labels cairo as "Mozilla Public License 2.0". The cairo
1.18.4 sources actually bundled are offered under **either the GNU LGPL 2.1 or
the Mozilla Public License 1.1** (`cairo-1.18.4-COPYING`), and both real texts
are tracked and embedded (`cairo-1.18.4-COPYING-LGPL-2.1`,
`cairo-1.18.4-COPYING-MPL-1.1`). Documentation should describe cairo by the
retained texts, not by the upstream label. Whether to report the label upstream
is an owner decision (see `docs/LIBVIPS_CORRESPONDING_SOURCE.md`).

## Other notice-bearing terms (no extra sentence required, listed for completeness)

- libaom and libwebp ship additional patent-grant files; both are tracked and
  embedded.
- highway (Apache-2.0 or BSD-3-Clause) and libultrahdr (MIT or Apache-2.0) are
  dual-licensed; the upstream table names the BSD-3-Clause and MIT options
  respectively. Their combined licence files are tracked and embedded.
- Rust crates statically linked through librsvg: see
  `Config/SharpLibvipsRustProvenance.json` and the generated
  `RUST_CRATE_NOTICES.md`. 159 of the 161 crates were observed compiling in the
  retained historical build log (two remain approximation-only); which crate
  code the shipped dylib incorporates is unverified. They include MPL-2.0 and
  Unicode-3.0 crates whose terms carry their own notice and source-availability
  requirements. Six crates carry no licence text in their archive:
  `Config/SharpLibvipsRustNoticeMaterials.json` holds exact external material
  for `mutants 0.0.4` (MIT, "Copyright (c) 2021 Martin Pool") and
  `selectors 0.40.0` (MPL-2.0, per-file headers plus the SPDX text), and
  precise unresolved records for `block 0.1.6`, `malloc_buf 0.0.6`,
  `objc-foundation 0.1.1` and `objc_id 0.1.1`, whose upstream published no
  licence text or copyright line for those versions. When
  `scripts/prepare-libvips-source-materials.mjs` runs with
  `--notice-materials Config/SharpLibvipsRustNoticeMaterials.json`, the
  rendered `RUST_CRATE_NOTICES.md` carries the two external texts (labelled
  external, never as archive members) and the four unresolved records with
  their exact status; the generated `THIRD_PARTY_NOTICES.md` carries the same
  when generated with `--rust-crate-materials`. The four unresolved notices
  remain an owner/legal decision.
