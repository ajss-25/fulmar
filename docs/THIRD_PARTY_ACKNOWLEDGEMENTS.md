# Third-party acknowledgements required in accompanying documentation

Some licences bound for the redistributed `@img/sharp-libvips-darwin-arm64`
1.3.2 combined binary (`lib/libvips-cpp.8.18.3.dylib`) require a statement in
the documentation that accompanies the executable, over and above the licence
text itself. This file holds the exact wording so that it can be placed
verbatim. **Placing it is Codex integration work** (installation guide, about
text, or the generated notices bundle — an owner decision); the existence of
this file does not by itself satisfy those terms and is not legal clearance.

Every statement below is derived from a licence text tracked under
`Resources/ThirdPartyLicenses/sharp-libvips-1.3.2/` and digest-bound in
`Config/ThirdPartyBinaryProvenance.json`.

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
  `RUST_CRATE_NOTICES.md`. Those are an explicitly partial approximation of the
  historical build; they include MPL-2.0 and Unicode-3.0 crates whose terms
  carry their own notice and source-availability requirements.
