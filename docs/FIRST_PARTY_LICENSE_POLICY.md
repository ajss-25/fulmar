# First-party licence policy

The repository owner selected the MIT License for Fulmar's original source on
2026-09-02. The release tooling does not make that legal decision; it enforces that the selected terms,
their metadata, the signed app, the SBOM, and public release assets cannot drift apart.

The selected source state is top-level `LICENSE` SHA-256
`599a408a33e7d465ff51ce08f1b18c1799dae3e1af09694af999c85b519260dc`, with
SPDX expression `MIT` and display name `MIT License` in
`Config/ProjectLicense.json`. Third-party code and artwork remain governed by their
own terms and separate provenance/trademark review.

The source tree has exactly three states:

1. Neither top-level `LICENSE` nor `Config/ProjectLicense.json` exists. Private builds
   are allowed, the app does not bundle a first-party licence, and the application plus
   all six Fulmar DSH plugins are recorded as `Fulmar unlicensed private code` in the
   SBOM. Public packaging fails.
2. Both files exist and validate. `LICENSE` is copied byte-for-byte into the app before
   signing; its exact SHA-256 and owner-selected SPDX expression are bound to the SBOM
   application and every Fulmar DSH plugin. Public packaging may proceed to the other
   independent legal, signing, notarization, clean-Mac, and provider gates.
3. Only one file exists, or either file is unsafe or inconsistent. Every production
   build and release verification fails. There is no environment-variable bypass.

The owner-selected metadata is a strict v1 JSON object with exactly these fields:

```json
{
  "schemaVersion": 1,
  "licenseFile": "LICENSE",
  "spdxExpression": "MIT",
  "displayName": "MIT License",
  "licenseSHA256": "599a408a33e7d465ff51ce08f1b18c1799dae3e1af09694af999c85b519260dc"
}
```

The authoritative bounded schema is
`scripts/first-party-license-v1.schema.json`. Licence identifiers and `WITH`
exceptions must also occur in the digest-pinned, deliberately reviewed
`scripts/first-party-spdx-v1.json` subset of SPDX License List 3.28.0. Custom terms
must use the SPDX `LicenseRef-...` or `DocumentRef-...:LicenseRef-...` form; an
identifier-shaped invented licence is rejected. Expanding the supported subset is a
reviewed source change, not an environment override. The policy rejects symbolic links,
hard links, non-regular files, group/world-writable inputs, non-owner inputs, invalid
UTF-8, empty or oversized terms, malformed or duplicate metadata fields, invalid or
oversized SPDX grammar, and a digest mismatch. The top-level terms are limited to
1 MiB and metadata to 16 KiB.

The public asset tool requires the selected state and emits exactly nine files:
the app archive, its ordinary-user checksum sidecar, dSYMs, release manifest, the
manifest-bound static-security summary, SBOM, third-party notices, `LICENSE`, and
`SHA256SUMS.txt`. The checksum set authenticates the other eight files. Public verification independently compares source, signed-app,
and release-copy licence bytes before Apple trust assessment.

This machinery prevents an accidental or substituted licence payload. It does not
decide which licence is appropriate, grant rights by itself, establish ownership of
third-party material, or replace legal advice.
