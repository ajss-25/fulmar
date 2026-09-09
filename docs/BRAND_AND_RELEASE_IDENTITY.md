# Fulmar brand and release identity

## Public identity

- Product name: **Fulmar**
- Canonical repository: <https://github.com/ajss-25/fulmar>
- Public maintainer and first-party copyright/licence holder: **ajss-25**
- Private security contact: <https://github.com/ajss-25/fulmar/security/advisories/new>
- Description: a private, provider-neutral macOS workbench for local and cloud
  models through DeepSeek Harness
- Icon: generated artwork supplied for Fulmar and stored at
  `Resources/FulmarAppIcon.png`. The owner authorizes its inclusion and redistribution
  with this MIT source preview. No claim is made that the artwork is registered,
  exclusive, independently commissioned, or supported by a formal legal opinion
- Status: independent software; not affiliated with or endorsed by DeepSeek,
  OpenAI, Anthropic, Qwen or Ollama

The owner selected and authorizes the **Fulmar** name for this source preview. The name
received a preliminary web collision check; no registered-right, exclusivity, or formal
trademark-clearance claim is made. A public binary and broader product-marketing
campaign still require a separate owner/legal decision.

## Stable legacy technical identity

The following values intentionally retain the LocalHarness name:

- bundle ID `com.angadjairath.localharness`
- executable and helper names
- Keychain services and access groups
- Application Support directory `Local Harness`
- launch-agent identifier and environment-variable namespace
- internal local DSH plugin package scope
- internal storage roots under `Local Harness`

Those values locate and authenticate existing data. Renaming them cosmetically would
make settings, credentials, backups, schedules or rollback material appear missing.
They can change only through a tested, transactional identity migration in a separately
versioned release. They are not exposed as the user-facing product brand. The physical
application and update archive are named `Fulmar.app` and `Fulmar.app.zip`; changing
those cosmetic container names does not change the signed bundle identity or data roots.

## One release source of truth

`Config/ReleaseIdentity.json` binds the public display name, stable bundle ID,
application version/build, minimum macOS, Node digest/version and reviewed DSH/MCP
versions. Production assembly, manifest generation and release verification reject
an `Info.plist` or runtime that disagrees with it.

First-party legal terms are deliberately separate from product identity. The owner
selected the MIT License for original Fulmar source. Top-level `LICENSE` and
`Config/ProjectLicense.json` must remain together and pass the bounded, digest-bound
policy in `docs/FIRST_PARTY_LICENSE_POLICY.md`; those exact bytes are bundled before
signing and carried in the exact nine-asset public set. Branding metadata cannot
select, replace, or override the licence. The source-preview third-party inventory is
separately reviewed, including exact upstream MIT terms for modified
`@earendil-works/pi-ai` 0.82.1. Public binary distribution remains blocked on libvips
LGPL/GPL notice/source/relink compliance and the other binary-specific privacy,
export, trust, installation, and update gates.

## Update rule

Fulmar updates DSH only by shipping a complete, versioned app. The runtime is never
updated independently in place. See `UPSTREAM_DSH_UPGRADES.md` for staging,
compatibility review, qualification, signing, migration and rollback gates.
