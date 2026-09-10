# Private DMG wrapper

`scripts/prepare-beta-dmg.mjs` tests a disk-image delivery container around an
existing Fulmar candidate ZIP. It does **not** build or re-sign Fulmar, install or
launch it, read credentials, or qualify a public beta. The public ZIP manifest and
nine-asset stable contract are unchanged. Claude's separate beta asset lane does
not depend on this wrapper.

## Inputs and operation

Use the Node binary whose SHA-256 matches `Config/ReleaseIdentity.json`. All paths
must be absolute; inputs must be owned, canonical, single-link regular files.
Create the output's parent and the verification work parent as private directories
(mode 0700). Never pass an installed app or an existing destination as output.

```sh
VendorRuntime/node-v22.23.1-darwin-arm64/bin/node scripts/prepare-beta-dmg.mjs \
  create /absolute/reviewed/Fulmar.app.zip <trusted-zip-sha256> /absolute/private/new-output

VendorRuntime/node-v22.23.1-darwin-arm64/bin/node scripts/prepare-beta-dmg.mjs \
  verify /absolute/private/new-output/Fulmar.dmg <trusted-dmg-sha256> \
  /absolute/reviewed/Fulmar.app.zip <trusted-zip-sha256> /absolute/private/verification-work
```

Digests are explicit operator inputs. A checksum or JSON file downloaded beside an
image is not an independent trust source. The ZIP digest should come from the
previously reviewed candidate record; retain the generated image digest separately
before testing it as a recipient. Public distribution still requires the existing
full release verification and external evidence, not just this command.

The wrapper snapshots each external archive through the repository's attested
reader, checks its expected digest before use, validates the ZIP, extracts one app
and checks its identity and code-signature integrity. It then copies that app into
a private HFS+ compressed disk image with an Applications shortcut and an explicit
private-preview notice. No Finder automation, installer script or app launch runs.

Both create and verify check the disk-image checksum, mount the exact private image
read-only with ownership enabled, check the mounted contents, copy the app back to
a new private location, and compare its files, types, modes and relative symlink
targets to the ZIP app. App-root type, owner and mode are also compared. Signature
integrity is rechecked on the recovered app. This does not claim preservation of
filesystem-specific directory sizes, timestamps or every extended attribute.

The tool detaches only the device associated with its exact private image and mount
path. It does not force-detach volumes. An ambiguous attachment or failed detach
retains the work directory and reports its path; it is not recursively removed.

## Outputs and limitations

A successful private output contains `Fulmar.dmg`, `dmg-binding.json` and
`SHA256SUMS.txt`. The binding explicitly says `publicBetaQualified: false`, retains
both archive digests and lists the checks not performed. The checksum list covers
the image and binding. The output directory is created exclusively, never replacing
an existing destination.

This is not the public atomic asset publisher. Normal errors clean up only this
invocation's owned output. An uncatchable process kill or system failure can leave
an incomplete private directory or attached private image. Preserve and inspect
such residue; do not distribute it or retry with overwrite. A successful independent
verification is required, and even that is only container evidence.

DMG byte-for-byte reproducibility is **not** claimed: the filesystem and image tools
can introduce variable metadata. The app content must nevertheless compare exactly
on every round trip. Ad-hoc signature integrity can pass this private check; that is
not Developer ID trust, notarisation, permission persistence, licensing clearance,
clean-install acceptance or a successful local/cloud model test.

## Testing and integration boundary

`Tests/JS/BetaDMGPackageTests.mjs` uses a small, ad-hoc-signed fixture app that is never
executed. It exercises the native disk-image round trip and rejection/cleanup paths
with explicit private-only status. No real signing credential is used. Run it with
the repository's bounded test/watchdog entry points and pinned Node; do not run
concurrent heavy native qualification on the same Mac.

This lane does not add a thirteenth public asset or edit the shared beta packaging
scripts. Adding a real distributable DMG later requires deliberate asset binding,
signing/notarisation decisions for the final container, and acceptance of the exact
downloaded bytes. Re-derive the combined JavaScript topology when integrating this
test suite with Claude's lane; this isolated lane does not change shared count files.
