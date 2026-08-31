# Public release policy

Fulmar will distinguish source publication, developer previews, and supported macOS downloads. Passing one level does not imply the next.

## 1. Repository foundation

The repository may contain project-status documentation, contribution boundaries, issue templates, and release policy before application source is published.

It must not contain private workspace data, credentials, signing material, model weights, generated runtimes, build products, or claims that an unfinished build is supported.

## 2. Source publication

Application source may be published only after:

- an explicit project licence is selected and included;
- final tracked files and complete imported history pass secret and privacy review;
- third-party redistribution and trademark materials are reviewed;
- a clean checkout reconstructs and tests the intended source;
- continuous integration and repository protections are enabled;
- security, support, contribution, and known-limitation documents are ready.

## 3. Developer preview

A developer preview must be labelled unsupported and may require local compilation. Its tag, source commit, limitations, and test evidence must be immutable.

A developer preview must not be described as a supported ordinary-user download.

## 4. Supported macOS download

A supported binary requires one frozen artifact whose source inventory, dependency inventory, manifest, SBOM, notices, archive, checksum, signing identity, notarisation records, and retained test evidence all agree.

The exact distributed app must:

- use a reviewed Developer ID Application identity and hardened runtime;
- be accepted by Apple notarisation and carry a stapled ticket;
- pass Gatekeeper online and offline without security bypasses;
- pass clean installation, first launch, quit/relaunch, uninstall, reinstall, update, and rollback;
- pass the declared minimum and current supported macOS checks;
- pass local-model, provider, permissions, accessibility, thermal, lifecycle, and privacy qualification;
- leave the prior stable app recoverable until replacement is verified.

## 5. Release assets

A supported GitHub release should include:

- the versioned application archive;
- its SHA-256 sidecar and a complete checksum file;
- release notes and known limitations;
- the project licence;
- the artifact-derived SBOM and third-party notice inventory;
- the qualification evidence appropriate for public review.

Release assets are immutable. A defective release is superseded with a new version; files under an existing tag are never silently replaced.

## 6. Website links

The official website must link to the versioned GitHub release or serve byte-identical HTTPS assets with the same visible checksum. It must not host a separately rebuilt binary or instruct users to bypass macOS security.
