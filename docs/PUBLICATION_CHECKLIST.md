# Publication checklist

This checklist is intentionally fail-closed. An unchecked item is not an implied waiver.

## Ownership and legal

- [ ] Select and publish the project licence.
- [ ] Verify that every first-party file and plugin is covered by that licence.
- [ ] Review third-party redistribution, notices, trademarks, name, and icon provenance.
- [ ] Publish privacy, support, contribution, security, and known-limitation policies.

## Repository

- [ ] Review the exact Git index and every imported commit for credentials and private data.
- [ ] Reject generated runtimes, model weights, applications, archives, certificates, logs, databases, and oversized blobs.
- [ ] Reconstruct and test the application from a clean clone.
- [ ] Enable protected branches, required checks, secret scanning, push protection, dependency alerts, code scanning, and private vulnerability reporting.
- [ ] Review collaborators, deploy keys, webhooks, Actions permissions, environments, and installed GitHub Apps.

## Frozen candidate

- [ ] Freeze one version/build and source commit.
- [ ] Bind source inventory, runtime inventory, dependency lock, SBOM, notices, manifest, app archive, dSYM, and checksums.
- [ ] Run the complete deterministic native, JavaScript, security, provider, toolbar, credential, sandbox, runtime, and release-verification suites.
- [ ] Retain exact commands, outputs, timestamps, hashes, hardware, operating-system, runtime, model, and provider evidence.

## Apple distribution

- [ ] Sign the app and every nested executable with one reviewed Developer ID Application team.
- [ ] Verify hardened runtime and the minimal required entitlements.
- [ ] Obtain an Accepted, issue-free Apple notarisation result and retain its matching records.
- [ ] Staple and validate the ticket.
- [ ] Confirm Gatekeeper acceptance online and offline from the downloaded archive.
- [ ] Test the same archive on the declared minimum and current supported macOS versions.

## Product qualification

- [ ] Complete first-run, missing-runtime, local-model, funded remote-provider, provider-switch, error, cancellation, tools, history, schedules, skills, MCP, download, permissions, accessibility, thermal, lifecycle, and resource-pressure paths.
- [ ] Verify clean installation, quit/relaunch, logout/login, uninstall/data-retention, reinstall, update, automatic rollback, and recovery after interrupted replacement.
- [ ] Confirm no app-owned process remains after protected quit.
- [ ] Verify privacy disclosures and explicit local/cloud data boundaries.
- [ ] Record accepted residual risks without claiming zero defects.

## Publication

- [ ] Create an immutable draft release from the frozen tag.
- [ ] Upload the exact qualified archive, checksums, licence, SBOM, notices, release notes, limitations, and evidence.
- [ ] Independently download and verify every public asset.
- [ ] Publish only after the owner signs the final go/no-go record.
- [ ] Link the website to the exact versioned GitHub release and checksum.
