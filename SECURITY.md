# Security policy

## Supported versions

Fulmar has not yet published a supported release. There are currently no supported public versions or binaries.

| Version | Supported |
| --- | --- |
| Public releases | None yet |

## Reporting sensitive issues

Do **not** place credentials, private prompts, personal paths, model data, security diagnostics, exploit details, or other sensitive material in a public issue, pull request, discussion, commit, or attachment.

Before the first supported release, the repository owner must enable GitHub private vulnerability reporting and publish a verified private security contact. Once enabled, use the repository's **Security → Report a vulnerability** flow.

Until that private channel is available, this repository cannot responsibly accept confidential vulnerability material. Please retain the details rather than disclosing them publicly.

## Release integrity

A supported Fulmar binary must be distributed only as an immutable, versioned release asset with a published SHA-256 checksum. It must be Developer ID signed, notarised, stapled, accepted by Gatekeeper, and linked from this repository or the official project website.

Fulmar will never require users to remove quarantine metadata, disable Gatekeeper, weaken System Integrity Protection, or use another macOS security bypass.

## Scope

The eventual policy will distinguish:

- vulnerabilities in Fulmar's native application and bundled helpers;
- vulnerabilities inherited from pinned third-party dependencies;
- security behavior controlled by local model runtimes or remote providers;
- reports about unofficial builds or modified distributions.

This document will be expanded before the first supported release.
