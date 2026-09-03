# Security policy

Fulmar is pre-release software and is not yet approved for general public binary
distribution.

Canonical repository: <https://github.com/ajss-25/fulmar>. Public maintainer identity:
**ajss-25**. The security contact is the repository's private vulnerability-reporting
channel below; no public mailbox is represented as a confidential fallback.

No released Fulmar version is currently security-supported. A locally built candidate
is suitable for review only; do not represent it as a supported or notarized release.

Please do not place a vulnerability, credential, private prompt, diagnostic archive,
or exploit proof in a public issue. Use
[Fulmar's private vulnerability reporting](https://github.com/ajss-25/fulmar/security/advisories/new).
Include the Fulmar version/build, macOS version, provider boundary (on-device, local
network, or cloud), and the smallest redacted reproduction you can provide.

If GitHub's private reporting form is unavailable, do not post exploit details publicly;
open a non-sensitive issue that reports only that the private contact path is unavailable.

The maintainer will acknowledge a complete report before publishing details. There is
currently no guaranteed response-time SLA. Unsupported areas and open release gates are
listed in `docs/KNOWN_LIMITATIONS.md` and `docs/RELEASE_CHECKLIST.md`.
