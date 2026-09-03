# Static-analysis rule provenance

Fulmar's source gate runs Semgrep Community Edition 1.135.0. The general `p/default`
rules scan `Package.swift`, `Makefile`, `Config`, `Sources`, `Tools`, `Resources`,
`scripts`, and `Tests`. Secret detection separately covers **every bounded UTF-8
source-controlled text surface** under `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`,
`SECURITY.md`, `SUPPORT.md`, the exact top-level `LICENSE` when present, `docs`,
`.github`, `.gitattributes`, `.gitignore`, the
general-code targets above, `VendorRuntime.inventory.json`, and the two authoritative
`VendorRuntime` package manifests. It runs the language-aware `p/secrets` rules and a
second unknown-extension text pass with only the explicitly enumerated
language-specific rules removed to prevent duplicate results. The registry rule
bodies are never checked into this repository.

The top-level coverage guard fails closed if a new real project entry is neither in
that exact target set nor one exact private/generated exclusion. `.build`, `build`,
and the generated runtime/cache trees must be real directories. `.git` may instead be
the tightly bounded, reciprocal worktree metadata file produced by Git itself; links,
special files, oversized or multiline pointers, and out-of-shape targets are rejected.
The sole source binary exclusion is the exact hash-bound Fulmar PNG icon.

The runner itself is also version-bound. `make static-security-scan` starts the
portable clean-environment launcher with `/bin/sh`; that launcher prefers the
reconstructed `VendorRuntime` Node when present and otherwise accepts only Node
22.23.1. The static GitHub job pins `actions/setup-node` by commit and requests that
exact release, so a clean Ubuntu checkout does not need to reconstruct the macOS
runtime before scanning. Both the shell boundary and JavaScript runner fail closed on
Node loader/search options, proxy variables, custom CA/OpenSSL configuration, Python
path injection, dynamic-loader variables, and Semgrep credentials or alternate URLs.
The Semgrep child receives a new allowlisted environment rather than the caller's
environment. Contract tests exercise the clean-checkout fallback, bundled-runtime
preference, wrong-version rejection, and hostile-variable stripping/rejection.

The Semgrep Rules License restricts redistribution of the rule packs. Fulmar therefore
downloads them from two exact `https://semgrep.dev/c/p/…` endpoints into a private
temporary directory, sends no Semgrep account token or metrics, rejects redirects,
and verifies each response before Semgrep sees it. `Config/SemgrepRules.json` binds:

- Semgrep engine version;
- exact HTTPS host/path and response content type;
- byte count and reviewed-content SHA-256;
- rule count and unique rule identities; and
- the complete scan-target list.

Both current packs are YAML and use a canonical rule-set pin: a length-framed,
byte-exact set of complete top-level rule blocks sorted by bounded ASCII rule IDs.
Only top-level rule ordering is ignored. A byte change inside any rule,
addition/removal, duplicate/missing ID, byte-count change, format/content-type change,
or origin change still fails closed. The raw response digest is retained in the
canonical evidence summary even though the reviewed manifest binds the canonical
rule-block-set digest.

The owner's legal review must still confirm that intended public-project/CI use
complies with the published terms; this document is not legal clearance.

## Reviewed pins — 2026-08-29

| Pack | Rules | Bytes | SHA-256 |
| --- | ---: | ---: | --- |
| `p/default` | 1,074 | 2,423,491 | `ef6306c3be7298ab8ce1fc2702a56044740d05d5c728808f3e32d3c85b4d11a0` |
| `p/secrets` | 52 | 89,772 | `d8c1c5e0e532e641858800330a8c1c9bc1f8eddeea6905696fd93e07a7ed229a` |

During the build-135 audit, the registry stopped serving the previously reviewed
2,195,213-byte JSON response and began serving YAML despite an `Accept: application/json`
request. A later clean-checkout simulation then caught another drift from raw SHA-256
`9568eb5f…` to `f8db8582…`, both 2,423,491 bytes. Owner-only retained samples also
included raw SHA-256 `974409ed…`.

The gate stopped each unreviewed change. Retained old and proposed YAML bytes were
parsed with pinned `js-yaml` 4.3.1 and independently validated by Semgrep 1.135.0: all
three contain the same 1,074 unique IDs and no rule-object addition, removal, or content
change. The retained build-135 comparison produced the same one finding, seven
warning-level parser messages, and normalized report digest
`330d391b86fa4a6b47d04c5a1db85805a36aeca81904c2ea9a6977c82c9ca6a7`.
The former line counter missed one valid rule whose `id` followed another top-level key;
the current manifest schema corrects the count and uses the exact rule-block-set digest
above. The 52-rule secrets response was independently reviewed and is bound with the
same fail-closed YAML rule-block-set scheme.

## Result and evidence policy

A successful 1,126-rule run may contain only the structurally verified generic
cleartext-WebSocket finding for Fulmar's authenticated exact-port `127.0.0.1` CSP
construction. The runner accepts it only while the entire fail-closed ternary, sole
interpolation, exact source line, and exact rule ID remain unchanged. Any second
occurrence or unrelated finding fails the gate.

Parser/report warnings do **not** receive a broad non-blocking status. Each permitted
warning must match one source-controlled allowlist entry by scan, exact path, exact
rule identity, level, numeric code, reason, and the current source file's SHA-256. An
unidentifiable, missing, duplicate, changed, extra, or stale warning fails closed, as
does every report error. During active release edits the warning hashes are refreshed
only after source freeze and full review; until then, a mismatch is an intentional
qualification failure rather than evidence to suppress.

The live release scan currently has nine exact warning reviews. That count is not a
permanent baseline: the allowlist is consumed in full on every run, so a missing warning
is stale evidence and an additional warning is unreviewed evidence; either condition
fails the scan.

Before scanning, the runner removes only a safe owner-controlled prior summary. After
all three reports, input-stability checks, warning checks, and finding checks pass, it
atomically writes `build/static-security-summary.json` (maximum 512 KiB). That canonical
summary binds every scanned text path/size/SHA-256, exact exclusions, each report hash,
reviewed warning/finding identities, engine version, and canonical/raw rule-material
digests. It is fsynced and its final SHA-256 and byte count are printed; an unsafe
directory/file topology or oversized summary fails closed.

Release assembly cannot consume this as a free-standing or timestamp-based receipt.
`verify-static-security-summary.mjs` derives the complete text-file set from the exact
frozen `source-build-inputs.json`, checks every path/size/SHA-256 plus the reviewed
binary exclusions and policy/rule evidence, and rejects an absent, failed, stale, or
modified summary. The release manifest cryptographically binds both artifacts. The
same pair is rechecked by deterministic/full qualification, retained evidence, frozen-
candidate preflight, public-asset preparation, and public-distribution verification;
the public nine-asset set carries the exact manifest-bound summary.

## Updating a pin

Never replace a checksum merely because CI failed.

1. Fetch the old and proposed responses without an account token.
2. Verify TLS origin, status, content type, byte count, raw SHA-256, ETag, and repeated
   fetch behavior. Retain compared bodies only in an owner-only temporary evidence
   directory; never print, upload, commit, or redistribute them.
3. Parse both packs with a pinned real parser, compare every rule ID and rule object,
   review every addition/removal/change, validate both with the pinned Semgrep engine,
   and compare full scan reports.
4. Re-run pin-contract tests and the complete static gate.
5. Record exact old/new hashes, counts, differences, findings, parser warnings, date,
   engine version, and reviewer decision in this file and release evidence.

If old reviewed content is unavailable, the correct behavior is a failed gate until a
defensible comparison is possible. Top-level reordering may reuse the existing
rule-block-set digest only after exact block equality is proven; no other semantic or
format drift is accepted automatically. A local cache or broad allowlist must not
silently stand in for a changed registry response.
