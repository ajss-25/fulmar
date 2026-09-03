# Vendored runtime patches — Fulmar 1.2.36 build 156

Fulmar normally ships the pinned DeepSeek Harness packages unchanged. Any
intentional divergence is recorded here, included in the signed runtime inventory,
and covered by source and candidate-backed qualification. An upstream refresh must
reapply or deliberately retire each entry after review.

## Reproducible public-source materialization

`Config/VendorRuntimePatches.json` is the machine-readable review record for this
release. It binds the checked root package and lockfile, both exact upstream tarball
URLs and npm SHA-512 integrity values, the single install-only lock transformation,
and every patched file's before/after SHA-256 values.

The checked lock records the historical
`@local-harness/dsh-credentials-keychain@1.0.3` marker in the DSH package metadata,
but that package has never existed in the public npm registry. A clean checkout must
therefore use `scripts/materialize-vendor-runtime.mjs`; running `npm ci` directly is
not a supported or reproducible build path. The materializer verifies the reviewed
lock checksum, derives a temporary lock by removing only that exact marker, and
verifies the derived lock checksum before invoking the pinned npm client. It uses a
private temporary npm configuration/cache, discards credential-shaped environment
configuration, starts pinned Node and npm processes without ambient `NODE_OPTIONS`,
`NODE_PATH`, proxy, custom-CA, SSH-agent, dynamic-loader, or npm configuration,
forces the public HTTPS registry URLs already pinned in the lock, and disables
lifecycle scripts in both configuration and command-line policy.

After npm verifies every lock-bound package integrity, the materializer rejects
special files and escaping links, requires the exact upstream SHA-256 for all thirteen
reviewed patch inputs, applies deterministic anchored transformations, and requires
the exact reviewed output SHA-256. The temporary dependency tree is moved into place
only after those checks. `VendorRuntime.inventory.json` then authenticates all 38,501
paths and 394,622,078 file bytes, not just the patched packages. The generated hidden
npm lock metadata now correctly identifies the source runtime package as `1.1.0`;
the previous `1.0.0` value was stale, and no dependency content changed in that
correction.

The source workflow executes this complete reconstruction before either native or
JavaScript tests. Any changed lock, upstream tarball, patch anchor, file checksum,
topology, or final inventory fails closed and requires a new explicit review record.

## `@deepseek-ai/dsh-llm-deepseek` 0.1.1-rc.1 — privacy revision 1; streamed tool-identity revision 2

Upstream generates a stable UUID in `$DSH_HOME/.anonymous-user-id` and sends it as
`x-deepseek-harness-user-id`; it also sends the internal Harness session identifier.
This private distribution removes the anonymous-ID import/resolver, omits both
headers, removes the now-unused package/type contract, and updates the bundled English
and Chinese documentation. It retains the normal product/version `User-Agent` and
all headers required by the DeepSeek wire protocol.

Defense in depth: `RuntimeSecurityPreload.mjs` strips both identifier names from every
guarded provider Fetch request. The provider matrix requires their absence and proves
that no `.anonymous-user-id` file is created by the composed DeepSeek route. The
runtime inventory and application signature authenticate the patched bytes.
The root npm lockfile intentionally retains each upstream tarball's resolution and
integrity metadata as provenance; it is not asserted to be the hash of these locally
patched files. `Config/VendorRuntimePatches.json` binds every before/after patch hash,
and `VendorRuntime.inventory.json` remains the complete byte-level authority used for
assembly and release verification.

The same adapter previously replaced an already-valid streamed tool-call `id` or
function `name` whenever a continuation frame supplied any value. OpenAI-compatible
providers are permitted to omit those continuation fields, and some gateways emit
them as `null` or an empty string. That could erase the correlation identity after
the first arguments fragment and persist an empty tool name/id into Harness history.
Fulmar revision 2 of the package-local patch now accepts the first non-empty string
for each identity field and preserves it for the rest of that indexed tool block;
argument fragments continue to concatenate normally. Repeated valid identity values
are therefore harmless, while omitted, null, empty, or later conflicting values
cannot replace the established identity.

The machine-readable entry is named `deepseek-provider-runtime-hardening`, making
both semantic purposes explicit. It is an anchored, checksum-bound transform of the
reviewed upstream adapter:
`lib/index.js` SHA-256 changes from
`bf7fc6a6fca55ce9ae980fc3f39483fb52efadc9e013747a2bd9a475149b7a4f` to
`4a10b1e00676c41e313a4d4c8578840c63711ee69fdeff077f998d5194964e60`.
The patched package manifest changes from
`5993ff245be62eb3727a952d3cce9d49908355aaca72b916c3179a1dd17574b7` to
`3eb24383ad6a02ec92d3c9d30d05611d18561b8099ce4fec241bee9ff3f786dc`.
Any upstream-byte, patch-anchor, manifest, or installed-output drift fails before the
tree can be accepted. Direct adapter regressions cover omitted, null, empty, repeated,
and conflicting non-empty identities across fragmented arguments, then serialize the
resulting call and result back into an exact correlated follow-up. The composed
provider matrix adds the same five DeepSeek cases, requires one tool side effect and
exactly two agent requests per case, and rejects empty, duplicated, retargeted, or
mismatched durable history.

## `@deepseek-ai/dsh-llm-pi-ai` and `@earendil-works/pi-ai` — explicit private no-auth revision 1

The upstream adapter accepts a profile without `apiKeyEnv`, but its OpenAI-compatible
and Anthropic request clients still refuse to start without a key or an authentication
header. That made a credential-optional custom profile appear configured while every
task failed before provider I/O.

Fulmar adds an explicit `unauthenticated: true` profile mode. The DSH-side validator
accepts it only for a DNS-free literal loopback, RFC 1918, or IPv6 ULA base URL,
rejects any simultaneous credential reference or custom header, and rejects it for
every hostname and cloud origin. It also bypasses pi-ai stored and ambient credentials
even when a custom route ID collides with an installed catalog provider. On an admitted route it supplies three
internal null header tombstones. The reviewed pi-ai OpenAI Chat Completions, OpenAI
Responses, and Anthropic Messages clients recognize only that complete tombstone set,
use the SDK's required placeholder internally where necessary, and clear
`Authorization`, `X-Api-Key`, and Cloudflare authentication before Fetch. Ordinary
keyless profiles remain fail-closed.

The same DSH validator rejects an explicit Anthropic Messages base ending in `/v1`;
the Anthropic SDK appends `/v1/messages`, so accepting that input would address
`/v1/v1/messages`. Native validation duplicates both policies before any credential or
settings mutation. Machine-readable before/after SHA-256 records bind the DSH adapter
runtime, type declaration, English and Chinese documentation, plus all three pi-ai
protocol clients. Behavioral tests
require cloud no-auth rejection and require all three admitted local protocols to emit
no authentication header.

## Fulmar runtime plugins — automatic continuation

Fulmar does not patch the pinned DSH application or Web UI for output-limit recovery.
The reviewed `performance-profile` plugin observes the completed `turn/end` event and
uses DSH's public Agent follow-up API to enqueue a new, source-labelled continuation
only for a foreground root turn that ended with `max-tokens`. It is bounded, yields to
queued user work, and never reconstructs partial tool calls. The reviewed
`client-security-bridge` replaces the two exact stock manual-continuation messages in
English and Chinese so the visible UI describes the automatic behaviour. Mutation of
unrelated UI text is outside that bridge's contract.

## Fulmar runtime plugin — approved page retrieval

The upstream DSH composition always registers `web_search` against a DeepSeek API-key
route and disables `web_fetch`. Fulmar's product patch disables that search provider
and tool unless an independent route is later qualified, then registers the signed
`web-fetch-safe` provider for `web_fetch`. The provider asks for the exact normalized
URL on every call and delegates the request to a short-lived preload capability. That
boundary allows public HTTPS/443 only, checks DNS and the connected address, denies
redirects and non-text media, strips browser-like state, and bounds content to 2 MiB.
The plugin also tells the model never to retry denied or failed web work through Bash
or another client. This is a Fulmar composition extension; upstream web packages stay
byte-identical and their future DeepSeek-search wire contract remains pinned for an
explicitly configured release.
