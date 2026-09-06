# Getting started with Fulmar

Fulmar 1.2.36 build 156 is a source-only developer-preview candidate, not a supported
public app-binary download. The
current build still lacks Developer ID signing, Apple notarization, clean-Mac release
qualification, binary-specific libvips licence/source/relink compliance, and a post-install updater
health/commit transaction proven across power loss and two notarized versions. Do not
bypass Gatekeeper or download an unsigned copy from an unofficial mirror.
Original Fulmar source is available under the MIT License. Its source-preview
third-party inventory has been reviewed, including exact MIT provenance for the
modified `@earendil-works/pi-ai` dependency. A built app contains additional binary
materials and remains a separate legal and technical release gate.

[DeepSeek classifies Harness itself](https://github.com/deepseek-ai/deepseek-harness/blob/main/SAFETY.md) as experimental developer-preview software and says
it has not undergone a security audit. Fulmar adds narrower native controls, but those
controls cannot guarantee isolation from model-generated commands or an extension you
explicitly approve. Use the least access needed, keep backups, and review Skills, MCP
servers, plugins, network disclosures, and commands before allowing them.

This guide is for source reviewers and for the future signed release. Where the two
paths differ, that difference is called out explicitly.

## Choose the model boundary first

| Choice | Runs where | Credential | What can leave the Mac |
| --- | --- | --- | --- |
| Ollama (Local) | An app-owned Ollama process on this Mac | None; `local-ollama` is a fixed non-secret readiness marker | Model requests stay on the app-owned loopback route, but separately approved tools, Skills, MCP servers, or browser handoffs can still disclose data. Only exact `qwen3.8:27b-mlx` is release-qualified; other admitted Ollama models use unqualified Compatibility mode |
| DeepSeek API | DeepSeek's cloud service | Your DeepSeek API key in macOS Keychain | The task content and approved tool/context data described by the boundary confirmation |
| OpenAI / Anthropic | The selected provider's cloud service | Your provider API key in macOS Keychain | The task content and approved tool/context data described by the boundary confirmation |
| Compatible endpoint | The exact endpoint you configure | Optional bearer-style API-key reference | Depends on whether Fulmar classifies the exact origin as local-network or cloud. Custom endpoints are never labelled on-device; only the app-owned Ollama route receives that boundary |

Changing provider or crossing a boundary restarts the authenticated agent service and
starts a fresh main task. Quick Chat also starts fresh. A prior task remains in History
but is not silently carried into the new route.

## Requirements

- Apple-silicon Mac running macOS 15 or later. This floor is enforced against every
  bundled native executable and addon, not only the app's Info.plist.
- Xcode command-line tools for a source build.
- Network access during source bootstrap for checksum-bound Node and npm packages;
  during the content-pinned Python/Semgrep installation for hash-locked archives and
  wheels; during the exact Semgrep rule-pack fetch; and during the credential-free
  production dependency audit.
- For release-equivalent static analysis, use `scripts/install-pinned-semgrep.sh` as
  shown below. It installs the exact source-pinned Python 3.12.3 archive and complete
  Semgrep 1.135.0 wheel closure for this platform. An externally managed
  `pipx install semgrep==1.135.0` may be convenient for informal development, but its
  transitive dependency bytes are not Fulmar release or hosted-CI evidence.
- The official signed Ollama macOS application, stable version 0.33.2 through
  the 0.33.x series, for
  local models. Ollama's official
  [v0.32.12 release](https://github.com/ollama/ollama/releases/tag/v0.32.12)
  introduced Qwen 3.8 27B and its Apple-silicon `27b-mlx` variant, but Fulmar's
  supported floor is the oldest version exercised end to end on the development
  host: 0.33.2. A 0.34-or-newer series needs a later Fulmar qualification and
  fails closed in this release. The
  frozen candidate's physical generation/tool rerun remains separate release evidence.
- At least 48 GB of physical memory for the release-qualified Qwen 27B route.
  Fulmar enforces that floor before starting local inference. Smaller admitted
  Compatibility models and cloud providers remain available on lower-memory Macs.
- A canonical, owner-safe macOS login home. Homes outside `/Users` are supported when
  every path ancestor is a real root/current-user-owned directory with no group/world
  write permission or extended ACL; the account home is current-user-owned. The
  private installer additionally requires current-user-owned, non-writable,
  ACL-free `Library` and `Application Support` directories for a nonstandard home.
  Symlinked, ACL-bearing, or writable custom-home layouts fail closed.

Intel Macs are not a supported target. The minimum-macOS and clean-machine matrix is
still an open public-binary gate.

## Understand support versus qualification

The hardware tiers in the automated suite are injected policy inputs, not a collection
of physical test machines. Tests at 8, 16, 24, 32, 48, 64, and 96 GiB prove the exact
admission and refusal thresholds. Current real local-inference, Metal/MLX, thermal,
memory-pressure, and tool evidence comes from one 48 GB Apple M5 Pro. A smaller
Compatibility model may be admitted on a lower-memory Apple-silicon Mac, but that is
not physical performance qualification for that model or host class.

The provider distinction is equally important:

- DeepSeek, OpenAI, Anthropic, and the three reviewed compatible wire protocols have
  credential-free fixture coverage for request shape, streaming, tools, cancellation,
  authentication/error handling, retry bounds, and secret suppression.
- Those custom protocols are exactly **OpenAI Chat Completions**, **OpenAI
  Responses**, and **Anthropic Messages**. Passing the editor's structural checks is
  not a claim that every nominally compatible server or model implements them fully.
- Fixture coverage does not prove that a real account accepted, billed, retained, or
  successfully completed a request. Do not call a provider live-qualified unless the
  exact release evidence records an account-backed text/tool/cancel/error run.
- Only Fulmar's app-owned Ollama route receives the native local-model size/RAM gate,
  exact child ownership checks, adaptive Eco workload, and emergency thermal stop.
  A user-declared loopback or private-network OpenAI-compatible endpoint is labelled
  **Local network**, not **On this Mac**, and does not inherit those protections.

## Review or build the source candidate

From a fresh checkout at the repository root:

```sh
umask 022
zsh scripts/bootstrap-source-checkout.sh
semgrep_parent="$(/usr/bin/mktemp -d /private/tmp/fulmar-semgrep.XXXXXX)"
semgrep_root="$semgrep_parent/toolchain"
semgrep_path_file="$semgrep_parent/path-command"
/usr/bin/touch "$semgrep_path_file"
/bin/bash -p scripts/install-pinned-semgrep.sh \
  "$semgrep_root" "$semgrep_path_file" \
  "$PWD/VendorRuntime/node-v22.23.1-darwin-arm64/bin/node"
export PATH="$semgrep_root/bin:$PATH"
semgrep --version # must report 1.135.0
make source-contract-test
make deepseek-contract-test
make runtime-inventory-verify
make dependency-audit
make static-security-scan
zsh scripts/run-swift-tests.sh
zsh scripts/run-js-tests.sh --test Tests/JS/*.mjs
make private-release
```

The assembled local candidate is
`/private/tmp/LocalHarnessBuild/Fulmar.app`. Generated `.build`, `build`, Node, and
`node_modules` trees are intentionally excluded from Git. Bootstrap must recreate
them from the checked lock, patch manifest, and byte inventory. A clean bootstrap and
test run is necessary evidence; it is not Developer ID signing or notarization.
`make private-release` deliberately creates or reuses **Fulmar Local Signing** in
your login Keychain, potentially with a first-use authorization prompt. This is a
persistent self-signed development identity, not a paid Apple Developer ID, and the
target neither installs nor publishes the app. Reuse it on later builds so the
credential helper and XPC services retain their shared designated requirement.
Before use, quit any previous copy and place the reviewed app in `/Applications`,
retaining your previous bundle and a private state backup. Read
[Preview binary and Gatekeeper](PREVIEW_BINARY_GATEKEEPER.md) first.

For compile/review-only work, the explicit
`LOCAL_HARNESS_REQUIRE_STABLE_SIGNING=0 LOCAL_HARNESS_SIGN_IDENTITY=- LOCAL_HARNESS_SIGN_TIMESTAMP=0 make build`
command avoids creating a signing identity. That ad-hoc bundle cannot satisfy the
packaged credential services' shared-signature requirement; do not use it to
evaluate cloud credentials or weaken the identity checks to make it run.
The Semgrep installer refuses an existing destination; use a new private temporary
root for a new installation rather than modifying a previously reviewed toolchain in
place.

Do not run `npm ci` directly against the reviewed provenance lock. Use the bootstrap
script so the exact install-only lock transformation and thirteen hash-bound runtime
patches are applied and verified.

## Use an Ollama model on this Mac

1. Install the official Ollama macOS application from Ollama's official distribution.
   Fulmar rejects an ad-hoc, modified, unexpectedly signed, or PATH-only executable.
   Fulmar also checks the bounded official `GET /api/version` response before model
   admission: 0.32.12 was the first upstream release with the model, while 0.33.2 is
   Fulmar's oldest end-to-end-qualified and therefore minimum supported version.
   Later patches in the 0.33.x series may proceed, but 0.34-or-newer, prerelease,
   or malformed versions fail closed until a later Fulmar release qualifies them.
   Model digest, capability, context, memory, PID/listener, and behavioral endpoint
   checks still decide whether the selected route is compatible.
2. For the qualified route, run `ollama pull qwen3.8:27b-mlx` through Ollama's
   official CLI. Verify it appears in `ollama list`.
   Fulmar never pulls, downloads, updates, or deletes model weights. Model names and
   memory needs vary; do not assume every Ollama model has been release qualified
   merely because it appears in the selector.
3. Quit or leave the normal Ollama service as desired. Fulmar does not adopt port
   11434; it starts a separate, confined Ollama child on a random loopback port.
4. Open Fulmar, choose **Ollama (Local)**, and select an installed model. Only
   `qwen3.8:27b-mlx` with manifest digest
   SHA-256 `5642e97495e1a088883805981563dcdc4a040c2f53388b7a41d1f24d3622cf7e`
   receives the qualified Fast/Balanced/Deep controls. Fulmar refuses a missing,
   changed, or merely retagged model instead of trusting the mutable tag alone.
5. For any other model, select **Use Compatibility Mode**. Fulmar reads bounded
   metadata from the verified app-owned Ollama listener and admits only a model that
   reports completion, tool use, no model-specific thinking mode, and a context between
   8,192 and 1,048,576 tokens. It also requires physical memory of at least twice
   Ollama's reported installed size plus a 4 GiB reserve. An admitted model is text-and-tools-only and fixed at 8,192 context / 2,048
   output; it remains unqualified for complete DSH behavior.
6. Start qualified Qwen with **Fast**, then move to Balanced or Deep only when the
   workload and temperature justify the larger context/output budget. Compatibility
   models cannot select those profiles or reasoning controls.

If the saved local model is missing, task admission remains closed and the recovery
screen offers **Choose Installed Local Model**. Choose a compatible installed model,
or install one through Ollama and refresh. Fulmar never chooses the first list item,
silently substitutes a model, or starts an automatic download.

No DeepSeek key belongs in this flow. A prompt asking for `OLLAMA_API_KEY` indicates a
configuration or runtime defect; the app supplies its own fixed non-secret marker.
An alternate thinking-capable Ollama model is rejected rather than guessed at: Fulmar
does not infer an unreviewed model's reasoning-control dialect.

## Use the DeepSeek API

1. Create a DeepSeek API key for a test account and confirm that the account has
   usable quota or credit. A valid key with no credit can reach the API but cannot
   prove a successful chat, tool call, or cancellation path.
2. Open **Models & Providers**, select DeepSeek, and choose **API Key…**.
3. Paste the key only into Fulmar's credential sheet. The value is written to macOS
   Keychain and cannot be read back by the window. Never place it in the repository,
   a prompt, a screenshot, diagnostics, or an issue.
4. Save the credential. Verification does not select DeepSeek as the inference route
   and does not send a model request. Fulmar returns to a zero-inference provider
   control plane.
5. Refresh the catalog, select the intended DeepSeek model, read the exact cloud
   destination and disclosure categories, then choose **Use for New Tasks**. This
   separate action commits the route and starts fresh tasks; there is no automatic
   provider/model activation.
6. Start a new test task. Confirm text response, one harmless tool flow, cancellation,
   and the provider's expected quota/error behavior before trusting that account for
   real work.

The packaged protocol fixtures test DeepSeek request, stream, tool, cancellation,
authentication, retry, malformed-response, and size-limit behavior without a real
account. They do not prove that a live service accepted or billed a request. The exact
live qualification status is recorded in `docs/QUALIFICATION_EVIDENCE.md`.

## Use a reviewed custom endpoint

1. Open **Models & Providers**, add a custom provider, and choose exactly one reviewed
   protocol: **OpenAI Chat Completions**, **OpenAI Responses**, or **Anthropic
   Messages**. Fulmar does not offer an arbitrary protocol adapter.
2. Enter the protocol-specific base URL. For either OpenAI protocol, enter the API
   prefix before `/chat/completions` or `/responses` (commonly a URL ending in
   `/v1`). For Anthropic Messages, stop before `/v1`; its SDK appends
   `/v1/messages`, so Fulmar rejects an Anthropic base already ending in `/v1`.
   Plain HTTP is accepted only for a literal loopback or private address; public
   origins must use HTTPS. A local address is labelled **Local network**, not **On
   this Mac**.
3. Normally enter an `apiKeyEnv` credential reference and store the bearer-style API
   key through Fulmar's credential service. An explicit **No authentication** mode
   is available only for a literal loopback, RFC 1918, or IPv6 ULA address; it sends
   no Authorization or API-key header. Hostnames (including `localhost`) and cloud
   origins cannot use it. The custom editor does not support arbitrary headers or
   query parameters, proxies, custom certificate authorities, or mutual TLS.
4. Enter one model per line using exactly:

   `model ID | display name | text,image | context tokens | max output tokens`

   Use `text` when the model has no image input. Audio and video declarations are
   rejected. Context must be 1,024 through
   16,777,216 tokens; maximum output must be 256 through that model's context limit.
   These are capability declarations, so use the endpoint model's real supported
   values rather than the budget you hope to request.
5. Save the profile. Fulmar writes the provider into DSH, re-reads the live document,
   and refuses to present it as configured unless the provider, models, capabilities,
   and both token limits round-trip exactly. This does **not** contact the endpoint.
   Select the model, review the destination, choose **Use for New Tasks**, then run a
   test task to verify authentication, protocol behavior, streaming, tools, and the
   declared limits.

A custom local server is user-managed. It does not receive Fulmar's signed Ollama
process ownership, lifecycle, model-size/RAM admission, Metal/MLX tuning, or thermal
protection. Qualify that exact server, model, protocol, tools, streaming, cancellation,
and privacy behavior before relying on it.

## Web access is deliberately narrow

Generic credential-backed `web_search` is not exposed in this candidate. A task may
request one public HTTPS page through `web_fetch`; Fulmar shows the exact URL and asks
for approval each time. It rejects redirects, credentials, custom ports,
private/reserved addresses, binary content, and oversized bodies. Opening a normal
link hands it to the default browser after confirmation and leaves Fulmar's agent
boundary.

## Common first-run outcomes

| Symptom | Meaning | Safe next step |
| --- | --- | --- |
| Local model missing | Ollama does not report the saved model to the app-owned service | Select **Choose Installed Local Model** and choose a validated installed model, or install it with Ollama and refresh; Fulmar never downloads one |
| Local model refused in Compatibility mode | The model lacks completion/tools, reports model-specific thinking, has less than 8K context, returned malformed/out-of-bounds metadata, or leaves insufficient RAM headroom | Choose exact `qwen3.8:27b-mlx`, a smaller non-thinking tool model, or an API route; do not bypass the check |
| Official Qwen tag reports an identity mismatch | That exact tag is reserved for the release-qualified immutable digest, so it cannot fall back to Compatibility mode | Remove the mismatched tag and pull the documented official model again, choose a differently tagged compatible local model, or use an API provider |
| Ollama refused | The version is below 0.33.2, outside the qualified 0.33.x series, prerelease/malformed, or the executable signature, team, path, model store, PID, or listener could not be proven | For a newer series, install a Fulmar release that qualifies it or restore supported Ollama 0.33.x; otherwise reinstall the official app, restart Fulmar, and do not weaken verification |
| DeepSeek authentication error | Missing, invalid, or no-longer-valid Keychain credential | Replace the key through **Models & Providers** |
| DeepSeek quota/credit error | The service recognized the route but the account cannot run the request | Add test credit/quota or keep using the local route; do not label the live test passed |
| Keychain prompt after replacing a private build | The signing identity changed or a legacy credential has no trusted metadata | Follow the in-app Move and Verify/replacement guidance; local Ollama should not need Keychain |
| Page retrieval unavailable | The exact-page tool is blocked, unavailable, or was not approved | Approve a specific public HTTPS page or use the confirmed system-browser handoff |
| Thermal Eco mode | macOS reports sustained local pressure | Let the request finish at the reduced cap, allow the enforced rest, or select Fast for qualified Qwen. Compatibility is already fixed at 2K output |

## Report a problem safely

Read `SUPPORT.md`, `SECURITY.md`, `docs/KNOWN_LIMITATIONS.md`, `docs/SUPPORT_MATRIX.md`,
`docs/TROUBLESHOOTING.md`, and `docs/BUG_REPORT_CHECKLIST.md`. Include the exact
Fulmar version/build, macOS version, Apple chip/RAM, provider boundary, model tag, and
non-secret reproduction. Use the app's sanitized Diagnostics report and inspect it
before attaching it. Never post credentials, prompts, workspace content, private
endpoint URLs, or unreviewed logs.
