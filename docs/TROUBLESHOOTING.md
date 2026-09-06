# Troubleshooting — Fulmar 1.2.36 build 156 (v1.2.36-preview.1)

Fulmar is unofficial, independent software; DeepSeek, OpenAI, Anthropic, Ollama and
the Qwen project cannot support it. This guide covers the failures a source-preview
user is most likely to meet. Never paste credentials, prompts, workspace content or
unreviewed logs anywhere while troubleshooting.

## Building from source

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| `build input is not owner-controlled` immediately after checkout | The checkout inherited a group-writable umask such as `002` | Set `umask 022` and make a fresh clone outside iCloud-synchronised folders; do not recursively loosen source permissions |
| `bootstrap-source-checkout.sh` fails downloading Node | No network, a proxy, or a changed `nodejs.org` archive | The script downloads exactly `node-v22.23.1-darwin-arm64` and compares SHA-256 `ef28d8fa…` (archive) and `2e3f1286…` (binary); a mismatch is fail-closed — do not edit the expected hash. Retry on a clean network; a proxy is deliberately ignored |
| `pinned npm ci failed` during materialisation | Registry unreachable, or `VendorRuntime/package-lock.json` was modified | The install runs with an isolated cache against `registry.npmjs.org` only. Restore the exact lock (`git checkout VendorRuntime/package-lock.json`) and rerun; never run `npm ci`/`npm install` yourself in `VendorRuntime` |
| `runtime patch manifest` / `reviewed lock` / `derived install-only lock` hash errors | A file the bootstrap binds by digest was changed | `git status` must be clean for `Config/VendorRuntimePatches.json`, `VendorRuntime/package.json`, `VendorRuntime/package-lock.json` and `VendorRuntime.inventory.json` |
| `Runtime inventory error: … has an extra entry` or `directory changed while scanning` | Something else wrote into `VendorRuntime` (iCloud/FileProvider sync, an editor, a second bootstrap) | Keep the checkout **outside** iCloud Drive/Desktop/Documents sync; wait for sync daemons to settle and rerun `make runtime-inventory-verify` |
| `semgrep --version` is not `1.135.0`, or `make static-security-scan` fails to fetch rules | Wrong Semgrep, or the registry packs drifted | Install exactly `pipx install semgrep==1.135.0`. The scan pins the two registry rule packs by URL, size, SHA-256 and rule count; a changed pack is a deliberate stop, not something to re-pin locally |
| `swift build` reports `no such module 'Testing'` | Using a bare toolchain command outside the gate script | Run `zsh scripts/run-swift-tests.sh` (it selects the SDK and Testing framework paths). For ad-hoc development builds use `source scripts/select-compatible-swift-sdk.sh` first |
| Swift gate stops with a warning | The gate builds with warnings as errors | Fix the warning; do not add `-suppress-warnings` |
| `make frozen-candidate-check` prints `requires an authenticated root watchdog` | The verifier must run under the repository supervisor | `./scripts/run-with-watchdog.sh --seconds 1800 --max-rss-bytes 8589934592 --rss-grace-seconds 15 --emergency-rss-bytes 17179869184 --label "Fulmar frozen-candidate check" -- /usr/bin/make frozen-candidate-check` |
| A usable source build needs initial Keychain authorization | `make private-release` creates/reuses a persistent local signing identity | Review the prompt and reuse **Fulmar Local Signing** for subsequent builds. No paid Apple Developer ID or notarisation is required. Explicit ad-hoc signing is compile/review-only: it cannot satisfy the packaged credential service's identity checks |
| A second `make build` refuses to start (`release lock`) | A previous supervised run left `/private/tmp/LocalHarnessBuild.lock` with a dead owner | The next supervised command reclaims it automatically once the recorded owner PID is dead; if the owner is alive, wait for it |

## Launching the preview app

| Symptom | Meaning | What to do |
| --- | --- | --- |
| macOS says the app "cannot be opened", "is damaged", or that Apple could not verify it | Local signing does not supply an Apple notarisation ticket; damage must also be ruled out | Read [Preview binary and Gatekeeper](PREVIEW_BINARY_GATEKEEPER.md). Prefer building it yourself. Never run `xattr -d`, `spctl --master-disable` or download a copy from an unofficial mirror |
| `credential broker identity is invalid` / `credential broker is unavailable` in a source build | Ad-hoc helper/service requirements differ, or the sandbox cannot inspect the sibling helper from the launch location | Build with `make private-release`, retain the local signing identity, quit older copies and use the reviewed app from `/Applications`. Do not disable the sandbox or signature checks |
| App launches but immediately shows a recovery screen | The saved local model is missing or the Ollama executable failed verification | See the local-model rows below |
| "Keychain prompt after replacing a private build" | The signing identity changed between builds, so the earlier Keychain item's ACL no longer matches | Follow the in-app **Move and Verify** or replacement guidance; local Ollama work needs no Keychain access |
| Menu-bar item not visible | macOS can hide third-party items on crowded menu bars | Use the Dock/window or the Command Center; the item is recreated at most twice per launch without Accessibility access |

## On-device models (Ollama)

| Symptom | Meaning | What to do |
| --- | --- | --- |
| **Local model missing** | The app-owned Ollama service does not report the saved model | Choose **Choose Installed Local Model**, or `ollama pull qwen3.8:27b-mlx` and refresh. Fulmar never downloads weights |
| **Ollama refused** | Version below 0.33.2, a 0.34+ series, a pre-release, or an executable whose signature/team/path/listener could not be proven | Install the official Ollama.app 0.33.x from Ollama; do not weaken verification |
| **Model refused in Compatibility mode** | The model lacks completion/tools, advertises model-specific thinking, has < 8K context, returned malformed metadata, or the Mac lacks 2 × model size + 4 GiB | Use exact `qwen3.8:27b-mlx` (48 GB Mac), a smaller non-thinking tool-capable model, or a cloud route |
| **Identity mismatch on the official Qwen tag** | The `qwen3.8:27b-mlx` tag now points at a different digest than the qualified one | Remove the tag and pull the documented model again, or use a differently tagged model in Compatibility mode |
| Route refused with a memory message on a < 48 GB Mac | The qualified 27B route has a 48 GB floor | Use a smaller Compatibility model or a cloud route; this is an evidence boundary, not a bug |
| Slow first response, fans up, then **Eco mode** | Thermal pressure or four minutes of sustained generation | Let the turn finish; Eco caps later outputs at 2K tokens and rests five seconds between generations. Choose **Fast** for Qwen; improve cooling; serious/critical pressure stops local work with a 90 s / 10 min cooldown |
| Local work blocked with an orange status after a thermal event | Fulmar could not durably persist the return to Normal | Use **Restart Local Services** or Performance Center; cloud routes stay available |
| Two Ollama instances loading models | Your normal Ollama.app service and Fulmar's private child both loaded a model | Stop the unrelated service if duplicate memory use is unwanted; Fulmar never adopts port 11434 |

## Cloud providers

| Symptom | Meaning | What to do |
| --- | --- | --- |
| Saved a DeepSeek key but tasks still run locally | Saving/verifying a credential never switches routes | Select the DeepSeek model, review the destination, choose **Use for New Tasks** |
| **Authentication error** | Missing, invalid or revoked Keychain credential | Replace the key in **Models & Providers** |
| **Quota/credit error** | The provider accepted the route but the account cannot run requests | Add credit/quota; this is not a Fulmar defect and not a passing live test |
| Custom provider "not configured" after saving | The provider/model/limits did not round-trip exactly through DSH | Enter the endpoint's real context and max-output limits (`1,024–16,777,216` and `256–context`), one model per line, and the correct base URL (`…/v1` for OpenAI protocols; stop **before** `/v1` for Anthropic Messages) |
| Custom provider refuses plain `http://` | Only literal loopback/private addresses may use HTTP | Use HTTPS for public origins |
| No-authentication mode rejected | Only literal loopback, RFC 1918 or IPv6-ULA addresses qualify; `localhost` and hostnames do not | Use a literal address or an `apiKeyEnv` reference |
| Page retrieval unavailable | `web_fetch` needs per-page approval; `web_search` is hidden | Approve the exact public HTTPS page or open the link in your browser |

## Data, backups and removal

- Where Fulmar keeps data and how to delete it:
  [Public installation and removal → Uninstall and retained data](PUBLIC_INSTALLATION.md#uninstall-and-retained-data).
- Harness backups are integrity-authenticated, not encrypted, and may contain chats;
  keep them private.
- `~/.ollama` belongs to Ollama and is never part of Fulmar cleanup.

## Collecting diagnostics safely

1. Open **Diagnostics** and copy the sanitized support report.
2. Read it. Redaction is pattern-based; remove anything private that survived.
3. Follow [the bug-report checklist](BUG_REPORT_CHECKLIST.md) and the GitHub issue
   template. Security problems go through private vulnerability reporting
   (`SECURITY.md`), never a public issue.
