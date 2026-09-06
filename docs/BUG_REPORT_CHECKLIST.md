# Bug-report diagnostic checklist

Use this before opening a GitHub issue for Fulmar (unofficial software; not supported by
DeepSeek, OpenAI, Anthropic or Ollama). Security problems must **not** go into a public
issue — use GitHub private vulnerability reporting as described in `SECURITY.md`.

## 1. Identify the exact build

- [ ] Fulmar version and build from **About Fulmar** or the Diagnostics report
      (for the preview: `1.2.36 (156)`), and whether you built it yourself or received
      a binary (from where).
- [ ] macOS version and build (`sw_vers`), chip and unified memory (`About This Mac`).
- [ ] If you built from source: the Git tag/commit, `swift --version`, `semgrep --version`
      (must be 1.135.0), and whether `zsh scripts/bootstrap-source-checkout.sh` and
      `make runtime-inventory-verify` passed.

## 2. Identify the route

- [ ] Which boundary: **On this Mac** (Ollama), **Local network** (your own endpoint),
      **DeepSeek API**, **OpenAI**, **Anthropic**, or a custom cloud endpoint.
- [ ] Model label as shown in the selector (for Ollama also `ollama --version` and the
      output of `ollama list` for that model only).
- [ ] Whether Compatibility mode was in use, and which profile (Fast/Balanced/Deep) if
      the qualified Qwen route was selected.
- [ ] Never include the credential, the private endpoint URL query, or the account.

## 3. Reproduce with disposable content

- [ ] The smallest exact sequence of steps, using a throwaway workspace and prompt.
- [ ] Expected result and actual result, with the exact non-secret error text.
- [ ] Whether it reproduces after **Restart Local Services**, after quitting and
      relaunching, and (for local models) after `ollama list` confirms the model.
- [ ] Thermal state at the time if relevant (Eco mode shown? fans at maximum?).

## 4. Collect evidence safely

- [ ] Open **Diagnostics** → copy the sanitized support report. **Read it.** Remove
      anything private that the pattern-based redaction missed before attaching.
- [ ] Do not attach Harness backups, `~/.dsh`, workspace files, raw logs, screenshots
      containing prompts, or credentials.
- [ ] For build/bootstrap failures, attach only the failing command and its last
      50 lines with any absolute home paths replaced by `~`.

## 5. Check known behaviour first

- [ ] `docs/KNOWN_LIMITATIONS.md` and `docs/SUPPORT_MATRIX.md` — is the configuration
      qualified, protocol-simulated, untested or unsupported?
- [ ] `docs/TROUBLESHOOTING.md` — is there a documented cause?
- [ ] A provider quota/credit error, a refused non-official Ollama build, or a refused
      thinking-capable model is expected behaviour, not a defect.

## 6. File the issue

- [ ] Use the **Bug report** template and complete the safety checkboxes truthfully.
- [ ] One problem per issue; link related issues instead of merging them.
