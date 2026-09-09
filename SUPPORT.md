# Support

Fulmar is an independent project, not a DeepSeek, OpenAI, Anthropic, Ollama, Alibaba,
or Qwen product. Those projects cannot support this app.

For a reproducible defect, work through `docs/BUG_REPORT_CHECKLIST.md` and
`docs/TROUBLESHOOTING.md`, check `docs/SUPPORT_MATRIX.md` for whether your configuration
is qualified, protocol-simulated, untested or unsupported, then
[open a GitHub issue](https://github.com/ajss-25/fulmar/issues/new/choose) with the Fulmar
version/build, macOS version, selected provider boundary, exact non-secret steps, and
sanitized diagnostics.
Do not paste API keys, prompts, private workspace files, or full unreviewed logs.
Security-sensitive reports belong in
[private vulnerability reporting](https://github.com/ajss-25/fulmar/security/advisories/new)
instead.

Before filing, distinguish the route that failed:

- **On this Mac** requires the official signed Ollama macOS application and an
  installed model; it never requires a DeepSeek API key.
- **DeepSeek API** requires a valid key plus account quota/credit and intentionally
  sends approved task content to DeepSeek's service.
- **Compatible endpoint** failures must name whether the endpoint is loopback, on the
  local network, or in the cloud; never include its credential or private URL query.

Use **Diagnostics** to make a sanitized support report. Review it before attachment.
If the report still contains private material, describe the failure without attaching
the report.

Local model speed, temperature, memory use, and output quality vary by model,
quantization, workload, and hardware. Paid-provider availability, cost, retention,
quota, and terms remain the user's responsibility.
