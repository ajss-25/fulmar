# Fulmar

Fulmar is an independent macOS desktop client under active development for using DeepSeek Harness with local language models and optional remote model providers.

## Project status

> **Pre-release — active qualification**

This repository currently contains only the public project foundation. Fulmar's application source and downloadable builds have not yet been published.

The app is undergoing reliability, security, privacy, performance, accessibility, installation, and rollback qualification. There is currently no supported public download, and Fulmar should not be represented as production-ready.

## Intended direction

Fulmar is being designed to provide:

- a native macOS home for DeepSeek Harness;
- private on-device workflows using compatible local models through Ollama;
- optional, explicit use of supported remote model providers;
- visible model and data-boundary controls;
- agent workspaces, task history, schedules, skills, MCP tools, recovery, and diagnostics;
- thermal and resource safeguards for sustained local inference.

This list describes the intended product direction, not a compatibility or release guarantee.

## Downloads

No public binary is available yet.

When a qualified release is ready, downloads will be published as immutable, versioned GitHub release assets with SHA-256 checksums. A general macOS download will not be advertised until the exact artifact has completed Developer ID signing, notarisation, Gatekeeper, clean-install, permissions, provider, local-model, and rollback checks.

Do not download Fulmar binaries offered by third parties or follow instructions that bypass macOS security controls.

## Security

Please do not place credentials, API keys, private prompts, personal paths, model data, or vulnerability details in public issues.

The public vulnerability-reporting process will be enabled before the first supported release. Until then, this repository does not accept operational security reports for a published product because no public product has been released.

## Contributing

The repository is not yet accepting application-code contributions. Contribution guidance will be finalised alongside the source release, project licence, security policy, and continuous-integration requirements.

## Licence

No open-source project licence has been selected yet. Unless and until a `LICENSE` file is published, no permission is granted to copy, modify, redistribute, or create derivative works from future Fulmar source code.

## Independence and trademarks

Fulmar is an independent project and is not affiliated with or endorsed by DeepSeek, Alibaba/Qwen, Ollama, Apple, OpenAI, Anthropic, or other model and platform providers. Product names and trademarks belong to their respective owners.
