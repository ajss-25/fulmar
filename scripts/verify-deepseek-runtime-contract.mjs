#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";

const root = path.resolve(process.argv[2] ?? path.join(import.meta.dirname, ".."));
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");
const readJSON = (relative) => JSON.parse(read(relative));
const fail = (message) => {
  process.stderr.write(`DeepSeek runtime contract failed: ${message}\n`);
  process.exit(1);
};
const requireText = (source, needle, label) => {
  if (!source.includes(needle)) fail(`${label} is missing ${JSON.stringify(needle)}`);
};

const identity = readJSON("Config/ReleaseIdentity.json");
const expectedVersion = identity.runtime.deepseekHarnessVersion;
const packageRoots = [
  "VendorRuntime/node_modules/@deepseek-ai/dsh-llm-deepseek",
  "VendorRuntime/node_modules/@deepseek-ai/dsh-web-search-deepseek",
  "VendorRuntime/node_modules/@deepseek-ai/dsh-tool-web"
];
for (const packageRoot of packageRoots) {
  const manifest = readJSON(`${packageRoot}/package.json`);
  if (manifest.version !== expectedVersion) {
    fail(`${manifest.name} is ${manifest.version}; reviewed DSH is ${expectedVersion}`);
  }
}

const adapter = read(`${packageRoots[0]}/lib/index.js`);
for (const model of ["deepseek-v4-flash", "deepseek-v4-pro", "deepseek-v4-flash-vision-exp"]) {
  requireText(adapter, `id: "${model}"`, "DeepSeek adapter catalog");
}
for (const retiredDefault of ['id: "deepseek-chat"', 'id: "deepseek-reasoner"']) {
  if (adapter.includes(retiredDefault)) fail(`adapter still exposes retired default ${retiredDefault}`);
}
for (const wireContract of [
  "reasoning_content: reasoning",
  "tool_calls: toolCalls",
  "delta?.reasoning_content",
  "delta?.tool_calls",
  "const resolvedThinking = resolveThinking(options, defaults)",
  'baseURL: config.baseURL ?? environment?.get(BASE_URL_ENV)?.value ?? "https://api.deepseek.com"'
]) {
  requireText(adapter, wireContract, "DeepSeek reasoning/tool wire contract");
}

const search = read(`${packageRoots[1]}/lib/index.js`);
for (const searchContract of [
  'type: "web_search_20250305"',
  'name: "web_search"',
  '"https://api.deepseek.com/anthropic/v1"',
  'model: config.model ?? "deepseek-v4-flash"',
  'credentialRef(config.apiKeyEnv ?? DEFAULT_API_KEY_ENV)'
]) {
  requireText(search, searchContract, "DeepSeek native web-search contract");
}

const preset = read("VendorRuntime/node_modules/@deepseek-ai/dsh/config/agent-presets/standard/agent.cordis.yml");
requireText(preset, "- id: tool-web", "standard agent preset");
requireText(preset, "name: '@deepseek-ai/dsh-tool-web'", "standard agent preset");
requireText(preset, "fetch: false", "standard agent preset");

const basePatch = read("VendorRuntime/node_modules/@deepseek-ai/dsh-base/cordis.patch.yml");
requireText(basePatch, "searchProvider: deepseek-official", "DSH base web composition");
requireText(basePatch, "name: '@deepseek-ai/dsh-web-search-deepseek'", "DSH base web composition");
requireText(basePatch, "apiKeyEnv: DEEPSEEK_API_KEY", "DSH base web composition");

const localPatch = read("Resources/LocalHarness.patch.yml");
requireText(localPatch, "id: credentials-keychain", "Fulmar runtime patch");
requireText(localPatch, "id: client-security-bridge", "Fulmar runtime patch");
requireText(localPatch, "id: fs-confined", "Fulmar runtime patch");
requireText(localPatch, "id: web-fetch-safe", "Fulmar runtime patch");
requireText(localPatch, "name: '@local-harness/dsh-web-fetch-safe'", "Fulmar runtime patch");
requireText(localPatch, "fetchProvider: fulmar-approved-fetch", "Fulmar runtime patch");
requireText(localPatch, "search: false", "Fulmar runtime patch");
requireText(localPatch, "fetch: true", "Fulmar runtime patch");
if (!/- id: web-search-deepseek\s+disabled: true/u.test(localPatch)) {
  fail("Fulmar must not advertise credential-bound DeepSeek search in local sessions");
}
const presetSanitizer = read("scripts/sanitize-agent-presets.mjs");
requireText(presetSanitizer, 'replaceSingleTopLevelRow(composition, "tool-web", approvedWebToolRow)', "Fulmar sanitized agent preset");
requireText(presetSanitizer, '"    search: false"', "Fulmar sanitized agent preset");
requireText(presetSanitizer, '"    fetch: true"', "Fulmar sanitized agent preset");
const securityPreload = read("Resources/RuntimeSecurityPreload.mjs");
requireText(securityPreload, "LOCAL_HARNESS_PROVIDER_ORIGINS", "Fulmar egress preload");
requireText(securityPreload, "com.fulmar.runtime.approved-web-fetch.v1", "Fulmar approved web-fetch boundary");
requireText(securityPreload, "isPublicIPAddress", "Fulmar approved web-fetch boundary");
requireText(securityPreload, "consumeRuntimeAuthenticationInput()", "Fulmar private runtime authentication boundary");
requireText(securityPreload, "fs.fstatSync(0, { bigint: true })", "Fulmar private runtime authentication boundary");
requireText(securityPreload, "fs.closeSync(0)", "Fulmar private runtime authentication boundary");
if (/const\s+(?:token|nonce)\s*=\s*process\.env\.LOCAL_HARNESS_/u.test(securityPreload)) {
  fail("Fulmar runtime authentication must not be sourced from the child environment");
}
const localFetch = read("Resources/DSHPlugins/web-fetch-safe/index.mjs");
requireText(localFetch, "Never retry web access through Bash", "Fulmar approved web-fetch guidance");
requireText(localFetch, 'kind: "ask"', "Fulmar approved web-fetch consent");

process.stdout.write(
  `DeepSeek runtime contract passed for DSH ${expectedVersion}: V4 catalog, thinking/tool replay, future native search compatibility, and Fulmar's approved fetch-only local-session surface are pinned.\n`
);
