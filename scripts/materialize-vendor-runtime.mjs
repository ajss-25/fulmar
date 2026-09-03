#!/usr/bin/env node

import { constants } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readdir,
  readlink,
  realpath,
  rename,
  rm,
  stat,
  writeFile
} from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const MAX_JSON_BYTES = 2 * 1024 * 1024;
const MAX_PATCH_BYTES = 512 * 1024;
const MAX_TREE_ENTRIES = 100_000;

function fail(message) {
  throw new Error(`Fulmar runtime materialization failed: ${message}`);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

async function readRegular(path, maximumBytes = MAX_JSON_BYTES) {
  const before = await lstat(path, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n
      || before.size < 1n || before.size > BigInt(maximumBytes)) {
    fail(`unsafe regular file: ${path}`);
  }
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino
        || opened.size !== before.size || opened.mtimeNs !== before.mtimeNs) {
      fail(`file changed while opening: ${path}`);
    }
    return { bytes: await handle.readFile(), mode: Number(before.mode & 0o777n) };
  } finally {
    await handle.close();
  }
}

function parseJSON(bytes, label) {
  let value;
  try { value = JSON.parse(bytes.toString("utf8")); }
  catch { fail(`${label} is not valid JSON`); }
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} is not an object`);
  return value;
}

function assertHash(bytes, expected, label) {
  const actual = sha256(bytes);
  if (actual !== expected) fail(`${label} checksum mismatch: expected ${expected}, found ${actual}`);
}

function replaceExactlyOnce(text, before, after, label) {
  const first = text.indexOf(before);
  if (first < 0 || text.indexOf(before, first + before.length) >= 0) {
    fail(`${label} patch anchor was absent or ambiguous`);
  }
  return `${text.slice(0, first)}${after}${text.slice(first + before.length)}`;
}

async function writeAtomic(path, bytes, mode) {
  const temporary = join(dirname(path), `.${randomUUID()}.fulmar-patch`);
  try {
    await writeFile(temporary, bytes, { flag: "wx", mode: 0o600 });
    await chmod(temporary, mode);
    await rename(temporary, path);
  } catch (error) {
    await rm(temporary, { force: true }).catch(() => {});
    throw error;
  }
}

function patchDSHManifest(bytes) {
  const manifest = parseJSON(bytes, "upstream DSH manifest");
  if (manifest.name !== "@deepseek-ai/dsh" || manifest.version !== "0.1.1-rc.1"
      || !manifest.dependencies || typeof manifest.dependencies !== "object"
      || Array.isArray(manifest.dependencies)
      || Object.keys(manifest.dependencies).some((name) => name.startsWith("@local-harness/"))) {
    fail("upstream DSH manifest identity or dependency closure changed");
  }
  manifest.dependencies = {
    "@local-harness/dsh-credentials-keychain": "1.0.3",
    ...manifest.dependencies
  };
  return Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, "utf8");
}

const DEEPSEEK_README_UPSTREAM = "DeepSeek request identity is separate from app attribution. After credential resolution, every provider request carries `x-deepseek-harness-user-id` with the stable anonymous id from [`@deepseek-ai/dsh-anonymous-user-id`](../../identity/anonymous-user-id/README.md); a request carrying `GenerateOptions.sessionId` also sends that exact value as `x-deepseek-harness-session-id`, while a direct call without a session omits the session header. Both headers go to the resolved `baseURL`, including a configured gateway, and remain outside the request body and model-visible content.";
const DEEPSEEK_README_PATCHED = "**Fulmar privacy patch (revision 1):** this bundled distribution intentionally\nomits upstream's stable `x-deepseek-harness-user-id` and internal\n`x-deepseek-harness-session-id`. It neither imports nor calls\n`@deepseek-ai/dsh-anonymous-user-id`; only the shared product/version `User-Agent`\nand protocol-required headers remain. Fulmar's guarded Fetch boundary strips\nboth identifier names again if a future adapter update accidentally reintroduces them.\nSee Fulmar's vendored-patch register and qualification evidence before upgrading\nthis package.";
const DEEPSEEK_README_ZH_UPSTREAM = "DeepSeek 请求身份独立于应用归因。凭据解析成功后，每个提供方请求都会通过 `x-deepseek-harness-user-id` 携带来自 [`@deepseek-ai/dsh-anonymous-user-id`](../../identity/anonymous-user-id/README.zh.md) 的稳定匿名 id；携带 `GenerateOptions.sessionId` 的请求还会通过 `x-deepseek-harness-session-id` 发送该确切值，缺少会话的直接调用则省略会话标头。两个标头都会发送至解析后的 `baseURL`（包括已配置的 gateway），且不会进入请求正文或模型可见内容。";
const DEEPSEEK_README_ZH_PATCHED = "**Fulmar 隐私补丁（修订版 1）：**此捆绑版本有意省略上游稳定的\n`x-deepseek-harness-user-id` 和内部 `x-deepseek-harness-session-id`。它既不导入也不调用\n`@deepseek-ai/dsh-anonymous-user-id`；仅保留共享的产品／版本 `User-Agent` 与协议必需标头。\nFulmar 的受保护 Fetch 边界还会再次移除这两个标头名称，以防未来适配器升级意外重新引入它们。\n升级此软件包前，请查看应用级 vendored-patch 登记与资格测试证据。";

function patchDeepSeekRuntime(bytes) {
  let text = bytes.toString("utf8");
  const replacements = [
    ['import { getOrCreateAnonymousUserId } from "@deepseek-ai/dsh-anonymous-user-id";\n', ""],
    ["\t\t\tconst userId = this.config.resolveUserId();\n", ""],
    ["this.request(options, watchdog.signal, connection, apiKey, userId, attachments, () => {", "this.request(options, watchdog.signal, connection, apiKey, attachments, () => {"],
    ["async *request(options, signal, connection, apiKey, userId, attachments, onComment) {", "async *request(options, signal, connection, apiKey, attachments, onComment) {"],
    ["\t\t\t\"x-deepseek-harness-user-id\": String(userId),\n", ""],
    ["\t\t\t...options.sessionId !== void 0 ? { \"x-deepseek-harness-session-id\": String(options.sessionId) } : {},\n", ""],
    ["\tlet userId;\n\tconst resolveUserId = () => userId ??= getOrCreateAnonymousUserId();\n", ""],
    ["\t\tresolveApiKey,\n\t\tresolveUserId,\n", "\t\tresolveApiKey,\n"],
    [
      "\t\t\t\tif (call.id !== void 0) block.callId = call.id;\n\t\t\t\tif (call.function?.name !== void 0) block.name = call.function.name;\n",
      "\t\t\t\tif (block.callId === void 0 && typeof call.id === \"string\" && call.id.length > 0) block.callId = call.id;\n\t\t\t\tif (block.name === void 0 && typeof call.function?.name === \"string\" && call.function.name.length > 0) block.name = call.function.name;\n"
    ]
  ];
  for (const [before, after] of replacements) {
    text = replaceExactlyOnce(text, before, after, "DeepSeek provider runtime");
  }
  return Buffer.from(text, "utf8");
}

function patchDeepSeekTypes(bytes) {
  let text = bytes.toString("utf8");
  text = replaceExactlyOnce(
    text,
    "import type { AnonymousUserId } from '@deepseek-ai/dsh-anonymous-user-id';\n",
    "",
    "DeepSeek provider types"
  );
  text = replaceExactlyOnce(
    text,
    "    /** Resolve the harness-home anonymous id shared with telemetry and feedback. */\n    resolveUserId: () => AnonymousUserId;\n",
    "",
    "DeepSeek provider types"
  );
  return Buffer.from(text.endsWith("\n") ? text : `${text}\n`, "utf8");
}

function patchDeepSeekManifest(bytes) {
  const manifest = parseJSON(bytes, "upstream DeepSeek provider manifest");
  if (manifest.name !== "@deepseek-ai/dsh-llm-deepseek" || manifest.version !== "0.1.1-rc.1"
      || manifest.peerDependencies?.["@deepseek-ai/dsh-anonymous-user-id"] !== "^0.1.1-rc.1"
      || manifest.devDependencies?.["@deepseek-ai/dsh-anonymous-user-id"] !== "^0.1.1-rc.1"
      || Object.hasOwn(manifest, "localHarnessPatch")) {
    fail("upstream DeepSeek provider manifest identity or privacy dependency changed");
  }
  delete manifest.peerDependencies["@deepseek-ai/dsh-anonymous-user-id"];
  delete manifest.devDependencies["@deepseek-ai/dsh-anonymous-user-id"];
  manifest.localHarnessPatch = {
    revision: 2,
    purpose: "omit stable installation and internal session identifiers, and preserve the first non-empty streamed tool-call identity"
  };
  return Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, "utf8");
}

const PI_AI_NO_AUTH_HELPER = `function explicitlyUnauthenticated(headers) {
    const required = new Set(["authorization", "x-api-key", "cf-aig-authorization"]);
    for (const [key, value] of Object.entries(headers ?? {})) {
        const normalized = key.toLowerCase();
        if (!required.has(normalized))
            continue;
        if (value !== null)
            return false;
        required.delete(normalized);
    }
    return required.size === 0;
}`;

function patchPiAIOpenAIClientNoAuth(bytes) {
  let text = bytes.toString("utf8");
  text = replaceExactlyOnce(
    text,
    `    return false;\n}\nfunction getClientApiKey(provider, apiKey, headers) {`,
    `    return false;\n}\n${PI_AI_NO_AUTH_HELPER}\nfunction getClientApiKey(provider, apiKey, headers) {`,
    "pi-ai OpenAI client explicit no-auth helper"
  );
  text = replaceExactlyOnce(
    text,
    `    if (hasHeader(headers, "authorization") || hasHeader(headers, "cf-aig-authorization"))\n        return "unused";\n    throw new Error(\`No API key for provider: \${provider}\`);`,
    `    if (hasHeader(headers, "authorization") || hasHeader(headers, "cf-aig-authorization"))\n        return "unused";\n    if (explicitlyUnauthenticated(headers))\n        return "unused";\n    throw new Error(\`No API key for provider: \${provider}\`);`,
    "pi-ai OpenAI client explicit no-auth admission"
  );
  return Buffer.from(text.endsWith("\n") ? text : `${text}\n`, "utf8");
}

function patchPiAIAnthropicClientNoAuth(bytes) {
  let text = bytes.toString("utf8");
  text = replaceExactlyOnce(
    text,
    `    return false;\n}\nfunction assertRequestAuth(provider, apiKey, headers) {`,
    `    return false;\n}\n${PI_AI_NO_AUTH_HELPER}\nfunction assertRequestAuth(provider, apiKey, headers) {`,
    "pi-ai Anthropic client explicit no-auth helper"
  );
  text = replaceExactlyOnce(
    text,
    `        return;\n    }\n    throw new Error(\`No API key for provider: \${provider}\`);\n}\nconst ANTHROPIC_MESSAGE_EVENTS`,
    `        return;\n    }\n    if (explicitlyUnauthenticated(headers))\n        return;\n    throw new Error(\`No API key for provider: \${provider}\`);\n}\nconst ANTHROPIC_MESSAGE_EVENTS`,
    "pi-ai Anthropic client explicit no-auth admission"
  );
  return Buffer.from(text.endsWith("\n") ? text : `${text}\n`, "utf8");
}

const PI_AI_ADAPTER_NO_AUTH_HELPERS = `const unauthenticatedPrivateOrigins = new BlockList();
unauthenticatedPrivateOrigins.addAddress("::1", "ipv6");
unauthenticatedPrivateOrigins.addSubnet("fc00::", 7, "ipv6");
/** A DNS-free literal loopback/RFC1918/ULA URL eligible for explicit no-auth. */
function isUnauthenticatedPrivateOrigin(raw) {
\tif (typeof raw !== "string" || raw.length === 0) return false;
\tlet url;
\ttry {
\t\turl = new URL(raw);
\t} catch {
\t\treturn false;
\t}
\tif (url.protocol !== "http:" && url.protocol !== "https:") return false;
\tif (url.username.length > 0 || url.password.length > 0 || url.search.length > 0 || url.hash.length > 0) return false;
\tconst authorityStart = raw.indexOf("://") + 3;
\tif (authorityStart < 3) return false;
\tconst authority = raw.slice(authorityStart).split(/[/?#]/u, 1)[0];
\tif (authority.length === 0 || authority.includes("@")) return false;
\tlet host;
\tif (authority.startsWith("[")) {
\t\tconst close = authority.indexOf("]");
\t\tif (close < 0 || !/^:\\d+$/u.test(authority.slice(close + 1)) && authority.slice(close + 1) !== "") return false;
\t\thost = authority.slice(1, close);
\t} else {
\t\tconst parts = authority.split(":");
\t\tif (parts.length > 2 || parts.length === 2 && !/^\\d+$/u.test(parts[1])) return false;
\t\thost = parts[0];
\t}
\tconst family = isIP(host);
\tif (family === 4) {
\t\tconst parts = host.split(".");
\t\tif (parts.length !== 4 || parts.some((part) => !/^(?:0|[1-9]\\d{0,2})$/u.test(part) || Number(part) > 255)) return false;
\t\tconst [a, b] = parts.map(Number);
\t\treturn a === 127 || a === 10 || a === 192 && b === 168 || a === 172 && b >= 16 && b <= 31;
\t}
\treturn family === 6 && unauthenticatedPrivateOrigins.check(host, "ipv6");
}
/** Anthropic's SDK appends \`v1/messages\`; a base already ending in v1 doubles it. */
function endsInVersionOne(raw) {
\ttry {
\t\tconst last = new URL(raw).pathname.split("/").filter(Boolean).at(-1);
\t\treturn last !== void 0 && decodeURIComponent(last).toLowerCase() === "v1";
\t} catch {
\t\treturn false;
\t}
}`;

function patchPiAIAdapterRuntime(bytes) {
  let text = bytes.toString("utf8");
  const replacements = [
    ['import { resolve } from "node:path";\n', 'import { resolve } from "node:path";\nimport { BlockList, isIP } from "node:net";\n'],
    [
      `function requestHeaders(headers) {
\tconst attribution = attributionHeaders();
\tconst reserved = new Set(Object.keys(attribution).map((name) => name.toLowerCase()));
\treturn {
\t\t...Object.fromEntries(Object.entries(headers ?? {}).filter(([name]) => !reserved.has(name.toLowerCase()))),
\t\t...attribution
\t};
}`,
      `function requestHeaders(headers, unauthenticated = false) {
\tconst attribution = attributionHeaders();
\tconst reserved = new Set(Object.keys(attribution).map((name) => name.toLowerCase()));
\treturn {
\t\t...Object.fromEntries(Object.entries(headers ?? {}).filter(([name]) => !reserved.has(name.toLowerCase()))),
\t\t...attribution,
\t\t...unauthenticated ? {
\t\t\tauthorization: null,
\t\t\t"x-api-key": null,
\t\t\t"cf-aig-authorization": null
\t\t} : {}
\t};
}`
    ],
    ["\t\t\t\t\theaders: requestHeaders(profile.headers)\n", "\t\t\t\t\theaders: requestHeaders(profile.headers, profile.unauthenticated)\n"],
    [
      `function profileOptions(profile, reasoning, apiKey) {
\tconst enabledReasoning = reasoning === "off" ? void 0 : reasoning;
\treturn {
\t\t...apiKey === void 0 ? {} : { apiKey },`,
      `function profileOptions(profile, reasoning, apiKey) {
\tconst enabledReasoning = reasoning === "off" ? void 0 : reasoning;
\t// An explicit empty override selects the dedicated keyless auth method
\t// before pi-ai can inspect a stored record or ambient provider credential.
\t// Protocol clients treat it as absent, and the complete null-header
\t// tombstone proves that this is the reviewed no-auth path.
\tconst effectiveApiKey = profile.unauthenticated ? "" : apiKey;
\treturn {
\t\t...effectiveApiKey === void 0 ? {} : { apiKey: effectiveApiKey },`
    ],
    ['\tapiKeyEnv: z.string().role("credential-ref"),\n', '\tapiKeyEnv: z.string().role("credential-ref"),\n\tunauthenticated: z.boolean(),\n'],
    ["const Config = z.object({ providers: z.dict(profile).default({}) });", `const Config = z.object({ providers: z.dict(profile).default({}) });\n${PI_AI_ADAPTER_NO_AUTH_HELPERS}`],
    [
      '\t\tif (source.displayName !== void 0 && source.displayName.length === 0) throw new Error(`llm-pi-ai: provider "${provider}" has an empty displayName`);\n',
      '\t\tif (source.displayName !== void 0 && source.displayName.length === 0) throw new Error(`llm-pi-ai: provider "${provider}" has an empty displayName`);\n\t\tif (source.api === "anthropic-messages" && source.baseURL !== void 0 && endsInVersionOne(source.baseURL)) throw new Error(`llm-pi-ai: provider "${provider}" uses Anthropic Messages, so baseURL must stop before /v1 because the SDK appends /v1/messages`);\n\t\tif (source.unauthenticated === true) {\n\t\t\tif (source.apiKeyEnv !== void 0) throw new Error(`llm-pi-ai: provider "${provider}" cannot combine unauthenticated mode with apiKeyEnv`);\n\t\t\tif (!isUnauthenticatedPrivateOrigin(source.baseURL)) throw new Error(`llm-pi-ai: provider "${provider}" may use unauthenticated mode only with a literal loopback, RFC1918, or IPv6 ULA baseURL`);\n\t\t\tif (Object.keys(source.headers ?? {}).length !== 0) throw new Error(`llm-pi-ai: provider "${provider}" cannot combine unauthenticated mode with custom headers`);\n\t\t}\n'
    ],
    [
      "\t\tconst { apiKeyEnv, retryPolicy, models: _models, displayName: _displayName, ...rest } = source;\n",
      "\t\tconst { apiKeyEnv, unauthenticated, retryPolicy, models: _models, displayName: _displayName, ...rest } = source;\n"
    ],
    [
      "\t\t\t...apiKeyEnv === void 0 ? {} : { apiKeyEnv: credentialRef(apiKeyEnv) },\n",
      "\t\t\t...apiKeyEnv === void 0 ? {} : { apiKeyEnv: credentialRef(apiKeyEnv) },\n\t\t\t...unauthenticated === true ? { unauthenticated: true } : {},\n"
    ],
    [
      `function routeAuth(spec, catalog) {
\tif (catalog === void 0) return { apiKey: harnessApiKeyAuth(spec.displayName) };
\tif (catalog.auth.apiKey !== void 0 || !spec.namesCredential) return catalog.auth;`,
      `function routeAuth(spec, catalog) {
\t// Explicit no-auth must not inherit a same-named catalog provider's stored
\t// or ambient credential resolution. The adapter supplies an empty override
\t// so Models selects this method without reading either credential source.
\tif (spec.unauthenticated) return { apiKey: harnessApiKeyAuth(spec.displayName) };
\tif (catalog === void 0) return { apiKey: harnessApiKeyAuth(spec.displayName) };
\tif (catalog.auth.apiKey !== void 0 || !spec.namesCredential) return catalog.auth;`
    ],
    [
      "\n\t\t\t\tnamesCredential: apiKeyEnv !== void 0\n\t\t\t})\n",
      "\n\t\t\t\tnamesCredential: apiKeyEnv !== void 0,\n\t\t\t\tunauthenticated: unauthenticated === true\n\t\t\t})\n"
    ]
  ];
  for (const [before, after] of replacements) {
    text = replaceExactlyOnce(text, before, after, "pi-ai adapter explicit no-auth");
  }
  return Buffer.from(text.endsWith("\n") ? text : `${text}\n`, "utf8");
}

function patchPiAIConfigTypes(bytes) {
  const text = replaceExactlyOnce(
    bytes.toString("utf8"),
    "    /** Credential reference (environment-variable name) resolved per request through `ctx.credentials`. */\n    apiKeyEnv?: string;\n",
    "    /** Credential reference (environment-variable name) resolved per request through `ctx.credentials`. */\n    apiKeyEnv?: string;\n    /**\n     * Explicitly send no API-key authentication. Mutually exclusive with\n     * `apiKeyEnv` and all custom headers, and accepted only for a literal\n     * loopback, RFC1918, or IPv6 ULA base URL.\n     */\n    unauthenticated?: boolean;\n",
    "pi-ai adapter no-auth type"
  );
  return Buffer.from(text.endsWith("\n") ? text : `${text}\n`, "utf8");
}

function patchDocumentation(bytes, replacements, label) {
  let text = bytes.toString("utf8");
  for (const [before, after] of replacements) {
    text = replaceExactlyOnce(text, before, after, label);
  }
  return Buffer.from(text.endsWith("\n") ? text : `${text}\n`, "utf8");
}

function patchPiAIReadmeEnglish(bytes) {
  return patchDocumentation(bytes, [
    [
      "Omitting it leaves the route unauthenticated, which for an installed catalog route means pi-ai's provider-native ambient discovery; a configured reference that resolves to nothing fails the request with `MISSING_CREDENTIAL` instead, because falling through would authenticate with whatever unrelated key the environment happens to hold. One credential serves every model on its route.",
      "Omitting it does not assert that a request is unauthenticated: an installed catalog route may still use pi-ai's provider-native stored or ambient discovery. A configured reference that resolves to nothing fails the request with `MISSING_CREDENTIAL` instead, because falling through would authenticate with whatever unrelated key the environment happens to hold. To deliberately send no API-key authentication, set `unauthenticated: true`; that explicit mode is accepted only for a literal loopback, RFC1918, or IPv6 ULA base URL, cannot be combined with `apiKeyEnv` or custom headers, and bypasses stored and ambient credential resolution. One credential serves every model on its route."
    ],
    [
      "A profile naming no credential at all — and only that case — defers to pi-ai's ambient discovery.",
      "A profile that omits both `apiKeyEnv` and `unauthenticated: true` defers to pi-ai's stored and ambient discovery. Explicit `unauthenticated: true` instead selects a dedicated keyless route before pi-ai can inspect either source."
    ],
    [
      "Supported profile fields are `apiKeyEnv`, `displayName`, `api`, `baseURL`, `models`, `modelOverrides`, `compat`, `defaultContextWindow`, `defaultMaxTokens`, `defaultInput`, `headers`, `reasoning`, `thinkingBudgets`, `cacheRetention`, `transport`, `timeoutMs`, `websocketConnectTimeoutMs`, `streamIdleTimeoutMs`, `maxRequestImageBytes`, and `retryPolicy`.",
      "Supported profile fields are `apiKeyEnv`, `unauthenticated`, `displayName`, `api`, `baseURL`, `models`, `modelOverrides`, `compat`, `defaultContextWindow`, `defaultMaxTokens`, `defaultInput`, `headers`, `reasoning`, `thinkingBudgets`, `cacheRetention`, `transport`, `timeoutMs`, `websocketConnectTimeoutMs`, `streamIdleTimeoutMs`, `maxRequestImageBytes`, and `retryPolicy`. `unauthenticated: true` is mutually exclusive with both `apiKeyEnv` and the complete `headers` dict, so an unreviewed credential spelling cannot slip through a nominally keyless route."
    ],
    [
      "A route naming no credential at all resolves as configured-but-keyless and leaves the requirement to the protocol, which is where it actually lives.",
      "A route that omits both authentication fields leaves the requirement to pi-ai's provider-native stored or ambient discovery. Explicit `unauthenticated: true` is different: it bypasses those sources even if the route ID collides with an installed catalog provider."
    ],
    [
      "- **An unauthenticated route depends on its protocol** — naming no credential resolves the route as configured-but-keyless, but pi-ai's OpenAI-compatible implementation still requires an API key or an `Authorization` header, so a keyless local server needs a placeholder credential referenced by `apiKeyEnv` or an `Authorization` entry in `headers`.",
      "- **Explicit no-auth is deliberately narrow** — use `unauthenticated: true` only for a literal loopback, RFC1918, or IPv6 ULA endpoint. It rejects `apiKeyEnv` and every custom header, bypasses stored and ambient credentials even when the route ID matches a catalog provider, and installs only the protocol-level null authentication tombstones. Omitting both authentication fields retains pi-ai's normal stored and ambient discovery instead."
    ]
  ], "pi-ai English explicit no-auth documentation");
}

function patchPiAIReadmeChinese(bytes) {
  return patchDocumentation(bytes, [
    [
      "省略它会让该路由处于未认证状态；对已安装 catalog 路由而言，这意味着交给 pi-ai 的提供方原生环境发现。已配置却解析不出任何值的引用则相反，会让请求以 `MISSING_CREDENTIAL` 失败，因为放行下去就会用环境里恰好持有的某个无关密钥完成认证。一条凭据服务该路由下的全部模型。",
      "省略它并不表示请求一定未认证：已安装的 catalog 路由仍可能使用 pi-ai 的提供方原生存储凭据或环境发现。已配置却解析不出任何值的引用会让请求以 `MISSING_CREDENTIAL` 失败，因为放行下去就会用环境里恰好持有的某个无关密钥完成认证。若要明确不发送 API-key 认证，请设置 `unauthenticated: true`；该模式只接受字面量 loopback、RFC1918 或 IPv6 ULA 基础 URL，不能与 `apiKeyEnv` 或任何自定义标头组合，并且会绕过存储凭据与环境发现。一条凭据服务该路由下的全部模型。"
    ],
    [
      "只有完全没有点名任何凭据的 profile——仅限这一种情况——才交给 pi-ai 的环境发现。",
      "同时省略 `apiKeyEnv` 与 `unauthenticated: true` 的 profile 会交给 pi-ai 的存储凭据和环境发现；明确设置 `unauthenticated: true` 则在 pi-ai 检查这两类来源前选中专用的无密钥路由。"
    ],
    [
      "受支持的 profile 字段是 `apiKeyEnv`、`displayName`、`api`、`baseURL`、`models`、`modelOverrides`、`compat`、`defaultContextWindow`、`defaultMaxTokens`、`defaultInput`、`headers`、`reasoning`、`thinkingBudgets`、`cacheRetention`、`transport`、`timeoutMs`、`websocketConnectTimeoutMs`、`streamIdleTimeoutMs`、`maxRequestImageBytes` 和 `retryPolicy`。",
      "受支持的 profile 字段是 `apiKeyEnv`、`unauthenticated`、`displayName`、`api`、`baseURL`、`models`、`modelOverrides`、`compat`、`defaultContextWindow`、`defaultMaxTokens`、`defaultInput`、`headers`、`reasoning`、`thinkingBudgets`、`cacheRetention`、`transport`、`timeoutMs`、`websocketConnectTimeoutMs`、`streamIdleTimeoutMs`、`maxRequestImageBytes` 和 `retryPolicy`。`unauthenticated: true` 与 `apiKeyEnv` 及整个 `headers` 字典互斥，因此未经审核的凭据标头拼写无法混入名义上的无密钥路由。"
    ],
    [
      "完全没有点名任何凭据的路由会解析为「已配置但无密钥」，把该要求留给协议——那才是它真正所在的位置。",
      "同时省略两个认证字段会保留 pi-ai 原生的存储凭据或环境发现。明确设置 `unauthenticated: true` 则不同：即使路由 ID 与已安装 catalog 提供方冲突，也会绕过这些来源。"
    ],
    [
      "- **未认证路由取决于其协议**：不点名凭据会让路由解析为「已配置但无密钥」，但 pi-ai 的 OpenAI 兼容实现仍要求 API key 或 `Authorization` 标头，因此无鉴权的本地服务需要一个由 `apiKeyEnv` 引用的占位凭据，或在 `headers` 中给出 `Authorization` 条目。",
      "- **明确无认证模式刻意保持狭窄**：只有字面量 loopback、RFC1918 或 IPv6 ULA 端点才可使用 `unauthenticated: true`。该模式拒绝 `apiKeyEnv` 与所有自定义标头；即使路由 ID 与 catalog 提供方相同，也会绕过存储凭据和环境凭据，并且只安装协议层的空认证 tombstone。同时省略两个认证字段则继续使用 pi-ai 的正常存储与环境发现。"
    ]
  ], "pi-ai Chinese explicit no-auth documentation");
}

const PATCHERS = Object.freeze({
  "dsh-local-plugin-bootstrap": patchDSHManifest,
  "deepseek-provider-privacy-readme-en": (bytes) => Buffer.from(
    replaceExactlyOnce(bytes.toString("utf8"), DEEPSEEK_README_UPSTREAM, DEEPSEEK_README_PATCHED, "English privacy documentation"),
    "utf8"
  ),
  "deepseek-provider-privacy-readme-zh": (bytes) => Buffer.from(
    replaceExactlyOnce(bytes.toString("utf8"), DEEPSEEK_README_ZH_UPSTREAM, DEEPSEEK_README_ZH_PATCHED, "Chinese privacy documentation"),
    "utf8"
  ),
  "deepseek-provider-runtime-hardening": patchDeepSeekRuntime,
  "deepseek-provider-privacy-types": patchDeepSeekTypes,
  "deepseek-provider-privacy-manifest": patchDeepSeekManifest,
  "pi-ai-adapter-private-no-auth": patchPiAIAdapterRuntime,
  "pi-ai-adapter-private-no-auth-types": patchPiAIConfigTypes,
  "pi-ai-adapter-private-no-auth-readme-en": patchPiAIReadmeEnglish,
  "pi-ai-adapter-private-no-auth-readme-zh": patchPiAIReadmeChinese,
  "pi-ai-openai-completions-private-no-auth": patchPiAIOpenAIClientNoAuth,
  "pi-ai-openai-responses-private-no-auth": patchPiAIOpenAIClientNoAuth,
  "pi-ai-anthropic-private-no-auth": patchPiAIAnthropicClientNoAuth
});

async function validateReviewManifest(projectRoot, vendorRoot) {
  const manifestPath = join(projectRoot, "Config", "VendorRuntimePatches.json");
  const manifest = parseJSON((await readRegular(manifestPath)).bytes, "runtime patch manifest");
  if (manifest.schemaVersion !== 1 || !Array.isArray(manifest.patches)
      || manifest.patches.length !== Object.keys(PATCHERS).length
      || !Array.isArray(manifest.upstreamTarballs) || manifest.upstreamTarballs.length !== 2) {
    fail("unsupported runtime patch manifest schema");
  }

  const packageBytes = (await readRegular(join(vendorRoot, "package.json"))).bytes;
  assertHash(packageBytes, manifest.runtimePackageSHA256, "reviewed runtime package");
  const rootPackage = parseJSON(packageBytes, "reviewed runtime package");
  if (rootPackage.dependencies?.["@deepseek-ai/dsh"] !== "0.1.1-rc.1") {
    fail("reviewed runtime package no longer pins the qualified DSH version");
  }

  const lockBytes = (await readRegular(join(vendorRoot, "package-lock.json"))).bytes;
  assertHash(lockBytes, manifest.reviewedLockSHA256, "reviewed runtime lock");
  const lock = parseJSON(lockBytes, "reviewed runtime lock");
  const removal = manifest.removedInstallOnlyDependency;
  const dshEntry = lock.packages?.[`node_modules/${removal.package}`];
  if (dshEntry?.dependencies?.[removal.dependency] !== removal.version
      || lock.packages?.[`node_modules/${removal.dependency}`] !== undefined) {
    fail("reviewed lock no longer contains the exact non-registry bootstrap dependency marker");
  }

  const expectedTarballs = new Map(manifest.upstreamTarballs.map((entry) => [entry.package, entry]));
  for (const packageName of ["@deepseek-ai/dsh", "@deepseek-ai/dsh-llm-deepseek"]) {
    const expected = expectedTarballs.get(packageName);
    const actual = lock.packages?.[`node_modules/${packageName}`];
    if (!expected || actual?.version !== expected.version || actual.resolved !== expected.resolved
        || actual.integrity !== expected.integrity || !expected.resolved.startsWith("https://registry.npmjs.org/")) {
      fail(`upstream tarball provenance changed for ${packageName}`);
    }
  }

  const installLock = structuredClone(lock);
  delete installLock.packages[`node_modules/${removal.package}`].dependencies[removal.dependency];
  const installLockBytes = Buffer.from(`${JSON.stringify(installLock, null, 2)}\n`, "utf8");
  assertHash(installLockBytes, manifest.installLockSHA256, "derived install-only lock");

  const seen = new Set();
  for (const patch of manifest.patches) {
    if (!patch || typeof patch.id !== "string" || typeof patch.path !== "string"
        || !/^[a-f0-9]{64}$/u.test(patch.beforeSHA256)
        || !/^[a-f0-9]{64}$/u.test(patch.afterSHA256)
        || !Object.hasOwn(PATCHERS, patch.id) || seen.has(patch.id)
        || isAbsolute(patch.path) || patch.path.split("/").includes("..")) {
      fail("runtime patch manifest contains an invalid or duplicate patch entry");
    }
    seen.add(patch.id);
  }
  if (seen.size !== Object.keys(PATCHERS).length) fail("runtime patch manifest is incomplete");
  return { manifest, packageBytes, installLockBytes };
}

async function patchInstalledTree(nodeModules, review) {
  for (const patch of review.manifest.patches) {
    const path = join(nodeModules, ...patch.path.split("/"));
    const { bytes, mode } = await readRegular(path, MAX_PATCH_BYTES);
    assertHash(bytes, patch.beforeSHA256, `${patch.id} upstream input`);
    const patched = PATCHERS[patch.id](bytes);
    assertHash(patched, patch.afterSHA256, `${patch.id} patched output`);
    await writeAtomic(path, patched, mode);
  }
}

async function verifyPatchedTree(nodeModules, review) {
  for (const patch of review.manifest.patches) {
    const path = join(nodeModules, ...patch.path.split("/"));
    const bytes = (await readRegular(path, MAX_PATCH_BYTES)).bytes;
    assertHash(bytes, patch.afterSHA256, `${patch.id} installed output`);
  }
}

function isContained(root, candidate) {
  const rel = relative(root, candidate);
  return rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel));
}

async function validateInstalledTopology(nodeModules) {
  const root = await realpath(nodeModules);
  const pending = [root];
  let entries = 0;
  while (pending.length > 0) {
    const directory = pending.pop();
    for (const name of await readdir(directory)) {
      entries += 1;
      if (entries > MAX_TREE_ENTRIES) fail("installed dependency tree exceeds the reviewed entry bound");
      const path = join(directory, name);
      const info = await lstat(path);
      if (info.isDirectory()) {
        pending.push(path);
      } else if (info.isSymbolicLink()) {
        const target = await readlink(path);
        let canonicalTarget;
        try { canonicalTarget = await realpath(path); }
        catch { fail(`installed dependency link is dangling or cyclic: ${relative(root, path)}`); }
        if (isAbsolute(target) || !isContained(root, resolve(dirname(path), target))
            || !isContained(root, canonicalTarget)) {
          fail(`installed dependency link escapes the runtime: ${relative(root, path)}`);
        }
      } else if (info.isFile()) {
        if (info.nlink !== 1) fail(`installed dependency file is hard linked: ${relative(root, path)}`);
      } else {
        fail(`installed dependency tree contains a special file: ${relative(root, path)}`);
      }
    }
  }
}

async function main() {
  const [projectArgument, npmArgument] = process.argv.slice(2);
  if (process.argv.length !== 4) fail("expected <project-root> <pinned-npm-cli>");
  const projectRoot = resolve(projectArgument);
  const vendorRoot = join(projectRoot, "VendorRuntime");
  const vendorInfo = await lstat(vendorRoot);
  if (!vendorInfo.isDirectory() || vendorInfo.isSymbolicLink()) fail("VendorRuntime must be a real directory");
  const npmCLI = resolve(npmArgument);
  await readRegular(npmCLI, 16 * 1024 * 1024);
  const review = await validateReviewManifest(projectRoot, vendorRoot);
  const target = join(vendorRoot, "node_modules");

  try {
    const targetInfo = await lstat(target);
    if (!targetInfo.isDirectory() || targetInfo.isSymbolicLink()) fail("existing node_modules is not a real directory");
    await validateInstalledTopology(target);
    await verifyPatchedTree(target, review);
    process.stdout.write("Verified existing patched Fulmar dependency tree.\n");
    return;
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }

  const stage = await mkdtemp(join(vendorRoot, ".fulmar-materialize-"));
  try {
    await chmod(stage, 0o700);
    await writeFile(join(stage, "package.json"), review.packageBytes, { flag: "wx", mode: 0o600 });
    await writeFile(join(stage, "package-lock.json"), review.installLockBytes, { flag: "wx", mode: 0o600 });
    const npmConfiguration = join(stage, ".npmrc");
    const npmGlobalConfiguration = join(stage, ".npmrc-global");
    const npmCache = join(stage, ".npm-cache");
    const npmHome = join(stage, ".home");
    const npmTemporary = join(stage, ".tmp");
    await mkdir(npmHome, { mode: 0o700 });
    await mkdir(npmTemporary, { mode: 0o700 });
    await writeFile(npmConfiguration, [
      "ignore-scripts=true",
      "audit=false",
      "fund=false",
      "registry=https://registry.npmjs.org/",
      "replace-registry-host=never",
      "strict-ssl=true",
      `cache=${npmCache}`,
      ""
    ].join("\n"), { flag: "wx", mode: 0o600 });
    await writeFile(npmGlobalConfiguration, "", { flag: "wx", mode: 0o600 });
    // Do not inherit executable loaders, module search paths, credentials, proxies,
    // custom trust stores, SSH agents, or npm configuration from the caller. The
    // lock contains only public HTTPS registry tarballs with pinned integrity.
    const cleanEnvironment = {
      HOME: npmHome,
      LANG: "C",
      LC_ALL: "C",
      NO_COLOR: "1",
      PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
      TMPDIR: npmTemporary,
      __CF_USER_TEXT_ENCODING: "0x0:0x0"
    };
    const result = spawnSync(process.execPath, [
      npmCLI,
      "ci",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      "--package-lock=true",
      "--replace-registry-host=never",
      "--loglevel=error"
    ], {
      cwd: stage,
      env: {
        ...cleanEnvironment,
        NPM_CONFIG_USERCONFIG: npmConfiguration,
        npm_config_userconfig: npmConfiguration,
        NPM_CONFIG_GLOBALCONFIG: npmGlobalConfiguration,
        npm_config_globalconfig: npmGlobalConfiguration,
        NPM_CONFIG_CACHE: npmCache,
        npm_config_cache: npmCache,
        NPM_CONFIG_REGISTRY: "https://registry.npmjs.org/",
        npm_config_registry: "https://registry.npmjs.org/",
        NPM_CONFIG_IGNORE_SCRIPTS: "true",
        npm_config_ignore_scripts: "true",
        NPM_CONFIG_AUDIT: "false",
        npm_config_audit: "false",
        NPM_CONFIG_FUND: "false",
        npm_config_fund: "false"
      },
      encoding: "utf8",
      maxBuffer: 4 * 1024 * 1024
    });
    if (result.error) fail(`pinned npm could not start: ${result.error.message}`);
    if (result.status !== 0) {
      fail(`pinned npm ci failed with status ${result.status}; captured npm output was discarded to protect credentials`);
    }
    assertHash((await readRegular(join(stage, "package-lock.json"))).bytes, review.manifest.installLockSHA256, "post-install lock");
    const stagedModules = join(stage, "node_modules");
    const stagedInfo = await stat(stagedModules);
    if (!stagedInfo.isDirectory()) fail("pinned npm did not create node_modules");
    await validateInstalledTopology(stagedModules);
    await patchInstalledTree(stagedModules, review);
    await verifyPatchedTree(stagedModules, review);
    await rename(stagedModules, target);
    process.stdout.write("Materialized the pinned dependency tree and applied thirteen checksum-bound Fulmar patches.\n");
  } finally {
    await rm(stage, { recursive: true, force: true });
  }
}

if (process.argv[1] !== void 0 && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}

export {
  patchDeepSeekRuntime,
  patchPiAIAdapterRuntime,
  patchPiAIConfigTypes,
  patchPiAIReadmeEnglish,
  patchPiAIReadmeChinese,
  patchPiAIOpenAIClientNoAuth,
  patchPiAIAnthropicClientNoAuth
};
