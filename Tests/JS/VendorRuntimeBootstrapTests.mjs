import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFile, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  patchDeepSeekRuntime,
  patchPiAIAdapterRuntime,
  patchPiAIAnthropicClientNoAuth,
  patchPiAIConfigTypes,
  patchPiAIReadmeChinese,
  patchPiAIReadmeEnglish,
  patchPiAIOpenAIClientNoAuth
} from "../../scripts/materialize-vendor-runtime.mjs";

const project = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const script = join(project, "scripts", "materialize-vendor-runtime.mjs");
const nodeBootstrap = join(project, "scripts", "fetch-node-runtime.sh");
const npmCLI = join(
  project,
  "VendorRuntime",
  "node-v22.23.1-darwin-arm64",
  "lib",
  "node_modules",
  "npm",
  "bin",
  "npm-cli.js"
);
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const DEEPSEEK_RUNTIME_BEFORE = "bf7fc6a6fca55ce9ae980fc3f39483fb52efadc9e013747a2bd9a475149b7a4f";
const DEEPSEEK_RUNTIME_AFTER = "4a10b1e00676c41e313a4d4c8578840c63711ee69fdeff077f998d5194964e60";

function invoke(root, npm = npmCLI, env = process.env) {
  return spawnSync(process.execPath, [script, root, npm], { encoding: "utf8", env });
}

async function copyRegular(source, destination) {
  await mkdir(dirname(destination), { recursive: true });
  await copyFile(source, destination);
}

async function fixture(includePatchedTree = true) {
  const root = await mkdtemp(join(tmpdir(), "fulmar-vendor-bootstrap."));
  await mkdir(join(root, "Config"), { recursive: true });
  await copyRegular(
    join(project, "Config", "VendorRuntimePatches.json"),
    join(root, "Config", "VendorRuntimePatches.json")
  );
  for (const name of ["package.json", "package-lock.json"]) {
    await copyRegular(join(project, "VendorRuntime", name), join(root, "VendorRuntime", name));
  }
  const review = JSON.parse(await readFile(join(project, "Config", "VendorRuntimePatches.json"), "utf8"));
  if (includePatchedTree) {
    for (const patch of review.patches) {
      await copyRegular(
        join(project, "VendorRuntime", "node_modules", ...patch.path.split("/")),
        join(root, "VendorRuntime", "node_modules", ...patch.path.split("/"))
      );
    }
  }
  return { root, review };
}

test("review manifest binds the lock, exact upstream packages, and every installed patch", async () => {
  const review = JSON.parse(await readFile(join(project, "Config", "VendorRuntimePatches.json"), "utf8"));
  assert.equal(sha256(await readFile(join(project, "VendorRuntime", "package.json"))), review.runtimePackageSHA256);
  assert.equal(sha256(await readFile(join(project, "VendorRuntime", "package-lock.json"))), review.reviewedLockSHA256);
  assert.equal(review.patches.length, 13);
  assert.deepEqual(
    review.upstreamTarballs.map(({ package: name, resolved }) => [name, new URL(resolved).origin]),
    [
      ["@deepseek-ai/dsh", "https://registry.npmjs.org"],
      ["@deepseek-ai/dsh-llm-deepseek", "https://registry.npmjs.org"]
    ]
  );
  for (const patch of review.patches) {
    const installed = await readFile(join(project, "VendorRuntime", "node_modules", ...patch.path.split("/")));
    assert.equal(sha256(installed), patch.afterSHA256, patch.id);
  }
});

test("every pi-ai no-auth transform accepts its exact upstream anchors and rejects anchor drift", () => {
  const adapterUpstream = Buffer.from([
    'import { resolve } from "node:path";\n',
    `function requestHeaders(headers) {
\tconst attribution = attributionHeaders();
\tconst reserved = new Set(Object.keys(attribution).map((name) => name.toLowerCase()));
\treturn {
\t\t...Object.fromEntries(Object.entries(headers ?? {}).filter(([name]) => !reserved.has(name.toLowerCase()))),
\t\t...attribution
\t};
}`,
    "\t\t\t\t\theaders: requestHeaders(profile.headers)\n",
    `function profileOptions(profile, reasoning, apiKey) {
\tconst enabledReasoning = reasoning === "off" ? void 0 : reasoning;
\treturn {
\t\t...apiKey === void 0 ? {} : { apiKey },`,
    '\tapiKeyEnv: z.string().role("credential-ref"),\n',
    "const Config = z.object({ providers: z.dict(profile).default({}) });",
    '\t\tif (source.displayName !== void 0 && source.displayName.length === 0) throw new Error(`llm-pi-ai: provider "${provider}" has an empty displayName`);\n',
    "\t\tconst { apiKeyEnv, retryPolicy, models: _models, displayName: _displayName, ...rest } = source;\n",
    "\t\t\t...apiKeyEnv === void 0 ? {} : { apiKeyEnv: credentialRef(apiKeyEnv) },\n",
    `function routeAuth(spec, catalog) {
\tif (catalog === void 0) return { apiKey: harnessApiKeyAuth(spec.displayName) };
\tif (catalog.auth.apiKey !== void 0 || !spec.namesCredential) return catalog.auth;`,
    "\t\t\t\tnamesCredential: apiKeyEnv !== void 0\n\t\t\t})\n"
  ].join("\n// independent exact upstream anchor\n"));
  const adapterPatched = patchPiAIAdapterRuntime(adapterUpstream).toString("utf8");
  assert.match(adapterPatched, /unauthenticated: unauthenticated === true/u);
  assert.match(adapterPatched, /if \(spec\.unauthenticated\) return/u);
  assert.throws(
    () => patchPiAIAdapterRuntime(Buffer.concat([adapterUpstream, adapterUpstream])),
    /patch anchor was absent or ambiguous/u
  );
  assert.throws(
    () => patchPiAIAdapterRuntime(Buffer.from(adapterUpstream.toString("utf8").replace(
      "\n\t\t\t\tnamesCredential: apiKeyEnv !== void 0\n\t\t\t})\n",
      "\n\t\t\t\t\tnamesCredential: apiKeyEnv !== void 0\n\t\t\t})\n"
    ))),
    /patch anchor was absent or ambiguous/u
  );

  const typeUpstream = Buffer.from(
    "    /** Credential reference (environment-variable name) resolved per request through `ctx.credentials`. */\n    apiKeyEnv?: string;\n"
  );
  assert.match(patchPiAIConfigTypes(typeUpstream).toString("utf8"), /unauthenticated\?: boolean/u);
  assert.throws(
    () => patchPiAIConfigTypes(Buffer.concat([typeUpstream, typeUpstream])),
    /patch anchor was absent or ambiguous/u
  );

  const englishUpstream = Buffer.from([
    "Omitting it leaves the route unauthenticated, which for an installed catalog route means pi-ai's provider-native ambient discovery; a configured reference that resolves to nothing fails the request with `MISSING_CREDENTIAL` instead, because falling through would authenticate with whatever unrelated key the environment happens to hold. One credential serves every model on its route.",
    "A profile naming no credential at all — and only that case — defers to pi-ai's ambient discovery.",
    "Supported profile fields are `apiKeyEnv`, `displayName`, `api`, `baseURL`, `models`, `modelOverrides`, `compat`, `defaultContextWindow`, `defaultMaxTokens`, `defaultInput`, `headers`, `reasoning`, `thinkingBudgets`, `cacheRetention`, `transport`, `timeoutMs`, `websocketConnectTimeoutMs`, `streamIdleTimeoutMs`, `maxRequestImageBytes`, and `retryPolicy`.",
    "A route naming no credential at all resolves as configured-but-keyless and leaves the requirement to the protocol, which is where it actually lives.",
    "- **An unauthenticated route depends on its protocol** — naming no credential resolves the route as configured-but-keyless, but pi-ai's OpenAI-compatible implementation still requires an API key or an `Authorization` header, so a keyless local server needs a placeholder credential referenced by `apiKeyEnv` or an `Authorization` entry in `headers`."
  ].join("\n\n"));
  const englishPatched = patchPiAIReadmeEnglish(englishUpstream).toString("utf8");
  assert.match(englishPatched, /Explicit no-auth is deliberately narrow/u);
  assert.match(englishPatched, /bypasses stored and ambient credentials/u);
  assert.throws(
    () => patchPiAIReadmeEnglish(Buffer.concat([englishUpstream, englishUpstream])),
    /patch anchor was absent or ambiguous/u
  );

  const chineseUpstream = Buffer.from([
    "省略它会让该路由处于未认证状态；对已安装 catalog 路由而言，这意味着交给 pi-ai 的提供方原生环境发现。已配置却解析不出任何值的引用则相反，会让请求以 `MISSING_CREDENTIAL` 失败，因为放行下去就会用环境里恰好持有的某个无关密钥完成认证。一条凭据服务该路由下的全部模型。",
    "只有完全没有点名任何凭据的 profile——仅限这一种情况——才交给 pi-ai 的环境发现。",
    "受支持的 profile 字段是 `apiKeyEnv`、`displayName`、`api`、`baseURL`、`models`、`modelOverrides`、`compat`、`defaultContextWindow`、`defaultMaxTokens`、`defaultInput`、`headers`、`reasoning`、`thinkingBudgets`、`cacheRetention`、`transport`、`timeoutMs`、`websocketConnectTimeoutMs`、`streamIdleTimeoutMs`、`maxRequestImageBytes` 和 `retryPolicy`。",
    "完全没有点名任何凭据的路由会解析为「已配置但无密钥」，把该要求留给协议——那才是它真正所在的位置。",
    "- **未认证路由取决于其协议**：不点名凭据会让路由解析为「已配置但无密钥」，但 pi-ai 的 OpenAI 兼容实现仍要求 API key 或 `Authorization` 标头，因此无鉴权的本地服务需要一个由 `apiKeyEnv` 引用的占位凭据，或在 `headers` 中给出 `Authorization` 条目。"
  ].join("\n\n"));
  const chinesePatched = patchPiAIReadmeChinese(chineseUpstream).toString("utf8");
  assert.match(chinesePatched, /明确无认证模式刻意保持狭窄/u);
  assert.match(chinesePatched, /绕过存储凭据与环境发现/u);
  assert.throws(
    () => patchPiAIReadmeChinese(Buffer.concat([chineseUpstream, chineseUpstream])),
    /patch anchor was absent or ambiguous/u
  );
});

test("DeepSeek streamed tool identity patch is exact and fails closed on byte, hash, or anchor drift", async () => {
  const review = JSON.parse(await readFile(join(project, "Config", "VendorRuntimePatches.json"), "utf8"));
  const runtimePatch = review.patches.find((patch) => patch.id === "deepseek-provider-runtime-hardening");
  assert.ok(runtimePatch);
  assert.equal(runtimePatch.beforeSHA256, DEEPSEEK_RUNTIME_BEFORE);
  assert.equal(runtimePatch.afterSHA256, DEEPSEEK_RUNTIME_AFTER);
  assert.equal(
    sha256(await readFile(join(project, "VendorRuntime", "node_modules", ...runtimePatch.path.split("/")))),
    DEEPSEEK_RUNTIME_AFTER
  );

  const syntheticUpstream = Buffer.from([
    'import { getOrCreateAnonymousUserId } from "@deepseek-ai/dsh-anonymous-user-id";',
    "\t\t\tconst userId = this.config.resolveUserId();",
    "this.request(options, watchdog.signal, connection, apiKey, userId, attachments, () => {",
    "async *request(options, signal, connection, apiKey, userId, attachments, onComment) {",
    "\t\t\t\"x-deepseek-harness-user-id\": String(userId),",
    "\t\t\t...options.sessionId !== void 0 ? { \"x-deepseek-harness-session-id\": String(options.sessionId) } : {},",
    "\tlet userId;",
    "\tconst resolveUserId = () => userId ??= getOrCreateAnonymousUserId();",
    "\t\tresolveApiKey,",
    "\t\tresolveUserId,",
    "\t\t\t\tif (call.id !== void 0) block.callId = call.id;",
    "\t\t\t\tif (call.function?.name !== void 0) block.name = call.function.name;",
    ""
  ].join("\n"));
  const transformed = patchDeepSeekRuntime(syntheticUpstream).toString("utf8");
  assert.match(transformed, /block\.callId === void 0 && typeof call\.id === "string" && call\.id\.length > 0/);
  assert.match(transformed, /block\.name === void 0 && typeof call\.function\?\.name === "string" && call\.function\.name\.length > 0/);
  assert.doesNotMatch(transformed, /if \(call\.id !== void 0\) block\.callId = call\.id/);
  assert.throws(
    () => patchDeepSeekRuntime(Buffer.from(syntheticUpstream.toString("utf8").replace(
      "\t\t\t\tif (call.id !== void 0) block.callId = call.id;\n",
      ""
    ))),
    /patch anchor was absent or ambiguous/
  );
  assert.throws(
    () => patchDeepSeekRuntime(Buffer.from(`${syntheticUpstream.toString("utf8")}\t\t\t\tif (call.id !== void 0) block.callId = call.id;\n\t\t\t\tif (call.function?.name !== void 0) block.name = call.function.name;\n`)),
    /patch anchor was absent or ambiguous/
  );

  const outputDrift = await fixture();
  try {
    const target = join(outputDrift.root, "VendorRuntime", "node_modules", ...runtimePatch.path.split("/"));
    await writeFile(target, Buffer.concat([await readFile(target), Buffer.from("\n// drift\n")]));
    const rejected = invoke(outputDrift.root);
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /deepseek-provider-runtime-hardening installed output checksum mismatch/);
  } finally {
    await rm(outputDrift.root, { recursive: true, force: true });
  }

  const hashDrift = await fixture();
  try {
    const manifestPath = join(hashDrift.root, "Config", "VendorRuntimePatches.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    manifest.patches.find((patch) => patch.id === runtimePatch.id).afterSHA256 = "0".repeat(64);
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    const rejected = invoke(hashDrift.root);
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /deepseek-provider-runtime-hardening installed output checksum mismatch/);
  } finally {
    await rm(hashDrift.root, { recursive: true, force: true });
  }
});

test("existing generated runtime is accepted only when all reviewed patch outputs match", async () => {
  const current = invoke(project);
  assert.equal(current.status, 0, current.stderr);
  assert.match(current.stdout, /Verified existing patched Fulmar dependency tree/u);

  const { root, review } = await fixture();
  try {
    const valid = invoke(root);
    assert.equal(valid.status, 0, valid.stderr);

    const target = join(root, "VendorRuntime", "node_modules", ...review.patches[0].path.split("/"));
    await writeFile(target, "tampered\n");
    const tampered = invoke(root);
    assert.notEqual(tampered.status, 0);
    assert.match(tampered.stderr, /checksum mismatch/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("linked patch outputs and reviewed-lock drift fail before npm can run", async () => {
  const linkedFixture = await fixture();
  try {
    const target = join(
      linkedFixture.root,
      "VendorRuntime",
      "node_modules",
      ...linkedFixture.review.patches[0].path.split("/")
    );
    await rm(target);
    await symlink(join(project, "VendorRuntime", "node_modules", ...linkedFixture.review.patches[0].path.split("/")), target);
    const linked = invoke(linkedFixture.root);
    assert.notEqual(linked.status, 0);
    assert.match(linked.stderr, /installed dependency link escapes the runtime|unsafe regular file/u);
  } finally {
    await rm(linkedFixture.root, { recursive: true, force: true });
  }

  const driftFixture = await fixture();
  try {
    const lockPath = join(driftFixture.root, "VendorRuntime", "package-lock.json");
    const lock = JSON.parse(await readFile(lockPath, "utf8"));
    lock.packages["node_modules/@deepseek-ai/dsh"].dependencies["@local-harness/dsh-credentials-keychain"] = "9.9.9";
    await writeFile(lockPath, `${JSON.stringify(lock, null, 2)}\n`);
    const drifted = invoke(driftFixture.root);
    assert.notEqual(drifted.status, 0);
    assert.match(drifted.stderr, /reviewed runtime lock.*checksum mismatch/u);
  } finally {
    await rm(driftFixture.root, { recursive: true, force: true });
  }
});

test("npm bootstrap is isolated, lifecycle-disabled, and suppresses captured failure output", async () => {
  const source = await readFile(script, "utf8");
  for (const contract of [
    '"--ignore-scripts"',
    '"ignore-scripts=true"',
    'NPM_CONFIG_USERCONFIG: npmConfiguration',
    'NPM_CONFIG_GLOBALCONFIG: npmGlobalConfiguration',
    'NPM_CONFIG_CACHE: npmCache',
    'HOME: npmHome',
    'PATH: "/usr/bin:/bin:/usr/sbin:/sbin"',
    'TMPDIR: npmTemporary',
    '"--replace-registry-host=never"',
    'captured npm output was discarded to protect credentials'
  ]) {
    assert.ok(source.includes(contract), `missing bootstrap isolation contract: ${contract}`);
  }
});

test("npm child receives only the explicit bootstrap environment", async () => {
  const { root } = await fixture(false);
  try {
    const marker = join(root, "observed-environment.json");
    const fakeNPM = join(root, "fake-npm.mjs");
    await writeFile(fakeNPM, [
      'import { writeFileSync } from "node:fs";',
      `writeFileSync(${JSON.stringify(marker)}, JSON.stringify({ env: process.env, args: process.argv.slice(2) }));`,
      "process.exit(27);",
      ""
    ].join("\n"));
    const poisonedEnvironment = {
      ...process.env,
      NODE_PATH: join(root, "attacker-modules"),
      NODE_EXTRA_CA_CERTS: join(root, "attacker-ca.pem"),
      HTTPS_PROXY: "http://credential@example.invalid:9999",
      ALL_PROXY: "socks5://credential@example.invalid:9999",
      SSH_AUTH_SOCK: join(root, "attacker-agent.sock"),
      NPM_TOKEN: "must-not-reach-child",
      npm_config_userconfig: join(root, "attacker.npmrc"),
      npm_config_registry: "https://example.invalid/"
    };
    const result = invoke(root, fakeNPM, poisonedEnvironment);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /captured npm output was discarded to protect credentials/u);
    const observed = JSON.parse(await readFile(marker, "utf8"));
    assert.deepEqual(Object.keys(observed.env).sort(), [
      "HOME", "LANG", "LC_ALL", "NO_COLOR", "PATH", "TMPDIR",
      "__CF_USER_TEXT_ENCODING",
      "NPM_CONFIG_AUDIT", "NPM_CONFIG_CACHE", "NPM_CONFIG_FUND",
      "NPM_CONFIG_GLOBALCONFIG", "NPM_CONFIG_IGNORE_SCRIPTS", "NPM_CONFIG_REGISTRY",
      "NPM_CONFIG_USERCONFIG", "npm_config_audit", "npm_config_cache", "npm_config_fund",
      "npm_config_globalconfig", "npm_config_ignore_scripts", "npm_config_registry",
      "npm_config_userconfig"
    ].sort());
    assert.equal(observed.env.PATH, "/usr/bin:/bin:/usr/sbin:/sbin");
    assert.equal(observed.env.NPM_CONFIG_REGISTRY, "https://registry.npmjs.org/");
    assert.ok(observed.args.includes("--ignore-scripts"));
    assert.ok(observed.args.includes("--replace-registry-host=never"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("public bootstrap strips NODE_OPTIONS before any pinned Node process", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-node-options-policy."));
  try {
    const marker = join(root, "node-options-executed");
    const injector = join(root, "inject.cjs");
    await writeFile(injector, `require("node:fs").writeFileSync(${JSON.stringify(marker)}, "executed");\n`);
    const result = spawnSync("/bin/zsh", ["-f", join(project, "scripts", "bootstrap-source-checkout.sh")], {
      encoding: "utf8",
      env: {
        ...process.env,
        NODE_OPTIONS: `--require=${injector}`,
        NODE_PATH: join(root, "attacker-modules"),
        npm_config_registry: "https://example.invalid/",
        HTTPS_PROXY: "http://credential@example.invalid:9999"
      }
    });
    assert.equal(result.status, 0, result.stderr);
    await assert.rejects(readFile(marker), { code: "ENOENT" });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Node bootstrap rejects linked and incomplete existing destinations before downloading", async () => {
  for (const linked of [true, false]) {
    const root = await mkdtemp(join(tmpdir(), "fulmar-node-bootstrap-policy."));
    try {
      await mkdir(join(root, "scripts"), { recursive: true });
      await mkdir(join(root, "VendorRuntime"), { recursive: true });
      await copyFile(nodeBootstrap, join(root, "scripts", "fetch-node-runtime.sh"));
      const destination = join(root, "VendorRuntime", "node-v22.23.1-darwin-arm64");
      if (linked) {
        const target = join(root, "outside");
        await mkdir(target);
        await symlink(target, destination);
      } else {
        await mkdir(destination);
      }
      const result = spawnSync("/bin/zsh", ["-f", join(root, "scripts", "fetch-node-runtime.sh")], { encoding: "utf8" });
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /incomplete or linked/u);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }
});

test("Node bootstrap rejects a version-spoofing existing executable before it can run", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-node-bootstrap-spoof."));
  try {
    await mkdir(join(root, "scripts"), { recursive: true });
    await mkdir(join(root, "VendorRuntime", "node-v22.23.1-darwin-arm64", "bin"), { recursive: true });
    await copyFile(nodeBootstrap, join(root, "scripts", "fetch-node-runtime.sh"));
    const marker = join(root, "executed");
    const fake = join(root, "VendorRuntime", "node-v22.23.1-darwin-arm64", "bin", "node");
    await writeFile(fake, `#!/bin/sh\nprintf executed > ${JSON.stringify(marker)}\nprintf 'v22.23.1\\n'\n`, { mode: 0o755 });
    const result = spawnSync("/bin/zsh", ["-f", join(root, "scripts", "fetch-node-runtime.sh")], { encoding: "utf8" });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /executable checksum is not reviewed/u);
    await assert.rejects(readFile(marker), { code: "ENOENT" });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
