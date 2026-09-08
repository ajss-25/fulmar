import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFile, cp, mkdir, mkdtemp, readFile, realpath, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  patchDSHProfileReadOnlyBoot,
  patchDeepSeekRuntime,
  patchPiAIAdapterRuntime,
  patchPiAIAnthropicClientNoAuth,
  patchPiAIConfigTypes,
  patchPiAIReadmeChinese,
  patchPiAIReadmeEnglish,
  patchPiAIOpenAIClientNoAuth
} from "../../scripts/materialize-vendor-runtime.mjs";
import { loadManifest, loadRustNoticeMaterials, renderInventory } from "../../scripts/prepare-libvips-source-materials.mjs";

const project = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const script = join(project, "scripts", "materialize-vendor-runtime.mjs");
const nodeBootstrap = join(project, "scripts", "fetch-node-runtime.sh");
const noticeMaterialsGlue = join(project, "scripts", "prepare-third-party-notice-materials.mjs");
const noticeMaterialsRelative = ["build", "third-party-notice-materials", "sharp-libvips-1.3.2-rust-crate-materials"];
const projectNoticeMaterials = join(project, ...noticeMaterialsRelative);
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
  assert.equal(review.patches.length, 14);
  assert.deepEqual(
    review.upstreamTarballs.map(({ package: name, resolved }) => [name, new URL(resolved).origin]),
    [
      ["@deepseek-ai/dsh", "https://registry.npmjs.org"],
      ["@deepseek-ai/dsh-llm-deepseek", "https://registry.npmjs.org"],
      ["@deepseek-ai/dsh-app-boot", "https://registry.npmjs.org"]
    ]
  );
  for (const patch of review.patches) {
    const installed = await readFile(join(project, "VendorRuntime", "node_modules", ...patch.path.split("/")));
    assert.equal(sha256(installed), patch.afterSHA256, patch.id);
  }

  const bootPatch = review.patches.find(({ id }) => id === "dsh-profile-read-only-boot");
  assert.equal(bootPatch.beforeSHA256, "9d4b7f214cd35b3e8ce4e027b12cca34a416d355577aeacbf08a5b324f0cabb6");
  assert.equal(bootPatch.afterSHA256, "df332740cc09975ac403fb785beb2fff226ce5307115dffa4b41a4e53065e5db");
  const upstreamAnchors = Buffer.from([
    'function initProfile(dir, bundles) {\n\tmkdirSync(dir, { recursive: true });',
    '\tconst modulesDir = join(join(home, PROFILES_DIR), "node_modules");\n\tmkdirSync(modulesDir, { recursive: true });',
    '\t\tconst link = join(modulesDir, packageName);\n\t\tmkdirSync(dirname(link), { recursive: true });'
  ].join("\n// exact upstream anchor\n"));
  const transformed = patchDSHProfileReadOnlyBoot(upstreamAnchors).toString("utf8");
  assert.match(transformed, /metadata = lstatSync\(path\)/u);
  assert.match(transformed, /metadata\.isDirectory\(\).*metadata\.isSymbolicLink\(\)/u);
  assert.match(transformed, /ensureRealProfileDirectory\(modulesDir\)/u);
  assert.throws(() => patchDSHProfileReadOnlyBoot(Buffer.concat([upstreamAnchors, upstreamAnchors])),
    /patch anchor was absent or ambiguous/u);
  assert.throws(() => patchDSHProfileReadOnlyBoot(Buffer.from(transformed)),
    /patch anchor was absent or ambiguous/u);

  // Exercise the actual materialized boot exports: after native preparation,
  // an existing web profile must boot without even an idempotent write syscall.
  // This is complementary to the real native Seatbelt boundary regression.
  const home = await realpath(await mkdtemp(join(tmpdir(), "fulmar-prepared-profile.")));
  try {
    const outcome = spawnSync(process.execPath, ["--input-type=module", "-e", String.raw`
      import assert from "node:assert/strict";
      import fs from "node:fs";
      import { join } from "node:path";
      import { pathToFileURL } from "node:url";
      import { syncBuiltinESMExports } from "node:module";
      const [entry, anchor, home] = process.argv.slice(1);
      const boot = await import(pathToFileURL(entry).href);
      process.umask(0o077);
      boot.healProfilesModuleFallback(anchor, home);
      const profile = boot.loadProfile("dsh", "web", anchor, home);
      assert.equal(profile.dir, join(home, "profiles", "web"));
      assert.deepEqual(profile.layers.map(layer => layer.packageName),
        ["@deepseek-ai/dsh-base", "@deepseek-ai/dsh-web-app"]);
      const before = fs.readFileSync(join(profile.dir, "package.json"), "utf8");
      const originals = new Map(["mkdirSync", "writeFileSync", "symlinkSync", "unlinkSync"]
        .map(name => [name, fs[name]]));
      for (const name of originals.keys()) fs[name] = () => { throw new Error("unexpected profile write: " + name); };
      syncBuiltinESMExports();
      boot.healProfilesModuleFallback(anchor, home);
      const reloaded = boot.loadProfile("dsh", "web", anchor, home);
      boot.initProfile(profile.dir, ["@deepseek-ai/dsh-base", "@deepseek-ai/dsh-web-app"]);
      assert.equal(reloaded.dir, profile.dir);
      assert.equal(fs.readFileSync(join(profile.dir, "package.json"), "utf8"), before);
      for (const [name, value] of originals) fs[name] = value;
      syncBuiltinESMExports();
      const fallback = join(home, "profiles", "node_modules");
      fs.renameSync(fallback, fallback + "-retained");
      fs.symlinkSync(fallback + "-retained", fallback);
      assert.throws(() => boot.healProfilesModuleFallback(anchor, home), /not a real directory/u);
      fs.unlinkSync(fallback);
      fs.writeFileSync(fallback, "not a directory");
      assert.throws(() => boot.healProfilesModuleFallback(anchor, home), /not a real directory/u);
      process.stdout.write("PREPARED_PROFILE_READ_ONLY_OK\n");
    `, join(project, "VendorRuntime", "node_modules", ...bootPatch.path.split("/")),
    join(project, "VendorRuntime", "node_modules", "@deepseek-ai", "dsh", "package.json"), home], {
      env: { HOME: home, DSH_HOME: home, PATH: "/usr/bin:/bin", DSH_TELEMETRY_MODE: "DISABLED" },
      encoding: "utf8", timeout: 10_000
    });
    assert.equal(outcome.error, undefined);
    assert.equal(outcome.signal, null);
    assert.equal(outcome.status, 0, outcome.stderr);
    assert.equal(outcome.stdout, "PREPARED_PROFILE_READ_ONLY_OK\n");
  } finally {
    await rm(home, { recursive: true, force: true });
  }

  // The assembler relocates the dsh package itself out of node_modules. Invoke
  // the exact standalone helper against that packaged layout; calling the boot
  // exports from the npm checkout alone cannot catch a wrong manifest anchor.
  // These are the real pinned boot import closure and its two shipped layers,
  // not substituted exports or a copy of the complete 400 MB runtime.
  const assembledRoot = await realpath(await mkdtemp(join(tmpdir(), "fulmar-assembled-profile.")));
  try {
    const resources = join(assembledRoot, "Resources");
    const runtime = join(resources, "Runtime", "dsh");
    const moduleRoot = join(runtime, "node_modules");
    const bootModules = [
      ["@deepseek-ai/dsh-app-boot", "lib/index.js"],
      ["js-yaml", "dist/js-yaml.mjs"],
      ["@deepseek-ai/cordis", "lib/index.js"],
      ["@deepseek-ai/cordis-plugin-loader", "lib/index.js"],
      ["@deepseek-ai/cordis-plugin-group", "lib/index.js"],
      ["@deepseek-ai/dsh-home-paths", "lib/index.js"],
      ["@deepseek-ai/dsh-launch-environment", "lib/index.js"],
      ["@deepseek-ai/cosmokit", "lib/index.js"],
      ["@deepseek-ai/dsh-base", "cordis.patch.yml"],
      ["@deepseek-ai/dsh-web-app", "cordis.patch.yml"]
    ];
    let copiedBytes = 0;
    for (const [name, entry] of bootModules) {
      for (const relative of ["package.json", entry]) {
        const source = join(project, "VendorRuntime", "node_modules", name, relative);
        copiedBytes += (await stat(source)).size;
        await copyRegular(source, join(moduleRoot, name, relative));
      }
    }
    const helper = join(resources, "PrepareHarnessProfile.mjs");
    await copyRegular(join(project, "Resources", "PrepareHarnessProfile.mjs"), helper);
    await copyRegular(join(project, "VendorRuntime", "node_modules", "@deepseek-ai", "dsh", "package.json"),
      join(runtime, "package.json"));
    assert.ok(copiedBytes > 250_000 && copiedBytes < 512 * 1024,
      "the assembled boot fixture must remain the bounded real import closure");
    assert.equal(await stat(join(moduleRoot, "@deepseek-ai", "dsh", "package.json"))
      .then(() => true, (error) => { if (error.code === "ENOENT") return false; throw error; }), false,
    "the fixture must not preserve the npm-only manifest location");
    for (const name of ["first-private-home", "second-private-home"]) {
      const preparedHome = join(assembledRoot, name);
      await mkdir(preparedHome, { mode: 0o700 });
      const invokeHelper = () => spawnSync(process.execPath, [helper, preparedHome], {
        env: { PATH: "/usr/bin:/bin", HOME: preparedHome, DSH_HOME: "/untrusted-ambient-dsh-home" },
        encoding: "utf8", timeout: 10_000
      });
      const check = (result) => {
        assert.equal(result.error, undefined);
        assert.equal(result.signal, null);
        assert.equal(result.status, 0, result.stderr);
        assert.equal(result.stdout, "FULMAR_PROFILE_PREPARED\n");
        assert.equal(result.stderr, "");
      };
      check(invokeHelper());
      const manifest = join(preparedHome, "profiles", "web", "package.json");
      const patch = join(preparedHome, "profiles", "web", "cordis.patch.yml");
      const firstManifest = await readFile(manifest);
      const firstPatch = await readFile(patch);
      assert.deepEqual(JSON.parse(firstManifest).dsh.profile.bundles,
        ["@deepseek-ai/dsh-base", "@deepseek-ai/dsh-web-app"]);
      check(invokeHelper());
      assert.deepEqual(await readFile(manifest), firstManifest);
      assert.deepEqual(await readFile(patch), firstPatch);
    }
  } finally {
    await rm(assembledRoot, { recursive: true, force: true });
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
    // The same clean lane prepares the notice-material cache. A test run must
    // stay offline: the cache prepared by the real bootstrap beforehand is
    // re-verified as a hit, never acquired again, and only HTTPS-acquired,
    // authoritative output is accepted.
    assert.match(result.stderr, new RegExp(`^verified notice-material cache ${projectNoticeMaterials.replaceAll(/[.*+?^${}()|[\]\\]/gu, "\\$&")}: transport https \\(authoritative\\); 159 items \\(12047290 bytes\\); inventory sha256:[0-9a-f]{64}; checksum list sha256:[0-9a-f]{64}; RUST_CRATE_NOTICES\\.md sha256:[0-9a-f]{64}; external notice material Config/SharpLibvipsRustNoticeMaterials\\.json \\(sha256:[0-9a-f]{64}; established 2, unresolved 4\\)$`, "mu"));
    assert.doesNotMatch(result.stderr, /acquiring|published .* via .* transport|\(NOT authoritative\)/u, "the test run must not acquire the cache");
    assert.match(result.stdout, /third-party notice materials are reconstructed and verified/u);
    const cache = await stat(projectNoticeMaterials);
    assert.ok(cache.isDirectory());
    assert.equal(cache.mode & 0o777, 0o700);
    assert.equal(cache.uid, process.getuid());
    assert.equal((await stat(join(project, "build", "third-party-notice-materials"))).mode & 0o777, 0o700);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// The notice-material cache glue is exercised against a private fixture root
// that carries the tracked manifests and their external notice material, plus
// a fake acquisition tool that records what it received and refuses. Nothing
// here touches the network; the one real cache it reads is the one the actual
// bootstrap prepared above, copied and relabelled so that fixture-transport
// output is proven to be refused.
async function noticeMaterialsFixture() {
  const root = await realpath(await mkdtemp(join(tmpdir(), "fulmar-notice-materials.")));
  await mkdir(join(root, "scripts"), { mode: 0o700 });
  await mkdir(join(root, "Config"), { mode: 0o700 });
  await mkdir(join(root, "Resources", "ThirdPartyLicenses", "sharp-libvips-1.3.2", "rust"), { recursive: true, mode: 0o700 });
  for (const name of ["SharpLibvipsRustProvenance.json", "SharpLibvipsRustNoticeMaterials.json", "ThirdPartyBinaryProvenance.json"]) {
    await copyFile(join(project, "Config", name), join(root, "Config", name));
  }
  for (const name of ["mutants-0.0.4-external-cargo-mutants-LICENSE", "selectors-0.38.0-external-spdx-3.28.0-MPL-2.0.txt"]) {
    await copyFile(join(project, "Resources", "ThirdPartyLicenses", "sharp-libvips-1.3.2", "rust", name),
      join(root, "Resources", "ThirdPartyLicenses", "sharp-libvips-1.3.2", "rust", name));
  }
  const observed = join(root, "observed-acquisition.json");
  await writeFile(join(root, "scripts", "prepare-libvips-source-materials.mjs"), [
    'import { writeFileSync } from "node:fs";',
    `writeFileSync(${JSON.stringify(observed)}, JSON.stringify({ env: process.env, args: process.argv.slice(2), execArgv: process.execArgv, cwd: process.cwd() }));`,
    'process.stderr.write("fake acquisition tool refused\\n");',
    "process.exit(3);",
    ""
  ].join("\n"));
  return { root, observed, cache: join(root, ...noticeMaterialsRelative), cacheDirectory: join(root, "build", "third-party-notice-materials") };
}

function runNoticeMaterials(args, env = process.env) {
  return spawnSync(process.execPath, [noticeMaterialsGlue, ...args], { encoding: "utf8", env, timeout: 120_000 });
}

test("notice-material cache preparation admits only a private canonical cache, refuses stale or fixture output and inherits nothing into acquisition", async () => {
  const { root, observed, cache, cacheDirectory } = await noticeMaterialsFixture();
  try {
    // Absent cache: the existing acquisition tool is invoked exactly once with
    // the tracked manifests, HTTPS transport and an environment that carries
    // no loader, proxy, CA store, credential or registry setting.
    const poisoned = {
      ...process.env,
      NODE_PATH: join(root, "attacker-modules"),
      NODE_EXTRA_CA_CERTS: join(root, "attacker-ca.pem"),
      HTTPS_PROXY: "http://credential@example.invalid:9999",
      ALL_PROXY: "socks5://credential@example.invalid:9999",
      SSH_AUTH_SOCK: join(root, "attacker-agent.sock"),
      CARGO_REGISTRY_TOKEN: "must-not-reach-child",
      NPM_TOKEN: "must-not-reach-child",
      npm_config_registry: "https://example.invalid/"
    };
    const absent = runNoticeMaterials(["prepare", root], poisoned);
    assert.notEqual(absent.status, 0);
    assert.match(absent.stderr, /notice-material cache absent: .*; acquiring 159 crate materials \(12047290 bytes\) over HTTPS/u);
    assert.match(absent.stderr, /fake acquisition tool refused/u);
    assert.match(absent.stderr, /HTTPS acquisition failed \(status 3\); cache publication state is unverified at/u);
    assert.doesNotMatch(absent.stderr, /no cache was published/u);
    const acquisition = JSON.parse(await readFile(observed, "utf8"));
    assert.deepEqual(acquisition.args, [
      "acquire", join(root, "Config", "SharpLibvipsRustProvenance.json"), cache,
      "--transport", "https", "--notice-materials", join(root, "Config", "SharpLibvipsRustNoticeMaterials.json")
    ]);
    assert.deepEqual(Object.keys(acquisition.env).filter((name) => name !== "__CF_USER_TEXT_ENCODING").sort(), ["LANG", "LC_ALL", "PATH", "TMPDIR"]);
    assert.equal(acquisition.env.PATH, "/usr/bin:/bin:/usr/sbin:/sbin");
    assert.deepEqual(acquisition.execArgv, []);
    assert.equal(acquisition.cwd, root);
    assert.equal((await stat(join(root, "build"))).mode & 0o777, 0o700);
    assert.equal((await stat(cacheDirectory)).mode & 0o777, 0o700);
    await assert.rejects(stat(cache), { code: "ENOENT" });
    await rm(observed);

    // Release-script verification never acquires: an absent cache names the
    // bootstrap, an operand outside the literal path is refused outright.
    const verifyAbsent = runNoticeMaterials(["verify", root, cache]);
    assert.notEqual(verifyAbsent.status, 0);
    assert.match(verifyAbsent.stderr, /notice-material cache is absent: .*; run scripts\/bootstrap-source-checkout\.sh \(which acquires it over HTTPS\)/u);
    const wrongOperand = runNoticeMaterials(["verify", root, join(root, "build", "elsewhere")]);
    assert.notEqual(wrongOperand.status, 0);
    assert.match(wrongOperand.stderr, /is not the literal checkout-local cache/u);
    await assert.rejects(stat(observed), { code: "ENOENT" });

    // Unsafe pre-existing paths are refused before any acquisition and are
    // never chmod-followed or removed.
    const unsafe = [
      {
        name: "symbolic-link containing directory",
        arrange: async () => { await rm(cacheDirectory, { recursive: true }); await mkdir(join(root, "elsewhere"), { mode: 0o700 }); await symlink(join(root, "elsewhere"), cacheDirectory); },
        message: /notice-material cache directory is a symbolic link, which the release cache refuses/u,
        restore: async () => { await rm(cacheDirectory); await rm(join(root, "elsewhere"), { recursive: true }); await mkdir(cacheDirectory, { mode: 0o700 }); }
      },
      {
        name: "group- and world-readable containing directory",
        arrange: async () => { await rm(cacheDirectory, { recursive: true }); await mkdir(cacheDirectory, { mode: 0o755 }); },
        message: /notice-material cache directory is unsafe \(notice-material cache directory is not owner-private: third-party-notice-materials\)/u,
        after: async () => assert.equal((await stat(cacheDirectory)).mode & 0o777, 0o755, "an unsafe mode is reported, never corrected"),
        restore: async () => { await rm(cacheDirectory, { recursive: true }); await mkdir(cacheDirectory, { mode: 0o700 }); }
      },
      {
        name: "regular file at the cache path",
        arrange: async () => writeFile(cache, "not a directory\n", { mode: 0o600 }),
        message: /notice-material cache is not a directory: .*; remove it deliberately/u,
        restore: async () => rm(cache)
      },
      {
        name: "symbolic link at the cache path",
        arrange: async () => { await mkdir(join(root, "elsewhere"), { mode: 0o700 }); await symlink(join(root, "elsewhere"), cache); },
        message: /notice-material cache is a symbolic link, which the release cache refuses/u,
        restore: async () => { await rm(cache); await rm(join(root, "elsewhere"), { recursive: true }); }
      },
      {
        name: "stale cache",
        arrange: async () => { await mkdir(cache, { mode: 0o700 }); await writeFile(join(cache, "INVENTORY.json"), "stale\n", { mode: 0o600 }); },
        message: /existing notice-material cache is invalid or stale: .*: destination is missing expected entries; inspect it with "scripts\/prepare-libvips-source-materials\.mjs verify Config\/SharpLibvipsRustProvenance\.json .* --notice-materials Config\/SharpLibvipsRustNoticeMaterials\.json", remove it deliberately if it is stale, then rerun scripts\/bootstrap-source-checkout\.sh; nothing is overwritten or deleted automatically/u,
        after: async () => assert.equal(await readFile(join(cache, "INVENTORY.json"), "utf8"), "stale\n", "a stale cache is left in place for the operator"),
        restore: async () => rm(cache, { recursive: true })
      }
    ];
    for (const current of unsafe) {
      await current.arrange();
      for (const command of [["prepare", root], ["verify", root, cache]]) {
        const result = runNoticeMaterials(command);
        assert.notEqual(result.status, 0, `${current.name} must fail for ${command[0]}`);
        assert.match(result.stderr, current.message, `${current.name} (${command[0]}): ${result.stderr}`);
        assert.ok(result.stderr.includes(cacheDirectory), `${current.name} must name the exact path: ${result.stderr}`);
        await assert.rejects(stat(observed), { code: "ENOENT" }, `${current.name} must not attempt acquisition`);
      }
      await current.after?.();
      await current.restore();
    }

    // Fixture-transport output is refused for the production cache even when
    // every byte verifies: the real HTTPS cache is copied and its inventory is
    // re-rendered exactly as the acquisition tool would for local-fixture
    // transport, so only the recorded acquisition mode differs.
    await stat(projectNoticeMaterials).catch(() => {
      throw new Error(`the real notice-material cache is absent at ${projectNoticeMaterials}; run scripts/bootstrap-source-checkout.sh before the JS suites`);
    });
    await mkdir(cache, { mode: 0o700 });
    await cp(projectNoticeMaterials, cache, { recursive: true, errorOnExist: false, force: true });
    const verifyHTTPSCopy = runNoticeMaterials(["verify", root, cache]);
    assert.equal(verifyHTTPSCopy.status, 0, verifyHTTPSCopy.stderr);
    assert.match(verifyHTTPSCopy.stderr, /^verified notice-material cache .*: transport https \(authoritative\); 159 items/mu);

    // A child can fail after publishing a complete cache. Failure must remain
    // fatal without claiming absence, removing the cache, retrying acquisition,
    // or bypassing independent verification of the retained published bytes.
    await rm(cache, { recursive: true });
    await writeFile(join(root, "scripts", "prepare-libvips-source-materials.mjs"), [
      'import { appendFileSync, chmodSync, cpSync } from "node:fs";',
      'const destination = process.argv[4];',
      `cpSync(${JSON.stringify(projectNoticeMaterials)}, destination, { recursive: true, errorOnExist: true, force: false });`,
      'chmodSync(destination, 0o700);',
      `appendFileSync(${JSON.stringify(observed)}, "published-then-failed\\n");`,
      'process.stderr.write("fake acquisition published then refused\\n");',
      "process.exit(3);",
      ""
    ].join("\n"), { mode: 0o600 });
    const publishedFailure = runNoticeMaterials(["prepare", root]);
    assert.equal(publishedFailure.status, 1, publishedFailure.stderr);
    assert.match(publishedFailure.stderr, /HTTPS acquisition failed \(status 3\); cache publication state is unverified at/u);
    assert.doesNotMatch(publishedFailure.stderr, /no cache was published/u);
    const expectedRecovery = `inspect it with "scripts/prepare-libvips-source-materials.mjs verify Config/SharpLibvipsRustProvenance.json ${cache} --notice-materials Config/SharpLibvipsRustNoticeMaterials.json", remove it deliberately if it is stale, then rerun scripts/bootstrap-source-checkout.sh; nothing is overwritten or deleted automatically`;
    assert.ok(publishedFailure.stderr.includes(expectedRecovery), publishedFailure.stderr);
    assert.equal(await readFile(observed, "utf8"), "published-then-failed\n", "a failed child must not be retried");
    assert.equal((await stat(cache)).mode & 0o777, 0o700);
    for (const name of ["INVENTORY.json", "SHA256SUMS", "RUST_CRATE_NOTICES.md"]) {
      assert.deepEqual(await readFile(join(cache, name)), await readFile(join(projectNoticeMaterials, name)), "published cache bytes must be preserved after failure");
    }
    const verifyPublished = runNoticeMaterials(["verify", root, cache]);
    assert.equal(verifyPublished.status, 0, verifyPublished.stderr);
    assert.match(verifyPublished.stderr, /^verified notice-material cache .*: transport https \(authoritative\); 159 items/mu);
    assert.equal(await readFile(observed, "utf8"), "published-then-failed\n", "independent verification must not acquire");
    await rm(observed);
    const { manifest, manifestSHA256, manifestPath } = await loadManifest(join(root, "Config", "SharpLibvipsRustProvenance.json"));
    const noticeMaterials = await loadRustNoticeMaterials(join(root, "Config", "SharpLibvipsRustNoticeMaterials.json"), manifest, manifestPath);
    const inventory = JSON.parse(await readFile(join(cache, "INVENTORY.json"), "utf8"));
    assert.equal(inventory.transport, "https");
    const relabelled = renderInventory(manifest, manifestSHA256, new Map(inventory.items.map((item) => [item.id, item.redirectHosts])), "local-fixture", inventory.rustNoticesSHA256, noticeMaterials);
    assert.equal(relabelled.sumsText, await readFile(join(cache, "SHA256SUMS"), "utf8"));
    await writeFile(join(cache, "INVENTORY.json"), relabelled.inventoryText, { mode: 0o600 });
    for (const command of [["prepare", root], ["verify", root, cache]]) {
      const result = runNoticeMaterials(command);
      assert.notEqual(result.status, 0, `fixture transport must be refused for ${command[0]}`);
      assert.match(result.stderr, /existing notice-material cache records transport local-fixture \(NOT authoritative\): .*; the release cache must be acquired over HTTPS, so remove it deliberately and rerun scripts\/bootstrap-source-checkout\.sh/u);
      await assert.rejects(stat(observed), { code: "ENOENT" });
    }
    // The relabelled copy still verifies as fixture output for the materials
    // tool itself, which is what proves the refusal came from the recorded
    // transport rather than from drifted bytes.
    const fixtureVerify = spawnSync(process.execPath, [join(project, "scripts", "prepare-libvips-source-materials.mjs"), "verify",
      join(root, "Config", "SharpLibvipsRustProvenance.json"), cache, "--notice-materials", join(root, "Config", "SharpLibvipsRustNoticeMaterials.json")], { encoding: "utf8", timeout: 120_000 });
    assert.equal(fixtureVerify.status, 0, fixtureVerify.stderr);
    assert.match(fixtureVerify.stderr, /transport local-fixture \(NOT authoritative\)/u);
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
