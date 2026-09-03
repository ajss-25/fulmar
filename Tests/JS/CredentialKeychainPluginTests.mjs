import assert from "node:assert/strict";
import test, { after, before } from "node:test";
import { chmod, copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const project = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
let root;
let plugin;
let previousHome;
let previousOllamaAPIKey;
let previousForbidCredentialHelper;
let previousCredentialHelper;
let previousCredentialHelperTimeout;

function shellQuote(value) {
  return `'${String(value).replaceAll("'", `'"'"'`)}'`;
}

async function writeModule(name, source) {
  const directory = join(root, "node_modules", ...name.split("/"));
  await mkdir(directory, { recursive: true });
  await writeFile(join(directory, "package.json"), JSON.stringify({
    name,
    version: "0.0.0-test",
    type: "module",
    exports: "./index.mjs"
  }));
  await writeFile(join(directory, "index.mjs"), source);
}

before(async () => {
  root = await mkdtemp(join(tmpdir(), "local-harness-credential-plugin-"));
  await writeModule("@deepseek-ai/dsh-credentials", `
    export class CredentialProvider {
      notifyUpdated() {}
      notifyRecordUpdated() {}
    }
    export function credentialRef(value) { return value; }
    export function parseCredentialKey(value) { return value; }
  `);
  await writeModule("@deepseek-ai/schemastery", "export default { object() { return {}; } };\n");

  // A Mach-O interpreter path inside "Local Harness.app" contains a space,
  // which POSIX shebang parsing cannot represent. Use a tiny fixed /bin/sh
  // launcher so the candidate-bundle Node qualifies the same helper behavior
  // without turning its pathname into a false spawn failure.
  const helperModule = join(root, "fake-helper-body.mjs");
  await writeFile(helperModule, `import { appendFile, open, readFile, rm, writeFile } from "node:fs/promises";
    import { join } from "node:path";
    const command = process.argv[2];
    const subject = process.argv[3];
    const orderLog = join(process.env.HOME, "credential-order.log");
    const invocationLog = join(process.env.HOME, "credential-invocations.log");
    await appendFile(invocationLog, command + ":" + String(subject) + "\\n");
    if (subject === "authorization-required") {
      process.exitCode = 5;
    } else if (subject?.startsWith("stable-exit-")) {
      process.stderr.write("TOP_SECRET_MUST_NOT_ESCAPE");
      process.exitCode = Number(subject.slice("stable-exit-".length));
    } else if (subject === "hung") {
      process.on("SIGTERM", () => {});
      setInterval(() => {}, 1000);
    } else if (subject === "oversized") {
      process.stdout.write(Buffer.alloc(1_100_000, 120));
    } else if (subject === "stderr-oversized") {
      process.stderr.write(Buffer.alloc(80_000, 115));
      process.stderr.write("TOP_SECRET_MUST_NOT_ESCAPE");
    } else if (subject === "noisy") {
      process.stderr.write(Buffer.alloc(32_000, 110));
      process.stderr.write("TOP_SECRET_MUST_NOT_ESCAPE");
      process.stdout.write("1");
    } else if (command === "modify-record-locked") {
      const safe = Buffer.from(subject).toString("hex");
      const lockPath = join(process.env.HOME, safe + ".lock");
      const valuePath = join(process.env.HOME, safe + ".record");
      let lock;
      while (!lock) {
        try { lock = await open(lockPath, "wx", 0o600); }
        catch (error) { if (error.code !== "EEXIST") throw error; await new Promise((resolve) => setTimeout(resolve, 5)); }
      }
      try {
        let current;
        try { current = await readFile(valuePath); } catch (error) { if (error.code !== "ENOENT") throw error; }
        process.stdout.write("CURRENT " + (current?.length ?? -1) + "\\n");
        if (current) process.stdout.write(current);
        const chunks = [];
        for await (const chunk of process.stdin) chunks.push(chunk);
        const response = Buffer.concat(chunks);
        if (response.toString("utf8") !== "UNCHANGED\\n") {
          const newline = response.indexOf(10);
          const match = /^STORE ([0-9]+)$/.exec(response.subarray(0, newline).toString("utf8"));
          if (!match || Number(match[1]) !== response.length - newline - 1) process.exit(11);
          current = response.subarray(newline + 1);
          await writeFile(valuePath, current, { mode: 0o600 });
          await appendFile(orderLog, "M:" + subject + "\\n");
        }
        process.stdout.write("COMMITTED\\n");
        if (current) {
          if (subject === "owner/protocol-truncated") process.stdout.write(current.subarray(0, Math.max(0, current.length - 1)));
          else process.stdout.write(current);
        }
        if (subject === "owner/protocol-extra") process.stdout.write("x");
      } finally { await lock.close(); await rm(lockPath, { force: true }); }
    } else if (command === "get-record") {
      if (subject === "blocked-modify") await new Promise((resolve) => setTimeout(resolve, 175));
      if (subject === "owner/invalid-read") process.stdout.write('{"kind":"grant"}');
      else process.exitCode = 3;
    } else if (command === "set-record") {
      await new Promise((resolve) => { process.stdin.resume(); process.stdin.on("end", resolve); });
      await appendFile(orderLog, "M:" + subject + "\\n");
    } else if (command === "unset-record") {
      if (subject === "blocked-delete") await new Promise((resolve) => setTimeout(resolve, 175));
      await appendFile(orderLog, "D:" + subject + "\\n");
    } else if (command === "set") {
      if (subject === "blocked-set") await new Promise((resolve) => setTimeout(resolve, 175));
      await new Promise((resolve) => { process.stdin.resume(); process.stdin.on("end", resolve); });
      await appendFile(orderLog, "S:" + subject + "\\n");
    } else if (command === "unset") {
      if (subject === "blocked-unset") await new Promise((resolve) => setTimeout(resolve, 175));
      await appendFile(orderLog, "U:" + subject + "\\n");
    } else {
      process.stdout.write("1");
    }
  `);
  const helper = join(root, "fake-helper");
  await writeFile(
    helper,
    `#!/bin/sh\nexec ${shellQuote(process.execPath)} ${shellQuote(helperModule)} "$@"\n`
  );
  await chmod(helper, 0o700);

  const pluginPath = join(root, "plugin", "index.mjs");
  await mkdir(dirname(pluginPath), { recursive: true });
  await copyFile(join(project, "Resources", "DSHPlugins", "credentials-keychain", "index.mjs"), pluginPath);
  previousHome = process.env.HOME;
  previousOllamaAPIKey = process.env.OLLAMA_API_KEY;
  previousForbidCredentialHelper = process.env.LOCAL_HARNESS_FORBID_CREDENTIAL_HELPER;
  previousCredentialHelper = process.env.LOCAL_HARNESS_CREDENTIAL_HELPER;
  previousCredentialHelperTimeout = process.env.LOCAL_HARNESS_CREDENTIAL_HELPER_TIMEOUT_MS;
  process.env.HOME = root;
  process.env.OLLAMA_API_KEY = "local-ollama";
  process.env.LOCAL_HARNESS_CREDENTIAL_HELPER = join(root, "fake-helper");
  process.env.LOCAL_HARNESS_CREDENTIAL_HELPER_TIMEOUT_MS = "1000";
  delete process.env.LOCAL_HARNESS_FORBID_CREDENTIAL_HELPER;
  plugin = await import(`${pathToFileURL(pluginPath).href}?test=${Date.now()}`);
});

after(async () => {
  if (previousHome === undefined) delete process.env.HOME;
  else process.env.HOME = previousHome;
  if (previousOllamaAPIKey === undefined) delete process.env.OLLAMA_API_KEY;
  else process.env.OLLAMA_API_KEY = previousOllamaAPIKey;
  if (previousForbidCredentialHelper === undefined) delete process.env.LOCAL_HARNESS_FORBID_CREDENTIAL_HELPER;
  else process.env.LOCAL_HARNESS_FORBID_CREDENTIAL_HELPER = previousForbidCredentialHelper;
  if (previousCredentialHelper === undefined) delete process.env.LOCAL_HARNESS_CREDENTIAL_HELPER;
  else process.env.LOCAL_HARNESS_CREDENTIAL_HELPER = previousCredentialHelper;
  if (previousCredentialHelperTimeout === undefined) delete process.env.LOCAL_HARNESS_CREDENTIAL_HELPER_TIMEOUT_MS;
  else process.env.LOCAL_HARNESS_CREDENTIAL_HELPER_TIMEOUT_MS = previousCredentialHelperTimeout;
  if (root !== undefined) await rm(root, { recursive: true, force: true });
});

test("drains bounded finite stderr without reflecting secret diagnostics", async () => {
  const result = await plugin.runHelper("describe", "noisy");
  assert.equal(result.toString("utf8"), "1");
});

test("local Ollama readiness and resolution never launch the Keychain helper", async () => {
  const log = join(root, "credential-invocations.log");
  await rm(log, { force: true });
  const provider = new plugin.KeychainCredentialProvider();

  assert.deepEqual(await provider.resolve("OLLAMA_API_KEY"), {
    value: "local-ollama",
    source: "Local Ollama runtime"
  });
  assert.deepEqual(await provider.describe("OLLAMA_API_KEY"), {
    configured: true,
    source: "Local Ollama runtime",
    writable: true
  });
  await assert.rejects(readFile(log, "utf8"), { code: "ENOENT" });
});

test("the physical on-device boundary can forbid every native Keychain helper spawn", async () => {
  const isolatedPluginPath = join(root, "forbidden-plugin", "index.mjs");
  await mkdir(dirname(isolatedPluginPath), { recursive: true });
  await copyFile(join(project, "Resources", "DSHPlugins", "credentials-keychain", "index.mjs"), isolatedPluginPath);
  process.env.LOCAL_HARNESS_CREDENTIAL_HELPER = join(root, "fake-helper");
  process.env.LOCAL_HARNESS_FORBID_CREDENTIAL_HELPER = "1";
  const forbidden = await import(`${pathToFileURL(isolatedPluginPath).href}?forbidden=${Date.now()}`);
  delete process.env.LOCAL_HARNESS_FORBID_CREDENTIAL_HELPER;
  await assert.rejects(
    forbidden.runHelper("describe", "DEEPSEEK_API_KEY"),
    /forbidden by the on-device acceptance boundary/u
  );
  await assert.rejects(
    readFile(join(root, "credential-invocations.log"), "utf8"),
    { code: "ENOENT" }
  );
});

test("surfaces a typed actionable error when non-interactive Keychain access is denied", async () => {
  await assert.rejects(
    plugin.runHelper("get", "authorization-required"),
    (error) => error?.code === "KEYCHAIN_AUTHORIZATION_REQUIRED"
      && /Models & Providers/u.test(error.message)
  );
});

test("describe exposes only foreground-repairable states as a value-free read-only marker", async () => {
  const provider = new plugin.KeychainCredentialProvider();
  const expected = {
    configured: false,
    source: "Fulmar credential recovery required",
    writable: false
  };
  assert.deepEqual(await provider.describe("authorization-required"), expected);
  assert.deepEqual(await provider.describe("stable-exit-6"), expected);

  for (const status of [7, 8, 9, 10]) {
    await assert.rejects(
      provider.describe(`stable-exit-${status}`),
      (error) => error?.code !== undefined
        && error.code !== "KEYCHAIN_AUTHORIZATION_REQUIRED"
        && error.code !== "CREDENTIAL_RECOVERY_REQUIRED"
    );
  }
});

test("maps every credential transaction helper exit to a stable non-secret code", async () => {
  const cases = new Map([
    [6, "CREDENTIAL_RECOVERY_REQUIRED"],
    [7, "CREDENTIAL_TRANSACTION_BUSY"],
    [8, "CREDENTIAL_STATE_UNSAFE"],
    [9, "CREDENTIAL_STATE_UNAVAILABLE"],
    [10, "CREDENTIAL_VERIFICATION_FAILED"],
    [11, "CREDENTIAL_RECORD_PROTOCOL_FAILED"]
  ]);
  for (const [status, code] of cases) {
    let caught;
    try { await plugin.runHelper("get", `stable-exit-${status}`); }
    catch (error) { caught = error; }
    assert.equal(caught?.code, code);
    assert.match(caught?.message ?? "", /^credentials-keychain: /u);
    assert.doesNotMatch(caught?.message ?? "", /TOP_SECRET_MUST_NOT_ESCAPE/u);
    assert.deepEqual(caught?.failure, {
      message: caught?.message,
      code
    });
    assert.equal(Object.isFrozen(caught?.failure), true);
  }
});

test("kills and reaps a hung TERM-resistant helper within the bounded deadline", async () => {
  const started = performance.now();
  await assert.rejects(plugin.runHelper("get", "hung"), /native helper timed out/u);
  assert.ok(performance.now() - started < 3_000, "hung helper did not reach bounded close/reap");
});

test("cancellation terminates and reaps the exact helper process", async () => {
  const controller = new AbortController();
  const operation = plugin.runHelper("get", "hung", undefined, { signal: controller.signal });
  setTimeout(() => controller.abort(), 25);
  await assert.rejects(operation, /native helper was cancelled/u);
});

test("rejects oversized stdout only after bounded process disposal", async () => {
  await assert.rejects(plugin.runHelper("get", "oversized"), /response exceeded its size limit/u);
});

test("bounds stderr and never includes helper diagnostics in the error", async () => {
  let caught;
  try { await plugin.runHelper("get", "stderr-oversized"); }
  catch (error) { caught = error; }
  assert.match(caught?.message ?? "", /diagnostic output exceeded its size limit/u);
  assert.doesNotMatch(caught?.message ?? "", /TOP_SECRET_MUST_NOT_ESCAPE/u);
});

test("a timed-out serialized record mutation cannot poison later mutations", async () => {
  const provider = new plugin.KeychainCredentialProvider();
  await assert.rejects(
    provider.modifyRecord("hung", async () => ({ kind: "grant", payload: null })),
    /native (?:helper timed out|record modification .*timed out)/u
  );
  const result = await provider.modifyRecord("ok", async () => ({ kind: "grant", payload: null }));
  assert.deepEqual(result, { kind: "grant", payload: null });
});

test("record deletion is ordered after an already-running record refresh", async () => {
  const log = join(root, "credential-order.log");
  await rm(log, { force: true });
  const provider = new plugin.KeychainCredentialProvider();
  const modify = provider.modifyRecord("blocked-modify", async () => ({ kind: "grant", payload: null }));
  const remove = provider.deleteRecord("blocked-modify");
  await Promise.all([modify, remove]);
  assert.equal(await readFile(log, "utf8"), "M:blocked-modify\nD:blocked-modify\n");
});

test("record refresh is ordered after an already-running deletion", async () => {
  const log = join(root, "credential-order.log");
  await rm(log, { force: true });
  const provider = new plugin.KeychainCredentialProvider();
  const remove = provider.deleteRecord("blocked-delete");
  const modify = provider.modifyRecord("blocked-delete", async () => ({ kind: "grant", payload: null }));
  await Promise.all([remove, modify]);
  assert.equal(await readFile(log, "utf8"), "D:blocked-delete\nM:blocked-delete\n");
});

test("two independent providers cannot lose a cross-process record rotation", async () => {
  const first = new plugin.KeychainCredentialProvider();
  const second = new plugin.KeychainCredentialProvider();
  const mutate = async (current) => {
    await new Promise((resolve) => setTimeout(resolve, 75));
    return { kind: "grant", payload: { generation: (current?.payload?.generation ?? 0) + 1 } };
  };
  const results = await Promise.all([
    first.modifyRecord("owner/concurrent", mutate),
    second.modifyRecord("owner/concurrent", mutate)
  ]);
  assert.deepEqual(results.map((entry) => entry.payload.generation).sort(), [1, 2]);
});

test("record mutation rejects malformed and lossy records before commit", async () => {
  const provider = new plugin.KeychainCredentialProvider();
  const sparse = [];
  sparse.length = 1;
  const cyclic = {};
  cyclic.self = cyclic;
  const shared = { token: "same" };
  let tooDeep = "leaf";
  for (let index = 0; index < 66; index += 1) tooDeep = { nested: tooDeep };
  const invalid = [
    { kind: "api-key", key: "" },
    { kind: "api-key", env: { "NOT-AN-ENV": "value" } },
    { kind: "api-key", env: { VALID_ENV: "" } },
    { kind: "api-key", unexpected: "secret" },
    { kind: "grant" },
    { kind: "grant", payload: { lost: undefined } },
    { kind: "grant", payload: Number.POSITIVE_INFINITY },
    { kind: "grant", payload: sparse },
    { kind: "grant", payload: cyclic },
    { kind: "grant", payload: { first: shared, second: shared } },
    { kind: "grant", payload: tooDeep }
  ];
  for (const [index, record] of invalid.entries()) {
    await assert.rejects(provider.modifyRecord(`owner/malformed-${index}`, async () => record), /credentials-keychain:/u);
  }
});

test("record normalization never invokes accessors or toJSON and returns only typed app errors", async () => {
  const provider = new plugin.KeychainCredentialProvider();
  const secret = "sk-accessor-secret /Users/example/private request-id-secret";
  let getterCalls = 0;
  let toJSONCalls = 0;
  const getterRecord = { kind: "api-key" };
  Object.defineProperty(getterRecord, "key", {
    enumerable: true,
    get() { getterCalls += 1; throw new Error(secret); }
  });
  const toJSONRecord = { kind: "grant", payload: { token: "safe" } };
  Object.defineProperty(toJSONRecord.payload, "toJSON", {
    get() {
      getterCalls += 1;
      return () => { toJSONCalls += 1; throw new Error(secret); };
    }
  });
  const rejectedCallback = async () => { throw new Error(secret); };

  for (const [subject, mutate] of [
    ["owner/hostile-getter", async () => getterRecord],
    ["owner/hostile-to-json", async () => toJSONRecord],
    ["owner/hostile-rejection", rejectedCallback]
  ]) {
    let caught;
    try { await provider.modifyRecord(subject, mutate); }
    catch (error) { caught = error; }
    assert.equal(caught?.code, "CREDENTIAL_RECORD_PROTOCOL_FAILED");
    assert.equal(caught?.failure?.code, "CREDENTIAL_RECORD_PROTOCOL_FAILED");
    assert.equal(Object.isFrozen(caught?.failure), true);
    assert.doesNotMatch(caught?.message ?? "", /sk-accessor|\/Users\/example|request-id/u);
  }
  assert.equal(getterCalls, 0);
  assert.equal(toJSONCalls, 0);
});

test("record reads and committed protocol trailers are exact and schema checked", async () => {
  const provider = new plugin.KeychainCredentialProvider();
  await assert.rejects(
    provider.readRecord("owner/invalid-read"),
    (error) => error?.code === "CREDENTIAL_RECORD_PROTOCOL_FAILED"
      && /stored credential record is invalid/u.test(error.message)
  );
  for (const subject of ["owner/protocol-extra", "owner/protocol-truncated"]) {
    await assert.rejects(
      provider.modifyRecord(subject, async () => ({ kind: "grant", payload: { token: "exact" } })),
      /invalid native record protocol/u
    );
  }
});

test("an unchanged locked mutation returns the observed record without writing", async () => {
  const provider = new plugin.KeychainCredentialProvider();
  const stored = await provider.modifyRecord("owner/unchanged", async () => ({ kind: "grant", payload: { token: "one" } }));
  const observed = await provider.modifyRecord("owner/unchanged", async () => undefined);
  assert.deepEqual(observed, stored);
});

test("API-key writes and removals preserve invocation order", async () => {
  const log = join(root, "credential-order.log");
  await rm(log, { force: true });
  const first = new plugin.KeychainCredentialProvider();
  await Promise.all([
    first.set("blocked-set", "replacement"),
    first.unset("blocked-set")
  ]);
  assert.equal(await readFile(log, "utf8"), "S:blocked-set\nU:blocked-set\n");

  await rm(log, { force: true });
  const second = new plugin.KeychainCredentialProvider();
  await Promise.all([
    second.unset("blocked-unset"),
    second.set("blocked-unset", "replacement")
  ]);
  assert.equal(await readFile(log, "utf8"), "U:blocked-unset\nS:blocked-unset\n");
});
