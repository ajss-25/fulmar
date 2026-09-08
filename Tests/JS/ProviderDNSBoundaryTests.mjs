import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { closeSync, existsSync, fstatSync, unlinkSync } from "node:fs";
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test, { after, before } from "node:test";
import {
  fixtureAuthToken, fixtureInstanceNonce, openRuntimeAuthenticationFixture,
  openRuntimeAuthenticationInput, postHandoffRuntimeAuthenticationStdio,
  runtimeAuthenticationFrame
} from "../Fixtures/RuntimeAuthenticationInput.mjs";

const project = resolve(import.meta.dirname, "../..");
const preload = join(project, "Resources", "RuntimeSecurityPreload.mjs");
const stub = join(project, "Tests", "Fixtures", "RuntimeSecurityGuardedFetchStubPreload.mjs");
const actualFetchTraversalStub = join(
  project,
  "Tests",
  "Fixtures",
  "RuntimeSecurityActualFetchTraversalPreload.mjs"
);
let root;
let runtimeRoot;

before(async () => {
  root = await realpath(await mkdtemp(join(tmpdir(), "fulmar-provider-dns-")));
  runtimeRoot = join(root, "runtime");
  for (const packageName of [
    "dsh-credentials-keychain",
    "dsh-mcp-guarded",
    "dsh-client-security-bridge",
    "dsh-performance-profile",
    "dsh-fs-confined",
    "dsh-web-fetch-safe"
  ]) {
    const directory = join(runtimeRoot, "node_modules", "@local-harness", packageName);
    await mkdir(directory, { recursive: true });
    await writeFile(join(directory, "index.mjs"), "export {};\n", { mode: 0o600 });
  }
  await mkdir(join(root, "home", ".dsh", "profiles"), { recursive: true });
});

after(async () => {
  if (root) await rm(root, { recursive: true, force: true });
});

function childEnvironment(origins) {
  return {
    HOME: join(root, "home"),
    PATH: "/usr/bin:/bin",
    DSH_HOME: join(root, "home", ".dsh"),
    LOCAL_HARNESS_STRICT_LOCAL: "0",
    LOCAL_HARNESS_SANDBOX_HELPER: "/usr/bin/false",
    LOCAL_HARNESS_PROVIDER_ORIGINS: typeof origins === "string" ? origins : JSON.stringify(origins),
    LOCAL_HARNESS_RUNTIME_ROOT: runtimeRoot
  };
}

async function runChild({
  origins,
  script = "process.exit(0)",
  arguments: childArguments = [],
  useStub = false,
  preloadFixture
}) {
  const nodeArguments = [
    ...((preloadFixture ?? (useStub ? stub : undefined)) ? ["--import", preloadFixture ?? stub] : []),
    "--import", preload,
    "--input-type=module", "-e", script,
    ...childArguments
  ];
  const authenticationInput = openRuntimeAuthenticationInput(fixtureAuthToken, fixtureInstanceNonce);
  const handoff = postHandoffRuntimeAuthenticationStdio(authenticationInput);
  let child;
  try {
    child = spawn(process.execPath, nodeArguments, {
      env: { ...childEnvironment(origins), ...handoff.env },
      stdio: handoff.stdio
    });
  } finally {
    handoff.close();
    closeSync(authenticationInput);
  }
  assert.throws(() => fstatSync(authenticationInput), (error) => error?.code === "EBADF",
    "the launching parent retained its runtime authentication descriptor");
  const output = [];
  child.stdout.on("data", (chunk) => output.push(chunk));
  child.stderr.on("data", (chunk) => output.push(chunk));
  const result = await new Promise((resolveChild) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      resolveChild({ code: undefined, signal: "TIMEOUT" });
    }, 5_000);
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      resolveChild({ code, signal });
    });
  });
  return { ...result, output: Buffer.concat(output).toString("utf8") };
}

const fetchProbe = `
  import assert from "node:assert/strict";
  import dns from "node:dns";
  import net from "node:net";
  const [host, expected] = process.argv.slice(1);
  const authority = net.isIP(host) === 6 ? \`[\${host}]\` : host;
  const url = \`https://\${authority}/v1/chat/completions\`;
  try {
    const response = await fetch(url, { method: "POST", body: "{}" });
    assert.equal(expected, "allow");
    assert.equal(await response.text(), "GUARDED_TLS_OK");
    assert.equal(typeof globalThis.__localHarnessLastTLSOptions.lookup, "function");
    if (net.isIP(host) === 0) assert.ok(globalThis.__localHarnessDNSStubCalls > 0);
  } catch (error) {
    if (expected !== "deny" || error?.code !== "EACCES") throw error;
  }
  assert.throws(() => dns.lookup(host, () => {}), (error) => error?.code === "EACCES");
  if (globalThis.__localHarnessLastTLSOptions?.lookup) {
    assert.throws(
      () => net.Socket.prototype.connect.call({}, {
        host,
        port: 443,
        lookup: globalThis.__localHarnessLastTLSOptions.lookup
      }),
      (error) => error?.code === "EACCES"
    );
  }
`;

test("provider capability schema fails closed on missing, invalid, or conflicting boundaries", async () => {
  const malformed = [
    [{ scheme: "https", host: "public.example", port: 443 }],
    [{ scheme: "https", host: "public.example", port: 443, boundary: "internet" }],
    [{ scheme: "https", host: "public.example", port: 443, boundary: "cloud", extra: true }],
    [
      { scheme: "https", host: "public.example", port: 443, boundary: "cloud" },
      { scheme: "https", host: "public.example", port: 443, boundary: "localNetwork" }
    ],
    "not-json"
  ];
  for (const origins of malformed) {
    const result = await runChild({ origins });
    assert.notEqual(result.code, 0, JSON.stringify(origins));
    assert.equal(result.signal, null);
  }
});

test("cloud literal capabilities reject private and reserved IPv4 and IPv6 ranges", async () => {
  for (const host of [
    "0.0.0.0", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.169.254",
    "172.16.0.1", "192.0.2.1", "192.168.1.1", "198.18.0.1", "198.51.100.1",
    "203.0.113.1", "224.0.0.1", "::", "::1", "::ffff:127.0.0.1", "fc00::1",
    "fe80::1", "ff02::1", "2001:db8::1", "2001:2::1", "2001:10::1",
    "2001:20::1", "2002:0a00:0001::1", "3ffe::1", "3fff::1"
  ]) {
    const result = await runChild({
      origins: [{ scheme: "https", host, port: 443, boundary: "cloud" }]
    });
    assert.notEqual(result.code, 0, host);
  }
});

test("cloud DNS rejects private, reserved, mixed, and rebinding results before content", async () => {
  for (const host of ["private.example", "private-v6.example", "mixed.example", "rebind.example"]) {
    const result = await runChild({
      origins: [{ scheme: "https", host, port: 443, boundary: "cloud" }],
      script: fetchProbe,
      arguments: [host, "deny"],
      useStub: true
    });
    assert.deepEqual({ code: result.code, signal: result.signal }, { code: 0, signal: null }, `${host}\n${result.output}`);
  }
});

test("guarded cloud fetch traverses the private lookup hook and accepts public IPv4 and IPv6", async () => {
  for (const host of ["public.example", "public-v6.example"]) {
    const result = await runChild({
      origins: [{ scheme: "https", host, port: 443, boundary: "cloud" }],
      script: fetchProbe,
      arguments: [host, "allow"],
      useStub: true
    });
    assert.deepEqual({ code: result.code, signal: result.signal }, { code: 0, signal: null }, `${host}\n${result.output}`);
  }
});

test("the pinned Node fetch implementation traverses guarded TLS and the injected lookup", async () => {
  const result = await runChild({
    origins: [{ scheme: "https", host: "public.example", port: 443, boundary: "cloud" }],
    preloadFixture: actualFetchTraversalStub,
    script: `
      import assert from "node:assert/strict";
      const cancellation = new AbortController();
      const timer = setTimeout(() => cancellation.abort(), 500);
      try { await fetch("https://public.example/v1/models", { signal: cancellation.signal }); }
      catch {}
      clearTimeout(timer);
      assert.ok(globalThis.__localHarnessActualFetchTLSCalls > 0);
      assert.ok(globalThis.__localHarnessActualFetchDNSCalls > 0);
      assert.equal(globalThis.__localHarnessActualFetchLookupSeen, true);
      process.exit(0);
    `
  });
  assert.deepEqual({ code: result.code, signal: result.signal }, { code: 0, signal: null }, result.output);
});

test("local-network and on-device boundaries admit only matching peers", async () => {
  for (const fixture of [
    { host: "192.168.1.20", boundary: "localNetwork" },
    { host: "fd00::20", boundary: "localNetwork" },
    { host: "127.0.0.1", boundary: "onDevice" },
    { host: "::1", boundary: "onDevice" }
  ]) {
    const result = await runChild({
      origins: [{ scheme: "https", host: fixture.host, port: 443, boundary: fixture.boundary }],
      script: fetchProbe,
      arguments: [fixture.host, "allow"],
      useStub: true
    });
    assert.deepEqual({ code: result.code, signal: result.signal }, { code: 0, signal: null }, `${fixture.host}\n${result.output}`);
  }

  for (const fixture of [
    { host: "93.184.216.34", boundary: "localNetwork" },
    { host: "192.168.1.20", boundary: "onDevice" }
  ]) {
    const result = await runChild({
      origins: [{ scheme: "https", host: fixture.host, port: 443, boundary: fixture.boundary }]
    });
    assert.notEqual(result.code, 0, JSON.stringify(fixture));
  }
});

test("runtime authentication is consumed from its dedicated descriptor before application code", async () => {
  const ready = join(root, "runtime-auth-ready.json");
  const authenticationInput = openRuntimeAuthenticationInput(fixtureAuthToken, fixtureInstanceNonce);
  const handoff = postHandoffRuntimeAuthenticationStdio(authenticationInput);
  let child;
  try {
    child = spawn(process.execPath, [
      "--import", preload, "--input-type=module", "-e", String.raw`
        import fs from "node:fs";
        const ready = process.argv[1];
        // Descriptor 0 must stay occupied for the whole process lifetime: libuv
        // claims the lowest free descriptor while initializing a stream and
        // aborts in uv__close when that number is a standard descriptor. The
        // record itself must be unreachable, whichever descriptor carried it.
        const standardInput = fs.fstatSync(0, { bigint: true });
        let drained = -1;
        try { drained = fs.readSync(0, Buffer.alloc(1), 0, 1, null); } catch { drained = -2; }
        let reachable = 0;
        for (let descriptor = 0; descriptor < 64; descriptor += 1) {
          let metadata;
          try { metadata = fs.fstatSync(descriptor, { bigint: true }); } catch { continue; }
          if (metadata.isFile() && metadata.nlink === 0n && (metadata.mode & 0o777n) === 0o600n
            && metadata.uid === BigInt(process.getuid())
            && metadata.size >= 64n && metadata.size <= 384n) { reachable += 1; }
        }
        const safe = standardInput.isCharacterDevice() && drained === 0 && reachable === 0
          && process.env.LOCAL_HARNESS_RUNTIME_AUTH_FD === undefined
          && process.env.LOCAL_HARNESS_AUTH_TOKEN === undefined
          && process.env.LOCAL_HARNESS_INSTANCE_NONCE === undefined
          && process.argv.length === 2;
        fs.writeFileSync(ready, JSON.stringify({
          pid: process.pid, ppid: process.ppid, safe, drained, reachable
        }), { mode: 0o600 });
        setTimeout(() => process.exit(safe ? 0 : 91), 1500);
      `, ready
    ], {
      env: { ...childEnvironment([]), ...handoff.env },
      stdio: handoff.stdio
    });
  } finally {
    handoff.close();
    closeSync(authenticationInput);
  }
  assert.throws(() => fstatSync(authenticationInput), (error) => error?.code === "EBADF",
    "the paused launching parent retained its runtime authentication descriptor");
  const output = [];
  child.stdout.on("data", (chunk) => output.push(chunk));
  child.stderr.on("data", (chunk) => output.push(chunk));
  const outcomePromise = new Promise((resolveChild) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      resolveChild({ code: undefined, signal: "TIMEOUT" });
    }, 5_000);
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      resolveChild({ code, signal });
    });
  });
  for (let attempt = 0; attempt < 100 && !existsSync(ready); attempt += 1) {
    await new Promise((resolveWait) => setTimeout(resolveWait, 20));
  }
  assert.equal(existsSync(ready), true, "paused runtime authentication probe did not start");
  const report = JSON.parse(await readFile(ready, "utf8"));
  assert.equal(report.safe, true, JSON.stringify(report));
  assert.equal(report.drained, 0, "standard input was not an empty, readable null device");
  assert.equal(report.reachable, 0, "application code could still reach the authentication record");
  assert.equal(report.pid, child.pid);

  const processListing = spawnSync("/bin/ps", ["-axo", "pid=,ppid=,command="], {
    encoding: "utf8", timeout: 2_000
  });
  const environmentListing = spawnSync("/bin/ps", ["eww", "-p", String(child.pid)], {
    encoding: "utf8", timeout: 2_000
  });
  for (const listing of [processListing.stdout, environmentListing.stdout]) {
    assert.equal(listing.includes(fixtureAuthToken) || listing.includes(fixtureInstanceNonce), false,
      "runtime authentication material appeared in a process listing");
  }
  const descriptors = spawnSync("/usr/sbin/lsof", ["-a", "-p", String(child.pid), "-d", "0", "-Fftn"], {
    encoding: "utf8", timeout: 2_000
  });
  assert.match(descriptors.stdout, /^n\/dev\/null$/mu,
    "application code did not receive the verified null device on standard input");
  assert.doesNotMatch(descriptors.stdout, /^tREG$/mu,
    "application code retained a regular file on standard input");
  const outcome = await outcomePromise;
  const transcript = Buffer.concat(output).toString("utf8");
  assert.deepEqual(outcome, { code: 0, signal: null }, transcript);
  assert.equal(transcript.includes(fixtureAuthToken) || transcript.includes(fixtureInstanceNonce), false,
    "runtime authentication material appeared in the child transcript");
  const artifact = await readFile(ready, "utf8");
  assert.equal(artifact.includes(fixtureAuthToken) || artifact.includes(fixtureInstanceNonce), false,
    "runtime authentication material appeared in a fixture artifact");
});

test("runtime authentication stdin rejects malformed, linked, wrong-mode, oversized, and replayed records", () => {
  const validFrame = runtimeAuthenticationFrame(fixtureAuthToken, fixtureInstanceNonce);
  const fixtures = [
    openRuntimeAuthenticationFixture(validFrame.subarray(0, validFrame.length - 3)),
    openRuntimeAuthenticationFixture(Buffer.alloc(385, 0x61)),
    openRuntimeAuthenticationFixture(Buffer.from("FULMAR_RUNTIME_AUTH_V1:bad:frame\n", "utf8")),
    openRuntimeAuthenticationFixture(validFrame, { linked: true }),
    openRuntimeAuthenticationFixture(validFrame, { mode: 0o640 }),
    openRuntimeAuthenticationFixture(validFrame, { consumeBytes: 1 })
  ];
  for (const fixture of fixtures) {
    const handoff = postHandoffRuntimeAuthenticationStdio(fixture.descriptor);
    try {
      const result = spawnSync(process.execPath, [
        "--import", preload, "--input-type=module", "-e", "process.exit(92)"
      ], {
        env: { ...childEnvironment([]), ...handoff.env },
        stdio: handoff.stdio,
        encoding: "utf8",
        timeout: 3_000
      });
      assert.notEqual(result.status, 0, "preloader accepted an unsafe authentication record");
      assert.equal(result.signal, null, "preloader hung on an unsafe authentication record");
      assert.equal(result.stdout.includes(fixtureAuthToken) || result.stderr.includes(fixtureAuthToken)
        || result.stdout.includes(fixtureInstanceNonce) || result.stderr.includes(fixtureInstanceNonce), false,
      "preloader disclosed rejected authentication material");
    } finally {
      handoff.close();
      closeSync(fixture.descriptor);
      if (fixture.linkedPath) unlinkSync(fixture.linkedPath);
    }
  }

  const legacyInput = openRuntimeAuthenticationInput(fixtureAuthToken, fixtureInstanceNonce);
  const legacyHandoff = postHandoffRuntimeAuthenticationStdio(legacyInput);
  try {
    const legacy = spawnSync(process.execPath, [
      "--import", preload, "--input-type=module", "-e", "process.exit(93)"
    ], {
      env: {
        ...childEnvironment([]),
        ...legacyHandoff.env,
        LOCAL_HARNESS_AUTH_TOKEN: fixtureAuthToken,
        LOCAL_HARNESS_INSTANCE_NONCE: fixtureInstanceNonce
      },
      stdio: legacyHandoff.stdio,
      encoding: "utf8",
      timeout: 3_000
    });
    assert.notEqual(legacy.status, 0, "preloader accepted legacy environment authentication");
    assert.equal(legacy.stdout.includes(fixtureAuthToken) || legacy.stderr.includes(fixtureAuthToken)
      || legacy.stdout.includes(fixtureInstanceNonce) || legacy.stderr.includes(fixtureInstanceNonce), false,
    "preloader disclosed legacy authentication material");
  } finally {
    legacyHandoff.close();
    closeSync(legacyInput);
  }
});

test("runtime authentication rejects an unpublished, standard, or malformed descriptor number", () => {
  // The descriptor number is the only thing the native lease publishes, so an
  // absent, standard, or forged number must fail closed rather than let the
  // preloader read or close something it does not own.
  for (const published of [undefined, "", "0", "1", "2", "-1", "3.0", " 3", "03", "abc", "999999"]) {
    const authenticationInput = openRuntimeAuthenticationInput(fixtureAuthToken, fixtureInstanceNonce);
    const handoff = postHandoffRuntimeAuthenticationStdio(authenticationInput);
    try {
      const environment = { ...childEnvironment([]), ...handoff.env };
      if (published === undefined) {
        delete environment.LOCAL_HARNESS_RUNTIME_AUTH_FD;
      } else {
        environment.LOCAL_HARNESS_RUNTIME_AUTH_FD = published;
      }
      const result = spawnSync(process.execPath, [
        "--import", preload, "--input-type=module", "-e", "process.exit(94)"
      ], { env: environment, stdio: handoff.stdio, encoding: "utf8", timeout: 3_000 });
      assert.notEqual(result.status, 0,
        `preloader accepted the descriptor number ${JSON.stringify(published)}`);
      assert.equal(result.signal, null,
        `preloader aborted on the descriptor number ${JSON.stringify(published)}`);
      assert.equal(result.stdout.includes(fixtureAuthToken) || result.stderr.includes(fixtureAuthToken)
        || result.stdout.includes(fixtureInstanceNonce) || result.stderr.includes(fixtureInstanceNonce), false,
      "preloader disclosed authentication material while refusing a descriptor number");
    } finally {
      handoff.close();
      closeSync(authenticationInput);
    }
  }
});

test("runtime authentication refuses a record that is still reachable through standard input", () => {
  // Descriptor 0 must never carry the record once the runtime is executing:
  // application code would be able to read it, and closing it is what aborted
  // libuv. Publishing a second descriptor onto the same record is refused.
  const authenticationInput = openRuntimeAuthenticationInput(fixtureAuthToken, fixtureInstanceNonce);
  try {
    const result = spawnSync(process.execPath, [
      "--import", preload, "--input-type=module", "-e", "process.exit(95)"
    ], {
      env: { ...childEnvironment([]), LOCAL_HARNESS_RUNTIME_AUTH_FD: "3" },
      stdio: [authenticationInput, "pipe", "pipe", authenticationInput],
      encoding: "utf8",
      timeout: 3_000
    });
    assert.notEqual(result.status, 0, "preloader accepted a record still reachable through stdin");
    assert.equal(result.signal, null, "preloader aborted on a record still reachable through stdin");
    assert.equal(result.stdout.includes(fixtureAuthToken) || result.stderr.includes(fixtureAuthToken)
      || result.stdout.includes(fixtureInstanceNonce) || result.stderr.includes(fixtureInstanceNonce), false,
    "preloader disclosed authentication material while refusing a reachable record");
  } finally {
    closeSync(authenticationInput);
  }
});

test("runtime authentication survives pipe-backed streams and a lazy process import", () => {
  // The reproduced startup abort. Consuming the record used to close descriptor
  // 0; libuv then claimed that vacant standard slot while initializing a
  // pipe-backed stream and aborted in uv__close ("fd > STDERR_FILENO"). Node's
  // own spawn uses socket pairs, which never reproduced it, so this case drives
  // the runtime through a shell that gives it real POSIX pipes on both output
  // streams, exactly as Foundation's Process does. Completion is ordinary
  // event-loop exhaustion, never process.exit().
  const observation = String.raw`
    await import("node:process");
    const fs = await import("node:fs");
    const standardInput = fs.fstatSync(0, { bigint: true });
    let drained = -1;
    try { drained = fs.readSync(0, Buffer.alloc(1), 0, 1, null); } catch { drained = -2; }
    let reachable = 0;
    for (let descriptor = 0; descriptor < 64; descriptor += 1) {
      let metadata;
      try { metadata = fs.fstatSync(descriptor, { bigint: true }); } catch { continue; }
      if (metadata.isFile() && metadata.nlink === 0n && (metadata.mode & 0o777n) === 0o600n
        && metadata.uid === BigInt(process.getuid())
        && metadata.size >= 64n && metadata.size <= 384n) { reachable += 1; }
    }
    const safe = standardInput.isCharacterDevice() && drained === 0 && reachable === 0
      && process.env.LOCAL_HARNESS_RUNTIME_AUTH_FD === undefined;
    process.stderr.write("HANDOFF_STDERR\n");
    process.stdout.write(safe ? "HANDOFF_OK\n" : "HANDOFF_BAD_" + drained + "_" + reachable + "\n");
  `;
  const shapes = [
    { name: "merged pipe", shell: 'setopt PIPE_FAIL; ulimit -c 0; "$@" 2>&1 | /bin/cat', merged: true },
    { name: "separate pipes", shell: 'ulimit -c 0; "$@" > >(/bin/cat) 2> >(/bin/cat >&2); exit $?', merged: false }
  ];
  for (const shape of shapes) {
    for (const order of ["stdout-first", "stderr-first"]) {
      const lead = order === "stdout-first"
        ? 'process.stdout.write("");'
        : 'process.stderr.write("");';
      const authenticationInput = openRuntimeAuthenticationInput(fixtureAuthToken, fixtureInstanceNonce);
      const handoff = postHandoffRuntimeAuthenticationStdio(authenticationInput);
      try {
        const result = spawnSync("/bin/zsh", [
          "-f", "-c", shape.shell, "probe",
          process.execPath, "--import", preload, "--input-type=module", "-e", lead + observation
        ], {
          env: { ...childEnvironment([]), ...handoff.env },
          stdio: handoff.stdio,
          encoding: "utf8",
          timeout: 5_000
        });
        const label = `${shape.name}/${order}`;
        assert.equal(result.signal, null, `${label} runtime was signalled: ${result.stderr}`);
        assert.equal(result.status, 0,
          `${label} runtime did not complete normally: ${result.stdout}${result.stderr}`);
        assert.match(result.stdout, /HANDOFF_OK/u,
          `${label} runtime did not observe the expected descriptor state: ${result.stdout}`);
        const transcript = shape.merged ? result.stdout : result.stderr;
        assert.match(transcript, /HANDOFF_STDERR/u, `${label} runtime lost its standard error`);
        assert.equal(result.stdout.includes(fixtureAuthToken) || result.stderr.includes(fixtureAuthToken)
          || result.stdout.includes(fixtureInstanceNonce) || result.stderr.includes(fixtureInstanceNonce),
        false, `${label} runtime disclosed authentication material`);
      } finally {
        handoff.close();
        closeSync(authenticationInput);
      }
    }
  }
});
