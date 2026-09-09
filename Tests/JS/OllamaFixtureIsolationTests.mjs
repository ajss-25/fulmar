import assert from "node:assert/strict";
import test from "node:test";
import http from "node:http";
import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { spawn, spawnSync } from "node:child_process";
import { join } from "node:path";

const project = process.cwd();
const node = join(project, "VendorRuntime", "node-v22.23.1-darwin-arm64", "bin", "node");

test("Qwen qualification never reuses the conventional Ollama listener", async (context) => {
  const route = await readFile(join(project, "scripts", "verify-dsh-qwen-route.sh"), "utf8");
  const fetcher = await readFile(join(project, "scripts", "attested-loopback-fetch.zsh"), "utf8");
  assert.match(route, /allocate-loopback-port\.mjs" --exclude 11434/u);
  assert.match(route, /OLLAMA_PORT.*!= 11434/u);
  assert.match(route, /lsof -nP -a -iTCP@127\.0\.0\.1:/u);
  assert.match(route, /listeners" == "\$OLLAMA_LISTENER_PID"/u);
  assert.match(route, /fulmar_attest_sole_inherited_child/u);
  assert.match(route, /fulmar_attest_pid_in_process_group "\$OLLAMA_LISTENER_PID" "\$OLLAMA_FIXTURE_GROUP_ID"/u);
  assert.equal(route.match(/fulmar_fetch_attested_loopback_json/gu)?.length, 2);
  assert.doesNotMatch(route, /curl[^\n]*api\/(?:version|tags)/u);
  const fetchStart = fetcher.indexOf("fulmar_fetch_attested_loopback_json() (");
  const preflight = fetcher.indexOf("attest_exact_listener || return 1", fetchStart);
  const request = fetcher.indexOf("/usr/bin/curl", preflight);
  const postflight = fetcher.indexOf("attest_exact_listener || return 1", preflight + 1);
  assert.ok(fetchStart >= 0 && preflight > fetchStart && request > preflight && postflight > request,
    "the exact listener must be attested immediately before and after every HTTP fetch");
  assert.match(fetcher, /setopt noclobber[\s\S]*exec \{response_fd\}> "\$destination"/u);
  assert.match(fetcher, /-o "\/dev\/fd\/\$response_fd"/u);
  assert.match(fetcher, /rm -f -- "\$destination"/u);
  assert.match(route, /codesign --verify --strict --requirements/u);
  assert.doesNotMatch(route, /http:\/\/127\.0\.0\.1:11434/u);

  let requests = 0;
  const malicious = http.createServer((_request, response) => {
    requests += 1;
    response.writeHead(200, { "content-type": "application/json" });
    response.end('{"version":"999.999.999"}');
  });
  const listening = await new Promise((resolve) => {
    malicious.once("error", (error) => resolve({ error }));
    malicious.listen({ host: "127.0.0.1", port: 11434, exclusive: true }, () => resolve({ error: null }));
  });
  if (listening.error?.code === "EADDRINUSE") {
    context.diagnostic("port 11434 was already occupied by an untrusted listener; allocator isolation still exercised");
  } else {
    assert.equal(listening.error, null, listening.error?.message);
  }
  try {
    const result = spawnSync(node, [
      join(project, "scripts", "allocate-loopback-port.mjs"), "--exclude", "11434"
    ], { encoding: "utf8", timeout: 5_000 });
    assert.equal(result.error, undefined, result.error?.message);
    assert.equal(result.status, 0, result.stderr);
    const selected = Number(result.stdout.trim());
    assert.ok(Number.isSafeInteger(selected) && selected >= 1024 && selected <= 65535);
    assert.notEqual(selected, 11434);
    assert.equal(requests, 0, "the untrusted conventional listener must not receive a probe");
  } finally {
    if (malicious.listening) await new Promise((resolve) => malicious.close(resolve));
  }
});

test("a malicious winner of the selected random port receives no attested fetch", async () => {
  const root = await mkdtemp("/private/tmp/fulmar-attested-fetch-test.");
  const destination = join(root, "response.json");
  let requests = 0;
  const malicious = http.createServer((_request, response) => {
    requests += 1;
    response.writeHead(200, { "content-type": "application/json" });
    response.end('{"version":"malicious"}');
  });
  await new Promise((resolve, reject) => {
    malicious.once("error", reject);
    malicious.listen({ host: "127.0.0.1", port: 0, exclusive: true }, resolve);
  });
  const unrelated = spawn("/bin/sleep", ["20"], { stdio: "ignore" });
  try {
    const address = malicious.address();
    assert.equal(typeof address, "object");
    const result = spawnSync("/bin/zsh", ["-f",
      join(project, "scripts", "attested-loopback-fetch.zsh"),
      String(unrelated.pid), String(process.pid), String(address.port),
      "/api/version", destination, "1", "256"
    ], { encoding: "utf8", timeout: 4_000 });
    assert.equal(result.error, undefined, result.error?.message);
    assert.notEqual(result.status, 0, "a listener PID mismatch must fail closed");
    assert.equal(requests, 0, "listener attestation must happen before sending any HTTP request");
    await assert.rejects(access(destination), { code: "ENOENT" });
  } finally {
    unrelated.kill("SIGKILL");
    await new Promise((resolve) => unrelated.once("exit", resolve));
    await new Promise((resolve) => malicious.close(resolve));
    await rm(root, { recursive: true, force: true });
  }
});

test("local-model qualification commands are bounded exact-group supervisors", async () => {
  const [route, appOwned, supervisor] = await Promise.all([
    readFile(join(project, "scripts", "verify-dsh-qwen-route.sh"), "utf8"),
    readFile(join(project, "scripts", "verify-app-owned-ollama-generation.sh"), "utf8"),
    readFile(join(project, "scripts", "supervised-process-group.zsh"), "utf8")
  ]);
  for (const script of [route, appOwned]) {
    assert.match(script, /run-with-watchdog\.sh" \\\n[\s\S]*?--lock-dir \/private\/tmp\/LocalHarnessBuild\.lock/u);
    assert.match(script, /run-with-watchdog\.sh" --inherit-root/u);
    assert.match(script, /fulmar_attest_pid_in_process_group/u);
    assert.match(script, /fulmar_stop_inherited_process/u);
    assert.doesNotMatch(script, /max-rss-bytes (?:4[2-9]|[5-9][0-9])\s*\*?\s*1024/u);
  }
  assert.match(route, /--max-rss-bytes 34359738368[\s\S]*?--emergency-rss-bytes 38654705664/u);
  assert.match(appOwned, /--max-rss-bytes 30064771072[\s\S]*?--emergency-rss-bytes 34359738368/u);
  assert.match(supervisor, /fulmar_stop_inherited_process/u);
  assert.match(supervisor, /kill -TERM -- "-\$group_id"/u);
  assert.match(supervisor, /kill -KILL -- "-\$group_id"/u);
  assert.match(supervisor, /attempt <= 80/u);
  assert.match(supervisor, /attempt <= 40/u);
});
