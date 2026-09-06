import assert from "node:assert/strict";
import test from "node:test";
import { spawn, spawnSync } from "node:child_process";
import { join } from "node:path";

const project = process.cwd();
const node = join(project, "VendorRuntime", "node-v22.23.1-darwin-arm64", "bin", "node");
const redactor = join(project, "scripts", "bounded-redacted-release-stream.mjs");

async function streamOneByteAtATime(input, maximum = 64 * 1024) {
  const child = spawn(node, [redactor, String(maximum)], { stdio: ["pipe", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (value) => { stdout += value; });
  child.stderr.on("data", (value) => { stderr += value; });
  for (const byte of Buffer.from(input)) {
    if (!child.stdin.write(Buffer.of(byte))) {
      await new Promise((resolve) => child.stdin.once("drain", resolve));
    }
    await new Promise((resolve) => setImmediate(resolve));
  }
  child.stdin.end();
  const status = await new Promise((resolve) => child.once("close", resolve));
  return { status, stdout, stderr };
}

test("release stream redacts secrets across every input chunk boundary and complete PEM blocks", async () => {
  const secrets = [
    "release-secret-123456789",
    "local-token-abcdefghijklmnopqrstuvwxyz",
    "sk-releaseCredential123456789",
    "deepseek-secret-abcdefghijklmnopqrstuvwxyz",
    "MIIEvPrivateBodyMustDisappear",
    "quoted-password-abcdefghijklmnopqrstuvwxyz",
    "client-secret-abcdefghijklmnopqrstuvwxyz",
    "access-token-abcdefghijklmnopqrstuvwxyz",
    "url-password-abcdefghijklmnopqrstuvwxyz",
    ["eyJhbGciOiJub25lIn0", "eyJzdWIiOiJwcml2YXRlIn0", "signaturePrivate123"].join("."),
    ["AK", "IA", "ABCDEFGHIJKLMNOP"].join(""),
    "github_pat_abcdefghijklmnopqrstuvwxyz123456",
    "xoxb-1234567890-private-slack-token",
    "hf_abcdefghijklmnopqrstuvwxyz123456",
    "AIzaabcdefghijklmnopqrstuvwxyz1234567890",
    "rk-releaseRestrictedCredential123456789",
    "api_releaseCredential123456789",
    "json-secret-abcdefghijklmnopqrstuvwxyz"
  ];
  const input = [
    `Authorization: Bearer ${secrets[0]}`,
    `x-local-harness-token=${secrets[1]}`,
    secrets[2],
    `api_key: ${secrets[3]}`,
    `password="${secrets[5]}"`,
    `client_secret='${secrets[6]}'`,
    `access_token=${secrets[7]}`,
    `https://release-user:${secrets[8]}@example.invalid/path`,
    secrets[9],
    secrets[10],
    secrets[11],
    secrets[12],
    secrets[13],
    secrets[14],
    secrets[15],
    secrets[16],
    `{"clientSecret":"${secrets[17]}"}`,
    "/Users/privateowner/project/file.swift",
    "-----BEGIN PRIVATE KEY-----",
    secrets[4],
    "another-private-key-line",
    "-----END PRIVATE KEY-----",
    "safe trailing evidence"
  ].join("\n") + "\n";
  const result = await streamOneByteAtATime(input);
  assert.equal(result.status, 0, result.stderr);
  for (const secret of secrets) assert.equal(result.stdout.includes(secret), false, `leaked ${secret}`);
  assert.doesNotMatch(result.stdout, /BEGIN PRIVATE KEY|END PRIVATE KEY|another-private-key-line/u);
  assert.match(result.stdout, /Authorization: Bearer <redacted>/u);
  assert.match(result.stdout, /<redacted private key material>/u);
  assert.match(result.stdout, /\/Users\/<private>\/project/u);
  assert.match(result.stdout, /safe trailing evidence/u);
});

test("a complete single-line PEM is replaced without emitting its body", async () => {
  const body = "singleLinePrivateBodyMustDisappear";
  const result = await streamOneByteAtATime(
    `before\n-----BEGIN PRIVATE KEY-----${body}-----END PRIVATE KEY-----\nafter\n`
  );
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.includes(body), false);
  assert.match(result.stdout, /before\n<redacted private key material>\nafter\n/u);
});

test("release stream fails closed on an overlong line and on aggregate output overflow", () => {
  let result = spawnSync(node, [redactor, String(2 * 1024 * 1024)], {
    input: `${"x".repeat(1024 * 1024 + 1)}\n`, encoding: "utf8", timeout: 5_000
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /oversized/u);

  result = spawnSync(node, [redactor, "1024"], {
    input: `${"a".repeat(600)}\n${"b".repeat(600)}\n`, encoding: "utf8", timeout: 5_000
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /exceeded 1024 bytes/u);
});

test("release stream fails closed on an unterminated private-key block", () => {
  const result = spawnSync(node, [redactor, "4096"], {
    input: "-----BEGIN PRIVATE KEY-----\nprivate-body\n", encoding: "utf8", timeout: 5_000
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /ended inside private key material/u);
  assert.doesNotMatch(result.stdout, /private-body/u);
});
