#!/usr/bin/env node
import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { chmod, copyFile, mkdtemp, rm, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const helper = process.argv[2] ? resolve(process.argv[2]) : undefined;
assert.ok(helper, "credential helper path is required");
const root = await mkdtemp(join(tmpdir(), "fulmar-keychain-no-ui-"));
const legacy = join(root, "LegacyCredentialHelper");
const reference = `FULMAR_NO_UI_${randomUUID().replaceAll("-", "").toUpperCase()}`;
const orphanReference = `FULMAR_ORPHAN_${randomUUID().replaceAll("-", "").toUpperCase()}`;
const secret = randomBytes(32);
const replacement = randomBytes(32);

function metadataPath(subject) {
  const account = `ref:${subject}`;
  const digest = createHash("sha256").update(account).digest("hex");
  return join(process.env.HOME, "Library", "Application Support", "Local Harness", "CredentialMetadata", `${digest}.json`);
}

function run(executable, args, input, deadline = 3_000) {
  return new Promise((resolveRun, reject) => {
    const child = spawn(executable, args, { stdio: ["pipe", "pipe", "pipe"] });
    const stdout = [];
    const stderr = [];
    let settled = false;
    const started = performance.now();
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish(new Error(`${executable} ${args.join(" ")} exceeded ${deadline} ms`));
    }, deadline);
    const finish = (error, result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolveRun({ ...result, elapsedMilliseconds: performance.now() - started });
    };
    child.on("error", (error) => finish(error));
    child.stdout.on("data", (chunk) => {
      stdout.push(chunk);
      if (Buffer.concat(stdout).length > 1_048_576) child.kill("SIGKILL");
    });
    child.stderr.on("data", (chunk) => {
      stderr.push(chunk);
      if (Buffer.concat(stderr).length > 65_536) child.kill("SIGKILL");
    });
    child.on("close", (status, signal) => finish(undefined, {
      status,
      signal,
      stdout: Buffer.concat(stdout),
      stderr: Buffer.concat(stderr)
    }));
    child.stdin.on("error", (error) => {
      if (error.code !== "EPIPE") finish(error);
    });
    child.stdin.end(input);
  });
}

try {
  await copyFile(helper, legacy);
  await chmod(legacy, 0o700);
  let result = await run("/usr/bin/codesign", [
    "--force", "--options", "runtime", "--sign", "-",
    "--identifier", "com.angadjairath.fulmar.legacy-credential-fixture", legacy
  ]);
  assert.equal(result.status, 0, result.stderr.toString("utf8"));

  // Exercise the exact production backup-authentication service/account. This
  // canary deliberately never deletes or replaces that item: when it is absent,
  // the current reviewed helper creates the same device-only key Fulmar needs;
  // when a previous signature owns it, denial must be typed and prompt-free.
  const currentBackupKey = await run(helper, ["backup-load-or-create"]);
  assert.equal(currentBackupKey.signal, null);
  assert.ok(currentBackupKey.elapsedMilliseconds < 2_500, "backup-key access waited for authorization UI");
  assert.ok([0, 5].includes(currentBackupKey.status), `unexpected backup-key status ${currentBackupKey.status}`);
  if (currentBackupKey.status === 0) {
    assert.equal(currentBackupKey.stdout.length, 32, "backup helper returned a malformed key");
    assert.equal(currentBackupKey.stderr.includes(currentBackupKey.stdout), false, "backup helper diagnostic exposed key bytes");

    const changedSignatureBackupRead = await run(legacy, ["backup-load-or-create"]);
    assert.equal(changedSignatureBackupRead.signal, null);
    assert.ok(changedSignatureBackupRead.elapsedMilliseconds < 2_500, "changed-signature backup read waited for authorization UI");
    assert.ok([0, 5].includes(changedSignatureBackupRead.status), `unexpected changed-signature backup status ${changedSignatureBackupRead.status}`);
    if (changedSignatureBackupRead.status === 0) {
      assert.deepEqual(changedSignatureBackupRead.stdout, currentBackupKey.stdout, "changed-signature backup access rotated the existing key");
    }

    const retainedBackupKey = await run(helper, ["backup-load-or-create"]);
    assert.equal(retainedBackupKey.status, 0, retainedBackupKey.stderr.toString("utf8"));
    assert.deepEqual(retainedBackupKey.stdout, currentBackupKey.stdout, "changed-signature probing mutated the backup key");
  }

  result = await run(legacy, ["set", reference], secret);
  assert.equal(result.status, 0, result.stderr.toString("utf8"));

  const described = await run(helper, ["describe", reference]);
  assert.equal(described.status, 0, "a changed credential-helper identity could not inspect non-secret metadata");
  assert.equal(described.signal, null);
  assert.equal(described.stdout.toString("utf8"), "1");
  assert.ok(described.elapsedMilliseconds < 2_500, "metadata inspection waited as if an authorization UI were active");
  assert.equal(described.stderr.includes(secret), false, "the helper diagnostic exposed credential bytes");

  const changedSignatureReplacement = await run(helper, ["set", reference], replacement);
  assert.equal(changedSignatureReplacement.signal, null);
  assert.ok(changedSignatureReplacement.elapsedMilliseconds < 2_500, "changed-signature replacement waited for authorization UI");
  assert.equal(changedSignatureReplacement.stderr.includes(secret), false, "the replacement diagnostic exposed old credential bytes");
  assert.equal(changedSignatureReplacement.stderr.includes(replacement), false, "the replacement diagnostic exposed new credential bytes");
  assert.ok([0, 5].includes(changedSignatureReplacement.status), `unexpected changed-signature replacement status ${changedSignatureReplacement.status}`);

  const metadataAfterReplacement = await run(helper, ["describe", reference]);
  assert.equal(metadataAfterReplacement.status, 0, metadataAfterReplacement.stderr.toString("utf8"));
  assert.equal(metadataAfterReplacement.stdout.toString("utf8"), "1", "a denied replacement erased pre-existing credential metadata");

  if (changedSignatureReplacement.status === 0) {
    const replaced = await run(helper, ["get", reference]);
    assert.equal(replaced.status, 0, replaced.stderr.toString("utf8"));
    assert.deepEqual(replaced.stdout, replacement, "an admitted atomic replacement did not commit the new credential");
  } else {
    const retained = await run(legacy, ["get", reference]);
    assert.equal(retained.status, 0, retained.stderr.toString("utf8"));
    assert.deepEqual(retained.stdout, secret, "a denied replacement mutated the existing credential");
  }

  result = await run(helper, ["set", orphanReference], secret);
  assert.equal(result.status, 0, result.stderr.toString("utf8"));
  await unlink(metadataPath(orphanReference));
  result = await run(helper, ["describe", orphanReference]);
  assert.equal(result.status, 0, result.stderr.toString("utf8"));
  assert.equal(result.stdout.toString("utf8"), "0", "the metadata-less fixture was not created");
  result = await run(helper, ["set", orphanReference], replacement);
  assert.equal(result.status, 0, result.stderr.toString("utf8"));
  assert.ok(result.elapsedMilliseconds < 2_500, "same-signer orphan adoption waited for authorization UI");
  const adopted = await run(helper, ["get", orphanReference]);
  assert.equal(adopted.status, 0, adopted.stderr.toString("utf8"));
  assert.deepEqual(adopted.stdout, replacement, "the metadata-less credential was not atomically adopted and replaced");

  process.stdout.write("Changed-signature and metadata-less Keychain transitions completed without an authorization dialog or credential loss.\n");
} finally {
  await run(helper, ["unset", orphanReference], undefined).catch(() => {});
  await run(helper, ["unset", reference], undefined).catch(() => {});
  await run(legacy, ["unset", reference], undefined).catch(() => {});
  await rm(root, { recursive: true, force: true });
}
