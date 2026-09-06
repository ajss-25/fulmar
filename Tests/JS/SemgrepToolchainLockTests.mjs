import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { copyFile, mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import test from "node:test";

const project = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const node = process.execPath;
const verifier = join(project, "scripts", "verify-semgrep-toolchain-lock.mjs");

function run(...args) {
  return spawnSync(node, [verifier, ...args], { encoding: "utf8" });
}

async function copyToolchainFixture() {
  const temporary = await mkdtemp(join(tmpdir(), "fulmar-semgrep-lock-test-"));
  const manifest = JSON.parse(await readFile(join(project, "Config", "SemgrepToolchain.json"), "utf8"));
  await mkdir(join(temporary, "Config"), { mode: 0o700 });
  await copyFile(join(project, "Config", "SemgrepToolchain.json"), join(temporary, "Config", "SemgrepToolchain.json"));
  await copyFile(join(project, manifest.requirementsInput.path), join(temporary, manifest.requirementsInput.path));
  for (const descriptor of Object.values(manifest.locks)) {
    await copyFile(join(project, descriptor.path), join(temporary, descriptor.path));
  }
  return { temporary, manifest };
}

test("reviewed Semgrep dependency closures are complete and hash-bound", () => {
  const result = run("verify", project);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Verified hash-locked Semgrep 1\.135\.0 closures/u);
});

test("Semgrep lock selector accepts only the two reviewed CI platforms", () => {
  const mac = run("select", project, "Darwin:arm64");
  const linux = run("select", project, "Linux:x86_64");
  const unsupported = run("select", project, "Darwin:x86_64");
  assert.equal(mac.status, 0, mac.stderr);
  const macFields = mac.stdout.trim().split("\t");
  assert.deepEqual(macFields, [
    "Config/SemgrepRequirements-macos-arm64.lock",
    "https://github.com/astral-sh/python-build-standalone/releases/download/20240415/cpython-3.12.3%2B20240415-aarch64-apple-darwin-install_only.tar.gz",
    "16814925",
    "ccc40e5af329ef2af81350db2a88bbd6c17b56676e82d62048c15d548401519e",
    "2176",
    "python/bin/python3.12",
    "02f1498c0eff1936ab91de7c411abf49c6f918e11628445cc6502da94d5aa15b"
  ]);
  assert.equal(linux.status, 0, linux.stderr);
  const linuxFields = linux.stdout.trim().split("\t");
  assert.equal(linuxFields.length, 7);
  assert.equal(linuxFields[0], "Config/SemgrepRequirements-linux-x64.lock");
  assert.equal(linuxFields[2], "67368051");
  assert.equal(linuxFields[4], "5191");
  assert.notEqual(unsupported.status, 0);
});

test("Semgrep lock verification rejects changed closure bytes", async () => {
  const { temporary, manifest } = await copyToolchainFixture();
  try {
    const changedPath = join(temporary, manifest.locks["Darwin:arm64"].path);
    const changed = Buffer.concat([await readFile(changedPath), Buffer.from("# drift\n")]);
    await writeFile(changedPath, changed, { mode: 0o600 });
    const result = run("verify", temporary);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /requirements digest changed/u);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("requirements input is exact and digest-bound", async () => {
  const { temporary, manifest } = await copyToolchainFixture();
  try {
    await writeFile(join(temporary, manifest.requirementsInput.path), "semgrep==1.135.0\nsetuptools==80.9.0\nextra-package==1.0\n", { mode: 0o600 });
    const result = run("verify", temporary);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /requirements input bytes changed/u);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("requirement names use PEP 503 canonical duplicate detection", async () => {
  const { temporary, manifest } = await copyToolchainFixture();
  try {
    const descriptor = manifest.locks["Darwin:arm64"];
    const changedPath = join(temporary, descriptor.path);
    const changed = Buffer.concat([
      await readFile(changedPath),
      Buffer.from("typing.extensions==4.16.0 --hash=sha256:0000000000000000000000000000000000000000000000000000000000000000\n")
    ]);
    await writeFile(changedPath, changed, { mode: 0o600 });
    descriptor.sha256 = createHash("sha256").update(changed).digest("hex");
    await writeFile(join(temporary, "Config", "SemgrepToolchain.json"), `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
    const result = run("verify", temporary);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /duplicate requirement typing-extensions/u);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("Semgrep lock digests in the manifest identify the tracked bytes", async () => {
  const manifest = JSON.parse(await readFile(join(project, "Config", "SemgrepToolchain.json"), "utf8"));
  for (const descriptor of Object.values(manifest.locks)) {
    const bytes = await readFile(join(project, descriptor.path));
    assert.equal(createHash("sha256").update(bytes).digest("hex"), descriptor.sha256);
  }
});

test("the lock generator and downloadable Python distributions are content-pinned", async () => {
  const manifest = JSON.parse(await readFile(join(project, "Config", "SemgrepToolchain.json"), "utf8"));
  assert.deepEqual(manifest.lockGeneration, {
    platform: "Darwin:arm64",
    resolverExecutableSHA256: "51f0ae3c531a124727fa39e16e8599f2e371e427822a4aa92ebf667b52548b43",
    pythonExecutableSHA256: "02f1498c0eff1936ab91de7c411abf49c6f918e11628445cc6502da94d5aa15b"
  });
  for (const distribution of Object.values(manifest.pythonDistributions)) {
    assert.match(distribution.url, /^https:\/\/github\.com\/astral-sh\/python-build-standalone\/releases\/download\/20240415\//u);
    assert.ok(Number.isSafeInteger(distribution.bytes) && distribution.bytes > 1_000_000);
    assert.ok(Number.isSafeInteger(distribution.archiveEntries) && distribution.archiveEntries > 100);
    assert.match(distribution.sha256, /^[a-f0-9]{64}$/u);
    assert.match(distribution.executableSHA256, /^[a-f0-9]{64}$/u);
  }
});

test("Python archive verification rejects bytes outside the reviewed content pin", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "fulmar-semgrep-python-archive-"));
  try {
    const archive = join(temporary, "python.tar.gz");
    await writeFile(archive, "not the reviewed archive", { mode: 0o600 });
    const result = run("verify-python-archive", project, "Darwin:arm64", archive);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Python archive does not match the reviewed bytes/u);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("hosted workflow installs Semgrep only from the reviewed hash-locked closure", async () => {
  const workflow = await readFile(join(project, ".github", "workflows", "verify-source.yml"), "utf8");
  assert.doesNotMatch(workflow, /(?:pipx|python[^\n]*-m[ ]+pip|uv[^\n]*tool|brew)[^\n]*install[^\n]*semgrep/iu);
  assert.doesNotMatch(workflow, /actions\/setup-python@/u);
  assert.equal((workflow.match(/\/bin\/bash -p scripts\/install-pinned-semgrep\.sh/g) || []).length, 2);
  assert.ok((workflow.match(/\$GITHUB_PATH/g) || []).length >= 2);
  assert.match(workflow, /VendorRuntime\/node-v22\.23\.1-darwin-arm64\/bin\/node/u);
});

test("maintainer lock regeneration is versioned, time-bounded and reproducibility-checkable", async () => {
  const updater = await readFile(join(project, "scripts", "update-semgrep-locks.sh"), "utf8");
  assert.match(updater, /uv 0\.11\.8/u);
  assert.match(updater, /51f0ae3c531a124727fa39e16e8599f2e371e427822a4aa92ebf667b52548b43/u);
  assert.match(updater, /02f1498c0eff1936ab91de7c411abf49c6f918e11628445cc6502da94d5aa15b/u);
  assert.match(updater, /2026-09-03T00:00:00Z/u);
  assert.match(updater, /\/usr\/bin\/env -i/u);
  assert.match(updater, /--no-config --no-cache --no-python-downloads/u);
  assert.match(updater, /--python "\$PYTHON_INPUT"/u);
  assert.match(updater, /--python-version 3\.12\.3/u);
  assert.match(updater, /--only-binary=:all:/u);
  assert.match(updater, /--generate-hashes/u);
  assert.match(updater, /--check\|--update/u);
  assert.doesNotMatch(updater, /for pair in/u);
});

test("installer verifies exact Python bytes, archive topology, wheel hashes and dependency closure", async () => {
  const installer = await readFile(join(project, "scripts", "install-pinned-semgrep.sh"), "utf8");
  assert.match(installer, /curl --disable/u);
  assert.match(installer, /verify-python-archive/u);
  assert.match(installer, /safe_archive_member/u);
  assert.match(installer, /Python archive contains an unsupported entry type/u);
  assert.match(installer, /sha256_file "\$PYTHON"/u);
  assert.match(installer, /"\$PYTHON" -I -m venv/u);
  assert.match(installer, /--only-binary=:all: --require-hashes/u);
  assert.match(installer, /--no-input --no-deps/u);
  assert.match(installer, /clean_python -m pip check/u);
  assert.match(installer, /SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0/u);
  assert.match(installer, /command_file_identity/u);
  assert.match(installer, /multiply linked/u);
});
