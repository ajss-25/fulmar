import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { link, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { assertCIWorkflowSigningTransport } from "../Fixtures/CISigningTransportSmoke.mjs";

const project = new URL("../..", import.meta.url).pathname.replace(/\/$/u, "");
const generator = join(project, "scripts", "generate-ci-evidence-summary.mjs");
const transportTool = join(project, "scripts", "ci-candidate-transport.mjs");
const sourceRevision = "d".repeat(40);

function run(executable, argumentsList, options = {}) {
  const result = spawnSync(executable, argumentsList, {
    cwd: project,
    encoding: "utf8",
    timeout: 30_000,
    maxBuffer: 4 * 1024 * 1024,
    ...options
  });
  assert.equal(result.error, undefined, result.error?.message);
  return result;
}

function descriptor(file) {
  return { file, bytes: 64, sha256: "a".repeat(64) };
}

async function evidenceFixture(root, vulnerabilities = 0) {
  const identityPath = join(root, "ReleaseIdentity.json");
  const manifestPath = join(root, "release-manifest.json");
  const auditPath = join(root, "dependency-audit-summary.json");
  await writeFile(identityPath, JSON.stringify({
    schemaVersion: 1,
    productDisplayName: "Fulmar",
    bundleIdentifier: "com.angadjairath.localharness",
    appVersion: "9.8.7",
    appBuild: 987,
    minimumMacOS: "15.0",
    releaseArchiveName: "Fulmar.app.zip"
  }), { mode: 0o600 });
  await writeFile(manifestPath, JSON.stringify({
    schemaVersion: 6,
    product: "Fulmar",
    bundleIdentifier: "com.angadjairath.localharness",
    version: "9.8.7",
    build: 987,
    minimumMacOS: "15.0",
    archive: "Fulmar.app.zip",
    archiveBytes: 123_456,
    sha256: "b".repeat(64),
    symbols: descriptor("Fulmar.dSYMs.zip"),
    inventories: {
      vendor: descriptor("VendorRuntime.inventory.json"),
      unsignedRuntime: descriptor("runtime-unsigned-inventory.json"),
      runtimeSignables: descriptor("runtime-signables.json"),
      assembledRuntime: descriptor("runtime-release-inventory.json"),
      buildInputs: descriptor("source-build-inputs.json"),
      staticSecurity: descriptor("static-security-summary.json"),
      toolchain: descriptor("toolchain-inventory.json")
    }
  }), { mode: 0o600 });
  await writeFile(auditPath, JSON.stringify({
    schemaVersion: 1,
    productionOnly: true,
    packageLockSHA256: "c".repeat(64),
    nodeVersion: "v22.23.1",
    npmVersion: "10.9.2",
    vulnerabilities: { total: vulnerabilities },
    unresolved: vulnerabilities === 0 ? [] : [{ name: "fixture" }]
  }), { mode: 0o600 });
  return { identityPath, manifestPath, auditPath };
}

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

async function transportFixture(root) {
  const identityPath = join(root, "ReleaseIdentity.json");
  const artifactRoot = join(root, "transport");
  await mkdir(artifactRoot, { mode: 0o700 });
  const archivePath = join(artifactRoot, "Fulmar.app.zip");
  const manifestPath = join(artifactRoot, "release-manifest.json");
  const evidencePath = join(artifactRoot, "ci-evidence-summary.json");
  const signablesPath = join(artifactRoot, "runtime-signables.json");
  const transportPath = join(artifactRoot, "ci-candidate-transport.json");
  const identity = {
    schemaVersion: 1,
    productDisplayName: "Fulmar",
    applicationBundleName: "Fulmar.app",
    releaseArchiveName: "Fulmar.app.zip",
    bundleIdentifier: "com.angadjairath.localharness",
    appVersion: "9.8.7",
    appBuild: 987,
    minimumMacOS: "15.0"
  };
  const archive = Buffer.from("exact candidate archive fixture\n");
  const signables = Buffer.from(`${JSON.stringify({
    schemaVersion: 1,
    root: "Runtime",
    count: 1,
    paths: ["node"]
  }, null, 2)}\n`);
  const archiveDescriptor = {
    file: "Fulmar.app.zip", bytes: archive.length, sha256: digest(archive)
  };
  const signablesDescriptor = {
    file: "runtime-signables.json", bytes: signables.length, sha256: digest(signables)
  };
  const manifest = {
    schemaVersion: 6,
    product: "Fulmar",
    bundleIdentifier: "com.angadjairath.localharness",
    version: "9.8.7",
    build: 987,
    minimumMacOS: "15.0",
    archive: archiveDescriptor.file,
    archiveBytes: archiveDescriptor.bytes,
    sha256: archiveDescriptor.sha256,
    symbols: descriptor("Fulmar.dSYMs.zip"),
    inventories: {
      vendor: descriptor("VendorRuntime.inventory.json"),
      unsignedRuntime: descriptor("runtime-unsigned-inventory.json"),
      runtimeSignables: signablesDescriptor,
      assembledRuntime: descriptor("runtime-release-inventory.json"),
      buildInputs: descriptor("source-build-inputs.json"),
      staticSecurity: descriptor("static-security-summary.json"),
      toolchain: descriptor("toolchain-inventory.json")
    }
  };
  const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
  const manifestDescriptor = {
    file: "release-manifest.json", bytes: manifestBytes.length, sha256: digest(manifestBytes)
  };
  const evidence = {
    schemaVersion: 1,
    evidenceType: "fulmar-candidate-qualification",
    profile: "deterministic-ci",
    product: "Fulmar",
    bundleIdentifier: "com.angadjairath.localharness",
    version: "9.8.7",
    build: 987,
    minimumMacOS: "15.0",
    candidate: {
      archive: archiveDescriptor.file,
      bytes: archiveDescriptor.bytes,
      sha256: archiveDescriptor.sha256,
      symbols: manifest.symbols
    },
    evidence: {
      releaseManifest: manifestDescriptor,
      dependencyAudit: descriptor("dependency-audit-summary.json"),
      inventories: manifest.inventories,
      productionPackageLockSHA256: "c".repeat(64),
      nodeVersion: "v22.23.1",
      npmVersion: "10.9.2"
    },
    gates: {
      deterministicCandidate: "passed",
      physicalQwenHardware: "required-not-run",
      developerIDAndNotarization: "external-not-established",
      minimumOSCleanInstall: "external-not-established",
      fullGitHistory: "external-not-established"
    },
    finalPublicReleaseQualified: false
  };
  const evidenceBytes = Buffer.from(`${JSON.stringify(evidence, null, 2)}\n`);
  await Promise.all([
    writeFile(identityPath, `${JSON.stringify(identity, null, 2)}\n`, { mode: 0o600 }),
    writeFile(archivePath, archive, { mode: 0o600 }),
    writeFile(manifestPath, manifestBytes, { mode: 0o600 }),
    writeFile(evidencePath, evidenceBytes, { mode: 0o600 }),
    writeFile(signablesPath, signables, { mode: 0o600 })
  ]);
  return {
    identityPath, artifactRoot, archivePath, manifestPath, evidencePath, signablesPath,
    transportPath,
    digests: {
      archive: archiveDescriptor.sha256,
      manifest: manifestDescriptor.sha256,
      evidence: digest(evidenceBytes),
      signables: signablesDescriptor.sha256
    }
  };
}

test("release verifier keeps hardware mandatory by default and exposes one explicit deterministic CI profile", async () => {
  const [
    release, makefile, runner, publicTests, clone, runtime, workflow, build,
    ciDocumentation, readiness, readme, frozen, hostedConsumer, transport
  ] = await Promise.all([
    readFile(join(project, "scripts", "verify-release.sh"), "utf8"),
    readFile(join(project, "Makefile"), "utf8"),
    readFile(join(project, "scripts", "run-js-tests.sh"), "utf8"),
    readFile(join(project, "Tests", "JS", "PublicDistributionScriptsTests.mjs"), "utf8"),
    readFile(join(project, "scripts", "verify-cloned-state-security.sh"), "utf8"),
    readFile(join(project, "scripts", "verify-runtime-security.sh"), "utf8"),
    readFile(join(project, ".github", "workflows", "verify-source.yml"), "utf8"),
    readFile(join(project, "scripts", "build-app.sh"), "utf8"),
    readFile(join(project, "docs", "CI_SECURITY.md"), "utf8"),
    readFile(join(project, "docs", "PUBLIC_RELEASE_READINESS.md"), "utf8"),
    readFile(join(project, "README.md"), "utf8"),
    readFile(join(project, "scripts", "verify-frozen-candidate.sh"), "utf8"),
    readFile(join(project, "scripts", "verify-hosted-candidate-consumer.sh"), "utf8"),
    readFile(transportTool, "utf8")
  ]);

  assert.match(release, /VERIFICATION_PROFILE="full-hardware"/u);
  assert.match(release, /"\$\{1:-\}" == "--deterministic-ci"/u);
  assert.match(release, /if \[\[ "\$VERIFICATION_PROFILE" == "full-hardware" \]\]; then[\s\S]*verify-app-owned-ollama-generation\.sh/u);
  assert.match(release, /if \[\[ "\$VERIFICATION_PROFILE" == "full-hardware" \]\]; then[\s\S]*verify-dsh-qwen-route\.sh" "\$APP_DIR" bash/u);
  assert.match(release, /mandatory 48 GB physical-Qwen generation gate is explicitly not run/u);
  assert.match(release, /This is not final release qualification/u);
  assert.match(makefile, /release-verify:[^\n]*\n\ttest[\s\S]*retain-release-verification\.sh --signing-profile private-stable "\/private\/tmp\/LocalHarnessBuild\/Fulmar\.app"/u);
  assert.match(makefile, /deterministic-release-verify:[\s\S]*verify-release-orchestrated\.sh --signing-profile private-stable --deterministic-ci/u);
  assert.match(makefile, /release-verify:[\s\S]*LOCAL_HARNESS_REQUIRE_STABLE_SIGNING=1[\s\S]*retain-release-verification\.sh/u);
  assert.match(makefile, /deterministic-release-verify:[\s\S]*LOCAL_HARNESS_REQUIRE_STABLE_SIGNING=1[\s\S]*verify-release-orchestrated\.sh --signing-profile private-stable --deterministic-ci/u);
  assert.match(makefile, /release-verify:[\s\S]*retain-release-verification\.sh --signing-profile private-stable/u);
  assert.match(release, /requires the explicit reviewed signing profile: --signing-profile private-stable/u);
  const directWithoutProfile = run(["/bin", "zsh"].join("/"), [
    "-f", join(project, "scripts", "verify-release.sh")
  ], {
    env: {
      HOME: process.env.HOME,
      PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
      LANG: "en_US.UTF-8",
      LC_CTYPE: "UTF-8"
    }
  });
  assert.equal(directWithoutProfile.status, 64);
  assert.match(directWithoutProfile.stderr, /requires the explicit reviewed signing profile/u);
  assert.match(makefile, /build: static-security-scan/u);
  assert.match(makefile, /private-release: static-security-scan/u);
  assert.match(makefile, /build-and-smoke: private-release[\s\S]*\$\(MAKE\) frozen-smoke/u);
  assert.match(makefile, /installed-web-live-canary: frozen-installed-candidate-check/u);
  assert.match(frozen, /source-build-input-inventory\.mjs/u);
  assert.match(frozen, /verify-static-security-summary\.mjs/u);
  assert.match(frozen, /verify-release-manifest\.mjs/u);
  assert.doesNotMatch(frozen, /(?:CANDIDATE|INSTALLED|TARGET)="\$\{(?:CANDIDATE|INSTALLED|TARGET):A\}"/u);
  assert.match(frozen, /for fixed_parent in "\$\{CANDIDATE:h:h\}" "\$\{INSTALLED:h\}"/u);
  assert.match(frozen, /-d "\$CANDIDATE" && ! -L "\$CANDIDATE" && "\$\{CANDIDATE:A\}" == "\$CANDIDATE"/u);
  assert.match(frozen, /if \[\[ "\$TARGET" == "\$INSTALLED" \]\]; then[\s\S]*-d "\$INSTALLED" && ! -L "\$INSTALLED" && "\$\{INSTALLED:A\}" == "\$INSTALLED"/u);
  assert.match(frozen, /REFERENCE="\$CANDIDATE"[\s\S]*"\$TARGET" == "\$INSTALLED"/u);
  assert.match(frozen, /verify-release-tree\.mjs" "\$REFERENCE" "\$EXTRACTED"/u);
  assert.match(frozen, /if \[\[ "\$TARGET" != "\$REFERENCE" \]\]; then[\s\S]*verify-release-tree\.mjs" "\$REFERENCE" "\$TARGET"/u);
  assert.match(frozen, /codesign --verify --deep --strict "\$INSTALLED"/u);
  assert.match(frozen, /exact installed copy/u);
  for (const target of [
    "security-test", "web-rpc-canary", "web-live-canary", "sandbox-test",
    "cloned-state-security", "provider-contract-test", "provider-matrix-test",
    "agent-route-test", "deep-agent-test", "realistic-agent-test", "app-owned-ollama-generation"
  ]) {
    assert.match(makefile, new RegExp(`^${target}: frozen-candidate-check$`, "mu"));
    assert.doesNotMatch(makefile, new RegExp(`^${target}: app$`, "mu"));
  }
  assert.match(build, /CI_EVIDENCE_SUMMARY="\$BUILD_OUTPUT_DIR\/ci-evidence-summary\.json"/u);
  assert.match(build, /generated_release_outputs=\([\s\S]*"\$CI_EVIDENCE_SUMMARY"/u);

  assert.match(runner, /candidate_policy="\$\{FULMAR_CI_REQUIRE_CURRENT_CANDIDATE_TESTS:-0\}"/u);
  assert.match(publicTests, /Clean CI requires the current candidate-dependent public-distribution test/u);
  assert.match(release, /FULMAR_CI_REQUIRE_CURRENT_CANDIDATE_TESTS=1/u);

  assert.match(clone, /fulmar-cloned-state-fixture/u);
  assert.match(clone, /\.fulmar-ci-clone-fixture\.json/u);
  assert.match(clone, /LOCAL_HARNESS_REQUIRE_NONEMPTY_CLONE=1/u);
  assert.match(runtime, /A required deterministic cloned-state canary needs an explicit source fixture/u);
  assert.match(runtime, /The deterministic cloned-state marker was not copied byte-for-byte/u);
  assert.match(runtime, /for _ in \{1\.\.600\}; do/u);
  assert.match(runtime, /\/usr\/bin\/grep -Eo 'dsh web: http:\/\/127\\\.0\\\.0\\\.1:\[0-9\]\+'/u);
  assert.doesNotMatch(runtime, /(^|\n)\s*PORT="\$\(rg\s/u);
  assert.doesNotMatch(runtime, /(^|\n)\s*!?\s*rg\s+-q/gu);

  assert.equal((workflow.match(/persist-credentials: false/gu) ?? []).length, 4);
  assert.match(workflow, /schedule:\n\s+- cron: "17 4 \* \* 1"/u);
  assert.match(workflow, /concurrency:[\s\S]*cancel-in-progress: true/u);
  assert.equal((workflow.match(/\/bin\/bash -p scripts\/verify-tracked-index\.sh \./gu) ?? []).length, 4);
  assert.ok(
    workflow.indexOf("verify-tracked-index.sh") < workflow.indexOf("actions/setup-node"),
    "the static tracked-index gate must precede downloaded tooling"
  );
  const consumerOffset = workflow.indexOf("  minimum-macos-candidate:");
  assert.ok(consumerOffset > workflow.indexOf("  macos:"), "minimum-macOS consumer job is missing");
  const macJob = workflow.slice(workflow.indexOf("  macos:"), consumerOffset);
  const consumerJob = workflow.slice(consumerOffset);
  assert.ok(
    macJob.indexOf("verify-tracked-index.sh") < macJob.indexOf("bootstrap-source-checkout.sh"),
    "the macOS tracked-index gate must precede repository bootstrap code"
  );
  assert.match(macJob, /Darwin:arm64/u);
  assert.match(macJob, /available_kib/u);
  assert.match(macJob, /make dependency-audit/u);
  assertCIWorkflowSigningTransport(project, workflow);
  assert.match(macJob, /make private-release/u);
  assert.doesNotMatch(macJob, /run: make build(?:\s|$)/u);
  assert.match(macJob, /make deterministic-release-verify/u);
  assert.match(macJob, /build\/ci-evidence-summary\.json/u);
  assert.equal((macJob.match(/actions\/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a/gu) ?? []).length, 6);
  assert.match(macJob, /git rev-parse --verify 'HEAD\^\{commit\}'[\s\S]*source_revision[\s\S]*GITHUB_SHA/u);
  assert.equal((macJob.match(/archive: false/gu) ?? []).length, 6);
  assert.equal((macJob.match(/retention-days: 1/gu) ?? []).length, 1);
  assert.equal((macJob.match(/retention-days: 90/gu) ?? []).length, 5);
  const transportedFiles = [
    "Fulmar.app.zip", "release-manifest.json", "ci-evidence-summary.json",
    "runtime-signables.json", "ci-candidate-transport.json"
  ];
  for (const file of transportedFiles) {
    assert.match(macJob, new RegExp(`name: ${file.replaceAll(".", "\\.")}`, "u"));
    assert.match(macJob, new RegExp(`path: \\$\\{\\{ runner\\.temp \\}\\}/fulmar-ci-candidate/${file.replaceAll(".", "\\.")}`, "u"));
  }
  assert.match(macJob, /name: Fulmar\.app\.zip[\s\S]*retention-days: 1/u);
  for (const file of transportedFiles.slice(1)) {
    const escaped = file.replaceAll(".", "\\.");
    assert.match(macJob, new RegExp(`name: ${escaped}[\\s\\S]*?retention-days: 90`, "u"));
  }
  assert.doesNotMatch(
    macJob,
    /^\s+path:\s+(?:(?:build|\/private|\/Users)|[^\n]*(?:\.log(?:\s|$)|\.keychain))/mu
  );

  assert.match(consumerJob, /needs: macos/u);
  assert.match(consumerJob, /runs-on: macos-15/u);
  assert.match(consumerJob, /Darwin:arm64/u);
  assert.match(consumerJob, /sw_vers -productVersion[\s\S]*= "15"/u);
  assert.match(consumerJob, /git rev-parse --verify 'HEAD\^\{commit\}'[\s\S]*GITHUB_SHA/u);
  assert.equal((consumerJob.match(/actions\/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c/gu) ?? []).length, 5);
  assert.equal((consumerJob.match(/artifact-ids: \$\{\{ needs\.macos\.outputs\.[a-z_]+_artifact_id \}\}/gu) ?? []).length, 5);
  assert.equal((consumerJob.match(/skip-decompress: true/gu) ?? []).length, 5);
  assert.equal((consumerJob.match(/digest-mismatch: error/gu) ?? []).length, 5);
  assert.match(consumerJob, /verify-hosted-candidate-consumer\.sh/u);
  assert.doesNotMatch(consumerJob, /bootstrap-source-checkout|make\s|swift\s+build|xcodebuild/u);
  for (const required of [
    "ci-candidate-transport.mjs", "verify-zip-entries.mjs", "ditto -x -k",
    "codesign --verify --deep --strict", "verify-macho-compatibility.sh", "--version"
  ]) assert.match(hostedConsumer, new RegExp(required.replaceAll(".", "\\."), "u"));
  assert.match(hostedConsumer, /codesign --verify --strict "\$BUNDLED_NODE"/u);
  assert.doesNotMatch(hostedConsumer, /shasum[^\n]*BUNDLED_NODE/u);
  assert.match(transport, /sourceRevision[\s\S]*runnerImage: "macos-26"[\s\S]*architecture: "arm64"/u);
  assert.match(transport, /upload digest does not match the downloaded bytes/u);
  assert.match(transport, /contains a private path or control character/u);

  assert.match(ciDocumentation, /green hosted run[\s\S]*not by itself permission to publish/u);
  assert.match(ciDocumentation, /does not scan prior\s+commits/u);
  assert.match(ciDocumentation, /required-not-run/u);
  for (const openGate of [
    "exact Xcode", "macOS 15 ARM consumer", "two different checkout", "Semgrep",
    "complete real Git history", "content-pinned upload"
  ]) assert.match(ciDocumentation, new RegExp(openGate, "u"));
  assert.match(readiness, /docs\/CI_SECURITY\.md/u);
  assert.match(readme, /make deterministic-release-verify/u);
  assert.match(readme, /default `make release-verify` remains the[\s\S]*full-hardware path/u);
});

test("CI evidence generator emits a bounded path-free canonical summary with an explicit hardware boundary", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-ci-evidence."));
  try {
    const inputs = await evidenceFixture(root);
    const destination = join(root, "ci-evidence-summary.json");
    const result = run(process.execPath, [
      generator, "deterministic-ci", inputs.identityPath, inputs.manifestPath, inputs.auditPath, destination
    ]);
    assert.equal(result.status, 0, result.stderr);
    const bytes = await readFile(destination, "utf8");
    const summary = JSON.parse(bytes);
    assert.equal(bytes, `${JSON.stringify(summary, null, 2)}\n`);
    assert.equal(summary.profile, "deterministic-ci");
    assert.equal(summary.gates.deterministicCandidate, "passed");
    assert.equal(summary.gates.physicalQwenHardware, "required-not-run");
    assert.equal(summary.finalPublicReleaseQualified, false);
    assert.equal(summary.candidate.sha256, "b".repeat(64));
    assert.equal(summary.evidence.productionPackageLockSHA256, "c".repeat(64));
    assert.doesNotMatch(bytes, new RegExp(root.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"));
    assert.doesNotMatch(bytes, /generatedAt|HOME|Users\//u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("CI evidence generator fails closed on an unknown profile or a non-zero dependency audit", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-ci-evidence-negative."));
  try {
    let inputs = await evidenceFixture(root);
    let result = run(process.execPath, [
      generator, "skip-hardware", inputs.identityPath, inputs.manifestPath, inputs.auditPath, join(root, "unknown.json")
    ]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /CI evidence profile is unsupported/u);

    inputs = await evidenceFixture(root, 1);
    result = run(process.execPath, [
      generator, "deterministic-ci", inputs.identityPath, inputs.manifestPath, inputs.auditPath, join(root, "audit.json")
    ]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /complete zero-finding production dependency audit/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("CI evidence generator rejects symbolic and hard-linked evidence inputs", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-ci-evidence-links."));
  try {
    const inputs = await evidenceFixture(root);
    const identityTarget = join(root, "identity-target.json");
    const identityLink = join(root, "identity-symbolic.json");
    await writeFile(identityTarget, await readFile(inputs.identityPath), { mode: 0o600 });
    await symlink(identityTarget, identityLink);
    let result = run(process.execPath, [
      generator, "deterministic-ci", identityLink, inputs.manifestPath,
      inputs.auditPath, join(root, "symbolic.json")
    ]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /ELOOP|symbolic|too many levels/iu);

    const auditHardLink = join(root, "audit-hardlink.json");
    await link(inputs.auditPath, auditHardLink);
    result = run(process.execPath, [
      generator, "deterministic-ci", inputs.identityPath, inputs.manifestPath,
      inputs.auditPath, join(root, "hardlink.json")
    ]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /must not be hard linked/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("CI evidence generator rejects path-bearing or control-bearing public fields", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-ci-evidence-private-path."));
  try {
    const inputs = await evidenceFixture(root);
    const manifest = JSON.parse(await readFile(inputs.manifestPath, "utf8"));
    manifest.symbols.file = "/Users/reviewer/private/Fulmar.dSYMs.zip";
    await writeFile(inputs.manifestPath, JSON.stringify(manifest), { mode: 0o600 });
    let result = run(process.execPath, [
      generator, "deterministic-ci", inputs.identityPath, inputs.manifestPath,
      inputs.auditPath, join(root, "path.json")
    ]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /path-free artifact name/u);

    const repaired = await evidenceFixture(root);
    const audit = JSON.parse(await readFile(repaired.auditPath, "utf8"));
    audit.nodeVersion = "v22.23.1\n/private/path";
    await writeFile(repaired.auditPath, JSON.stringify(audit), { mode: 0o600 });
    result = run(process.execPath, [
      generator, "deterministic-ci", repaired.identityPath, repaired.manifestPath,
      repaired.auditPath, join(root, "control.json")
    ]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Node version is not one bounded public value/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("hosted candidate transport canonically binds the exact producer bytes and upload digests", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-hosted-transport."));
  try {
    const fixture = await transportFixture(root);
    let result = run(process.execPath, [
      transportTool, "create", fixture.identityPath, fixture.manifestPath,
      fixture.archivePath, fixture.evidencePath, fixture.signablesPath,
      sourceRevision, fixture.transportPath
    ]);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Created path-free hosted candidate transport evidence/u);

    const transportBytes = await readFile(fixture.transportPath);
    const transport = JSON.parse(transportBytes);
    assert.equal(transportBytes.toString("utf8"), `${JSON.stringify(transport, null, 2)}\n`);
    assert.equal(transport.sourceRevision, sourceRevision);
    assert.deepEqual(transport.producer, { runnerImage: "macos-26", architecture: "arm64" });
    assert.equal(transport.artifacts.archive.sha256, fixture.digests.archive);
    assert.equal(transport.artifacts.releaseManifest.sha256, fixture.digests.manifest);
    assert.equal(transport.artifacts.canonicalEvidence.sha256, fixture.digests.evidence);
    assert.equal(transport.artifacts.runtimeSignables.sha256, fixture.digests.signables);
    assert.doesNotMatch(transportBytes.toString("utf8"), /generatedAt|\/Users\/|\/private\/|\/tmp\//u);

    result = run(process.execPath, [
      transportTool, "verify", fixture.identityPath, fixture.manifestPath,
      fixture.archivePath, fixture.evidencePath, fixture.signablesPath,
      fixture.transportPath, sourceRevision, fixture.digests.archive,
      fixture.digests.manifest, fixture.digests.evidence, fixture.digests.signables,
      digest(transportBytes)
    ]);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Verified exact hosted candidate transport/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("hosted candidate transport fails closed on upload-digest mismatch and unexpected files", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-hosted-transport-negative."));
  try {
    const fixture = await transportFixture(root);
    let result = run(process.execPath, [
      transportTool, "create", fixture.identityPath, fixture.manifestPath,
      fixture.archivePath, fixture.evidencePath, fixture.signablesPath,
      sourceRevision, fixture.transportPath
    ]);
    assert.equal(result.status, 0, result.stderr);
    const transportBytes = await readFile(fixture.transportPath);

    result = run(process.execPath, [
      transportTool, "verify", fixture.identityPath, fixture.manifestPath,
      fixture.archivePath, fixture.evidencePath, fixture.signablesPath,
      fixture.transportPath, sourceRevision, "e".repeat(64),
      fixture.digests.manifest, fixture.digests.evidence, fixture.digests.signables,
      digest(transportBytes)
    ]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /archive upload digest does not match the downloaded bytes/u);

    result = run(process.execPath, [
      transportTool, "verify", fixture.identityPath, fixture.manifestPath,
      fixture.archivePath, fixture.evidencePath, fixture.signablesPath,
      fixture.transportPath, "f".repeat(40), fixture.digests.archive,
      fixture.digests.manifest, fixture.digests.evidence, fixture.digests.signables,
      digest(transportBytes)
    ]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /transport evidence does not match the downloaded candidate/u);

    await writeFile(join(fixture.artifactRoot, "unexpected.txt"), "not reviewed\n", { mode: 0o600 });
    result = run(process.execPath, [
      transportTool, "verify", fixture.identityPath, fixture.manifestPath,
      fixture.archivePath, fixture.evidencePath, fixture.signablesPath,
      fixture.transportPath, sourceRevision, fixture.digests.archive,
      fixture.digests.manifest, fixture.digests.evidence, fixture.digests.signables,
      digest(transportBytes)
    ]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /artifact directory contains an unexpected entry/u);

    const pathCaseRoot = join(root, "path-case");
    await mkdir(pathCaseRoot, { mode: 0o700 });
    const pathCase = await transportFixture(pathCaseRoot);
    const manifest = JSON.parse(await readFile(pathCase.manifestPath, "utf8"));
    manifest.privateNote = "/Users/reviewer/private-candidate";
    const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
    await writeFile(pathCase.manifestPath, manifestBytes, { mode: 0o600 });
    const evidence = JSON.parse(await readFile(pathCase.evidencePath, "utf8"));
    evidence.evidence.releaseManifest.bytes = manifestBytes.length;
    evidence.evidence.releaseManifest.sha256 = digest(manifestBytes);
    await writeFile(pathCase.evidencePath, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
    result = run(process.execPath, [
      transportTool, "create", pathCase.identityPath, pathCase.manifestPath,
      pathCase.archivePath, pathCase.evidencePath, pathCase.signablesPath,
      sourceRevision, pathCase.transportPath
    ]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /manifest contains a private path or control character/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
