import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  copyFile,
  link,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  writeFile
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  loadPinnedRuleManifest,
  parsePinnedRuleManifest,
  validatePinnedRuleBytes
} from "../../scripts/pinned-semgrep-rules.mjs";
import {
  collectSecretTextFiles,
  enforceExactSecretCoverage,
  enforceReportWarnings,
  enforceTopLevelCoverage,
  invalidateCanonicalSummary,
  resolvePresentSecretScanTargets,
  writeCanonicalSummary
} from "../../scripts/run-static-security-scan.mjs";

const project = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const manifestPath = join(project, "Config", "SemgrepRules.json");

function shellLiteral(value) {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

test("static scan manifest pins the complete reviewed registry packs and targets", async () => {
  const manifest = await loadPinnedRuleManifest(manifestPath);
  assert.equal(manifest.engineVersion, "1.135.0");
  assert.deepEqual(manifest.scanTargets, [
    "Package.swift", "Makefile", "Config", "Sources", "Tools", "Resources", "scripts", "Tests"
  ]);
  assert.deepEqual(manifest.secretScanTargets, [
    "Package.swift", "Makefile", ".gitattributes", ".gitignore", ".github",
    "LICENSE", "README.md", "CHANGELOG.md", "CONTRIBUTING.md", "SECURITY.md", "SUPPORT.md",
    "docs", "Config", "Sources", "Tools", "Resources", "scripts", "Tests",
    "VendorRuntime.inventory.json", "VendorRuntime/package.json", "VendorRuntime/package-lock.json"
  ]);
  assert.equal(manifest.maximumTargetBytes, 16 * 1_024 * 1_024);
  assert.deepEqual(manifest.topLevelExcludedEntries, [
    ".git", ".build", "build", "recovered-duplicates"
  ]);
  assert.deepEqual(manifest.vendorRuntimeGeneratedEntries, [
    ".npm-cache", "node-v22.23.1-darwin-arm64", "node_modules"
  ]);
  assert.deepEqual(manifest.vendorRuntimeGeneratedPrefixes, [
    ".node-bootstrap.", ".fulmar-materialize-"
  ]);
  assert.deepEqual(manifest.binaryScanExclusions, [{
    path: "Resources/FulmarAppIcon.png",
    reason: "Reviewed raster application icon; its exact bytes are not a source text surface.",
    sha256: "0266694b0a44bcb3f3500ab543c9a8f96540bdfd95333caddf9d74002a3fae43"
  }]);
  assert.equal(manifest.secretLanguageSpecificRuleIds.length, 15);
  assert.ok(manifest.secretLanguageSpecificRuleIds.every((id) => typeof id === "string" && id.length > 0));
  assert.equal(manifest.reportWarningAllowlist.length, 7);
  assert.ok(manifest.reportWarningAllowlist.every((entry) =>
    entry.reason.length >= 20 && /^[a-f0-9]{64}$/u.test(entry.sourceSha256)
  ));
  assert.deepEqual(manifest.rules.map((rule) => rule.id), ["semgrep-default", "semgrep-secrets"]);
  assert.deepEqual(manifest.rules.map((rule) => rule.ruleCount), [1_074, 52]);
  assert.equal(manifest.rules.reduce((total, rule) => total + rule.ruleCount, 0), 1_126);
  assert.deepEqual(manifest.rules.map((rule) => rule.digestMode), [
    "yaml-top-level-rule-block-set-v1", "yaml-top-level-rule-block-set-v1"
  ]);
  assert.deepEqual(manifest.rules.map((rule) => rule.url), [
    "https://semgrep.dev/c/p/default",
    "https://semgrep.dev/c/p/secrets"
  ]);
});

test("top-level coverage fails closed for new source and permits only exact private/generated roots", async () => {
  const fixture = await mkdtemp(join(tmpdir(), "fulmar-top-level-coverage."));
  const root = join(fixture, "worktree");
  const metadata = join(fixture, "repository.git", "worktrees", "fixture");
  const targets = ["README.md", "LICENSE", "docs", "VendorRuntime/package.json", "VendorRuntime/package-lock.json"];
  const excluded = [".git", ".build", "build", "recovered-duplicates"];
  const vendorGenerated = [".npm-cache", "node-v22.23.1-darwin-arm64", "node_modules"];
  const vendorPrefixes = [".node-bootstrap.", ".fulmar-materialize-"];
  try {
    await mkdir(root, { recursive: true });
    await mkdir(metadata, { recursive: true });
    await mkdir(join(root, "docs"), { recursive: true });
    await mkdir(join(root, "build"), { recursive: true });
    await mkdir(join(root, "VendorRuntime", "node_modules"), { recursive: true });
    await mkdir(join(root, "VendorRuntime", ".node-bootstrap.ABC123"), { recursive: true });
    await writeFile(join(root, ".git"), `gitdir: ${metadata}\n`, "utf8");
    await writeFile(join(metadata, "gitdir"), `${join(root, ".git")}\n`, "utf8");
    await writeFile(join(metadata, "commondir"), "../..\n", "utf8");
    await writeFile(join(root, "README.md"), "# Fixture\n", "utf8");
    await writeFile(join(root, "VendorRuntime", "package.json"), "{}\n", "utf8");
    await writeFile(join(root, "VendorRuntime", "package-lock.json"), "{}\n", "utf8");
    enforceTopLevelCoverage(root, targets, excluded, vendorGenerated, vendorPrefixes);

    await writeFile(join(root, "LICENSE"), "future owner-selected licence fixture\n", "utf8");
    enforceTopLevelCoverage(root, targets, excluded, vendorGenerated, vendorPrefixes);
    await rm(join(root, "LICENSE"));

    await mkdir(join(root, "LICENSE"));
    assert.throws(
      () => enforceTopLevelCoverage(root, targets, excluded, vendorGenerated, vendorPrefixes),
      /optional top-level LICENSE must be a regular file/u
    );
    await rm(join(root, "LICENSE"), { recursive: true });

    await writeFile(join(root, "NEW.md"), "must not escape secret coverage\n", "utf8");
    assert.throws(
      () => enforceTopLevelCoverage(root, targets, excluded, vendorGenerated, vendorPrefixes),
      /uncovered top-level source entry: NEW\.md/u
    );
    await rm(join(root, "NEW.md"));
    await writeFile(join(root, "VendorRuntime", "unexpected.json"), "{}\n", "utf8");
    assert.throws(
      () => enforceTopLevelCoverage(root, targets, excluded, vendorGenerated, vendorPrefixes),
      /uncovered VendorRuntime source entry/u
    );
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});

test("the optional LICENSE target is absent-safe and becomes exact secret-scan input when present", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-optional-license-coverage."));
  const declared = ["README.md", "LICENSE"];
  try {
    await writeFile(join(root, "README.md"), "# Fixture\n", "utf8");
    assert.deepEqual(resolvePresentSecretScanTargets(root, declared), ["README.md"]);

    await writeFile(join(root, "LICENSE"), "future owner-selected licence fixture\n", "utf8");
    const present = resolvePresentSecretScanTargets(root, declared);
    assert.deepEqual(present, declared);
    assert.deepEqual(
      collectSecretTextFiles(root, present, 16 * 1_024 * 1_024).map((entry) => entry.path),
      ["LICENSE", "README.md"]
    );

    await rm(join(root, "LICENSE"));
    assert.deepEqual(resolvePresentSecretScanTargets(root, declared), ["README.md"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("top-level coverage accepts only an exact safe Git worktree metadata file", async () => {
  const fixture = await mkdtemp(join(tmpdir(), "fulmar-git-worktree-coverage."));
  const root = join(fixture, "worktree");
  const metadata = join(fixture, "repository.git", "worktrees", "fixture");
  const targets = ["README.md"];
  const excluded = [".git", ".build", "build", "recovered-duplicates"];
  const enforce = () => enforceTopLevelCoverage(root, targets, excluded, [], []);
  try {
    await mkdir(root, { recursive: true });
    await mkdir(metadata, { recursive: true });
    await writeFile(join(root, "README.md"), "# Fixture\n", "utf8");
    await writeFile(join(root, ".git"), `gitdir: ${metadata}\n`, "utf8");
    await writeFile(join(metadata, "gitdir"), `${join(root, ".git")}\n`, "utf8");
    await writeFile(join(metadata, "commondir"), "../..\n", "utf8");
    enforce();

    await writeFile(join(root, ".git"), `gitdir: ${metadata}\nsecond line\n`, "utf8");
    assert.throws(enforce, /Git worktree pointer is malformed/u);

    await writeFile(join(root, ".git"), "not-a-gitdir-pointer\n", "utf8");
    assert.throws(enforce, /Git worktree pointer is malformed/u);

    await writeFile(join(root, ".git"), `gitdir: ${metadata}${"x".repeat(4_096)}\n`, "utf8");
    assert.throws(enforce, /exceeds its byte limit/u);

    await writeFile(join(root, ".git"), `gitdir: ${metadata}\n`, "utf8");
    await writeFile(join(metadata, "gitdir"), `${join(fixture, "different", ".git")}\n`, "utf8");
    assert.throws(enforce, /does not have an exact reciprocal reference/u);
    await writeFile(join(metadata, "gitdir"), `${join(root, ".git")}\n`, "utf8");

    const arbitrary = join(fixture, "arbitrary-metadata");
    await mkdir(arbitrary, { recursive: true });
    await writeFile(join(root, ".git"), `gitdir: ${arbitrary}\n`, "utf8");
    assert.throws(enforce, /outside the reviewed metadata shape/u);

    await rm(join(root, ".git"));
    await symlink(metadata, join(root, ".git"));
    assert.throws(enforce, /linked top-level entry is not permitted/u);
    await rm(join(root, ".git"));

    await writeFile(join(root, ".git"), `gitdir: ${metadata}\n`, "utf8");
    await writeFile(join(root, ".build"), "not a directory\n", "utf8");
    assert.throws(enforce, /excluded top-level entry is not a directory: \.build/u);
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});

test("static scan manifest warning allowlist is exact, reviewed, and source-bound", async () => {
  const original = JSON.parse(await readFile(manifestPath, "utf8"));
  const nativeProviderRecoveryWarning = {
    scan: "default",
    path: "Tests/LocalHarnessTests/NativeProviderStateRecoveryTests.swift",
    rule: "PartialParsing",
    level: "warn",
    code: 3,
    reason: "Semgrep 1.135 does not parse Swift Testing #require and #expect expression macros; all 108 reported spans exactly match the reviewed file's 108 macros, and the exact source SHA requires review after any edit.",
    sourceSha256: "c3c3f65808030653ac2a4e3524bf4a9e3cdf023d441941b68af326e2d82c4e71"
  };
  assert.deepEqual(
    original.reportWarningAllowlist.filter((entry) => entry.path === nativeProviderRecoveryWarning.path),
    [nativeProviderRecoveryWarning]
  );
  const controllerActionWarning = {
    scan: "default",
    path: "Tests/LocalHarnessTests/ControllerActionWiringTests.swift",
    rule: "PartialParsing",
    level: "warn",
    code: 3,
    reason: "Semgrep 1.135 does not parse Swift Testing #require and #expect expression macros; all 107 reported spans exactly match the reviewed file's 107 macros, and the exact source SHA requires review after any edit.",
    sourceSha256: "5d50aa72f97b8da340075bee84c3f11acc372ecf0a73412090109b1ba993a985"
  };
  assert.deepEqual(
    original.reportWarningAllowlist.filter((entry) => entry.path === controllerActionWarning.path),
    [controllerActionWarning]
  );
  const reviewedShellWarnings = [
    {
      scan: "default",
      path: "scripts/create-local-signing-identity.sh",
      rule: "PartialParsing",
      level: "warn",
      code: 3,
      reason: "Semgrep 1.135 cannot parse the reviewed zsh named-file-descriptor close that prevents the signing secret from reaching child processes; the exact source SHA requires review after any edit.",
      sourceSha256: "6e90b16a64ef5b6c5159b696f7e0d93d9ce43f598cb54fc6a6f4372530f0509d"
    },
    {
      scan: "default",
      path: "scripts/prepare-swift-testing-host.sh",
      rule: "PartialParsing",
      level: "warn",
      code: 3,
      reason: "Semgrep 1.135 only partially parses the reviewed POSIX shell path-pattern and escaped-case constructs; the exact source SHA requires review after any edit.",
      sourceSha256: "bc6f2eb8611dfdb5d1e87e0a3f62f8e57e2a0c0fb1da377b668dc856897504a5"
    },
    {
      scan: "default",
      path: "scripts/run-with-watchdog.sh",
      rule: "PartialParsing",
      level: "warn",
      code: 3,
      reason: "Semgrep 1.135 only partially parses the reviewed POSIX literal-newline case pattern and descriptor here-document used by the clean watchdog bootstrap; the exact source SHA requires review after any edit.",
      sourceSha256: "1192957ab8907f592cc1d7add0698496ad331d497bd8de73a7ee404ae1b81abf"
    },
    {
      scan: "default",
      path: "scripts/verify-runtime-lease.sh",
      rule: "PartialParsing",
      level: "warn",
      code: 3,
      reason: "Semgrep 1.135 only partially parses the reviewed zsh line-array split and deliberately nested shell/Perl parent-death process fixture; the exact source SHA requires review after any edit.",
      sourceSha256: "0c91a41120580ddacee70235388915ada429988a7484fe589a2b3f8a798b40cf"
    },
    {
      scan: "default",
      path: "scripts/verify-simulated-provider-matrix.sh",
      rule: "PartialParsing",
      level: "warn",
      code: 3,
      reason: "Semgrep 1.135 cannot meaningfully parse the reviewed zsh associative-array and process-control script; the exact source SHA requires review after any edit.",
      sourceSha256: "76fd68be3bd5403e4c2a25bf6098339c81a998838b0a5559b67cbb950034e7bd"
    }
  ];
  assert.deepEqual(
    original.reportWarningAllowlist.filter((entry) => entry.path.startsWith("scripts/")),
    reviewedShellWarnings
  );
  const entry = {
    scan: "default",
    path: "scripts/build-app.sh",
    rule: "PartialParsing",
    level: "warn",
    code: 3,
    reason: "Pinned parser limitation reviewed against this exact source file.",
    sourceSha256: "a".repeat(64)
  };
  const parse = (reportWarningAllowlist) => parsePinnedRuleManifest(Buffer.from(JSON.stringify({
    ...original,
    reportWarningAllowlist
  })));
  assert.deepEqual(parse([entry]).reportWarningAllowlist, [entry]);
  assert.throws(() => parse([{ ...entry, path: "scripts/*" }]), /outside the exact reviewed boundary/u);
  assert.throws(() => parse([{ ...entry, path: "../build-app.sh" }]), /outside the exact reviewed boundary/u);
  assert.throws(() => parse([{ ...entry, reason: "too short" }]), /outside the exact reviewed boundary/u);
  assert.throws(() => parse([{ ...entry, level: "info" }]), /outside the exact reviewed boundary/u);
  assert.throws(() => parse([{ ...entry, sourceSha256: "0" }]), /outside the exact reviewed boundary/u);
  assert.throws(() => parse([entry, entry]), /duplicate identity/u);
});

test("production build script keeps parser-safe equivalents for reviewed zsh operations", async () => {
  const source = await readFile(join(project, "scripts", "build-app.sh"), "utf8");
  const publicDistribution = await readFile(
    join(project, "scripts", "verify-public-distribution.sh"),
    "utf8"
  );
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  assert.doesNotMatch(source, /\$\{\(P\)/u);
  assert.doesNotMatch(source, /\$\{\(@f\)/u);
  assert.match(source, /case "\$forwarded_name" in[\s\S]*LOCAL_HARNESS_NOTARY_PROFILE/u);
  assert.match(source, /while IFS= read -r relative_path; do[\s\S]*done < <\("\$NODE_BIN"/u);
  assert.doesNotMatch(publicDistribution, /Contents\/MacOS\/\*\(N\)/u);
  assert.match(
    publicDistribution,
    /while IFS= read -r signed_target; do[\s\S]*\/usr\/bin\/find "\$APP\/Contents\/MacOS"/u
  );
  assert.equal(
    manifest.reportWarningAllowlist.some((entry) => entry.path === "scripts/build-app.sh"),
    false
  );
  assert.equal(
    manifest.reportWarningAllowlist.some((entry) => entry.path === "scripts/verify-public-distribution.sh"),
    false
  );
});

test("secret coverage enumerates every bounded UTF-8 source file and excludes binary data", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-secret-coverage."));
  try {
    await mkdir(join(root, ".github", "workflows"), { recursive: true });
    await mkdir(join(root, "docs"), { recursive: true });
    await writeFile(join(root, "README.md"), "# Fixture\n", "utf8");
    await writeFile(join(root, ".gitignore"), "build/\n", "utf8");
    await writeFile(join(root, ".github", "workflows", "verify.yml"), "name: verify\n", "utf8");
    await writeFile(join(root, "docs", "nested.md"), "secret scan fixture\n", "utf8");
    await writeFile(join(root, "VendorRuntime.inventory.json"), "x".repeat(2_000_001), "utf8");
    const iconBytes = Buffer.from([0, 1, 2, 3]);
    const binaryExclusions = [{
      path: "docs/icon.png",
      reason: "Reviewed binary fixture for exact coverage testing.",
      sha256: digest(iconBytes)
    }];
    await writeFile(join(root, "docs", "icon.png"), iconBytes);

    const entries = collectSecretTextFiles(root, [
      "README.md", ".gitignore", ".github", "docs", "VendorRuntime.inventory.json"
    ], 16 * 1_024 * 1_024, binaryExclusions);
    assert.deepEqual(entries.map((entry) => entry.path), [
      ".github/workflows/verify.yml",
      ".gitignore",
      "README.md",
      "VendorRuntime.inventory.json",
      "docs/nested.md"
    ]);
    assert.equal(entries.find((entry) => entry.path === "VendorRuntime.inventory.json")?.bytes, 2_000_001);
    assert.throws(
      () => collectSecretTextFiles(root, ["docs"], 16 * 1_024 * 1_024),
      /unreviewed non-text source input/u
    );
    assert.throws(
      () => collectSecretTextFiles(root, ["docs"], 16 * 1_024 * 1_024, [{
        ...binaryExclusions[0], sha256: "0".repeat(64)
      }]),
      /unreviewed non-text source input/u
    );
    enforceExactSecretCoverage(entries, entries.map((entry) => entry.path), []);
    assert.throws(
      () => enforceExactSecretCoverage(entries, entries.slice(1).map((entry) => entry.path), []),
      /exact full-text secret target set/u
    );
    assert.throws(
      () => enforceExactSecretCoverage(entries, entries.map((entry) => entry.path), [{ path: "README.md" }]),
      /skipped one or more/u
    );
    assert.throws(
      () => collectSecretTextFiles(root, ["VendorRuntime.inventory.json"], 2_000_000),
      /exceeds its byte limit/u
    );
    await symlink("nested.md", join(root, "docs", "linked.md"));
    assert.throws(
      () => collectSecretTextFiles(root, ["docs"], 16 * 1_024 * 1_024, binaryExclusions),
      /linked secret-scan input/u
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("production secret coverage includes public docs, dotfiles, workflow, and vendor metadata", async () => {
  const manifest = await loadPinnedRuleManifest(manifestPath);
  enforceTopLevelCoverage(
    project,
    manifest.secretScanTargets,
    manifest.topLevelExcludedEntries,
    manifest.vendorRuntimeGeneratedEntries,
    manifest.vendorRuntimeGeneratedPrefixes
  );
  const entries = collectSecretTextFiles(
    project,
    resolvePresentSecretScanTargets(project, manifest.secretScanTargets),
    manifest.maximumTargetBytes,
    manifest.binaryScanExclusions
  );
  const byPath = new Map(entries.map((entry) => [entry.path, entry]));
  for (const path of [
    "README.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "SUPPORT.md",
    ".gitattributes",
    ".gitignore",
    ".github/workflows/verify-source.yml",
    "docs/STATIC_ANALYSIS.md",
    "VendorRuntime.inventory.json",
    "VendorRuntime/package.json",
    "VendorRuntime/package-lock.json"
  ]) {
    assert.ok(byPath.has(path), `${path} escaped the exact secret-scan set`);
  }
  assert.ok(byPath.get("VendorRuntime.inventory.json").bytes > 2_000_000);
  assert.equal(byPath.has("Resources/FulmarAppIcon.png"), false);
});

test("static-analysis documentation matches comprehensive coverage and fail-closed evidence policy", async () => {
  const documentation = await readFile(join(project, "docs", "STATIC_ANALYSIS.md"), "utf8");
  for (const expected of [
    "LICENSE", "README.md", "CHANGELOG.md", "CONTRIBUTING.md", "SECURITY.md", "SUPPORT.md",
    "docs", ".github", ".gitattributes", ".gitignore", "VendorRuntime.inventory.json",
    "VendorRuntime` package manifests"
  ]) {
    assert.ok(documentation.includes(expected), `static-analysis coverage documentation omitted ${expected}`);
  }
  assert.match(documentation, /exact path, exact[\s\S]*rule identity[\s\S]*source file's SHA-256/u);
  assert.match(documentation, /unidentifiable, missing, duplicate, changed, extra, or stale warning fails closed/u);
  assert.match(documentation, /build\/static-security-summary\.json` \(maximum 512 KiB\)/u);
  assert.match(documentation, /binds every scanned text path\/size\/SHA-256/u);
  assert.match(documentation, /canonical\/raw rule-material/u);
  assert.doesNotMatch(documentation, /parser warnings are retained in the report as non-blocking warnings/u);
  assert.doesNotMatch(documentation, /p\/secrets` pack remains exact-byte pinned/u);
});

test("Semgrep report warnings fail closed except for one exact source-bound review", () => {
  const source = [{ path: "scripts/build-app.sh", sha256: "b".repeat(64) }];
  const warning = { level: "warn", code: 3, path: "scripts/build-app.sh", type: "PartialParsing" };
  const allowlist = [{
    scan: "default",
    path: warning.path,
    rule: warning.type,
    level: warning.level,
    code: warning.code,
    reason: "Pinned parser limitation reviewed against this exact source file.",
    sourceSha256: source[0].sha256
  }];
  const reports = [{ name: "default", report: { errors: [warning] } }];
  assert.deepEqual(enforceReportWarnings(reports, allowlist, source), allowlist);
  assert.throws(() => enforceReportWarnings(reports, [], source), /unreviewed Semgrep report warning/u);
  assert.throws(
    () => enforceReportWarnings(reports, allowlist, [{ ...source[0], sha256: "c".repeat(64) }]),
    /unreviewed Semgrep report warning/u
  );
  assert.throws(
    () => enforceReportWarnings([{ name: "default", report: { errors: [] } }], allowlist, source),
    /stale entry/u
  );
  assert.throws(
    () => enforceReportWarnings([{
      name: "default",
      report: { errors: [{ ...warning, level: "error" }] }
    }], allowlist, source),
    /execution error/u
  );
  assert.throws(
    () => enforceReportWarnings([{
      name: "default",
      report: { errors: [{ ...warning, code: 2 }] }
    }], allowlist, source),
    /unreviewed Semgrep report warning/u
  );
  assert.throws(
    () => enforceReportWarnings([{
      name: "default",
      report: { errors: [{ ...warning, level: "info" }] }
    }], allowlist, source),
    /unidentifiable warning/u
  );
  assert.throws(
    () => enforceReportWarnings([{
      name: "default",
      report: { errors: [warning, warning] }
    }], allowlist, source),
    /unreviewed Semgrep report warning/u
  );
  assert.throws(
    () => enforceReportWarnings([{
      name: "default",
      report: { errors: [{ level: "warn", path: "../outside", type: "PartialParsing" }] }
    }], allowlist, source),
    /unidentifiable warning/u
  );
});

test("canonical static-security summary is bounded, deterministic, and link-safe", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-static-summary."));
  const build = join(root, "build");
  const destination = join(build, "static-security-summary.json");
  const target = join(build, "target.json");
  const summary = { schemaVersion: 1, passed: true, coverage: { files: ["README.md"] } };
  try {
    const first = writeCanonicalSummary(root, summary);
    const firstBytes = await readFile(destination);
    assert.equal(first.sha256, digest(firstBytes));
    assert.ok(first.bytes > 0 && first.bytes < 512 * 1_024);

    invalidateCanonicalSummary(root);
    assert.deepEqual(JSON.parse(await readFile(destination, "utf8")), {
      schemaVersion: 1,
      passed: false,
      state: "scan-incomplete"
    });
    const second = writeCanonicalSummary(root, summary);
    const secondBytes = await readFile(destination);
    assert.equal(second.sha256, first.sha256);
    assert.deepEqual(secondBytes, firstBytes);

    const sourceBytes = Buffer.from("reviewed source\n", "utf8");
    const sourceDescriptor = {
      path: "README.md", type: "file", mode: 0o644,
      bytes: sourceBytes.length, sha256: digest(sourceBytes)
    };
    const inventoryPath = join(build, "source-build-inputs.json");
    const policyPath = join(root, "SemgrepRules.json");
    const verifierPath = join(project, "scripts", "verify-static-security-summary.mjs");
    const inventory = {
      schemaVersion: 1,
      rootLabel: "LocalHarnessBuildInputs",
      algorithm: "sha256",
      inputRoots: ["README.md"],
      totals: { entries: 1, fileBytes: sourceBytes.length },
      entries: [sourceDescriptor]
    };
    const policy = {
      engineVersion: "1.135.0",
      secretScanTargets: ["README.md"],
      binaryScanExclusions: [],
      topLevelExcludedEntries: [],
      vendorRuntimeGeneratedEntries: [],
      vendorRuntimeGeneratedPrefixes: [],
      reportWarningAllowlist: [],
      rules: []
    };
    const coveragePayload = Buffer.from(
      `README.md\u0000${sourceBytes.length}\u0000${sourceDescriptor.sha256}\n`, "utf8"
    );
    const passingSummary = {
      schemaVersion: 1,
      passed: true,
      engineVersion: policy.engineVersion,
      coverage: {
        roots: ["README.md"],
        excludedTopLevelEntries: [],
        excludedVendorRuntimeEntries: [],
        excludedVendorRuntimePrefixes: [],
        reviewedBinaryExclusions: [],
        textFileCount: 1,
        textFileBytes: sourceBytes.length,
        sha256: digest(coveragePayload),
        files: [{ path: sourceDescriptor.path, bytes: sourceDescriptor.bytes, sha256: sourceDescriptor.sha256 }]
      },
      scans: {
        default: { reportSha256: "a".repeat(64), scannedPathCount: 1, rawFindingCount: 0, reviewedWarningCount: 0 },
        secretsLanguageSpecific: { reportSha256: "b".repeat(64), scannedPathCount: 1, rawFindingCount: 0, reviewedWarningCount: 0 },
        secretsFullText: { reportSha256: "c".repeat(64), scannedPathCount: 1, rawFindingCount: 0, reviewedWarningCount: 0 }
      },
      reviewedFindings: [],
      reviewedReportWarnings: [],
      unreviewedFindingCount: 0,
      rules: []
    };
    await writeFile(inventoryPath, `${JSON.stringify(inventory)}\n`, { mode: 0o644 });
    await writeFile(policyPath, `${JSON.stringify(policy)}\n`, { mode: 0o644 });
    invalidateCanonicalSummary(root);
    writeCanonicalSummary(root, passingSummary);
    let verification = spawnSync(process.execPath, [verifierPath, destination, inventoryPath, policyPath], {
      cwd: root, encoding: "utf8"
    });
    assert.equal(verification.status, 0, verification.stderr);

    invalidateCanonicalSummary(root);
    verification = spawnSync(process.execPath, [verifierPath, destination, inventoryPath, policyPath], {
      cwd: root, encoding: "utf8"
    });
    assert.notEqual(verification.status, 0);
    assert.match(verification.stderr, /absent, failed, or uses an unreviewed schema/u);
    writeCanonicalSummary(root, passingSummary);

    await writeFile(destination, `${JSON.stringify({ ...passingSummary, passed: false })}\n`, { mode: 0o644 });
    verification = spawnSync(process.execPath, [verifierPath, destination, inventoryPath, policyPath], {
      cwd: root, encoding: "utf8"
    });
    assert.notEqual(verification.status, 0);
    assert.match(verification.stderr, /absent, failed, or uses an unreviewed schema/u);

    await writeFile(destination, `${JSON.stringify(passingSummary)}\n`, { mode: 0o644 });
    await writeFile(inventoryPath, `${JSON.stringify({
      ...inventory,
      entries: [{ ...sourceDescriptor, sha256: "d".repeat(64) }]
    })}\n`, { mode: 0o644 });
    verification = spawnSync(process.execPath, [verifierPath, destination, inventoryPath, policyPath], {
      cwd: root, encoding: "utf8"
    });
    assert.notEqual(verification.status, 0);
    assert.match(verification.stderr, /exact frozen source-input file set/u);
    await rm(destination);
    verification = spawnSync(process.execPath, [verifierPath, destination, inventoryPath, policyPath], {
      cwd: root, encoding: "utf8"
    });
    assert.notEqual(verification.status, 0);
    assert.match(verification.stderr, /ENOENT|no such file/u);

    invalidateCanonicalSummary(root);
    await rm(destination);
    await writeFile(target, "target\n", "utf8");
    await symlink("target.json", destination);
    assert.throws(() => invalidateCanonicalSummary(root), /ELOOP|symbolic|unsafe/u);
    await rm(destination, { force: true });

    await symlink("missing.json", destination);
    assert.throws(() => invalidateCanonicalSummary(root), /ELOOP|symbolic|unsafe/u);
    await rm(destination, { force: true });

    await link(target, destination);
    assert.throws(() => invalidateCanonicalSummary(root), /unsafe|descriptor-bound upsert/u);
    await rm(destination, { force: true });
    await rm(target, { force: true });

    assert.throws(
      () => writeCanonicalSummary(root, { payload: "x".repeat(512 * 1_024) }),
      /summary exceeds its byte limit/u
    );

    // The writer publishes only inside an owner-controlled, no-follow build
    // directory: a group-writable or symbolically linked directory is refused
    // before any temporary file exists, and no temporary is left behind.
    await chmod(build, 0o775);
    assert.throws(() => writeCanonicalSummary(root, summary), /summary directory is unsafe/u);
    await chmod(build, 0o700);
    const linkedProject = join(root, "linked-project");
    await mkdir(linkedProject, { mode: 0o700 });
    await symlink(build, join(linkedProject, "build"));
    assert.throws(() => writeCanonicalSummary(linkedProject, summary), /summary directory is unsafe/u);
    assert.deepEqual(
      (await readdir(build)).filter((name) => name.startsWith(".static-security-summary.")),
      []
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("pinned rule validation rejects byte, checksum, count, and identity drift", () => {
  const bytes = Buffer.from([
    "rules:",
    "- id: fixture.one",
    "  pattern: $X == $X",
    "  message: fixture",
    "  languages: [javascript]",
    "  severity: ERROR",
    ""
  ].join("\n"), "utf8");
  const descriptor = {
    id: "fixture",
    format: "yaml",
    digestMode: "exact-bytes-v1",
    byteCount: bytes.length,
    sha256: digest(bytes),
    ruleCount: 1
  };
  assert.equal(validatePinnedRuleBytes(descriptor, bytes).ruleCount, 1);
  assert.throws(
    () => validatePinnedRuleBytes({ ...descriptor, byteCount: bytes.length + 1 }, bytes),
    /byte count changed/u
  );
  assert.throws(
    () => validatePinnedRuleBytes({ ...descriptor, sha256: "0".repeat(64) }, bytes),
    /checksum changed/u
  );
  assert.throws(
    () => validatePinnedRuleBytes({ ...descriptor, ruleCount: 2 }, bytes),
    /rule count or identities changed/u
  );
  const duplicate = Buffer.from(bytes.toString("utf8") + bytes.toString("utf8"), "utf8");
  assert.throws(
    () => validatePinnedRuleBytes({
      ...descriptor,
      byteCount: duplicate.length,
      sha256: digest(duplicate),
      ruleCount: 2
    }, duplicate),
    /rule count or identities changed/u
  );
});

test("YAML rule-set pin ignores only top-level rule ordering", () => {
  const first = Buffer.from([
    "rules:",
    "- id: fixture.one",
    "  pattern: $X == $X",
    "  message: first",
    "  languages: [javascript]",
    "  severity: ERROR",
    "- patterns:",
    "  - pattern: $Y",
    "  id: fixture.two",
    "  message: second",
    "  languages: [javascript]",
    "  severity: WARNING",
    ""
  ].join("\n"), "utf8");
  const permuted = Buffer.from([
    "rules:",
    "- patterns:",
    "  - pattern: $Y",
    "  id: fixture.two",
    "  message: second",
    "  languages: [javascript]",
    "  severity: WARNING",
    "- id: fixture.one",
    "  pattern: $X == $X",
    "  message: first",
    "  languages: [javascript]",
    "  severity: ERROR",
    ""
  ].join("\n"), "utf8");
  const descriptor = {
    id: "fixture",
    format: "yaml",
    digestMode: "yaml-top-level-rule-block-set-v1",
    byteCount: first.length,
    sha256: "a87bfb2f37b0fbbc54758a6732ca4d2bd2d82f0922340df75152fa3d59612da7",
    ruleCount: 2
  };
  assert.notEqual(digest(first), digest(permuted));
  assert.equal(validatePinnedRuleBytes(descriptor, first).digest, descriptor.sha256);
  assert.equal(validatePinnedRuleBytes(descriptor, permuted).digest, descriptor.sha256);
  assert.notEqual(
    validatePinnedRuleBytes(descriptor, first).rawDigest,
    validatePinnedRuleBytes(descriptor, permuted).rawDigest
  );

  const changedRule = Buffer.from(first.toString("utf8").replace("message: first", "message: fIrst"));
  assert.throws(() => validatePinnedRuleBytes(descriptor, changedRule), /reviewed content checksum changed/u);

  const reorderedInsideRule = Buffer.from(first.toString("utf8").replace(
    "  pattern: $X == $X\n  message: first",
    "  message: first\n  pattern: $X == $X"
  ));
  assert.equal(reorderedInsideRule.length, first.length);
  assert.throws(
    () => validatePinnedRuleBytes(descriptor, reorderedInsideRule),
    /reviewed content checksum changed/u
  );

  const duplicateID = Buffer.from(first.toString("utf8").replace("fixture.two", "fixture.one"));
  assert.throws(() => validatePinnedRuleBytes(descriptor, duplicateID), /rule count or identities changed/u);

  const missingID = Buffer.from(first.toString("utf8").replace("  id: fixture.two\n", "  xx: fixture.two\n"));
  assert.throws(() => validatePinnedRuleBytes(descriptor, missingID), /missing, duplicate, or unsafe/u);

  const multipleIDs = Buffer.from(first.toString("utf8").replace(
    "  id: fixture.two\n",
    "  id: fixture.two\n  id: fixture.more\n"
  ));
  assert.throws(
    () => validatePinnedRuleBytes({ ...descriptor, byteCount: multipleIDs.length }, multipleIDs),
    /missing, duplicate, or unsafe/u
  );

  const malformedPrefix = Buffer.from(first.toString("utf8").replace("rules:\n", "rules: []\n"));
  assert.throws(
    () => validatePinnedRuleBytes({ ...descriptor, byteCount: malformedPrefix.length }, malformedPrefix),
    /reviewed rules document prefix/u
  );
  assert.throws(
    () => validatePinnedRuleBytes({ ...descriptor, byteCount: first.length + 1 }, first),
    /byte count changed/u
  );
  assert.throws(
    () => validatePinnedRuleBytes({ ...descriptor, ruleCount: 3 }, first),
    /rule count or identities changed/u
  );
  assert.throws(
    () => validatePinnedRuleBytes({ ...descriptor, sha256: "0".repeat(64) }, first),
    /reviewed content checksum changed/u
  );
  const removedRule = Buffer.from("rules:\n" + first.toString("utf8").split("- patterns:\n", 1)[0].slice("rules:\n".length));
  assert.throws(
    () => validatePinnedRuleBytes({ ...descriptor, byteCount: removedRule.length }, removedRule),
    /rule count or identities changed/u
  );
  const addedRule = Buffer.concat([first, Buffer.from([
    "- id: fixture.three",
    "  pattern: $Z",
    "  message: third",
    "  languages: [javascript]",
    "  severity: INFO",
    ""
  ].join("\n"))]);
  assert.throws(
    () => validatePinnedRuleBytes({ ...descriptor, byteCount: addedRule.length }, addedRule),
    /rule count or identities changed/u
  );
});

test("exact-byte mode still rejects reordered JSON rules", () => {
  const first = Buffer.from(JSON.stringify({ rules: [{ id: "one" }, { id: "two" }] }));
  const permuted = Buffer.from(JSON.stringify({ rules: [{ id: "two" }, { id: "one" }] }));
  const descriptor = {
    id: "fixture-json",
    format: "json",
    digestMode: "exact-bytes-v1",
    byteCount: first.length,
    sha256: digest(first),
    ruleCount: 2
  };
  assert.equal(validatePinnedRuleBytes(descriptor, first).digest, descriptor.sha256);
  assert.throws(() => validatePinnedRuleBytes(descriptor, permuted), /checksum changed/u);
});

test("static runner uses only materialized local configs and disables rule ID rewriting", async () => {
  const source = await readFile(join(project, "scripts", "run-static-security-scan.mjs"), "utf8");
  assert.match(source, /materializePinnedSemgrepRules/u);
  assert.match(source, /"--no-rewrite-rule-ids"/u);
  assert.match(source, /SEMGREP_SEND_METRICS: "off"/u);
  assert.match(source, /SEMGREP_APP_TOKEN: ""/u);
  assert.doesNotMatch(source, /["']p\/(?:default|secrets)["']/u);
  assert.doesNotMatch(source, /new RegExp\(`/u);
});

test("static scan launcher and CI pin Node and clean the launch boundary", async () => {
  const [launcher, runner, makefile, workflow, releaseIdentity, bundledNodeBytes] = await Promise.all([
    readFile(join(project, "scripts", "run-static-security-scan.sh"), "utf8"),
    readFile(join(project, "scripts", "run-static-security-scan.mjs"), "utf8"),
    readFile(join(project, "Makefile"), "utf8"),
    readFile(join(project, ".github", "workflows", "verify-source.yml"), "utf8"),
    readFile(join(project, "Config", "ReleaseIdentity.json"), "utf8").then(JSON.parse),
    readFile(join(project, "VendorRuntime", "node-v22.23.1-darwin-arm64", "bin", "node"))
  ]);

  assert.equal(releaseIdentity.runtime.nodeSHA256, digest(bundledNodeBytes));
  assert.equal(
    releaseIdentity.runtime.nodeLinuxX64SHA256,
    "93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068"
  );

  assert.match(launcher, /^#!\/bin\/sh -p\n/u);
  assert.match(launcher, /EXPECTED_NODE_VERSION="v22\.23\.1"/u);
  assert.match(launcher, /VendorRuntime\/node-v22\.23\.1-darwin-arm64\/bin\/node/u);
  assert.match(launcher, /\/usr\/bin\/env -i/u);
  assert.match(launcher, /SEMGREP_BIN="\$SEMGREP_BIN"/u);
  assert.doesNotMatch(launcher, /NODE_(?:OPTIONS|PATH|EXTRA_CA_CERTS)=/u);
  assert.doesNotMatch(launcher, /(?:HTTP|HTTPS|ALL|NO)_PROXY=/u);

  assert.match(runner, /const expectedNodeVersion = "v22\.23\.1"/u);
  for (const name of [
    "NODE_OPTIONS", "NODE_PATH", "NODE_EXTRA_CA_CERTS", "OPENSSL_CONF",
    "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "HTTPS_PROXY", "NO_PROXY",
    "npm_config_cafile", "SEMGREP_APP_TOKEN", "PYTHONPATH", "LD_PRELOAD"
  ]) {
    assert.match(runner, new RegExp(`"${name}"`, "u"));
  }
  assert.doesNotMatch(runner, /env:\s*\{\s*\.\.\.process\.env/u);

  assert.match(makefile, /static-security-scan:\n\t\/bin\/sh -p scripts\/run-static-security-scan\.sh/u);
  assert.doesNotMatch(makefile, /\bnode scripts\/run-static-security-scan\.mjs/u);
  assert.match(
    workflow,
    /actions\/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4\.4\.0/u
  );
  assert.match(workflow, /node-version: 22\.23\.1/u);
  assert.match(workflow, /nodeLinuxX64SHA256/u);
  assert.match(workflow, /sha256sum "\$node_path"/u);
  assert.match(launcher, /ACTUAL_NODE_SHA256/u);
  assert.match(launcher, /nodeLinuxX64SHA256/u);
});

test("direct static runner fails closed on hostile ambient Node settings", () => {
  assert.equal(process.version, "v22.23.1", "test suite itself must use the pinned Node release");
  const result = spawnSync(process.execPath, [join(project, "scripts", "run-static-security-scan.mjs")], {
    cwd: project,
    encoding: "utf8",
    env: {
      PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
      HOME: tmpdir(),
      TMPDIR: tmpdir(),
      LANG: "C",
      LC_ALL: "C",
      SEMGREP_BIN: "/bin/false",
      NODE_OPTIONS: "--no-warnings",
      NODE_PATH: join(tmpdir(), "hostile-node-path"),
      HTTPS_PROXY: "http://127.0.0.1:9",
      NODE_EXTRA_CA_CERTS: "/etc/ssl/cert.pem"
    }
  });
  assert.equal(result.status, 1, result.stderr || result.stdout);
  assert.match(result.stderr, /unsafe launch environment/u);
  assert.match(result.stderr, /NODE_OPTIONS/u);
  assert.match(result.stderr, /NODE_PATH/u);
  assert.match(result.stderr, /HTTPS_PROXY/u);
  assert.match(result.stderr, /NODE_EXTRA_CA_CERTS/u);
});

test("clean launcher binds Node bytes before execution and strips ambient injection", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-static-launcher."));
  const scripts = join(root, "scripts");
  const ambientBin = join(root, "ambient-bin");
  const ambientNode = join(ambientBin, "node");
  const semgrep = join(ambientBin, "semgrep");
  const bundledNode = join(root, "VendorRuntime", "node-v22.23.1-darwin-arm64", "bin", "node");
  const releaseIdentity = join(root, "Config", "ReleaseIdentity.json");
  const executionMarker = join(root, "unreviewed-node-executed");
  const shellEnvironment = join(root, "hostile-shell-environment.sh");
  const environmentMarker = join(root, "shell-environment-executed");
  const functionMarker = join(root, "exported-function-executed");
  const actualNode = process.execPath;
  const validNodeShim = [
    "#!/bin/sh",
    "if [ \"$1\" = \"--version\" ]; then printf '%s\\n' 'v22.23.1'; exit 0; fi",
    `exec ${shellLiteral(actualNode)} \"$@\"`,
    ""
  ].join("\n");
  const invalidNodeShim = [
    "#!/bin/sh",
    "if [ \"$1\" = \"--version\" ]; then printf '%s\\n' 'v0.0.0'; exit 0; fi",
    "exit 90",
    ""
  ].join("\n");
  const hostile = {
    PATH: `${ambientBin}:/usr/bin:/bin`,
    HOME: root,
    TMPDIR: root,
    LANG: "C",
    LC_ALL: "C",
    NODE_OPTIONS: "--no-warnings",
    NODE_PATH: join(root, "hostile-node-path"),
    HTTPS_PROXY: "http://127.0.0.1:9",
    NODE_EXTRA_CA_CERTS: "/etc/ssl/cert.pem",
    BASH_ENV: shellEnvironment,
    ENV: shellEnvironment,
    FULMAR_BASH_ENV_MARKER: environmentMarker,
    FULMAR_EXPORTED_FUNCTION_MARKER: functionMarker,
    "BASH_FUNC_fulmar_injected%%":
      '() { printf injected > "$FULMAR_EXPORTED_FUNCTION_MARKER"; }'
  };

  try {
    await mkdir(scripts, { recursive: true });
    await mkdir(ambientBin, { recursive: true });
    await mkdir(dirname(releaseIdentity), { recursive: true });
    await copyFile(
      join(project, "scripts", "run-static-security-scan.sh"),
      join(scripts, "run-static-security-scan.sh")
    );
    await chmod(join(scripts, "run-static-security-scan.sh"), 0o755);
    await writeFile(ambientNode, validNodeShim, "utf8");
    await chmod(ambientNode, 0o755);
    await writeFile(semgrep, "#!/bin/sh\nexit 0\n", "utf8");
    await chmod(semgrep, 0o755);
    await writeFile(
      shellEnvironment,
      'printf injected > "$FULMAR_BASH_ENV_MARKER"\nfulmar_injected\n',
      { mode: 0o600 }
    );
    await writeFile(releaseIdentity, `${JSON.stringify({
      runtime: {
        nodeSHA256: digest(Buffer.from(validNodeShim, "utf8")),
        nodeLinuxX64SHA256: "0".repeat(64)
      }
    }, null, 2)}\n`, "utf8");
    await writeFile(join(scripts, "run-static-security-scan.mjs"), [
      "const forbidden = [",
      "  'NODE_OPTIONS', 'NODE_PATH', 'NODE_EXTRA_CA_CERTS', 'HTTPS_PROXY'",
      "];",
      "if (process.version !== 'v22.23.1') process.exit(81);",
      "if (forbidden.some((name) => Object.hasOwn(process.env, name))) process.exit(82);",
      "if (!process.env.SEMGREP_BIN?.startsWith('/')) process.exit(83);",
      "process.stdout.write('CLEAN_LAUNCH_OK\\n');",
      ""
    ].join("\n"), "utf8");

    // An ambient executable on an unreviewed host/architecture never reaches
    // even its --version branch.
    const cleanCheckout = spawnSync("/bin/sh", ["-p", join(scripts, "run-static-security-scan.sh")], {
      cwd: root,
      env: hostile,
      encoding: "utf8"
    });
    assert.equal(cleanCheckout.status, 1, cleanCheckout.stderr || cleanCheckout.stdout);
    assert.match(cleanCheckout.stderr, /no reviewed Node provenance/u);
    await assert.rejects(readFile(environmentMarker), { code: "ENOENT" });
    await assert.rejects(readFile(functionMarker), { code: "ENOENT" });

    // Once the signed source bootstrap reconstructs the bundled runtime, it
    // wins even if an incompatible executable appears first on ambient PATH.
    await mkdir(dirname(bundledNode), { recursive: true });
    await writeFile(bundledNode, validNodeShim, "utf8");
    await chmod(bundledNode, 0o755);
    await writeFile(ambientNode, invalidNodeShim, "utf8");
    const bundledPreferred = spawnSync("/bin/sh", ["-p", join(scripts, "run-static-security-scan.sh")], {
      cwd: root,
      env: hostile,
      encoding: "utf8"
    });
    assert.equal(bundledPreferred.status, 0, bundledPreferred.stderr || bundledPreferred.stdout);
    assert.match(bundledPreferred.stdout, /CLEAN_LAUNCH_OK/u);
    await assert.rejects(readFile(environmentMarker), { code: "ENOENT" });
    await assert.rejects(readFile(functionMarker), { code: "ENOENT" });

    // A binary that prints the expected version is rejected by digest before
    // the launcher gives it a chance to execute any code.
    const versionSpoof = [
      "#!/bin/sh",
      `printf '%s\\n' executed > ${shellLiteral(executionMarker)}`,
      "printf '%s\\n' 'v22.23.1'",
      ""
    ].join("\n");
    await writeFile(bundledNode, versionSpoof, "utf8");
    await chmod(bundledNode, 0o755);
    const rejectedSpoof = spawnSync("/bin/sh", ["-p", join(scripts, "run-static-security-scan.sh")], {
      cwd: root,
      env: hostile,
      encoding: "utf8"
    });
    assert.equal(rejectedSpoof.status, 1, rejectedSpoof.stderr || rejectedSpoof.stdout);
    assert.match(rejectedSpoof.stderr, /rejected an unreviewed Node executable/u);
    await assert.rejects(readFile(executionMarker), { code: "ENOENT" });

    await rm(join(root, "VendorRuntime"), { recursive: true, force: true });
    const wrongAmbient = spawnSync("/bin/sh", ["-p", join(scripts, "run-static-security-scan.sh")], {
      cwd: root,
      env: hostile,
      encoding: "utf8"
    });
    assert.equal(wrongAmbient.status, 1, wrongAmbient.stderr || wrongAmbient.stdout);
    assert.match(wrongAmbient.stderr, /no reviewed Node provenance/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("public gitignore excludes completed and interrupted generated runtime trees", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-public-index-ignore."));
  try {
    await copyFile(join(project, ".gitignore"), join(root, ".gitignore"));
    const ignored = [
      ".build/probe",
      "build/Fulmar.app.zip",
      "recovered-duplicates/2026-08-21/legacy.swift",
      "VendorRuntime/node_modules/@deepseek-ai/dsh/package.json",
      "VendorRuntime/node-v22.23.1-darwin-arm64/bin/node",
      "VendorRuntime/.node-bootstrap.ABC123/archive",
      "VendorRuntime/.fulmar-materialize-ABC123/.npm-cache/content",
      "VendorRuntime/.npm-cache/content",
      "VendorRuntime/nested/.12345678.fulmar-patch",
      "npm-debug.log.1"
    ];
    const retained = [
      "VendorRuntime/package.json",
      "VendorRuntime/package-lock.json",
      "VendorRuntime.inventory.json",
      "Config/SemgrepRules.json",
      "scripts/pinned-semgrep-rules.mjs",
      "Sources/LocalHarness/PublicSource.swift"
    ];
    for (const relative of [...ignored, ...retained]) {
      const path = join(root, relative);
      await mkdir(dirname(path), { recursive: true });
      await writeFile(path, "fixture\n", "utf8");
    }
    const initialized = spawnSync("git", ["init", "--quiet"], { cwd: root, encoding: "utf8" });
    assert.equal(initialized.status, 0, initialized.stderr);
    for (const relative of ignored) {
      const result = spawnSync("git", ["check-ignore", "--quiet", "--no-index", relative], {
        cwd: root,
        encoding: "utf8"
      });
      assert.equal(result.status, 0, `${relative} was not ignored: ${result.stderr}`);
    }
    for (const relative of retained) {
      const result = spawnSync("git", ["check-ignore", "--quiet", "--no-index", relative], {
        cwd: root,
        encoding: "utf8"
      });
      assert.equal(result.status, 1, `${relative} was unexpectedly ignored`);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
