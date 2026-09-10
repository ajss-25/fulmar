// Fixture-only tests for the explicit manual-install beta asset arrangement:
// the stable package stays exactly nine assets (eight SHA256SUMS.txt entries)
// and the beta package is exactly twelve (eleven entries) — the nine plus the
// verified third-party material archive, its sha256sum sidecar and its binding,
// named only from the tracked provenance record. They exercise the pure asset
// policy, the material admission step through the existing packager verifier,
// the preparer's and verifier's operand boundaries, and the copied operator's
// exact operand forwarding. Every archive, binding and candidate here is
// unmistakably synthetic and lives in a private temporary root; nothing signs,
// builds, uploads, touches a Keychain, the shared build root or the installed
// app, and no fixture result is release evidence or licensing clearance.
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { chmod, copyFile, link, mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import test from "node:test";
import { rootWatchdogChildOptions } from "./RootWatchdogChildProcess.mjs";
import {
  CHECKSUM_LIST_NAME,
  STABLE_CHECKSUM_ENTRY_NAMES,
  STABLE_PACKAGE_ASSET_NAMES,
  admitMaterialPackage,
  checksumEntryNames,
  loadMaterialRootName,
  materialAssetNames,
  packageAssetNames,
  requireAuthoritativeAcquisition,
  resolveAssetProfile
} from "../../scripts/public-release-asset-policy.mjs";

const root = process.cwd();
const policyTool = join(root, "scripts", "public-release-asset-policy.mjs");
const preparer = join(root, "scripts", "prepare-public-release-assets.sh");
const verifier = join(root, "scripts", "verify-public-distribution.sh");
const provenancePath = join(root, "Config", "ThirdPartyBinaryProvenance.json");
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const syntheticDigest = (label) => digest(`synthetic-beta-asset-fixture:${label}`);
const gitOutput = (arguments_) => spawnSync("/usr/bin/git", ["-C", root, ...arguments_], { encoding: "utf8" });
const headCommit = gitOutput(["rev-parse", "--verify", "HEAD^{commit}"]).stdout.trim();
// Tracked-file cleanliness decides how far the verifier's beta path can run in
// this checkout: a release verifier must refuse a modified tracked tree, so a
// developer's dirty checkout legitimately stops there, while the committed
// bytes the complete gate runs on reach the material admission boundary.
const trackedTreeClean = gitOutput(["status", "--porcelain=v1", "--untracked-files=no"]).stdout.trim() === "";
const OTHER_COMMIT = "7".repeat(40);

const stableNames = Object.freeze([
  "Fulmar.app.zip",
  "Fulmar.app.zip.sha256",
  "Fulmar.dSYMs.zip",
  "LICENSE",
  "LocalHarness.sbom.cdx.json",
  "SHA256SUMS.txt",
  "THIRD_PARTY_NOTICES.md",
  "release-manifest.json",
  "static-security-summary.json"
]);
const payloadNames = Object.freeze(stableNames.filter((name) => !["SHA256SUMS.txt", "Fulmar.app.zip.sha256"].includes(name)));

function runPolicy(arguments_) {
  return spawnSync(process.execPath, [policyTool, ...arguments_], { cwd: root, encoding: "utf8", timeout: 30_000 });
}

function runPreparer(arguments_) {
  return spawnSync("/bin/zsh", ["-f", preparer, ...arguments_], rootWatchdogChildOptions({ cwd: root, encoding: "utf8", timeout: 20_000 }));
}

function runVerifier(arguments_, { script = verifier, timeout = 120_000 } = {}) {
  return spawnSync("/bin/zsh", ["-f", script, ...arguments_], rootWatchdogChildOptions({ cwd: root, encoding: "utf8", timeout }));
}

// A synthetic material package: a whole-block byte stream that is not a
// tar, an empty JSON object as the binding and a correct sha256sum sidecar.
// It exercises every boundary before extraction; it can never verify.
async function writeSyntheticMaterials(directory, rootName, { tarBytes = Buffer.concat([randomBytes(1024), Buffer.alloc(1024, 0)]), bindingText = "{}\n", sidecarDigest } = {}) {
  const [bindingName, archiveName, sidecarName] = materialAssetNames(rootName);
  await writeFile(join(directory, archiveName), tarBytes, { mode: 0o644 });
  await writeFile(join(directory, bindingName), bindingText, { mode: 0o644 });
  await writeFile(join(directory, sidecarName), `${sidecarDigest ?? digest(tarBytes)}  ${archiveName}\n`, { mode: 0o644 });
  return { archiveName, bindingName, sidecarName, tarDigest: digest(tarBytes) };
}

// A synthetic package directory for the distribution verifier: the nine stable
// assets as short texts, plus (for beta) the synthetic materials, with a
// checksum list over the requested entry names.
async function writeSyntheticPackage(directory, profile, rootName, { entryNames, materials = {} } = {}) {
  for (const name of payloadNames) await writeFile(join(directory, name), name, { mode: 0o644 });
  await writeFile(join(directory, "Fulmar.app.zip.sha256"), `${await fileDigest(join(directory, "Fulmar.app.zip"))}  Fulmar.app.zip\n`, { mode: 0o644 });
  let written = null;
  if (profile === "beta") written = await writeSyntheticMaterials(directory, rootName, materials);
  const names = entryNames ?? checksumEntryNames(profile, rootName);
  const lines = [];
  for (const name of names) lines.push(`${await fileDigest(join(directory, name))}  ${name}`);
  await writeFile(join(directory, CHECKSUM_LIST_NAME), `${lines.join("\n")}\n`, { mode: 0o644 });
  return written;
}

async function fileDigest(path) {
  return digest(await readFile(path));
}

async function privateTemporary(prefix) {
  const directory = await mkdtemp(`/private/tmp/${prefix}.`);
  await chmod(directory, 0o700);
  return directory;
}

test("the asset policy is exactly nine stable assets and twelve provenance-named beta assets in checksum order", async () => {
  assert.deepEqual([...STABLE_PACKAGE_ASSET_NAMES], stableNames);
  assert.deepEqual([...STABLE_CHECKSUM_ENTRY_NAMES], stableNames.filter((name) => name !== CHECKSUM_LIST_NAME));
  assert.equal(STABLE_PACKAGE_ASSET_NAMES.length, 9);
  assert.equal(STABLE_CHECKSUM_ENTRY_NAMES.length, 8);
  assert.deepEqual([...packageAssetNames("stable")], stableNames, "stable ignores any material root");
  assert.deepEqual([...packageAssetNames("stable", "anything")], stableNames);

  const rootName = await loadMaterialRootName(provenancePath);
  assert.equal(rootName, "sharp-libvips-1.3.3-delivery-materials", "the material root comes from the tracked provenance record only");
  assert.deepEqual([...materialAssetNames(rootName)], [`${rootName}.binding.json`, `${rootName}.tar`, `${rootName}.tar.sha256`]);
  const beta = packageAssetNames("beta", rootName);
  assert.equal(beta.length, 12);
  assert.deepEqual([...beta], [
    "Fulmar.app.zip",
    "Fulmar.app.zip.sha256",
    "Fulmar.dSYMs.zip",
    "LICENSE",
    "LocalHarness.sbom.cdx.json",
    "SHA256SUMS.txt",
    "THIRD_PARTY_NOTICES.md",
    "release-manifest.json",
    `${rootName}.binding.json`,
    `${rootName}.tar`,
    `${rootName}.tar.sha256`,
    "static-security-summary.json"
  ], "C-locale byte order, which is the SHA256SUMS.txt order");
  const entries = checksumEntryNames("beta", rootName);
  assert.equal(entries.length, 11);
  assert.deepEqual([...entries], beta.filter((name) => name !== CHECKSUM_LIST_NAME), "SHA256SUMS.txt covers every distributed asset except itself");
  assert.ok(Object.isFrozen(beta) && Object.isFrozen(entries) && Object.isFrozen(STABLE_PACKAGE_ASSET_NAMES));

  for (const name of ["", "alpha", "Beta", "stable ", undefined, null, 0, {}]) {
    assert.throws(() => resolveAssetProfile(name), /unknown public release profile/u, JSON.stringify(name));
    assert.throws(() => packageAssetNames(name, rootName), /unknown public release profile/u, JSON.stringify(name));
  }
  for (const bad of ["", ".hidden", "../escape", "a/b", "name with space", "x".repeat(201), undefined, 7]) {
    assert.throws(() => materialAssetNames(bad), /bounded directory-name contract/u, JSON.stringify(bad));
    assert.throws(() => packageAssetNames("beta", bad), /bounded directory-name contract/u, JSON.stringify(bad));
  }
  assert.throws(() => packageAssetNames("beta"), /bounded directory-name contract/u, "beta without a provenance-derived root has no names");

  // The CLI emits the same lists; usage and profile errors fail closed.
  let result = runPolicy(["names", "stable"]);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.stdout.trimEnd().split("\n"), stableNames);
  result = runPolicy(["names", "beta", provenancePath]);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.stdout.trimEnd().split("\n"), [...beta]);
  result = runPolicy(["checksum-names", "beta", provenancePath]);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.stdout.trimEnd().split("\n"), [...entries]);
  result = runPolicy(["checksum-names", "stable"]);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.stdout.trimEnd().split("\n"), [...STABLE_CHECKSUM_ENTRY_NAMES]);
  for (const [label, arguments_, status, rejection] of [
    ["no command", [], 64, /usage: public-release-asset-policy\.mjs/u],
    ["unknown command", ["list", "beta", provenancePath], 64, /usage:/u],
    ["beta without provenance", ["names", "beta"], 1, /requires the tracked provenance record operand/u],
    ["unknown profile", ["names", "alpha"], 1, /unknown public release profile: alpha/u],
    ["option-shaped operand", ["names", "--profile", "beta"], 64, /usage:/u],
    ["admit with too few operands", ["admit-materials", provenancePath, "/private/tmp"], 64, /usage:/u],
    ["stable listing with a non-record path", ["names", "stable", join(root, "README.md")], 1, /provenance record must be one tracked JSON document under Config/u]
  ]) {
    result = runPolicy(arguments_);
    assert.equal(result.status, status, `${label}: ${result.stderr}`);
    assert.match(result.stderr, rejection, label);
  }
});

test("distributable material must record HTTPS-authoritative acquisition for both inputs", () => {
  const authoritative = {
    acquisition: {
      upstreamSource: { transport: "https", authoritative: true, itemCount: 41, totalBytes: 1 },
      rustCrates: { transport: "https", authoritative: true, itemCount: 161, totalBytes: 1 }
    }
  };
  assert.deepEqual(requireAuthoritativeAcquisition(authoritative), { upstream: "https", crates: "https", authoritative: true });
  for (const [label, mutate, shown] of [
    ["fixture upstream", (value) => { value.acquisition.upstreamSource = { transport: "local-fixture", authoritative: false }; }, /upstream local-fixture, NOT authoritative; crates https\)/u],
    ["fixture crates", (value) => { value.acquisition.rustCrates = { transport: "local-fixture", authoritative: false }; }, /upstream https; crates local-fixture, NOT authoritative\)/u],
    ["relabelled fixture", (value) => { value.acquisition.upstreamSource.transport = "local-fixture"; }, /upstream local-fixture; crates https\)/u],
    ["https without authority", (value) => { value.acquisition.rustCrates.authoritative = false; }, /crates https, NOT authoritative\)/u],
    ["string authority", (value) => { value.acquisition.rustCrates.authoritative = "true"; }, /NOT authoritative/u],
    ["missing record", (value) => { delete value.acquisition.rustCrates; }, /crates unknown, NOT authoritative/u],
    ["missing acquisition", (value) => { delete value.acquisition; }, /not HTTPS-authoritative/u]
  ]) {
    const fixture = structuredClone(authoritative);
    mutate(fixture);
    assert.throws(() => requireAuthoritativeAcquisition(fixture), /material acquisition is not HTTPS-authoritative/u, label);
    assert.throws(() => requireAuthoritativeAcquisition(fixture), shown, label);
    assert.throws(() => requireAuthoritativeAcquisition(fixture), /fixture or non-authoritative material cannot become a distributed beta asset/u, label);
  }
  assert.throws(() => requireAuthoritativeAcquisition(null), /not HTTPS-authoritative/u);
});

test("material admission snapshots the package before verification, binds the operand digest and never reopens the external path", async () => {
  const rootName = await loadMaterialRootName(provenancePath);
  const temporary = await privateTemporary("fulmar-beta-admission");
  try {
    const packageDirectory = join(temporary, "package");
    await mkdir(packageDirectory, { mode: 0o700 });
    const destination = join(temporary, "admitted");
    const unpackParent = join(temporary, "unpack");
    const fresh = async () => {
      await rm(destination, { recursive: true, force: true });
      await rm(unpackParent, { recursive: true, force: true });
      await mkdir(destination, { mode: 0o700 });
      await mkdir(unpackParent, { mode: 0o700 });
    };
    const original = Buffer.concat([Buffer.from("synthetic material archive "), randomBytes(2021)]);
    const swapped = Buffer.concat([Buffer.from("SWAPPED after admission   "), randomBytes(2022)]);
    const { archiveName, bindingName, sidecarName, tarDigest } = await writeSyntheticMaterials(packageDirectory, rootName, { tarBytes: original });
    const admit = (overrides = {}, observers = undefined) => admitMaterialPackage({
      provenancePath,
      packageDirectory,
      expectedSHA256: tarDigest,
      sourceCommit: headCommit,
      destinationDirectory: destination,
      unpackParent,
      ...overrides
    }, observers);

    // 1. The external package is replaced after the snapshots are taken. The
    //    packager verifier is handed the snapshot (never the external path),
    //    sees the original digest, and the admitted bytes stay the originals.
    await fresh();
    const observed = {};
    await assert.rejects(admit({}, {
      afterMaterialSnapshot: async ({ destinationDirectory, files }) => {
        observed.snapshot = { destinationDirectory, archivePath: files.archive.path, archiveSHA256: files.archive.sha256 };
        await writeFile(join(packageDirectory, archiveName), swapped);
        await writeFile(join(packageDirectory, bindingName), "{\"swapped\":true}\n");
      },
      afterSnapshotAdmitted: async ({ snapshotPath, snapshotSHA256, externalPath }) => {
        observed.verifier = { snapshotPath, snapshotSHA256, externalPath };
      },
      beforeExtraction: async () => { observed.extractionReached = true; }
    }), /binding has an unexpected shape/u, "a synthetic binding can never verify; the rejection happens before extraction");
    assert.equal(observed.snapshot.destinationDirectory, destination);
    assert.equal(observed.snapshot.archivePath, join(destination, archiveName));
    assert.equal(observed.snapshot.archiveSHA256, tarDigest);
    assert.equal(observed.verifier.externalPath, join(destination, archiveName), "verify-archive reads the admitted snapshot, not the operator's package");
    assert.equal(observed.verifier.snapshotSHA256, tarDigest);
    assert.ok(observed.verifier.snapshotPath.startsWith(`${unpackParent}/`), "the verifier's own snapshot stays inside the private unpack parent");
    assert.equal(observed.extractionReached, undefined, "nothing reached extraction");
    assert.equal(digest(await readFile(join(destination, archiveName))), tarDigest, "the admitted bytes are the original, digest-checked bytes");
    assert.equal(digest(await readFile(join(packageDirectory, archiveName))), digest(swapped), "the external package really was replaced and is left as the caller changed it");
    assert.equal(await readFile(join(destination, bindingName), "utf8"), "{}\n");
    assert.equal((await stat(join(destination, archiveName))).mode & 0o777, 0o600);
    assert.deepEqual((await readdir(unpackParent)).sort(), [], "no unpack staging remains after a rejection");

    // 2. Digest, sidecar, shape and link boundaries, each before any verifier
    //    snapshot is taken.
    await writeFile(join(packageDirectory, archiveName), original);
    await writeFile(join(packageDirectory, bindingName), "{}\n");
    const cases = [
      ["wrong expected digest (the app ZIP digest, for example)", { expectedSHA256: syntheticDigest("Fulmar.app.zip") }, /material archive SHA-256 is [a-f0-9]{64}, not the expected [a-f0-9]{64}; the expected digest must be the material archive digest from the reviewed release record, not the app candidate digest, and nothing was extracted/u],
      ["uppercase digest", { expectedSHA256: tarDigest.toUpperCase() }, /must be one lowercase SHA-256 taken from the reviewed release record/u],
      ["short commit", { sourceCommit: headCommit.slice(0, 39) }, /must be one full 40-hex commit/u],
      ["relative provenance path", { provenancePath: "Config/ThirdPartyBinaryProvenance.json" }, /provenance record path must be absolute/u],
      ["missing package directory", { packageDirectory: join(temporary, "absent") }, /ENOENT/u],
      ["relative package directory", { packageDirectory: "package" }, /must be one absolute path/u]
    ];
    for (const [label, overrides, rejection] of cases) {
      await fresh();
      let verifierReached = false;
      await assert.rejects(admit(overrides, { afterSnapshotAdmitted: async () => { verifierReached = true; } }), rejection, label);
      assert.equal(verifierReached, false, `${label}: the packager verifier never ran`);
      assert.deepEqual((await readdir(unpackParent)).sort(), [], `${label}: no unpack staging`);
    }

    await fresh();
    await writeFile(join(packageDirectory, sidecarName), `${syntheticDigest("other")}  ${archiveName}\n`);
    await assert.rejects(admit(), /material sidecar .* does not name the expected digest/u, "a sidecar that disagrees with the operand digest is refused; it is never the trust root");
    await writeFile(join(packageDirectory, sidecarName), `${tarDigest}  ${archiveName}\n`);

    await fresh();
    await rm(join(packageDirectory, bindingName));
    await assert.rejects(admit(), /material package is missing .*\.binding\.json/u);
    await writeFile(join(packageDirectory, bindingName), "{}\n");

    await fresh();
    await rm(join(packageDirectory, archiveName));
    await symlink(join(temporary, "elsewhere.tar"), join(packageDirectory, archiveName));
    await writeFile(join(temporary, "elsewhere.tar"), original);
    await assert.rejects(admit(), /material package entry is not a regular file/u, "a symbolic link in the package is refused");
    await rm(join(packageDirectory, archiveName));
    await link(join(temporary, "elsewhere.tar"), join(packageDirectory, archiveName));
    await fresh();
    await assert.rejects(admit(), /must not be hard linked/u, "a hard-linked archive is refused by the attested read");
    await rm(join(packageDirectory, archiveName));
    await writeFile(join(packageDirectory, archiveName), original);

    await fresh();
    await chmod(destination, 0o755);
    await assert.rejects(admit(), /material admission destination is not owner-private/u);
    await chmod(destination, 0o700);
    await fresh();
    await symlink(destination, join(temporary, "admitted-link"));
    await assert.rejects(admit({ destinationDirectory: join(temporary, "admitted-link") }), /material admission destination is not a real directory/u, "a symbolic link is never a destination");
    await fresh();
    await chmod(packageDirectory, 0o777);
    await assert.rejects(admit(), /material package directory is writable by other users/u);
    await chmod(packageDirectory, 0o700);

    for (const observers of [{ afterMaterialSnapshot: "yes" }, { unknownObserver: async () => {} }, [], "afterMaterialSnapshot"]) {
      await fresh();
      await assert.rejects(admit({}, observers), /observers/u, JSON.stringify(observers));
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("the asset preparer and distribution verifier validate beta material operands before any watchdog, lock or expensive work", async () => {
  const validDigest = syntheticDigest("material");
  for (const [label, arguments_, rejection] of [
    ["beta without material operands", ["--profile", "beta"], /The beta profile requires --material-package, --material-sha256 and --source-commit/u],
    ["beta missing the commit", ["--profile", "beta", "--material-package", "/private/tmp/x", "--material-sha256", validDigest], /requires --material-package, --material-sha256 and --source-commit/u],
    ["stable with a material digest", ["--material-sha256", validDigest], /Material operands are accepted only with --profile beta/u],
    ["explicit stable with a material package", ["--profile", "stable", "--material-package", "/private/tmp/x"], /Material operands are accepted only with --profile beta/u],
    ["relative material package", ["--profile", "beta", "--material-package", "relative/package", "--material-sha256", validDigest, "--source-commit", headCommit], /must be one absolute package directory, one lowercase SHA-256 and one full 40-hex source commit/u],
    ["uppercase material digest", ["--profile", "beta", "--material-package", "/private/tmp/x", "--material-sha256", validDigest.toUpperCase(), "--source-commit", headCommit], /one lowercase SHA-256/u],
    ["short source commit", ["--profile", "beta", "--material-package", "/private/tmp/x", "--material-sha256", validDigest, "--source-commit", headCommit.slice(0, 12)], /one full 40-hex source commit/u],
    ["duplicate profile", ["--profile", "beta", "--profile", "beta"], /^Usage: prepare-public-release-assets\.sh/u],
    ["duplicate digest", ["--profile", "beta", "--material-sha256", validDigest, "--material-sha256", validDigest], /^Usage:/u],
    ["unknown profile", ["--profile", "alpha"], /accepts only the exact release profiles stable or beta/u],
    ["option without value", ["--profile", "beta", "--material-package"], /^Usage:/u],
    ["unknown option", ["--materials", "/private/tmp/x"], /^Usage:/u],
    ["three positional operands", ["a", "b", "c"], /^Usage:/u],
    ["seven positional operands", ["a", "b", "c", "d", "e", "f", "g"], /^Usage:/u]
  ]) {
    const result = runPreparer(arguments_);
    assert.equal(result.status, 64, `${label}: ${result.stdout}\n${result.stderr}`);
    assert.match(result.stderr, rejection, label);
    assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, /Prepared the exact|supervisor-owned root lock|clean environment/u,
      `${label} must be refused before the watchdog, the clean environment or any preparation`);
  }
  const usage = runPreparer(["--profile", "beta", "--profile", "beta"]).stderr;
  assert.match(usage, /--profile beta --material-package \/absolute\/package --material-sha256 <sha256> --source-commit <commit>/u);

  const temporary = await privateTemporary("fulmar-beta-verifier-arguments");
  try {
    const scripts = join(temporary, "scripts");
    await mkdir(scripts, { mode: 0o700 });
    const copiedVerifier = join(scripts, "verify-public-distribution.sh");
    const watchdogHelper = join(scripts, "watchdog-root.zsh");
    await copyFile(verifier, copiedVerifier);
    // The copied source cannot enter any real watchdog or lock: sourcing its
    // first helper is an immediate sentinel failure. Check the copy first so
    // an ordering regression fails before any production-path invocation.
    await writeFile(watchdogHelper, 'print -u2 "fixture: blocked watchdog entered"\nexit 79\n', { mode: 0o600 });
    const packageDirectory = join(temporary, "package never inspected");
    const malformed = [
      ["beta without material operands", [packageDirectory, "--profile", "beta"], /The beta profile requires --material-sha256 and --source-commit/u],
      ["beta missing the commit", ["--profile", "beta", "--material-sha256", validDigest], /The beta profile requires --material-sha256 and --source-commit/u],
      ["stable with a material digest", [packageDirectory, "--material-sha256", validDigest], /Material operands are accepted only with --profile beta/u],
      ["stable with a source commit", ["--profile", "stable", "--source-commit", headCommit], /Material operands are accepted only with --profile beta/u],
      ["beta with a malformed commit", [packageDirectory, "--profile", "beta", "--material-sha256", validDigest, "--source-commit", "abc"], /one lowercase SHA-256 and one full 40-hex source commit/u],
      ["beta with an uppercase digest", ["--profile", "beta", "--material-sha256", validDigest.toUpperCase(), "--source-commit", headCommit], /one lowercase SHA-256 and one full 40-hex source commit/u],
      ["duplicate profile", ["--profile", "beta", "--profile", "beta"], /^Usage: verify-public-distribution\.sh/u],
      ["duplicate material digest", ["--profile", "beta", "--material-sha256", validDigest, "--material-sha256", validDigest, "--source-commit", headCommit], /^Usage:/u],
      ["duplicate source commit", ["--profile", "beta", "--material-sha256", validDigest, "--source-commit", headCommit, "--source-commit", headCommit], /^Usage:/u],
      ["unknown profile", ["--profile", "alpha"], /accepts only the exact release profiles stable or beta/u],
      ["profile without a value", ["--profile"], /^Usage:/u],
      ["digest without a value", ["--profile", "beta", "--material-sha256"], /^Usage:/u],
      ["commit without a value", ["--profile", "beta", "--material-sha256", validDigest, "--source-commit"], /^Usage:/u],
      ["unknown option", [packageDirectory, "--profile", "beta", "--material-package", packageDirectory], /^Usage:/u],
      ["three positional operands", ["a", "b", "c"], /^Usage:/u],
      ["more than the bounded argument count", Array(9).fill(packageDirectory), /^Usage:/u]
    ];
    for (const [label, arguments_, rejection] of malformed) {
      for (const script of [copiedVerifier, verifier]) {
        const result = runVerifier(arguments_, { script, timeout: 5_000 });
        assert.equal(result.error, undefined, `${label}: ${result.error?.message}`);
        assert.equal(result.signal, null, label);
        assert.equal(result.status, 64, `${label}: ${result.stdout}\n${result.stderr}`);
        assert.match(result.stderr, rejection, label);
        assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, /fixture: blocked watchdog entered|supervisor-owned root lock|clean environment|Public .*verification passed/u,
          `${label}: rejected before the watchdog even if the shared lock is held`);
      }
    }

    // A syntactically valid invocation must reach the blocked watchdog, proving
    // the negative cases did not merely exercise a broken or unreachable copy.
    const originalArguments = [packageDirectory, "--profile", "beta", "--material-sha256", validDigest,
      join(temporary, "evidence with spaces.json"), "--source-commit", headCommit];
    let result = runVerifier(originalArguments, { script: copiedVerifier, timeout: 5_000 });
    assert.equal(result.status, 79, result.stderr);
    assert.match(result.stderr, /fixture: blocked watchdog entered/u);

    // Replace only private helpers with built-in-only recording stubs. They
    // exercise both real re-execution callsites, preserve byte boundaries with
    // NUL-delimited records, and stop before any file processing or real lock.
    await writeFile(watchdogHelper, `fulmar_root_watchdog_state() {
  [[ "\${FULMAR_FIXTURE_WATCHDOG_REEXEC:-}" == 1 ]] && return 0
  return 1
}
`, { mode: 0o600 });
    await writeFile(join(scripts, "run-with-watchdog.sh"), `#!/bin/zsh -f
set -euo pipefail
while (( $# > 0 )) && [[ "$1" != -- ]]; do shift; done
[[ "\${1:-}" == -- ]] || exit 80
shift
printf '%s\\0' "$@" > "\${0:A:h:h}/watchdog-argv"
export FULMAR_FIXTURE_WATCHDOG_REEXEC=1
exec "$@"
`, { mode: 0o700 });
    await writeFile(join(scripts, "clean-release-environment.zsh"), `fulmar_require_clean_release_environment() {
  local mode="$1" script="$2"
  shift 2
  [[ "$mode" == public ]] || exit 81
  printf '%s\\0' "$@" > "$PROJECT_DIR/clean-argv"
  if [[ "\${FULMAR_FIXTURE_CLEAN_REEXEC:-}" != 1 ]]; then
    export FULMAR_FIXTURE_CLEAN_REEXEC=1
    exec /bin/zsh -f "$script" "$@"
  fi
}
`, { mode: 0o600 });
    await writeFile(join(scripts, "release-lock.zsh"), `printf '%s\\0' "$RELEASE_PROFILE" "$MATERIAL_SHA256" "$SOURCE_COMMIT_OPERAND" "\${POSITIONAL_OPERANDS[@]}" > "$PROJECT_DIR/parsed-argv"
print -u2 "fixture: stopped before real lock or file processing"
exit 79
`, { mode: 0o600 });
    result = runVerifier(originalArguments, { script: copiedVerifier, timeout: 5_000 });
    assert.equal(result.error, undefined, result.error?.message);
    assert.equal(result.signal, null);
    assert.equal(result.status, 79, result.stderr);
    assert.match(result.stderr, /fixture: stopped before real lock or file processing/u);
    const nulDelimited = (values) => Buffer.from(`${values.join("\0")}\0`);
    assert.deepEqual(await readFile(join(temporary, "watchdog-argv")), nulDelimited([join("/bin", "zsh"), "-f", copiedVerifier, ...originalArguments]),
      "watchdog re-execution preserves every original operand and its order");
    assert.deepEqual(await readFile(join(temporary, "clean-argv")), nulDelimited(originalArguments),
      "clean-environment re-execution preserves every original operand and its order");
    assert.deepEqual(await readFile(join(temporary, "parsed-argv")), nulDelimited(["beta", validDigest, headCommit, packageDirectory, originalArguments[5]]),
      "both re-executions parse the exact beta digest, source commit and positional operands again");
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("the distribution verifier binds the beta package to twelve provenance-named assets, eleven checksum entries and the operator's digest and commit", async () => {
  const rootName = await loadMaterialRootName(provenancePath);
  const [bindingName, archiveName] = materialAssetNames(rootName);
  const temporary = await privateTemporary("fulmar-beta-verifier");
  const notTopology = /must contain exactly the nine reviewed release assets|must contain exactly the twelve reviewed beta release assets/u;
  try {
    const packageDirectory = join(temporary, "package");
    const freshPackage = async (profile, options) => {
      await rm(packageDirectory, { recursive: true, force: true });
      await mkdir(packageDirectory, { mode: 0o700 });
      return writeSyntheticPackage(packageDirectory, profile, rootName, options);
    };
    const beta = (digestOperand, commit = headCommit, extra = []) => runVerifier([packageDirectory, "--profile", "beta", "--material-sha256", digestOperand, "--source-commit", commit, ...extra]);

    // Topology: beta demands exactly twelve assets; stable still demands exactly nine.
    const nineOnly = await freshPackage("stable");
    assert.equal(nineOnly, null);
    let result = beta(syntheticDigest("x"));
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Public beta package must contain exactly the twelve reviewed beta release assets/u, "beta never silently accepts the nine-asset stable package");
    const twelve = await freshPackage("beta");
    result = runVerifier([packageDirectory]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Public package must contain exactly the nine reviewed release assets/u, "stable never silently accepts the twelve-asset beta package");
    await writeFile(join(packageDirectory, "unexpected.txt"), "extra", { mode: 0o644 });
    result = beta(twelve.tarDigest);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /must contain exactly the twelve reviewed beta release assets/u, "an unrelated additional file is refused");
    await rm(join(packageDirectory, "unexpected.txt"));
    await rm(join(packageDirectory, bindingName));
    await writeFile(join(packageDirectory, "other-materials.binding.json"), "{}\n", { mode: 0o644 });
    result = beta(twelve.tarDigest);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /is missing, links or duplicates the reviewed asset: .*\.binding\.json/u, "an arbitrarily named material file is not a beta asset");

    // Checksum membership: eleven exact entries, never the stable eight.
    await freshPackage("beta", { entryNames: STABLE_CHECKSUM_ENTRY_NAMES });
    result = beta(twelve.tarDigest);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /SHA256SUMS\.txt has unexpected or unsafe entries/u, "a beta checksum list must cover the material assets");
    assert.doesNotMatch(result.stderr, notTopology);
    const wrongOrder = checksumEntryNames("beta", rootName).slice().reverse();
    await freshPackage("beta", { entryNames: wrongOrder });
    result = beta(twelve.tarDigest);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /SHA256SUMS\.txt has unexpected or unsafe entries/u, "canonical order is exact");

    // Links and unsafe entries at the package boundary.
    const linked = await freshPackage("beta");
    await rm(join(packageDirectory, archiveName));
    await symlink(join(temporary, "outside.tar"), join(packageDirectory, archiveName));
    await writeFile(join(temporary, "outside.tar"), "outside");
    result = beta(linked.tarDigest);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /is missing, links or duplicates the reviewed asset: .*\.tar$/mu, "a symlinked material archive is refused before any read");
    await rm(join(packageDirectory, archiveName));
    await link(join(temporary, "outside.tar"), join(packageDirectory, archiveName));
    result = beta(linked.tarDigest);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /is missing, links or duplicates the reviewed asset: .*\.tar$/mu, "a hard-linked material archive is refused");

    // The source commit must be this checkout's HEAD; the digest must be the
    // material archive's, never the app ZIP's; the binding must verify.
    const bound = await freshPackage("beta");
    result = beta(bound.tarDigest, OTHER_COMMIT);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, new RegExp(`The supplied --source-commit ${OTHER_COMMIT} is not this checkout's HEAD ${headCommit}`, "u"));
    assert.doesNotMatch(result.stderr, /public-release-asset-policy:/u, "the checkout is checked before any material is admitted");
    const zipDigest = await fileDigest(join(packageDirectory, "Fulmar.app.zip"));
    for (const [label, digestOperand, rejection] of [
      ["the app ZIP digest supplied as the material digest", zipDigest, /material archive SHA-256 is [a-f0-9]{64}, not the expected [a-f0-9]{64}; the expected digest must be the material archive digest from the reviewed release record, not the app candidate digest/u],
      ["a wrong material digest", syntheticDigest("wrong"), /material archive SHA-256 is [a-f0-9]{64}, not the expected/u],
      ["the exact synthetic digest with an unverifiable synthetic binding", bound.tarDigest, /public-release-asset-policy: binding has an unexpected shape/u]
    ]) {
      result = beta(digestOperand);
      assert.notEqual(result.status, 0, label);
      const output = `${result.stdout}\n${result.stderr}`;
      assert.match(output, new RegExp(`${archiveName}: OK`, "u"), `${label}: the eleven-entry checksum list verified the material archive first`);
      if (trackedTreeClean) {
        assert.match(result.stderr, rejection, label);
      } else {
        assert.match(result.stderr, /requires a clean committed source tree \(no modified tracked files\)/u,
          `${label}: a modified tracked tree is refused before material admission (the complete gate runs on committed bytes)`);
      }
      assert.doesNotMatch(output, notTopology, label);
      assert.doesNotMatch(output, /extracting validated snapshot/u, `${label}: nothing was extracted`);
      assert.doesNotMatch(output, /Public verification requires timestamped Developer ID Application/u, `${label}: rejected before Apple trust assessment`);
    }
    // The package itself is never modified by verification.
    assert.deepEqual((await readdir(packageDirectory)).sort(), [...packageAssetNames("beta", rootName)].sort());
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("the copied operator forwards the exact beta operands, refuses them under stable, and finalize neither rebuilds nor regenerates material", async () => {
  const stateRoot = await mkdtemp("/private/tmp/fulmar-public-release-test.");
  const copiedOperator = join(stateRoot, "scripts", "run-public-release.sh");
  const seamPath = join(stateRoot, "test-support", "run-public-release-test-seam.zsh");
  const state = join(stateRoot, "test-state");
  const actionLog = join(state, "actions.log");
  const materialPackage = join(state, "materials");
  const candidateA = syntheticDigest("candidate-A");
  const materialDigest = syntheticDigest("material-archive");
  const otherMaterialDigest = syntheticDigest("material-archive-other");
  const testIdentity = "Developer ID Application: Fulmar Beta Asset Tests (AAAAAAAAAA)";
  const seam = String.raw`TEST_STATE="$PROJECT_DIR/test-state"
ACTION_LOG="$TEST_STATE/actions.log"
log_test_action() {
  print -r -- "$1" >> "$ACTION_LOG"
}
read_key_value() {
  local path="$1" expected="$2" name value
  while IFS='=' read -r name value; do
    if [[ "$name" == "$expected" ]]; then
      print -r -- "$value"
      return 0
    fi
  done < "$path"
  return 1
}
write_test_candidate() {
  local sha256="$1"
  /bin/mkdir -p "$APP" "$BUILD_DIR"
  print -r -- "archive:$sha256" > "$ARCHIVE"
  {
    print -r -- "sha256=$sha256"
    print -r -- "version=9.8.7"
    print -r -- "build=987"
  } > "$MANIFEST"
  print -r -- accepted > "$NOTARY_SUBMISSION"
  print -r -- accepted > "$NOTARY_LOG"
  /bin/chmod 0600 "$ARCHIVE" "$MANIFEST" "$NOTARY_SUBMISSION" "$NOTARY_LOG"
}
read_candidate_field() {
  read_key_value "$MANIFEST" "$1"
}
run_reviewed_node() {
  local script="$1"
  shift
  case "\${script:t}" in
    first-party-license-policy.mjs)
      log_test_action license
      ;;
    verify-public-external-evidence.mjs)
      local evidence="$1" expected_sha="$2" expected_version="$3" expected_build="$4"
      [[ -f "$evidence" && ! -L "$evidence" \
         && "$(read_key_value "$evidence" sha256)" == "$expected_sha" \
         && "$(read_key_value "$evidence" version)" == "$expected_version" \
         && "$(read_key_value "$evidence" build)" == "$expected_build" ]] || return 1
      log_test_action evidence
      ;;
    *)
      print -u2 "Unexpected public-release test Node command: \${script:t}"
      return 1
      ;;
  esac
}
run_static_scan() {
  log_test_action static-scan
}
run_public_build() {
  log_test_action build
  write_test_candidate "\${FULMAR_TEST_CANDIDATE_A}"
}
retain_public_candidate() {
  log_test_action retain
}
verify_public_candidate() {
  [[ -d "$APP" && ! -L "$APP" && -f "$ARCHIVE" && ! -L "$ARCHIVE" \
     && -f "$MANIFEST" && ! -L "$MANIFEST" \
     && -f "$NOTARY_SUBMISSION" && ! -L "$NOTARY_SUBMISSION" \
     && -f "$NOTARY_LOG" && ! -L "$NOTARY_LOG" ]] || return 1
  log_test_action verify-candidate
}
run_clean_script() {
  local script="$1"
  shift
  case "\${script:t}" in
    prepare-public-release-assets.sh)
      log_test_action "prepare:$*"
      local expected_sha="$4"
      [[ "$(read_candidate_field sha256)" == "$expected_sha" ]] || return 1
      [[ ! -e "$PUBLIC_ASSETS" && ! -L "$PUBLIC_ASSETS" ]] || return 1
      /bin/mkdir -m 0700 "$PUBLIC_ASSETS"
      print -r -- "$expected_sha" > "$PUBLIC_ASSETS/candidate-sha256"
      print -r -- "$*" > "$PUBLIC_ASSETS/prepared-with"
      /bin/chmod 0600 "$PUBLIC_ASSETS/candidate-sha256" "$PUBLIC_ASSETS/prepared-with"
      ;;
    verify-public-distribution.sh)
      log_test_action "final-verify:$*"
      [[ -d "$PUBLIC_ASSETS" && ! -L "$PUBLIC_ASSETS" \
         && "$(<"$PUBLIC_ASSETS/candidate-sha256")" == "$(read_candidate_field sha256)" ]] || return 1
      # The fixture verifier refuses material drift exactly as the real one
      # would: the retained package was prepared with one material digest.
      if [[ "$*" == *"--material-sha256 "* ]]; then
        local prepared_with requested
        prepared_with="$(<"$PUBLIC_ASSETS/prepared-with")"
        requested="\${@[\${@[(i)--material-sha256]}+1]}"
        [[ "$prepared_with" == *"--material-sha256 $requested "* ]] || {
          print -u2 "fixture: retained package material digest differs from the requested $requested"
          return 1
        }
      fi
      run_reviewed_node "$PROJECT_DIR/scripts/verify-public-external-evidence.mjs" \
        "$PUBLIC_EXTERNAL_EVIDENCE" "$(read_candidate_field sha256)" \
        "$(read_candidate_field version)" "$(read_candidate_field build)"
      ;;
    *)
      print -u2 "Unexpected public-release test script command: \${script:t}"
      return 1
      ;;
  esac
}
`.replaceAll("\\${", "${");
  try {
    await chmod(stateRoot, 0o700);
    await Promise.all([
      mkdir(join(stateRoot, "scripts"), { recursive: true, mode: 0o700 }),
      mkdir(join(stateRoot, "test-support"), { recursive: true, mode: 0o700 }),
      mkdir(join(stateRoot, "Config"), { recursive: true, mode: 0o700 })
    ]);
    await copyFile(join(root, "scripts", "run-public-release.sh"), copiedOperator);
    await chmod(copiedOperator, 0o700);
    await writeFile(seamPath, seam, { mode: 0o600 });
    await chmod(seamPath, 0o600);
    await writeFile(join(stateRoot, "Config", "ReleaseIdentity.json"), "{}\n", { mode: 0o600 });

    const resetState = async () => {
      await rm(state, { recursive: true, force: true });
      await mkdir(join(state, "home"), { recursive: true, mode: 0o700 });
      await mkdir(materialPackage, { recursive: true, mode: 0o700 });
      await writeFile(join(state, "signing.keychain"), "test-only\n", { mode: 0o600 });
      await chmod(join(state, "signing.keychain"), 0o600);
    };
    const betaOperands = (materialSHA = materialDigest) => ["--profile", "beta", "--material-package", materialPackage, "--material-sha256", materialSHA, "--source-commit", headCommit];
    const runOperator = (arguments_ = []) => spawnSync("/bin/zsh", ["-f", copiedOperator, ...arguments_], {
      cwd: stateRoot,
      encoding: "utf8",
      timeout: 10_000,
      env: {
        HOME: join(state, "home"),
        PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
        USER: process.env.USER,
        LOGNAME: process.env.LOGNAME,
        LANG: "en_US.UTF-8",
        LC_CTYPE: "UTF-8",
        FULMAR_PUBLIC_RELEASE_TEST_SEAM: "1",
        FULMAR_TEST_CANDIDATE_A: candidateA,
        LOCAL_HARNESS_SIGN_IDENTITY: testIdentity,
        LOCAL_HARNESS_SIGNING_KEYCHAIN: join(state, "signing.keychain"),
        LOCAL_HARNESS_NOTARY_PROFILE: "fulmar-beta-asset-test",
        LOCAL_HARNESS_SIGN_TIMESTAMP: "1"
      }
    });
    const writeBetaEvidence = async (sha256) => {
      await writeFile(join(state, "build", "public-beta-external-evidence.json"), `sha256=${sha256}\nversion=9.8.7\nbuild=987\n`, { mode: 0o600 });
      await chmod(join(state, "build", "public-beta-external-evidence.json"), 0o600);
    };
    const actions = async () => (await readFile(actionLog, "utf8").catch(() => "")).trim().split("\n").filter(Boolean);

    // Operand boundary: refused before any seam action is logged.
    await resetState();
    let result = runOperator(["--profile", "beta"]);
    assert.equal(result.status, 64, result.stderr);
    assert.match(result.stderr, /The beta profile requires --material-package, --material-sha256 and --source-commit/u);
    assert.deepEqual(await actions(), [], "no license, scan, build or verification happened");
    result = runOperator(["--material-sha256", materialDigest]);
    assert.equal(result.status, 64, result.stderr);
    assert.match(result.stderr, /Material operands are accepted only with --profile beta/u);
    result = runOperator(["--profile", "beta", "--material-package", "relative", "--material-sha256", materialDigest, "--source-commit", headCommit]);
    assert.equal(result.status, 64, result.stderr);
    assert.match(result.stderr, /must be one absolute package directory/u);
    result = runOperator(["--profile", "beta", "--material-package", "/private/tmp/outside-the-test-root", "--material-sha256", materialDigest, "--source-commit", headCommit]);
    assert.equal(result.status, 64, result.stderr);
    assert.match(result.stderr, /only accepts a material package inside its temporary root/u, "the seam stays confined");
    assert.deepEqual(await actions(), []);

    // Fresh beta run: builds once, pauses for evidence; the candidate digest
    // can never double as the material digest.
    const fresh = runOperator(betaOperands());
    assert.equal(fresh.status, 78, `${fresh.stdout}\n${fresh.stderr}`);
    assert.match(fresh.stderr, /\(beta profile\)[\s\S]*intentionally paused/u);
    assert.deepEqual(await actions(), ["license", "static-scan", "build", "retain", "verify-candidate"]);
    result = runOperator([...betaOperands(candidateA), "--finalize"]);
    assert.equal(result.status, 64, result.stderr);
    assert.match(result.stderr, /The expected material digest equals the retained app candidate digest/u);
    assert.ok(!(await actions()).some((action) => action.startsWith("prepare")), "the confused digest never reaches asset preparation");

    // Finalize with evidence: exact operands forwarded to both children,
    // exactly one build, no material regeneration.
    await writeBetaEvidence(candidateA);
    const finalized = runOperator([...betaOperands(), "--finalize"]);
    assert.equal(finalized.status, 0, `${finalized.stdout}\n${finalized.stderr}`);
    assert.match(finalized.stdout, /without rebuilding it[\s\S]*Public BETA release qualification passed[^\n]*verified third-party material archive [a-f0-9]{64} bound to source commit [a-f0-9]{40}[^\n]*closes no licensing obligation[^\n]*No upload or publication was performed/u);
    let recorded = await actions();
    assert.equal(recorded.filter((action) => action === "build").length, 1, "finalize must not rebuild");
    const prepareAction = recorded.find((action) => action.startsWith("prepare:"));
    assert.ok(prepareAction, "asset preparation ran once");
    assert.ok(prepareAction.endsWith(` ${candidateA} 9.8.7 987 --profile beta --material-package ${materialPackage} --material-sha256 ${materialDigest} --source-commit ${headCommit}`),
      `the preparer received the exact profile and material operands after the candidate identity: ${prepareAction}`);
    const verifyAction = recorded.find((action) => action.startsWith("final-verify:"));
    assert.ok(verifyAction, "distribution verification ran");
    assert.ok(verifyAction.endsWith(` --profile beta --material-sha256 ${materialDigest} --source-commit ${headCommit}`),
      `the verifier received the profile, digest and commit operands: ${verifyAction}`);
    assert.doesNotMatch(verifyAction, /--material-package/u, "the verifier never receives the private package path; it verifies the retained assets");
    assert.equal(await readFile(join(state, "build", "public-release-assets", "candidate-sha256"), "utf8"), `${candidateA}\n`);

    // A second finalize with a different material digest refuses the retained
    // package instead of regenerating it; the package bytes stay as prepared.
    const drift = runOperator([...betaOperands(otherMaterialDigest), "--finalize"]);
    assert.notEqual(drift.status, 0, drift.stdout);
    assert.match(drift.stderr, /retained package material digest differs from the requested/u);
    recorded = await actions();
    assert.equal(recorded.filter((action) => action.startsWith("prepare:")).length, 1, "a present package is never re-prepared");
    assert.equal(recorded.filter((action) => action === "build").length, 1);
    assert.match(await readFile(join(state, "build", "public-release-assets", "prepared-with"), "utf8"), new RegExp(`--material-sha256 ${materialDigest} `, "u"));

    // Stable finalize on the same state never consumes the beta evidence or operands.
    const stable = runOperator(["--finalize"]);
    assert.equal(stable.status, 78, stable.stderr);
    assert.match(stable.stderr, /\(stable profile\)[\s\S]*public-external-evidence\.json/u);
  } finally {
    await rm(stateRoot, { recursive: true, force: true });
  }
});
