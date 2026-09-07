// Fixture-only tests for scripts/stage-libvips-delivery-materials.mjs: the
// private delivery staging of verified corresponding-source archives, .crate
// archives, external notice material, manifests, accompanying documentation
// and the generated inventory, checksum list and status record. Every input is
// synthetic and acquired through the materials tool's local-fixture transport;
// no test contacts the network, extracts an archive, or claims clearance.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, readdir, readFile, realpath, rename, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { gzipSync } from "node:zlib";
import test from "node:test";

const project = process.cwd();
const stagingTool = join(project, "scripts", "stage-libvips-delivery-materials.mjs");
const materialsTool = join(project, "scripts", "prepare-libvips-source-materials.mjs");
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");

function tarEntry(name, bytes, type = "0") {
  const header = Buffer.alloc(512, 0);
  header.write(name, 0, 100, "latin1");
  header.write("0000644\0", 100, "latin1");
  header.write("0000000\0", 108, "latin1");
  header.write("0000000\0", 116, "latin1");
  header.write(`${bytes.byteLength.toString(8).padStart(11, "0")}\0`, 124, "latin1");
  header.write("00000000000\0", 136, "latin1");
  header.write("        ", 148, "latin1");
  header.write(type, 156, "latin1");
  header.write("ustar\0", 257, "latin1");
  header.write("00", 263, "latin1");
  let sum = 0;
  for (const byte of header) sum += byte;
  header.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, "latin1");
  const padded = Buffer.alloc(Math.ceil(bytes.byteLength / 512) * 512, 0);
  bytes.copy(padded);
  return Buffer.concat([header, padded]);
}

function crateArchive(entries) {
  return gzipSync(Buffer.concat([...entries.map(([name, bytes, type]) => tarEntry(name, bytes, type)), Buffer.alloc(1024, 0)]));
}

const FIXTURE_COMMIT = "0".repeat(40);
const GAMMA_COMMIT = "1".repeat(40);
const DELTA_COMMIT = "3".repeat(40);
const MPL_HEADER = "/* This Source Code Form is subject to the terms of the Mozilla Public\n * License, v. 2.0. If a copy of the MPL was not distributed with this\n * file, You can obtain one at https://mozilla.org/MPL/2.0/. */";

function run(args) {
  return spawnSync(process.execPath, [stagingTool, ...args], { cwd: project, encoding: "utf8", timeout: 60_000 });
}

async function listDirectory(path) {
  try {
    return (await readdir(path)).sort();
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

async function walk(root, relative = "") {
  const entries = new Map();
  for (const entry of (await readdir(join(root, relative), { withFileTypes: true })).sort((left, right) => (left.name < right.name ? -1 : 1))) {
    const path = relative === "" ? entry.name : `${relative}/${entry.name}`;
    if (entry.isDirectory()) {
      for (const [child, bytes] of await walk(root, path)) entries.set(child, bytes);
    } else {
      entries.set(path, await readFile(join(root, path)));
    }
  }
  return entries;
}

async function fixture() {
  const root = await realpath(await mkdtemp(join(tmpdir(), "fulmar-delivery-materials.")));
  const config = join(root, "Config");
  await mkdir(config, { mode: 0o700 });
  await mkdir(join(root, "docs"), { mode: 0o700 });
  await mkdir(join(root, "inputs"), { mode: 0o700 });
  await mkdir(join(root, "out"), { mode: 0o700 });
  const licences = join(root, "Resources", "ThirdPartyLicenses", "fixture-binary-1.0.0");
  await mkdir(join(licences, "rust"), { recursive: true, mode: 0o700 });
  // Upstream corresponding-source items: one recipe, one patch, one archive (opaque bytes).
  const recipeBytes = Buffer.from("#!/bin/sh\necho fixture recipe\n");
  const patchBytes = Buffer.from("--- a\n+++ b\n@@ -1 +1 @@\n-x\n+y\n");
  const archiveBytes = Buffer.concat([Buffer.from("fixture archive "), Buffer.alloc(3000, 0x41)]);
  const put = async (url, bytes) => {
    const parsed = new URL(url);
    const path = join(root, "upstream", parsed.hostname, ...parsed.pathname.split("/").filter(Boolean));
    await mkdir(join(path, ".."), { recursive: true, mode: 0o700 });
    await writeFile(path, bytes);
  };
  await put("https://example.test/recipe/build.sh", recipeBytes);
  await put("https://example.test/patches/fix.patch", patchBytes);
  await put("https://example.test/archive/lib-1.0.tar.gz", archiveBytes);
  // Crates: alpha carries a licence member; gamma carries none but an external upstream LICENSE is retained; delta carries none and is unresolved.
  const alphaLicence = Buffer.from("MIT License\n\nCopyright (c) Alpha Crate Authors\n");
  const alpha = crateArchive([
    ["alpha-1.2.3/Cargo.toml", Buffer.from("[package]\nname = \"alpha\"\nversion = \"1.2.3\"\nlicense = \"MIT\"\n")],
    ["alpha-1.2.3/LICENSE-MIT", alphaLicence],
    ["alpha-1.2.3/src/lib.rs", Buffer.from(`${MPL_HEADER}\npub fn alpha() {}\n`)]
  ]);
  const gamma = crateArchive([
    ["gamma-2.0.0/Cargo.toml", Buffer.from("[package]\nname = \"gamma\"\nversion = \"2.0.0\"\nlicense = \"MIT\"\n")],
    ["gamma-2.0.0/src/lib.rs", Buffer.from("pub fn gamma() {}\n")]
  ]);
  const delta = crateArchive([
    ["delta-0.1.0/Cargo.toml", Buffer.from("[package]\nname = \"delta\"\nversion = \"0.1.0\"\nlicense = \"MIT\"\n")],
    ["delta-0.1.0/src/lib.rs", Buffer.from("pub fn delta() {}\n")]
  ]);
  await put("https://static.crates.io/crates/alpha/alpha-1.2.3.crate", alpha);
  await put("https://static.crates.io/crates/gamma/gamma-2.0.0.crate", gamma);
  await put("https://static.crates.io/crates/delta/delta-0.1.0.crate", delta);
  const binary = {
    packageName: "@fixture/combined-binary", version: "1.0.0", buildRepository: "https://example.test/build", buildTag: "v1.0.0",
    buildCommit: FIXTURE_COMMIT, buildPlatform: "darwin-arm64v8", shippedBinary: "node_modules/@fixture/combined-binary/lib/lib.dylib",
    shippedBinarySHA256: "1".repeat(64), provenanceRecord: "Config/provenance.json"
  };
  const sourceManifest = {
    schemaVersion: 1,
    purpose: "Fixture corresponding-source manifest for hermetic tests. It identifies material; it is not legal clearance and is not a corresponding-source offer.",
    binary,
    outputDirectoryName: "fixture-source-materials",
    limits: { maximumFileBytes: 65536, maximumTotalBytes: 1048576, maximumRedirects: 0, requestTimeoutMilliseconds: 5000 },
    items: [
      { id: "recipe-build-sh", kind: "build-recipe", fileName: "build.sh", url: "https://example.test/recipe/build.sh", size: recipeBytes.byteLength, sha256: digest(recipeBytes), allowedRedirectHosts: [], immutability: "commit-pinned-raw-file", role: "fixture recipe entry point" },
      { id: "patch-fix", kind: "patch", fileName: "fix.patch", url: "https://example.test/patches/fix.patch", size: patchBytes.byteLength, sha256: digest(patchBytes), allowedRedirectHosts: [], immutability: "revision-pinned", component: "lib", role: "fixture patch applied with patch -p1" },
      { id: "source-lib", kind: "source-archive", component: "lib", versionKey: "lib", version: "1.0", fileName: "lib-1.0.tar.gz", url: "https://example.test/archive/lib-1.0.tar.gz", size: archiveBytes.byteLength, sha256: digest(archiveBytes), allowedRedirectHosts: [], immutability: "release-asset", upstreamRepository: "https://example.test/lib", upstreamRevision: "a".repeat(40), revisionEvidence: "fixture tag resolution recorded for the test", recipeReference: "build/posix.sh (VERSION_LIB)" }
    ],
    unretained: [{ id: "rebuild-not-attempted", component: "all", detail: "No build was attempted by this fixture." }]
  };
  const crateItem = (name, version, bytes, extra) => ({
    id: `crate-${name}-${version}`, kind: "rust-crate", crateName: name, crateVersion: version, fileName: `${name}-${version}.crate`,
    url: `https://static.crates.io/crates/${name}/${name}-${version}.crate`, size: bytes.byteLength, sha256: digest(bytes), allowedRedirectHosts: [],
    immutability: "crates-io-immutable-crate-file", registry: "https://github.com/rust-lang/crates.io-index",
    checksumSource: "fixture Cargo.lock checksum recorded for the test", role: "normal", ...extra
  });
  const crateManifest = {
    schemaVersion: 1,
    purpose: "Fixture rust-crate manifest: an approximation for hermetic tests; not legal clearance and not a corresponding-source offer.",
    binary,
    outputDirectoryName: "fixture-rust-materials",
    limits: { maximumFileBytes: 1048576, maximumTotalBytes: 8388608, maximumRedirects: 0, requestTimeoutMilliseconds: 5000 },
    historicalBuildEvidence: {
      jobLog: { rawSHA256: "b".repeat(64), rawBytes: 4096, lines: 100 },
      observedCompilation: { registryCrateCount: 2, approximationNotObserved: [{ name: "delta", version: "0.1.0" }], observedNotInApproximation: [] }
    },
    categories: {
      resolvedForTargetApproximation: { workspaceMembers: ["fixture-workspace 1.0.0 (root)"] },
      compiledInHistoricalBuild: { status: "observed", detail: "fixture: alpha and gamma observed in a retained log" },
      incorporatedIntoShippedBinary: { status: "unverified", detail: "fixture" }
    },
    items: [
      crateItem("alpha", "1.2.3", alpha, { licenseExpression: "MIT", provenanceStatus: "compiled-per-build-log", observedCompilation: { logLine: 42, timestamp: "2026-06-30T09:14:26.3311710Z" }, authors: ["Alpha Author"], noticeMembers: [{ member: "alpha-1.2.3/LICENSE-MIT", size: alphaLicence.byteLength, sha256: digest(alphaLicence) }], noticeStatus: "crate-carries-licence-text" }),
      crateItem("delta", "0.1.0", delta, { licenseExpression: "MIT", provenanceStatus: "resolved-approximation", observedCompilation: null, authors: ["Delta Author"], noticeMembers: [], noticeStatus: "no-licence-text-in-crate" }),
      crateItem("gamma", "2.0.0", gamma, { licenseExpression: "MIT", provenanceStatus: "compiled-per-build-log", observedCompilation: { logLine: 43, timestamp: "2026-06-30T09:14:27.3311710Z" }, noticeMembers: [], noticeStatus: "no-licence-text-in-crate" })
    ],
    unretained: [{ id: "compile-log-coverage", detail: "Fixture: the retained log is synthetic." }]
  };
  const gammaUpstream = Buffer.from("MIT License\n\nCopyright (c) Gamma Crate Upstream\n\nPermission is hereby granted to use this fixture licence.\n");
  const gammaPath = "Resources/ThirdPartyLicenses/fixture-binary-1.0.0/rust/gamma-2.0.0-external-gamma-LICENSE";
  await writeFile(join(root, ...gammaPath.split("/")), gammaUpstream);
  const noticeMaterials = {
    schemaVersion: 1,
    purpose: "Fixture version-bound notice material for crates whose archives carry no licence text. External material is labelled as such and was never a member of the original archive. This is material identification, not legal clearance.",
    crateManifest: "Config/crate-manifest.json",
    researchedOn: "2026-09-06",
    summary: { established: ["gamma 2.0.0"], unresolved: ["delta 0.1.0"] },
    records: [
      {
        crateName: "delta", crateVersion: "0.1.0", crateSHA256: digest(delta), licenseExpression: "MIT", status: "unresolved",
        connection: { kind: "version-tag", repository: "https://github.com/fixture/delta", revision: DELTA_COMMIT, revisionEvidence: `lightweight tag 0.1.0 resolved with git ls-remote on 2026-09-06; Cargo.toml at that commit carries version = "0.1.0" and license = "MIT" and authors = ["Delta Author"]` },
        materials: [],
        unresolved: {
          missingEvidence: "An upstream-published MIT licence text and copyright statement for this exact version. Neither the crate archive nor the tagged upstream revision carries any licence text; a generic MIT text would need a copyright line the upstream never published, so none is asserted.",
          checksPerformed: [
            { check: "crate archive top-level members", result: "Cargo.toml only; no licence member" },
            { check: "upstream repository tag for this exact version", result: `tag 0.1.0 = commit ${DELTA_COMMIT}` },
            { check: "repository tree at that commit", result: "no LICENSE, COPYING or NOTICE file at any path" },
            { check: "source file header (fallback)", result: "src/lib.rs carries no copyright or licence header" }
          ],
          fallbackUsed: "source file headers at the tagged revision (none present); research stopped per the bounded scope"
        }
      },
      {
        crateName: "gamma", crateVersion: "2.0.0", crateSHA256: digest(gamma), licenseExpression: "MIT", status: "established",
        connection: { kind: "cargo-vcs-info", repository: "https://github.com/fixture/gamma", revision: GAMMA_COMMIT, pathInVcs: "gamma",
          revisionEvidence: `the crate archive member gamma-2.0.0/.cargo_vcs_info.json (sha256 ${"6".repeat(64)}) records git sha1 ${GAMMA_COMMIT} and path_in_vcs gamma; gamma/Cargo.toml at that commit declares version = "2.0.0"; the crate member src/lib.rs is byte-identical to gamma/src/lib.rs at that commit` },
        materials: [{
          kind: "external-upstream-file", sourcePath: gammaPath,
          describes: "MIT licence with copyright statement, the repository-level LICENSE at the exact commit the crate was packaged from (external to the archive)",
          origin: `https://github.com/fixture/gamma/blob/${GAMMA_COMMIT}/LICENSE`,
          upstreamSHA256: digest(gammaUpstream.subarray(0, gammaUpstream.byteLength - 1)), upstreamSize: gammaUpstream.byteLength - 1,
          normalization: "append-terminal-lf-v1", sha256: digest(gammaUpstream), size: gammaUpstream.byteLength, retrievedOn: "2026-09-06"
        }]
      }
    ]
  };
  const alphaNotice = Buffer.from("MIT License\n\nCopyright (c) Alpha Authors\n");
  await writeFile(join(licences, "alpha-1.2.3-LICENSE"), alphaNotice);
  const acknowledgements = "# Fixture acknowledgements\n\n## alpha — required credit\n\n> Portions of this fixture are copyright (c) Alpha Authors\n> (https://example.test/alpha). All rights reserved.\n";
  await writeFile(join(root, "docs", "ACKNOWLEDGEMENTS.md"), acknowledgements);
  const provenance = {
    schemaVersion: 1,
    purpose: "Fixture provenance record for hermetic tests; an auditable inventory, not legal clearance.",
    components: [{
      id: "combined-binary",
      packageName: "@fixture/combined-binary",
      version: "1.0.0",
      lockfilePath: "node_modules/@fixture/combined-binary",
      upstream: { buildCommit: FIXTURE_COMMIT },
      componentNotices: [{
        component: "alpha", versionKey: "alpha", version: "1.2.3", manifestLicense: "MIT",
        upstreamRepository: "https://example.test/alpha", upstreamRevision: "a".repeat(40), revisionEvidence: "fixture tag resolution recorded for the test",
        materials: [{ sourcePath: "Resources/ThirdPartyLicenses/fixture-binary-1.0.0/alpha-1.2.3-LICENSE", describes: "alpha fixture notice text", origin: `https://example.test/alpha/blob/${"c".repeat(40)}/LICENSE`, upstreamSHA256: digest(alphaNotice.subarray(0, alphaNotice.byteLength - 1)), normalization: "append-terminal-lf-v1", sha256: digest(alphaNotice), archiveMember: "alpha-1.2.3/LICENSE", archiveSHA256: "d".repeat(64) }]
      }],
      deliveryMaterials: {
        purpose: "Fixture delivery material bindings; they identify and verify material and are not legal clearance.",
        outputDirectoryName: "fixture-delivery-materials",
        sourceMaterials: "Config/source-manifest.json",
        rustCrateMaterials: "Config/crate-manifest.json",
        rustNoticeMaterials: "Config/notice-materials.json",
        accompanyingDocumentation: {
          path: "docs/ACKNOWLEDGEMENTS.md",
          statements: [{ id: "alpha-credit", component: "alpha", material: "Resources/ThirdPartyLicenses/fixture-binary-1.0.0/alpha-1.2.3-LICENSE", basis: "fixture licence section 2 requires a credit in product documentation", statement: "Portions of this fixture are copyright (c) Alpha Authors (https://example.test/alpha). All rights reserved." }],
          clarifications: []
        }
      },
      obligations: [
        { id: "corresponding-source", status: "open", detail: "Fixture: no corresponding-source offer exists yet; this record identifies material only." },
        { id: "legal-clearance", status: "open", detail: "Fixture: no formal legal clearance is claimed for redistributing this binary." }
      ]
    }]
  };
  const writeJSON = async (name, value) => writeFile(join(config, name), `${JSON.stringify(value, null, 2)}\n`);
  await writeJSON("provenance.json", provenance);
  await writeJSON("source-manifest.json", sourceManifest);
  await writeJSON("crate-manifest.json", crateManifest);
  await writeJSON("notice-materials.json", noticeMaterials);
  const upstreamDirectory = join(root, "inputs", "fixture-source-materials");
  const crateDirectory = join(root, "inputs", "fixture-rust-materials");
  const acquireUpstream = spawnSync(process.execPath, [materialsTool, "acquire", join(config, "source-manifest.json"), upstreamDirectory, "--transport", `local-fixture:${join(root, "upstream")}`], { cwd: project, encoding: "utf8", timeout: 30_000 });
  const acquireCrates = spawnSync(process.execPath, [materialsTool, "acquire", join(config, "crate-manifest.json"), crateDirectory, "--transport", `local-fixture:${join(root, "upstream")}`, "--notice-materials", join(config, "notice-materials.json")], { cwd: project, encoding: "utf8", timeout: 30_000 });
  if (acquireUpstream.status !== 0 || acquireCrates.status !== 0) {
    await rm(root, { recursive: true, force: true });
    assert.fail(`fixture inputs could not be acquired: ${acquireUpstream.stderr}\n${acquireCrates.stderr}`);
  }
  return {
    root, config, upstreamDirectory, crateDirectory, provenance, sourceManifest, crateManifest, noticeMaterials, gammaPath, gammaUpstream, acknowledgements,
    provenancePath: join(config, "provenance.json"),
    destination: join(root, "out", "fixture-delivery-materials"),
    saveProvenance: () => writeJSON("provenance.json", provenance),
    saveCrateManifest: () => writeJSON("crate-manifest.json", crateManifest),
    saveNoticeMaterials: () => writeJSON("notice-materials.json", noticeMaterials)
  };
}

function stage(files, destination = files.destination) {
  return run(["stage", files.provenancePath, files.upstreamDirectory, files.crateDirectory, destination]);
}

function verify(files, destination = files.destination) {
  return run(["verify", files.provenancePath, destination]);
}

const EXPECTED_FILES = [
  "DELIVERY_INVENTORY.json",
  "DELIVERY_STATUS.md",
  "SHA256SUMS",
  "manifests/crate-manifest.json",
  "manifests/notice-materials.json",
  "manifests/provenance.json",
  "manifests/source-manifest.json",
  "notices/ACKNOWLEDGEMENTS.md",
  "notices/rust-external/gamma-2.0.0-external-gamma-LICENSE",
  "rust-crates/fixture-rust-materials/INVENTORY.json",
  "rust-crates/fixture-rust-materials/RUST_CRATE_NOTICES.md",
  "rust-crates/fixture-rust-materials/SHA256SUMS",
  "rust-crates/fixture-rust-materials/alpha-1.2.3.crate",
  "rust-crates/fixture-rust-materials/delta-0.1.0.crate",
  "rust-crates/fixture-rust-materials/gamma-2.0.0.crate",
  "upstream-source/fixture-source-materials/INVENTORY.json",
  "upstream-source/fixture-source-materials/SHA256SUMS",
  "upstream-source/fixture-source-materials/build.sh",
  "upstream-source/fixture-source-materials/fix.patch",
  "upstream-source/fixture-source-materials/lib-1.0.tar.gz"
];

test("staging assembles a verified, deterministic delivery set with a bound inventory, checksum list and factual status record", async () => {
  const files = await fixture();
  try {
    const staged = stage(files);
    assert.equal(staged.status, 0, staged.stderr);
    assert.match(staged.stderr, /published 20 files \(\d+ bytes\) to .*fixture-delivery-materials; DELIVERY_INVENTORY\.json sha256:[a-f0-9]{64}; SHA256SUMS sha256:[a-f0-9]{64}; upstream local-fixture \(NOT authoritative\), crates local-fixture \(NOT authoritative\); unresolved notices 1/u);
    assert.deepEqual(await listDirectory(join(files.root, "out")), ["fixture-delivery-materials"], "no staging directory remains");
    const tree = await walk(files.destination);
    assert.deepEqual([...tree.keys()].sort(), EXPECTED_FILES);
    // Inputs are copied byte-for-byte and the tracked files verbatim.
    for (const name of ["build.sh", "fix.patch", "lib-1.0.tar.gz", "INVENTORY.json", "SHA256SUMS"]) {
      assert.deepEqual(tree.get(`upstream-source/fixture-source-materials/${name}`), await readFile(join(files.upstreamDirectory, name)), name);
    }
    for (const name of ["alpha-1.2.3.crate", "delta-0.1.0.crate", "gamma-2.0.0.crate", "INVENTORY.json", "SHA256SUMS", "RUST_CRATE_NOTICES.md"]) {
      assert.deepEqual(tree.get(`rust-crates/fixture-rust-materials/${name}`), await readFile(join(files.crateDirectory, name)), name);
    }
    for (const name of ["provenance.json", "source-manifest.json", "crate-manifest.json", "notice-materials.json"]) {
      assert.deepEqual(tree.get(`manifests/${name}`), await readFile(join(files.config, name)), name);
    }
    assert.deepEqual(tree.get("notices/rust-external/gamma-2.0.0-external-gamma-LICENSE"), files.gammaUpstream);
    assert.equal(tree.get("notices/ACKNOWLEDGEMENTS.md").toString("utf8"), files.acknowledgements);
    // The complete Rust notices carry the external text and the unresolved record.
    const rustNotices = tree.get("rust-crates/fixture-rust-materials/RUST_CRATE_NOTICES.md").toString("utf8");
    assert.match(rustNotices, /Copyright \(c\) Gamma Crate Upstream/u);
    assert.match(rustNotices, /### `delta` 0\.1\.0 — UNRESOLVED/u);
    // Checksum list: every file except itself, sorted, GNU coreutils shape.
    const sums = tree.get("SHA256SUMS").toString("utf8");
    const expectedSums = EXPECTED_FILES.filter((path) => path !== "SHA256SUMS").map((path) => `${digest(tree.get(path))}  ${path}`).join("\n");
    assert.equal(sums, `${expectedSums}\n`);
    // Inventory: machine-readable, bounded, binds every file and every input digest, no timestamps or private paths.
    const inventory = JSON.parse(tree.get("DELIVERY_INVENTORY.json").toString("utf8"));
    assert.equal(inventory.inventoryType, "fulmar-libvips-delivery-materials");
    assert.equal(inventory.schemaVersion, 1);
    assert.equal(inventory.fileCount, 18);
    assert.deepEqual(inventory.files.map(({ path }) => path), EXPECTED_FILES.filter((path) => path !== "SHA256SUMS" && path !== "DELIVERY_INVENTORY.json"));
    for (const file of inventory.files) {
      assert.equal(file.sha256, digest(tree.get(file.path)), file.path);
      assert.equal(file.size, tree.get(file.path).byteLength, file.path);
    }
    assert.equal(inventory.provenanceRecord.sha256, digest(await readFile(files.provenancePath)));
    assert.equal(inventory.manifests.sourceMaterials.sha256, digest(await readFile(join(files.config, "source-manifest.json"))));
    assert.equal(inventory.manifests.rustCrateMaterials.sha256, digest(await readFile(join(files.config, "crate-manifest.json"))));
    assert.equal(inventory.manifests.rustNoticeMaterials.sha256, digest(await readFile(join(files.config, "notice-materials.json"))));
    assert.equal(inventory.upstreamSource.itemCount, 3);
    assert.equal(inventory.upstreamSource.transport, "local-fixture");
    assert.equal(inventory.upstreamSource.authoritative, false, "the fixture transport flag is carried forward truthfully");
    assert.equal(inventory.rustCrates.itemCount, 3);
    assert.equal(inventory.rustCrates.authoritative, false);
    assert.deepEqual(inventory.rustCrates.historicalBuildProvenance, { compiledInHistoricalBuild: "observed", incorporatedIntoShippedBinary: "unverified" });
    assert.equal(inventory.rustCrates.observedRegistryCrates, 2);
    assert.deepEqual(inventory.rustCrates.approximationOnlyCrates, ["delta 0.1.0"]);
    assert.deepEqual(inventory.rustCrates.workspaceMembers, ["fixture-workspace 1.0.0 (root)"]);
    assert.deepEqual(inventory.rustCrates.noticeMaterials.unresolved, ["delta 0.1.0"]);
    assert.equal(inventory.rustCrates.rustNoticesSHA256, digest(tree.get("rust-crates/fixture-rust-materials/RUST_CRATE_NOTICES.md")));
    assert.deepEqual(inventory.externalNoticeMaterials.map(({ crate, kind, stagedPath, sha256 }) => ({ crate, kind, stagedPath, sha256 })),
      [{ crate: "gamma 2.0.0", kind: "external-upstream-file", stagedPath: "notices/rust-external/gamma-2.0.0-external-gamma-LICENSE", sha256: digest(files.gammaUpstream) }]);
    assert.equal(inventory.unresolvedNotices.length, 1);
    assert.match(inventory.unresolvedNotices[0].missingEvidence, /none is asserted/u);
    assert.equal(inventory.accompanyingDocumentation.sha256, digest(Buffer.from(files.acknowledgements)));
    assert.equal(inventory.accompanyingDocumentation.statements[0].statement, "Portions of this fixture are copyright (c) Alpha Authors (https://example.test/alpha). All rights reserved.");
    assert.deepEqual(inventory.status, {
      kind: "material-delivery-preparation-set",
      historicalCompilation: "observed",
      dylibIncorporation: "unverified",
      unresolvedNoticeCount: 1,
      openObligations: ["corresponding-source", "legal-clearance"],
      statement: "A material-delivery preparation set assembled from verified inputs. Historical compilation is observed, dylib incorporation is unverified, the listed crate notices remain unresolved, and no legal clearance or public source offer is inferred from this directory's existence."
    });
    const serialized = JSON.stringify(inventory);
    assert.doesNotMatch(serialized, new RegExp(files.root.replaceAll(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"), "no private absolute path is recorded");
    assert.doesNotMatch(serialized, /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/u, "no generation timestamp is recorded");
    assert.doesNotMatch(serialized, /cleared|compliant|legally (?:sufficient|satisfied)/iu);
    // Status record: concise and factual.
    const status = tree.get("DELIVERY_STATUS.md").toString("utf8");
    assert.match(status, /^# Delivery material preparation set: @fixture\/combined-binary 1\.0\.0\n/u);
    assert.match(status, /It is not a public source offer, not a release asset and not legal clearance/u);
    assert.match(status, /Historical compilation: \*\*observed\*\* for 2 registry crates and the workspace packages `fixture-workspace 1\.0\.0 \(root\)` in the retained job log \(raw `sha256:b{64}`\); 1 crate remains? approximation-only \(`delta 0\.1\.0`\)/u);
    assert.match(status, /Incorporation into the shipped dylib: \*\*unverified\*\*/u);
    assert.match(status, /\*\*1 remain UNRESOLVED\*\* \(`delta 0\.1\.0`\)/u);
    assert.match(status, /NOT authoritative: an offline re-read of retained bytes whose digests equal the manifest pins/u);
    assert.match(status, /No source offer is published, no release asset is defined and no hosting location is chosen/u);
    // Verification passes and the set is independently reproducible byte-for-byte.
    const verified = verify(files);
    assert.equal(verified.status, 0, verified.stderr);
    assert.match(verified.stderr, /verified 20 files .*; unresolved notices 1; dylib incorporation unverified/u);
    await mkdir(join(files.root, "second"), { mode: 0o700 });
    const second = stage(files, join(files.root, "second", "fixture-delivery-materials"));
    assert.equal(second.status, 0, second.stderr);
    const secondTree = await walk(join(files.root, "second", "fixture-delivery-materials"));
    assert.deepEqual([...secondTree.keys()].sort(), [...tree.keys()].sort());
    for (const [path, bytes] of tree) assert.deepEqual(secondTree.get(path), bytes, `${path} is byte-identical across independent stagings`);
    assert.equal(verify(files, join(files.root, "second", "fixture-delivery-materials")).status, 0);
  } finally {
    await rm(files.root, { recursive: true, force: true });
  }
});

test("staging fails closed and publishes nothing on unverifiable inputs, unsafe destinations or malformed invocations", async (context) => {
  const cases = [
    {
      name: "destination already exists",
      mutate: async (files) => mkdir(files.destination, { mode: 0o700 }),
      message: /destination already exists/u,
      keeps: ["fixture-delivery-materials"]
    },
    {
      name: "destination with the wrong name",
      destination: (files) => join(files.root, "out", "other-name"),
      message: /destination must be named fixture-delivery-materials/u
    },
    {
      name: "destination parent writable by other users",
      mutate: async (files) => chmod(join(files.root, "out"), 0o777),
      message: /writable by other users; a private destination is required/u
    },
    {
      name: "destination parent reached through a symbolic link",
      mutate: async (files) => symlink(join(files.root, "out"), join(files.root, "linked-out")),
      destination: (files) => join(files.root, "linked-out", "fixture-delivery-materials"),
      message: /must not traverse aliases or symbolic links|is not a real directory/u
    },
    {
      name: "destination inside an input directory",
      destination: (files) => join(files.crateDirectory, "fixture-delivery-materials"),
      message: /must not overlap an input directory|writable by other users|is not owned/u
    },
    {
      name: "upstream archive truncated",
      mutate: async (files) => {
        const path = join(files.upstreamDirectory, "lib-1.0.tar.gz");
        await writeFile(path, (await readFile(path)).subarray(0, 100));
      },
      message: /size or topology drifted: lib-1\.0\.tar\.gz/u
    },
    {
      name: "upstream item substituted at the same size",
      mutate: async (files) => {
        const path = join(files.upstreamDirectory, "fix.patch");
        const bytes = Buffer.from(await readFile(path));
        bytes[0] ^= 0x01;
        await writeFile(path, bytes);
      },
      message: /SHA-256 drifted: fix\.patch/u
    },
    {
      name: "upstream directory with an extra file",
      mutate: async (files) => writeFile(join(files.upstreamDirectory, "extra.tar.gz"), "x"),
      message: /unexpected entry: extra\.tar\.gz/u
    },
    {
      name: "crate archive deleted",
      mutate: async (files) => rm(join(files.crateDirectory, "gamma-2.0.0.crate")),
      message: /missing expected entries/u
    },
    {
      name: "crate archive replaced by a symbolic link",
      mutate: async (files) => {
        const path = join(files.crateDirectory, "alpha-1.2.3.crate");
        const target = join(files.root, "alpha-target.crate");
        await writeFile(target, await readFile(path));
        await unlink(path);
        await symlink(target, path);
      },
      message: /not a regular file|ELOOP|symbolic link|too many levels/u
    },
    {
      name: "crate directory rendered without the external notice material",
      mutate: async (files) => {
        await rm(files.crateDirectory, { recursive: true });
        const acquired = spawnSync(process.execPath, [materialsTool, "acquire", join(files.config, "crate-manifest.json"), files.crateDirectory, "--transport", `local-fixture:${join(files.root, "upstream")}`], { cwd: project, encoding: "utf8", timeout: 30_000 });
        assert.equal(acquired.status, 0, acquired.stderr);
      },
      message: /inventory was rendered without external notice material/u
    },
    {
      name: "stale crate directory after the crate manifest changed",
      mutate: async (files) => {
        files.crateManifest.unretained.push({ id: "later-note", detail: "Fixture: a later edit to the tracked manifest." });
        await files.saveCrateManifest();
      },
      message: /inventory does not describe this manifest/u
    },
    {
      name: "external notice material missing",
      mutate: async (files) => rm(join(files.root, ...files.gammaPath.split("/"))),
      message: /ENOENT|no such file/u
    },
    {
      name: "external notice material drifted",
      mutate: async (files) => {
        const bytes = Buffer.from(files.gammaUpstream);
        bytes[bytes.indexOf("Gamma")] = 0x4c;
        await writeFile(join(files.root, ...files.gammaPath.split("/")), bytes);
      },
      message: /tracked material SHA-256 drifted/u
    },
    {
      name: "acknowledgement statement absent from the documentation",
      mutate: async (files) => writeFile(join(files.root, "docs", "ACKNOWLEDGEMENTS.md"), files.acknowledgements.replace("Alpha Authors", "Alpha Team")),
      message: /does not carry the exact statement alpha-credit/u
    },
    {
      name: "provenance record without delivery bindings",
      mutate: async (files) => {
        delete files.provenance.components[0].deliveryMaterials;
        await files.saveProvenance();
      },
      message: /exactly one component must declare delivery materials \(found 0\)/u
    },
    {
      name: "provenance record promoting an obligation",
      mutate: async (files) => {
        files.provenance.components[0].obligations[0].status = "closed";
        await files.saveProvenance();
      },
      message: /obligations must be material-bound or open/u
    },
    {
      name: "crate manifest naming another provenance record",
      mutate: async (files) => {
        files.crateManifest.binary.provenanceRecord = "Config/other.json";
        await files.saveCrateManifest();
      },
      message: /inventory does not describe this manifest|names Config\/other\.json as its provenance record/u
    },
    {
      name: "upstream and crate directories swapped",
      swap: true,
      message: /destination must be named fixture-source-materials|unexpected entry/u
    }
  ];
  for (const current of cases) {
    await context.test(current.name, async () => {
      const files = await fixture();
      try {
        // A pre-existing sibling output must survive a failed staging untouched.
        const sibling = join(files.root, "out", "unrelated-materials");
        await mkdir(sibling, { mode: 0o700 });
        await writeFile(join(sibling, "keep.txt"), "keep\n");
        const upstreamBefore = await walk(files.upstreamDirectory).catch(() => null);
        if (current.mutate) await current.mutate(files);
        const destination = current.destination ? current.destination(files) : files.destination;
        const result = current.swap
          ? run(["stage", files.provenancePath, files.crateDirectory, files.upstreamDirectory, destination])
          : stage(files, destination);
        assert.notEqual(result.status, 0, `${current.name} must fail closed`);
        assert.match(result.stderr, current.message);
        const remaining = await listDirectory(join(files.root, "out"));
        assert.deepEqual(remaining, ["unrelated-materials", ...(current.keeps ?? [])].sort(), "no output or staging directory remains");
        assert.equal(await readFile(join(sibling, "keep.txt"), "utf8"), "keep\n");
        if (current.keeps) assert.deepEqual(await listDirectory(files.destination), [], "a pre-existing destination is not touched");
        if (upstreamBefore && !current.mutate) {
          const upstreamAfter = await walk(files.upstreamDirectory);
          assert.deepEqual([...upstreamAfter.keys()], [...upstreamBefore.keys()], "input material is untouched");
        }
      } finally {
        await rm(files.root, { recursive: true, force: true });
      }
    });
  }
});

test("verification rejects deletion, substitution, extra files, a changed manifest, a truncated archive, output tampering and links", async (context) => {
  const cases = [
    { name: "staged file deleted", mutate: async (files) => rm(join(files.destination, "notices", "rust-external", "gamma-2.0.0-external-gamma-LICENSE")), message: /missing a listed file|ENOENT/u },
    { name: "staged archive deleted", mutate: async (files) => rm(join(files.destination, "upstream-source", "fixture-source-materials", "lib-1.0.tar.gz")), message: /missing expected entries/u },
    {
      name: "staged archive substituted at the same size",
      mutate: async (files) => {
        const path = join(files.destination, "rust-crates", "fixture-rust-materials", "delta-0.1.0.crate");
        const bytes = Buffer.from(await readFile(path));
        bytes[bytes.byteLength - 1] ^= 0x01;
        await writeFile(path, bytes);
      },
      message: /SHA-256 drifted: delta-0\.1\.0\.crate/u
    },
    {
      name: "staged archive truncated",
      mutate: async (files) => {
        const path = join(files.destination, "upstream-source", "fixture-source-materials", "lib-1.0.tar.gz");
        await writeFile(path, (await readFile(path)).subarray(0, 512));
      },
      message: /size or topology drifted: lib-1\.0\.tar\.gz/u
    },
    { name: "extra top-level file", entryBudget: true, extraDirectories: ["extra-empty"], mutate: async (files) => writeFile(join(files.destination, "README.md"), "extra\n"), message: /unlisted file: README\.md/u },
    { name: "extra nested file", extraDirectories: ["notices/extra-empty", "notices/rust-external/extra-empty"], mutate: async (files) => writeFile(join(files.destination, "notices", "rust-external", "stray-LICENSE"), "MIT\n"), message: /unlisted file: notices\/rust-external\/stray-LICENSE/u },
    {
      name: "external notice material substituted",
      mutate: async (files) => writeFile(join(files.destination, "notices", "rust-external", "gamma-2.0.0-external-gamma-LICENSE"), "MIT License\n\nCopyright (c) Somebody Else\n"),
      message: /file size drifted|file SHA-256 drifted/u
    },
    {
      name: "copied manifest substituted",
      mutate: async (files) => writeFile(join(files.destination, "manifests", "crate-manifest.json"), "{}\n"),
      message: /file size drifted|file SHA-256 drifted/u
    },
    {
      name: "tracked crate manifest changed after staging",
      mutate: async (files) => {
        files.crateManifest.unretained.push({ id: "later-note", detail: "Fixture: a later edit to the tracked manifest." });
        await files.saveCrateManifest();
      },
      message: /inventory does not describe this manifest/u
    },
    {
      name: "tracked provenance record changed after staging",
      mutate: async (files) => {
        files.provenance.purpose += " Edited after staging; not legal clearance.";
        await files.saveProvenance();
      },
      message: /delivery inventory does not describe this provenance record/u
    },
    {
      name: "delivery inventory edited",
      mutate: async (files) => {
        const path = join(files.destination, "DELIVERY_INVENTORY.json");
        const inventory = JSON.parse(await readFile(path, "utf8"));
        inventory.status.dylibIncorporation = "verified";
        await writeFile(path, `${JSON.stringify(inventory, null, 2)}\n`);
      },
      message: /delivery inventory drifted from the verified inputs/u
    },
    {
      name: "status record edited",
      mutate: async (files) => {
        const path = join(files.destination, "DELIVERY_STATUS.md");
        await writeFile(path, (await readFile(path, "utf8")).replace("**unverified**", "**verified**"));
      },
      message: /delivery status record drifted from the verified inputs/u
    },
    {
      name: "checksum list edited",
      mutate: async (files) => {
        const path = join(files.destination, "SHA256SUMS");
        await writeFile(path, `${await readFile(path, "utf8")}${"0".repeat(64)}  extra\n`);
      },
      message: /delivery checksum list drifted from the verified files/u
    },
    {
      name: "staged file replaced by a symbolic link",
      mutate: async (files) => {
        const path = join(files.destination, "notices", "ACKNOWLEDGEMENTS.md");
        const target = join(files.root, "ack-target.md");
        await writeFile(target, await readFile(path));
        await unlink(path);
        await symlink(target, path);
      },
      message: /carries a symbolic link: notices\/ACKNOWLEDGEMENTS\.md/u
    },
    {
      name: "nested material directory renamed",
      mutate: async (files) => rename(join(files.destination, "rust-crates", "fixture-rust-materials"), join(files.destination, "rust-crates", "other")),
      message: /ENOENT|not a real directory/u
    },
    {
      name: "inventory removed",
      mutate: async (files) => rm(join(files.destination, "DELIVERY_INVENTORY.json")),
      message: /missing its inventory, checksum list or status record/u
    }
  ];
  for (const current of cases) {
    await context.test(current.name, async () => {
      const files = await fixture();
      try {
        const staged = stage(files);
        assert.equal(staged.status, 0, staged.stderr);
        assert.equal(verify(files).status, 0);
        if (current.entryBudget) {
          const overflowDirectory = join(files.destination, "extra-empty-budget");
          await mkdir(overflowDirectory, { mode: 0o700 });
          // Exceed MAXIMUM_FILES * MAXIMUM_DEPTH using only empty directories.
          for (let index = 0; index < 4096; index += 1) {
            await mkdir(join(overflowDirectory, String(index)), { mode: 0o700 });
          }
          const overflowResult = verify(files);
          assert.notEqual(overflowResult.status, 0, "empty directories must count toward the traversal budget");
          assert.match(overflowResult.stderr, /carries more than 4096 filesystem entries/u);
          await rm(overflowDirectory, { recursive: true });
        }
        for (const relative of current.extraDirectories ?? []) {
          const extraDirectory = join(files.destination, ...relative.split("/"));
          await mkdir(extraDirectory, { mode: 0o700 });
          const extraResult = verify(files);
          assert.notEqual(extraResult.status, 0, `unlisted empty directory ${relative} must fail`);
          assert.ok(extraResult.stderr.includes(`delivery set carries an unlisted directory: ${relative}`), extraResult.stderr);
          await rm(extraDirectory, { recursive: true });
        }
        await current.mutate(files);
        const result = verify(files);
        assert.notEqual(result.status, 0, `${current.name} must fail`);
        assert.match(result.stderr, current.message);
      } finally {
        await rm(files.root, { recursive: true, force: true });
      }
    });
  }
});

test("malformed invocations are refused without touching the destination", async () => {
  const files = await fixture();
  try {
    for (const args of [
      [],
      ["stage", files.provenancePath, files.upstreamDirectory, files.crateDirectory],
      ["stage", files.provenancePath, files.upstreamDirectory, files.crateDirectory, files.destination, "extra"],
      ["verify", files.provenancePath],
      ["publish", files.provenancePath, files.destination],
      ["stage", files.provenancePath, files.upstreamDirectory, files.crateDirectory, "--force"]
    ]) {
      const result = run(args);
      assert.notEqual(result.status, 0, JSON.stringify(args));
      assert.match(result.stderr, /usage:/u, JSON.stringify(args));
    }
    assert.deepEqual(await listDirectory(join(files.root, "out")), []);
  } finally {
    await rm(files.root, { recursive: true, force: true });
  }
});
