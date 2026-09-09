// Fixture-only tests for scripts/stage-libvips-delivery-materials.mjs: the
// private delivery staging of verified corresponding-source archives, .crate
// archives, external notice material, manifests, accompanying documentation
// and the generated inventory, checksum list and status record, and for
// scripts/package-libvips-delivery-materials.mjs: the deterministic ustar
// archive, sidecar and binding built from such a set and their recipient-side
// verification. Every input is synthetic and acquired through the materials
// tool's local-fixture transport; no test contacts the network, extracts an
// upstream archive, or claims clearance. The only archives extracted are the
// small fixture delivery archives these tests build themselves.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, readdir, readFile, realpath, rename, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { spawn, spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { gzipSync } from "node:zlib";
import test from "node:test";
import { verify as verifyDeliverySetInProcess } from "../../scripts/stage-libvips-delivery-materials.mjs";

const project = process.cwd();
const stagingTool = join(project, "scripts", "stage-libvips-delivery-materials.mjs");
const materialsTool = join(project, "scripts", "prepare-libvips-source-materials.mjs");
const packagingTool = join(project, "scripts", "package-libvips-delivery-materials.mjs");
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

// ---------------------------------------------------------------------------
// scripts/package-libvips-delivery-materials.mjs

const TAR = "/usr/bin/tar";
const ROOT_NAME = "fixture-delivery-materials";
const ARCHIVE_NAME = `${ROOT_NAME}.tar`;
const SIDECAR_NAME = `${ARCHIVE_NAME}.sha256`;
const BINDING_NAME = `${ROOT_NAME}.binding.json`;
const PACKAGE_SOURCE_COMMIT = "5".repeat(40);
const OTHER_SOURCE_COMMIT = "7".repeat(40);
const ARCHIVE_MTIME = 946684800;

function expectedListing(paths) {
  const directories = new Set();
  for (const path of paths) {
    const segments = path.split("/");
    for (let depth = 1; depth < segments.length; depth += 1) directories.add(segments.slice(0, depth).join("/"));
  }
  const entries = [...[...directories].map((path) => ({ path, directory: true })), ...paths.map((path) => ({ path, directory: false }))]
    .sort((left, right) => (left.path < right.path ? -1 : left.path > right.path ? 1 : 0));
  return [`${ROOT_NAME}/`, ...entries.map((entry) => `${ROOT_NAME}/${entry.path}${entry.directory ? "/" : ""}`)];
}
const EXPECTED_LISTING = expectedListing(EXPECTED_FILES);

function runPackaging(args) {
  return spawnSync(process.execPath, [packagingTool, ...args], { cwd: project, encoding: "utf8", timeout: 120_000 });
}

function packageSet(files, output, { sourceCommit = PACKAGE_SOURCE_COMMIT, deliveryDirectory = files.destination } = {}) {
  return runPackaging(["package", files.provenancePath, deliveryDirectory, output, sourceCommit]);
}

function verifyArchive(files, { archive, binding, digest: expected, sourceCommit = PACKAGE_SOURCE_COMMIT, unpack }) {
  return runPackaging(["verify-archive", files.provenancePath, archive, binding, expected, sourceCommit, unpack]);
}

function listTar(path) {
  const result = spawnSync(TAR, ["-t", "-f", path], { encoding: "utf8", env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" } });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.split("\n").slice(0, -1);
}

async function packagedOutputs(directory) {
  assert.deepEqual((await readdir(directory)).sort(), [ARCHIVE_NAME, SIDECAR_NAME, BINDING_NAME].sort());
  const archive = await readFile(join(directory, ARCHIVE_NAME));
  const bindingText = await readFile(join(directory, BINDING_NAME), "utf8");
  return { archive, sidecar: await readFile(join(directory, SIDECAR_NAME), "utf8"), bindingText, binding: JSON.parse(bindingText), archivePath: join(directory, ARCHIVE_NAME), bindingPath: join(directory, BINDING_NAME) };
}

// Stages and packages one fixture set; returns the outputs and the walked tree.
async function stagedAndPackaged(files, output = join(files.root, "out", "pkg")) {
  const staged = stage(files);
  assert.equal(staged.status, 0, staged.stderr);
  const tree = await walk(files.destination);
  const packaged = packageSet(files, output);
  assert.equal(packaged.status, 0, packaged.stderr);
  return { tree, packaged, outputs: await packagedOutputs(output), output };
}

// A raw ustar member with an explicit type, link name and mode, for hostile
// archives. Modes default to the packager's own 0700/0600 so that each case
// exercises exactly one deviation.
function hostileEntry(name, bytes, type = "0", linkName = "", mode = type === "5" ? "0000700" : "0000600") {
  const entry = tarEntry(name, bytes, type);
  const header = entry.subarray(0, 512);
  header.write(`${mode}\0`, 100, "latin1");
  header.write(linkName, 157, 100, "latin1");
  header.write("        ", 148, "latin1");
  let sum = 0;
  for (const byte of header) sum += byte;
  header.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, "latin1");
  return entry;
}

// Rebuilds the fixture archive from the staged tree with one transformation of
// its member list, and writes it beside the fixture with a consistent binding.
async function hostileArchive(files, packaged, transform) {
  const entries = EXPECTED_LISTING.map((name) => (name.endsWith("/")
    ? { name, bytes: Buffer.alloc(0), type: "5" }
    : { name, bytes: packaged.tree.get(name.slice(ROOT_NAME.length + 1)), type: "0" }));
  const archive = Buffer.concat([...transform(entries).map((entry) => hostileEntry(entry.name, entry.bytes, entry.type, entry.linkName, entry.mode)), Buffer.alloc(1024, 0)]);
  const archivePath = join(files.root, "hostile.tar");
  await writeFile(archivePath, archive);
  const binding = JSON.parse(packaged.outputs.bindingText);
  binding.archive.sha256 = digest(archive);
  binding.archive.size = archive.byteLength;
  const bindingPath = join(files.root, "hostile.binding.json");
  await writeFile(bindingPath, `${JSON.stringify(binding, null, 2)}\n`);
  return { archive: archivePath, binding: bindingPath, digest: digest(archive) };
}

// The location-independent part of a packaged output set, for byte comparisons.
function comparable({ archive, sidecar, bindingText }) {
  return { archive, sidecar, bindingText };
}

async function editedBinding(files, outputs, edit) {
  const binding = JSON.parse(outputs.bindingText);
  edit(binding);
  const path = join(files.root, "edited.binding.json");
  await writeFile(path, `${JSON.stringify(binding, null, 2)}\n`);
  return path;
}

test("packaging turns a verified delivery set into one deterministic ustar archive, sidecar and binding that a recipient can verify and unpack exactly", async () => {
  const files = await fixture();
  try {
    const first = await stagedAndPackaged(files, join(files.root, "out", "pkg-1"));
    assert.match(first.packaged.stderr, /packaged 20 files \(\d+ bytes\) as .*\/pkg-1\/fixture-delivery-materials\.tar \(\d+ bytes, sha256:[a-f0-9]{64}, ustar, 28 members, mtime 946684800, bsdtar [^)]+\); binding fixture-delivery-materials\.binding\.json sha256:[a-f0-9]{64}; source commit 5{40}; upstream local-fixture \(NOT authoritative\), crates local-fixture \(NOT authoritative\); acquisition NOT authoritative; unresolved notices 1; not a source offer, not a release asset, not legal clearance/u);
    assert.deepEqual(await listDirectory(join(files.root, "out")), ["fixture-delivery-materials", "pkg-1"], "no staging directory remains");
    const { archive, sidecar, binding, bindingText } = first.outputs;
    // Sidecar: GNU coreutils shape over the archive bytes.
    assert.equal(sidecar, `${digest(archive)}  ${ARCHIVE_NAME}\n`);
    // Archive: exactly the planned members, in order, and nothing else.
    assert.deepEqual(listTar(first.outputs.archivePath), EXPECTED_LISTING);
    assert.equal(archive.byteLength % 512, 0, "whole-block ustar stream");
    assert.equal(archive.subarray(257, 262).toString("latin1"), "ustar");
    // Binding: exact source commit, cohort, tracked digests, delivery inventory and archive identity.
    assert.equal(binding.schemaVersion, 1);
    assert.equal(binding.bindingType, "fulmar-libvips-delivery-materials-archive-binding");
    assert.equal(binding.sourceCommit, PACKAGE_SOURCE_COMMIT);
    assert.equal(binding.component.id, "combined-binary");
    const { provenanceRecord: _provenanceRecord, ...validatedBinary } = files.crateManifest.binary;
    assert.deepEqual(binding.binary, validatedBinary, "the validated binary record, as the manifests carry it");
    assert.equal(binding.trackedBindings.provenanceRecord.sha256, digest(await readFile(files.provenancePath)));
    assert.equal(binding.trackedBindings.sourceMaterials.sha256, digest(await readFile(join(files.config, "source-manifest.json"))));
    assert.equal(binding.trackedBindings.rustCrateMaterials.sha256, digest(await readFile(join(files.config, "crate-manifest.json"))));
    assert.equal(binding.trackedBindings.rustNoticeMaterials.sha256, digest(await readFile(join(files.config, "notice-materials.json"))));
    assert.equal(binding.trackedBindings.accompanyingDocumentation.sha256, digest(Buffer.from(files.acknowledgements)));
    assert.deepEqual(binding.acquisition, {
      upstreamSource: { transport: "local-fixture", authoritative: false, itemCount: 3, totalBytes: files.sourceManifest.items.reduce((total, item) => total + item.size, 0) },
      rustCrates: { transport: "local-fixture", authoritative: false, itemCount: 3, totalBytes: files.crateManifest.items.reduce((total, item) => total + item.size, 0) }
    }, "fixture provenance is carried forward as NOT authoritative");
    assert.equal(binding.status.dylibIncorporation, "unverified");
    assert.equal(binding.deliverySet.rootDirectory, ROOT_NAME);
    assert.equal(binding.deliverySet.fileCount, 20);
    assert.deepEqual(binding.deliverySet.files, EXPECTED_FILES.map((path) => ({ path, size: first.tree.get(path).byteLength, sha256: digest(first.tree.get(path)) })));
    assert.equal(binding.deliverySet.totalBytes, EXPECTED_FILES.reduce((total, path) => total + first.tree.get(path).byteLength, 0));
    assert.equal(binding.deliverySet.inventory.sha256, digest(first.tree.get("DELIVERY_INVENTORY.json")));
    assert.equal(binding.deliverySet.statusRecord.sha256, digest(first.tree.get("DELIVERY_STATUS.md")));
    assert.equal(binding.deliverySet.checksumList.sha256, digest(first.tree.get("SHA256SUMS")));
    assert.deepEqual({ ...binding.archive, metadata: undefined }, { fileName: ARCHIVE_NAME, format: "ustar", compression: "none", size: archive.byteLength, sha256: digest(archive), memberCount: 28, directoryCount: 8, fileCount: 20, metadata: undefined, sidecar: { fileName: SIDECAR_NAME, format: "sha256sum" } });
    assert.deepEqual({ ...binding.archive.metadata, toolVersion: undefined, createOptions: undefined }, { uid: 0, gid: 0, uname: "", gname: "", mtimeEpochSeconds: ARCHIVE_MTIME, fileMode: "0600", directoryMode: "0700", tool: TAR, toolVersion: undefined, createOptions: undefined });
    assert.match(binding.archive.metadata.toolVersion, /^bsdtar /u);
    assert.match(binding.purpose, /not legal clearance/u);
    assert.doesNotMatch(bindingText, new RegExp(files.root.replaceAll(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"), "no private absolute path is recorded");
    assert.doesNotMatch(bindingText, /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/u, "no generation timestamp is recorded");
    assert.doesNotMatch(bindingText, /cleared|compliant|legally (?:sufficient|satisfied)/iu);
    // The stager's exported verifier returns the state the packager builds on.
    const inProcess = await verifyDeliverySetInProcess(files.provenancePath, files.destination);
    assert.equal(inProcess.expected.size, 20);
    assert.deepEqual([...inProcess.expected.keys()].sort(), EXPECTED_FILES);
    assert.equal(inProcess.inventory.inventoryType, "fulmar-libvips-delivery-materials");
    assert.equal(inProcess.inventorySHA256, digest(first.tree.get("DELIVERY_INVENTORY.json")));
    assert.equal(inProcess.statusSHA256, digest(first.tree.get("DELIVERY_STATUS.md")));
    assert.equal(inProcess.sumsSHA256, digest(first.tree.get("SHA256SUMS")));
    assert.equal(inProcess.inputs.crates.noticeMaterials.summary.unresolved.length, 1);
    // Inputs are preserved byte-for-byte and still verify.
    assert.deepEqual(await walk(files.destination), first.tree);
    assert.equal(verify(files).status, 0);
    // Determinism: an independent later staging (different input mtimes) packages to identical bytes.
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 1100));
    await mkdir(join(files.root, "second"), { mode: 0o700 });
    const secondSet = join(files.root, "second", ROOT_NAME);
    assert.equal(stage(files, secondSet).status, 0);
    const second = packageSet(files, join(files.root, "second", "pkg-2"), { deliveryDirectory: secondSet });
    assert.equal(second.status, 0, second.stderr);
    const secondOutputs = await packagedOutputs(join(files.root, "second", "pkg-2"));
    assert.deepEqual(secondOutputs.archive, archive, "archive bytes are identical across independent packagings");
    assert.equal(secondOutputs.sidecar, sidecar);
    assert.equal(secondOutputs.bindingText, bindingText);
    // Recipient verification with the externally supplied digest recovers the exact tree.
    const unpack = join(files.root, "out", "unpack-1");
    const verified = verifyArchive(files, { archive: first.outputs.archivePath, binding: first.outputs.bindingPath, digest: digest(archive), unpack });
    assert.equal(verified.status, 0, verified.stderr);
    assert.match(verified.stderr, /verified archive .*\/pkg-1\/fixture-delivery-materials\.tar \(\d+ bytes, sha256:[a-f0-9]{64}\) against source commit 5{40} and binding .*fixture-delivery-materials\.binding\.json \(sha256:[a-f0-9]{64}\); unpacked 20 files to .*\/unpack-1\/fixture-delivery-materials and re-verified them against the tracked manifests; upstream local-fixture \(NOT authoritative\), crates local-fixture \(NOT authoritative\); acquisition NOT authoritative; unresolved notices 1; dylib incorporation unverified; archive tool bsdtar [^;]+; not a legal conclusion/u);
    assert.deepEqual(await listDirectory(join(files.root, "out")), ["fixture-delivery-materials", "pkg-1", "unpack-1"], "no unpack staging remains");
    assert.deepEqual(await listDirectory(unpack), [ROOT_NAME]);
    assert.deepEqual(await walk(join(unpack, ROOT_NAME)), first.tree, "the unpacked tree equals the staged set byte-for-byte");
    assert.equal(verify(files, join(unpack, ROOT_NAME)).status, 0, "the stager verifier accepts the unpacked root");
  } finally {
    await rm(files.root, { recursive: true, force: true });
  }
});

test("packaging fails closed, publishes nothing and preserves the delivery set and existing outputs", async (context) => {
  const cases = [
    { name: "packaging output directory already exists", mutate: async (files) => mkdir(join(files.root, "out", "pkg"), { mode: 0o700 }), message: /output directory already exists/u, keeps: ["pkg"] },
    { name: "packaging output parent writable by other users", mutate: async (files) => chmod(join(files.root, "out"), 0o777), message: /writable by other users; a private destination is required/u },
    { name: "packaging output parent reached through a symbolic link", mutate: async (files) => symlink(join(files.root, "out"), join(files.root, "linked-out")), output: (files) => join(files.root, "linked-out", "pkg"), message: /must not traverse aliases or symbolic links|is not a real directory/u },
    { name: "packaging output inside the delivery set", output: (files) => join(files.destination, "pkg"), message: /output directory must not overlap the delivery directory/u },
    { name: "packaging with a malformed source commit", sourceCommit: "5f2e6a6", message: /source commit must be one full 40-hex commit/u },
    { name: "packaging a delivery set with the wrong name", mutate: async (files) => rename(files.destination, join(files.root, "out", "other-name")), deliveryDirectory: (files) => join(files.root, "out", "other-name"), message: /destination must be named fixture-delivery-materials/u, keeps: ["other-name"], renamed: true },
    {
      name: "packaging a delivery set with a substituted archive",
      mutate: async (files) => {
        const path = join(files.destination, "rust-crates", "fixture-rust-materials", "delta-0.1.0.crate");
        const bytes = Buffer.from(await readFile(path));
        bytes[bytes.byteLength - 1] ^= 0x01;
        await writeFile(path, bytes);
      },
      message: /SHA-256 drifted: delta-0\.1\.0\.crate/u
    },
    { name: "packaging a delivery set with a deleted file", mutate: async (files) => rm(join(files.destination, "notices", "rust-external", "gamma-2.0.0-external-gamma-LICENSE")), message: /missing a listed file|ENOENT/u },
    { name: "packaging a delivery set with an unlisted file", mutate: async (files) => writeFile(join(files.destination, "README.md"), "extra\n"), message: /unlisted file: README\.md/u },
    {
      name: "packaging a delivery set with a symbolic link",
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
      name: "packaging after the tracked crate manifest changed",
      mutate: async (files) => {
        files.crateManifest.unretained.push({ id: "later-note", detail: "Fixture: a later edit to the tracked manifest." });
        await files.saveCrateManifest();
      },
      message: /inventory does not describe this manifest/u
    },
    {
      name: "packaging a delivery set whose inventory was edited",
      mutate: async (files) => {
        const path = join(files.destination, "DELIVERY_INVENTORY.json");
        const inventory = JSON.parse(await readFile(path, "utf8"));
        inventory.status.dylibIncorporation = "verified";
        await writeFile(path, `${JSON.stringify(inventory, null, 2)}\n`);
      },
      message: /delivery inventory drifted from the verified inputs/u
    }
  ];
  for (const current of cases) {
    await context.test(current.name, async () => {
      const files = await fixture();
      try {
        assert.equal(stage(files).status, 0);
        const before = await walk(files.destination);
        const sibling = join(files.root, "out", "unrelated-output");
        await mkdir(sibling, { mode: 0o700 });
        await writeFile(join(sibling, "keep.txt"), "keep\n");
        if (current.mutate) await current.mutate(files);
        const output = current.output ? current.output(files) : join(files.root, "out", "pkg");
        const result = packageSet(files, output, { sourceCommit: current.sourceCommit, deliveryDirectory: current.deliveryDirectory?.(files) });
        assert.notEqual(result.status, 0, `${current.name} must fail closed`);
        assert.match(result.stderr, current.message);
        const remaining = await listDirectory(join(files.root, "out"));
        assert.deepEqual(remaining, [...(current.renamed ? [] : ["fixture-delivery-materials"]), "unrelated-output", ...(current.keeps ?? [])].sort(), "no output or staging directory remains");
        assert.equal(await readFile(join(sibling, "keep.txt"), "utf8"), "keep\n");
        if (current.keeps && !current.renamed) assert.deepEqual(await listDirectory(join(files.root, "out", "pkg")), [], "a pre-existing output directory is not touched");
        if (!current.mutate) assert.deepEqual(await walk(files.destination), before, "the delivery set is untouched");
      } finally {
        await rm(files.root, { recursive: true, force: true });
      }
    });
  }
  await context.test("malformed packaging invocations are refused", async () => {
    const files = await fixture();
    try {
      assert.equal(stage(files).status, 0);
      for (const args of [
        [],
        ["package", files.provenancePath, files.destination, join(files.root, "out", "pkg")],
        ["package", files.provenancePath, files.destination, join(files.root, "out", "pkg"), PACKAGE_SOURCE_COMMIT, "extra"],
        ["verify-archive", files.provenancePath, join(files.root, "x.tar"), join(files.root, "x.json"), "0".repeat(64), PACKAGE_SOURCE_COMMIT],
        ["pack", files.provenancePath, files.destination, join(files.root, "out", "pkg"), PACKAGE_SOURCE_COMMIT],
        ["package", files.provenancePath, files.destination, join(files.root, "out", "pkg"), "--source-commit"]
      ]) {
        const result = runPackaging(args);
        assert.notEqual(result.status, 0, JSON.stringify(args));
        assert.match(result.stderr, /usage:/u, JSON.stringify(args));
      }
      assert.deepEqual(await listDirectory(join(files.root, "out")), ["fixture-delivery-materials"]);
    } finally {
      await rm(files.root, { recursive: true, force: true });
    }
  });
});

test("archive verification rejects a wrong digest, altered or truncated bytes, a mismatched binding, a wrong cohort, unsafe or extra members and an unsafe unpack destination without leaving an unpacked tree", async (context) => {
  const cases = [
    { name: "wrong expected digest", arrange: async () => ({ digest: "0".repeat(64) }), message: /archive SHA-256 is [a-f0-9]{64}, not the expected 0{64}; nothing was extracted/u },
    {
      name: "truncated archive with the original binding",
      arrange: async (files, packaged) => {
        const truncated = packaged.outputs.archive.subarray(0, 10240);
        const archive = join(files.root, "truncated.tar");
        await writeFile(archive, truncated);
        return { archive, digest: digest(truncated) };
      },
      message: /binding archive digest differs from the externally supplied expected digest/u
    },
    {
      name: "truncated archive with a consistent binding",
      arrange: async (files, packaged) => {
        const truncated = packaged.outputs.archive.subarray(0, 10240);
        const archive = join(files.root, "truncated.tar");
        await writeFile(archive, truncated);
        const binding = await editedBinding(files, packaged.outputs, (value) => { value.archive.sha256 = digest(truncated); value.archive.size = truncated.byteLength; });
        return { archive, binding, digest: digest(truncated) };
      },
      message: /archive listing: \/usr\/bin\/tar failed|archive listing does not equal the bound member set/u
    },
    {
      name: "archive member payload altered with a consistent binding",
      arrange: async (files, packaged) => {
        const altered = Buffer.from(packaged.outputs.archive);
        // Flip one byte inside the opaque upstream archive payload (lib-1.0.tar.gz), leaving every header intact.
        const payload = altered.indexOf("fixture archive ");
        assert.ok(payload > 0);
        altered[payload + 20] ^= 0x01;
        const archive = join(files.root, "altered.tar");
        await writeFile(archive, altered);
        const binding = await editedBinding(files, packaged.outputs, (value) => { value.archive.sha256 = digest(altered); });
        return { archive, binding, digest: digest(altered) };
      },
      message: /SHA-256 drifted: lib-1\.0\.tar\.gz/u
    },
    { name: "wrong source commit for the trusted checkout", arrange: async () => ({ sourceCommit: OTHER_SOURCE_COMMIT }), message: /binding names source commit 5{40}, not the trusted checkout's 7{40}/u },
    { name: "binding delivery file digest edited", arrange: async (files, packaged) => ({ binding: await editedBinding(files, packaged.outputs, (value) => { value.deliverySet.files[0].sha256 = "1".repeat(64); }) }), message: /binding deliverySet does not equal the verified delivery inventory/u },
    { name: "binding tracked manifest digest edited", arrange: async (files, packaged) => ({ binding: await editedBinding(files, packaged.outputs, (value) => { value.trackedBindings.rustNoticeMaterials.sha256 = "2".repeat(64); }) }), message: /binding trackedBindings rustNoticeMaterials digest does not match the trusted checkout/u },
    { name: "binding binary cohort edited", arrange: async (files, packaged) => ({ binding: await editedBinding(files, packaged.outputs, (value) => { value.binary.version = "1.0.1"; }) }), message: /binding binary cohort does not match the trusted crate manifest/u },
    { name: "binding component edited", arrange: async (files, packaged) => ({ binding: await editedBinding(files, packaged.outputs, (value) => { value.component.openObligations = []; }) }), message: /binding component does not match the trusted provenance record/u },
    { name: "binding metadata relabelled", arrange: async (files, packaged) => ({ binding: await editedBinding(files, packaged.outputs, (value) => { value.archive.metadata.uid = 501; }) }), message: /binding archive metadata does not describe the deterministic ustar contract/u },
    { name: "binding not JSON", arrange: async (files) => { const binding = join(files.root, "broken.binding.json"); await writeFile(binding, "{\n"); return { binding }; }, message: /binding is not valid JSON/u },
    {
      name: "tracked crate manifest changed after packaging",
      arrange: async (files) => {
        files.crateManifest.unretained.push({ id: "later-note", detail: "Fixture: a later edit to the tracked manifest." });
        await files.saveCrateManifest();
        return {};
      },
      message: /binding trackedBindings rustCrateMaterials digest does not match the trusted checkout/u
    },
    {
      name: "archive with an extra member",
      arrange: async (files, packaged) => hostileArchive(files, packaged, (entries) => [...entries, { name: `${ROOT_NAME}/EXTRA`, bytes: Buffer.from("extra\n"), type: "0" }]),
      message: /archive listing does not equal the bound member set; unexpected: "fixture-delivery-materials\/EXTRA"/u
    },
    {
      name: "archive with a member escaping the root",
      arrange: async (files, packaged) => hostileArchive(files, packaged, (entries) => [...entries, { name: "../escape", bytes: Buffer.from("escape\n"), type: "0" }]),
      message: /archive carries an unsafe member name/u
    },
    {
      name: "archive with a listed file replaced by a symbolic link",
      arrange: async (files, packaged) => hostileArchive(files, packaged, (entries) => entries.map((entry) => (entry.name === `${ROOT_NAME}/notices/ACKNOWLEDGEMENTS.md` ? { name: entry.name, bytes: Buffer.alloc(0), type: "2", linkName: "/etc/hosts" } : entry))),
      message: /unpacked archive carries a symbolic link: fixture-delivery-materials\/notices\/ACKNOWLEDGEMENTS\.md/u
    },
    {
      name: "archive with a listed file replaced by a hard link",
      arrange: async (files, packaged) => hostileArchive(files, packaged, (entries) => entries.map((entry) => (entry.name === `${ROOT_NAME}/notices/ACKNOWLEDGEMENTS.md` ? { name: entry.name, bytes: Buffer.alloc(0), type: "1", linkName: `${ROOT_NAME}/DELIVERY_STATUS.md` } : entry))),
      message: /hard-linked file|not one bounded, unlinked regular file|drifted/u
    },
    {
      name: "archive with a directory member stored without traversal rights",
      arrange: async (files, packaged) => hostileArchive(files, packaged, (entries) => entries.map((entry) => (entry.name === `${ROOT_NAME}/notices/` ? { ...entry, mode: "0000600" } : entry))),
      message: /unpacked archive directory mode is not 0700: fixture-delivery-materials\/notices/u
    },
    {
      name: "archive with a file member stored with permissive mode",
      arrange: async (files, packaged) => hostileArchive(files, packaged, (entries) => entries.map((entry) => (entry.name === `${ROOT_NAME}/DELIVERY_STATUS.md` ? { ...entry, mode: "0000755" } : entry))),
      message: /unpacked archive file mode is not 0600: fixture-delivery-materials\/DELIVERY_STATUS\.md/u
    },
    { name: "unpack directory already exists", arrange: async (files) => { await mkdir(join(files.root, "out", "unpack"), { mode: 0o700 }); return {}; }, message: /unpack directory already exists/u, keepsUnpack: true },
    { name: "unpack directory parent writable by other users", arrange: async (files) => { await mkdir(join(files.root, "loose"), { mode: 0o777 }); await chmod(join(files.root, "loose"), 0o777); return { unpack: join(files.root, "loose", "unpack") }; }, message: /writable by other users; a private destination is required/u }
  ];
  for (const current of cases) {
    await context.test(current.name, async () => {
      const files = await fixture();
      try {
        const packaged = await stagedAndPackaged(files);
        const override = await current.arrange(files, packaged);
        const unpack = override.unpack ?? join(files.root, "out", "unpack");
        const result = verifyArchive(files, {
          archive: override.archive ?? packaged.outputs.archivePath,
          binding: override.binding ?? packaged.outputs.bindingPath,
          digest: override.digest ?? digest(packaged.outputs.archive),
          sourceCommit: override.sourceCommit,
          unpack
        });
        assert.notEqual(result.status, 0, `${current.name} must fail`);
        assert.match(result.stderr, current.message);
        const remaining = await listDirectory(join(files.root, "out"));
        assert.deepEqual(remaining, ["fixture-delivery-materials", "pkg", ...(current.keepsUnpack ? ["unpack"] : [])], "no unpacked tree or unpack staging remains");
        if (current.keepsUnpack) assert.deepEqual(await listDirectory(unpack), [], "a pre-existing unpack directory is not touched");
        // The packaged outputs themselves are never modified by verification.
        assert.deepEqual(await packagedOutputs(packaged.output), packaged.outputs);
      } finally {
        await rm(files.root, { recursive: true, force: true });
      }
    });
  }
});

test("an interrupted packaging publishes nothing partial, leaves the delivery set intact and a later packaging succeeds byte-for-byte", async (context) => {
  const files = await fixture();
  try {
    assert.equal(stage(files).status, 0);
    const before = await walk(files.destination);
    const reference = join(files.root, "out", "pkg-reference");
    assert.equal(packageSet(files, reference).status, 0);
    const referenceOutputs = await packagedOutputs(reference);
    const output = join(files.root, "out", "pkg-interrupted");
    const child = spawn(process.execPath, [packagingTool, "package", files.provenancePath, files.destination, output, PACKAGE_SOURCE_COMMIT], { cwd: project, stdio: "ignore" });
    const exited = new Promise((resolveExit) => child.on("exit", (code, signal) => resolveExit({ code, signal })));
    let interrupted = false;
    for (let attempt = 0; attempt < 60_000 && child.exitCode === null && child.signalCode === null; attempt += 1) {
      const entries = await listDirectory(join(files.root, "out"));
      if (entries.some((name) => name.startsWith(".pkg-interrupted.staging."))) {
        child.kill("SIGKILL");
        interrupted = true;
        break;
      }
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 1));
    }
    const outcome = await exited;
    const remaining = await listDirectory(join(files.root, "out"));
    const leftovers = remaining.filter((name) => name.startsWith(".pkg-interrupted.staging."));
    context.diagnostic(`packaging ${interrupted && outcome.signal === "SIGKILL" ? "was interrupted by SIGKILL inside its staging window" : `completed before interruption (${JSON.stringify(outcome)})`}; output ${remaining.includes("pkg-interrupted") ? "published" : "absent"}; staging leftovers ${leftovers.length}`);
    assert.ok(leftovers.length <= 1, "at most this invocation's own identifiable staging directory may remain");
    if (remaining.includes("pkg-interrupted")) {
      // Published before or despite the interruption: the output is complete, never partial.
      assert.deepEqual(comparable(await packagedOutputs(output)), comparable(referenceOutputs));
    } else {
      assert.ok(interrupted && outcome.signal === "SIGKILL", `the packaging neither published nor was interrupted: ${JSON.stringify(outcome)}`);
      assert.deepEqual(remaining.filter((name) => !name.startsWith(".")), ["fixture-delivery-materials", "pkg-reference"], "no partial output directory exists");
    }
    for (const leftover of leftovers) await rm(join(files.root, "out", leftover), { recursive: true, force: true });
    assert.deepEqual(await walk(files.destination), before, "the delivery set is untouched");
    assert.equal(verify(files).status, 0);
    const after = join(files.root, "out", "pkg-after");
    const rerun = packageSet(files, after);
    assert.equal(rerun.status, 0, rerun.stderr);
    assert.deepEqual(comparable(await packagedOutputs(after)), comparable(referenceOutputs), "a later packaging reproduces the reference bytes");
  } finally {
    await rm(files.root, { recursive: true, force: true });
  }
});
