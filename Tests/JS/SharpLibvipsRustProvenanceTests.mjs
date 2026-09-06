// Fixture-only tests for Config/SharpLibvipsRustProvenance.json and the
// rust-crate handling of scripts/prepare-libvips-source-materials.mjs. They read
// tracked repository files and private temporary fixture roots only; no test
// contacts crates.io, GitHub or npm. Nothing here proves what the historical
// build compiled: the manifest must keep saying so, and these tests enforce it.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readdir, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { gzipSync } from "node:zlib";
import test from "node:test";

const project = process.cwd();
const tool = join(project, "scripts", "prepare-libvips-source-materials.mjs");
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const SHA256 = /^[a-f0-9]{64}$/u;
const readJSON = async (relative) => JSON.parse(await readFile(join(project, relative), "utf8"));

test("rust provenance manifest is an explicitly partial, digest-pinned approximation bound to the shipped tarball", async () => {
  const manifest = await readJSON("Config/SharpLibvipsRustProvenance.json");
  const sourceMaterials = await readJSON("Config/SharpLibvipsSourceMaterials.json");
  const provenance = (await readJSON("Config/ThirdPartyBinaryProvenance.json")).components[0];
  assert.equal(manifest.schemaVersion, 1);
  assert.match(manifest.purpose, /not legal clearance/u);
  assert.match(manifest.purpose, /approximation/u);
  assert.doesNotMatch(manifest.purpose, /cleared|satisfied|compliant|complete corresponding source/iu);
  assert.deepEqual(manifest.binary, sourceMaterials.binary, "same binary record as the source materials manifest");
  assert.equal(manifest.outputDirectoryName, "sharp-libvips-1.3.2-rust-crate-materials");

  // Historical-build evidence: the npm attestation subject must be the exact tarball the lockfile pins.
  const lock = await readJSON(provenance.lockfile);
  const integrity = lock.packages[provenance.lockfilePath].integrity;
  assert.ok(integrity.startsWith("sha512-"));
  const lockSHA512 = Buffer.from(integrity.slice("sha512-".length), "base64").toString("hex");
  const attestation = manifest.historicalBuildEvidence.npmProvenanceAttestation;
  assert.equal(attestation.subjectSHA512, lockSHA512, "attested subject is the pinned tarball");
  assert.equal(attestation.subjectEqualsLockfileIntegrity, true);
  assert.equal(attestation.sourceCommit, provenance.upstream.buildCommit);
  assert.equal(attestation.workflowRef, `refs/tags/${provenance.upstream.buildTag}`);
  assert.match(attestation.invocationId, /^https:\/\/github\.com\/lovell\/sharp-libvips\/actions\/runs\/\d+\/attempts\/1$/u);
  const job = manifest.historicalBuildEvidence.workflowJob;
  assert.ok(attestation.invocationId.includes(`/runs/${job.runId}/`), "job belongs to the attested run");
  assert.equal(job.name, "build-darwin-arm64v8");
  assert.match(job.logStatus, /^retrieved-and-retained/u, "the compile log was retrieved and retained, and the manifest says so");
  const log = manifest.historicalBuildEvidence.jobLog;
  assert.equal(log.rawSHA256, "b7b3362b69a9dacebb3588502529cfa8f6b130854040213b928ad1011010158b", "raw log digest as recorded by the sealed review evidence");
  assert.equal(log.rawBytes, 944166);
  assert.equal(log.lines, 10027);
  assert.match(log.endpoint, /jobs\/84249528353\/logs$/u);
  assert.match(log.retention, /74c16427f8f9a5fd56b90855142b4f79c28ca9352fa31ecbdb9270603c9a1fb4/u, "the sealed evidence manifest digest is recorded");
  assert.doesNotMatch(JSON.stringify(log), /\/Users\//u, "no local private path is committed");
  const toolchain = manifest.historicalBuildEvidence.toolchainObserved;
  assert.equal(toolchain.rustc, "1.98.0-nightly (096694416 2026-06-29)");
  assert.match(toolchain.cargoC, /^0\.10\.23\+cargo-0\.97\.1/u);
  assert.match(toolchain.rustcRevisionNote, /not expanded into a full commit/u);
  assert.match(toolchain.note, /none is a compiler or tool binary digest/u);
  const lockfile = manifest.historicalBuildEvidence.lockfile;
  const rsvg = sourceMaterials.items.find(({ id }) => id === "source-librsvg");
  assert.equal(lockfile.archiveSHA256, rsvg.sha256, "Cargo.lock evidence comes from the pinned librsvg archive");
  assert.equal(lockfile.archiveFileName, rsvg.fileName);
  assert.match(lockfile.sha256, SHA256);
  assert.equal(lockfile.vendoredCrates, false);
  assert.match(manifest.historicalBuildEvidence.cargoInvocation.command, /cargo cbuild --locked .* -p librsvg-c/u);
  assert.deepEqual(manifest.historicalBuildEvidence.cargoInvocation.features, []);
  assert.deepEqual(manifest.historicalBuildEvidence.recipeEdits.map(({ recipeLine }) => recipeLine), [335, 337, 341]);

  // Categories must be distinguished and the unprovable ones must stay unverified.
  const categories = manifest.categories;
  assert.equal(categories.lockfileListed.count, lockfile.packageCount);
  assert.equal(categories.lockfileListed.status, "exact");
  assert.equal(categories.reachableFromBuiltMember.status, "exact-superset");
  assert.ok(categories.reachableFromBuiltMember.count <= categories.lockfileListed.count);
  assert.equal(categories.resolvedForTargetApproximation.status, "approximation");
  assert.equal(categories.resolvedForTargetApproximation.registryCrates, manifest.items.length);
  assert.equal(categories.resolvedForTargetApproximation.count, manifest.items.length + categories.resolvedForTargetApproximation.workspaceMembers.length);
  assert.ok(categories.resolvedForTargetApproximation.count <= categories.reachableFromBuiltMember.count);
  assert.equal(categories.compiledInHistoricalBuild.status, "observed", "compilation is observed from the retained log, which is distinct from verified incorporation");
  assert.equal(categories.compiledInHistoricalBuild.registryCrates, 157);
  assert.equal(categories.compiledInHistoricalBuild.count, 159);
  assert.equal(categories.incorporatedIntoShippedBinary.status, "unverified", "the log is not a linkage map");
  assert.match(categories.incorporatedIntoShippedBinary.detail, /not a linkage map/u);
  assert.match(categories.resolvedForTargetApproximation.workspaceMembers[1], /^librsvg 2\.63\.0-beta\.0 /u, "workspace package version corrected from the retained rsvg/Cargo.toml and the observed compile line");
  assert.match(categories.resolvedForTargetApproximation.workspaceMembers[0], /^librsvg-c 2\.62\.90 /u);
  const observed = manifest.historicalBuildEvidence.observedCompilation;
  assert.equal(observed.registryCrateCount, 157);
  assert.deepEqual(observed.workspaceCrates.map(({ name, version }) => `${name} ${version}`), ["librsvg 2.63.0-beta.0", "librsvg-c 2.62.90"]);
  assert.deepEqual(observed.approximationNotObserved.map(({ name, version }) => `${name} ${version}`), ["rustc_version 0.4.1", "semver 1.0.28"]);
  assert.deepEqual(observed.observedNotInApproximation, []);
  assert.equal(observed.cargoInvocationLogLine, 8985);
  assert.deepEqual(observed.workspaceUpdateObserved.removed, ["color_quant 1.1.0", "gif 0.14.2", "image-webp 0.2.4"]);
  assert.match(observed.statement, /not a linkage map/u);
  const roles = {};
  for (const item of manifest.items) roles[item.role] = (roles[item.role] ?? 0) + 1;
  assert.deepEqual(roles, categories.resolvedForTargetApproximation.roles);

  // Items.
  const identities = new Set();
  const summary = {};
  let compiledCount = 0;
  const approximatedOnly = [];
  for (const item of manifest.items) {
    assert.equal(item.kind, "rust-crate", item.id);
    assert.equal(item.id, `crate-${item.crateName}-${item.crateVersion}`.toLowerCase().replaceAll("+", "-"));
    const identity = `${item.crateName} ${item.crateVersion}`;
    assert.ok(!identities.has(identity), `${identity} is named once`);
    identities.add(identity);
    assert.equal(item.fileName, `${item.crateName}-${item.crateVersion}.crate`);
    assert.equal(item.url, `https://static.crates.io/crates/${item.crateName}/${item.crateName}-${item.crateVersion}.crate`);
    assert.deepEqual(item.allowedRedirectHosts, []);
    assert.equal(item.registry, "https://github.com/rust-lang/crates.io-index");
    assert.match(item.sha256, SHA256, item.id);
    assert.ok(Number.isSafeInteger(item.size) && item.size > 0 && item.size <= manifest.limits.maximumFileBytes, item.id);
    if (item.provenanceStatus === "compiled-per-build-log") {
      assert.ok(Number.isSafeInteger(item.observedCompilation.logLine) && item.observedCompilation.logLine >= 8721 && item.observedCompilation.logLine <= 8985,
        `${item.id} observed inside the librsvg phase of the retained log`);
      assert.match(item.observedCompilation.timestamp, /^2026-06-30T09:1[45]:/u, item.id);
      compiledCount += 1;
    } else {
      assert.equal(item.provenanceStatus, "resolved-approximation", item.id);
      assert.equal(item.observedCompilation, null, `${item.id} carries no observation record`);
      approximatedOnly.push(`${item.crateName} ${item.crateVersion}`);
    }
    assert.ok(["normal", "proc-macro", "build-only"].includes(item.role), item.id);
    assert.equal(item.noticeStatus, item.noticeMembers.length === 0 ? "no-licence-text-in-crate" : "crate-carries-licence-text", item.id);
    for (const member of item.noticeMembers) {
      assert.ok(member.member.startsWith(`${item.crateName}-${item.crateVersion}/`), item.id);
      assert.match(member.sha256, SHA256, item.id);
    }
    summary[item.licenseExpression] = (summary[item.licenseExpression] ?? 0) + 1;
  }
  assert.deepEqual(manifest.licenseExpressionSummary, summary);
  assert.equal(compiledCount, 157, "157 registry crates were observed compiling");
  assert.deepEqual(approximatedOnly.sort(), ["rustc_version 0.4.1", "semver 1.0.28"], "exactly the two unobserved crates stay approximation-only and are retained");
  assert.ok(manifest.items.some(({ noticeStatus }) => noticeStatus === "no-licence-text-in-crate"), "the known gap of crates without licence text is recorded, not hidden");
  const unretained = manifest.unretained.map(({ id }) => id);
  for (const required of ["compile-log-coverage", "resolver-approximation", "binary-incorporation", "crates-without-licence-text", "workspace-members", "mpl-and-unicode-terms"]) {
    assert.ok(unretained.includes(required), required);
  }
  assert.ok(!unretained.includes("historical-compile-log"), "the stale log-access blocker is retired");
  assert.ok(manifest.items.some(({ licenseExpression }) => licenseExpression === "MPL-2.0"), "MPL crates are present and therefore flagged");
  // The 29-component notices are untouched by this manifest.
  assert.equal(provenance.componentNotices.length, 29);
  assert.equal(provenance.obligations.find(({ id }) => id === "corresponding-source").status, "open");
});

// ---------------------------------------------------------------------------
// Synthetic .crate fixtures: a minimal ustar writer so no test needs a real crate.

function tarEntry(name, bytes, type = "0", linkName = "") {
  const header = Buffer.alloc(512, 0);
  header.write(name, 0, 100, "latin1");
  header.write("0000644\0", 100, "latin1");
  header.write("0000000\0", 108, "latin1");
  header.write("0000000\0", 116, "latin1");
  header.write(`${bytes.byteLength.toString(8).padStart(11, "0")}\0`, 124, "latin1");
  header.write("00000000000\0", 136, "latin1");
  header.write("        ", 148, "latin1");
  header.write(type, 156, "latin1");
  header.write(linkName, 157, 100, "latin1");
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
  return gzipSync(Buffer.concat([...entries.map(([name, bytes, type, link]) => tarEntry(name, bytes, type, link)), Buffer.alloc(1024, 0)]));
}

async function fixture(options = {}) {
  const root = await realpath(await mkdtemp(join(tmpdir(), "fulmar-rust-provenance-test.")));
  const upstream = join(root, "upstream");
  const out = join(root, "out");
  await mkdir(out, { mode: 0o700 });
  const alphaLicense = Buffer.from("MIT License\n\nCopyright (c) Alpha Crate Authors\n");
  const alphaApache = Buffer.from("Apache License\nVersion 2.0\n\nCopyright (c) Alpha Crate Authors\n");
  const alphaEntries = options.alphaEntries ?? [
    ["alpha-1.2.3/", Buffer.alloc(0), "5"],
    ["alpha-1.2.3/Cargo.toml", Buffer.from("[package]\nname = \"alpha\"\nversion = \"1.2.3\"\nlicense = \"MIT OR Apache-2.0\"\n")],
    ["alpha-1.2.3/LICENSE-MIT", alphaLicense],
    ["alpha-1.2.3/LICENSE-APACHE", alphaApache],
    ["alpha-1.2.3/src/lib.rs", Buffer.from("pub fn alpha() {}\n")]
  ];
  const alpha = crateArchive(alphaEntries);
  const betaEntries = options.betaEntries ?? [
    ["beta-0.9.0/Cargo.toml", Buffer.from("[package]\nname = \"beta\"\nversion = \"0.9.0\"\nlicense = \"MPL-2.0\"\n")],
    ["beta-0.9.0/src/lib.rs", Buffer.from("pub fn beta() {}\n")]
  ];
  const beta = crateArchive(betaEntries);
  const put = async (url, bytes) => {
    const parsed = new URL(url);
    const path = join(upstream, parsed.hostname, ...parsed.pathname.split("/").filter(Boolean));
    await mkdir(join(path, ".."), { recursive: true, mode: 0o700 });
    await writeFile(path, bytes);
  };
  await put("https://static.crates.io/crates/alpha/alpha-1.2.3.crate", alpha);
  await put("https://static.crates.io/crates/beta/beta-0.9.0.crate", beta);
  const manifest = {
    schemaVersion: 1,
    purpose: "Fixture rust-crate manifest: an approximation for hermetic tests; not legal clearance and not a corresponding-source offer.",
    binary: {
      packageName: "@fixture/binary", version: "1.0.0", buildRepository: "https://example.test/build", buildTag: "v1.0.0",
      buildCommit: "0".repeat(40), buildPlatform: "darwin-arm64v8", shippedBinary: "node_modules/@fixture/binary/lib/lib.dylib",
      shippedBinarySHA256: "1".repeat(64), provenanceRecord: "Config/Fixture.json"
    },
    outputDirectoryName: "fixture-rust-materials",
    limits: { maximumFileBytes: 1048576, maximumTotalBytes: 8388608, maximumRedirects: 0, requestTimeoutMilliseconds: 5000 },
    categories: {
      compiledInHistoricalBuild: { status: "unverified", detail: "fixture" },
      incorporatedIntoShippedBinary: { status: "unverified", detail: "fixture" }
    },
    items: [
      {
        id: "crate-alpha-1.2.3", kind: "rust-crate", crateName: "alpha", crateVersion: "1.2.3", fileName: "alpha-1.2.3.crate",
        url: "https://static.crates.io/crates/alpha/alpha-1.2.3.crate", size: alpha.byteLength, sha256: digest(alpha), allowedRedirectHosts: [],
        immutability: "crates-io-immutable-crate-file", registry: "https://github.com/rust-lang/crates.io-index",
        checksumSource: "fixture Cargo.lock checksum recorded for the test", role: "normal", licenseExpression: "MIT OR Apache-2.0",
        provenanceStatus: "resolved-approximation", authors: ["Alpha Author <alpha@example.test>"],
        noticeMembers: [
          { member: "alpha-1.2.3/LICENSE-APACHE", size: alphaApache.byteLength, sha256: digest(alphaApache) },
          { member: "alpha-1.2.3/LICENSE-MIT", size: alphaLicense.byteLength, sha256: digest(alphaLicense) }
        ],
        noticeStatus: "crate-carries-licence-text"
      },
      {
        id: "crate-beta-0.9.0", kind: "rust-crate", crateName: "beta", crateVersion: "0.9.0", fileName: "beta-0.9.0.crate",
        url: "https://static.crates.io/crates/beta/beta-0.9.0.crate", size: beta.byteLength, sha256: digest(beta), allowedRedirectHosts: [],
        immutability: "crates-io-immutable-crate-file", registry: "https://github.com/rust-lang/crates.io-index",
        checksumSource: "fixture Cargo.lock checksum recorded for the test", role: "proc-macro", licenseExpression: "MPL-2.0",
        provenanceStatus: "resolved-approximation", noticeMembers: [], noticeStatus: "no-licence-text-in-crate"
      }
    ],
    unretained: [{ id: "historical-compile-log", detail: "Fixture: the historical compile log was not retrieved." }]
  };
  const manifestPath = join(root, "manifest.json");
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  return { root, upstream, out, manifest, manifestPath, alpha, alphaLicense, alphaApache, destination: join(out, "fixture-rust-materials") };
}

async function writeManifest(files) {
  await writeFile(files.manifestPath, `${JSON.stringify(files.manifest, null, 2)}\n`);
}

function run(args) {
  return spawnSync(process.execPath, [tool, ...args], { cwd: project, encoding: "utf8", timeout: 30_000 });
}

// Turns the fixture manifest into an observed-compilation manifest: alpha was
// observed compiling at a log line, beta stays a resolved approximation.
function observedFixture(files) {
  files.manifest.categories.compiledInHistoricalBuild = { status: "observed", detail: "fixture: alpha observed in a retained log" };
  files.manifest.historicalBuildEvidence = {
    jobLog: { rawSHA256: "b".repeat(64), rawBytes: 4096, lines: 100 },
    observedCompilation: {
      registryCrateCount: 1,
      approximationNotObserved: [{ name: "beta", version: "0.9.0" }],
      observedNotInApproximation: []
    }
  };
  files.manifest.items[0].provenanceStatus = "compiled-per-build-log";
  files.manifest.items[0].observedCompilation = { logLine: 42, timestamp: "2026-06-30T09:14:26.3311710Z" };
  files.manifest.items[1].observedCompilation = null;
}

function acquire(files, destination = files.destination) {
  return run(["acquire", files.manifestPath, destination, "--transport", `local-fixture:${files.upstream}`]);
}

async function listDirectory(path) {
  try {
    return (await readdir(path)).sort();
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

test("rust crates are acquired opaque, their notice members verified and rendered deterministically, and the output stays labelled partial", async () => {
  const files = await fixture();
  try {
    const first = acquire(files);
    assert.equal(first.status, 0, first.stderr);
    assert.deepEqual(await listDirectory(files.destination), ["INVENTORY.json", "RUST_CRATE_NOTICES.md", "SHA256SUMS", "alpha-1.2.3.crate", "beta-0.9.0.crate"]);
    assert.deepEqual(await readFile(join(files.destination, "alpha-1.2.3.crate")), files.alpha, "crate archives are stored byte-for-byte");
    const notices = await readFile(join(files.destination, "RUST_CRATE_NOTICES.md"), "utf8");
    assert.match(notices, /compiledInHistoricalBuild=unverified, incorporatedIntoShippedBinary=unverified/u);
    assert.match(notices, /\| `alpha` \| `1\.2\.3` \| normal \| MIT OR Apache-2\.0 \| resolved-approximation \| `LICENSE-APACHE`<br>`LICENSE-MIT` \|/u);
    assert.match(notices, /\| `beta` \| `0\.9\.0` \| proc-macro \| MPL-2\.0 \| resolved-approximation \| none in crate \|/u);
    assert.match(notices, /## Crates whose archive carries no licence text\n\n[^\n]*\n\n- `beta` 0\.9\.0: MPL-2\.0/u);
    assert.match(notices, /Copyright \(c\) Alpha Crate Authors/u);
    assert.match(notices, /authors: Alpha Author <alpha@example\.test>/u);
    assert.match(notices, /not a corresponding-source offer and not legal clearance/u);
    assert.doesNotMatch(notices, /compiled-per-build-log|=verified\b/u);
    const inventory = JSON.parse(await readFile(join(files.destination, "INVENTORY.json"), "utf8"));
    assert.deepEqual(inventory.historicalBuildProvenance, { compiledInHistoricalBuild: "unverified", incorporatedIntoShippedBinary: "unverified" });
    assert.equal(inventory.rustNoticesSHA256, digest(notices));
    assert.equal(inventory.authoritative, false);
    const sums = await readFile(join(files.destination, "SHA256SUMS"), "utf8");
    assert.ok(sums.includes(`${digest(notices)}  RUST_CRATE_NOTICES.md\n`));
    const verified = run(["verify", files.manifestPath, files.destination]);
    assert.equal(verified.status, 0, verified.stderr);

    await mkdir(join(files.root, "second"), { mode: 0o700 });
    const second = acquire(files, join(files.root, "second", "fixture-rust-materials"));
    assert.equal(second.status, 0, second.stderr);
    assert.equal(await readFile(join(files.root, "second", "fixture-rust-materials", "RUST_CRATE_NOTICES.md"), "utf8"), notices, "notices are deterministic");
    assert.equal(await readFile(join(files.root, "second", "fixture-rust-materials", "INVENTORY.json"), "utf8"), await readFile(join(files.destination, "INVENTORY.json"), "utf8"));
  } finally {
    await rm(files.root, { recursive: true, force: true });
  }
});

test("rust crate acquisition fails closed and publishes nothing on notice drift, unsafe archives, ambiguous identities or overclaimed provenance", async (context) => {
  const cases = [
    {
      name: "notice member digest drift",
      mutate: async (files) => { files.manifest.items[0].noticeMembers[1].sha256 = "f".repeat(64); await writeManifest(files); },
      message: /notice member SHA-256 drifted: crate-alpha-1\.2\.3 -> alpha-1\.2\.3\/LICENSE-MIT/u
    },
    {
      name: "notice member missing from the archive",
      mutate: async (files) => {
        files.manifest.items[0].noticeMembers.push({ member: "alpha-1.2.3/COPYING", size: 4, sha256: digest("abc\n") });
        await writeManifest(files);
      },
      message: /notice member is missing from the crate archive: crate-alpha-1\.2\.3 -> alpha-1\.2\.3\/COPYING/u
    },
    {
      name: "crate archive containing a symbolic link",
      fixtureOptions: (base) => ({
        alphaEntries: [["alpha-1.2.3/Cargo.toml", Buffer.from("[package]\n")], ["alpha-1.2.3/LICENSE-MIT", Buffer.alloc(0), "2", "/etc/passwd"]]
      }),
      message: /not a plain file or directory \(type "2"\)/u
    },
    {
      name: "crate archive entry escaping the crate root",
      fixtureOptions: () => ({
        alphaEntries: [["alpha-1.2.3/Cargo.toml", Buffer.from("[package]\n")], ["alpha-1.2.3/../outside", Buffer.from("x")]]
      }),
      message: /escapes the crate root/u
    },
    {
      name: "crate archive entry under a different root",
      fixtureOptions: () => ({
        alphaEntries: [["alpha-1.2.3/Cargo.toml", Buffer.from("[package]\n")], ["other-9.9.9/LICENSE-MIT", Buffer.from("x")]]
      }),
      message: /escapes the crate root/u
    },
    {
      name: "duplicate crate identity",
      mutate: async (files) => {
        files.manifest.items.push({ ...files.manifest.items[0], id: "crate-alpha-1.2.3-again", fileName: "alpha-1.2.3.crate" });
        await writeManifest(files);
      },
      message: /duplicate or invalid fileName|names one crate identity twice/u
    },
    {
      name: "crate url not the exact static.crates.io path",
      mutate: async (files) => { files.manifest.items[0].url = "https://static.crates.io/crates/alpha/alpha-1.2.4.crate"; await writeManifest(files); },
      message: /exact static\.crates\.io path/u
    },
    {
      name: "crate item allowing redirects",
      mutate: async (files) => { files.manifest.items[0].allowedRedirectHosts = ["mirror.example.test"]; await writeManifest(files); },
      message: /must not allow redirects/u
    },
    {
      name: "notice status contradicting notice members",
      mutate: async (files) => { files.manifest.items[1].noticeStatus = "crate-carries-licence-text"; await writeManifest(files); },
      message: /noticeStatus does not match/u
    },
    {
      name: "notice member outside the crate top level",
      mutate: async (files) => {
        files.manifest.items[0].noticeMembers[0].member = "alpha-1.2.3/src/LICENSE-APACHE";
        await writeManifest(files);
      },
      message: /one unique top-level licence file/u
    },
    {
      name: "observed status claimed without a retained log record",
      mutate: async (files) => { files.manifest.categories.compiledInHistoricalBuild.status = "observed"; await writeManifest(files); },
      message: /observed requires historicalBuildEvidence\.jobLog/u
    },
    {
      name: "verified compilation status is not a recognised claim",
      mutate: async (files) => { files.manifest.categories.compiledInHistoricalBuild.status = "verified"; await writeManifest(files); },
      message: /must be unverified or observed/u
    },
    {
      name: "incorporation into the shipped binary promoted to verified",
      mutate: async (files) => { files.manifest.categories.incorporatedIntoShippedBinary.status = "verified"; await writeManifest(files); },
      message: /must remain unverified: observed compilation is not a linkage map/u
    },
    {
      name: "item claims compiled-per-build-log while the category is unverified",
      mutate: async (files) => {
        files.manifest.items[0].provenanceStatus = "compiled-per-build-log";
        files.manifest.items[0].observedCompilation = { logLine: 10, timestamp: "2026-06-30T09:14:26.3311710Z" };
        await writeManifest(files);
      },
      message: /cannot be unverified while items claim compiled-per-build-log/u
    },
    {
      name: "compiled-per-build-log item without an observation record",
      mutate: async (files) => {
        observedFixture(files);
        delete files.manifest.items[0].observedCompilation;
        await writeManifest(files);
      },
      message: /must carry the observed log line and timestamp/u
    },
    {
      name: "observed registry crate count disagrees with the items",
      mutate: async (files) => {
        observedFixture(files);
        files.manifest.historicalBuildEvidence.observedCompilation.registryCrateCount = 2;
        await writeManifest(files);
      },
      message: /registry crate count equals the compiled-per-build-log items/u
    },
    {
      name: "approximation-not-observed list disagrees with the items",
      mutate: async (files) => {
        observedFixture(files);
        files.manifest.historicalBuildEvidence.observedCompilation.approximationNotObserved = [];
        await writeManifest(files);
      },
      message: /approximationNotObserved to name exactly the resolved-approximation items/u
    },
    {
      name: "observed log line beyond the retained log length",
      mutate: async (files) => {
        observedFixture(files);
        files.manifest.items[0].observedCompilation.logLine = 5000;
        await writeManifest(files);
      },
      message: /log line exceeds the retained log length/u
    },
    {
      name: "resolved-approximation item carrying an observation record",
      mutate: async (files) => {
        observedFixture(files);
        files.manifest.items[1].observedCompilation = { logLine: 12, timestamp: "2026-06-30T09:14:26.3311710Z" };
        await writeManifest(files);
      },
      message: /resolved-approximation items must not carry an observed compilation record/u
    },
    {
      name: "unknown provenance status",
      mutate: async (files) => { files.manifest.items[0].provenanceStatus = "shipped"; await writeManifest(files); },
      message: /provenanceStatus must be resolved-approximation or compiled-per-build-log/u
    },
    {
      name: "missing categories",
      mutate: async (files) => { delete files.manifest.categories; await writeManifest(files); },
      message: /must record provenance categories/u
    },
    {
      name: "crate digest drift",
      mutate: async (files) => { files.manifest.items[1].sha256 = "e".repeat(64); await writeManifest(files); },
      message: /SHA-256 [a-f0-9]{64} differs from the manifest digest e{64}: crate-beta-0\.9\.0/u
    }
  ];
  for (const current of cases) {
    await context.test(current.name, async () => {
      const files = await fixture(current.fixtureOptions ? current.fixtureOptions() : {});
      try {
        if (current.fixtureOptions) {
          // Re-pin the mutated alpha archive so only the archive contents are under test.
          const alpha = await readFile(join(files.upstream, "static.crates.io", "crates", "alpha", "alpha-1.2.3.crate"));
          files.manifest.items[0].size = alpha.byteLength;
          files.manifest.items[0].sha256 = digest(alpha);
          await writeManifest(files);
        }
        if (current.mutate) await current.mutate(files);
        const result = acquire(files);
        assert.notEqual(result.status, 0, `${current.name} must fail closed`);
        assert.match(result.stderr, current.message);
        const remaining = await listDirectory(files.out);
        assert.ok(remaining === null || remaining.every((name) => name !== "fixture-rust-materials" && !name.includes(".staging.")),
          `no output or staging directory may remain: ${JSON.stringify(remaining)}`);
      } finally {
        await rm(files.root, { recursive: true, force: true });
      }
    });
  }
});

test("an observed-compilation manifest renders per-crate observation status and keeps incorporation unverified", async () => {
  const files = await fixture();
  try {
    observedFixture(files);
    await writeManifest(files);
    const acquired = acquire(files);
    assert.equal(acquired.status, 0, acquired.stderr);
    const notices = await readFile(join(files.destination, "RUST_CRATE_NOTICES.md"), "utf8");
    assert.match(notices, /1 observed compiling in the retained historical build log, 1 resolved by approximation only/u);
    assert.match(notices, /compiledInHistoricalBuild=observed, incorporatedIntoShippedBinary=unverified/u);
    assert.match(notices, /\| `alpha` \| `1\.2\.3` \| normal \| MIT OR Apache-2\.0 \| compiled-per-build-log \|/u);
    assert.match(notices, /\| `beta` \| `0\.9\.0` \| proc-macro \| MPL-2\.0 \| resolved-approximation \|/u);
    assert.match(notices, /Observed compilation is not a linkage map/u);
    const inventory = JSON.parse(await readFile(join(files.destination, "INVENTORY.json"), "utf8"));
    assert.deepEqual(inventory.historicalBuildProvenance, { compiledInHistoricalBuild: "observed", incorporatedIntoShippedBinary: "unverified" });
    assert.deepEqual(inventory.items.find(({ id }) => id === "crate-alpha-1.2.3").observedCompilation, { logLine: 42, timestamp: "2026-06-30T09:14:26.3311710Z" });
    assert.equal(inventory.items.find(({ id }) => id === "crate-beta-0.9.0").observedCompilation, undefined);
    const verified = run(["verify", files.manifestPath, files.destination]);
    assert.equal(verified.status, 0, verified.stderr);
  } finally {
    await rm(files.root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Archive framing regressions. The two sealed diagnostic fixtures from the
// Codex review (claude-rust-tar-diagnostic-2026-09-06) are embedded by exact
// bytes and bound by their recorded SHA-256 so the red-to-green result is tied
// to the reviewed defect: a gzip whose only decompressed byte is 0x78 used to be
// accepted as a complete crate with no declared notices.
const SEALED_MALFORMED_CRATE = Buffer.from("1f8b0800000000000013ab00008316dc8c01000000", "hex");
const SEALED_VALID_CRATE = Buffer.from("1f8b0800000000000013ed933b0f8230148599f9150d930e945be4110727574ddc8d434baa2142212db818ffbb298bf848180434a1df729b9b26e726e71cc62bea025e62f0aca100008882a09900f03a3fbce305892d140e76518b5a55545a006368fd21ece1ff9aca5381ab22cf7ad6e8f43f8e9efd27c40f430b8de2c9c4fddf973439d3133fd882e61cad90a313e1d8172e555a08bd68d2e1d8599a70a19a2fdbddc6f5f5eed7d71bbea5d57f25132f4b1996aa678dcefefbe4adff2432fd1f83b266e828908ec16c8eae37536983c1609806770a7b3a3d000e0000", "hex");
assert.equal(digest(SEALED_MALFORMED_CRATE), "489be88dbb5b62a75c1dd00ae02954d0f78880595f9d06922c7e9b3c98d2185d", "sealed malformed fixture bytes");
assert.equal(digest(SEALED_VALID_CRATE), "dd4c7c40f2f1ca9d3ec1936fde3023081b466696f22ba2ffe75e84b4cbd1f9af", "sealed valid fixture bytes");

// Replaces the fixture's beta crate (declared with no notice members) with the
// given archive bytes and re-pins its size and digest, so only framing is under test.
async function withBetaArchive(files, bytes) {
  await writeFile(join(files.upstream, "static.crates.io", "crates", "beta", "beta-0.9.0.crate"), bytes);
  files.manifest.items[1].size = bytes.byteLength;
  files.manifest.items[1].sha256 = digest(bytes);
  await writeManifest(files);
}

// Replaces the alpha crate (which declares two notice members) with the given entries.
async function withAlphaEntries(files, entries) {
  const bytes = gzipSync(Buffer.concat([...entries.map(([name, content, type, link]) => tarEntry(name, content, type, link))]));
  await writeFile(join(files.upstream, "static.crates.io", "crates", "alpha", "alpha-1.2.3.crate"), bytes);
  files.manifest.items[0].size = bytes.byteLength;
  files.manifest.items[0].sha256 = digest(bytes);
  await writeManifest(files);
}

const END_BLOCKS = Buffer.alloc(1024, 0);
const alphaLicenseMIT = Buffer.from("MIT License\n\nCopyright (c) Alpha Crate Authors\n");
const alphaLicenseApache = Buffer.from("Apache License\nVersion 2.0\n\nCopyright (c) Alpha Crate Authors\n");
const alphaManifestEntry = ["alpha-1.2.3/Cargo.toml", Buffer.from("[package]\nname = \"alpha\"\nversion = \"1.2.3\"\nlicense = \"MIT OR Apache-2.0\"\n")];
const alphaNoticeEntries = [["alpha-1.2.3/LICENSE-MIT", alphaLicenseMIT], ["alpha-1.2.3/LICENSE-APACHE", alphaLicenseApache]];

function rawTar(...parts) {
  return Buffer.concat(parts);
}

test("the sealed one-byte malformed crate with no declared notices is rejected on acquisition and on verification", async () => {
  const files = await fixture();
  try {
    const before = await readFile(join(files.upstream, "static.crates.io", "crates", "alpha", "alpha-1.2.3.crate"));
    await withBetaArchive(files, SEALED_MALFORMED_CRATE);
    const acquired = acquire(files);
    assert.notEqual(acquired.status, 0, "acquisition must fail closed");
    assert.match(acquired.stderr, /crate archive is not a whole-block tar stream \(1 bytes\): crate-beta-0\.9\.0/u);
    assert.deepEqual(await listDirectory(files.out), [], "nothing is published and no staging directory remains");
    assert.deepEqual(await readFile(join(files.upstream, "static.crates.io", "crates", "beta", "beta-0.9.0.crate")), SEALED_MALFORMED_CRATE, "input material is untouched");
    assert.deepEqual(await readFile(join(files.upstream, "static.crates.io", "crates", "alpha", "alpha-1.2.3.crate")), before, "sibling input material is untouched");

    // Independent verification of a retained destination that already holds the
    // malformed archive (as the defective tool would have published it) fails on
    // the archive itself, before any inventory metadata is consulted.
    await mkdir(files.destination, { mode: 0o700 });
    const alpha = await readFile(join(files.upstream, "static.crates.io", "crates", "alpha", "alpha-1.2.3.crate"));
    await writeFile(join(files.destination, "alpha-1.2.3.crate"), alpha);
    await writeFile(join(files.destination, "beta-0.9.0.crate"), SEALED_MALFORMED_CRATE);
    await writeFile(join(files.destination, "INVENTORY.json"), "{}\n");
    await writeFile(join(files.destination, "SHA256SUMS"), "\n");
    await writeFile(join(files.destination, "RUST_CRATE_NOTICES.md"), "# stale\n");
    const verified = run(["verify", files.manifestPath, files.destination]);
    assert.notEqual(verified.status, 0, "verification must reject the retained malformed archive");
    assert.match(verified.stderr, /crate archive is not a whole-block tar stream \(1 bytes\): crate-beta-0\.9\.0/u);
    assert.deepEqual(await readFile(join(files.destination, "beta-0.9.0.crate")), SEALED_MALFORMED_CRATE, "verification does not alter the retained material");
  } finally {
    await rm(files.root, { recursive: true, force: true });
  }
});

test("the sealed valid empty-notice crate and the fixture's own empty-notice crate still pass acquisition and verification", async () => {
  const files = await fixture();
  try {
    await withBetaArchive(files, SEALED_VALID_CRATE);
    const acquired = acquire(files);
    assert.equal(acquired.status, 0, acquired.stderr);
    const verified = run(["verify", files.manifestPath, files.destination]);
    assert.equal(verified.status, 0, verified.stderr);
    const notices = await readFile(join(files.destination, "RUST_CRATE_NOTICES.md"), "utf8");
    assert.match(notices, /\| `beta` \| `0\.9\.0` \| proc-macro \| MPL-2\.0 \| resolved-approximation \| none in crate \|/u);
  } finally {
    await rm(files.root, { recursive: true, force: true });
  }
});

test("incomplete headers, truncated payload or padding, and missing or dirty end framing fail closed even after every declared notice was found", async (context) => {
  const cases = [
    {
      name: "trailing partial block after a complete archive",
      alpha: () => rawTar(tarEntry(...alphaManifestEntry), ...alphaNoticeEntries.map((entry) => tarEntry(...entry)), END_BLOCKS, Buffer.alloc(100, 0x41)),
      message: /not a whole-block tar stream/u
    },
    {
      name: "payload truncated after the declared notices",
      alpha: () => {
        const truncated = tarEntry("alpha-1.2.3/src/lib.rs", Buffer.alloc(2000, 0x61)).subarray(0, 1024);
        return rawTar(tarEntry(...alphaManifestEntry), ...alphaNoticeEntries.map((entry) => tarEntry(...entry)), truncated);
      },
      message: /entry payload is truncated: crate-alpha-1\.2\.3 -> alpha-1\.2\.3\/src\/lib\.rs/u
    },
    {
      name: "payload truncated into the end blocks after the declared notices",
      alpha: () => {
        const truncated = tarEntry("alpha-1.2.3/src/lib.rs", Buffer.alloc(1000, 0x61)).subarray(0, 1024);
        return rawTar(tarEntry(...alphaManifestEntry), ...alphaNoticeEntries.map((entry) => tarEntry(...entry)), truncated, END_BLOCKS);
      },
      message: /entry padding is not zero|end-of-archive framing is incomplete|entry payload is truncated/u
    },
    {
      name: "non-zero padding bytes",
      alpha: () => {
        const entry = tarEntry("alpha-1.2.3/src/lib.rs", Buffer.from("pub fn alpha() {}\n"));
        entry[512 + 100] = 0x5a;
        return rawTar(tarEntry(...alphaManifestEntry), ...alphaNoticeEntries.map((e) => tarEntry(...e)), entry, END_BLOCKS);
      },
      message: /entry padding is not zero/u
    },
    {
      name: "no end-of-archive blocks after the declared notices",
      alpha: () => rawTar(tarEntry(...alphaManifestEntry), ...alphaNoticeEntries.map((entry) => tarEntry(...entry))),
      message: /ends without end-of-archive blocks/u
    },
    {
      name: "only one end-of-archive block",
      alpha: () => rawTar(tarEntry(...alphaManifestEntry), ...alphaNoticeEntries.map((entry) => tarEntry(...entry)), Buffer.alloc(512, 0)),
      message: /end-of-archive framing is incomplete/u
    },
    {
      name: "entry appended after the end-of-archive blocks",
      alpha: () => rawTar(tarEntry(...alphaManifestEntry), ...alphaNoticeEntries.map((entry) => tarEntry(...entry)), END_BLOCKS, tarEntry("alpha-1.2.3/late", Buffer.from("x"))),
      message: /non-zero bytes after its end-of-archive blocks/u
    },
    {
      name: "header with a wrong checksum",
      alpha: () => {
        const entry = tarEntry(...alphaManifestEntry);
        entry[0] ^= 0x01;
        return rawTar(entry, ...alphaNoticeEntries.map((e) => tarEntry(...e)), END_BLOCKS);
      },
      message: /header checksum is wrong/u
    },
    {
      name: "header without the ustar magic",
      alpha: () => {
        const entry = tarEntry(...alphaManifestEntry);
        entry.fill(0, 257, 263);
        let sum = 0;
        for (let index = 0; index < 512; index += 1) sum += index >= 148 && index < 156 ? 0x20 : entry[index];
        entry.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, "latin1");
        return rawTar(entry, ...alphaNoticeEntries.map((e) => tarEntry(...e)), END_BLOCKS);
      },
      message: /lacks the ustar magic/u
    },
    {
      name: "empty archive of only end blocks",
      alpha: () => rawTar(END_BLOCKS),
      message: /contains no entries|notice member is missing/u
    },
    {
      name: "directory entry carrying data",
      alpha: () => rawTar(tarEntry("alpha-1.2.3/src/", Buffer.from("data"), "5"), tarEntry(...alphaManifestEntry), ...alphaNoticeEntries.map((e) => tarEntry(...e)), END_BLOCKS),
      message: /directory entry carries data/u
    }
  ];
  for (const current of cases) {
    await context.test(current.name, async () => {
      const files = await fixture();
      try {
        const bytes = gzipSync(current.alpha());
        await writeFile(join(files.upstream, "static.crates.io", "crates", "alpha", "alpha-1.2.3.crate"), bytes);
        files.manifest.items[0].size = bytes.byteLength;
        files.manifest.items[0].sha256 = digest(bytes);
        await writeManifest(files);
        // A pre-existing sibling destination must survive a failed acquisition untouched.
        const sibling = join(files.out, "unrelated-materials");
        await mkdir(sibling, { mode: 0o700 });
        await writeFile(join(sibling, "keep.txt"), "keep\n");
        const result = acquire(files);
        assert.notEqual(result.status, 0, `${current.name} must fail closed`);
        assert.match(result.stderr, current.message);
        assert.deepEqual(await listDirectory(files.out), ["unrelated-materials"], "no output or staging directory remains");
        assert.equal(await readFile(join(sibling, "keep.txt"), "utf8"), "keep\n");
        assert.deepEqual(await readFile(join(files.upstream, "static.crates.io", "crates", "alpha", "alpha-1.2.3.crate")), bytes, "input material is untouched");
      } finally {
        await rm(files.root, { recursive: true, force: true });
      }
    });
  }
});

test("a structurally complete crate with declared notices still passes with the stricter framing checks (GNU and POSIX magics)", async () => {
  for (const magic of ["ustar\0" + "00", "ustar " + " \0"]) {
    const files = await fixture();
    try {
      const entries = [tarEntry(...alphaManifestEntry), ...alphaNoticeEntries.map((entry) => tarEntry(...entry)), tarEntry("alpha-1.2.3/src/lib.rs", Buffer.from("pub fn alpha() {}\n"))];
      for (const entry of entries) {
        entry.write(magic, 257, 8, "latin1");
        let sum = 0;
        for (let index = 0; index < 512; index += 1) sum += index >= 148 && index < 156 ? 0x20 : entry[index];
        entry.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, "latin1");
      }
      const bytes = gzipSync(rawTar(...entries, END_BLOCKS, Buffer.alloc(512, 0)));
      await writeFile(join(files.upstream, "static.crates.io", "crates", "alpha", "alpha-1.2.3.crate"), bytes);
      files.manifest.items[0].size = bytes.byteLength;
      files.manifest.items[0].sha256 = digest(bytes);
      await writeManifest(files);
      const acquired = acquire(files);
      assert.equal(acquired.status, 0, `${JSON.stringify(magic)}: ${acquired.stderr}`);
      const verified = run(["verify", files.manifestPath, files.destination]);
      assert.equal(verified.status, 0, verified.stderr);
      assert.match(await readFile(join(files.destination, "RUST_CRATE_NOTICES.md"), "utf8"), /Copyright \(c\) Alpha Crate Authors/u);
    } finally {
      await rm(files.root, { recursive: true, force: true });
    }
  }
});

test("rust crate verification fails when the rendered notices or a crate archive are tampered", async (context) => {
  const cases = [
    {
      name: "tampered notices file",
      mutate: async (files) => {
        const path = join(files.destination, "RUST_CRATE_NOTICES.md");
        await writeFile(path, `${await readFile(path, "utf8")}\nextra\n`);
      },
      message: /rust crate notices drifted|inventory does not describe|checksum list drifted/u
    },
    {
      name: "tampered crate archive",
      mutate: async (files) => {
        const path = join(files.destination, "beta-0.9.0.crate");
        const bytes = Buffer.from(await readFile(path));
        bytes[bytes.byteLength - 1] ^= 0x01;
        await writeFile(path, bytes);
      },
      message: /SHA-256 drifted/u
    },
    {
      name: "notices file removed",
      mutate: async (files) => rm(join(files.destination, "RUST_CRATE_NOTICES.md")),
      message: /missing expected entries/u
    }
  ];
  for (const current of cases) {
    await context.test(current.name, async () => {
      const files = await fixture();
      try {
        const acquired = acquire(files);
        assert.equal(acquired.status, 0, acquired.stderr);
        await current.mutate(files);
        const result = run(["verify", files.manifestPath, files.destination]);
        assert.notEqual(result.status, 0, `${current.name} must fail`);
        assert.match(result.stderr, current.message);
      } finally {
        await rm(files.root, { recursive: true, force: true });
      }
    });
  }
});

// ---------------------------------------------------------------------------
// External notice material (--notice-materials): the version-bound manifest
// for crates whose archive carries no licence text is verified before its
// exact text is rendered, kept explicitly distinct from archive-contained
// members, recorded in the inventory, and a destination rendered one way is
// refused by a verification run the other way. Fixture-only; no network.

const MPL_HEADER = "/* This Source Code Form is subject to the terms of the Mozilla Public\n * License, v. 2.0. If a copy of the MPL was not distributed with this\n * file, You can obtain one at https://mozilla.org/MPL/2.0/. */";
const BETA_COMMIT = "2".repeat(40);
const SPDX_COMMIT = "4".repeat(40);

async function noticeMaterialsFixture(status = "established") {
  const betaLib = Buffer.from(`${MPL_HEADER}\n\npub fn beta() {}\n`);
  const files = await fixture({
    betaEntries: [
      ["beta-0.9.0/Cargo.toml", Buffer.from("[package]\nname = \"beta\"\nversion = \"0.9.0\"\nlicense = \"MPL-2.0\"\n")],
      ["beta-0.9.0/src/lib.rs", betaLib]
    ]
  });
  const beta = await readFile(join(files.upstream, "static.crates.io", "crates", "beta", "beta-0.9.0.crate"));
  files.manifest.items[1].size = beta.byteLength;
  files.manifest.items[1].sha256 = digest(beta);
  await writeManifest(files);
  await mkdir(join(files.root, "Config"), { mode: 0o700 });
  const rustDirectory = join(files.root, "Resources", "ThirdPartyLicenses", "fixture-binary-1.0.0", "rust");
  await mkdir(rustDirectory, { recursive: true, mode: 0o700 });
  const mpl = Buffer.from("Mozilla Public License Version 2.0 (fixture text)\n\n1. Definitions\n\nThis fixture stands in for the SPDX licence text; permission terms follow.\n");
  const mplPath = "Resources/ThirdPartyLicenses/fixture-binary-1.0.0/rust/beta-0.9.0-external-spdx-MPL-2.0.txt";
  await writeFile(join(files.root, ...mplPath.split("/")), mpl);
  const connection = {
    kind: "cargo-vcs-info", repository: "https://github.com/fixture/beta", revision: BETA_COMMIT, pathInVcs: "beta",
    revisionEvidence: `the crate archive member beta-0.9.0/.cargo_vcs_info.json (sha256 ${"5".repeat(64)}) records git sha1 ${BETA_COMMIT} and path_in_vcs beta; beta/Cargo.toml at that commit declares version = "0.9.0"; the crate member src/lib.rs is byte-identical to beta/src/lib.rs at that commit`
  };
  const record = status === "established"
    ? {
      crateName: "beta", crateVersion: "0.9.0", crateSHA256: digest(beta), licenseExpression: "MPL-2.0", status: "established", connection,
      archiveNotice: { member: "beta-0.9.0/src/lib.rs", memberSHA256: digest(betaLib), text: MPL_HEADER, note: "Per-file MPL-2.0 notice carried by the crate archive member (archive-contained); no LICENSE file exists upstream." },
      materials: [{
        kind: "external-spdx-licence-text", sourcePath: mplPath,
        describes: "MPL-2.0 text as published by SPDX, the licence the crate's per-file notices designate (external to the archive)",
        origin: `https://github.com/spdx/license-list-data/blob/${SPDX_COMMIT}/text/MPL-2.0.txt`,
        upstreamSHA256: digest(mpl.subarray(0, mpl.byteLength - 1)), upstreamSize: mpl.byteLength - 1, normalization: "append-terminal-lf-v1",
        sha256: digest(mpl), size: mpl.byteLength, retrievedOn: "2026-09-06"
      }]
    }
    : {
      crateName: "beta", crateVersion: "0.9.0", crateSHA256: digest(beta), licenseExpression: "MPL-2.0", status: "unresolved",
      connection: { kind: "version-tag", repository: "https://github.com/fixture/beta", revision: BETA_COMMIT, revisionEvidence: `lightweight tag 0.9.0 resolved with git ls-remote on 2026-09-06; Cargo.toml at that commit carries version = "0.9.0" and license = "MPL-2.0"` },
      materials: [],
      unresolved: {
        missingEvidence: "An upstream-published licence text and copyright statement for this exact version. Neither the crate archive nor the tagged upstream revision carries a licence file; none is asserted.",
        checksPerformed: [
          { check: "crate archive top-level members", result: "Cargo.toml only; no licence member" },
          { check: "upstream repository tag for this exact version", result: `tag 0.9.0 = commit ${BETA_COMMIT}` },
          { check: "repository tree at that commit", result: "no LICENSE file at any path" },
          { check: "source file header (fallback)", result: "src/lib.rs carries a per-file notice but no copyright line" }
        ],
        fallbackUsed: "source file headers at the tagged revision; research stopped per the bounded scope"
      }
    };
  if (status !== "established") await rm(join(files.root, ...mplPath.split("/")));
  const noticeMaterials = {
    schemaVersion: 1,
    purpose: "Fixture version-bound notice material for crates whose archives carry no licence text. External material is labelled as such and was never a member of the original archive. This is material identification, not legal clearance.",
    crateManifest: "manifest.json",
    researchedOn: "2026-09-06",
    summary: status === "established" ? { established: ["beta 0.9.0"], unresolved: [] } : { established: [], unresolved: ["beta 0.9.0"] },
    records: [record]
  };
  const noticeMaterialsPath = join(files.root, "Config", "notice-materials.json");
  const saveNoticeMaterials = () => writeFile(noticeMaterialsPath, `${JSON.stringify(noticeMaterials, null, 2)}\n`);
  await saveNoticeMaterials();
  return { ...files, beta, betaLib, mpl, mplPath, noticeMaterials, noticeMaterialsPath, saveNoticeMaterials };
}

function acquireWithNotices(files, destination = files.destination) {
  return run(["acquire", files.manifestPath, destination, "--transport", `local-fixture:${files.upstream}`, "--notice-materials", files.noticeMaterialsPath]);
}

test("external notice material is verified, rendered distinct from archive members, recorded in the inventory, and never relabelled", async () => {
  const files = await noticeMaterialsFixture();
  try {
    const acquired = acquireWithNotices(files);
    assert.equal(acquired.status, 0, acquired.stderr);
    assert.match(acquired.stderr, /external notice material bound from Config\/notice-materials\.json \(sha256:[a-f0-9]{64}; established 1, unresolved 0\)/u);
    const notices = await readFile(join(files.destination, "RUST_CRATE_NOTICES.md"), "utf8");
    assert.match(notices, /\| `beta` \| `0\.9\.0` \| proc-macro \| MPL-2\.0 \| resolved-approximation \| none in crate; external material bound \(see below\) \|/u);
    assert.match(notices, /## Crates whose archive carries no licence text\n\nThese 1 crates are identified by their Cargo\.toml licence expression/u);
    assert.match(notices, /### `beta` 0\.9\.0 — established \(archive-contained notice plus external licence text\)/u);
    assert.match(notices, /Packaged from: `https:\/\/github\.com\/fixture\/beta` @ `2{40}` \(cargo-vcs-info, path `beta`\)\./u);
    assert.match(notices, /Archive-contained notice: member `beta-0\.9\.0\/src\/lib\.rs` \(`sha256:[a-f0-9]{64}`, verified in the \.crate archive\) begins with:\n\n    \/\* This Source Code Form/u);
    assert.match(notices, /#### External material for `beta` 0\.9\.0: `Resources\/ThirdPartyLicenses\/fixture-binary-1\.0\.0\/rust\/beta-0\.9\.0-external-spdx-MPL-2\.0\.txt`\n\nKind: external-spdx-licence-text — external to the \.crate archive; this text was never an archive member\./u);
    assert.match(notices, /Mozilla Public License Version 2\.0 \(fixture text\)/u);
    assert.match(notices, /Copyright \(c\) Alpha Crate Authors/u, "archive-carried texts are still rendered");
    assert.doesNotMatch(notices, /not retained here/u);
    const inventory = JSON.parse(await readFile(join(files.destination, "INVENTORY.json"), "utf8"));
    assert.equal(inventory.noticeMaterials.manifest, "Config/notice-materials.json");
    assert.equal(inventory.noticeMaterials.manifestSHA256, digest(await readFile(files.noticeMaterialsPath)));
    assert.deepEqual(inventory.noticeMaterials.summary, { established: ["beta 0.9.0"], unresolved: [] });
    assert.equal(inventory.noticeMaterials.records[0].materials[0].sha256, digest(files.mpl));
    assert.equal(inventory.noticeMaterials.records[0].materials[0].kind, "external-spdx-licence-text");
    assert.deepEqual(inventory.noticeMaterials.records[0].archiveNotice, { member: "beta-0.9.0/src/lib.rs", memberSHA256: digest(files.betaLib) });
    assert.equal(inventory.rustNoticesSHA256, digest(notices));
    assert.ok((await readFile(join(files.destination, "SHA256SUMS"), "utf8")).includes(`${digest(notices)}  RUST_CRATE_NOTICES.md\n`));

    const verified = run(["verify", files.manifestPath, files.destination, "--notice-materials", files.noticeMaterialsPath]);
    assert.equal(verified.status, 0, verified.stderr);
    assert.match(verified.stderr, /external notice material Config\/notice-materials\.json/u);
    const withoutOption = run(["verify", files.manifestPath, files.destination]);
    assert.notEqual(withoutOption.status, 0);
    assert.match(withoutOption.stderr, /inventory records external notice material bound from Config\/notice-materials\.json; pass --notice-materials with that manifest to verify it/u);

    // A plain acquisition is unchanged and is never relabelled as complete.
    await mkdir(join(files.root, "plain"), { mode: 0o700 });
    const plainDestination = join(files.root, "plain", "fixture-rust-materials");
    const plain = acquire(files, plainDestination);
    assert.equal(plain.status, 0, plain.stderr);
    const plainNotices = await readFile(join(plainDestination, "RUST_CRATE_NOTICES.md"), "utf8");
    assert.match(plainNotices, /the applicable licence text and any copyright statement are not retained here/u);
    assert.doesNotMatch(plainNotices, /external material|UNRESOLVED|Archive-contained/u);
    assert.equal(JSON.parse(await readFile(join(plainDestination, "INVENTORY.json"), "utf8")).noticeMaterials, undefined);
    const relabelled = run(["verify", files.manifestPath, plainDestination, "--notice-materials", files.noticeMaterialsPath]);
    assert.notEqual(relabelled.status, 0);
    assert.match(relabelled.stderr, /inventory was rendered without external notice material; acquire again with --notice-materials instead of relabelling this destination/u);
    assert.equal(run(["verify", files.manifestPath, plainDestination]).status, 0);

    await mkdir(join(files.root, "second"), { mode: 0o700 });
    const second = acquireWithNotices(files, join(files.root, "second", "fixture-rust-materials"));
    assert.equal(second.status, 0, second.stderr);
    assert.equal(await readFile(join(files.root, "second", "fixture-rust-materials", "RUST_CRATE_NOTICES.md"), "utf8"), notices, "rendering is deterministic");
    assert.equal(await readFile(join(files.root, "second", "fixture-rust-materials", "INVENTORY.json"), "utf8"), await readFile(join(files.destination, "INVENTORY.json"), "utf8"));
  } finally {
    await rm(files.root, { recursive: true, force: true });
  }
});

test("an unresolved notice record is rendered with its exact status and bounded reason and never as external material", async () => {
  const files = await noticeMaterialsFixture("unresolved");
  try {
    const acquired = acquireWithNotices(files);
    assert.equal(acquired.status, 0, acquired.stderr);
    const notices = await readFile(join(files.destination, "RUST_CRATE_NOTICES.md"), "utf8");
    assert.match(notices, /\| `beta` \| `0\.9\.0` \| proc-macro \| MPL-2\.0 \| resolved-approximation \| none in crate; UNRESOLVED \(see below\) \|/u);
    assert.match(notices, /Unresolved: 1 \(`beta 0\.9\.0`\); no licence text or copyright statement is rendered for them and none is asserted\./u);
    assert.match(notices, /### `beta` 0\.9\.0 — UNRESOLVED\n/u);
    assert.match(notices, /Status: UNRESOLVED — no upstream-published licence text or copyright statement exists for this exact version; nothing is rendered for it and none is asserted\./u);
    assert.match(notices, /Missing evidence: An upstream-published licence text and copyright statement for this exact version\./u);
    assert.match(notices, /Checks performed:\n- crate archive top-level members: Cargo\.toml only; no licence member\n/u);
    assert.match(notices, /Fallback used: source file headers at the tagged revision; research stopped per the bounded scope/u);
    assert.doesNotMatch(notices, /external material bound|External material for|Mozilla Public License Version 2\.0 \(fixture text\)/u);
    const inventory = JSON.parse(await readFile(join(files.destination, "INVENTORY.json"), "utf8"));
    assert.equal(inventory.noticeMaterials.records[0].status, "unresolved");
    assert.deepEqual(inventory.noticeMaterials.records[0].materials, []);
    assert.match(inventory.noticeMaterials.records[0].unresolved.missingEvidence, /none is asserted/u);
    assert.equal(run(["verify", files.manifestPath, files.destination, "--notice-materials", files.noticeMaterialsPath]).status, 0);
  } finally {
    await rm(files.root, { recursive: true, force: true });
  }
});

test("acquisition with external notice material fails closed and publishes nothing on unbound, drifted, mislabelled or unverifiable material", async (context) => {
  const cases = [
    {
      name: "archive-contained notice text not at the start of the member",
      mutate: async (files) => { files.noticeMaterials.records[0].archiveNotice.text = "/* some other header the member does not carry */"; await files.saveNoticeMaterials(); },
      message: /archive-contained notice member does not begin with the recorded notice text: crate-beta-0\.9\.0 -> beta-0\.9\.0\/src\/lib\.rs/u
    },
    {
      name: "archive-contained notice member absent from the archive",
      mutate: async (files) => { files.noticeMaterials.records[0].archiveNotice.member = "beta-0.9.0/src/notice.rs"; await files.saveNoticeMaterials(); },
      message: /archive-contained notice member is missing from the crate archive: crate-beta-0\.9\.0 -> beta-0\.9\.0\/src\/notice\.rs/u
    },
    {
      name: "archive-contained notice member digest drifted",
      mutate: async (files) => { files.noticeMaterials.records[0].archiveNotice.memberSHA256 = "e".repeat(64); await files.saveNoticeMaterials(); },
      message: /archive-contained notice member SHA-256 drifted/u
    },
    {
      name: "record bound to a different crate archive digest",
      mutate: async (files) => { files.noticeMaterials.records[0].crateSHA256 = "0".repeat(64); await files.saveNoticeMaterials(); },
      message: /not bound to the pinned crate archive digest/u
    },
    {
      name: "record naming a crate whose archive carries licence text",
      mutate: async (files) => {
        files.noticeMaterials.records.unshift({ ...structuredClone(files.noticeMaterials.records[0]), crateName: "alpha", crateVersion: "1.2.3" });
        await files.saveNoticeMaterials();
      },
      message: /must cover exactly the crates without archive licence text/u
    },
    {
      name: "notice-materials manifest bound to another crate manifest",
      mutate: async (files) => { files.noticeMaterials.crateManifest = "other.json"; await files.saveNoticeMaterials(); },
      message: /binds other\.json, which is not the crate manifest being processed/u
    },
    {
      name: "tracked external text with CRLF line endings",
      mutate: async (files) => writeFile(join(files.root, ...files.mplPath.split("/")), files.mpl.toString("utf8").replaceAll("\n", "\r\n")),
      message: /size drifted|not canonical UTF-8 text/u
    },
    {
      name: "tracked external text drifted at the same size",
      mutate: async (files) => {
        const bytes = Buffer.from(files.mpl);
        bytes[0] ^= 0x01;
        await writeFile(join(files.root, ...files.mplPath.split("/")), bytes);
      },
      message: /tracked material SHA-256 drifted/u
    },
    {
      name: "tracked external text without the terminal LF normalization",
      mutate: async (files) => {
        const bytes = Buffer.concat([files.mpl.subarray(0, files.mpl.byteLength - 1), Buffer.from("!")]);
        files.noticeMaterials.records[0].materials[0].sha256 = digest(bytes);
        await files.saveNoticeMaterials();
        await writeFile(join(files.root, ...files.mplPath.split("/")), bytes);
      },
      message: /no longer equals the exact upstream bytes plus one terminal LF/u
    },
    {
      name: "material labelled as an archive member",
      mutate: async (files) => { files.noticeMaterials.records[0].materials[0].describes = "MPL-2.0 licence member of the crate archive"; await files.saveNoticeMaterials(); },
      message: /must be described as external to the archive/u
    },
    {
      name: "material with an unlabelled kind",
      mutate: async (files) => { files.noticeMaterials.records[0].materials[0].kind = "archive-member"; await files.saveNoticeMaterials(); },
      message: /material kind must be labelled external/u
    },
    {
      name: "unresolved record carrying invented certainty",
      mutate: async (files) => {
        const record = files.noticeMaterials.records[0];
        delete record.archiveNotice;
        record.status = "unresolved";
        record.materials = [];
        record.unresolved = {
          missingEvidence: "The MPL licence obviously applies with copyright The Fixture Authors; treat as resolved for release purposes and nothing further is needed here at all.",
          checksPerformed: [{ check: "crate archive top-level members", result: "none" }, { check: "tag", result: "none" }, { check: "tree", result: "none" }, { check: "header", result: "none" }],
          fallbackUsed: "source file headers at the tagged revision; research stopped"
        };
        files.noticeMaterials.summary = { established: [], unresolved: ["beta 0.9.0"] };
        await files.saveNoticeMaterials();
        await rm(join(files.root, ...files.mplPath.split("/")));
      },
      message: /unresolved record must assert nothing it cannot show/u
    },
    {
      name: "manifest reading as a legal conclusion",
      mutate: async (files) => { files.noticeMaterials.purpose += " The binary is therefore licence-cleared for release."; await files.saveNoticeMaterials(); },
      message: /must not read as a legal conclusion/u
    }
  ];
  for (const current of cases) {
    await context.test(current.name, async () => {
      const files = await noticeMaterialsFixture();
      try {
        await current.mutate(files);
        const result = acquireWithNotices(files);
        assert.notEqual(result.status, 0, `${current.name} must fail closed`);
        assert.match(result.stderr, current.message);
        assert.deepEqual(await listDirectory(files.out), [], "no output or staging directory remains");
      } finally {
        await rm(files.root, { recursive: true, force: true });
      }
    });
  }
});

test("the notice-materials option is refused when malformed or when the manifest has no crates", async () => {
  const files = await noticeMaterialsFixture();
  try {
    for (const args of [
      ["acquire", files.manifestPath, files.destination, "--notice-materials"],
      ["acquire", files.manifestPath, files.destination, "--notice-materials", files.noticeMaterialsPath, "--notice-materials", files.noticeMaterialsPath],
      ["acquire", files.manifestPath, files.destination, "--transport", `local-fixture:${files.upstream}`, "--notice-materials", "--transport"],
      ["verify", files.manifestPath, files.destination, "--transport", `local-fixture:${files.upstream}`, "--notice-materials", files.noticeMaterialsPath]
    ]) {
      const result = run(args);
      assert.notEqual(result.status, 0, JSON.stringify(args));
      assert.match(result.stderr, /usage:/u, JSON.stringify(args));
    }
    assert.deepEqual(await listDirectory(files.out), []);
  } finally {
    await rm(files.root, { recursive: true, force: true });
  }
});
