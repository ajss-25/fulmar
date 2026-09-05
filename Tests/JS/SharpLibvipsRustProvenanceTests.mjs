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
  assert.match(job.logStatus, /^not-retrieved/u, "the compile log was not retrieved and the manifest says so");
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
  assert.equal(categories.compiledInHistoricalBuild.status, "unverified");
  assert.equal(categories.incorporatedIntoShippedBinary.status, "unverified");
  const roles = {};
  for (const item of manifest.items) roles[item.role] = (roles[item.role] ?? 0) + 1;
  assert.deepEqual(roles, categories.resolvedForTargetApproximation.roles);

  // Items.
  const identities = new Set();
  const summary = {};
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
    assert.equal(item.provenanceStatus, "resolved-approximation", `${item.id} must not claim compiled status without the build log`);
    assert.ok(["normal", "proc-macro", "build-only"].includes(item.role), item.id);
    assert.equal(item.noticeStatus, item.noticeMembers.length === 0 ? "no-licence-text-in-crate" : "crate-carries-licence-text", item.id);
    for (const member of item.noticeMembers) {
      assert.ok(member.member.startsWith(`${item.crateName}-${item.crateVersion}/`), item.id);
      assert.match(member.sha256, SHA256, item.id);
    }
    summary[item.licenseExpression] = (summary[item.licenseExpression] ?? 0) + 1;
  }
  assert.deepEqual(manifest.licenseExpressionSummary, summary);
  assert.ok(manifest.items.some(({ noticeStatus }) => noticeStatus === "no-licence-text-in-crate"), "the known gap of crates without licence text is recorded, not hidden");
  const unretained = manifest.unretained.map(({ id }) => id);
  for (const required of ["historical-compile-log", "resolver-approximation", "binary-incorporation", "crates-without-licence-text", "workspace-members", "mpl-and-unicode-terms"]) {
    assert.ok(unretained.includes(required), required);
  }
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
      name: "compiled status claimed without build-log provenance",
      mutate: async (files) => { files.manifest.categories.compiledInHistoricalBuild.status = "verified"; await writeManifest(files); },
      message: /cannot be verified while any crate is only a resolved approximation/u
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
