// Fixture-only tests for the libvips corresponding-source material manifest and
// the acquisition/verification tool. They read tracked repository files and
// private temporary fixture roots; they never contact upstream services.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readdir, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";

const project = process.cwd();
const tool = join(project, "scripts", "prepare-libvips-source-materials.mjs");
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const SHA256 = /^[a-f0-9]{64}$/u;
const COMMIT = /^[a-f0-9]{40}$/u;
const readJSON = async (relative) => JSON.parse(await readFile(join(project, relative), "utf8"));

test("source materials manifest pins every component of the exact 1.3.2 build by URL, size and digest", async () => {
  const manifest = await readJSON("Config/SharpLibvipsSourceMaterials.json");
  const provenance = (await readJSON("Config/ThirdPartyBinaryProvenance.json")).components[0];
  assert.equal(manifest.schemaVersion, 1);
  assert.match(manifest.purpose, /not legal clearance/u);
  assert.doesNotMatch(manifest.purpose, /cleared|satisfied|compliant/iu);
  assert.equal(manifest.binary.packageName, provenance.packageName);
  assert.equal(manifest.binary.version, provenance.version);
  assert.equal(manifest.binary.buildCommit, provenance.upstream.buildCommit);
  assert.equal(manifest.binary.buildTag, provenance.upstream.buildTag);
  const dylib = provenance.shippedFiles.find(({ path }) => path.endsWith(".dylib"));
  assert.equal(manifest.binary.shippedBinary, dylib.path);
  assert.equal(manifest.binary.shippedBinarySHA256, dylib.sha256);
  assert.equal(manifest.outputDirectoryName, "sharp-libvips-1.3.2-corresponding-source-materials");

  const ids = manifest.items.map(({ id }) => id);
  assert.deepEqual(ids, [...new Set(ids)], "item ids are unique");
  const names = manifest.items.map(({ fileName }) => fileName);
  assert.deepEqual(names, [...new Set(names)], "file names are unique");
  let total = 0;
  for (const item of manifest.items) {
    assert.match(item.sha256, SHA256, item.id);
    assert.ok(Number.isSafeInteger(item.size) && item.size > 0 && item.size <= manifest.limits.maximumFileBytes, item.id);
    total += item.size;
    const url = new URL(item.url);
    assert.equal(url.protocol, "https:", item.id);
    assert.equal(url.search, "", item.id);
    assert.equal(url.hash, "", item.id);
    assert.ok(Array.isArray(item.allowedRedirectHosts) && item.allowedRedirectHosts.length <= 4, item.id);
    if (url.hostname === "github.com" && /\/releases\/download\//u.test(url.pathname)) {
      assert.ok(item.allowedRedirectHosts.some((host) => host === "release-assets.githubusercontent.com"), `${item.id} release asset must allow the asset host`);
    }
    if (url.hostname === "github.com" && /\/archive\//u.test(url.pathname)) {
      assert.deepEqual(item.allowedRedirectHosts, ["codeload.github.com"], item.id);
    }
  }
  assert.ok(total <= manifest.limits.maximumTotalBytes);

  const archives = manifest.items.filter(({ kind }) => kind === "source-archive");
  assert.equal(archives.length, Object.keys(provenance.componentVersions).length, "one archive per pinned component version");
  assert.deepEqual(archives.map(({ versionKey }) => versionKey).sort(), Object.keys(provenance.componentVersions).sort());
  for (const archive of archives) {
    assert.equal(archive.version, provenance.componentVersions[archive.versionKey], archive.id);
    assert.match(archive.upstreamRevision, COMMIT, archive.id);
    assert.ok(archive.url.includes(archive.version) || archive.url.includes(archive.version.replaceAll(".", "-")),
      `${archive.id} archive URL must name the exact version`);
    assert.equal(archive.recipeReference, `build/posix.sh (VERSION_${archive.versionKey.toUpperCase().replaceAll("-", "_")})`);
    const notice = provenance.componentNotices.find(({ versionKey }) => versionKey === archive.versionKey);
    assert.ok(notice, archive.id);
    assert.equal(notice.upstreamRevision, archive.upstreamRevision, `${archive.id} revision agrees with the notice record`);
    assert.equal(notice.upstreamRepository, archive.upstreamRepository, archive.id);
    for (const material of notice.materials) {
      assert.equal(material.archiveSHA256, archive.sha256, `${material.sourcePath} was verified against the pinned archive`);
      const segments = material.archiveMember.split("/");
      assert.ok(segments.length >= 2 && segments.every((segment) => segment.length > 0 && segment !== "." && segment !== ".."), material.sourcePath);
      assert.ok(segments[0].includes(archive.version) || segments[0].includes(archive.upstreamRevision)
        || segments[0].includes(archive.version.replaceAll(".", "-")), `${material.sourcePath} member lives under the versioned archive root`);
    }
  }
  const libnsgif = provenance.componentNotices.find(({ component }) => component === "libnsgif");
  const vips = archives.find(({ versionKey }) => versionKey === "vips");
  assert.equal(libnsgif.materials[0].archiveSHA256, vips.sha256, "libnsgif notice comes from the libvips archive");

  const recipe = manifest.items.filter(({ kind }) => kind === "build-recipe");
  const buildCommit = manifest.binary.buildCommit;
  for (const item of recipe) {
    assert.ok(item.url.startsWith(`https://raw.githubusercontent.com/lovell/sharp-libvips/${buildCommit}/`), item.id);
    assert.equal(item.immutability, "commit-pinned-raw-file");
  }
  assert.deepEqual(recipe.map(({ url }) => url.slice(url.indexOf(buildCommit) + buildCommit.length + 1)).sort(), [
    "LICENSE", "THIRD-PARTY-NOTICES.md", "build.sh", "build/posix.sh", "npm/darwin-arm64/package.json",
    "platforms/darwin-arm64v8/Toolchain.cmake", "platforms/darwin-arm64v8/meson.ini", "populate-npm-workspace.sh", "versions.properties"
  ]);
  const buildLicense = recipe.find(({ url }) => url.endsWith("/LICENSE"));
  assert.equal(buildLicense.sha256, provenance.upstream.buildScriptsLicenseSHA256);

  const patches = manifest.items.filter(({ kind }) => kind === "patch");
  assert.deepEqual(patches.map(({ component }) => component).sort(), ["glib", "mozjpeg", "uhdr", "vips"]);
  const pullRequestPatch = patches.find(({ id }) => id === "patch-libultrahdr-pull-383");
  assert.equal(pullRequestPatch.immutability, "mutable-pull-request-patch");

  const unretained = manifest.unretained.map(({ id }) => id);
  for (const required of ["rust-crates", "rust-toolchain", "apple-toolchain", "libnsgif-upstream-revision", "pull-request-patch-mutability", "rebuild-not-attempted"]) {
    assert.ok(unretained.includes(required), required);
  }
  for (const entry of [...manifest.unretained, ...manifest.buildTimeModifications]) {
    assert.doesNotMatch(JSON.stringify(entry), /cleared|satisfied|compliant/iu);
  }
  assert.ok(manifest.buildTimeModifications.some(({ component, modification }) => component === "libvips" && /static_library/u.test(modification)));
});

// ---------------------------------------------------------------------------
// Tool fixtures

async function fixture() {
  const root = await realpath(await mkdtemp(join(tmpdir(), "fulmar-source-materials-test.")));
  const upstream = join(root, "upstream");
  const out = join(root, "out");
  await mkdir(out, { mode: 0o700 });
  const archiveBytes = Buffer.concat([Buffer.from("fixture archive "), Buffer.alloc(3000, 0x41)]);
  const recipeBytes = Buffer.from("#!/bin/sh\necho fixture recipe\n");
  const patchBytes = Buffer.from("--- a\n+++ b\n@@ -1 +1 @@\n-x\n+y\n");
  const put = async (url, bytes) => {
    const parsed = new URL(url);
    const path = join(upstream, parsed.hostname, ...parsed.pathname.split("/").filter(Boolean));
    await mkdir(join(path, ".."), { recursive: true, mode: 0o700 });
    await writeFile(path, bytes);
    return path;
  };
  await put("https://example.test/recipe/build.sh", recipeBytes);
  await put("https://example.test/patches/fix.patch", patchBytes);
  // The archive URL redirects once to an allowed host, whose file holds the bytes.
  const archivePath = await put("https://example.test/archive/lib-1.0.tar.gz", Buffer.alloc(0));
  await writeFile(`${archivePath}.redirect`, "https://mirror.example.test/lib-1.0.tar.gz\n");
  await put("https://mirror.example.test/lib-1.0.tar.gz", archiveBytes);
  const manifest = {
    schemaVersion: 1,
    purpose: "Fixture manifest for hermetic tests. It identifies material; it is not legal clearance and is not a corresponding-source offer.",
    binary: {
      packageName: "@fixture/binary", version: "1.0.0", buildRepository: "https://example.test/build", buildTag: "v1.0.0",
      buildCommit: "0".repeat(40), buildPlatform: "darwin-arm64v8", shippedBinary: "node_modules/@fixture/binary/lib/lib.dylib",
      shippedBinarySHA256: "1".repeat(64), provenanceRecord: "Config/Fixture.json"
    },
    outputDirectoryName: "fixture-materials",
    limits: { maximumFileBytes: 65536, maximumTotalBytes: 1048576, maximumRedirects: 2, requestTimeoutMilliseconds: 5000 },
    items: [
      { id: "recipe-build-sh", kind: "build-recipe", fileName: "build.sh", url: "https://example.test/recipe/build.sh", size: recipeBytes.byteLength, sha256: digest(recipeBytes), allowedRedirectHosts: [], immutability: "commit-pinned-raw-file", role: "fixture recipe entry point" },
      { id: "patch-fix", kind: "patch", fileName: "fix.patch", url: "https://example.test/patches/fix.patch", size: patchBytes.byteLength, sha256: digest(patchBytes), allowedRedirectHosts: [], immutability: "revision-pinned", component: "lib", role: "fixture patch applied with patch -p1" },
      { id: "source-lib", kind: "source-archive", component: "lib", versionKey: "lib", version: "1.0", fileName: "lib-1.0.tar.gz", url: "https://example.test/archive/lib-1.0.tar.gz", size: archiveBytes.byteLength, sha256: digest(archiveBytes), allowedRedirectHosts: ["mirror.example.test"], immutability: "release-asset", upstreamRepository: "https://example.test/lib", upstreamRevision: "a".repeat(40), revisionEvidence: "fixture tag resolution recorded for the test", recipeReference: "build/posix.sh (VERSION_LIB)" }
    ],
    buildTimeModifications: [{ component: "lib", recipeLine: 1, modification: "fixture sed" }],
    unretained: [{ id: "rebuild-not-attempted", component: "all", detail: "No build was attempted by this fixture." }]
  };
  const manifestPath = join(root, "manifest.json");
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  return { root, upstream, out, manifest, manifestPath, archiveBytes, destination: join(out, "fixture-materials") };
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

test("acquisition verifies every item, publishes a deterministic labelled inventory and verifies it back", async () => {
  const files = await fixture();
  try {
    const first = acquire(files);
    assert.equal(first.status, 0, first.stderr);
    assert.deepEqual(await listDirectory(files.destination), ["INVENTORY.json", "SHA256SUMS", "build.sh", "fix.patch", "lib-1.0.tar.gz"]);
    assert.deepEqual(await listDirectory(files.out), ["fixture-materials"], "no staging directory remains");
    const inventoryText = await readFile(join(files.destination, "INVENTORY.json"), "utf8");
    const inventory = JSON.parse(inventoryText);
    assert.equal(inventory.transport, "local-fixture");
    assert.equal(inventory.authoritative, false, "fixture output must be labelled non-authoritative");
    assert.equal(inventory.manifestSHA256, digest(await readFile(files.manifestPath)));
    assert.deepEqual(inventory.items.find(({ id }) => id === "source-lib").redirectHosts, ["mirror.example.test"]);
    assert.match(inventory.statement, /not a corresponding-source offer/u);
    const sums = await readFile(join(files.destination, "SHA256SUMS"), "utf8");
    assert.equal(sums, [
      `${digest(await readFile(join(files.upstream, "example.test", "recipe", "build.sh")))}  build.sh`,
      `${digest(await readFile(join(files.upstream, "example.test", "patches", "fix.patch")))}  fix.patch`,
      `${digest(files.archiveBytes)}  lib-1.0.tar.gz`,
      ""
    ].join("\n"));
    assert.deepEqual(await readFile(join(files.destination, "lib-1.0.tar.gz")), files.archiveBytes, "archives are stored opaque and unmodified");

    const verified = run(["verify", files.manifestPath, files.destination]);
    assert.equal(verified.status, 0, verified.stderr);
    assert.match(verified.stderr, /NOT authoritative/u);

    const second = acquire(files, join(files.root, "second", "fixture-materials"));
    assert.notEqual(second.status, 0, "destination parent must already exist");
    await mkdir(join(files.root, "second"), { mode: 0o700 });
    const third = acquire(files, join(files.root, "second", "fixture-materials"));
    assert.equal(third.status, 0, third.stderr);
    assert.equal(await readFile(join(files.root, "second", "fixture-materials", "INVENTORY.json"), "utf8"), inventoryText, "inventory is deterministic");
    assert.equal(await readFile(join(files.root, "second", "fixture-materials", "SHA256SUMS"), "utf8"), sums);
  } finally {
    await rm(files.root, { recursive: true, force: true });
  }
});

test("acquisition fails closed and publishes nothing on drift, missing material, unsafe redirects or unsafe destinations", async (context) => {
  const cases = [
    {
      name: "digest drift",
      mutate: async (files) => { files.manifest.items[2].sha256 = "f".repeat(64); await writeManifest(files); },
      message: /SHA-256 .* differs from the manifest digest/u
    },
    {
      name: "size drift (response longer than pinned)",
      mutate: async (files) => { files.manifest.items[2].size -= 1; await writeManifest(files); },
      message: /exceeds the manifest size/u
    },
    {
      name: "size drift (response shorter than pinned)",
      mutate: async (files) => { files.manifest.items[0].size += 1; await writeManifest(files); },
      message: /received \d+ bytes but the manifest pins/u
    },
    {
      name: "missing upstream material",
      mutate: async (files) => rm(join(files.upstream, "example.test", "patches", "fix.patch")),
      message: /fixture has no bytes for patch-fix/u
    },
    {
      name: "redirect to a host the item does not allow",
      mutate: async (files) => { files.manifest.items[2].allowedRedirectHosts = []; await writeManifest(files); },
      message: /redirect to a host the manifest does not allow \(mirror\.example\.test\)/u
    },
    {
      name: "redirect budget exhausted",
      mutate: async (files) => {
        files.manifest.limits.maximumRedirects = 0;
        await writeManifest(files);
      },
      message: /redirect budget exhausted|redirect to a host/u
    },
    {
      name: "non-HTTPS item URL",
      mutate: async (files) => { files.manifest.items[0].url = "http://example.test/recipe/build.sh"; await writeManifest(files); },
      message: /clean HTTPS URL/u
    },
    {
      name: "item URL with query string",
      mutate: async (files) => { files.manifest.items[0].url = "https://example.test/recipe/build.sh?ref=main"; await writeManifest(files); },
      message: /clean HTTPS URL/u
    },
    {
      name: "duplicate file name",
      mutate: async (files) => { files.manifest.items[1].fileName = "build.sh"; await writeManifest(files); },
      message: /duplicate or invalid fileName/u
    },
    {
      name: "traversing file name",
      mutate: async (files) => { files.manifest.items[1].fileName = "../escape.patch"; await writeManifest(files); },
      message: /duplicate or invalid fileName/u
    },
    {
      name: "unknown item kind",
      mutate: async (files) => { files.manifest.items[1].kind = "binary"; await writeManifest(files); },
      message: /unknown kind/u
    },
    {
      name: "short upstream revision",
      mutate: async (files) => { files.manifest.items[2].upstreamRevision = "1acdbed"; await writeManifest(files); },
      message: /must be one full commit/u
    },
    {
      name: "manifest claiming clearance",
      mutate: async (files) => { files.manifest.purpose = "Fixture manifest that has been fully cleared for release by nobody."; await writeManifest(files); },
      message: /not legal clearance/u
    },
    {
      name: "destination already exists",
      mutate: async (files) => mkdir(files.destination, { mode: 0o700 }),
      message: /destination already exists/u,
      keepsDestination: true
    },
    {
      name: "destination name differs from the manifest",
      mutate: async (files) => { files.destination = join(files.out, "somewhere-else"); },
      message: /destination must be named fixture-materials/u
    },
    {
      name: "symlinked destination parent",
      mutate: async (files) => {
        const target = join(files.root, "real-parent");
        await mkdir(target, { mode: 0o700 });
        await symlink(target, join(files.root, "linked-parent"));
        files.destination = join(files.root, "linked-parent", "fixture-materials");
      },
      message: /must not traverse aliases or symbolic links|is not a real directory/u
    },
    {
      name: "symlinked manifest",
      mutate: async (files) => {
        const target = join(files.root, "manifest-target.json");
        await writeFile(target, JSON.stringify(files.manifest));
        await rm(files.manifestPath);
        await symlink(target, files.manifestPath);
      },
      message: /ELOOP|symbolic link|too many levels/u
    }
  ];
  for (const current of cases) {
    await context.test(current.name, async () => {
      const files = await fixture();
      try {
        await current.mutate(files);
        const result = acquire(files);
        assert.notEqual(result.status, 0, `${current.name} must fail closed`);
        assert.match(result.stderr, current.message);
        const remaining = await listDirectory(files.out);
        if (current.keepsDestination) {
          assert.deepEqual(await listDirectory(files.destination), [], "pre-existing destination is left untouched");
        } else {
          assert.ok(remaining === null || remaining.every((name) => name !== "fixture-materials" && !name.includes(".staging.")),
            `no output or staging directory may remain: ${JSON.stringify(remaining)}`);
        }
      } finally {
        await rm(files.root, { recursive: true, force: true });
      }
    });
  }
});

test("verification fails on tampered, missing, extra or mislabelled output", async (context) => {
  const cases = [
    {
      name: "tampered archive byte",
      mutate: async (files) => {
        const path = join(files.destination, "lib-1.0.tar.gz");
        const bytes = Buffer.from(await readFile(path));
        bytes[bytes.byteLength - 1] ^= 0x01;
        await writeFile(path, bytes);
      },
      message: /SHA-256 drifted/u
    },
    {
      name: "missing item",
      mutate: async (files) => rm(join(files.destination, "fix.patch")),
      message: /missing expected entries/u
    },
    {
      name: "extra entry",
      mutate: async (files) => writeFile(join(files.destination, "extra.bin"), "x"),
      message: /unexpected entry/u
    },
    {
      name: "inventory relabelled as authoritative",
      mutate: async (files) => {
        const path = join(files.destination, "INVENTORY.json");
        const inventory = JSON.parse(await readFile(path, "utf8"));
        inventory.authoritative = true;
        await writeFile(path, `${JSON.stringify(inventory, null, 2)}\n`);
      },
      message: /inventory does not describe this manifest/u
    },
    {
      name: "manifest digest changed after acquisition",
      mutate: async (files) => { files.manifest.items[0].role = "fixture recipe entry point, edited"; await writeManifest(files); },
      message: /inventory does not describe this manifest/u
    },
    {
      name: "checksum list edited",
      mutate: async (files) => writeFile(join(files.destination, "SHA256SUMS"), "tampered\n"),
      message: /checksum list drifted/u
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

test("the tool refuses malformed invocations without touching the destination", async () => {
  const files = await fixture();
  try {
    for (const args of [
      [],
      ["acquire", files.manifestPath],
      ["publish", files.manifestPath, files.destination],
      ["acquire", files.manifestPath, files.destination, "--transport", "ftp"],
      ["verify", files.manifestPath, files.destination, "--transport", `local-fixture:${files.upstream}`]
    ]) {
      const result = run(args);
      assert.notEqual(result.status, 0, JSON.stringify(args));
      assert.match(result.stderr, /usage:|must not traverse|not a real directory/u);
    }
    assert.equal(await listDirectory(files.destination), null);
  } finally {
    await rm(files.root, { recursive: true, force: true });
  }
});
