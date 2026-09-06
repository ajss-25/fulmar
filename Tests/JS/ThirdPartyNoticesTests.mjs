import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  unlink,
  writeFile
} from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";

const project = process.cwd();
const generator = join(project, "scripts", "generate-third-party-notices.mjs");
const template = join(project, "Resources", "THIRD_PARTY_NOTICES.md");

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");

async function fixture() {
  const root = await realpath(await mkdtemp(join(tmpdir(), "fulmar-notices-test.")));
  const runtime = join(root, "Runtime");
  const trackedLicences = join(root, "Resources", "ThirdPartyLicenses");
  const adjacent = join(runtime, "dsh", "node_modules", "with-license");
  const overridden = join(runtime, "dsh", "node_modules", "needs-override");
  await mkdir(adjacent, { recursive: true, mode: 0o700 });
  await mkdir(overridden, { recursive: true, mode: 0o700 });
  await mkdir(trackedLicences, { recursive: true, mode: 0o700 });
  await writeFile(join(adjacent, "package.json"), JSON.stringify({ name: "with-license", version: "1.0.0", license: "MIT" }));
  await writeFile(join(adjacent, "LICENSE"), "adjacent MIT licence\n");
  await writeFile(join(overridden, "package.json"), JSON.stringify({ name: "needs-override", version: "2.0.0", license: "Apache-2.0" }));
  const overrideMaterial = Buffer.from("upstream licence declaration\n");
  const trackedMaterial = Buffer.from("MIT License\n\nCopyright (c) Fixture Author\n");
  await writeFile(join(overridden, "README.md"), overrideMaterial);
  await writeFile(join(trackedLicences, "fixture-LICENSE"), trackedMaterial);
  await writeFile(join(runtime, "NODE_LICENSE"), "Node licence fixture\n");
  await writeFile(join(runtime, "package-lock.json"), JSON.stringify({
    name: "fixture-runtime",
    version: "1.0.0",
    lockfileVersion: 3,
    packages: {
      "": { name: "fixture-runtime", version: "1.0.0" },
      "node_modules/needs-override": { version: "2.0.0", license: "Apache-2.0" },
      "node_modules/optional-absent": { version: "3.0.0", license: "MIT", optional: true },
      "node_modules/with-license": { version: "1.0.0", license: "MIT" }
    }
  }));
  const config = join(root, "Config");
  await mkdir(config, { mode: 0o700 });
  const overrides = join(config, "overrides.json");
  const overrideDocument = {
    schemaVersion: 1,
    overrides: [{
      packagePath: "node_modules/needs-override",
      reason: "The upstream fixture stores its licence declaration in README.md.",
      materials: [{
        path: "dsh/node_modules/needs-override/README.md",
        sha256: digest(overrideMaterial)
      }, {
        sourcePath: "Resources/ThirdPartyLicenses/fixture-LICENSE",
        origin: "https://example.test/upstream/0123456789abcdef/LICENSE",
        upstreamSHA256: digest(trackedMaterial.subarray(0, trackedMaterial.byteLength - 1)),
        normalization: "append-terminal-lf-v1",
        sha256: digest(trackedMaterial)
      }]
    }]
  };
  await writeFile(overrides, `${JSON.stringify(overrideDocument, null, 2)}\n`);
  return {
    root,
    runtime,
    adjacent,
    overridden,
    trackedMaterialPath: join(trackedLicences, "fixture-LICENSE"),
    overrides,
    overrideDocument,
    output: join(root, "THIRD_PARTY_NOTICES.md")
  };
}

function invoke(files, output = files.output) {
  return spawnSync(process.execPath, [generator, template, files.runtime, files.overrides, output], {
    cwd: project,
    encoding: "utf8",
    timeout: 30_000
  });
}

test("notices enumerate only shipped packages and bind every licence payload", async () => {
  const files = await fixture();
  try {
    const result = invoke(files);
    assert.equal(result.status, 0, result.stderr);
    const notices = await readFile(files.output, "utf8");
    assert.match(notices, /contains 2 package paths actually present in the bundled runtime; 1 lockfile-only optional package paths are absent/u);
    assert.match(notices, /dsh\/node_modules\/with-license\/LICENSE/u);
    assert.match(notices, new RegExp(digest("adjacent MIT licence\n"), "u"));
    assert.match(notices, /dsh\/node_modules\/needs-override\/README\.md/u);
    assert.match(notices, /source:Resources\/ThirdPartyLicenses\/fixture-LICENSE/u);
    assert.match(notices, /https:\/\/example\.test\/upstream\/0123456789abcdef\/LICENSE/u);
    assert.match(notices, /Copyright \(c\) Fixture Author/u);
    assert.match(notices, new RegExp(digest(Buffer.from("MIT License\n\nCopyright (c) Fixture Author")), "u"));
    assert.match(notices, new RegExp(digest("MIT License\n\nCopyright (c) Fixture Author\n"), "u"));
    assert.match(notices, /not legal clearance/u);
    assert.doesNotMatch(notices, /\| `dsh\/node_modules\/optional-absent`/u);
  } finally {
    await rm(files.root, { recursive: true, force: true });
  }
});

test("notices fail closed for required-package, override, material, and topology drift", async (context) => {
  const cases = [
    {
      name: "required package missing",
      mutate: async (files) => rm(files.adjacent, { recursive: true }),
      message: /required bundled package is missing/u
    },
    {
      name: "missing reviewed override",
      mutate: async (files) => writeFile(files.overrides, JSON.stringify({ schemaVersion: 1, overrides: [] })),
      message: /no adjacent licence material or reviewed override/u
    },
    {
      name: "stale override after upstream adds a licence",
      mutate: async (files) => writeFile(join(files.overridden, "LICENSE"), "new upstream licence\n"),
      message: /stale licence override is no longer required/u
    },
    {
      name: "mutated override material",
      mutate: async (files) => writeFile(join(files.overridden, "README.md"), "changed material\n"),
      message: /override material SHA-256 drifted/u
    },
    {
      name: "mutated tracked licence material",
      mutate: async (files) => writeFile(files.trackedMaterialPath, "changed tracked terms\n"),
      message: /override material SHA-256 drifted/u
    },
    {
      name: "tracked licence outside bounded source directory",
      mutate: async (files) => {
        files.overrideDocument.overrides[0].materials[1].sourcePath = "Resources/not-a-licence";
        await writeFile(files.overrides, JSON.stringify(files.overrideDocument));
      },
      message: /must remain under Resources\/ThirdPartyLicenses/u
    },
    {
      name: "tracked licence with unclean upstream provenance",
      mutate: async (files) => {
        files.overrideDocument.overrides[0].materials[1].origin = "http://example.test/LICENSE";
        await writeFile(files.overrides, JSON.stringify(files.overrideDocument));
      },
      message: /clean HTTPS upstream provenance/u
    },
    {
      name: "tracked licence with wrong raw upstream digest",
      mutate: async (files) => {
        files.overrideDocument.overrides[0].materials[1].upstreamSHA256 = "0".repeat(64);
        await writeFile(files.overrides, JSON.stringify(files.overrideDocument));
      },
      message: /exact upstream bytes plus one terminal LF/u
    },
    {
      name: "traversing override path",
      mutate: async (files) => {
        files.overrideDocument.overrides[0].materials[0].path = "../outside";
        await writeFile(files.overrides, JSON.stringify(files.overrideDocument));
      },
      message: /unsafe path segment/u
    },
    {
      name: "symlinked override material",
      mutate: async (files) => {
        const readme = join(files.overridden, "README.md");
        const target = join(files.root, "target.md");
        await writeFile(target, "upstream licence declaration\n");
        await unlink(readme);
        await symlink(target, readme);
      },
      message: /ELOOP|symbolic link|too many levels/u
    },
    {
      name: "symlinked tracked licence material",
      mutate: async (files) => {
        const target = join(files.root, "tracked-licence-target");
        await writeFile(target, "MIT License\n\nCopyright (c) Fixture Author\n");
        await unlink(files.trackedMaterialPath);
        await symlink(target, files.trackedMaterialPath);
      },
      message: /ELOOP|symbolic link|too many levels/u
    },
    {
      name: "tracked licence through symlinked parent",
      mutate: async (files) => {
        const sourceDirectory = join(files.root, "Resources", "ThirdPartyLicenses");
        const targetDirectory = join(files.root, "tracked-licences-target");
        await mkdir(targetDirectory, { mode: 0o700 });
        await writeFile(join(targetDirectory, "fixture-LICENSE"), "MIT License\n\nCopyright (c) Fixture Author\n");
        await rm(sourceDirectory, { recursive: true });
        await symlink(targetDirectory, sourceDirectory);
      },
      message: /must not traverse aliases or symbolic links/u
    },
    {
      name: "stale unshipped override",
      mutate: async (files) => {
        files.overrideDocument.overrides.push({
          packagePath: "node_modules/optional-absent",
          reason: "This deliberately stale fixture override must fail closed.",
          materials: [{
            path: "dsh/node_modules/needs-override/README.md",
            sha256: files.overrideDocument.overrides[0].materials[0].sha256
          }]
        });
        await writeFile(files.overrides, JSON.stringify(files.overrideDocument));
      },
      message: /stale or refers to an unshipped package/u
    },
    {
      name: "symlinked adjacent licence",
      mutate: async (files) => {
        const license = join(files.adjacent, "LICENSE");
        const target = join(files.root, "adjacent-target");
        await writeFile(target, "adjacent MIT licence\n");
        await unlink(license);
        await symlink(target, license);
      },
      message: /ELOOP|symbolic link|too many levels/u
    },
    {
      name: "symlinked destination",
      mutate: async (files) => {
        const target = join(files.root, "destination-target");
        await writeFile(target, "do not overwrite\n");
        await symlink(target, files.output);
      },
      message: /unsafe topology/u
    }
  ];

  for (const current of cases) {
    await context.test(current.name, async () => {
      const files = await fixture();
      try {
        await current.mutate(files);
        const result = invoke(files);
        assert.notEqual(result.status, 0, `${current.name} must fail closed`);
        assert.match(result.stderr, current.message);
      } finally {
        await rm(files.root, { recursive: true, force: true });
      }
    });
  }
});

test("pi-ai override binds exact upstream MIT terms and immutable provenance", async () => {
  const config = JSON.parse(await readFile(join(project, "Config", "ThirdPartyLicenseOverrides.json"), "utf8"));
  const entry = config.overrides.find(({ packagePath }) => packagePath === "node_modules/@earendil-works/pi-ai");
  assert.ok(entry, "pi-ai override must exist");
  assert.match(entry.reason, /0\.82\.1/u);
  assert.match(entry.reason, /b4f293684bba718d59cc1157679bcf6157b3a7f5/u);
  assert.match(entry.reason, /modifications recorded in Config\/VendorRuntimePatches\.json/u);

  const material = entry.materials.find(({ sourcePath }) => sourcePath !== undefined);
  assert.deepEqual(material, {
    sourcePath: "Resources/ThirdPartyLicenses/earendil-works-pi-ai-0.82.1-LICENSE",
    origin: "https://github.com/earendil-works/pi/blob/b4f293684bba718d59cc1157679bcf6157b3a7f5/LICENSE",
    upstreamSHA256: "0457f5bcec3b3b211605dfb5d1a49042fd638f3686a410fe099c24a25af13c48",
    normalization: "append-terminal-lf-v1",
    sha256: "4f6a1985796db5225e3b1e59972bd47e07a27a0748427cb3d3c8fbf39f9311f0"
  });
  const terms = await readFile(join(project, material.sourcePath));
  assert.equal(digest(terms), material.sha256);
  assert.match(terms.toString("utf8"), /^MIT License\n\nCopyright \(c\) 2025 Mario Zechner\n/u);
  assert.match(terms.toString("utf8"), /The above copyright notice and this permission notice shall be included in all\ncopies or substantial portions/u);
});

test("sharp-libvips override binds the exact component manifest, versions and LGPL texts without claiming clearance", async () => {
  const config = JSON.parse(await readFile(join(project, "Config", "ThirdPartyLicenseOverrides.json"), "utf8"));
  const entry = config.overrides.find(({ packagePath }) => packagePath === "node_modules/@img/sharp-libvips-darwin-arm64");
  assert.ok(entry, "sharp-libvips override must exist");
  assert.match(entry.reason, /1\.3\.2/u);
  assert.match(entry.reason, /remain recorded in Config\/ThirdPartyBinaryProvenance\.json as an open legal gate/u);
  assert.doesNotMatch(entry.reason, /cleared|satisfied|compliant/iu);
  assert.deepEqual(entry.materials.map((material) => material.path ?? `source:${material.sourcePath}`), [
    "dsh/node_modules/@img/sharp-libvips-darwin-arm64/README.md",
    "dsh/node_modules/@img/sharp-libvips-darwin-arm64/versions.json",
    "source:Resources/ThirdPartyLicenses/libvips-8.18.3-LICENSE",
    "source:Resources/ThirdPartyLicenses/sharp-libvips-1.3.2-LGPL-3.0-only-spdx-3.28.0"
  ]);
  for (const material of entry.materials.filter(({ sourcePath }) => sourcePath !== undefined)) {
    assert.equal(material.normalization, "append-terminal-lf-v1");
    assert.match(material.origin, /^https:\/\/github\.com\/[^/]+\/[^/]+\/blob\/[a-f0-9]{40}\//u, "tracked terms are pinned to an immutable commit");
    const terms = await readFile(join(project, material.sourcePath));
    assert.equal(digest(terms), material.sha256, material.sourcePath);
    assert.equal(digest(terms.subarray(0, terms.byteLength - 1)), material.upstreamSHA256, material.sourcePath);
  }
});

test("release call sites bind the runtime root and authoritative override config", async () => {
  for (const path of [
    "scripts/build-app.sh",
    "scripts/verify-release.sh",
    "scripts/prepare-public-release-assets.sh",
    "scripts/verify-public-distribution.sh"
  ]) {
    const source = await readFile(join(project, path), "utf8");
    assert.match(source, /generate-third-party-notices\.mjs/u, path);
    assert.match(source, /Config\/ThirdPartyLicenseOverrides\.json/u, path);
    assert.doesNotMatch(source, /generate-third-party-notices\.mjs"[\s\\\n]+[^\n]*package-lock\.json/u, path);
  }
});
