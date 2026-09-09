import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  cp,
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
import { gzipSync } from "node:zlib";
import test from "node:test";

const project = process.cwd();
const generator = join(project, "scripts", "generate-third-party-notices.mjs");
const materialsTool = join(project, "scripts", "prepare-libvips-source-materials.mjs");
const template = join(project, "Resources", "THIRD_PARTY_NOTICES.md");

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");

async function fixture() {
  const root = await realpath(await mkdtemp(join(tmpdir(), "fulmar-notices-test.")));
  const runtime = join(root, "Runtime");
  const trackedLicences = join(root, "Resources", "ThirdPartyLicenses");
  const adjacent = join(runtime, "dsh", "node_modules", "with-license");
  const overridden = join(runtime, "dsh", "node_modules", "needs-override");
  const binary = join(runtime, "dsh", "node_modules", "@fixture", "combined-binary");
  const componentLicences = join(trackedLicences, "combined-binary-1.0.0");
  await mkdir(adjacent, { recursive: true, mode: 0o700 });
  await mkdir(overridden, { recursive: true, mode: 0o700 });
  await mkdir(binary, { recursive: true, mode: 0o700 });
  await mkdir(trackedLicences, { recursive: true, mode: 0o700 });
  await mkdir(componentLicences, { recursive: true, mode: 0o700 });
  await writeFile(join(adjacent, "package.json"), JSON.stringify({ name: "with-license", version: "1.0.0", license: "MIT" }));
  await writeFile(join(adjacent, "LICENSE"), "adjacent MIT licence\n");
  await writeFile(join(overridden, "package.json"), JSON.stringify({ name: "needs-override", version: "2.0.0", license: "Apache-2.0" }));
  const overrideMaterial = Buffer.from("upstream licence declaration\n");
  const trackedMaterial = Buffer.from("MIT License\n\nCopyright (c) Fixture Author\n");
  await writeFile(join(overridden, "README.md"), overrideMaterial);
  await writeFile(join(trackedLicences, "fixture-LICENSE"), trackedMaterial);
  await writeFile(join(runtime, "NODE_LICENSE"), "Node licence fixture\n");
  await writeFile(join(binary, "package.json"), JSON.stringify({ name: "@fixture/combined-binary", version: "1.0.0", license: "LGPL-3.0-or-later" }));
  const binaryManifest = Buffer.from("| alpha | MIT |\n| beta | zlib |\n| gamma | MIT |\n");
  await writeFile(join(binary, "README.md"), binaryManifest);
  const alphaNotice = Buffer.from("MIT License\n\nCopyright (c) Alpha Authors\n");
  const betaNotice = Buffer.from("zlib License\n\nCopyright (c) Beta Authors\n");
  const gammaNotice = Buffer.from("MIT License\n\nCopyright (c) Gamma Authors (vendored)\n");
  await writeFile(join(componentLicences, "alpha-1.2.3-LICENSE"), alphaNotice);
  await writeFile(join(componentLicences, "beta-4.5-COPYING"), betaNotice);
  await writeFile(join(componentLicences, "gamma-vendored-COPYING"), gammaNotice);
  const componentMaterial = (name, sourcePath, bytes, member) => ({
    sourcePath,
    describes: `${name} fixture notice text`,
    origin: `https://example.test/${name}/blob/${"c".repeat(40)}/${sourcePath.split("/").at(-1)}`,
    upstreamSHA256: digest(bytes.subarray(0, bytes.byteLength - 1)),
    normalization: "append-terminal-lf-v1",
    sha256: digest(bytes),
    archiveMember: member,
    archiveSHA256: "d".repeat(64)
  });
  const provenanceDocument = {
    schemaVersion: 1,
    purpose: "Fixture provenance record; not legal clearance.",
    components: [{
      id: "combined-binary",
      packageName: "@fixture/combined-binary",
      version: "1.0.0",
      lockfilePath: "node_modules/@fixture/combined-binary",
      componentVersions: { alpha: "1.2.3", beta: "4.5" },
      manifestLibraries: ["alpha", "beta", "gamma"],
      manifestDiscrepancy: {
        librariesWithoutVersionKey: ["gamma"],
        resolution: "gamma is vendored inside alpha and has no separately pinned version in this fixture."
      },
      componentNotices: [
        {
          component: "alpha", versionKey: "alpha", version: "1.2.3", manifestLicense: "MIT",
          upstreamRepository: "https://example.test/alpha", upstreamRevision: "a".repeat(40),
          revisionEvidence: "fixture tag resolution recorded for the test",
          materials: [componentMaterial("alpha", "Resources/ThirdPartyLicenses/combined-binary-1.0.0/alpha-1.2.3-LICENSE", alphaNotice, "alpha-1.2.3/LICENSE")]
        },
        {
          component: "beta", versionKey: "beta", version: "4.5", manifestLicense: "zlib",
          upstreamRepository: "https://example.test/beta", upstreamRevision: "b".repeat(40),
          revisionEvidence: "fixture tag resolution recorded for the test",
          materials: [componentMaterial("beta", "Resources/ThirdPartyLicenses/combined-binary-1.0.0/beta-4.5-COPYING", betaNotice, "beta-4.5/COPYING")]
        },
        {
          component: "gamma", versionKey: null, version: null, manifestLicense: "MIT",
          upstreamRepository: "https://example.test/alpha", upstreamRevision: "a".repeat(40),
          revisionEvidence: "fixture tag resolution recorded for the test",
          note: "gamma is vendored inside the alpha tree; the alpha archive is its source and no gamma version is asserted.",
          materials: [componentMaterial("gamma", "Resources/ThirdPartyLicenses/combined-binary-1.0.0/gamma-vendored-COPYING", gammaNotice, "alpha-1.2.3/vendor/gamma/COPYING")]
        }
      ]
    }]
  };
  await writeFile(join(runtime, "package-lock.json"), JSON.stringify({
    name: "fixture-runtime",
    version: "1.0.0",
    lockfileVersion: 3,
    packages: {
      "": { name: "fixture-runtime", version: "1.0.0" },
      "node_modules/@fixture/combined-binary": { version: "1.0.0", license: "LGPL-3.0-or-later", optional: true },
      "node_modules/needs-override": { version: "2.0.0", license: "Apache-2.0" },
      "node_modules/optional-absent": { version: "3.0.0", license: "MIT", optional: true },
      "node_modules/with-license": { version: "1.0.0", license: "MIT" }
    }
  }));
  const config = join(root, "Config");
  await mkdir(config, { mode: 0o700 });
  const provenance = join(config, "provenance.json");
  await writeFile(provenance, `${JSON.stringify(provenanceDocument, null, 2)}\n`);
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
    }, {
      packagePath: "node_modules/@fixture/combined-binary",
      reason: "The fixture combined binary ships only a component licence table; its exact per-component notices are bound from the fixture provenance record.",
      componentNotices: { manifest: "Config/provenance.json", component: "combined-binary" },
      materials: [{ path: "dsh/node_modules/@fixture/combined-binary/README.md", sha256: digest(binaryManifest) }]
    }]
  };
  await writeFile(overrides, `${JSON.stringify(overrideDocument, null, 2)}\n`);
  return {
    root,
    runtime,
    adjacent,
    overridden,
    binary,
    componentLicences,
    trackedMaterialPath: join(trackedLicences, "fixture-LICENSE"),
    overrides,
    overrideDocument,
    provenance,
    provenanceDocument,
    output: join(root, "THIRD_PARTY_NOTICES.md")
  };
}

async function writeOverrides(files) {
  await writeFile(files.overrides, JSON.stringify(files.overrideDocument));
}

async function writeProvenance(files) {
  await writeFile(files.provenance, JSON.stringify(files.provenanceDocument));
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
    assert.match(notices, /contains 3 package paths actually present in the bundled runtime; 1 lockfile-only optional package paths are absent/u);
    assert.match(notices, /It additionally binds 3 exact per-component notice texts for redistributed combined binaries/u);
    assert.match(notices, /## Exact per-component notices for redistributed binaries/u);
    assert.match(notices, /### `node_modules\/@fixture\/combined-binary`/u);
    assert.match(notices, /component `combined-binary`: 3 components, 3 notice materials, 3 distinct texts\./u);
    assert.match(notices, /\| `alpha` \| `1\.2\.3` \| MIT \| `https:\/\/example\.test\/alpha` @ `a{40}` \| `Resources\/ThirdPartyLicenses\/combined-binary-1\.0\.0\/alpha-1\.2\.3-LICENSE` \|/u);
    assert.match(notices, /\| `gamma` \| vendored \(no separate version\) \| MIT \|/u);
    assert.match(notices, /Copyright \(c\) Alpha Authors/u);
    assert.match(notices, /Copyright \(c\) Beta Authors/u);
    assert.match(notices, /Copyright \(c\) Gamma Authors \(vendored\)/u);
    assert.match(notices, /Source archive member: `alpha-1\.2\.3\/LICENSE` of archive `sha256:d{64}`/u);
    assert.match(notices, new RegExp(`Component notice manifest: \`Config/provenance\\.json\` \\(\`sha256:${digest(await readFile(files.provenance))}\`\\)`, "u"));
    const again = invoke(files, join(files.root, "again.md"));
    assert.equal(again.status, 0, again.stderr);
    assert.equal(await readFile(join(files.root, "again.md"), "utf8"), notices, "output is deterministic");
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
        await cp(files.componentLicences, join(targetDirectory, "combined-binary-1.0.0"), { recursive: true });
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
    },
    {
      name: "component notice material missing on disk",
      mutate: async (files) => rm(join(files.componentLicences, "beta-4.5-COPYING")),
      message: /ENOENT|no such file/u
    },
    {
      name: "component notice material mutated",
      mutate: async (files) => writeFile(join(files.componentLicences, "beta-4.5-COPYING"), "zlib License\n\nCopyright (c) Someone Else\n"),
      message: /override material SHA-256 drifted: node_modules\/@fixture\/combined-binary component beta/u
    },
    {
      name: "component notice with wrong raw upstream digest",
      mutate: async (files) => {
        files.provenanceDocument.components[0].componentNotices[0].materials[0].upstreamSHA256 = "0".repeat(64);
        await writeProvenance(files);
      },
      message: /exact upstream bytes plus one terminal LF: node_modules\/@fixture\/combined-binary component alpha/u
    },
    {
      name: "component notice version drifted from the pinned component version",
      mutate: async (files) => {
        files.provenanceDocument.components[0].componentNotices[0].version = "1.2.4";
        await writeProvenance(files);
      },
      message: /version does not equal the exact pinned component version/u
    },
    {
      name: "component notice missing for a manifest library",
      mutate: async (files) => {
        files.provenanceDocument.components[0].componentNotices.pop();
        await writeProvenance(files);
      },
      message: /missing for upstream licence-manifest libraries: node_modules\/@fixture\/combined-binary -> gamma/u
    },
    {
      name: "component notice missing for a pinned version",
      mutate: async (files) => {
        const component = files.provenanceDocument.components[0];
        component.componentVersions.delta = "9.9";
        await writeProvenance(files);
      },
      message: /missing for pinned component versions: node_modules\/@fixture\/combined-binary -> delta/u
    },
    {
      name: "duplicate component notice",
      mutate: async (files) => {
        const notices = files.provenanceDocument.components[0].componentNotices;
        notices.push({ ...notices[0], materials: [{ ...notices[0].materials[0], sourcePath: "Resources/ThirdPartyLicenses/combined-binary-1.0.0/alpha-copy" }] });
        await writeProvenance(files);
      },
      message: /duplicate or invalid component name/u
    },
    {
      name: "component notice for an unknown library",
      mutate: async (files) => {
        const notices = files.provenanceDocument.components[0].componentNotices;
        notices.push({ ...notices[1], component: "omega", versionKey: null, version: null, note: "omega is not named by the fixture manifest at all and must be rejected." });
        await writeProvenance(files);
      },
      message: /absent from the upstream licence manifest/u
    },
    {
      name: "version-less component notice not listed as a resolved discrepancy",
      mutate: async (files) => {
        files.provenanceDocument.components[0].manifestDiscrepancy.librariesWithoutVersionKey = [];
        await writeProvenance(files);
      },
      message: /must be an explicitly resolved discrepancy/u
    },
    {
      name: "component notice material path traversal",
      mutate: async (files) => {
        files.provenanceDocument.components[0].componentNotices[0].materials[0].sourcePath = "Resources/ThirdPartyLicenses/../../outside";
        await writeProvenance(files);
      },
      message: /unsafe path segment/u
    },
    {
      name: "component notice material outside the tracked licence directory",
      mutate: async (files) => {
        files.provenanceDocument.components[0].componentNotices[0].materials[0].sourcePath = "Config/provenance.json";
        await writeProvenance(files);
      },
      message: /must be one unique tracked file under Resources\/ThirdPartyLicenses/u
    },
    {
      name: "component notice material bound twice",
      mutate: async (files) => {
        const notices = files.provenanceDocument.components[0].componentNotices;
        notices[1].materials[0] = { ...notices[0].materials[0] };
        await writeProvenance(files);
      },
      message: /must be one unique tracked file under Resources\/ThirdPartyLicenses/u
    },
    {
      name: "component notice with short upstream revision",
      mutate: async (files) => {
        files.provenanceDocument.components[0].componentNotices[0].upstreamRevision = "1acdbed";
        await writeProvenance(files);
      },
      message: /must pin one full upstream revision/u
    },
    {
      name: "component notice origin with query string",
      mutate: async (files) => {
        files.provenanceDocument.components[0].componentNotices[0].materials[0].origin += "?raw=1";
        await writeProvenance(files);
      },
      message: /clean HTTPS upstream provenance URL/u
    },
    {
      name: "component notice material with unexpected field",
      mutate: async (files) => {
        files.provenanceDocument.components[0].componentNotices[0].materials[0].legalClearance = true;
        await writeProvenance(files);
      },
      message: /unexpected shape/u
    },
    {
      name: "component notice reference to a manifest outside Config",
      mutate: async (files) => {
        files.overrideDocument.overrides[1].componentNotices.manifest = "Resources/provenance.json";
        await writeOverrides(files);
      },
      message: /must be one tracked JSON document under Config/u
    },
    {
      name: "component notice reference to an unknown component",
      mutate: async (files) => {
        files.overrideDocument.overrides[1].componentNotices.component = "other-binary";
        await writeOverrides(files);
      },
      message: /must describe the referenced component exactly once/u
    },
    {
      name: "component notice manifest describing a different package",
      mutate: async (files) => {
        files.provenanceDocument.components[0].lockfilePath = "node_modules/@fixture/other";
        await writeProvenance(files);
      },
      message: /does not describe this package/u
    },
    {
      name: "component notice manifest without notices",
      mutate: async (files) => {
        files.provenanceDocument.components[0].componentNotices = [];
        await writeProvenance(files);
      },
      message: /carries no bounded per-component notices/u
    },
    {
      name: "symlinked component notice manifest",
      mutate: async (files) => {
        const target = join(files.root, "provenance-target.json");
        await writeFile(target, JSON.stringify(files.provenanceDocument));
        await unlink(files.provenance);
        await symlink(target, files.provenance);
      },
      message: /ELOOP|symbolic link|too many levels/u
    },
    {
      name: "symlinked component notice material",
      mutate: async (files) => {
        const material = join(files.componentLicences, "alpha-1.2.3-LICENSE");
        const target = join(files.root, "alpha-target");
        await writeFile(target, "MIT License\n\nCopyright (c) Alpha Authors\n");
        await unlink(material);
        await symlink(target, material);
      },
      message: /ELOOP|symbolic link|too many levels/u
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
  assert.match(entry.reason, /1\.3\.3/u);
  assert.match(entry.reason, /remain recorded in Config\/ThirdPartyBinaryProvenance\.json as an open legal gate/u);
  assert.doesNotMatch(entry.reason, /cleared|satisfied|compliant/iu);
  assert.deepEqual(entry.materials.map((material) => material.path ?? `source:${material.sourcePath}`), [
    "dsh/node_modules/@img/sharp-libvips-darwin-arm64/README.md",
    "dsh/node_modules/@img/sharp-libvips-darwin-arm64/versions.json",
    "source:Resources/ThirdPartyLicenses/libvips-8.18.6-LICENSE",
    "source:Resources/ThirdPartyLicenses/sharp-libvips-1.3.2-LGPL-3.0-only-spdx-3.28.0"
  ]);
  assert.deepEqual(entry.componentNotices, { manifest: "Config/ThirdPartyBinaryProvenance.json", component: "sharp-libvips-darwin-arm64" },
    "per-component notices are bound from the tracked provenance record");
  for (const material of entry.materials.filter(({ sourcePath }) => sourcePath !== undefined)) {
    assert.equal(material.normalization, "append-terminal-lf-v1");
    assert.match(material.origin, /^https:\/\/github\.com\/[^/]+\/[^/]+\/blob\/[a-f0-9]{40}\//u, "tracked terms are pinned to an immutable commit");
    const terms = await readFile(join(project, material.sourcePath));
    assert.equal(digest(terms), material.sha256, material.sourcePath);
    assert.equal(digest(terms.subarray(0, terms.byteLength - 1)), material.upstreamSHA256, material.sourcePath);
  }
});

// End-to-end run of the generator over the REAL sharp-libvips override entry,
// provenance record and tracked component notice files, with a synthetic
// runtime standing in for the reconstructed bundle (the runtime material
// digests are recomputed from the fixture bytes; every tracked source digest is
// the real one). This proves the tracked material is bindable without the
// shared build root. The real record also declares Rust crate delivery
// materials, whose verified .crate archives are private build inputs and not
// tracked: with the record intact the generator must fail closed and name the
// missing operand; the component-notice path is then exercised over a copy of
// the record with that declaration removed (the delivery path itself is proven
// by the fixture tests above).
test("sharp-libvips per-component notices bind end to end from the tracked provenance record", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "fulmar-notices-real.")));
  try {
    const runtime = join(root, "Runtime");
    const packageDirectory = join(runtime, "dsh", "node_modules", "@img", "sharp-libvips-darwin-arm64");
    await mkdir(packageDirectory, { recursive: true, mode: 0o700 });
    await mkdir(join(root, "Config"), { mode: 0o700 });
    await mkdir(join(root, "Resources"), { mode: 0o700 });
    await cp(join(project, "Resources", "ThirdPartyLicenses"), join(root, "Resources", "ThirdPartyLicenses"), { recursive: true });
    const realProvenance = JSON.parse(await readFile(join(project, "Config", "ThirdPartyBinaryProvenance.json"), "utf8"));
    assert.ok(realProvenance.components[0].deliveryMaterials, "the real record declares Rust crate delivery materials");
    for (const name of ["SharpLibvipsRustProvenance.json", "SharpLibvipsRustNoticeMaterials.json", "SharpLibvipsSourceMaterials.json"]) {
      await cp(join(project, "Config", name), join(root, "Config", name));
    }
    await cp(join(project, "Config", "ThirdPartyBinaryProvenance.json"), join(root, "Config", "ThirdPartyBinaryProvenance.json"));
    const readme = Buffer.from("# fixture manifest stand-in\n");
    const versions = Buffer.from("{}\n");
    await writeFile(join(packageDirectory, "README.md"), readme);
    await writeFile(join(packageDirectory, "versions.json"), versions);
    await writeFile(join(packageDirectory, "package.json"), JSON.stringify({ name: "@img/sharp-libvips-darwin-arm64", version: "1.3.3", license: "LGPL-3.0-or-later" }));
    await writeFile(join(runtime, "NODE_LICENSE"), "Node licence fixture\n");
    await writeFile(join(runtime, "package-lock.json"), JSON.stringify({
      name: "fixture-runtime", version: "1.0.0", lockfileVersion: 3,
      packages: {
        "": { name: "fixture-runtime", version: "1.0.0" },
        "node_modules/@img/sharp-libvips-darwin-arm64": { version: "1.3.3", license: "LGPL-3.0-or-later", optional: true }
      }
    }));
    const config = JSON.parse(await readFile(join(project, "Config", "ThirdPartyLicenseOverrides.json"), "utf8"));
    const entry = structuredClone(config.overrides.find(({ packagePath }) => packagePath === "node_modules/@img/sharp-libvips-darwin-arm64"));
    for (const material of entry.materials) {
      if (material.path?.endsWith("README.md")) material.sha256 = digest(readme);
      if (material.path?.endsWith("versions.json")) material.sha256 = digest(versions);
    }
    const overrides = join(root, "Config", "overrides.json");
    await writeFile(overrides, JSON.stringify({ schemaVersion: 1, overrides: [entry] }));
    const output = join(root, "THIRD_PARTY_NOTICES.md");
    // With the real record intact, the declared Rust crate materials are a
    // required explicit input: the old invocation fails closed and names the seam.
    const withoutMaterials = spawnSync(process.execPath, [generator, template, runtime, overrides, output], { cwd: project, encoding: "utf8", timeout: 60_000 });
    assert.notEqual(withoutMaterials.status, 0, "the production record must not generate without the verified Rust crate materials");
    assert.match(withoutMaterials.stderr, /component sharp-libvips-darwin-arm64 \(node_modules\/@img\/sharp-libvips-darwin-arm64\) declares Rust crate delivery materials; pass --rust-crate-materials <verified sharp-libvips-1\.3\.3-rust-crate-materials directory> \(acquired and verified by scripts\/prepare-libvips-source-materials\.mjs with --notice-materials Config\/SharpLibvipsRustNoticeMaterials\.json\)/u);
    await assert.rejects(() => readFile(output), /ENOENT/u, "no partial notices file is written");
    // The component-notice path over the real record without the delivery declaration.
    const componentOnly = structuredClone(realProvenance);
    delete componentOnly.components[0].deliveryMaterials;
    await writeFile(join(root, "Config", "ThirdPartyBinaryProvenance.json"), `${JSON.stringify(componentOnly, null, 2)}\n`);
    const result = spawnSync(process.execPath, [generator, template, runtime, overrides, output], { cwd: project, encoding: "utf8", timeout: 60_000 });
    assert.equal(result.status, 0, result.stderr);
    const notices = await readFile(output, "utf8");
    assert.doesNotMatch(notices, /## Rust crate notices for redistributed binaries/u, "no Rust section is rendered without the declaration and its verified inputs");
    const provenance = JSON.parse(await readFile(join(project, "Config", "ThirdPartyBinaryProvenance.json"), "utf8")).components[0];
    const materialCount = provenance.componentNotices.reduce((total, notice) => total + notice.materials.length, 0);
    const distinct = new Set(provenance.componentNotices.flatMap((notice) => notice.materials.map((material) => material.sha256))).size;
    assert.match(notices, new RegExp(`component \`sharp-libvips-darwin-arm64\`: ${provenance.componentNotices.length} components, ${materialCount} notice materials, ${distinct} distinct texts\\.`, "u"));
    for (const notice of provenance.componentNotices) {
      assert.ok(notices.includes(`| \`${notice.component}\` | `), notice.component);
      for (const material of notice.materials) {
        assert.ok(notices.includes(material.sha256), material.sourcePath);
        assert.ok(notices.includes(material.origin), material.sourcePath);
      }
    }
    assert.match(notices, /Copyright \(C\) 2004 Richard Wilson/u, "libnsgif notice text is embedded");
    assert.match(notices, /Alliance for Open Media Patent License 1\.0/u);
    assert.match(notices, /Text identical to `Resources\/ThirdPartyLicenses\/libvips-8\.18\.6-LICENSE` embedded above; not repeated\./u);
    assert.doesNotMatch(notices, /legal clearance is granted|licence[- ]cleared/iu);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("release call sites bind the runtime root and authoritative override config", async () => {
  // Every caller binds the same literal checkout-local cache, verifies it with
  // the integration glue before regenerating, hands the exact operand to the
  // generator and never acquires or falls back to unbound notices.
  const crateManifest = JSON.parse(await readFile(join(project, "Config", "SharpLibvipsRustProvenance.json"), "utf8"));
  const literal = `RUST_CRATE_MATERIALS="$PROJECT_DIR/build/third-party-notice-materials/${crateManifest.outputDirectoryName}"`;
  assert.equal(crateManifest.outputDirectoryName, "sharp-libvips-1.3.3-rust-crate-materials");
  const verification = /"\$(?:NODE_BIN|INVENTORY_NODE|NODE)" "\$NOTICE_MATERIALS_TOOL" verify "\$PROJECT_DIR" "\$RUST_CRATE_MATERIALS"\n/u;
  const generation = /generate-third-party-notices\.mjs" \\\n(?:  [^\n]*\\\n)*  --rust-crate-materials "\$RUST_CRATE_MATERIALS"\n/u;
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
    assert.ok(source.includes(literal), `${path} must bind the literal checkout-local notice-material cache`);
    assert.ok(source.includes('NOTICE_MATERIALS_TOOL="$PROJECT_DIR/scripts/prepare-third-party-notice-materials.mjs"'), path);
    assert.equal((source.match(/generate-third-party-notices\.mjs/gu) ?? []).length, 1, `${path} regenerates notices exactly once`);
    assert.match(source, generation, `${path} must pass the exact materials operand to the generator`);
    const verificationOffset = source.search(verification);
    assert.ok(verificationOffset >= 0, `${path} must verify the notice-material cache with the integration glue`);
    assert.ok(verificationOffset < source.indexOf("generate-third-party-notices.mjs"), `${path} must verify the cache before regenerating notices`);
    assert.ok(verificationOffset > source.indexOf("node-v22.23.1-darwin-arm64/bin/node"), `${path} must locate the pinned Node before verifying the cache`);
    assert.doesNotMatch(source, /prepare-third-party-notice-materials\.mjs" prepare|prepare-libvips-source-materials\.mjs|--transport|--notice-materials/u, `${path} must never acquire notice materials`);
  }
  const bootstrap = await readFile(join(project, "scripts", "bootstrap-source-checkout.sh"), "utf8");
  assert.ok(bootstrap.includes('run_pinned_node "$PROJECT_DIR/scripts/prepare-third-party-notice-materials.mjs" prepare "$PROJECT_DIR"'));
  assert.doesNotMatch(bootstrap, /generate-third-party-notices\.mjs|--rust-crate-materials/u, "the bootstrap prepares the cache but never renders notices");
});

// ---------------------------------------------------------------------------
// Delivery material bindings: when the provenance record declares them, the
// verified Rust crate materials become a required explicit generator input.
// The fixtures below build synthetic .crate archives, a crate manifest, a
// notice-materials manifest (one crate with an archive-contained notice plus an
// external SPDX text, one with an external upstream file, one unresolved), a
// corresponding-source manifest and an acknowledgement document, acquire the
// crates through the materials tool's local-fixture transport, and run the
// generator over the result. No network, no real archives, no legal conclusion.

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
const BETA_COMMIT = "2".repeat(40);
const DELTA_COMMIT = "3".repeat(40);
const SPDX_COMMIT = "4".repeat(40);
const MPL_HEADER = "/* This Source Code Form is subject to the terms of the Mozilla Public\n * License, v. 2.0. If a copy of the MPL was not distributed with this\n * file, You can obtain one at https://mozilla.org/MPL/2.0/. */";

function crateItem(name, version, bytes, extra) {
  return {
    id: `crate-${name}-${version}`, kind: "rust-crate", crateName: name, crateVersion: version, fileName: `${name}-${version}.crate`,
    url: `https://static.crates.io/crates/${name}/${name}-${version}.crate`, size: bytes.byteLength, sha256: digest(bytes), allowedRedirectHosts: [],
    immutability: "crates-io-immutable-crate-file", registry: "https://github.com/rust-lang/crates.io-index",
    checksumSource: "fixture Cargo.lock checksum recorded for the test", role: "normal", provenanceStatus: "resolved-approximation", ...extra
  };
}

async function deliveryFixture() {
  const files = await fixture();
  const { root } = files;
  const rustLicences = join(root, "Resources", "ThirdPartyLicenses", "combined-binary-1.0.0", "rust");
  await mkdir(rustLicences, { mode: 0o700 });
  await mkdir(join(root, "docs"), { mode: 0o700 });
  await mkdir(join(root, "materials"), { mode: 0o700 });
  // Crates: alpha carries a licence member; beta carries only per-file MPL headers
  // (archive-contained notice plus external SPDX text); gamma carries none but its
  // upstream repository LICENSE at the packaged revision is retained (external
  // upstream file); delta carries none and remains unresolved.
  const alphaLicence = Buffer.from("MIT License\n\nCopyright (c) Alpha Crate Authors\n");
  const alpha = crateArchive([
    ["alpha-1.2.3/Cargo.toml", Buffer.from("[package]\nname = \"alpha\"\nversion = \"1.2.3\"\nlicense = \"MIT\"\n")],
    ["alpha-1.2.3/LICENSE-MIT", alphaLicence],
    ["alpha-1.2.3/src/lib.rs", Buffer.from("pub fn alpha() {}\n")]
  ]);
  const betaLib = Buffer.from(`${MPL_HEADER}\n\npub fn beta() {}\n`);
  const beta = crateArchive([
    ["beta-0.9.0/Cargo.toml", Buffer.from("[package]\nname = \"beta\"\nversion = \"0.9.0\"\nlicense = \"MPL-2.0\"\n")],
    ["beta-0.9.0/src/lib.rs", betaLib]
  ]);
  const gamma = crateArchive([
    ["gamma-2.0.0/Cargo.toml", Buffer.from("[package]\nname = \"gamma\"\nversion = \"2.0.0\"\nlicense = \"MIT\"\n")],
    ["gamma-2.0.0/src/lib.rs", Buffer.from("pub fn gamma() {}\n")]
  ]);
  const delta = crateArchive([
    ["delta-0.1.0/Cargo.toml", Buffer.from("[package]\nname = \"delta\"\nversion = \"0.1.0\"\nlicense = \"MIT\"\n")],
    ["delta-0.1.0/src/lib.rs", Buffer.from("pub fn delta() {}\n")]
  ]);
  const put = async (url, bytes) => {
    const parsed = new URL(url);
    const path = join(root, "upstream", parsed.hostname, ...parsed.pathname.split("/").filter(Boolean));
    await mkdir(join(path, ".."), { recursive: true, mode: 0o700 });
    await writeFile(path, bytes);
  };
  for (const [name, version, bytes] of [["alpha", "1.2.3", alpha], ["beta", "0.9.0", beta], ["gamma", "2.0.0", gamma], ["delta", "0.1.0", delta]]) {
    await put(`https://static.crates.io/crates/${name}/${name}-${version}.crate`, bytes);
  }
  const binary = {
    packageName: "@fixture/combined-binary", version: "1.0.0", buildRepository: "https://example.test/build", buildTag: "v1.0.0",
    buildCommit: FIXTURE_COMMIT, buildPlatform: "darwin-arm64v8", shippedBinary: "node_modules/@fixture/combined-binary/lib/lib.dylib",
    shippedBinarySHA256: "1".repeat(64), provenanceRecord: "Config/provenance.json"
  };
  const crateManifest = {
    schemaVersion: 1,
    purpose: "Fixture rust-crate manifest: an approximation for hermetic tests; not legal clearance and not a corresponding-source offer.",
    binary,
    outputDirectoryName: "fixture-rust-materials",
    limits: { maximumFileBytes: 1048576, maximumTotalBytes: 8388608, maximumRedirects: 0, requestTimeoutMilliseconds: 5000 },
    categories: {
      resolvedForTargetApproximation: { workspaceMembers: ["fixture-workspace 1.0.0 (root)"] },
      compiledInHistoricalBuild: { status: "unverified", detail: "fixture" },
      incorporatedIntoShippedBinary: { status: "unverified", detail: "fixture" }
    },
    items: [
      crateItem("alpha", "1.2.3", alpha, { licenseExpression: "MIT", authors: ["Alpha Author"], noticeMembers: [{ member: "alpha-1.2.3/LICENSE-MIT", size: alphaLicence.byteLength, sha256: digest(alphaLicence) }], noticeStatus: "crate-carries-licence-text" }),
      crateItem("beta", "0.9.0", beta, { licenseExpression: "MPL-2.0", noticeMembers: [], noticeStatus: "no-licence-text-in-crate" }),
      crateItem("delta", "0.1.0", delta, { licenseExpression: "MIT", authors: ["Delta Author"], noticeMembers: [], noticeStatus: "no-licence-text-in-crate" }),
      crateItem("gamma", "2.0.0", gamma, { licenseExpression: "MIT", noticeMembers: [], noticeStatus: "no-licence-text-in-crate" })
    ],
    unretained: [{ id: "historical-compile-log", detail: "Fixture: the historical compile log was not retrieved." }]
  };
  const sourceManifest = {
    schemaVersion: 1,
    purpose: "Fixture corresponding-source manifest for hermetic tests. It identifies material; it is not legal clearance and is not a corresponding-source offer.",
    binary,
    outputDirectoryName: "fixture-source-materials",
    limits: { maximumFileBytes: 65536, maximumTotalBytes: 1048576, maximumRedirects: 0, requestTimeoutMilliseconds: 5000 },
    items: [{ id: "recipe-build-sh", kind: "build-recipe", fileName: "build.sh", url: "https://example.test/recipe/build.sh", size: 16, sha256: "a".repeat(64), allowedRedirectHosts: [], immutability: "commit-pinned-raw-file", role: "fixture recipe entry point" }],
    unretained: [{ id: "rebuild-not-attempted", component: "all", detail: "No build was attempted by this fixture." }]
  };
  const gammaUpstream = Buffer.from("MIT License\n\nCopyright (c) Gamma Crate Upstream\n\nPermission is hereby granted to use this fixture licence.\n");
  const mplText = Buffer.from("Mozilla Public License Version 2.0 (fixture text)\n\n1. Definitions\n\nThis fixture stands in for the SPDX licence text; permission terms follow.\n");
  const externalMaterial = (kind, sourcePath, bytes, describes, origin) => ({
    kind, sourcePath, describes, origin,
    upstreamSHA256: digest(bytes.subarray(0, bytes.byteLength - 1)), upstreamSize: bytes.byteLength - 1,
    normalization: "append-terminal-lf-v1", sha256: digest(bytes), size: bytes.byteLength, retrievedOn: "2026-09-06"
  });
  const gammaPath = "Resources/ThirdPartyLicenses/combined-binary-1.0.0/rust/gamma-2.0.0-external-gamma-LICENSE";
  const mplPath = "Resources/ThirdPartyLicenses/combined-binary-1.0.0/rust/beta-0.9.0-external-spdx-MPL-2.0.txt";
  await writeFile(join(root, ...gammaPath.split("/")), gammaUpstream);
  await writeFile(join(root, ...mplPath.split("/")), mplText);
  const noticeMaterials = {
    schemaVersion: 1,
    purpose: "Fixture version-bound notice material for crates whose archives carry no licence text. External material is labelled as such and was never a member of the original archive. This is material identification, not legal clearance.",
    crateManifest: "Config/crate-manifest.json",
    researchedOn: "2026-09-06",
    summary: { established: ["beta 0.9.0", "gamma 2.0.0"], unresolved: ["delta 0.1.0"] },
    records: [
      {
        crateName: "beta", crateVersion: "0.9.0", crateSHA256: digest(beta), licenseExpression: "MPL-2.0", status: "established",
        connection: { kind: "cargo-vcs-info", repository: "https://github.com/fixture/beta", revision: BETA_COMMIT, pathInVcs: "beta",
          revisionEvidence: `the crate archive member beta-0.9.0/.cargo_vcs_info.json (sha256 ${"5".repeat(64)}) records git sha1 ${BETA_COMMIT} and path_in_vcs beta; beta/Cargo.toml at that commit declares version = "0.9.0"; the crate member src/lib.rs is byte-identical to beta/src/lib.rs at that commit` },
        archiveNotice: { member: "beta-0.9.0/src/lib.rs", memberSHA256: digest(betaLib), text: MPL_HEADER, note: "Per-file MPL-2.0 notice carried by the crate archive member (archive-contained); no LICENSE file exists upstream." },
        materials: [externalMaterial("external-spdx-licence-text", mplPath, mplText, "MPL-2.0 text as published by SPDX, the licence the crate's per-file notices designate (external to the archive)", `https://github.com/spdx/license-list-data/blob/${SPDX_COMMIT}/text/MPL-2.0.txt`)]
      },
      {
        crateName: "delta", crateVersion: "0.1.0", crateSHA256: digest(delta), licenseExpression: "MIT", status: "unresolved",
        connection: { kind: "version-tag", repository: "https://github.com/fixture/delta", revision: DELTA_COMMIT,
          revisionEvidence: `lightweight tag 0.1.0 resolved with git ls-remote on 2026-09-06; Cargo.toml at that commit carries version = "0.1.0" and license = "MIT" and authors = ["Delta Author"]` },
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
        materials: [externalMaterial("external-upstream-file", gammaPath, gammaUpstream, "MIT licence with copyright statement, the repository-level LICENSE at the exact commit the crate was packaged from (external to the archive)", `https://github.com/fixture/gamma/blob/${GAMMA_COMMIT}/LICENSE`)]
      }
    ]
  };
  const acknowledgements = [
    "# Fixture acknowledgements",
    "",
    "## alpha — required credit",
    "",
    "> Portions of this fixture are copyright (c) Alpha Authors",
    "> (https://example.test/alpha). All rights reserved.",
    "",
    "## beta — statement",
    "",
    "> This fixture is based in part on the work of the Beta Group.",
    ""
  ].join("\n");
  await writeFile(join(root, "docs", "ACKNOWLEDGEMENTS.md"), acknowledgements);
  const component = files.provenanceDocument.components[0];
  component.upstream = { buildCommit: FIXTURE_COMMIT };
  component.deliveryMaterials = {
    purpose: "Fixture delivery material bindings consumed by the notice generator; they identify and verify material and are not legal clearance.",
    outputDirectoryName: "fixture-delivery-materials",
    sourceMaterials: "Config/source-manifest.json",
    rustCrateMaterials: "Config/crate-manifest.json",
    rustNoticeMaterials: "Config/notice-materials.json",
    accompanyingDocumentation: {
      path: "docs/ACKNOWLEDGEMENTS.md",
      statements: [
        { id: "alpha-credit", component: "alpha", material: "Resources/ThirdPartyLicenses/combined-binary-1.0.0/alpha-1.2.3-LICENSE", basis: "fixture licence section 2 requires a credit in product documentation", statement: "Portions of this fixture are copyright (c) Alpha Authors (https://example.test/alpha). All rights reserved." },
        { id: "beta-statement", component: "beta", material: "Resources/ThirdPartyLicenses/combined-binary-1.0.0/beta-4.5-COPYING", basis: "fixture licence condition (2) requires this statement in accompanying documentation", statement: "This fixture is based in part on the work of the Beta Group." }
      ],
      clarifications: [
        { id: "gamma-label", component: "gamma", upstreamLabel: "MIT", retainedTexts: ["Resources/ThirdPartyLicenses/combined-binary-1.0.0/gamma-vendored-COPYING"], statement: "gamma is vendored inside alpha; the retained COPYING is the text that applies, not the upstream table label." }
      ]
    }
  };
  await writeProvenance(files);
  const writeJSON = async (name, value) => writeFile(join(root, "Config", name), `${JSON.stringify(value, null, 2)}\n`);
  await writeJSON("crate-manifest.json", crateManifest);
  await writeJSON("source-manifest.json", sourceManifest);
  await writeJSON("notice-materials.json", noticeMaterials);
  const crateDirectory = join(root, "materials", "fixture-rust-materials");
  const acquired = spawnSync(process.execPath, [materialsTool, "acquire", join(root, "Config", "crate-manifest.json"), crateDirectory,
    "--transport", `local-fixture:${join(root, "upstream")}`, "--notice-materials", join(root, "Config", "notice-materials.json")], { cwd: project, encoding: "utf8", timeout: 30_000 });
  if (acquired.status !== 0) {
    await rm(root, { recursive: true, force: true });
    assert.fail(`fixture crate materials could not be acquired: ${acquired.stderr}`);
  }
  return {
    ...files,
    crateDirectory,
    crateManifest,
    noticeMaterials,
    gammaPath,
    mplPath,
    gammaUpstream,
    mplText,
    acknowledgements,
    saveNoticeMaterials: () => writeJSON("notice-materials.json", noticeMaterials),
    saveCrateManifest: () => writeJSON("crate-manifest.json", crateManifest)
  };
}

function invokeDelivery(files, output = files.output, extra = ["--rust-crate-materials", files.crateDirectory]) {
  return spawnSync(process.execPath, [generator, template, files.runtime, files.overrides, output, ...extra], { cwd: project, encoding: "utf8", timeout: 60_000 });
}

test("declared delivery materials render the verified Rust notices, exact external texts, unresolved records, acknowledgements and a bound inventory", async () => {
  const files = await deliveryFixture();
  try {
    const result = invokeDelivery(files);
    assert.equal(result.status, 0, result.stderr);
    const notices = await readFile(files.output, "utf8");
    // The existing component notices and first-party semantics are intact.
    assert.match(notices, /It additionally binds 3 exact per-component notice texts for redistributed combined binaries/u);
    assert.match(notices, /Copyright \(c\) Alpha Authors/u);
    assert.match(notices, /Copyright \(c\) Beta Authors/u);
    assert.match(notices, /Copyright \(c\) Gamma Authors \(vendored\)/u);
    // Rust notices: coverage, distinction and unverified incorporation wording.
    assert.match(notices, /It additionally binds 1 Rust crate notice texts \(1 distinct\) read from 4 verified crates\.io archives, 2 version-bound external notice materials and 2 accompanying-documentation statements; 1 crate notices remain unresolved and are listed as such\./u);
    assert.match(notices, /## Rust crate notices for redistributed binaries/u);
    assert.match(notices, /4 crates\.io registry crates are identified for the librsvg-c static library of this binary: 0 were observed compiling in the retained historical build log and 4 are resolved by approximation only/u);
    assert.match(notices, /The workspace packages `fixture-workspace 1\.0\.0 \(root\)` are not registry crates/u);
    assert.match(notices, /compiledInHistoricalBuild=unverified, incorporatedIntoShippedBinary=unverified\. Observed compilation is not a linkage map/u);
    assert.match(notices, /\| `alpha` \| `1\.2\.3` \| normal \| MIT \| resolved-approximation \| `LICENSE-MIT` \(`sha256:[a-f0-9]{64}`\) \|/u);
    assert.match(notices, /\| `beta` \| `0\.9\.0` \| normal \| MPL-2\.0 \| resolved-approximation \| none in crate; external material bound \(see below\) \|/u);
    assert.match(notices, /\| `delta` \| `0\.1\.0` \| normal \| MIT \| resolved-approximation \| none in crate; UNRESOLVED \(see below\) \|/u);
    assert.match(notices, /\| `gamma` \| `2\.0\.0` \| normal \| MIT \| resolved-approximation \| none in crate; external material bound \(see below\) \|/u);
    // Exact external texts, explicitly distinct from archive members.
    assert.match(notices, /##### `gamma` 2\.0\.0 — established \(external material\)/u);
    assert.match(notices, /Kind: external-upstream-file — external to the \.crate archive; this text was never an archive member\./u);
    assert.match(notices, /Copyright \(c\) Gamma Crate Upstream/u);
    assert.match(notices, /##### `beta` 0\.9\.0 — established \(archive-contained notice plus external licence text\)/u);
    assert.match(notices, /Archive-contained notice: member `beta-0\.9\.0\/src\/lib\.rs` \(`sha256:[a-f0-9]{64}`, verified in the \.crate archive\) begins with:/u);
    assert.match(notices, /Mozilla Public License Version 2\.0 \(fixture text\)/u);
    assert.match(notices, /Kind: external-spdx-licence-text — external to the \.crate archive/u);
    // The unresolved record survives with its exact status and bounded reason.
    assert.match(notices, /##### `delta` 0\.1\.0 — UNRESOLVED/u);
    assert.match(notices, /Status: UNRESOLVED — no upstream-published licence text or copyright statement exists for this exact version; nothing is rendered for it and none is asserted\./u);
    assert.match(notices, /Missing evidence: An upstream-published MIT licence text and copyright statement for this exact version\./u);
    assert.match(notices, /- source file header \(fallback\): src\/lib\.rs carries no copyright or licence header/u);
    assert.match(notices, /Unresolved: 1 \(`delta 0\.1\.0`\); no licence text or copyright statement is rendered for them and none is asserted\./u);
    // Archive-carried texts are embedded once per distinct digest.
    assert.match(notices, /#### Licence texts carried by the crate archives/u);
    assert.match(notices, /Bound as: `alpha-1\.2\.3\/LICENSE-MIT` \(alpha 1\.2\.3, \d+ bytes\)/u);
    assert.match(notices, /Copyright \(c\) Alpha Crate Authors/u);
    // Acknowledgements are quoted verbatim and bound to their materials.
    assert.match(notices, /## Acknowledgements required in accompanying documentation/u);
    assert.match(notices, /> Portions of this fixture are copyright \(c\) Alpha Authors \(https:\/\/example\.test\/alpha\)\. All rights reserved\./u);
    assert.match(notices, /> This fixture is based in part on the work of the Beta Group\./u);
    assert.match(notices, /### Clarification: gamma licence label versus retained texts/u);
    assert.match(notices, /its presence here is not legal clearance/u);
    // The material inventory binds every consumed input and the rendered output.
    assert.match(notices, /## Delivery material inventory for `node_modules\/@fixture\/combined-binary`/u);
    for (const relative of ["Config/provenance.json", "Config/crate-manifest.json", "Config/notice-materials.json", "Config/source-manifest.json", "docs/ACKNOWLEDGEMENTS.md", files.gammaPath, files.mplPath]) {
      const expected = digest(await readFile(join(files.root, ...relative.split("/"))));
      assert.ok(notices.includes(`| \`${relative}\` | `), relative);
      assert.ok(notices.includes(`| \`${expected}\` |`), `${relative} digest is bound`);
    }
    for (const name of ["INVENTORY.json", "SHA256SUMS", "RUST_CRATE_NOTICES.md"]) {
      assert.ok(notices.includes(`| \`fixture-rust-materials/${name}\` | `), name);
      assert.ok(notices.includes(digest(await readFile(join(files.crateDirectory, name)))), `${name} digest is bound`);
    }
    assert.match(notices, /\| transport local-fixture \(NOT authoritative\) \|/u);
    assert.doesNotMatch(notices, new RegExp(files.root.replaceAll(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"), "no private absolute path is rendered");
    assert.doesNotMatch(notices, /legal clearance is granted|licence[- ]cleared/iu);
    // Repeated generation from identical inputs is byte-identical.
    const again = invokeDelivery(files, join(files.root, "again.md"));
    assert.equal(again.status, 0, again.stderr);
    assert.equal(await readFile(join(files.root, "again.md"), "utf8"), notices);
  } finally {
    await rm(files.root, { recursive: true, force: true });
  }
});

test("delivery material generation fails closed on absent, incomplete, stale, drifted, linked or mismatched inputs", async (context) => {
  const cases = [
    {
      name: "declared bindings without the crate materials operand",
      extra: [],
      message: /component combined-binary \(node_modules\/@fixture\/combined-binary\) declares Rust crate delivery materials; pass --rust-crate-materials <verified fixture-rust-materials directory>/u
    },
    {
      name: "operand given while nothing declares a binding",
      mutate: async (files) => {
        delete files.provenanceDocument.components[0].deliveryMaterials;
        await writeProvenance(files);
      },
      message: /--rust-crate-materials was given but no bound component declares Rust crate delivery materials/u
    },
    {
      name: "operand without a value",
      extra: ["--rust-crate-materials"],
      message: /usage:/u
    },
    {
      name: "unknown option",
      extra: (files) => ["--rust-crate-materials", files.crateDirectory, "--from-environment"],
      message: /usage:/u
    },
    {
      name: "crate materials directory missing",
      mutate: async (files) => rm(files.crateDirectory, { recursive: true }),
      message: /ENOENT|not a real directory/u
    },
    {
      name: "crate materials directory reached through a symbolic link",
      mutate: async (files) => {
        await symlink(files.crateDirectory, join(files.root, "materials", "linked"));
      },
      extra: (files) => ["--rust-crate-materials", join(files.root, "materials", "linked")],
      message: /must not traverse aliases or symbolic links|is not a real directory/u
    },
    {
      name: "crate materials directory with the wrong name",
      mutate: async (files) => {
        const { rename } = await import("node:fs/promises");
        await rename(files.crateDirectory, join(files.root, "materials", "other-materials"));
      },
      extra: (files) => ["--rust-crate-materials", join(files.root, "materials", "other-materials")],
      message: /destination must be named fixture-rust-materials/u
    },
    {
      name: "crate archive deleted from the verified directory",
      mutate: async (files) => rm(join(files.crateDirectory, "gamma-2.0.0.crate")),
      message: /missing expected entries/u
    },
    {
      name: "crate archive truncated",
      mutate: async (files) => {
        const path = join(files.crateDirectory, "alpha-1.2.3.crate");
        await writeFile(path, (await readFile(path)).subarray(0, 20));
      },
      message: /size or topology drifted: alpha-1\.2\.3\.crate/u
    },
    {
      name: "crate archive substituted by other bytes of the same size",
      mutate: async (files) => {
        const path = join(files.crateDirectory, "alpha-1.2.3.crate");
        const bytes = Buffer.from(await readFile(path));
        bytes[bytes.byteLength - 1] ^= 0x01;
        await writeFile(path, bytes);
      },
      message: /SHA-256 drifted: alpha-1\.2\.3\.crate/u
    },
    {
      name: "extra file inside the verified directory",
      mutate: async (files) => writeFile(join(files.crateDirectory, "extra.crate"), "x"),
      message: /unexpected entry: extra\.crate/u
    },
    {
      name: "rendered notices file edited",
      mutate: async (files) => {
        const path = join(files.crateDirectory, "RUST_CRATE_NOTICES.md");
        await writeFile(path, `${await readFile(path, "utf8")}\nextra\n`);
      },
      message: /rust crate notices drifted from the verified crate archives/u
    },
    {
      name: "directory acquired without the external notice material relabelled as complete",
      mutate: async (files) => {
        await rm(files.crateDirectory, { recursive: true });
        const acquired = spawnSync(process.execPath, [materialsTool, "acquire", join(files.root, "Config", "crate-manifest.json"), files.crateDirectory,
          "--transport", `local-fixture:${join(files.root, "upstream")}`], { cwd: project, encoding: "utf8", timeout: 30_000 });
        assert.equal(acquired.status, 0, acquired.stderr);
      },
      message: /inventory was rendered without external notice material; acquire again with --notice-materials instead of relabelling this destination/u
    },
    {
      name: "external notice material bytes drifted at the same size",
      mutate: async (files) => {
        const bytes = Buffer.from(files.gammaUpstream);
        bytes[bytes.indexOf("Gamma")] = 0x4c;
        await writeFile(join(files.root, ...files.gammaPath.split("/")), bytes);
      },
      message: /tracked material SHA-256 drifted: Resources\/ThirdPartyLicenses\/combined-binary-1\.0\.0\/rust\/gamma-2\.0\.0-external-gamma-LICENSE/u
    },
    {
      name: "external notice material replaced by a shorter text",
      mutate: async (files) => writeFile(join(files.root, ...files.gammaPath.split("/")), "MIT License\n\nCopyright (c) Somebody Else\n"),
      message: /tracked material size drifted/u
    },
    {
      name: "external notice material missing",
      mutate: async (files) => rm(join(files.root, ...files.mplPath.split("/"))),
      message: /ENOENT|no such file/u
    },
    {
      name: "external notice material replaced by a symbolic link",
      mutate: async (files) => {
        const path = join(files.root, ...files.gammaPath.split("/"));
        const target = join(files.root, "gamma-target");
        await writeFile(target, files.gammaUpstream);
        await unlink(path);
        await symlink(target, path);
      },
      message: /must not traverse aliases or symbolic links|ELOOP|symbolic link/u
    },
    {
      name: "unbound file beside the external notice material",
      mutate: async (files) => writeFile(join(files.root, "Resources", "ThirdPartyLicenses", "combined-binary-1.0.0", "rust", "stray-LICENSE"), "MIT License\n"),
      message: /unbound entry beside the tracked Rust notice material/u
    },
    {
      name: "external material origin at a revision other than the packaged one",
      mutate: async (files) => {
        files.noticeMaterials.records[2].materials[0].origin = `https://github.com/fixture/gamma/blob/${"f".repeat(40)}/LICENSE`;
        await files.saveNoticeMaterials();
      },
      message: /must come from the connected repository at the connected revision/u
    },
    {
      name: "external material origin on a mutable branch",
      mutate: async (files) => {
        files.noticeMaterials.records[2].materials[0].origin = "https://github.com/fixture/gamma/blob/main/LICENSE";
        await files.saveNoticeMaterials();
      },
      message: /must be pinned to one full commit/u
    },
    {
      name: "SPDX text for a licence the archive does not designate",
      mutate: async (files) => {
        delete files.noticeMaterials.records[0].archiveNotice;
        await files.saveNoticeMaterials();
      },
      message: /SPDX text may only stand in for a licence the archive itself designates/u
    },
    {
      name: "archive-contained notice digest disagrees with the archive",
      mutate: async (files) => {
        files.noticeMaterials.records[0].archiveNotice.memberSHA256 = "e".repeat(64);
        await files.saveNoticeMaterials();
      },
      message: /archive-contained notice member SHA-256 drifted: crate-beta-0\.9\.0 -> beta-0\.9\.0\/src\/lib\.rs/u
    },
    {
      name: "unresolved record silently upgraded without material",
      mutate: async (files) => {
        files.noticeMaterials.records[1].status = "established";
        files.noticeMaterials.summary.established.push("delta 0.1.0");
        files.noticeMaterials.summary.unresolved = [];
        await files.saveNoticeMaterials();
      },
      message: /established record cannot carry an unresolved record|established record must bind one to/u
    },
    {
      name: "crate without licence text dropped from the notice-materials manifest",
      mutate: async (files) => {
        files.noticeMaterials.records.splice(1, 1);
        files.noticeMaterials.summary.unresolved = [];
        await files.saveNoticeMaterials();
      },
      message: /must cover exactly the crates without archive licence text/u
    },
    {
      name: "notice-materials manifest bound to a different crate manifest",
      mutate: async (files) => {
        files.noticeMaterials.crateManifest = "Config/source-manifest.json";
        await files.saveNoticeMaterials();
      },
      message: /binds Config\/source-manifest\.json, which is not the crate manifest being processed/u
    },
    {
      name: "crate manifest describing a different binary than the provenance component",
      mutate: async (files) => {
        files.crateManifest.binary.version = "1.0.1";
        await files.saveCrateManifest();
      },
      message: /inventory does not describe this manifest|does not describe this component's package, version and build commit/u
    },
    {
      name: "corresponding-source manifest describing a different binary",
      mutate: async (files) => {
        const path = join(files.root, "Config", "source-manifest.json");
        const manifest = JSON.parse(await readFile(path, "utf8"));
        manifest.binary.buildCommit = "9".repeat(40);
        await writeFile(path, `${JSON.stringify(manifest, null, 2)}\n`);
      },
      message: /describe different binaries/u
    },
    {
      name: "acknowledgement statement absent from the accompanying documentation",
      mutate: async (files) => writeFile(join(files.root, "docs", "ACKNOWLEDGEMENTS.md"), files.acknowledgements.replace("Beta Group", "Beta Team")),
      message: /does not carry the exact statement beta-statement/u
    },
    {
      name: "acknowledgement statement bound to a material the component does not carry",
      mutate: async (files) => {
        files.provenanceDocument.components[0].deliveryMaterials.accompanyingDocumentation.statements[0].material = "Resources/ThirdPartyLicenses/combined-binary-1.0.0/beta-4.5-COPYING";
        await writeProvenance(files);
      },
      message: /names a material that is not bound for component alpha/u
    },
    {
      name: "clarification naming retained texts the component does not carry",
      mutate: async (files) => {
        files.provenanceDocument.components[0].deliveryMaterials.accompanyingDocumentation.clarifications[0].retainedTexts = [];
        await writeProvenance(files);
      },
      message: /must name exactly the retained texts bound for component gamma/u
    },
    {
      name: "clarification misquoting the upstream licence declaration",
      mutate: async (files) => {
        files.provenanceDocument.components[0].deliveryMaterials.accompanyingDocumentation.clarifications[0].upstreamLabel = "Apache-2.0";
        await writeProvenance(files);
      },
      message: /does not quote the upstream licence declaration exactly/u
    },
    {
      name: "delivery bindings naming a manifest outside Config",
      mutate: async (files) => {
        files.provenanceDocument.components[0].deliveryMaterials.rustNoticeMaterials = "Resources/notice-materials.json";
        await writeProvenance(files);
      },
      message: /must be one tracked JSON document under Config/u
    },
    {
      name: "delivery bindings with an unexpected field",
      mutate: async (files) => {
        files.provenanceDocument.components[0].deliveryMaterials.legalClearance = true;
        await writeProvenance(files);
      },
      message: /unexpected shape/u
    }
  ];
  for (const current of cases) {
    await context.test(current.name, async () => {
      const files = await deliveryFixture();
      try {
        if (current.mutate) await current.mutate(files);
        const extra = typeof current.extra === "function" ? current.extra(files) : current.extra;
        const result = invokeDelivery(files, files.output, extra);
        assert.notEqual(result.status, 0, `${current.name} must fail closed`);
        assert.match(result.stderr, current.message);
        await assert.rejects(() => readFile(files.output), /ENOENT/u, "no partial notices file is left behind");
      } finally {
        await rm(files.root, { recursive: true, force: true });
      }
    });
  }
});
