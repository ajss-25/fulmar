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
    assert.match(notices, new RegExp(`Component notice manifest: \`Config/provenance\.json\` \\(\`sha256:${digest(await readFile(files.provenance))}\`\\)`, "u"));
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
  assert.match(entry.reason, /1\.3\.2/u);
  assert.match(entry.reason, /remain recorded in Config\/ThirdPartyBinaryProvenance\.json as an open legal gate/u);
  assert.doesNotMatch(entry.reason, /cleared|satisfied|compliant/iu);
  assert.deepEqual(entry.materials.map((material) => material.path ?? `source:${material.sourcePath}`), [
    "dsh/node_modules/@img/sharp-libvips-darwin-arm64/README.md",
    "dsh/node_modules/@img/sharp-libvips-darwin-arm64/versions.json",
    "source:Resources/ThirdPartyLicenses/libvips-8.18.3-LICENSE",
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
// shared build root.
test("sharp-libvips per-component notices bind end to end from the tracked provenance record", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "fulmar-notices-real.")));
  try {
    const runtime = join(root, "Runtime");
    const packageDirectory = join(runtime, "dsh", "node_modules", "@img", "sharp-libvips-darwin-arm64");
    await mkdir(packageDirectory, { recursive: true, mode: 0o700 });
    await mkdir(join(root, "Config"), { mode: 0o700 });
    await mkdir(join(root, "Resources"), { mode: 0o700 });
    await cp(join(project, "Resources", "ThirdPartyLicenses"), join(root, "Resources", "ThirdPartyLicenses"), { recursive: true });
    await cp(join(project, "Config", "ThirdPartyBinaryProvenance.json"), join(root, "Config", "ThirdPartyBinaryProvenance.json"));
    const readme = Buffer.from("# fixture manifest stand-in\n");
    const versions = Buffer.from("{}\n");
    await writeFile(join(packageDirectory, "README.md"), readme);
    await writeFile(join(packageDirectory, "versions.json"), versions);
    await writeFile(join(packageDirectory, "package.json"), JSON.stringify({ name: "@img/sharp-libvips-darwin-arm64", version: "1.3.2", license: "LGPL-3.0-or-later" }));
    await writeFile(join(runtime, "NODE_LICENSE"), "Node licence fixture\n");
    await writeFile(join(runtime, "package-lock.json"), JSON.stringify({
      name: "fixture-runtime", version: "1.0.0", lockfileVersion: 3,
      packages: {
        "": { name: "fixture-runtime", version: "1.0.0" },
        "node_modules/@img/sharp-libvips-darwin-arm64": { version: "1.3.2", license: "LGPL-3.0-or-later", optional: true }
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
    const result = spawnSync(process.execPath, [generator, template, runtime, overrides, output], { cwd: project, encoding: "utf8", timeout: 60_000 });
    assert.equal(result.status, 0, result.stderr);
    const notices = await readFile(output, "utf8");
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
    assert.match(notices, /Text identical to `Resources\/ThirdPartyLicenses\/libvips-8\.18\.3-LICENSE` embedded above; not repeated\./u);
    assert.doesNotMatch(notices, /legal clearance is granted|licence[- ]cleared/iu);
  } finally {
    await rm(root, { recursive: true, force: true });
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
