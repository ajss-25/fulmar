import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";

const project = resolve(fileURLToPath(new URL("../..", import.meta.url)));
const execFileAsync = promisify(execFile);
const sbomGenerator = join(project, "scripts", "generate-sbom.mjs");
const sbomVerifier = join(project, "scripts", "verify-sbom.mjs");
const localPackagePath = "dsh/node_modules/@local-harness/test-plugin/package.json";

async function writeJSON(path, value) {
  await writeFile(path, JSON.stringify(value, null, 2) + "\n");
}

async function sbomFixture({ optionalPresent = true } = {}) {
  const root = await mkdtemp(join(tmpdir(), "fulmar-sbom-artifact-"));
  const runtime = join(root, "Runtime");
  const projectRoot = join(root, "source");
  await mkdir(join(projectRoot, "Config"), { recursive: true, mode: 0o700 });
  await mkdir(join(runtime, "dsh", "node_modules", "@scope", "required"), { recursive: true });
  await mkdir(join(runtime, "dsh", "node_modules", "@local-harness", "test-plugin"), { recursive: true });
  if (optionalPresent) await mkdir(join(runtime, "dsh", "node_modules", "optional-pkg"), { recursive: true });
  await writeFile(join(runtime, "node"), "signed node fixture\n", { mode: 0o755 });
  await writeFile(join(runtime, "NODE_LICENSE"), "Node license fixture\n");
  await writeFile(join(root, "LocalHarness.patch.yml"), "patches: []\n");
  await writeJSON(join(runtime, "package-lock.json"), {
    name: "fixture-runtime",
    version: "1.0.0",
    lockfileVersion: 3,
    packages: {
      "": { name: "fixture-runtime", version: "1.0.0", dependencies: { "@deepseek-ai/dsh": "1.2.3" } },
      "node_modules/@deepseek-ai/dsh": {
        version: "1.2.3",
        license: "MIT",
        dependencies: { "@scope/required": "2.0.0" },
        optionalDependencies: { "optional-pkg": "3.0.0" }
      },
      "node_modules/@scope/required": {
        version: "2.0.0",
        license: "Apache-2.0 AND LGPL-3.0-or-later",
        integrity: "sha512-lock-provenance"
      },
      "node_modules/optional-pkg": { version: "3.0.0", license: "MIT", optional: true }
    }
  });
  await writeJSON(join(runtime, "dsh", "package.json"), {
    name: "@deepseek-ai/dsh",
    version: "1.2.3",
    license: "MIT",
    dependencies: {
      "@scope/required": "2.0.0",
      "@local-harness/test-plugin": "1.0.0"
    },
    optionalDependencies: { "optional-pkg": "3.0.0" }
  });
  await writeJSON(join(runtime, "dsh", "node_modules", "@scope", "required", "package.json"), {
    name: "@scope/required", version: "2.0.0", license: "Apache-2.0 AND LGPL-3.0-or-later"
  });
  await writeFile(join(runtime, "dsh", "node_modules", "@scope", "required", "index.js"), "export default 1;\n");
  if (optionalPresent) {
    await writeJSON(join(runtime, "dsh", "node_modules", "optional-pkg", "package.json"), {
      name: "optional-pkg", version: "3.0.0", license: "MIT"
    });
    await writeFile(join(runtime, "dsh", "node_modules", "optional-pkg", "index.js"), "export default 2;\n");
  }
  await writeJSON(join(runtime, localPackagePath), {
    name: "@local-harness/test-plugin",
    version: "1.0.0",
    peerDependencies: { "@scope/required": "2.0.0" }
  });
  await writeFile(join(runtime, dirname(localPackagePath), "index.mjs"), "export const fixture = true;\n");
  return { root, runtime, projectRoot, sbom: join(root, "sbom.json") };
}

async function generateFixture(fixture) {
  return execFileAsync(process.execPath, [
    sbomGenerator, fixture.runtime, fixture.sbom, "1.2.3", fixture.projectRoot, localPackagePath
  ]);
}

async function verifyFixture(fixture, sbom = fixture.sbom) {
  return execFileAsync(process.execPath, [sbomVerifier, sbom, fixture.runtime, fixture.projectRoot, localPackagePath]);
}

async function selectFixtureLicense(fixture, expression = "MIT OR Apache-2.0") {
  const bytes = Buffer.from("Owner-selected fixture licence terms\n", "utf8");
  const licenseSHA256 = createHash("sha256").update(bytes).digest("hex");
  await writeFile(join(fixture.projectRoot, "LICENSE"), bytes, { mode: 0o600 });
  await writeJSON(join(fixture.projectRoot, "Config", "ProjectLicense.json"), {
    schemaVersion: 1,
    licenseFile: "LICENSE",
    spdxExpression: expression,
    displayName: "Fixture licence",
    licenseSHA256
  });
  await writeFile(join(fixture.root, "LICENSE"), bytes, { mode: 0o600 });
  return { bytes, licenseSHA256, expression };
}

function property(component, name) {
  return component.properties?.find((entry) => entry.name === name)?.value;
}

test("dependency audit resolves the bundled npm CLI before entering its isolated cwd", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "local-harness-audit-regression-"));
  const output = join(temporary, "summary.json");
  await mkdir(join(temporary, "home"), { mode: 0o700 });

  const registry = createServer((request, response) => {
    let received = 0;
    request.on("data", (chunk) => {
      received += chunk.length;
      if (received > 8 * 1024 * 1024) request.destroy();
    });
    request.on("end", () => {
      response.writeHead(200, { "content-type": "application/json" });
      response.end("{}");
    });
  });

  try {
    await new Promise((resolveListen, reject) => {
      registry.once("error", reject);
      registry.listen(0, "127.0.0.1", resolveListen);
    });
    const address = registry.address();
    assert.equal(typeof address, "object");
    const registryURL = `http://127.0.0.1:${address.port}/`;

    const result = await new Promise((resolveChild, reject) => {
      const child = spawn(process.execPath, [
        "scripts/audit-dependencies.mjs",
        "VendorRuntime/package.json",
        "VendorRuntime/package-lock.json",
        "VendorRuntime/node-v22.23.1-darwin-arm64/lib/node_modules/npm/bin/npm-cli.js",
        output
      ], {
        cwd: project,
        env: {
          ...process.env,
          HOME: join(temporary, "home"),
          NPM_CONFIG_REGISTRY: registryURL,
          HTTPS_PROXY: "http://127.0.0.1:1",
          HTTP_PROXY: "http://127.0.0.1:1",
          NO_PROXY: ""
        },
        stdio: ["ignore", "pipe", "pipe"]
      });
      const stdout = [];
      const stderr = [];
      child.stdout.on("data", (chunk) => stdout.push(chunk));
      child.stderr.on("data", (chunk) => stderr.push(chunk));
      child.once("error", reject);
      child.once("close", (code, signal) => resolveChild({
        code,
        signal,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8")
      }));
    });

    assert.equal(result.signal, null);
    assert.equal(result.code, 0, result.stderr);
    assert.match(result.stdout, /zero findings/);
    const summary = JSON.parse(await readFile(output, "utf8"));
    assert.equal(summary.registry, registryURL);
    assert.equal(summary.auditReportVersion, 2);
    assert.equal(summary.vulnerabilities.total, 0);
    assert.deepEqual(summary.unresolved, []);
    const implementation = await readFile(join(project, "scripts", "audit-dependencies.mjs"), "utf8");
    assert.doesNotMatch(implementation, /process\.env\.(?:HTTPS_PROXY|HTTP_PROXY|NO_PROXY)/u);
  } finally {
    await new Promise((resolveClose) => registry.close(resolveClose));
    await rm(temporary, { recursive: true, force: true });
  }
});

test("artifact-aware SBOM includes only shipped required and optional packages with valid CycloneDX semantics", async () => {
  const fixture = await sbomFixture();
  try {
    await generateFixture(fixture);
    const result = await verifyFixture(fixture);
    assert.match(result.stdout, /3 shipped npm paths \(0 optional omitted\)/u);
    const sbom = JSON.parse(await readFile(fixture.sbom, "utf8"));
    const dsh = sbom.components.find((component) => property(component, "local-harness:npm-path") === "node_modules/@deepseek-ai/dsh");
    const required = sbom.components.find((component) => property(component, "local-harness:npm-path") === "node_modules/@scope/required");
    const optional = sbom.components.find((component) => property(component, "local-harness:npm-path") === "node_modules/optional-pkg");
    const local = sbom.components.find((component) => component["bom-ref"]?.startsWith("local-package:"));
    assert.deepEqual(sbom.metadata.component.licenses, [{ license: { name: "Fulmar unlicensed private code" } }]);
    assert.equal(property(sbom.metadata.component, "local-harness:first-party-license-state"), "unlicensed-private");
    assert.deepEqual(local.licenses, [{ license: { name: "Fulmar unlicensed private code" } }]);
    assert.equal(property(local, "local-harness:first-party-license-state"), "unlicensed-private");
    assert.equal(property(sbom.metadata, "local-harness:npm-present-count"), "3");
    assert.equal(property(sbom.metadata, "local-harness:npm-omitted-optional-count"), "0");
    assert.equal(property(dsh, "local-harness:package-json-path"), "dsh/package.json");
    assert.equal(property(dsh, "local-harness:patch-source-path"), "../LocalHarness.patch.yml");
    assert.match(property(dsh, "local-harness:patch-source-sha256"), /^[a-f0-9]{64}$/u);
    assert.equal(required.scope, "required");
    assert.equal(optional.scope, "optional");
    assert.equal(required.purl, "pkg:npm/%40scope/required@2.0.0");
    assert.deepEqual(required.licenses, [{ expression: "Apache-2.0 AND LGPL-3.0-or-later" }]);
    assert.equal(property(required, "local-harness:lock-integrity"), "sha512-lock-provenance");
    assert.deepEqual(required.hashes.map((hash) => hash.alg), ["SHA-256"]);
    assert.match(required.hashes[0].content, /^[a-f0-9]{64}$/u);
    assert.ok(sbom.dependencies.some((entry) => entry.ref === "npm-path:node_modules/@deepseek-ai/dsh"
      && entry.dependsOn.includes("npm-path:node_modules/@scope/required")
      && entry.dependsOn.includes("local-package:@local-harness/test-plugin@1.0.0")));
    assert.ok(sbom.dependencies.some((entry) => entry.ref === "local-package:@local-harness/test-plugin@1.0.0"
      && entry.dependsOn.includes("npm-path:node_modules/@scope/required")));
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("selected first-party licence bytes and metadata bind the application and every local SBOM component", async () => {
  const fixture = await sbomFixture();
  try {
    const selected = await selectFixtureLicense(fixture);
    await generateFixture(fixture);
    await verifyFixture(fixture);
    const sbom = JSON.parse(await readFile(fixture.sbom, "utf8"));
    const firstParty = [
      sbom.metadata.component,
      ...sbom.components.filter((component) => component["bom-ref"]?.startsWith("local-package:"))
    ];
    assert.equal(firstParty.length, 2);
    for (const component of firstParty) {
      assert.deepEqual(component.licenses, [{ expression: selected.expression }]);
      assert.equal(property(component, "local-harness:first-party-license-state"), "selected");
      assert.equal(property(component, "local-harness:first-party-license-file"), "LICENSE");
      assert.equal(property(component, "local-harness:first-party-license-sha256"), selected.licenseSHA256);
      assert.equal(property(component, "local-harness:first-party-license-spdx-expression"), selected.expression);
      assert.equal(property(component, "local-harness:first-party-license-display-name"), "Fixture licence");
    }

    for (const [index, mutation] of [
      (document) => { document.metadata.component.licenses = [{ expression: "MIT" }]; },
      (document) => {
        const local = document.components.find((component) => component["bom-ref"]?.startsWith("local-package:"));
        local.properties.find((entry) => entry.name === "local-harness:first-party-license-sha256").value = "0".repeat(64);
      },
      (document) => {
        const local = document.components.find((component) => component["bom-ref"]?.startsWith("local-package:"));
        local.properties.push({ name: "local-harness:first-party-license-state", value: "selected" });
      }
    ].entries()) {
      const mutated = structuredClone(sbom);
      mutation(mutated);
      const path = join(fixture.root, `selected-mutated-${index}.json`);
      await writeJSON(path, mutated);
      await assert.rejects(verifyFixture(fixture, path));
    }
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("artifact-aware SBOM permits omission only for lockfile-optional packages", async () => {
  const optionalFixture = await sbomFixture({ optionalPresent: false });
  try {
    await generateFixture(optionalFixture);
    await verifyFixture(optionalFixture);
    const sbom = JSON.parse(await readFile(optionalFixture.sbom, "utf8"));
    assert.equal(property(sbom.metadata, "local-harness:npm-present-count"), "2");
    assert.equal(property(sbom.metadata, "local-harness:npm-omitted-optional-count"), "1");
    assert.equal(sbom.components.some((component) => property(component, "local-harness:npm-path") === "node_modules/optional-pkg"), false);
  } finally {
    await rm(optionalFixture.root, { recursive: true, force: true });
  }

  const missingAtGeneration = await sbomFixture();
  try {
    await rm(join(missingAtGeneration.runtime, "dsh", "node_modules", "@scope", "required", "package.json"));
    await assert.rejects(generateFixture(missingAtGeneration));
  } finally {
    await rm(missingAtGeneration.root, { recursive: true, force: true });
  }

  const missingAtVerification = await sbomFixture();
  try {
    await generateFixture(missingAtVerification);
    await rm(join(missingAtVerification.runtime, "dsh", "node_modules", "@scope", "required", "package.json"));
    await assert.rejects(verifyFixture(missingAtVerification));
  } finally {
    await rm(missingAtVerification.root, { recursive: true, force: true });
  }
});

test("independent SBOM verifier rejects scope, path, hash, graph, schema, purl, license, and extra-component mutations", async () => {
  const fixture = await sbomFixture();
  try {
    await generateFixture(fixture);
    const original = JSON.parse(await readFile(fixture.sbom, "utf8"));
    const cases = [
      (sbom) => { sbom.components.find((value) => property(value, "local-harness:npm-path") === "node_modules/optional-pkg").scope = "required"; },
      (sbom) => {
        const component = sbom.components.find((value) => property(value, "local-harness:npm-path") === "node_modules/@scope/required");
        component.properties.find((value) => value.name === "local-harness:package-json-path").value = "dsh/package.json";
      },
      (sbom) => {
        const component = sbom.components.find((value) => property(value, "local-harness:npm-path") === "node_modules/@scope/required");
        component.hashes[0].content = "0".repeat(64);
      },
      (sbom) => { sbom.dependencies.find((value) => value.ref.startsWith("application:")).dependsOn = []; },
      (sbom) => {
        const dependency = sbom.dependencies.find((value) => value.ref.startsWith("application:"));
        sbom.metadata.component["bom-ref"] = "application:forged";
        dependency.ref = "application:forged";
      },
      (sbom) => {
        const component = sbom.components.find((value) => property(value, "local-harness:npm-path") === "node_modules/@scope/required");
        component.hashes = [{ alg: "SRI", content: "sha512-invalid" }];
      },
      (sbom) => {
        const component = sbom.components.find((value) => property(value, "local-harness:npm-path") === "node_modules/@scope/required");
        component.purl = "pkg:npm/%40scope%2Frequired@2.0.0";
      },
      (sbom) => {
        const component = sbom.components.find((value) => property(value, "local-harness:npm-path") === "node_modules/@scope/required");
        component.licenses = [{ license: { id: "Apache-2.0 AND LGPL-3.0-or-later" } }];
      },
      (sbom) => { sbom.components.push({ type: "library", "bom-ref": "extra", name: "extra", version: "1.0.0", scope: "required" }); }
    ];
    for (const [index, mutate] of cases.entries()) {
      const sbom = structuredClone(original);
      mutate(sbom);
      const path = join(fixture.root, `mutated-${index}.json`);
      await writeJSON(path, sbom);
      await assert.rejects(verifyFixture(fixture, path), undefined, `mutation ${index} should fail`);
    }
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("independent SBOM verifier binds installed package metadata and complete shipped package trees", async () => {
  for (const mutation of [
    (value) => { value.name = "renamed"; },
    (value) => { value.version = "9.9.9"; },
    (value) => { value.license = "MIT"; }
  ]) {
    const fixture = await sbomFixture();
    try {
      await generateFixture(fixture);
      const packagePath = join(fixture.runtime, "dsh", "node_modules", "@scope", "required", "package.json");
      const value = JSON.parse(await readFile(packagePath, "utf8"));
      mutation(value);
      await writeJSON(packagePath, value);
      await assert.rejects(verifyFixture(fixture));
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  }

  const treeFixture = await sbomFixture();
  try {
    await generateFixture(treeFixture);
    await writeFile(join(treeFixture.runtime, "dsh", "node_modules", "@scope", "required", "index.js"), "export default 999;\n");
    await assert.rejects(verifyFixture(treeFixture), /digest mismatch/u);
  } finally {
    await rm(treeFixture.root, { recursive: true, force: true });
  }
});

test("SBOM artifact readers reject symbolic, nonregular, and oversized installed package metadata", async () => {
  const mutations = [
    async (fixture, packagePath) => {
      await rm(packagePath);
      await symlink(join(fixture.runtime, "dsh", "package.json"), packagePath);
    },
    async (_fixture, packagePath) => {
      await rm(packagePath);
      await mkdir(packagePath);
    },
    async (_fixture, packagePath) => {
      await writeFile(packagePath, Buffer.alloc(1024 * 1024 + 1, 0x20));
    }
  ];
  for (const mutation of mutations) {
    const fixture = await sbomFixture();
    try {
      const packagePath = join(fixture.runtime, "dsh", "node_modules", "@scope", "required", "package.json");
      await mutation(fixture, packagePath);
      await assert.rejects(generateFixture(fixture), /regular|symbolic|byte limit/u);
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  }
});

test("every build, release, and public SBOM call site supplies the bundled Runtime root", async () => {
  const [build, release, prepare, publicVerifier] = await Promise.all([
    readFile(join(project, "scripts", "build-app.sh"), "utf8"),
    readFile(join(project, "scripts", "verify-release.sh"), "utf8"),
    readFile(join(project, "scripts", "prepare-public-release-assets.sh"), "utf8"),
    readFile(join(project, "scripts", "verify-public-distribution.sh"), "utf8")
  ]);
  assert.match(build, /generate-sbom\.mjs" \\\n\s+"\$RUNTIME_DIR" "\$SBOM_PATH" "\$APP_VERSION" "\$PROJECT_DIR"/u);
  assert.match(release, /verify-sbom\.mjs" \\\n\s+"\$SBOM" "\$RUNTIME_ROOT" "\$PROJECT_DIR"/u);
  for (const script of [prepare, publicVerifier]) {
    assert.match(script, /verify-sbom\.mjs" \\\n\s+"\$SBOM" "\$RUNTIME" "\$PROJECT_DIR"/u);
    assert.doesNotMatch(script, /verify-sbom\.mjs"[\s\S]{0,200}package-lock\.json[\s\S]{0,100}NODE_LICENSE/u);
  }
});
