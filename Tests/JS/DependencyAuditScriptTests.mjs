import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { gzipSync } from "node:zlib";
import test from "node:test";
import {
  advisoryBatchSize,
  advisoryEndpointSuffix,
  osvFallbackProvenance,
  osvQueryBatchEndpoint,
  osvQueryBatchSize,
  productionAdvisoryPayload,
  publicNPMRegistry,
  splitAdvisoryBatches,
  splitOSVQueryBatches
} from "../../scripts/audit-dependencies.mjs";

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

test("dependency audit uses complete bounded bulk-advisory batches and fails closed on hostile responses", async () => {
  const temporary = await realpath(await mkdtemp(join(tmpdir(), "local-harness-audit-regression-")));
  await mkdir(join(temporary, "home"), { mode: 0o700 });
  let responseMode = "clean";
  let responseIndex = 0;
  const observed = [];

  const registry = createServer((request, response) => {
    const chunks = [];
    let received = 0;
    request.on("data", (chunk) => {
      received += chunk.length;
      if (received > 64 * 1024) request.destroy();
      else chunks.push(Buffer.from(chunk));
    });
    request.on("end", () => {
      const bytes = Buffer.concat(chunks, received);
      const body = JSON.parse(bytes.toString("utf8"));
      const isOSV = request.url === "/v1/querybatch";
      observed.push({
        authority: isOSV ? "osv" : "npm",
        method: request.method,
        url: request.url,
        headers: request.headers,
        bytes: bytes.length,
        body
      });
      const requestedName = isOSV ? null : Object.keys(body)[0];
      let document = isOSV
        ? { results: body.queries.map(() => ({})) }
        : {};
      if (!isOSV && ["advisory", "advisory-late-server-error"].includes(responseMode)
          && responseIndex === 0) {
        document = { [requestedName]: [{
          id: 12345,
          title: "fixture production vulnerability",
          severity: "high",
          vulnerable_versions: "<=999.0.0"
        }] };
      } else if (!isOSV && responseMode === "unexpected-key") {
        document = { "not-requested-by-fulmar": [] };
      } else if (!isOSV && (responseMode === "malformed-schema"
          || (responseMode === "late-malformed-schema" && responseIndex > 0))) {
        document = { [requestedName]: {} };
      } else if (isOSV && responseMode === "osv-cardinality") {
        document.results.pop();
      } else if (isOSV && responseMode === "osv-unexpected-top-level") {
        document.unexpected = true;
      } else if (isOSV && responseMode === "osv-unexpected-field") {
        document.results[0] = { unexpected: true };
      } else if (isOSV && responseMode === "osv-pagination") {
        document.results[0] = { next_page_token: "more" };
      } else if (isOSV && responseMode === "osv-malformed-vulnerability") {
        document.results[0] = { vulns: [{ id: "GHSA-fixture" }] };
      } else if (isOSV && responseMode === "osv-advisory" && responseIndex === 2) {
        document.results[0] = { vulns: [{
          id: "GHSA-fixture-0000-0000",
          modified: "2026-09-04T00:00:00Z"
        }] };
      }
      let payload = Buffer.from(JSON.stringify(document), "utf8");
      const headers = !isOSV && responseMode === "clean" && responseIndex === 0
        ? {} : { "content-type": "application/json" };
      if ((!isOSV && responseMode === "clean" && responseIndex < 2)
          || (!isOSV && responseMode === "malformed-gzip")
          || (isOSV && responseMode === "osv-malformed-gzip")) {
        payload = responseMode.includes("malformed-gzip")
          ? Buffer.from([0x1f, 0x8b, 0x00]) : gzipSync(payload);
        if (responseMode === "clean" && responseIndex === 1) headers["content-encoding"] = "gzip";
      } else if ((!isOSV && responseMode === "malformed-json")
          || (isOSV && responseMode === "osv-malformed-json")) {
        payload = Buffer.from("{", "utf8");
      }
      responseIndex += 1;
      if ((!isOSV && responseMode === "redirect") || (isOSV && responseMode === "osv-redirect")) {
        response.writeHead(302, { location: `/${advisoryEndpointSuffix}` });
        response.end("{}");
      } else if (!isOSV && responseMode === "invalid-http-status") {
        response.writeHead(600, headers);
        response.end("{}");
      } else if (responseMode === "server-error"
          || (!isOSV && responseMode.startsWith("osv-"))
          || (!isOSV && responseMode === "fallback-clean")
          || (!isOSV && ["late-server-error", "advisory-late-server-error"].includes(responseMode)
            && responseIndex > 1)) {
        response.writeHead(503, headers);
        response.end("{}");
      } else if ((!isOSV && responseMode === "oversized")
          || (isOSV && responseMode === "osv-oversized")) {
        response.writeHead(200, { ...headers, "content-length": String(9 * 1024 * 1024) });
        // Keep the declared-oversize response open. The client must destroy it
        // immediately rather than clearing its deadline and draining forever.
        response.write("{}");
      } else {
        response.writeHead(200, { ...headers, "content-length": String(payload.length) });
        response.end(payload);
      }
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

    const runAudit = (output) => new Promise((resolveChild, reject) => {
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

    const output = join(temporary, "summary.json");
    const result = await runAudit(output);
    assert.equal(result.signal, null);
    assert.equal(result.code, 0, result.stderr);
    assert.match(result.stdout, /zero findings/);
    const summary = JSON.parse(await readFile(output, "utf8"));
    const runtimePackageDocument = JSON.parse(
      await readFile(join(project, "VendorRuntime", "package.json"), "utf8")
    );
    const runtimeLockDocument = JSON.parse(
      await readFile(join(project, "VendorRuntime", "package-lock.json"), "utf8")
    );
    const expectedGraph = productionAdvisoryPayload(runtimePackageDocument, runtimeLockDocument);
    const expectedProvenance = osvFallbackProvenance(runtimeLockDocument);
    assert.equal(expectedProvenance.packageNodeCount, 511);
    assert.equal(
      expectedProvenance.packageNodeProvenanceSHA256,
      "c81a01227e4b7c6e6ca6bd909a5b77a3194a3fd377ae2ac48a81975fc7f2c4dc"
    );
    assert.ok(observed.length > 1);
    assert.equal(observed.length, Math.ceil(expectedGraph.packageNameCount / advisoryBatchSize));
    const observedNames = observed.flatMap((request) => Object.keys(request.body));
    assert.equal(new Set(observedNames).size, observedNames.length);
    assert.deepEqual([...observedNames].sort(), Object.keys(expectedGraph.payload).sort());
    for (const request of observed) {
      assert.equal(request.method, "POST");
      assert.equal(request.url, `/${advisoryEndpointSuffix}`);
      assert.equal(request.headers.authorization, undefined);
      assert.equal(request.headers.cookie, undefined);
      assert.equal(request.headers["content-type"], "application/json");
      assert.equal(request.headers["npm-command"], "audit");
      assert.ok(request.bytes <= 64 * 1024);
      assert.ok(Object.keys(request.body).length >= 1);
      assert.ok(Object.keys(request.body).length <= advisoryBatchSize);
      for (const [name, versions] of Object.entries(request.body)) {
        assert.deepEqual(versions, expectedGraph.payload[name]);
      }
    }
    const syntheticPayload = Object.fromEntries(Array.from(
      { length: advisoryBatchSize + 1 },
      (_, index) => [`synthetic-package-${String(index).padStart(4, "0")}`, ["1.0.0"]]
    ));
    const syntheticBatches = splitAdvisoryBatches(syntheticPayload);
    assert.equal(syntheticBatches.length, 2);
    assert.equal(Object.keys(syntheticBatches[0]).length, advisoryBatchSize);
    assert.equal(Object.keys(syntheticBatches[1]).length, 1);
    const omissionGraph = productionAdvisoryPayload(
      {
        name: "audit-omission-fixture",
        version: "1.0.0",
        dependencies: { "production-package": "1.0.0" },
        devDependencies: { "development-package": "1.0.0" },
        optionalDependencies: { "optional-package": "1.0.0" },
        peerDependencies: { "peer-package": "1.0.0" }
      },
      {
        name: "audit-omission-fixture",
        version: "1.0.0",
        lockfileVersion: 3,
        packages: {
          "": { name: "audit-omission-fixture", version: "1.0.0" },
          "node_modules/production-package": { version: "1.0.0" },
          "node_modules/development-package": { version: "1.0.0", dev: true },
          "node_modules/optional-package": { version: "1.0.0", optional: true },
          "node_modules/peer-package": { version: "1.0.0", peer: true }
        }
      }
    );
    assert.deepEqual(Object.keys(omissionGraph.payload), [
      "optional-package", "peer-package", "production-package"
    ]);
    assert.equal(summary.registry, registryURL);
    assert.equal(summary.auditEndpoint, `${registryURL}${advisoryEndpointSuffix}`);
    assert.equal(summary.auditTransport, "npm-bulk-advisory-v1");
    assert.equal(summary.auditReportVersion, 2);
    assert.equal(summary.packageNameCount, expectedGraph.packageNameCount);
    assert.equal(summary.packageVersionCount, expectedGraph.packageVersionCount);
    assert.equal(summary.packageGraphSHA256, expectedGraph.graphSHA256);
    assert.equal(summary.batchCount, observed.length);
    assert.equal(summary.batches.length, observed.length);
    assert.equal(summary.vulnerabilities.unknown, 0);
    assert.equal(summary.vulnerabilities.total, 0);
    assert.deepEqual(summary.unresolved, []);
    const verifier = join(project, "scripts", "verify-dependency-audit.mjs");
    const runtimeLockPath = join(project, "VendorRuntime", "package-lock.json");
    const publicPrimarySummary = structuredClone(summary);
    publicPrimarySummary.registry = publicNPMRegistry;
    publicPrimarySummary.auditEndpoint = `${publicNPMRegistry}${advisoryEndpointSuffix}`;
    const publicPrimaryPath = join(temporary, "public-primary-summary.json");
    await writeJSON(publicPrimaryPath, publicPrimarySummary);
    const primaryVerified = await execFileAsync(
      process.execPath, [verifier, publicPrimaryPath, runtimeLockPath]
    );
    assert.match(primaryVerified.stdout, /zero unresolved production vulnerabilities/u);
    for (const [index, mutation] of [
      (value) => { value.auditTransport = "osv-querybatch-v1-fallback"; },
      (value) => { value.auditEndpoint = osvQueryBatchEndpoint; },
      (value) => { value.batchCount -= 1; },
      (value) => { value.batches[0].attemptCount = 3; },
      (value) => { value.batches[0].requestSHA256 = "0".repeat(64); },
      (value) => { value.unexpectedTopLevel = true; }
    ].entries()) {
      const mutated = structuredClone(publicPrimarySummary);
      mutation(mutated);
      const mutatedPath = join(temporary, `primary-verifier-mutation-${index}.json`);
      await writeJSON(mutatedPath, mutated);
      await assert.rejects(execFileAsync(process.execPath, [verifier, mutatedPath, runtimeLockPath]));
    }
    responseMode = "advisory";
    responseIndex = 0;
    observed.length = 0;
    const vulnerableOutput = join(temporary, "vulnerable-summary.json");
    const vulnerable = await runAudit(vulnerableOutput);
    assert.equal(vulnerable.signal, null);
    assert.notEqual(vulnerable.code, 0);
    assert.match(vulnerable.stderr, /found 1 unresolved vulnerabilities/u);
    const vulnerableSummary = JSON.parse(await readFile(vulnerableOutput, "utf8"));
    assert.equal(vulnerableSummary.vulnerabilities.high, 1);
    assert.equal(vulnerableSummary.vulnerabilities.unknown, 0);
    assert.equal(vulnerableSummary.vulnerabilities.total, 1);
    assert.equal(vulnerableSummary.unresolved.length, 1);
    assert.equal(observed.some((request) => request.authority === "osv"), false);

    responseMode = "fallback-clean";
    responseIndex = 0;
    observed.length = 0;
    const fallbackOutput = join(temporary, "fallback-summary.json");
    const fallback = await runAudit(fallbackOutput);
    assert.equal(fallback.signal, null);
    assert.equal(fallback.code, 0, fallback.stderr);
    const fallbackSummary = JSON.parse(await readFile(fallbackOutput, "utf8"));
    const npmFallbackRequests = observed.filter((request) => request.authority === "npm");
    const osvRequests = observed.filter((request) => request.authority === "osv");
    const expectedOSVBatches = splitOSVQueryBatches(expectedGraph.payload);
    assert.equal(npmFallbackRequests.length, 2);
    assert.equal(osvRequests.length, expectedOSVBatches.length);
    assert.deepEqual(osvRequests.map((request) => request.body), expectedOSVBatches);
    assert.equal(osvRequests.flatMap((request) => request.body.queries).length, expectedGraph.packageVersionCount);
    for (const request of osvRequests) {
      assert.equal(request.method, "POST");
      assert.equal(request.url, "/v1/querybatch");
      assert.equal(request.headers.authorization, undefined);
      assert.equal(request.headers.cookie, undefined);
      assert.equal(request.headers["npm-command"], undefined);
      assert.equal(request.headers["content-type"], "application/json");
      assert.ok(request.bytes <= 64 * 1024);
      assert.ok(request.body.queries.length >= 1);
      assert.ok(request.body.queries.length <= osvQueryBatchSize);
    }
    assert.equal(fallbackSummary.auditTransport, "osv-querybatch-v1-fallback");
    assert.equal(fallbackSummary.queryBatchSize, osvQueryBatchSize);
    assert.equal(fallbackSummary.queryCount, expectedGraph.packageVersionCount);
    assert.equal(fallbackSummary.packageNodeCount, expectedProvenance.packageNodeCount);
    assert.equal(
      fallbackSummary.packageNodeProvenanceSHA256,
      expectedProvenance.packageNodeProvenanceSHA256
    );
    assert.equal(fallbackSummary.fallbackFrom.failedBatchIndex, 0);
    assert.equal(fallbackSummary.fallbackFrom.attemptCount, 2);
    assert.equal(fallbackSummary.fallbackFrom.failureClass, "retryable-http");
    assert.equal(fallbackSummary.vulnerabilities.unknown, 0);
    assert.equal(fallbackSummary.vulnerabilities.total, 0);
    assert.deepEqual(fallbackSummary.unresolved, []);

    responseMode = "late-server-error";
    responseIndex = 0;
    observed.length = 0;
    const lateFallbackOutput = join(temporary, "late-fallback-summary.json");
    const lateFallback = await runAudit(lateFallbackOutput);
    assert.equal(lateFallback.signal, null);
    assert.equal(lateFallback.code, 0, lateFallback.stderr);
    const lateFallbackSummary = JSON.parse(await readFile(lateFallbackOutput, "utf8"));
    assert.equal(lateFallbackSummary.auditTransport, "osv-querybatch-v1-fallback");
    assert.equal(lateFallbackSummary.fallbackFrom.failedBatchIndex, 1);
    assert.equal(lateFallbackSummary.fallbackFrom.attemptCount, 2);
    assert.equal(observed.filter((request) => request.authority === "npm").length, 3);
    assert.equal(observed.filter((request) => request.authority === "osv").length, expectedOSVBatches.length);

    const publicFallbackSummary = structuredClone(fallbackSummary);
    publicFallbackSummary.registry = publicNPMRegistry;
    publicFallbackSummary.auditEndpoint = osvQueryBatchEndpoint;
    publicFallbackSummary.fallbackFrom.auditEndpoint = `${publicNPMRegistry}${advisoryEndpointSuffix}`;
    const publicFallbackPath = join(temporary, "public-fallback-summary.json");
    await writeJSON(publicFallbackPath, publicFallbackSummary);
    const verified = await execFileAsync(process.execPath, [verifier, publicFallbackPath, runtimeLockPath]);
    assert.match(verified.stdout, /zero unresolved production vulnerabilities/u);
    const publicLateFallbackSummary = structuredClone(lateFallbackSummary);
    publicLateFallbackSummary.registry = publicNPMRegistry;
    publicLateFallbackSummary.auditEndpoint = osvQueryBatchEndpoint;
    publicLateFallbackSummary.fallbackFrom.auditEndpoint = `${publicNPMRegistry}${advisoryEndpointSuffix}`;
    const publicLateFallbackPath = join(temporary, "public-late-fallback-summary.json");
    await writeJSON(publicLateFallbackPath, publicLateFallbackSummary);
    await execFileAsync(process.execPath, [verifier, publicLateFallbackPath, runtimeLockPath]);
    for (const [index, mutation] of [
      (value) => { value.packageNodeCount -= 1; },
      (value) => { value.packageNodeProvenanceSHA256 = "0".repeat(64); },
      (value) => { value.fallbackFrom.failureClass = "invalid-response"; },
      (value) => { value.fallbackFrom.attemptCount = 1; },
      (value) => { value.fallbackFrom.requestSHA256 = "0".repeat(64); },
      (value) => { value.batches[0].queryCount -= 1; },
      (value) => { value.batches[0].requestSHA256 = "0".repeat(64); },
      (value) => { value.registry = "https://registry.example.invalid/"; },
      (value) => { value.unexpectedTopLevel = true; }
    ].entries()) {
      const mutated = structuredClone(publicFallbackSummary);
      mutation(mutated);
      const mutatedPath = join(temporary, `fallback-verifier-mutation-${index}.json`);
      await writeJSON(mutatedPath, mutated);
      await assert.rejects(execFileAsync(process.execPath, [verifier, mutatedPath, runtimeLockPath]));
    }

    const firstProductionPath = Object.keys(runtimeLockDocument.packages).find((path) => path !== ""
      && runtimeLockDocument.packages[path].dev !== true);
    for (const mutation of [
      (value) => { value.resolved = value.resolved.replace("registry.npmjs.org", "mirror.invalid"); },
      (value) => { value.integrity = undefined; },
      (value) => { value.integrity = "sha512-not-canonical"; },
      (value) => { value.link = true; },
      (value) => { value.name = "aliased-package"; }
    ]) {
      const mutatedLock = structuredClone(runtimeLockDocument);
      mutation(mutatedLock.packages[firstProductionPath]);
      assert.throws(() => osvFallbackProvenance(mutatedLock), /OSV fallback/u);
    }

    for (const mode of [
      "malformed-gzip", "malformed-json", "malformed-schema", "unexpected-key",
      "redirect", "oversized", "invalid-http-status", "late-malformed-schema",
      "advisory-late-server-error"
    ]) {
      responseMode = mode;
      responseIndex = 0;
      observed.length = 0;
      const hostileOutput = join(temporary, `${mode}.json`);
      const hostile = await runAudit(hostileOutput);
      assert.equal(hostile.signal, null);
      assert.notEqual(hostile.code, 0, `${mode} unexpectedly passed`);
      const incomplete = JSON.parse(await readFile(hostileOutput, "utf8"));
      assert.equal(incomplete.state, "audit-incomplete");
      assert.equal(incomplete.vulnerabilities, undefined);
      assert.ok(observed.length >= 1);
      assert.ok(observed.every((request) => request.url === `/${advisoryEndpointSuffix}`));
    }

    for (const mode of [
      "server-error", "osv-cardinality", "osv-unexpected-top-level", "osv-unexpected-field", "osv-pagination",
      "osv-malformed-vulnerability", "osv-redirect", "osv-malformed-gzip",
      "osv-malformed-json", "osv-oversized"
    ]) {
      responseMode = mode;
      responseIndex = 0;
      observed.length = 0;
      const hostileOutput = join(temporary, `${mode}.json`);
      const hostile = await runAudit(hostileOutput);
      assert.equal(hostile.signal, null);
      assert.notEqual(hostile.code, 0, `${mode} unexpectedly passed`);
      const incomplete = JSON.parse(await readFile(hostileOutput, "utf8"));
      assert.equal(incomplete.state, "audit-incomplete");
      assert.equal(incomplete.vulnerabilities, undefined);
      assert.equal(observed.some((request) => request.authority === "osv"), true);
    }

    responseMode = "osv-advisory";
    responseIndex = 0;
    observed.length = 0;
    const osvVulnerableOutput = join(temporary, "osv-advisory.json");
    const osvVulnerable = await runAudit(osvVulnerableOutput);
    assert.equal(osvVulnerable.signal, null);
    assert.notEqual(osvVulnerable.code, 0);
    const osvVulnerableSummary = JSON.parse(await readFile(osvVulnerableOutput, "utf8"));
    assert.equal(osvVulnerableSummary.vulnerabilities.unknown, 1);
    assert.equal(osvVulnerableSummary.vulnerabilities.total, 1);
    assert.equal(osvVulnerableSummary.unresolved[0].source, "OSV");
    assert.equal(osvVulnerableSummary.unresolved[0].advisoryID, "GHSA-fixture-0000-0000");

    const implementation = await readFile(join(project, "scripts", "audit-dependencies.mjs"), "utf8");
    assert.doesNotMatch(implementation, /process\.env\.(?:HTTPS_PROXY|HTTP_PROXY|NO_PROXY)/u);
    assert.match(implementation, /npm\/v1\/security\/advisories\/bulk/u);
    assert.match(implementation, /https:\/\/api\.osv\.dev\/v1\/querybatch/u);
    assert.doesNotMatch(implementation, /audits\/quick/u);
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
