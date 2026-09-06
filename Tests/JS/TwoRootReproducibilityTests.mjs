import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmod,
  link,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  unlink,
  utimes,
  writeFile
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { readAttestedRegularFile } from "../../scripts/attested-regular-file.mjs";

import {
  NATIVE_PRODUCTS,
  captureUnsignedBuild,
  compareUnsignedBuildCaptures,
  inventoryTree
} from "../../scripts/unsigned-reproducibility-inventory.mjs";

const project = new URL("../..", import.meta.url).pathname.replace(/\/$/u, "");

async function createCapture(parent, name) {
  const root = path.join(parent, name);
  const compiler = path.join(root, "CompilerProducts");
  const symbols = path.join(root, "Fulmar.dSYMs");
  const app = path.join(root, "Fulmar.app");
  await mkdir(compiler, { recursive: true, mode: 0o700 });
  await mkdir(symbols, { recursive: true, mode: 0o700 });
  await mkdir(path.join(app, "Contents", "Resources"), { recursive: true, mode: 0o755 });
  for (const product of NATIVE_PRODUCTS) {
    const compilerPath = path.join(compiler, product.name);
    const bundledPath = path.join(app, ...product.bundlePath.split("/"));
    const dwarfPath = path.join(
      symbols, `${product.name}.dSYM`, "Contents", "Resources", "DWARF", product.name
    );
    await mkdir(path.dirname(bundledPath), { recursive: true, mode: 0o755 });
    await mkdir(path.dirname(dwarfPath), { recursive: true, mode: 0o755 });
    await writeFile(compilerPath, `compiler:${product.name}\n`, { mode: 0o755 });
    await writeFile(bundledPath, `bundled:${product.name}\n`, { mode: 0o755 });
    await writeFile(dwarfPath, `symbols:${product.name}\n`, { mode: 0o644 });
    await chmod(compilerPath, 0o755);
    await chmod(bundledPath, 0o755);
  }
  const asset = path.join(app, "Contents", "Resources", "asset.txt");
  await writeFile(asset, "deterministic resource\n", { mode: 0o644 });
  await writeFile(path.join(app, "Contents", "Resources", "other.txt"), "other\n", { mode: 0o644 });
  await symlink("asset.txt", path.join(app, "Contents", "Resources", "asset-link"));
  return { app, compiler, root, symbols };
}

async function fixture() {
  const temporary = await realpath(await mkdtemp(path.join(tmpdir(), "fulmar-two-root-tests.")));
  return {
    temporary,
    cleanup: () => rm(temporary, { recursive: true, force: true })
  };
}

test("two different roots produce one path-free exact pre-sign summary", async () => {
  const value = await fixture();
  try {
    const leftRoot = await createCapture(value.temporary, "short-root");
    const rightRoot = await createCapture(value.temporary, "a-deliberately-different-length-root");
    const future = new Date(Date.now() + 60_000);
    await utimes(path.join(rightRoot.app, "Contents", "Resources", "asset.txt"), future, future);

    const [left, right] = await Promise.all([
      captureUnsignedBuild(leftRoot.root),
      captureUnsignedBuild(rightRoot.root)
    ]);
    const summary = compareUnsignedBuildCaptures(left, right);
    assert.equal(summary.result, "passed");
    assert.equal(summary.nativeProductCount, 8);
    assert.equal(summary.sections.compilerProducts.entries, 9);
    assert.match(summary.aggregateSHA256, /^[a-f0-9]{64}$/u);
    assert.doesNotMatch(JSON.stringify(summary), /fulmar-two-root-tests|short-root|different-length/u);

    const leftInventory = path.join(value.temporary, "left.json");
    const rightInventory = path.join(value.temporary, "right.json");
    const report = path.join(value.temporary, "report.json");
    await writeFile(leftInventory, `${JSON.stringify(left)}\n`, { mode: 0o600 });
    await writeFile(rightInventory, `${JSON.stringify(right)}\n`, { mode: 0o600 });
    let cli = spawnSync(process.execPath, [
      path.join(project, "scripts", "unsigned-reproducibility-inventory.mjs"),
      "compare-inventories", leftInventory, rightInventory, "a".repeat(40), "b".repeat(40), report
    ], { cwd: project, encoding: "utf8" });
    assert.equal(cli.status, 0, cli.stderr);
    assert.match(cli.stdout, /8 compiler products, 8 dSYMs/u);
    const firstReportInput = await readAttestedRegularFile(report, {
      label: "initial two-root comparison report",
      maximumBytes: 1024 * 1024,
      requirePrivateMode: true
    });
    assert.equal(Number(firstReportInput.metadata.mode & 0o777n), 0o600);
    cli = spawnSync(process.execPath, [
      path.join(project, "scripts", "unsigned-reproducibility-inventory.mjs"),
      "compare-inventories", leftInventory, rightInventory, "a".repeat(40), "b".repeat(40), report
    ], { cwd: project, encoding: "utf8" });
    assert.equal(cli.status, 0, cli.stderr);
    const repeatedReportInput = await readAttestedRegularFile(report, {
      label: "repeated two-root comparison report",
      maximumBytes: 1024 * 1024,
      requirePrivateMode: true
    });
    assert.deepEqual(repeatedReportInput.bytes, firstReportInput.bytes);
    const reportInput = await readAttestedRegularFile(report, {
      label: "two-root comparison report",
      maximumBytes: 1024 * 1024,
      requirePrivateMode: true
    });
    assert.deepEqual(JSON.parse(reportInput.bytes.toString("utf8")), {
      ...summary,
      source: { commit: "a".repeat(40), tree: "b".repeat(40) }
    });
  } finally {
    await value.cleanup();
  }
});

test("bytes, mode, entry type, and relative link-target drift each fail closed", async () => {
  for (const mutation of ["bytes", "mode", "type", "link-target"]) {
    const value = await fixture();
    try {
      const leftRoot = await createCapture(value.temporary, "left");
      const rightRoot = await createCapture(value.temporary, "right-longer");
      const left = await captureUnsignedBuild(leftRoot.root);
      const asset = path.join(rightRoot.app, "Contents", "Resources", "asset.txt");
      if (mutation === "bytes") {
        await writeFile(asset, "different bytes\n", { mode: 0o644 });
      } else if (mutation === "mode") {
        await chmod(asset, 0o600);
      } else if (mutation === "type") {
        await unlink(asset);
        await mkdir(asset, { mode: 0o755 });
      } else {
        const linked = path.join(rightRoot.app, "Contents", "Resources", "asset-link");
        await unlink(linked);
        await symlink("other.txt", linked);
      }
      const right = await captureUnsignedBuild(rightRoot.root);
      assert.throws(
        () => compareUnsignedBuildCaptures(left, right),
        /appBundle differs/u,
        `${mutation} drift must be rejected`
      );
    } finally {
      await value.cleanup();
    }
  }
});

test("capture topology requires all eight compiler products, app executables, and dSYMs", async () => {
  const value = await fixture();
  try {
    const capture = await createCapture(value.temporary, "capture");
    await unlink(path.join(capture.compiler, NATIVE_PRODUCTS.at(-1).name));
    await assert.rejects(
      captureUnsignedBuild(capture.root),
      /exactly eight compiler products and eight dSYM bundles/u
    );
  } finally {
    await value.cleanup();
  }
});

test("tree inventory rejects hard links and escaping symbolic links", async () => {
  const value = await fixture();
  try {
    const root = path.join(value.temporary, "tree");
    await mkdir(root, { mode: 0o700 });
    const file = path.join(root, "file");
    await writeFile(file, "fixture", { mode: 0o600 });
    await link(file, path.join(root, "hard-link"));
    await assert.rejects(inventoryTree(root), /hard linked/u);
    await unlink(path.join(root, "hard-link"));
    await symlink("../outside", path.join(root, "escape"));
    await assert.rejects(inventoryTree(root), /escapes its tree/u);
  } finally {
    await value.cleanup();
  }
});

test("the production build exposes one bounded pre-sign mode and the gate proves distinct roots", async () => {
  const [build, gate, symbolVerifier] = await Promise.all([
    readFile(path.join(project, "scripts", "build-app.sh"), "utf8"),
    readFile(path.join(project, "scripts", "verify-two-root-reproducibility.sh"), "utf8"),
    readFile(path.join(project, "scripts", "verify-native-symbol-privacy.sh"), "utf8")
  ]);
  const modeOffset = build.indexOf('if [[ "$BUILD_MODE" == "unsigned-reproducibility" ]]');
  const signingOffset = build.indexOf('LOCAL_SIGNING_IDENTITY_NAME="Fulmar Local Signing"');
  assert.ok(modeOffset >= 0 && signingOffset > modeOffset, "pre-sign capture must exit before signing setup");
  assert.match(build, /--unsigned-reproducibility-root/u);
  assert.match(build, /Unsigned reproducibility builds reject every signing, Keychain, timestamp, and notarization option/u);
  assert.match(build, /COMPILER_PRODUCTS_ROOT="\$OUTPUT_ROOT\/CompilerProducts"/u);
  assert.match(build, /"\$UNSIGNED_REPRODUCIBILITY_TOOL" create/u);
  const productArray = /native_products=\(\n([\s\S]*?)\n\)/u.exec(build)?.[1]
    .split("\n").map((line) => line.trim()).filter(Boolean);
  assert.deepEqual(productArray, NATIVE_PRODUCTS.map(({ name }) => name));

  assert.match(gate, /source-a/u);
  assert.match(gate, /source-root-with-distinct-length-b/u);
  assert.match(gate, /--no-hardlinks/u);
  assert.equal((gate.match(/--unsigned-reproducibility-root/g) ?? []).length, 2);
  assert.match(gate, /"\$SCRATCH_A" != "\$SCRATCH_B"/u);
  assert.match(gate, /compare-inventories/u);
  assert.doesNotMatch(gate, /\/usr\/bin\/security|codesign|notarytool/u);

  assert.match(symbolVerifier, /exactly eight reviewed dSYM bundles/u);
  assert.match(symbolVerifier, /eight arm64 executables/u);
  for (const script of ["build-app.sh", "verify-two-root-reproducibility.sh"]) {
    const syntax = spawnSync("/bin/zsh", ["-f", "-n", path.join(project, "scripts", script)], {
      encoding: "utf8"
    });
    assert.equal(syntax.status, 0, syntax.stderr);
  }
});
