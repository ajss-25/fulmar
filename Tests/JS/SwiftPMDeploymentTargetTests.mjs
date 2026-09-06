import assert from "node:assert/strict";
import { copyFile, mkdtemp, readFile, realpath, rm } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";

const root = process.cwd();
const verifier = join(root, "scripts", "verify-swiftpm-deployment-target.sh");
const identity = JSON.parse(await readFile(join(root, "Config", "ReleaseIdentity.json"), "utf8"));
const binPathResult = spawnSync("/usr/bin/swift", ["build", "--package-path", root, "--show-bin-path"], {
  cwd: root,
  encoding: "utf8"
});
const binPath = binPathResult.stdout.trim();
const product = join(binPath, "LocalHarness");
const testBundle = join(binPath, "LocalHarnessPackageTests.xctest", "Contents", "MacOS", "LocalHarnessPackageTests");

function invoke(...paths) {
  return spawnSync("/bin/zsh", ["-f", verifier, identity.minimumMacOS, ...paths], {
    cwd: root,
    encoding: "utf8",
    timeout: 30_000
  });
}

test("the post-test gate verifies the actual SwiftPM product and test bundle", () => {
  assert.equal(binPathResult.status, 0, binPathResult.stderr);
  const result = invoke(product, testBundle);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /2 product\/test Mach-O binaries/u);
});

test("the post-test gate rejects a real Mach-O lowered below the declared minimum", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "fulmar-deployment-negative."));
  try {
    const lowered = join(temporary, "LocalHarness-lowered");
    const intermediate = join(temporary, "LocalHarness-lowered.tmp");
    await copyFile(product, intermediate);
    const mutate = spawnSync("/usr/bin/vtool", [
      "-set-build-version", "macos", "14.0", "14.0", "-replace",
      "-output", lowered, intermediate
    ], { encoding: "utf8" });
    assert.equal(mutate.status, 0, mutate.stderr);

    const result = invoke(await realpath(lowered));
    assert.notEqual(result.status, 0, "a lower deployment target must fail closed");
    assert.match(result.stderr, /declares macOS minimum 14\.0; expected exactly 15\.0/u);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("the Swift qualification runner binds the deployment gate and rejects retargeting", async () => {
  const runner = await readFile(join(root, "scripts", "run-swift-tests.sh"), "utf8");
  assert.match(runner, /reports Apple's prebuilt Testing\.framework slice/u);
  assert.match(runner, /verify-swiftpm-deployment-target\.sh/u);
  assert.match(runner, /LocalHarnessPackageTests\.xctest\/Contents\/MacOS\/LocalHarnessPackageTests/u);
  assert.match(runner, /accepts no selectors in full mode/u);
  assert.match(runner, /--focused-filter[\s\S]*renderedMacOS26Toolbar/u);
  assert.match(runner, /verify-swift-test-plan\.mjs/u);
});
