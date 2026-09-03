import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  dependencyChanges,
  exactDeepSeekCohortOverrides,
  inventoryChanges,
  markdown,
  publishReviewBundle,
  reviewBundleDigest,
  runBoundedCommand,
  sensitiveDeepSeekPackageChanges,
  validateExactDeepSeekCohort,
  validateRegistryProvenance,
  validateRegistrySignature,
  validateTargetVersion
} from "../../scripts/prepare-dsh-upgrade.mjs";

test("DSH upgrade preparation accepts only one exact semantic version", () => {
  for (const version of ["0.1.2", "0.1.2-rc.1", "1.0.0+review.4"]) {
    assert.equal(validateTargetVersion(version), version);
  }
  for (const value of ["latest", "^1.2.3", "1.2", "1.2.3 || 9.9.9", "../1.2.3", ""]) {
    assert.throws(() => validateTargetVersion(value), /exact semantic version|target must/u);
  }
});

test("DSH review publication is private atomic immutable and idempotent", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-dsh-review-publish."));
  const parent = join(root, "observations");
  const files = {
    "review.json": Buffer.from("{\"safe\":true}\n"),
    "candidate-package-lock.json": Buffer.from("{\"lockfileVersion\":3}\n")
  };
  const digest = reviewBundleDigest(files);
  try {
    const first = await publishReviewBundle(parent, digest, files);
    assert.equal(first.alreadyPublished, false);
    const second = await publishReviewBundle(parent, digest, files);
    assert.equal(second.alreadyPublished, true);
    assert.equal(second.directory, first.directory);
    assert.deepEqual((await readFile(join(first.directory, "review.json"))), files["review.json"]);

    const changed = { ...files, "review.json": Buffer.from("{\"safe\":false}\n") };
    await assert.rejects(
      publishReviewBundle(parent, digest, changed),
      /digest does not match/u
    );

    const hostileParent = join(root, "hostile-parent");
    await mkdir(hostileParent, { mode: 0o700 });
    const hostileFiles = { "review.json": Buffer.from("{}\n") };
    const hostileDigest = reviewBundleDigest(hostileFiles);
    await symlink(root, join(hostileParent, hostileDigest));
    await assert.rejects(
      publishReviewBundle(hostileParent, hostileDigest, hostileFiles),
      /published review directory is not an exact private directory/u
    );

    const partialParent = join(root, "partial-parent");
    await mkdir(partialParent, { mode: 0o700 });
    const partialDigest = reviewBundleDigest(hostileFiles);
    const partial = join(partialParent, partialDigest);
    await mkdir(partial, { mode: 0o700 });
    await writeFile(join(partial, "unexpected"), "partial", { mode: 0o600 });
    await assert.rejects(
      publishReviewBundle(partialParent, partialDigest, hostileFiles),
      /unexpected file set/u
    );

    const permissive = join(root, "permissive");
    await mkdir(permissive, { mode: 0o755 });
    await chmod(permissive, 0o755);
    await assert.rejects(
      publishReviewBundle(permissive, hostileDigest, hostileFiles),
      /exact private directory/u
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("DSH registry provenance requires a valid signature from the reviewed npm key", () => {
  const target = "0.1.2-alpha.3";
  const registry = {
    "dist.tarball": `https://registry.npmjs.org/@deepseek-ai/dsh/-/dsh-${target}.tgz`,
    "dist.integrity": "sha512-VvATzYmQ4LMJREJ9e2POKksSHRfqP3y9pghplLBaQBuw2BqfbC0mQUVsaPwxe4wlcpj+riEgn8OJB01YnpF+3A==",
    "dist.signatures": [{
      keyid: "SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U",
      sig: "MEQCIAe/ZalaZbHHDi1NdEEWNgDQdlKMYMIRaR/MkJ1cFCYMAiA5Ai4wE0lKYDH4wkuQ0xbZC5hKzMUjBgjeMXz0/9Kmvg=="
    }]
  };
  assert.deepEqual(validateRegistrySignature("@deepseek-ai/dsh", target, registry), {
    keyid: registry["dist.signatures"][0].keyid
  });
  assert.throws(
    () => validateRegistrySignature("@deepseek-ai/dsh", "0.1.2-alpha.2", registry),
    /unexpected DSH tarball/u
  );
  const changed = structuredClone(registry);
  changed["dist.signatures"][0].sig = Buffer.alloc(70, 0x11).toString("base64");
  assert.throws(() => validateRegistrySignature("@deepseek-ai/dsh", target, changed), /did not verify/u);
  assert.throws(
    () => validateRegistrySignature("@deepseek-ai/dsh", target, registry, [{
      keyid: registry["dist.signatures"][0].keyid,
      keytype: "unsupported",
      scheme: "unsupported",
      expires: null,
      key: "not-a-key"
    }]),
    /signing-key configuration is invalid/u
  );
});

test("sensitive DSH review covers transitive code, config, manifests, and profile boot chunks", () => {
  const changes = [
    { path: "@deepseek-ai/dsh/package.json", change: "changed" },
    { path: "@deepseek-ai/dsh/lib/profile-boot-a1b2.js", change: "changed" },
    { path: "@deepseek-ai/dsh-session/config/default.yml", change: "added" },
    { path: "@deepseek-ai/dsh-tool-web/src/index.ts", change: "changed" },
    { path: "@deepseek-ai/dsh/README.md", change: "changed" },
    { path: "@deepseek-ai/not-dsh/lib/index.js", change: "changed" }
  ];
  assert.deepEqual(sensitiveDeepSeekPackageChanges(changes), changes.slice(0, 4));
});

test("DSH upgrade preparation pins and verifies the complete prerelease cohort", () => {
  const target = "0.1.2-alpha.3";
  const provisional = {
    packages: {
      "": { name: "candidate" },
      "node_modules/@deepseek-ai/dsh": { version: target },
      "node_modules/@deepseek-ai/dsh-agent": { version: "0.1.2-alpha.4" },
      "node_modules/@deepseek-ai/dsh-agent/node_modules/react": { version: "19.2.8" },
      "node_modules/other/node_modules/@deepseek-ai/dsh-tool-bash": { version: "0.1.2-alpha.4" },
      "node_modules/@deepseek-ai/not-dsh": { version: "9.9.9" }
    }
  };
  assert.deepEqual(exactDeepSeekCohortOverrides(provisional, target), {
    "@deepseek-ai/dsh-agent": target,
    "@deepseek-ai/dsh-tool-bash": target
  });

  const exact = structuredClone(provisional);
  exact.packages["node_modules/@deepseek-ai/dsh-agent"].version = target;
  exact.packages["node_modules/other/node_modules/@deepseek-ai/dsh-tool-bash"].version = target;
  assert.deepEqual(validateExactDeepSeekCohort(exact, target), [
    `@deepseek-ai/dsh-agent@${target}`,
    `@deepseek-ai/dsh-tool-bash@${target}`,
    `@deepseek-ai/dsh@${target}`
  ]);
  assert.throws(
    () => validateExactDeepSeekCohort(provisional, target),
    /cohort drifted/u
  );
  assert.throws(
    () => exactDeepSeekCohortOverrides({ packages: {} }, target),
    /requested DSH root/u
  );
});

test("human upgrade report preserves npm's exact dist provenance keys", () => {
  const rendered = markdown({
    currentVersion: "0.1.1-rc.1",
    targetVersion: "0.1.1-rc.2",
    generatedAt: "2026-08-29T00:00:00.000Z",
    registry: {
      "dist.tarball": "https://registry.npmjs.org/@deepseek-ai/dsh/-/dsh-0.1.1-rc.2.tgz",
      "dist.integrity": "sha512-review-provenance"
    },
    lockIntegrity: "sha512-review-provenance",
    rootDependencyChanges: [],
    blockers: [],
    sensitivePackageChanges: [],
    packageChanges: [],
    resolvedProductionPackages: 511,
    localMCPPeerContractMatches: false,
    candidateContainsForbiddenDeepSeekHeaders: true,
    audit: { totalVulnerabilities: 0 }
  });
  assert.match(rendered, /Tarball: https:\/\/registry\.npmjs\.org\/@deepseek-ai\/dsh\/-\/dsh-0\.1\.1-rc\.2\.tgz/u);
  assert.match(rendered, /Integrity: `sha512-review-provenance`/u);
  assert.doesNotMatch(rendered, /Tarball: unavailable|Integrity: `unavailable`/u);
  assert.doesNotMatch(rendered, /Root DSH package files changed/u);
  assert.equal([...rendered.matchAll(/First-party file changes/gmu)].length, 1);
});

test("DSH upgrade provenance fails closed on origin, version, integrity, and lock drift", () => {
  const target = "0.1.1-rc.2";
  const registry = {
    "dist.tarball": "https://registry.npmjs.org/@deepseek-ai/dsh/-/dsh-0.1.1-rc.2.tgz",
    "dist.integrity": `sha512-${Buffer.alloc(64, 0x55).toString("base64")}`
  };
  assert.deepEqual(validateRegistryProvenance(target, registry), {
    tarball: registry["dist.tarball"],
    integrity: registry["dist.integrity"]
  });
  assert.deepEqual(validateRegistryProvenance(target, registry, {
    resolved: registry["dist.tarball"],
    integrity: registry["dist.integrity"]
  }), {
    tarball: registry["dist.tarball"],
    integrity: registry["dist.integrity"]
  });

  for (const rejected of [
    { ...registry, "dist.tarball": "https://example.com/dsh-0.1.1-rc.2.tgz" },
    { ...registry, "dist.tarball": "https://registry.npmjs.org/@deepseek-ai/dsh/-/dsh-0.1.1-rc.1.tgz" },
    { ...registry, "dist.integrity": "sha256-not-the-reviewed-algorithm" },
    { "dist.tarball": registry["dist.tarball"] }
  ]) {
    assert.throws(() => validateRegistryProvenance(target, rejected), /unexpected DSH tarball|invalid DSH integrity/u);
  }
  assert.throws(
    () => validateRegistryProvenance(target, registry, {
      resolved: registry["dist.tarball"],
      integrity: `sha512-${Buffer.alloc(64, 0x44).toString("base64")}`
    }),
    /lock provenance does not match/u
  );
});

test("dependency review is deterministic and explicit", () => {
  assert.deepEqual(
    dependencyChanges({ a: "1", b: "1" }, { b: "2", c: "1" }),
    [
      { name: "a", change: "removed", current: "1" },
      { name: "b", change: "changed", current: "1", candidate: "2" },
      { name: "c", change: "added", candidate: "1" }
    ]
  );
});

test("package inventory review reports added, removed, and changed paths", () => {
  assert.deepEqual(
    inventoryChanges(
      [{ path: "a", sha256: "1" }, { path: "b", sha256: "1" }],
      [{ path: "b", sha256: "2" }, { path: "c", sha256: "1" }]
    ),
    [
      { path: "a", change: "removed" },
      { path: "b", change: "changed" },
      { path: "c", change: "added" }
    ]
  );
});

test("bounded release commands neither inherit secrets nor retain quadratic output buffers", async () => {
  const previousSecret = process.env.FULMAR_TEST_SECRET;
  process.env.FULMAR_TEST_SECRET = "must-not-cross-the-child-boundary";
  try {
    const result = await runBoundedCommand(process.execPath, [
      "-e",
      "process.stdout.write(JSON.stringify(process.env))"
    ], {
      environment: { PATH: "/usr/bin:/bin" },
      timeoutMS: 2_000,
      maximumStandardOutputBytes: 4_096,
      maximumStandardErrorBytes: 4_096,
      label: "environment probe"
    });
    const environment = JSON.parse(result.stdout);
    assert.equal(environment.FULMAR_TEST_SECRET, undefined);
    // CoreFoundation may inject this locale hint into every macOS process
    // after exec even when `env` is otherwise an exact allowlist.
    delete environment.__CF_USER_TEXT_ENCODING;
    assert.deepEqual(environment, { PATH: "/usr/bin:/bin" });

    const started = Date.now();
    await assert.rejects(
      runBoundedCommand(process.execPath, [
        "-e",
        "for (;;) process.stderr.write('0123456789abcdef')"
      ], {
        environment: { PATH: "/usr/bin:/bin" },
        timeoutMS: 2_000,
        maximumStandardOutputBytes: 1_024,
        maximumStandardErrorBytes: 1_024,
        label: "noisy release probe"
      }),
      /standard error limit/u
    );
    assert.ok(Date.now() - started < 2_000);
  } finally {
    if (previousSecret === undefined) delete process.env.FULMAR_TEST_SECRET;
    else process.env.FULMAR_TEST_SECRET = previousSecret;
  }
});

test("an escaped descendant holding release-command pipes cannot defeat the bound", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-bounded-child-test."));
  const pidFile = join(root, "escaped.pid");
  let escapedPID = 0;
  try {
    const descendantProgram = [
      "process.on('SIGTERM', () => {});",
      "setTimeout(() => process.exit(0), 5000);",
      "setInterval(() => process.stderr.write('escaped-descendant'), 2);"
    ].join("");
    const parentProgram = [
      "const {spawn}=require('node:child_process');",
      "const {writeFileSync}=require('node:fs');",
      "const child=spawn(process.execPath,['-e',process.argv[2]],{",
      "detached:true,stdio:['ignore','inherit','inherit'],env:{PATH:'/usr/bin:/bin'}});",
      "writeFileSync(process.argv[1],String(child.pid),{mode:0o600});",
      "child.unref();"
    ].join("");
    const started = Date.now();
    await assert.rejects(
      runBoundedCommand(process.execPath, ["-e", parentProgram, pidFile, descendantProgram], {
        environment: { PATH: "/usr/bin:/bin" },
        timeoutMS: 3_000,
        maximumStandardOutputBytes: 4_096,
        maximumStandardErrorBytes: 4_096,
        label: "escaped descendant probe"
      }),
      /descendant output streams open|standard error limit/u
    );
    assert.ok(Date.now() - started < 2_000);
    escapedPID = Number.parseInt((await readFile(pidFile, "utf8")).trim(), 10);
    assert.ok(Number.isSafeInteger(escapedPID) && escapedPID > 1);
  } finally {
    if (escapedPID > 1) {
      try { process.kill(escapedPID, "SIGKILL"); } catch {}
    }
    await rm(root, { recursive: true, force: true });
  }
});
