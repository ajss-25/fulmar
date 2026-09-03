import assert from "node:assert/strict";
import { execFile, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, link, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import {
  rootWatchdogChildOptions,
  rootWatchdogLogicalArguments
} from "./RootWatchdogChildProcess.mjs";
import {
  buildInputRoots,
  createBuildInputInventory,
  verifyBuildInputInventory
} from "../../scripts/source-build-input-inventory.mjs";

const execFileAsync = promisify(execFile);

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "local-harness-build-inputs-"));
  await writeFile(join(root, "Package.swift"), "// package\n", { mode: 0o644 });
  await writeFile(join(root, "Makefile"), "build:\n\t@true\n", { mode: 0o644 });
  await writeFile(join(root, ".gitattributes"), "* text=auto\n", { mode: 0o644 });
  await writeFile(join(root, ".gitignore"), "build/\n", { mode: 0o644 });
  for (const file of ["README.md", "CHANGELOG.md", "CONTRIBUTING.md", "SECURITY.md", "SUPPORT.md"]) {
    await writeFile(join(root, file), `${file}\n`, { mode: 0o644 });
  }
  await writeFile(join(root, "VendorRuntime.inventory.json"), "{}\n", { mode: 0o644 });
  await mkdir(join(root, "VendorRuntime"), { mode: 0o755 });
  await writeFile(join(root, "VendorRuntime", "package.json"), "{}\n", { mode: 0o644 });
  await writeFile(join(root, "VendorRuntime", "package-lock.json"), "{}\n", { mode: 0o644 });
  for (const directory of [".github", "docs", "Config", "Sources", "Tools", "Tests", "scripts", "Resources"]) {
    await mkdir(join(root, directory), { mode: 0o755 });
    await writeFile(join(root, directory, `${directory}.txt`), `${directory}\n`, { mode: 0o644 });
  }
  return root;
}

async function saveInventory(root, inventory) {
  const path = join(root, "inventory.json");
  await writeFile(path, `${JSON.stringify(inventory, null, 2)}\n`, { mode: 0o600 });
  return path;
}

test("build-input inventory is deterministic and verifies the exact bounded tree", async () => {
  const root = await fixture();
  try {
    const first = await createBuildInputInventory(root);
    const second = await createBuildInputInventory(root);
    assert.deepEqual(first, second);
    assert.deepEqual(first.inputRoots, buildInputRoots);
    assert.ok(first.inputRoots.includes("LICENSE"));
    assert.equal(first.entries.some((entry) => entry.path === "LICENSE"), false);
    assert.ok(first.entries.some((entry) => entry.path === "VendorRuntime/package.json" && entry.type === "file"));
    assert.ok(first.entries.some((entry) => entry.path === "VendorRuntime/package-lock.json" && entry.type === "file"));
    const path = await saveInventory(root, first);
    await verifyBuildInputInventory(root, path);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a future owner-selected LICENSE pair is optional before selection and both files are inventory-bound when present", async () => {
  const root = await fixture();
  try {
    const absentPath = await saveInventory(root, await createBuildInputInventory(root));
    const licence = "future owner-selected licence fixture\n";
    const digest = createHash("sha256").update(licence).digest("hex");
    const metadata = `${JSON.stringify({
      schemaVersion: 1,
      licenseFile: "LICENSE",
      spdxExpression: "MIT",
      displayName: "Fixture licence",
      licenseSHA256: digest
    }, null, 2)}\n`;
    await writeFile(join(root, "LICENSE"), licence, { mode: 0o644 });
    await writeFile(join(root, "Config", "ProjectLicense.json"), metadata, { mode: 0o644 });
    await assert.rejects(
      verifyBuildInputInventory(root, absentPath),
      /changed after the candidate was compiled/u
    );

    const present = await createBuildInputInventory(root);
    assert.ok(present.entries.some((entry) => entry.path === "LICENSE" && entry.type === "file"));
    assert.ok(present.entries.some((entry) => entry.path === "Config/ProjectLicense.json" && entry.type === "file"));
    const presentPath = await saveInventory(root, present);
    await writeFile(join(root, "LICENSE"), "mutated licence fixture\n", { mode: 0o644 });
    await assert.rejects(
      verifyBuildInputInventory(root, presentPath),
      /changed after the candidate was compiled/u
    );
    await writeFile(join(root, "LICENSE"), licence, { mode: 0o644 });
    await writeFile(join(root, "Config", "ProjectLicense.json"), `${metadata} `, { mode: 0o644 });
    await assert.rejects(
      verifyBuildInputInventory(root, presentPath),
      /changed after the candidate was compiled/u
    );
    await writeFile(join(root, "Config", "ProjectLicense.json"), metadata, { mode: 0o644 });
    await rm(join(root, "LICENSE"));
    await assert.rejects(
      verifyBuildInputInventory(root, presentPath),
      /changed after the candidate was compiled/u
    );
    await writeFile(join(root, "LICENSE"), licence, { mode: 0o644 });
    await rm(join(root, "Config", "ProjectLicense.json"));
    await assert.rejects(
      verifyBuildInputInventory(root, presentPath),
      /changed after the candidate was compiled/u
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("verification rejects byte mutation, extra files, and missing files", async () => {
  for (const mutation of [
    async (root) => writeFile(join(root, "Sources", "Sources.txt"), "changed\n"),
    async (root) => writeFile(join(root, "docs", "docs.txt"), "changed-docs\n"),
    async (root) => writeFile(join(root, ".gitattributes"), "* -text\n"),
    async (root) => writeFile(join(root, "Makefile"), "changed-target:\n\t@false\n"),
    async (root) => writeFile(join(root, "VendorRuntime", "package.json"), "{\"name\":\"mutated\"}\n"),
    async (root) => writeFile(join(root, "VendorRuntime", "package-lock.json"), "{\"lockfileVersion\":3}\n"),
    async (root) => writeFile(join(root, "Tools", "Tools.txt"), "changed-helper\n"),
    async (root) => writeFile(join(root, "Tests", "extra.txt"), "extra\n"),
    async (root) => rm(join(root, "Resources", "Resources.txt"))
  ]) {
    const root = await fixture();
    try {
      const path = await saveInventory(root, await createBuildInputInventory(root));
      await mutation(root);
      await assert.rejects(verifyBuildInputInventory(root, path), /changed after the candidate was compiled/u);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }
});

test("production assembly always compiles into a fresh private Swift scratch tree", async () => {
  const script = await readFile(join(process.cwd(), "scripts", "build-app.sh"), "utf8");
  assert.match(script, /mktemp -d \/private\/tmp\/local-harness-swift-build\.XXXXXX/u);
  assert.match(script, /swift build[\s\S]*--scratch-path "\$BUILD_SCRATCH"/u);
  assert.match(script, /SWIFT_SOURCE_ROOT="\$BUILD_SCRATCH\/canonical-source"/u);
  assert.match(script, /--package-path "\$SWIFT_SOURCE_ROOT"/u);
  assert.doesNotMatch(script, /--package-path "\$PROJECT_DIR"/u);
  assert.match(script, /source-build-input-inventory\.mjs[\s\S]*verify "\$SWIFT_SOURCE_ROOT" "\$SOURCE_INPUT_INVENTORY"/u);
  assert.ok((script.match(/verify "\$SWIFT_SOURCE_ROOT" "\$SOURCE_INPUT_INVENTORY"/gu)?.length ?? 0) >= 2);
  assert.match(script, /ditto --norsrc --noextattr --noacl --noqtn/u);
  assert.doesNotMatch(script, /-remove-runtime-asserts|-Ounchecked/u);
  assert.match(script, /--jobs 1/u);
  assert.match(script, /LOCAL_HARNESS_CLEAN_RELEASE_ENVIRONMENT/u);
  assert.match(script, /\/usr\/bin\/env -i/u);
  assert.match(script, /unexpected_environment/u);
  assert.match(script, /SAFE_RELEASE_PATH="\/usr\/bin:\/bin:\/usr\/sbin:\/sbin"/u);
  assert.match(script, /-Xlinker -oso_prefix[\s\\]+-Xlinker "\$BUILD_SCRATCH"[\s\\]+-Xlinker -reproducible/u);
  assert.match(script, /-debug-info-format none/u);
  assert.match(script, /-Xswiftc -Xfrontend[\s\\]*-Xswiftc -g/u);
  assert.match(script, /-Xswiftc -file-compilation-dir[\s\\]*-Xswiftc \/Fulmar\/Compilation/u);
  assert.match(script, /automatic_dsym="\$\(\/usr\/bin\/find "\$BUILD_SCRATCH" -type d -name '\*\.dSYM' -print -quit\)"/u);
  assert.match(script, /--oso-prepend-path "\$BUILD_SCRATCH"/u);
  assert.match(script, /--object-prefix-map "\/Fulmar\/Build="/u);
  assert.match(script, /--object-prefix-map "\/Fulmar\/Generated\/\$scratch_leaf="/u);
  assert.doesNotMatch(script, /--no-object-timestamp|--no-swiftmodule-timestamp/u);
  assert.match(script, /SWIFTPM_CACHE_DIR="\$BUILD_SCRATCH\/swiftpm-cache"/u);
  assert.match(script, /ICONSET_DIR="\$BUILD_SCRATCH\/AppIcon\.iconset"/u);
  assert.doesNotMatch(script, /SWIFTPM_CACHE_DIR="\$PROJECT_DIR\/\.build/u);
  assert.doesNotMatch(script, /ICONSET_DIR="\$PROJECT_DIR\/\.build/u);
  assert.match(script, /BUILD_OUTPUT_DIR="\$PROJECT_DIR\/build"/u);
  assert.match(script, /release-artifact root is not private/u);
  assert.match(script, /Refusing an unsafe pre-existing release output/u);
  assert.match(script, /run_release_command_without_warnings/u);
  assert.match(script, /release-command-gate\.zsh/u);
  assert.match(script, /Swift production build/u);
  assert.match(script, /dSYM generation for \$product/u);
  assert.doesNotMatch(script, /\| rg -q 'Mach-O'/u);
  assert.match(script, /\/usr\/bin\/file "\$candidate" > "\$FILE_KIND"/u);
  assert.match(script, /MACHO_STATUS=\$\?/u);
  assert.match(script, /MACHO_STATUS != 1/u);
  assert.match(script, /select-compatible-swift-sdk\.sh/u);
  assert.match(script, /native_products=\([\s\S]*LocalHarness[\s\S]*LocalHarnessUpdateHelper[\s\S]*\)/u);
  assert.match(script, /compiled="\$BUILD_SCRATCH\/release\/\$product"/u);
  assert.match(script, /verify-macho-compatibility\.sh" \\\n+  "\$APP_DIR" "\$RUNTIME_SIGNABLES" "\$MINIMUM_MACOS"/u);
  assert.match(script, /"\$BUILD_SCRATCH\/release\/IconPacker"/u);
  assert.doesNotMatch(script, /"\$PROJECT_DIR\/\.build\/release\//u);
});

test("the canonical Swift snapshot covers every source-build inventory root", async () => {
  const script = await readFile(join(process.cwd(), "scripts", "build-app.sh"), "utf8");
  const match = script.match(/source_snapshot_roots=\(\n([\s\S]*?)\n\)/u);
  assert.ok(match, "missing canonical Swift source-snapshot roots");
  const roots = match[1]
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  assert.deepEqual(roots, buildInputRoots);
});

test("release command gate rejects producer, log-sink, stdout-warning, and stderr-warning failures", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-release-command-gate-"));
  const gate = join(process.cwd(), "scripts", "release-command-gate.zsh");
  const watchdog = join(process.cwd(), "scripts", "run-with-watchdog.sh");
  let invocation = 0;
  const invokeWithLog = async (logPath, ...command) => {
    const argumentsList = rootWatchdogLogicalArguments([
      "--seconds", "15", "--max-rss-bytes", String(512 * 1024 * 1024),
      "--rss-grace-seconds", "1", "--emergency-rss-bytes", String(1024 * 1024 * 1024),
      "--label", "release command gate fixture", "--",
      "/bin/zsh", "-f", gate, "fixture", logPath, ...command
    ]);
    const result = spawnSync(watchdog, argumentsList, rootWatchdogChildOptions({
      encoding: "utf8", timeout: 20_000
    }));
    if (result.error || result.signal !== null || result.status !== 0) {
      const error = new Error(`release command gate failed (${result.status ?? result.signal}): ${result.stderr}`);
      error.code = result.status;
      error.stdout = result.stdout;
      error.stderr = result.stderr;
      throw error;
    }
    return { stdout: result.stdout, stderr: result.stderr };
  };
  const invoke = (...command) => {
    invocation += 1;
    return invokeWithLog(join(root, `command-${invocation}.log`), ...command);
  };
  try {
    const sourceResult = spawnSync("/bin/zsh", ["-f", "-c", 'source "$1"', "fixture", gate],
      rootWatchdogChildOptions({ encoding: "utf8", timeout: 5_000 }));
    assert.equal(sourceResult.status, 0, sourceResult.stderr || sourceResult.error?.message);
    await invoke("/bin/sh", "-p", "-c", "printf 'clean output\\n'");
    await assert.rejects(invoke("/bin/sh", "-p", "-c", "printf 'warning: stdout diagnostic\\n'"));
    await assert.rejects(invoke("/bin/sh", "-p", "-c", "printf 'warning: stderr diagnostic\\n' >&2"));
    await assert.rejects(invoke("/bin/sh", "-p", "-c", "printf '\\033[33mwarning: coloured diagnostic\\033[0m\\n'"));
    await assert.rejects(invoke("/bin/sh", "-p", "-c", "exit 7"));
    const vanishingLog = join(root, "vanishing.log");
    await assert.rejects(invokeWithLog(vanishingLog,
      "/bin/sh", "-p", "-c", 'printf "clean output\\n"; rm -f "$1"', "fixture", vanishingLog));
    const swappedLog = join(root, "swapped.log");
    await assert.rejects(invokeWithLog(swappedLog,
      "/bin/sh", "-p", "-c", 'printf "warning: hidden diagnostic\\n"; rm -f "$1"; printf "clean replacement\\n" > "$1"',
      "fixture", swappedLog));
    await assert.rejects(invokeWithLog(root, "/bin/true"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("production assembly strips private native symbols only after preserving matching dSYMs", async () => {
  const [build, verifier, release] = await Promise.all([
    readFile(join(process.cwd(), "scripts", "build-app.sh"), "utf8"),
    readFile(join(process.cwd(), "scripts", "verify-native-symbol-privacy.sh"), "utf8"),
    readFile(join(process.cwd(), "scripts", "verify-release.sh"), "utf8")
  ]);
  const dSYM = build.indexOf("dsymutil --verify-dwarf=output");
  const strip = build.indexOf('/usr/bin/strip -S -x "$destination"');
  const firstSignature = build.indexOf('codesign "${SIGN_ARGS[@]}"');
  assert.ok(dSYM >= 0 && strip > dSYM && firstSignature > strip);
  assert.match(build, /-file-prefix-map[\s\S]*\/Fulmar\/Sources/u);
  assert.match(build, /-prefix-serialized-debugging-options/u);
  assert.match(build, /BUILD_SCRATCH[\s\S]*\/Fulmar\/Build/u);
  assert.match(build, /HOST_TEMP_ROOT[\s\S]*\/Fulmar\/Generated/u);
  assert.match(verifier, / \(SO\|OSO\) /u);
  assert.match(verifier, /segname __DWARF\|sectname __debug_/u);
  assert.match(verifier, /dSYM UUID does not match its executable/u);
  assert.match(verifier, /unexpected internal topology/u);
  assert.match(verifier, /CFBundleIdentifier[\s\S]*com\.apple\.xcode\.dsym\.\$product/u);
  assert.match(verifier, /binary-path:\s+\$product/u);
  assert.match(verifier, /\/private\/tmp\/\|\/tmp\/\|\/var\/folders\//u);
  assert.match(verifier, /probe_file_pattern/u);
  assert.doesNotMatch(verifier, /if (?:LC_ALL=C )?\/usr\/bin\/grep/u);
  assert.doesNotMatch(verifier, /done < <\(\/usr\/bin\/find "\$symbol_bundle"/u);
  const signature = release.indexOf('verify_code_signature "$APP_DIR" --deep --strict');
  const privacy = release.indexOf("verify-native-symbol-privacy.sh");
  const adversarial = release.indexOf("verify-native-symbol-privacy-adversarial.sh");
  const candidateRuntime = release.indexOf('"$NODE" --version');
  assert.ok(signature >= 0 && privacy > signature && adversarial > privacy && candidateRuntime > adversarial);
});

test("the shipped SBOM hashes signed Runtime bytes before the app signature", async () => {
  const script = await readFile(join(process.cwd(), "scripts", "build-app.sh"), "utf8");
  const runtimeSeal = script.indexOf('"$NODE_BIN" "$INVENTORY_TOOL" verify-signing-transition');
  const sbom = script.indexOf('"$NODE_BIN" "$PROJECT_DIR/scripts/generate-sbom.mjs"');
  const appSignature = script.indexOf('codesign "${SIGN_ARGS[@]}" --entitlements "$PROJECT_DIR/Resources/LocalHarness.entitlements"');
  assert.ok(runtimeSeal >= 0, "Runtime signing transition must be sealed");
  assert.ok(sbom > runtimeSeal, "SBOM must hash post-signing Runtime bytes");
  assert.ok(appSignature > sbom, "the app signature must bind the generated SBOM");
});

test("the optimized app entry point explicitly retains its weak NSApplication delegate for the event loop", async () => {
  const source = await readFile(join(process.cwd(), "Sources/LocalHarness/LocalHarnessApp.swift"), "utf8");
  assert.match(source, /app\.delegate = delegate\s+withExtendedLifetime\(delegate\)\s*\{\s*app\.run\(\)\s*\}/u);
});

test("inventory refuses symbolic, hard-linked, and group-writable inputs", async () => {
  const cases = [
    async (root) => {
      await rm(join(root, "Sources", "Sources.txt"));
      await symlink(join(root, "Package.swift"), join(root, "Sources", "Sources.txt"));
    },
    async (root) => {
      await rm(join(root, "Sources", "Sources.txt"));
      await link(join(root, "Package.swift"), join(root, "Sources", "Sources.txt"));
    },
    async (root) => chmod(join(root, "Sources", "Sources.txt"), 0o664)
  ];
  for (const mutation of cases) {
    const root = await fixture();
    try {
      await mutation(root);
      await assert.rejects(createBuildInputInventory(root), /not accepted|not owner-controlled/u);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }
});

test("release manifest schema binds the exact source-build-input inventory", async () => {
  const root = await mkdtemp(join(tmpdir(), "local-harness-release-manifest-"));
  try {
    const identity = JSON.parse(await readFile(join(process.cwd(), "Config", "ReleaseIdentity.json"), "utf8"));
    const archive = join(root, identity.releaseArchiveName);
    const info = join(root, "Info.json");
    const destination = join(root, "release-manifest.json");
    const symbols = join(root, identity.symbolsArchiveName);
    await writeFile(archive, "archive-bytes", { mode: 0o600 });
    await writeFile(symbols, "symbol-bytes", { mode: 0o600 });
    await writeFile(info, JSON.stringify({
      CFBundleDisplayName: identity.productDisplayName,
      CFBundleName: identity.productDisplayName,
      CFBundleIdentifier: identity.bundleIdentifier,
      CFBundleShortVersionString: identity.appVersion,
      CFBundleVersion: String(identity.appBuild),
      LSMinimumSystemVersion: identity.minimumMacOS
    }), { mode: 0o600 });
    const names = [
      "VendorRuntime.inventory.json",
      "runtime-unsigned-inventory.json",
      "runtime-signables.json",
      "runtime-release-inventory.json",
      "source-build-inputs.json",
      "static-security-summary.json",
      "toolchain-inventory.json"
    ];
    const artifacts = names.map((name) => join(root, name));
    await Promise.all(artifacts.map((path, index) => writeFile(path, `artifact-${index}\n`, { mode: 0o600 })));

    await execFileAsync(process.execPath, [
      join(process.cwd(), "scripts", "generate-release-manifest.mjs"),
      archive, info, destination, symbols, ...artifacts
    ]);
    const verified = await execFileAsync(process.execPath, [
      join(process.cwd(), "scripts", "verify-release-manifest.mjs"),
      destination, archive, info, symbols, ...artifacts
    ]);
    assert.match(verified.stdout, /Release manifest verified/u);
    const generatedManifest = JSON.parse(await readFile(destination, "utf8"));
    assert.equal(generatedManifest.schemaVersion, 6);
    assert.equal(generatedManifest.inventories.staticSecurity.file, "static-security-summary.json");

    await writeFile(info, JSON.stringify({
      CFBundleDisplayName: identity.productDisplayName,
      CFBundleName: identity.productDisplayName,
      CFBundleIdentifier: identity.bundleIdentifier,
      CFBundleShortVersionString: "0.0.0-stale",
      CFBundleVersion: "1",
      LSMinimumSystemVersion: identity.minimumMacOS
    }), { mode: 0o600 });
    await assert.rejects(
      execFileAsync(process.execPath, [
        join(process.cwd(), "scripts", "verify-release-manifest.mjs"),
        destination, archive, info, symbols, ...artifacts
      ]),
      /Info\.plist does not match the reviewed release identity/u
    );
    await writeFile(info, JSON.stringify({
      CFBundleDisplayName: identity.productDisplayName,
      CFBundleName: identity.productDisplayName,
      CFBundleIdentifier: identity.bundleIdentifier,
      CFBundleShortVersionString: identity.appVersion,
      CFBundleVersion: String(identity.appBuild),
      LSMinimumSystemVersion: identity.minimumMacOS
    }), { mode: 0o600 });

    const buildInputArtifact = artifacts[names.indexOf("source-build-inputs.json")];
    await writeFile(buildInputArtifact, "mutated-build-input-inventory\n");
    await assert.rejects(
      execFileAsync(process.execPath, [
        join(process.cwd(), "scripts", "verify-release-manifest.mjs"),
        destination, archive, info, symbols, ...artifacts
      ]),
      /release manifest does not exactly describe/u
    );

    await writeFile(buildInputArtifact, `artifact-${names.indexOf("source-build-inputs.json")}\n`, { mode: 0o600 });
    const staticSecurityArtifact = artifacts[names.indexOf("static-security-summary.json")];
    await writeFile(staticSecurityArtifact, "digest-tampered-static-security-summary\n", { mode: 0o600 });
    await assert.rejects(
      execFileAsync(process.execPath, [
        join(process.cwd(), "scripts", "verify-release-manifest.mjs"),
        destination, archive, info, symbols, ...artifacts
      ]),
      /release manifest does not exactly describe/u
    );
    await writeFile(staticSecurityArtifact, `artifact-${names.indexOf("static-security-summary.json")}\n`, { mode: 0o600 });
    await rm(staticSecurityArtifact);
    await assert.rejects(
      execFileAsync(process.execPath, [
        join(process.cwd(), "scripts", "verify-release-manifest.mjs"),
        destination, archive, info, symbols, ...artifacts
      ]),
      /ENOENT|no such file/u
    );
    await writeFile(staticSecurityArtifact, `artifact-${names.indexOf("static-security-summary.json")}\n`, { mode: 0o600 });
    await writeFile(symbols, "mutated-symbol-bytes", { mode: 0o600 });
    await assert.rejects(
      execFileAsync(process.execPath, [
        join(process.cwd(), "scripts", "verify-release-manifest.mjs"),
        destination, archive, info, symbols, ...artifacts
      ]),
      /release manifest does not exactly describe/u
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
