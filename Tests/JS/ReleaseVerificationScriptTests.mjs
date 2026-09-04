import assert from "node:assert/strict";
import test from "node:test";
import { existsSync } from "node:fs";
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { assertCIWorkflowSigningTransport } from "../Fixtures/CISigningTransportSmoke.mjs";

const verifierPath = join(process.cwd(), "scripts", "verify-release.sh");

test("release verifier never executes a candidate-bundle interpreter before inventory verification", async () => {
  const script = await readFile(verifierPath, "utf8");
  const zipCheck = '"$INVENTORY_NODE" "$PROJECT_DIR/scripts/verify-zip-entries.mjs"';
  const treeCheck = '"$INVENTORY_NODE" "$PROJECT_DIR/scripts/verify-release-tree.mjs"';
  const signedRuntimeCheck = '"$INVENTORY_NODE" "$INVENTORY_TOOL" verify-signed-runtime';
  const firstCandidateNodeExecution = '[[ "$("$NODE" --version)" == "v$PINNED_NODE_VERSION" ]]';
  const packagedLockComparison = 'cmp -s "$PROJECT_DIR/VendorRuntime/package-lock.json" "$LOCKFILE"';
  const dependencyAudit = [
    '"$NODE" "$PROJECT_DIR/scripts/verify-dependency-audit.mjs" \\',
    '  "$AUDIT_SUMMARY" "$VENDOR_ROOT/package-lock.json"'
  ].join("\n");

  assert.ok(script.includes(zipCheck), "archive structure must use the independently pinned interpreter");
  assert.ok(script.includes(treeCheck), "tree comparison must use the independently pinned interpreter");
  assert.equal(
    /^"\$SOURCE_NODE"/mu.test(script),
    false,
    "the unverified source-bundle interpreter must never be executed"
  );

  const inventoryIndex = script.indexOf(signedRuntimeCheck);
  const candidateExecutionIndex = script.indexOf(firstCandidateNodeExecution);
  assert.ok(inventoryIndex >= 0, "signed runtime inventory verification must be present");
  assert.ok(candidateExecutionIndex > inventoryIndex, "candidate Node may execute only after signed-runtime inventory verification");
  const packagedLockComparisonIndex = script.indexOf(packagedLockComparison);
  const dependencyAuditIndex = script.indexOf(dependencyAudit);
  assert.ok(packagedLockComparisonIndex > inventoryIndex,
    "the packaged lock must be byte-bound to the reviewed npm project after runtime inventory verification");
  assert.ok(dependencyAuditIndex > packagedLockComparisonIndex,
    "dependency evidence must use the complete reviewed npm project after the packaged lock is bound to it");
  assert.doesNotMatch(
    script,
    /verify-dependency-audit\.mjs" "\$AUDIT_SUMMARY" "\$LOCKFILE"/u,
    "the incomplete packaged Runtime root must never be treated as an npm project"
  );
  assert.match(script, /verify-macho-compatibility\.sh" \\\n+  "\$APP_DIR" "\$RUNTIME_SIGNABLES" "\$MINIMUM_MACOS"/u);
});

test("runtime assembly restores reviewed distributable modes inside the private build root", async () => {
  const script = await readFile(join(process.cwd(), "scripts", "build-app.sh"), "utf8");
  assert.match(
    script,
    /umask 022\ncp "\$NODE_BIN" "\$RUNTIME_DIR\/node"[\s\S]*cp "\$VENDOR_ROOT\/package-lock\.json" "\$RUNTIME_DIR\/package-lock\.json"\numask 077\n\n# Re-attest/u
  );
  assert.match(script, /SIGNABLE_CANDIDATES="\$BUILD_SCRATCH\/signable-candidates\.txt"/u);
  assert.match(script, /SIGNABLE_PIPE_STATUS=\("\$\{pipestatus\[@\]\}"\)/u);
  assert.match(script, /done < "\$SIGNABLE_CANDIDATES"/u);
  assert.doesNotMatch(script, /done < <\(find "\$CONTENTS_DIR"/u);
});

test("build, archive verification, and public packaging enforce one fail-closed first-party licence state", async () => {
  const [build, release, prepare, publicVerifier, policy] = await Promise.all([
    readFile(join(process.cwd(), "scripts", "build-app.sh"), "utf8"),
    readFile(verifierPath, "utf8"),
    readFile(join(process.cwd(), "scripts", "prepare-public-release-assets.sh"), "utf8"),
    readFile(join(process.cwd(), "scripts", "verify-public-distribution.sh"), "utf8"),
    readFile(join(process.cwd(), "scripts", "first-party-license-policy.mjs"), "utf8")
  ]);

  assert.match(build, /first-party-license-policy\.mjs/u);
  assert.match(build, /"\$FIRST_PARTY_LICENSE_POLICY" state "\$PROJECT_DIR"/u);
  assert.match(build, /"\$FIRST_PARTY_LICENSE_POLICY" bundle \\\n+  "\$PROJECT_DIR" "\$RESOURCES_DIR\/LICENSE"/u);
  assert.ok(
    build.indexOf('"$FIRST_PARTY_LICENSE_POLICY" bundle') < build.indexOf('codesign "${SIGN_ARGS[@]}" --entitlements "$PROJECT_DIR/Resources/LocalHarness.entitlements"'),
    "selected LICENSE bytes must enter Resources before the enclosing app signature"
  );
  assert.match(release, /"\$FIRST_PARTY_LICENSE_POLICY" verify-bundle \\\n+  "\$PROJECT_DIR" "\$APP_DIR\/Contents\/Resources\/LICENSE"/u);
  assert.match(prepare, /state "\$PROJECT_DIR" --require-selected/u);
  assert.match(publicVerifier, /state "\$PROJECT_DIR" --require-selected/u);
  assert.match(publicVerifier, /Public package must contain exactly the nine reviewed release assets/u);
  assert.doesNotMatch(policy, /process\.env/u);
  assert.match(policy, /LICENSE and Config\/ProjectLicense\.json must either both exist or both be absent/u);
  assert.match(policy, /readAttestedRegularFile\(path, \{[\s\S]*?requireCurrentUser: true,[\s\S]*?requireOwnerControlledMode: true,[\s\S]*?requireSingleLink: true[\s\S]*?\}\)/u);
  assert.doesNotMatch(policy, /await lstat\(path\)[\s\S]{0,400}await open\(path/u);
  assert.match(policy, /mode & 0o022/u);
  assert.match(policy, /licenseSHA256 !== licenseDigest/u);
  assert.match(policy, /first-party-spdx-v1\.json/u);
  assert.match(policy, /spdxListSHA256/u);
  assert.match(policy, /unknown or unsupported SPDX identifier/u);
});

test("release verifier exercises a byte-identical macOS Applications-style layout", async () => {
  const script = await readFile(verifierPath, "utf8");
  assert.match(script, /SIMULATED_APPLICATIONS="\$TEMP_ROOT\/Applications"/u);
  assert.match(script, /chmod 0775 "\$SIMULATED_APPLICATIONS"/u);
  assert.match(script, /cp -Rp "\$APP_DIR" "\$INSTALLED_LAYOUT_APP"/u);
  assert.match(script, /verify-release-tree\.mjs" "\$APP_DIR" "\$INSTALLED_LAYOUT_APP"/u);
  assert.match(script, /verify_code_signature "\$INSTALLED_LAYOUT_APP" --deep --strict/u);
  assert.doesNotMatch(script, /^codesign --verify --deep --strict "\$INSTALLED_LAYOUT_APP"/mu);
  assert.match(script, /verify-dsh-web-rpc-canary\.mjs" "\$INSTALLED_LAYOUT_APP"/u);
});

test("Applications-style copy preserves executable modes under the release umask", async () => {
  const root = await mkdtemp(join(tmpdir(), "fulmar-applications-copy-"));
  const source = join(root, "source", "Fulmar.app");
  const executable = join(source, "Contents", "MacOS", "LocalHarness");
  const destination = join(root, "Applications", "Fulmar.app");
  try {
    await mkdir(join(source, "Contents", "MacOS"), { recursive: true, mode: 0o700 });
    await mkdir(join(root, "Applications"), { mode: 0o775 });
    await writeFile(executable, "fixture", { mode: 0o755 });
    await chmod(executable, 0o755);
    const copied = spawnSync("/bin/zsh", [
      "-f", "-c",
      'umask 077; /bin/cp -Rp "$1" "$2"',
      "fulmar-applications-copy",
      source,
      destination
    ], { encoding: "utf8", timeout: 10_000 });
    assert.equal(copied.error, undefined, copied.error?.message);
    assert.equal(copied.status, 0, copied.stderr);
    assert.equal((await stat(join(destination, "Contents", "MacOS", "LocalHarness"))).mode & 0o7777, 0o755);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("clean release canaries never depend on ambient Homebrew ripgrep", async () => {
  const cleanCanaries = [
    "verify-runtime-security.sh",
    "verify-simulated-provider-contract.sh",
    "verify-simulated-provider-matrix.sh",
    "verify-app-owned-ollama-generation.sh",
    "verify-dsh-qwen-route.sh",
    "compile-thermal-recovery-probe.sh",
    "wait-for-thermal-recovery.sh"
  ];
  for (const name of cleanCanaries) {
    const script = await readFile(join(process.cwd(), "scripts", name), "utf8");
    assert.doesNotMatch(script, /\brg\s+-/u, `${name} must use absolute system tools under the clean PATH`);
    assert.doesNotMatch(script, /!\s+\/usr\/bin\/grep\b/u, `${name} must distinguish no-match from scanner failure`);
  }

  const runtime = await readFile(join(process.cwd(), "scripts", "verify-runtime-security.sh"), "utf8");
  assert.match(runtime, /PORT_PARSE_STATUS=\$\?/u);
  assert.match(runtime, /PORT_PARSE_STATUS != 1/u);
  assert.doesNotMatch(runtime, /PORT=.*\|.*\|.*\|\| true/u);
  assert.match(runtime, /EVIDENCE_ROOT="\$TEST_ROOT\/evidence"/u);
  assert.match(runtime, /RUNTIME_SANDBOX_TEMP="\$TEST_ROOT\/runtime-sandbox-temp"/u);
  assert.match(runtime, /TMPDIR="\$RUNTIME_SANDBOX_TEMP"/u);
  assert.match(runtime, /LOCAL_HARNESS_SANDBOX_TEMP="\$RUNTIME_SANDBOX_TEMP"/u);
  assert.match(runtime, />"\$EVIDENCE_ROOT\/runtime\.log" 2>"\$EVIDENCE_ROOT\/runtime-error\.log"/u);
  const precreatedLog = runtime.indexOf(': > "$EVIDENCE_ROOT/runtime.log"');
  const backgroundLaunch = runtime.indexOf('>"$EVIDENCE_ROOT/runtime.log" 2>"$EVIDENCE_ROOT/runtime-error.log" &');
  assert.ok(precreatedLog >= 0 && backgroundLaunch > precreatedLog, "runtime evidence must exist before the background redirection race");
  assert.match(runtime, /chmod 600 "\$EVIDENCE_ROOT\/runtime\.log" "\$EVIDENCE_ROOT\/runtime-error\.log"/u);
  assert.doesNotMatch(runtime, />"\$RUNTIME_SANDBOX_TEMP\/runtime\.log"/u);

  const matrix = await readFile(join(process.cwd(), "scripts", "verify-simulated-provider-matrix.sh"), "utf8");
  assert.match(matrix, /marker_status != 1/u);
  assert.match(matrix, /marker_seen == 1/u);
  assert.match(matrix, /secret_scan_status != 1/u);
  assert.match(matrix, /call\.name!=="bash"/u);
  assert.doesNotMatch(matrix, /\/usr\/bin\/grep -R/u);
  const deepSeek402 = matrix.match(/run_failure deepseek deepseek-error-402[^\n]+/u)?.[0] ?? "";
  assert.match(deepSeek402, /insufficient\[ _-\]\*balance/u);
  assert.doesNotMatch(deepSeek402, /\|provider\||\|failed\||\|error(?:'|\|)/u);
  assert.match(matrix, /assert_request_count deepseek MATRIX_ERROR_402 1/u);

  for (const name of [
    "verify-runtime-security.sh",
    "verify-mcp-runtime-security.sh",
    "verify-simulated-provider-contract.sh",
    "verify-simulated-provider-matrix.sh",
    "verify-dsh-qwen-route.sh"
  ]) {
    const source = await readFile(join(process.cwd(), "scripts", name), "utf8");
    assert.doesNotMatch(source, /LOCAL_HARNESS_(?:AUTH_TOKEN|INSTANCE_NONCE)=/u,
      `${name} must exercise the private descriptor transport, not revive legacy environment authentication`);
    assert.match(source, /RuntimeAuthenticationRelay\.pl/u,
      `${name} must use the reviewed source-tree runtime-authentication relay`);
  }
});

test("release lock and public runtime-signing inventory fail closed", async () => {
  const [release, publicVerifier, releaseLock, rootLock] = await Promise.all([
    readFile(verifierPath, "utf8"),
    readFile(join(process.cwd(), "scripts", "verify-public-distribution.sh"), "utf8"),
    readFile(join(process.cwd(), "scripts", "release-lock.zsh"), "utf8"),
    readFile(join(process.cwd(), "scripts", "root-group-lock.zsh"), "utf8")
  ]);
  assert.match(release, /source "\$PROJECT_DIR\/scripts\/release-lock\.zsh"/u);
  assert.match(release, /fulmar_acquire_release_lock "Fulmar release verification"/u);
  assert.match(publicVerifier, /source "\$PROJECT_DIR\/scripts\/release-lock\.zsh"/u);
  assert.match(publicVerifier, /fulmar_acquire_release_lock "Fulmar public-distribution verification"/u);
  assert.match(releaseLock, /fulmar_acquire_root_group_lock/u);
  assert.match(rootLock, /stat -f '%z'[\s\S]*owner_size[\s\S]*-le 1024/u);
  assert.match(rootLock, /FULMAR_LOCK_SUCCESSOR_V1/u);
  assert.doesNotMatch(release, /lock_attempts=|LOCK_OWNER=/u);

  assert.match(publicVerifier, /RUNTIME_SIGNABLE_PATHS="\$TEMP_ROOT\/runtime-signable-paths\.txt"/u);
  assert.match(publicVerifier, /value\.paths\.length < 1 \|\| value\.paths\.length > 64/u);
  assert.match(publicVerifier, /done < "\$RUNTIME_SIGNABLE_PATHS"/u);
  assert.doesNotMatch(publicVerifier, /done < <\("\$NODE"/u);
  assert.match(release, /SIGNABLE_CANDIDATES="\$TEMP_ROOT\/signable-candidates\.txt"/u);
  assert.match(release, /SIGNABLE_PIPE_STATUS=\("\$\{pipestatus\[@\]\}"\)/u);
  assert.match(release, /done < "\$SIGNABLE_CANDIDATES"/u);
  assert.doesNotMatch(release, /done < <\(find "\$APP_DIR\/Contents"/u);
});

test("release entitlement extraction uses the supported XML output form", async () => {
  const script = await readFile(verifierPath, "utf8");
  assert.match(script, /codesign -d --xml --entitlements - "\$executable"/u);
  assert.match(script, /unexpected_stderr/u);
  assert.match(script, /! -s "\$actual_plist"/u);
  assert.doesNotMatch(script, /--entitlements :-/u);
});

test("native qualification uses the portable warning-clean Swift Testing runner", async () => {
  const verifier = await readFile(verifierPath, "utf8");
  const runner = await readFile(join(process.cwd(), "scripts", "run-swift-tests.sh"), "utf8");
  const sdkSelector = await readFile(join(process.cwd(), "scripts", "select-compatible-swift-sdk.sh"), "utf8");
  const eventVerifier = await readFile(join(process.cwd(), "scripts", "verify-swift-test-events.mjs"), "utf8");
  const planVerifier = await readFile(join(process.cwd(), "scripts", "verify-swift-test-plan.mjs"), "utf8");
  const plan = JSON.parse(await readFile(join(process.cwd(), "Config", "SwiftTestPlan.json"), "utf8"));
  const workflow = await readFile(join(process.cwd(), ".github", "workflows", "verify-source.yml"), "utf8");

  assert.match(verifier, /\/bin\/zsh -f "\$PROJECT_DIR\/scripts\/run-swift-tests\.sh"/u);
  assert.match(runner, /-Xswiftc -warnings-as-errors/u);
  assert.match(
    runner,
    /run_guarded "Swift SDK compatibility probe" 600 2147483648 3 3221225472/u,
    "a cold Swift SDK import probe must retain enough wall time for slower supported Macs"
  );
  assert.doesNotMatch(
    sdkSelector,
    /-module-cache-path/u,
    "SDK selection must not rebuild the entire system module cache inside each disposable gate root"
  );
  assert.match(runner, /Testing\.framework/u);
  assert.match(runner, /lib_TestingInterop\.dylib/u);
  assert.match(
    runner,
    /XCODE_TESTING_RUNTIME="\$DEVELOPER_ROOT\/Toolchains\/XcodeDefault\.xctoolchain\/usr\/lib\/swift\/macosx\/testing"/u
  );
  assert.match(runner, /XCODE_TESTING_LIBRARY="\$XCODE_TESTING_RUNTIME\/libTesting\.dylib"/u);
  assert.match(
    runner,
    /XCODE_PLATFORM_DEVELOPER="\$DEVELOPER_ROOT\/Platforms\/MacOSX\.platform\/Developer"/u
  );
  assert.match(runner, /XCODE_PLATFORM_PRIVATE_FRAMEWORKS="\$XCODE_PLATFORM_DEVELOPER\/Library\/PrivateFrameworks"/u);
  assert.match(runner, /XCODE_PLATFORM_LIBRARIES="\$XCODE_PLATFORM_DEVELOPER\/usr\/lib"/u);
  assert.match(runner, /XCODE_TESTING_INTEROP="\$XCODE_PLATFORM_LIBRARIES\/lib_TestingInterop\.dylib"/u);
  assert.match(runner, /XCODE_TESTING_INTEROP_OWNER" == 0[\s\S]*?XCODE_TESTING_INTEROP_OWNER" == "\$XCODE_DEVELOPER_OWNER"/u);
  assert.match(
    runner,
    /if \[\[ -e "\$XCODE_TESTING_RUNTIME"[\s\S]*?codesign --verify --strict --test-requirement '=anchor apple'[\s\S]*?for xcode_runtime_rpath in[\s\S]*?"\$XCODE_TESTING_RUNTIME"[\s\S]*?testing_arguments\+=\([\s\S]*?-Xlinker -rpath[\s\S]*?-Xlinker "\$xcode_runtime_rpath"/u,
    "the Xcode Swift Testing closure must become durable test-bundle rpaths"
  );
  assert.match(
    runner,
    /codesign --verify --strict --test-requirement '=anchor apple' \\\n+    "\$XCODE_TESTING_INTEROP"/u,
    "the transitive Xcode Testing interop image must be an attested Apple image"
  );
  assert.match(runner, /xcode_platform_runtime_paths=\([\s\S]*?"\$XCODE_PLATFORM_FRAMEWORKS"[\s\S]*?"\$XCODE_PLATFORM_PRIVATE_FRAMEWORKS"[\s\S]*?"\$XCODE_PLATFORM_LIBRARIES"/u);
  assert.match(runner, /XCODE_PLATFORM_RUNTIME_OWNER" == 0[\s\S]*?XCODE_PLATFORM_RUNTIME_OWNER" == "\$XCODE_DEVELOPER_OWNER"/u);
  assert.match(runner, /for xcode_runtime_rpath in[\s\S]*?"\$XCODE_TESTING_RUNTIME"[\s\S]*?"\$\{xcode_platform_runtime_paths\[@\]\}"[\s\S]*?required_testing_rpaths\+=\("\$xcode_runtime_rpath"\)/u);
  assert.match(runner, /Swift Testing bundle load-command inspection[\s\S]*?\/usr\/bin\/otool -l "\$TEST_BUNDLE_EXECUTABLE"/u);
  assert.match(runner, /\$1 == "cmd" && \$2 == "LC_RPATH"/u);
  assert.match(runner, /The Swift Testing bundle does not contain its exact selected runtime rpath\./u);
  assert.match(runner, /-Xlinker -rpath/u);
  assert.match(runner, /"\$\{test_selection_arguments\[@\]\}" \\\n\s+--no-parallel \\/u);
  assert.doesNotMatch(runner, /SWT_EXPERIMENTAL_MAXIMUM_PARALLELIZATION_WIDTH/u);
  assert.match(runner, /SWIFT_BUILD_JOBS="\$\{REQUESTED_BUILD_JOBS:-2\}"/u);
  assert.match(
    runner,
    /\[\[ "\$SWIFT_BUILD_JOBS" == <-> && "\$SWIFT_BUILD_JOBS" -ge 1[\s\S]*?"\$SWIFT_BUILD_JOBS" -le 4 \]\][\s\S]*?exit 64/u
  );
  assert.equal(
    runner.match(/--jobs "\$SWIFT_BUILD_JOBS"/gu)?.length,
    3,
    "every SwiftPM build invocation that may compile must use the bounded 1...4 job width"
  );
  assert.match(runner, /--jobs "\$SWIFT_BUILD_JOBS" \\\n  --build-tests/u);
  assert.match(runner, /--jobs "\$SWIFT_BUILD_JOBS" \\\n  --show-bin-path/u);
  assert.match(runner, /list --skip-build --disable-xctest --enable-swift-testing/u);
  assert.match(runner, /verify-swift-test-plan\.mjs/u);
  assert.match(eventVerifier, /profile === "full" && discoveredFunctions\.size !== fullPlan\.functionCount/u);
  assert.match(planVerifier, /Swift test binary does not match the frozen full-suite plan/u);
  assert.equal(plan.schemaVersion, 1);
  assert.ok(Number.isSafeInteger(plan.functionCount) && plan.functionCount > 1000);
  assert.match(plan.sortedSpecifierSHA256, /^[a-f0-9]{64}$/u);
  assert.doesNotMatch(runner, /SWIFT_BUILD_JOBS="\$\{REQUESTED_BUILD_JOBS:-[015-9][0-9]*\}"/u);
  assert.match(runner, /FulmarSwiftTests\.lock/u);
  assert.match(runner, /source "\$PROJECT_DIR\/scripts\/root-group-lock\.zsh"/u);
  assert.match(runner, /--lock-dir "\$TEST_LOCK_DIR"/u);
  assert.match(runner, /fulmar_acquire_root_group_lock "\$TEST_LOCK_DIR" "Fulmar Swift qualification"/u);
  assert.match(runner, /run-with-watchdog\.sh" --inherit-root/u);
  assert.match(runner, /select-compatible-swift-sdk\.sh/u);
  assert.doesNotMatch(runner, /DYLD_(?:FRAMEWORK|LIBRARY)_PATH/u);
  assert.match(runner, /\/usr\/bin\/env -i/u);
  assert.match(runner, /CFFIXED_USER_HOME=\$TEST_HOME/u);
  assert.match(runner, /LOCAL_HARNESS_SWIFT_TEST_ISOLATION_ROOT=\$CANONICAL_ISOLATION_ROOT/u);
  assert.match(runner, /LOCAL_HARNESS_UPDATE_ARCHIVE_TEST_PATH=\$UPDATE_ARCHIVE_FIXTURE/u);
  assert.match(runner, /LOCAL_HARNESS_TEST_APP_PATH=\$APPLICATION_FIXTURE/u);
  assert.match(runner, /verify-swiftpm-deployment-target\.sh/u);
  assert.match(runner, /reports Apple's prebuilt Testing\.framework slice/u);
  assert.doesNotMatch(runner, /REQUESTED_(?:SDKROOT|DEVELOPER_DIR|CLANG_CACHE|SWIFT_CACHE)/u);
  assert.doesNotMatch(verifier, /CLANG_MODULE_CACHE_PATH="\$PROJECT_DIR/u);
  assert.doesNotMatch(runner, /env[^\n]*\.\.\./u);
  assert.match(workflow, /Build the exact stable-signed candidate fixtures[\s\S]*run: make private-release/u);
  assert.doesNotMatch(workflow, /run: make build(?:\s|$)/u);
  assert.match(workflow, /Qualify every deterministic credential-free candidate gate[\s\S]*run: make deterministic-release-verify/u);
  assert.match(verifier, /LOCAL_HARNESS_UPDATE_ARCHIVE_TEST_PATH="\$ARCHIVE"/u);
  assert.match(verifier, /LOCAL_HARNESS_TEST_APP_PATH="\$APP_DIR"/u);
  const swiftGateOffset = verifier.indexOf('/bin/zsh -f "$PROJECT_DIR/scripts/run-swift-tests.sh"');
  const javascriptGateOffset = verifier.indexOf('/bin/zsh -f "$PROJECT_DIR/scripts/run-js-tests.sh" --test');
  assert.ok(swiftGateOffset >= 0 && javascriptGateOffset > swiftGateOffset,
    "clean release verification must build the SwiftPM products before JavaScript inspects them");
});

test("native qualification isolates every full-suite function behind complete event accounting", async () => {
  const runner = await readFile(join(process.cwd(), "scripts", "run-swift-tests.sh"), "utf8");
  const shardDriver = await readFile(join(process.cwd(), "scripts", "run-swift-test-shards.mjs"), "utf8");
  const assemblerPath = join(process.cwd(), "scripts", "prepare-swift-testing-host.sh");
  const assembler = await readFile(assemblerPath, "utf8");
  const hostSourcePath = join(process.cwd(), "Tests", "Support", "SwiftTestingHost.swift");
  const hostSource = await readFile(hostSourcePath, "utf8");
  const appKitLifetime = await readFile(
    join(process.cwd(), "Tests", "LocalHarnessTests", "AppKitTestHostLifetime.swift"), "utf8"
  );

  assert.match(assembler, /^#!\/bin\/sh -p\n/u);
  assert.match(assembler, /CFBundlePackageType -string APPL/u);
  assert.match(assembler, /LSUIElement -bool true/u);
  assert.match(assembler, /NSPrincipalClass -string NSApplication/u);
  assert.match(assembler, /NSSupportsAutomaticTermination -bool false/u);
  assert.match(assembler, /"\$swiftc" -parse-as-library -warnings-as-errors -O/u);
  assert.match(assembler, /-target "\$architecture-apple-macosx\$minimum_macos"/u);
  assert.match(assembler, /codesign --force --sign - --timestamp=none "\$staging_app"/u);
  assert.match(assembler, /codesign --verify --strict "\$staging_app"/u);
  assert.match(assembler, /"\$source_sha"/u);
  assert.match(assembler, /\/bin\/mv "\$staging_app" "\$destination_app"/u);
  assert.match(assembler, /cleanup_staging/u);
  const activityIndex = hostSource.indexOf("disableAutomaticTermination(");
  const loadIndex = hostSource.indexOf("dlopen(arguments[2], RTLD_LAZY | RTLD_FIRST)");
  assert.ok(activityIndex >= 0 && loadIndex > activityIndex,
    "the automatic-termination hold must begin before the test image is loaded");
  assert.match(hostSource, /disableSuddenTermination\(\)/u);
  assert.doesNotMatch(hostSource, /enableAutomaticTermination|enableSuddenTermination/u);
  assert.match(hostSource, /dlsym\(image, "main"\)/u);
  assert.match(hostSource, /test bundle load failed/u);
  assert.match(hostSource, /test entry point missing/u);
  assert.match(hostSource, /strnlen\(pointer, 2_048\)/u);
  assert.match(hostSource, /\(0x20\.\.\.0x7E\)\.contains\(byte\) \? byte : 0x3F/u);
  assert.match(hostSource, /testingMain\(CommandLine\.argc, CommandLine\.unsafeArgv\)/u);
  assert.doesNotMatch(`${runner}\n${assembler}\n${hostSource}\n${shardDriver}`,
    /\.prohibited|NSApplicationDelegate|NSWindow|NSPanel|swiftpm-testing-helper/u);
  assert.doesNotMatch(appKitLifetime,
    /NSApplicationDelegate|applicationShouldTerminate|anchorWindow|\.prohibited|setActivationPolicy/u);
  assert.match(appKitLifetime,
    /func ensureAppKitTestHostSurvivesAutomaticTermination\(\) \{\n    withExtendedLifetime\(AppKitTestHostLifetime\.application\) \{\}\n\}/u);
  assert.match(appKitLifetime, /window\.orderFrontRegardless\(\)[\s\S]*window\.close\(\)/u);

  assert.match(runner, /run_guarded "Swift isolated full test suite"[\s\S]*?run-swift-test-shards\.mjs/u);
  assert.match(runner, /"\$TEST_PLAN_STREAM" "\$TEST_HOST_EXECUTABLE" "\$TEST_BUNDLE_EXECUTABLE"/u);
  assert.match(shardDriver, /for \(const \[index, selector\] of selectors\.entries\(\)\)/u);
  assert.match(shardDriver, /functions\.length !== 1/u);
  assert.match(shardDriver, /native-shard function selectors are not substring-unique/u);
  assert.match(shardDriver, /Number\.isInteger\(result\.status\)/u);
  assert.match(shardDriver, /typeof result\.signal === "string"/u);
  assert.match(shardDriver, /"--no-parallel"/u);
  assert.match(shardDriver, /verify-swift-test-events\.mjs/u);
  assert.match(shardDriver, /a native-shard authority changed during qualification/u);

  const launchStart = runner.indexOf('run_guarded "Swift focused test suite"');
  const launchEnd = runner.indexOf('run_guarded "Swift event-accounting verification"', launchStart);
  assert.ok(launchStart >= 0 && launchEnd > launchStart, "the direct host launch must be uniquely bounded");
  const launch = runner.slice(launchStart, launchEnd);
  assert.match(launch, /\/usr\/bin\/env -i "\$\{test_environment\[@\]\}" "\$TEST_HOST_EXECUTABLE"/u);
  assert.doesNotMatch(launch, /\/usr\/bin\/swift\s+test|\/usr\/bin\/open/u);
  const orderedArguments = [
    '--test-bundle-path "$TEST_BUNDLE_EXECUTABLE"',
    '"${test_selection_arguments[@]}"',
    '--no-parallel',
    '--event-stream-output-path "$EVENT_STREAM"',
    '--event-stream-version 0',
    '--testing-library swift-testing'
  ];
  let previous = -1;
  for (const argument of orderedArguments) {
    const index = launch.indexOf(argument, previous + 1);
    assert.ok(index > previous, `the exact direct-host argument is missing or reordered: ${argument}`);
    previous = index;
  }
  assert.equal((launch.match(/\$TEST_BUNDLE_EXECUTABLE/gu) ?? []).length, 1,
    "the exact built test bundle must be passed once as the reviewed host load target");
  assert.equal((launch.match(/\$EVENT_STREAM/gu) ?? []).length, 1,
    "the private host must forward exactly one runner-owned event ledger");
  assert.ok(runner.indexOf('TEST_HOST_EXECUTABLE="$(run_guarded') < launchStart,
    "the private app must be assembled before the first test process starts");
  assert.match(runner, /\/usr\/bin\/swift test[\s\S]*list --skip-build/u,
    "the runner must independently enumerate the built full-suite topology");
  assert.match(runner, /if \(\( test_status != 0 \)\); then\n  finish_gate "\$test_status"/u);
  assert.match(runner, /if \(\( event_status != 0 \)\); then\n  finish_gate 126/u);

  const policyStart = runner.indexOf('SWIFT_TEST_PROFILE="full"');
  const policyEnd = runner.indexOf("\n\nROOT_WATCHDOG_STATE", policyStart);
  assert.ok(policyStart >= 0 && policyEnd > policyStart);
  const policyProbeRoot = await mkdtemp(join(tmpdir(), "fulmar-swift-argv-policy."));
  const policyProbe = join(policyProbeRoot, "probe.zsh");
  try {
    await writeFile(policyProbe,
      `#!/bin/zsh -f\n${runner.slice(policyStart, policyEnd)}\nprint -r -- accepted\n`, { mode: 0o700 });
    for (const argumentList of [
      ["--parallel"], ["--no-parallel"], ["--num-workers", "2"], ["--num-workers=2"],
      ["--experimental-test-isolation", "process"], ["--experimental-test-isolation=process"],
      ["--enable-xctest"], ["--disable-xctest=true"], ["--enable-swift-testing=false"],
      ["--disable-swift-testing"], ["--testing-library", "swift-testing"],
      ["--testing-library=swift-testing"], ["--filter", "reviewed-test"],
      ["--skip", "reviewed-skip"], ["--focused-filter", "someOtherTest"]
    ]) {
      const rejected = spawnSync("/bin/zsh", ["-f", policyProbe, ...argumentList], {
        encoding: "utf8", timeout: 2_000
      });
      assert.equal(rejected.status, 64, argumentList.join(" "));
      assert.match(rejected.stderr, /accepts no selectors in full mode/u);
    }
    for (const argumentList of [[], ["--focused-filter", "renderedMacOS26Toolbar"]]) {
      const accepted = spawnSync("/bin/zsh", ["-f", policyProbe, ...argumentList], {
        encoding: "utf8", timeout: 2_000
      });
      assert.equal(accepted.status, 0, accepted.stderr);
      assert.equal(accepted.stdout, "accepted\n");
    }
  } finally {
    await rm(policyProbeRoot, { recursive: true, force: true });
  }

  const sdk = spawnSync("/usr/bin/xcrun", ["--sdk", "macosx", "--show-sdk-path"], {
    encoding: "utf8", timeout: 2_000,
    env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" }
  });
  assert.equal(sdk.status, 0, sdk.stderr);
  const identity = JSON.parse(await readFile(join(process.cwd(), "Config", "ReleaseIdentity.json"), "utf8"));

  const root = await mkdtemp("/private/tmp/fulmar-swift-tests.");
  const hostileRoot = await mkdtemp(join(tmpdir(), "fulmar-swift-hostile-shell."));
  const host = join(root, "FulmarSwiftTestingHost.app");
  const bashMarker = join(hostileRoot, "bash-env-ran");
  const zshMarker = join(hostileRoot, "zsh-env-ran");
  const functionMarker = join(hostileRoot, "exported-function-ran");
  try {
    await chmod(root, 0o700);
    await writeFile(join(hostileRoot, "bash-env"), `printf injected > ${JSON.stringify(bashMarker)}\n`, { mode: 0o600 });
    await writeFile(join(hostileRoot, ".zshenv"), `print -r -- injected > ${JSON.stringify(zshMarker)}\n`, { mode: 0o600 });
    const prepared = spawnSync("/bin/sh", [
      "-p", assemblerPath, hostSourcePath, host, "/usr/bin/swiftc", sdk.stdout.trim(), identity.minimumMacOS
    ], {
      encoding: "utf8", timeout: 20_000,
      env: {
        ...process.env,
        HOME: hostileRoot,
        ZDOTDIR: hostileRoot,
        ENV: join(hostileRoot, "bash-env"),
        BASH_ENV: join(hostileRoot, "bash-env"),
        FULMAR_SWIFT_HOST_FUNCTION_MARKER: functionMarker,
        "BASH_FUNC_fulmar_injected%%": '() { printf injected > "$FULMAR_SWIFT_HOST_FUNCTION_MARKER"; }'
      }
    });
    assert.equal(prepared.status, 0, prepared.stderr);
    const executable = join(host, "Contents", "MacOS", "FulmarSwiftTestingHost");
    assert.equal(prepared.stdout, `${executable}\n`);
    assert.equal(existsSync(bashMarker), false, "the host assembler sourced hostile BASH_ENV bytes");
    assert.equal(existsSync(zshMarker), false, "the host assembler sourced hostile zsh startup bytes");
    assert.equal(existsSync(functionMarker), false, "the host assembler imported a hostile Bash function");
    assert.equal((await stat(executable)).mode & 0o777, 0o700);
    assert.equal((await stat(join(host, "Contents", "Info.plist"))).mode & 0o777, 0o600);
    const signature = spawnSync("/usr/bin/codesign", ["--verify", "--strict", host], {
      encoding: "utf8", timeout: 2_000
    });
    assert.equal(signature.status, 0, signature.stderr);
    const firstProcess = spawnSync(executable, ["--test-bundle-path", "/usr/bin/true"], {
      encoding: "utf8", timeout: 2_000,
      env: { HOME: hostileRoot, PATH: "/usr/bin:/bin:/usr/sbin:/sbin" }
    });
    assert.equal(firstProcess.error, undefined, firstProcess.error?.message);
    assert.equal(firstProcess.status, 126, firstProcess.stderr);
    assert.match(firstProcess.stderr, /^The private Swift Testing host could not start: test entry point missing\./u,
      "the signed app executable must reach its reviewed entry point without a policy prompt");

    const hostileMissingPath = join(hostileRoot, `missing-\n-\u001b-\u202e-${"x".repeat(4_000)}`);
    const loadFailure = spawnSync(executable, ["--test-bundle-path", hostileMissingPath], {
      encoding: "utf8", timeout: 2_000,
      env: { HOME: hostileRoot, PATH: "/usr/bin:/bin:/usr/sbin:/sbin" }
    });
    assert.equal(loadFailure.error, undefined, loadFailure.error?.message);
    assert.equal(loadFailure.status, 126, loadFailure.stderr);
    assert.match(loadFailure.stderr,
      /^The private Swift Testing host could not start: test bundle load failed\. Loader detail: /u);
    assert.equal(loadFailure.stderr.endsWith("\n"), true);
    assert.doesNotMatch(loadFailure.stderr.slice(0, -1), /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/u,
      "loader diagnostics must not preserve terminal controls or bidi formatting");
    assert.ok(Buffer.byteLength(loadFailure.stderr, "utf8") <= 2_200,
      "loader diagnostics must remain byte-bounded");

    const plist = spawnSync("/usr/bin/plutil", [
      "-convert", "json", "-o", "-", join(host, "Contents", "Info.plist")
    ], { encoding: "utf8", timeout: 2_000 });
    assert.equal(plist.status, 0, plist.stderr);
    assert.deepEqual(JSON.parse(plist.stdout), {
      CFBundleDevelopmentRegion: "en",
      CFBundleExecutable: "FulmarSwiftTestingHost",
      CFBundleIdentifier: "dev.fulmar.private.swift-testing-host",
      CFBundleName: "Fulmar Swift Testing Host",
      CFBundlePackageType: "APPL",
      CFBundleShortVersionString: "1.0",
      CFBundleVersion: "1",
      LSUIElement: true,
      NSPrincipalClass: "NSApplication",
      NSSupportsAutomaticTermination: false
    });
    const unexpectedStaging = (await readdir(root)).filter((name) => name.includes(".staging."));
    assert.deepEqual(unexpectedStaging, [], "the successful atomic assembly left staging residue");
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(hostileRoot, { recursive: true, force: true });
  }
});

test("native qualification rejects unbounded compile widths and defaults to two jobs", async () => {
  const runner = await readFile(join(process.cwd(), "scripts", "run-swift-tests.sh"), "utf8");
  const validationStart = runner.indexOf('[[ "$SWIFT_BUILD_JOBS" == <->');
  const validationEnd = runner.indexOf("\n\n# Full release qualification", validationStart);
  assert.ok(validationStart >= 0 && validationEnd > validationStart);
  const validation = runner.slice(validationStart, validationEnd);
  const root = await mkdtemp(join(tmpdir(), "fulmar-swift-job-policy-"));
  const probe = join(root, "probe.zsh");
  try {
    await writeFile(probe, `#!/bin/zsh\nSWIFT_BUILD_JOBS="\${1-}"\n${validation}\nprint -r -- accepted\n`, { mode: 0o700 });
    for (const value of ["1", "2", "4"]) {
      const result = spawnSync("/bin/zsh", ["-f", probe, value], { encoding: "utf8", timeout: 2_000 });
      assert.equal(result.status, 0, `bounded compile width ${value} must pass`);
      assert.equal(result.stdout, "accepted\n");
    }
    for (const value of ["", "0", "5", "1.5", "unbounded", "999999999"]) {
      const result = spawnSync("/bin/zsh", ["-f", probe, value], { encoding: "utf8", timeout: 2_000 });
      assert.equal(result.status, 64, `invalid compile width ${JSON.stringify(value)} must fail closed`);
      assert.match(result.stderr, /FULMAR_SWIFT_BUILD_JOBS must be an integer from 1 through 4/u);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("standalone native product gates share one bounded two-job supervisor", async () => {
  const [makefile, packageManifest, gate, crashGate, privateInstaller, rollbackInspector,
    recoveryWrapper, rollbackTool, privateCoordinator, privateCrashProbe] = await Promise.all([
    readFile(join(process.cwd(), "Makefile"), "utf8"),
    readFile(join(process.cwd(), "Package.swift"), "utf8"),
    readFile(join(process.cwd(), "scripts", "run-bounded-swift-product-gate.sh"), "utf8"),
    readFile(join(process.cwd(), "scripts", "verify-credential-transaction-crash.sh"), "utf8"),
    readFile(join(process.cwd(), "scripts", "install-qualified-private-candidate.sh"), "utf8"),
    readFile(join(process.cwd(), "scripts", "inspect-private-install-rollback.sh"), "utf8"),
    readFile(join(process.cwd(), "scripts", "recover-private-install.sh"), "utf8"),
    readFile(join(process.cwd(), "Tools", "PrivateRollbackInspector", "main.swift"), "utf8"),
    readFile(join(process.cwd(), "Sources", "PrivateInstallCoordinator",
      "PrivateInstallCoordinator.swift"), "utf8"),
    readFile(join(process.cwd(), "Tests", "PrivateInstallCrashProbe", "main.swift"), "utf8")
  ]);
  const runtimeTarget = makefile.slice(makefile.indexOf("runtime-lease-test:"), makefile.indexOf("cloned-state-security:"));
  const credentialTarget = makefile.slice(makefile.indexOf("credential-test:"), makefile.indexOf("credential-crash-test:"));
  assert.match(runtimeTarget, /run-bounded-swift-product-gate\.sh runtime-lease/u);
  assert.match(credentialTarget, /run-bounded-swift-product-gate\.sh credential/u);
  assert.match(makefile, /private-install-qualified:\n\t\/bin\/zsh -f scripts\/install-qualified-private-candidate\.sh/u);
  assert.match(makefile, /private-rollback-status:\n\t\/bin\/zsh -f scripts\/inspect-private-install-rollback\.sh/u);
  assert.match(makefile, /private-recovery-resume:\n\t\/bin\/zsh -f scripts\/recover-private-install\.sh resume/u);
  assert.match(makefile, /private-recovery-finalize:\n\t\/bin\/zsh -f scripts\/recover-private-install\.sh finalize/u);
  assert.match(makefile, /private-recovery-cancel:\n\t\/bin\/zsh -f scripts\/recover-private-install\.sh cancel/u);
  assert.match(makefile, /private-recovery-reconcile:\n\t\/bin\/zsh -f scripts\/recover-private-install\.sh reconcile/u);
  assert.match(makefile, /private-rollback-retire:\n\t\/bin\/zsh -f scripts\/recover-private-install\.sh retire/u);
  assert.match(privateInstaller, /case "\$SWIFT_BUILD_JOBS" in\n  1\|2\) ;;[\s\S]*FULMAR_SWIFT_BUILD_JOBS must be an integer from 1 through 2\./u);
  assert.match(privateInstaller, /EXECUTABLE_DETAILS="\$\(\/usr\/bin\/stat -f '%u:%Lp:%l:%HT' "\$executable"\)"/u);
  assert.match(privateInstaller, /"\$EXECUTABLE_DETAILS" =~ "\^\$\{CURRENT_UID\}:\[0-7\]\{1,2\}\[0145\]\[0145\]:1:Regular File\$"/u);
  assert.doesNotMatch(privateInstaller, /8#\$\(\/usr\/bin\/stat/u);
  assert.match(privateInstaller, /verify-frozen-candidate\.sh" "\$CANDIDATE"[\s\S]*"\$NODE" "\$EVIDENCE_VERIFIER"/u);
  assert.match(privateInstaller, /verify_qualified_candidate[\s\S]*LocalHarnessAtomicInstallSwapHelper[\s\S]*LocalHarnessPrivateInstallCoordinatorTool[\s\S]*verify_qualified_candidate[\s\S]*"\$COORDINATOR" --nonce "\$NONCE"[\s\S]*verify-frozen-candidate\.sh" "\$INSTALLED"/u);
  assert.doesNotMatch(privateInstaller, /\/bin\/(?:cp|mv|rm)[^\n]*\/Applications/u);
  assert.match(packageManifest, /name: "LocalHarnessPrivateRollbackInspectorTool"[\s\S]*dependencies: \["LocalHarnessPrivateInstallCoordinator"\]/u);
  assert.match(rollbackInspector, /BUILD_TARGETS=\(LocalHarnessPrivateRollbackInspectorTool\)/u);
  assert.match(rollbackInspector, /verify_qualified_recovery_source[\s\S]*--scratch-path "\$TOOL_ROOT\/build"[\s\S]*verify_qualified_recovery_source[\s\S]*"\$INSPECTOR"/u);
  assert.match(rollbackInspector, /verify-frozen-candidate\.sh" "\$CANDIDATE"/u);
  assert.match(rollbackInspector, /source-build-input-inventory\.mjs"[\s\S]*verify "\$PROJECT_DIR" "\$SOURCE_INPUTS"/u);
  assert.match(rollbackInspector, /"\$NODE" "\$EVIDENCE_VERIFIER"/u);
  assert.match(rollbackInspector, /LocalHarnessAtomicInstallSwapHelper/u);
  assert.match(rollbackInspector, /"\$INSPECTOR"/u);
  assert.match(rollbackInspector, /--lock-dir \/private\/tmp\/LocalHarnessBuild\.lock/u);
  assert.match(rollbackInspector, /case "\$SWIFT_BUILD_JOBS" in\n  1\|2\) ;;[\s\S]*FULMAR_SWIFT_BUILD_JOBS must be an integer from 1 through 2\./u);
  assert.match(rollbackInspector, /EXECUTABLE_DETAILS="\$\(\/usr\/bin\/stat -f '%u:%Lp:%l:%HT' "\$executable"\)"/u);
  assert.match(rollbackInspector, /"\$EXECUTABLE_DETAILS" =~ "\^\$\{CURRENT_UID\}:\[0-7\]\{1,2\}\[0145\]\[0145\]:1:Regular File\$"/u);
  assert.doesNotMatch(rollbackInspector, /8#\$\(\/usr\/bin\/stat/u);
  assert.doesNotMatch(rollbackInspector, /codesign|plutil|\/(?:bin|usr\/bin)\/(?:cp|mv|rm)[^\n]*\/Applications/u);
  assert.match(rollbackTool, /inspectProductionRecovery\(\)/u);
  assert.match(rollbackTool, /--resume-interrupted[\s\S]*--finalize-interrupted[\s\S]*--cancel-interrupted[\s\S]*--retire-committed[\s\S]*--reconcile-records/u);
  assert.match(rollbackTool, /complete bounded byte tree[\s\S]*CDHash[\s\S]*designated requirement/u);
  assert.match(rollbackTool, /archives the rollback and records;[\s\S]*does not delete them/u);
  assert.match(recoveryWrapper, /resume\) MODE="--resume-interrupted"/u);
  assert.match(recoveryWrapper, /finalize\) MODE="--finalize-interrupted"/u);
  assert.match(recoveryWrapper, /cancel\) MODE="--cancel-interrupted"/u);
  assert.match(recoveryWrapper, /retire\) MODE="--retire-committed"/u);
  assert.match(recoveryWrapper, /reconcile\) MODE="--reconcile-records"/u);
  assert.match(recoveryWrapper, /exec \/bin\/zsh -f "\$PROJECT_DIR\/scripts\/inspect-private-install-rollback\.sh" "\$MODE"/u);
  for (const boundary of ["afterTemporaryCreate", "afterPartialFileSync",
    "afterCompleteFileSync", "beforeExclusiveRename", "afterRenameBeforeDirectorySync"]) {
    assert.match(privateCoordinator, new RegExp(`case ${boundary}`, "u"));
  }
  assert.match(privateCoordinator, /O_WRONLY \| O_CREAT \| O_EXCL \| O_CLOEXEC \| O_NOFOLLOW/u);
  assert.match(privateCoordinator, /interruptedRecordArchivePrefix[\s\S]*RENAME_EXCL/u);
  assert.match(privateCoordinator, /stableRenamedRecord[\s\S]*st_nlink[\s\S]*st_size[\s\S]*st_mtimespec/u);
  assert.match(privateCoordinator, /inspectProductionRecovery[\s\S]*hasTemporaryRecord[\s\S]*interruptedRecordWrite/u);
  for (const kind of ["preparation", "abandonment", "journal", "receipt", "lifecycle"]) {
    for (const boundary of ["after-temporary-create", "after-partial-file-sync",
      "after-complete-file-sync", "before-exclusive-rename",
      "after-rename-before-directory-sync"]) {
      assert.match(privateCrashProbe, new RegExp(`${kind}-${boundary}`, "u"));
    }
  }
  assert.doesNotMatch(`${runtimeTarget}\n${credentialTarget}`, /swift build/u);
  assert.match(gate, /run-with-watchdog\.sh[\s\S]*--lock-dir \/private\/tmp\/FulmarSwiftTests\.lock/u);
  assert.match(gate, /SWIFT_BUILD_JOBS="\$\{FULMAR_SWIFT_BUILD_JOBS:-2\}"/u);
  assert.match(gate, /"\$SWIFT_BUILD_JOBS" -ge 1[\s\S]*"\$SWIFT_BUILD_JOBS" -le 2/u);
  assert.match(gate, /--jobs "\$SWIFT_BUILD_JOBS"/u);
  assert.equal(crashGate.match(/--jobs 1/gu)?.length, 2,
    "the credential crash build and its binary-path query must both remain single-job");

  const dryRun = spawnSync("/usr/bin/make", ["-n", "runtime-lease-test", "credential-test"], {
    cwd: process.cwd(), encoding: "utf8", timeout: 2_000
  });
  assert.equal(dryRun.error, undefined, dryRun.error?.message);
  assert.equal(dryRun.status, 0, dryRun.stderr);
  assert.match(dryRun.stdout, /run-bounded-swift-product-gate\.sh runtime-lease/u);
  assert.match(dryRun.stdout, /run-bounded-swift-product-gate\.sh credential/u);
  assert.doesNotMatch(dryRun.stdout, /swift build/u);

  const validationStart = gate.indexOf('[[ "$SWIFT_BUILD_JOBS" == <->');
  const validationEnd = gate.indexOf("\n\nTEST_LOCK_DIR=", validationStart);
  assert.ok(validationStart >= 0 && validationEnd > validationStart);
  const validation = gate.slice(validationStart, validationEnd);
  const root = await mkdtemp(join(tmpdir(), "fulmar-product-job-policy-"));
  const probe = join(root, "probe.zsh");
  try {
    await writeFile(probe, `#!/bin/zsh\nSWIFT_BUILD_JOBS="\${1-}"\n${validation}\nprint -r -- accepted\n`, { mode: 0o700 });
    for (const value of ["1", "2"]) {
      const result = spawnSync("/bin/zsh", ["-f", probe, value], { encoding: "utf8", timeout: 2_000 });
      assert.equal(result.status, 0, `bounded product width ${value} must pass`);
    }
    for (const value of ["", "0", "3", "4", "2.5", "unbounded", "999999999"]) {
      const result = spawnSync("/bin/zsh", ["-f", probe, value], { encoding: "utf8", timeout: 2_000 });
      assert.equal(result.status, 64, `invalid product width ${JSON.stringify(value)} must fail closed`);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("the release toolbar-render target requires a real macOS 26 host and a non-executable source script", async () => {
  const scriptPath = join(process.cwd(), "scripts", "verify-toolbar-render-macos26.sh");
  const [makefile, script, tests] = await Promise.all([
    readFile(join(process.cwd(), "Makefile"), "utf8"),
    readFile(scriptPath, "utf8"),
    readFile(join(process.cwd(), "Tests", "LocalHarnessTests", "HarnessWindowToolbarLayoutTests.swift"), "utf8")
  ]);
  const scriptMetadata = await stat(scriptPath);
  assert.equal(scriptMetadata.mode & 0o111, 0, "a zsh-invoked verifier must not bypass the tracked-index executable allowlist");
  assert.match(makefile, /toolbar-render-macos26:[\s\S]*\t\/bin\/zsh -f scripts\/verify-toolbar-render-macos26\.sh/u);
  assert.match(script, /sw_vers -productVersion/u);
  assert.match(script, /HOST_MAJOR[\s\S]*== "26"/u);
  assert.match(script, /--focused-filter renderedMacOS26Toolbar/u);
  assert.match(tests, /statusRect\.midY - routeRect\.midY/u);
  assert.match(tests, /renderedMacOS26ToolbarStatusAndModelTextAreVisuallyLevelAcrossReleaseMatrix/u);
  assert.match(tests, /rendered\.bitmapData/u);
  assert.match(tests, /releaseCaseCount == 64/u);
  assert.match(tests, /renderedMacOS26ToolbarMetricRejectsLegacyFullHeightStatusLabel/u);
  assert.match(tests, /\.disabled\([\s\S]*majorVersion != 26/u);
});

test("all ordinary JavaScript qualification uses the hermetic event-accounted pinned runner", async () => {
  const [runner, eventVerifier, verifier, credential, makefile, workflow,
    swiftRunner, selfTests, orchestrator, retention] = await Promise.all([
    readFile(join(process.cwd(), "scripts", "run-js-tests.sh"), "utf8"),
    readFile(join(process.cwd(), "scripts", "verify-js-test-events.mjs"), "utf8"),
    readFile(verifierPath, "utf8"),
    readFile(join(process.cwd(), "scripts", "verify-credential-migration.sh"), "utf8"),
    readFile(join(process.cwd(), "Makefile"), "utf8"),
    readFile(join(process.cwd(), ".github", "workflows", "verify-source.yml"), "utf8"),
    readFile(join(process.cwd(), "scripts", "run-swift-tests.sh"), "utf8"),
    readFile(join(process.cwd(), "scripts", "run-watchdog-self-tests.sh"), "utf8"),
    readFile(join(process.cwd(), "scripts", "verify-release-orchestrated.sh"), "utf8"),
    readFile(join(process.cwd(), "scripts", "retain-release-verification.sh"), "utf8")
  ]);
  for (const [name, source] of [
    ["JavaScript", runner],
    ["Swift", swiftRunner],
    ["watchdog self-test", selfTests],
    ["release orchestrator", orchestrator],
    ["release evidence retention", retention]
  ]) {
    assert.match(source, /^#!\/bin\/zsh -f\n/u, `${name} entry must suppress ambient .zshenv startup code`);
  }
  assert.match(runner, /VendorRuntime\/node-v22\.23\.1-darwin-arm64\/bin\/node/u);
  assert.match(runner, /--lock-dir \/private\/tmp\/LocalHarnessBuild\.lock/u);
  assert.match(runner, /--test\|--test=true\) test_mode=1/u);
  assert.match(runner, /--no-test\|--no-test-\*/u);
  assert.match(runner, /--test-\*/u);
  assert.match(runner, /requires at least one JavaScript test file/u);
  assert.match(runner, /rejects duplicate JavaScript test-file operands/u);
  assert.match(runner, /full_test_count="\$\(\/usr\/bin\/find[\s\S]*-name '\*\.mjs'/u);
  assert.match(runner, /operand_count == full_test_count/u);
  assert.match(runner, /seen_test_operands\[\$full_test_file\]/u);
  assert.doesNotMatch(runner, /requested_test_files|\(@k\)seen_test_operands/u);
  assert.match(runner, /--experimental-test-isolation=none --test-concurrency=1/u);
  assert.match(runner, /run-js-tests\.sh owns JavaScript test isolation and concurrency/u);
  assert.match(runner, /self-root-test-event-reporter\.mjs/u);
  assert.match(runner, /verify-js-test-events\.mjs/u);
  assert.match(selfTests, /--test-reporter=spec --test-reporter-destination=stdout/u);
  assert.match(selfTests, /--test-reporter="\$PROJECT_DIR\/scripts\/self-root-test-event-reporter\.mjs"/u);
  assert.match(selfTests, /verify-self-root-test-events\.mjs/u);
  assert.match(runner, /test_profile=full-source/u);
  assert.match(runner, /test_profile=full-candidate/u);
  assert.match(runner, /if ! cleanup; then/u);
  assert.match(runner, /exit 126/u);
  assert.match(eventVerifier, /full JavaScript qualification skip topology changed/u);
  assert.match(eventVerifier, /full JavaScript qualification count drift/u);
  assert.match(eventVerifier, /profile === "full-candidate" \? 620 : 619/u);
  assert.match(eventVerifier, /profile === "full-source"/u);
  assert.match(eventVerifier, /RootWatchdogChildProcess\.mjs/u);
  assert.match(runner, /\/usr\/bin\/env -i/u);
  assert.match(runner, /HOME=\$TEST_HOME/u);
  assert.match(runner, /CFFIXED_USER_HOME=\$TEST_HOME/u);
  assert.match(runner, /LOCAL_HARNESS_JS_TEST_ISOLATION_ROOT=\$CANONICAL_ROOT/u);
  assert.doesNotMatch(runner, /process\.env|env[^\n]*\.\.\./u);
  assert.match(verifier, /run-js-tests\.sh" --test/u);
  assert.match(credential, /run-js-tests\.sh" --test/u);
  assert.match(makefile, /runtime-inventory-test:[\s\S]*run-js-tests\.sh --test Tests\/JS\/RuntimeInventoryTests\.mjs/u);
  assert.match(makefile, /test:\n\t\/bin\/zsh -f scripts\/run-swift-tests\.sh/u);
  assert.match(makefile, /runtime-inventory-test:[\s\S]*\/bin\/zsh -f scripts\/run-js-tests\.sh/u);
  assert.match(makefile, /release-verify:[\s\S]*\/bin\/zsh -f scripts\/retain-release-verification\.sh/u);
  assert.match(makefile, /deterministic-release-verify:[\s\S]*\/bin\/zsh -f scripts\/verify-release-orchestrated\.sh/u);
  assert.match(orchestrator, /\/bin\/zsh -f "\$PROJECT_DIR\/scripts\/run-watchdog-self-tests\.sh"/u);
  assert.match(retention, /\/bin\/zsh -f "\$PROJECT_DIR\/scripts\/run-watchdog-self-tests\.sh"/u);
  assert.match(workflow, /run: make deterministic-release-verify/u);
  assert.match(makefile, /deterministic-release-verify:[\s\S]*verify-release-orchestrated\.sh --signing-profile private-stable --deterministic-ci/u);
  assert.match(verifier, /FULMAR_CI_REQUIRE_CURRENT_CANDIDATE_TESTS=1[\s\S]*run-js-tests\.sh" --test/u);

  const testRoot = join(process.cwd(), "Tests", "JS");
  const expectedZshCommands = new Map(Object.entries({
    "CleanReleaseEnvironmentTests.mjs": 2,
    "JSTestRunnerTests.mjs": 4,
    "MachOCompatibilityTests.mjs": 1,
    "OllamaFixtureIsolationTests.mjs": 1,
    "PublicDistributionScriptsTests.mjs": 8,
    "ReleaseEvidenceRetentionTests.mjs": 3,
    "ReleaseVerificationScriptTests.mjs": 7,
    "ReleaseWatchdogTests.mjs": 3,
    "SignalCleanupTrapTests.mjs": 6,
    "SourceBuildInputInventoryTests.mjs": 2,
    "SwiftPMDeploymentTargetTests.mjs": 1,
    "ThermalRecoveryBarrierTests.mjs": 1,
    "TwoRootReproducibilityTests.mjs": 1,
    "VendorRuntimeBootstrapTests.mjs": 3
  }));
  const testNames = (await readdir(testRoot)).filter((name) => name.endsWith(".mjs")).sort();
  assert.equal(testNames.length, 66, "the zsh launch audit must cover every reviewed JavaScript source");
  const zshExecutable = ["/bin/", "zsh"].join("");
  const zshLiterals = [`"${zshExecutable}"`, `'${zshExecutable}'`];
  let auditedZshCommands = 0;
  for (const name of testNames) {
    const source = await readFile(join(testRoot, name), "utf8");
    let fileCommands = 0;
    for (const literal of zshLiterals) {
      let offset = 0;
      while (true) {
        const index = source.indexOf(literal, offset);
        if (index < 0) break;
        const prefix = source.slice(Math.max(0, index - 80), index);
        const suffix = source.slice(index + literal.length, index + literal.length + 80);
        const directProcessCall = /(?:spawn|spawnSync|execFile|execFileSync)\(\s*$/u.test(prefix);
        if (directProcessCall) {
          assert.match(suffix, /^\s*,\s*\[\s*["']-f["']\s*,/u,
            `${name} launches a literal zsh executable without first argv -f`);
        } else {
          assert.match(suffix, /^\s*,\s*["']-f["']\s*,/u,
            `${name} embeds a literal zsh command without immediate -f`);
        }
        fileCommands += 1;
        offset = index + literal.length;
      }
    }
    assert.equal(fileCommands, expectedZshCommands.get(name) ?? 0,
      `${name} changed the reviewed literal zsh command topology`);
    auditedZshCommands += fileCommands;
  }
  assert.equal(auditedZshCommands, 43, "the literal zsh command audit must remain complete");
});

test("every production watchdog and privileged shell callsite suppresses ambient startup injection", async () => {
  const scriptRoot = join(process.cwd(), "scripts");
  const [launcher, internal, trackedIndex, staticLauncher, thermalBarrier, makefile, workflow, release, names] = await Promise.all([
    readFile(join(scriptRoot, "run-with-watchdog.sh"), "utf8"),
    readFile(join(scriptRoot, "run-with-watchdog.pl"), "utf8"),
    readFile(join(scriptRoot, "verify-tracked-index.sh"), "utf8"),
    readFile(join(scriptRoot, "run-static-security-scan.sh"), "utf8"),
    readFile(join(scriptRoot, "wait-for-thermal-recovery.sh"), "utf8"),
    readFile(join(process.cwd(), "Makefile"), "utf8"),
    readFile(join(process.cwd(), ".github", "workflows", "verify-source.yml"), "utf8"),
    readFile(join(scriptRoot, "verify-release.sh"), "utf8"),
    readdir(scriptRoot)
  ]);
  const launcherMetadata = await stat(join(scriptRoot, "run-with-watchdog.sh"));
  const internalMetadata = await stat(join(scriptRoot, "run-with-watchdog.pl"));
  assert.equal(launcherMetadata.mode & 0o777, 0o755);
  assert.equal(internalMetadata.mode & 0o111, 0,
    "the internal watchdog must not become directly executable");
  assert.equal(internalMetadata.mode & 0o022, 0,
    "the internal watchdog must not be group- or world-writable");
  assert.match(launcher, /^#!\/bin\/sh -p\n/u);
  assert.match(launcher, /exec \/usr\/bin\/env -i/u);
  const dyldStrip = launcher.indexOf("unset DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH");
  const cleanBootstrap = launcher.indexOf("exec /usr/bin/env -i");
  assert.ok(dyldStrip > 0 && cleanBootstrap > dyldStrip,
    "the public launcher must strip both DYLD hooks by builtin before its first external exec");
  assert.match(launcher, /FULMAR_WATCHDOG_CLEAN_LAUNCH_V1=1/u);
  assert.match(internal, /run-with-watchdog\.pl is internal/u);
  assert.match(trackedIndex, /scripts\/run-with-watchdog\.sh/u);
  assert.match(trackedIndex, /^#!\/bin\/bash -p\n/u);
  assert.match(staticLauncher, /^#!\/bin\/sh -p\n/u);
  assert.match(thermalBarrier, /^#!\/bin\/bash -p\n/u);
  assert.match(makefile, /\/bin\/bash -p scripts\/verify-tracked-index\.sh \./u);
  assert.match(makefile, /\/bin\/sh -p scripts\/run-static-security-scan\.sh/u);
  assert.equal((workflow.match(/\/bin\/bash -p scripts\/verify-tracked-index\.sh \./gu) ?? []).length, 4);
  assert.equal(
    (release.match(/\/bin\/bash -p "\$PROJECT_DIR\/scripts\/wait-for-thermal-recovery\.sh"/gu) ?? []).length,
    4
  );
  const productionSources = [["Makefile", makefile]];
  for (const name of names.filter((value) => /\.(?:sh|zsh|mjs|pl)$/u.test(value)
    && !["run-with-watchdog.sh", "run-with-watchdog.pl"].includes(value))) {
    productionSources.push([`scripts/${name}`, await readFile(join(scriptRoot, name), "utf8")]);
  }
  const workflowRoot = join(process.cwd(), ".github", "workflows");
  for (const name of await readdir(workflowRoot)) {
    if (/\.ya?ml$/u.test(name)) productionSources.push([
      `.github/workflows/${name}`, await readFile(join(workflowRoot, name), "utf8")
    ]);
  }
  for (const [name, source] of productionSources) {
    assert.doesNotMatch(source, /run-with-watchdog\.pl/u, `${name} bypasses the clean launcher`);
    assert.doesNotMatch(source, /(?:^|\s)(?:\/bin\/)?(?:sh|bash|zsh)\s+[^\n]*run-with-watchdog\.sh/gmu,
      `${name} bypasses the launcher's privileged shebang`);
    assert.doesNotMatch(
      source,
      /(?:spawn|spawnSync|execFile|execFileSync)\(\s*["']\/bin\/(?:sh|bash)["']\s*,\s*\[\s*(?!["']-p["'])/u,
      `${name} programmatically launches a shell without privileged startup suppression`
    );
    for (const line of source.split("\n").filter((value) => !/^\s*#/u.test(value))) {
      assert.doesNotMatch(
        line,
        /(?:^\s*|[;&|]\s*|--\s+|\bexec\s+)(?:\/bin\/)?zsh\s+(?!-f(?:\s|$))/u,
        `${name} invokes zsh without suppressing ambient startup files: ${line}`
      );
      assert.doesNotMatch(
        line,
        /\/bin\/(?:sh|bash)(?![A-Za-z0-9_.-])\s+(?!-p(?:\s|$))/u,
        `${name} invokes a shell without privileged startup suppression: ${line}`
      );
    }
  }
});

test("self-root JavaScript fixtures run only in the exact event-accounted private pre-root suite", async () => {
  const [selfTests, selfVerifier, reporter, watchdogTests, evidence, childHelper, rootHelper] = await Promise.all([
    readFile(join(process.cwd(), "scripts", "run-watchdog-self-tests.sh"), "utf8"),
    readFile(join(process.cwd(), "scripts", "verify-self-root-test-events.mjs"), "utf8"),
    readFile(join(process.cwd(), "scripts", "self-root-test-event-reporter.mjs"), "utf8"),
    readFile(join(process.cwd(), "Tests", "JS", "ReleaseWatchdogTests.mjs"), "utf8"),
    readFile(join(process.cwd(), "Tests", "JS", "ReleaseEvidenceRetentionTests.mjs"), "utf8"),
    readFile(join(process.cwd(), "Tests", "JS", "RootWatchdogChildProcess.mjs"), "utf8"),
    readFile(join(process.cwd(), "scripts", "watchdog-root.zsh"), "utf8")
  ]);
  assert.match(selfTests, /run-process-tree-watchdog\.mjs/u);
  assert.match(selfTests, /ReleaseWatchdogTests\.mjs/u);
  assert.match(selfTests, /ReleaseEvidenceRetentionTests\.mjs/u);
  assert.match(selfTests, /HOME="\$HOME_ROOT" CFFIXED_USER_HOME="\$HOME_ROOT" TMPDIR="\$TEMP_ROOT\/"/u);
  assert.match(selfTests, /--experimental-test-isolation=none --test-force-exit/u);
  assert.match(selfTests, /--test-concurrency=1 --test-timeout=30000/u);
  assert.match(selfTests, /self-root-test-event-reporter\.mjs/u);
  assert.match(selfTests, /verify-self-root-test-events\.mjs/u);
  assert.match(selfTests, /if ! cleanup; then/u);
  assert.match(selfVerifier, /const expectedNames = Object\.freeze\(\[/u);
  assert.equal(selfVerifier.match(/^  "/gmu)?.length, 62);
  assert.match(selfVerifier, /records\.filter\(\(record\) => record\.type === "test:summary"\)/u);
  assert.match(selfVerifier, /summaries\[0\]\.counts\?\.skipped !== 0/u);
  assert.match(reporter, /emittedBytes > 2 \* 1024 \* 1024/u);
  assert.match(reporter, /emittedRecords > 4_096/u);
  assert.equal(watchdogTests.match(/supervisorFixture\(/gu)?.length, 24);
  assert.match(watchdogTests, /for \(const \[signal, expectedCode\] of \[\["SIGTERM", 143\], \["SIGINT", 130\], \["SIGHUP", 129\]\]\)/u);
  assert.match(evidence, /isInsideAuthenticatedRootWatchdog \? test\.skip : test/u);
  assert.equal(evidence.match(/selfRootTest\(/gu)?.length, 17);
  assert.match(childHelper, /attest-watchdog-capability-fd\.pl/u);
  assert.match(childHelper, /bounded-process-group-inspector\.mjs/u);
  assert.match(childHelper, /stdio\[descriptor\] = descriptor/u);
  assert.match(childHelper, /--inherit-root/u);
  assert.match(rootHelper, /FULMAR_WATCHDOG_HELPER_PROJECT_DIR_V1="\$\{\$\{\(%\):-%N\}:A:h:h\}"/u);
  assert.match(rootHelper, /local project_dir="\$FULMAR_WATCHDOG_HELPER_PROJECT_DIR_V1"/u);
  assert.doesNotMatch(rootHelper, /local project_dir="\$\{PROJECT_DIR/u);
  assert.equal(rootHelper.match(/\/usr\/bin\/env -i PATH="\$attestation_path"/gu)?.length, 2);
  assert.match(rootHelper, /env -i[\s\S]*\/usr\/bin\/perl[\s\S]*env -i[\s\S]*"\$node"/u);
});

test("credential qualification has bounded helper and telemetry-lock lifecycles", async () => {
  const shell = await readFile(join(process.cwd(), "scripts", "verify-credential-helper.sh"), "utf8");
  const makefile = await readFile(join(process.cwd(), "Makefile"), "utf8");
  const productGate = await readFile(join(process.cwd(), "scripts", "run-bounded-swift-product-gate.sh"), "utf8");
  const credential = await readFile(join(process.cwd(), "scripts", "verify-credential-helper-bounds.mjs"), "utf8");
  const telemetry = await readFile(join(process.cwd(), "scripts", "verify-telemetry-lock-helper.mjs"), "utf8");
  assert.match(shell, /verify-credential-helper-bounds\.mjs/u);
  assert.match(shell, /verify-keychain-no-ui-transition\.mjs/u);
  assert.doesNotMatch(shell, /list-records/u);
  assert.match(credential, /deadlineMilliseconds\s*=\s*3_000/u);
  assert.match(credential, /\["describe-record", retainedRecord\]/u);
  assert.match(telemetry, /waitForExitWithin/u);
  assert.match(telemetry, /Date\.now\(\) \+ 5_000/u);
  assert.match(makefile, /run-bounded-swift-product-gate\.sh credential/u);
  assert.match(productGate, /build_product LocalHarnessCredentialHelper/u);
  assert.doesNotMatch(`${makefile}\n${productGate}`, /--target LocalHarnessCredentialHelper/u);
  const migration = await readFile(join(process.cwd(), "scripts", "verify-credential-migration.sh"), "utf8");
  assert.match(migration, /HELPER="\$PROJECT_DIR\/\.build\/debug\/LocalHarnessCredentialHelper"[\s\S]*HELPER="\$\{HELPER:A\}"/u);
});

test("release credential migration executes only candidate-bound helper and resources", async () => {
  const [migration, release] = await Promise.all([
    readFile(join(process.cwd(), "scripts", "verify-credential-migration.sh"), "utf8"),
    readFile(join(process.cwd(), "scripts", "verify-release.sh"), "utf8")
  ]);
  assert.match(migration, /HELPER="\$1"/u);
  assert.match(migration, /CONTENTS_DIR="\$\{HELPER:h:h\}"/u);
  assert.match(migration, /NODE="\$CONTENTS_DIR\/Resources\/Runtime\/node"/u);
  assert.match(migration, /MIGRATOR="\$CONTENTS_DIR\/Resources\/MigrateCredentials\.mjs"/u);
  assert.match(migration, /YAML_MODULE="\$CONTENTS_DIR\/Resources\/Runtime\/dsh\/node_modules\/yaml\/dist\/index\.js"/u);
  assert.match(migration, /MIGRATION_OUTPUT="\$TEMP_DIR\/migration-result\.json"/u);
  assert.match(migration, /\/usr\/bin\/stat -f '%z' "\$MIGRATION_OUTPUT"/u);
  assert.match(migration, /'\{"references":1,"records":1\}'/u);
  assert.doesNotMatch(migration, /\brg\b/u);
  assert.match(release, /verify-credential-migration\.sh" "\$APP_DIR\/Contents\/MacOS\/LocalHarnessCredentialHelper"/u);
});

test("cloned-state gate is not misrepresented as a two-version upgrade test", async () => {
  const [cloneGate, release, makefile] = await Promise.all([
    readFile(join(process.cwd(), "scripts", "verify-cloned-state-security.sh"), "utf8"),
    readFile(join(process.cwd(), "scripts", "verify-release.sh"), "utf8"),
    readFile(join(process.cwd(), "Makefile"), "utf8")
  ]);
  assert.match(cloneGate, /intentionally not called an upgrade test/u);
  assert.match(cloneGate, /LOCAL_HARNESS_CANARY_STATE=clone/u);
  assert.match(release, /verify-cloned-state-security\.sh/u);
  assert.doesNotMatch(release, /canary-runtime-upgrade/u);
  assert.match(makefile, /cloned-state-security:/u);
  assert.doesNotMatch(makefile, /canary-upgrade:/u);
});

test("background credentials are brokered non-interactively and local Ollama bypasses Keychain", async () => {
  const [helper, brokerClient, brokerService, transaction, packageManifest, recoveryTests, plugin] = await Promise.all([
    readFile(join(process.cwd(), "Tools", "CredentialHelper", "main.swift"), "utf8"),
    readFile(join(process.cwd(), "Tools", "CredentialHelper", "CredentialBrokerClient.swift"), "utf8"),
    readFile(join(process.cwd(), "Tools", "CredentialBrokerService", "main.swift"), "utf8"),
    readFile(join(process.cwd(), "Sources", "CredentialSecurity", "CredentialTransaction.swift"), "utf8"),
    readFile(join(process.cwd(), "Package.swift"), "utf8"),
    readFile(join(process.cwd(), "Tests", "LocalHarnessTests", "CredentialTransactionRecoveryTests.swift"), "utf8"),
    readFile(join(process.cwd(), "Resources", "DSHPlugins", "credentials-keychain", "index.mjs"), "utf8")
  ]);
  assert.match(packageManifest, /name:\s*"LocalHarnessCredentialSecurity"/u);
  assert.match(packageManifest, /name:\s*"LocalHarnessCredentialHelper",\s*dependencies:\s*\[[\s\S]*"LocalHarnessCredentialSecurity"[\s\S]*"LocalHarnessCredentialBrokerXPCProtocol"[\s\S]*\],\s*path:\s*"Tools\/CredentialHelper"/u);
  assert.match(helper, /import LocalHarnessCredentialSecurity/u);
  assert.match(helper, /CredentialTransactionCoordinator/u);
  assert.match(helper, /dlsym\(securityHandle, "SecKeychainSetUserInteractionAllowed"\)/u);
  assert.match(helper, /setKeychainInteraction\(0\)/u);
  assert.match(helper, /LAContext\(\)/u);
  assert.match(helper, /interactionNotAllowed\s*=\s*true/u);
  assert.match(helper, /dispatchCredentialBrokerCommandIfNeeded\(command: command, arguments: arguments\)/u);
  assert.match(brokerClient, /#if DEBUG[\s\S]*return[\s\S]*#else[\s\S]*brokerClientFail\(\.invalidBundle\)/u);
  assert.match(brokerClient, /connection\.setCodeSigningRequirement\(serviceIdentity\.exactRequirement\)/u);
  assert.match(brokerService, /CredentialPrivateDirectory\.prepareMetadataDirectoryCapability/u);
  assert.match(brokerService, /SecItemUpdate\(/u);
  assert.match(brokerService, /interactionNotAllowed\s*=\s*true/u);
  assert.match(transaction, /CredentialTransactionJournal/u);
  assert.match(transaction, /withAccountLock/u);
  assert.match(transaction, /flock\(descriptor, LOCK_EX \| LOCK_NB\)/u);
  assert.match(transaction, /fsync\(descriptor\)/u);
  assert.match(transaction, /renameat\([\s\S]*directoryDescriptor/u);
  assert.match(transaction, /synchronizeDirectory\(\)/u);
  assert.match(transaction, /recoverLocked\(account:/u);
  assert.match(transaction, /afterJournalPrepared/u);
  assert.match(transaction, /afterMetadataCommit/u);
  assert.match(recoveryTests, /CredentialTransactionCheckpoint\.allCases/u);
  assert.match(recoveryTests, /newCredentialRecoversAtEveryKillBoundaryWithoutKeychainAccess/u);
  assert.match(recoveryTests, /replacementRecoversAtEveryKillBoundaryWithoutCredentialLoss/u);
  assert.match(recoveryTests, /credentialRemovalRecoversAtEveryKillBoundaryWithoutFalseConfiguredState/u);
  assert.match(recoveryTests, /concurrentCoordinatorsSerializeOneAccountAcrossIndependentFileDescriptors/u);
  assert.match(recoveryTests, /bytes\.range\(of: secret\) == nil/u);
  assert.doesNotMatch(helper, /kSecUseAuthenticationUIFail/u);
  assert.match(helper, /authorizationRequiredExitStatus:\s*Int32\s*=\s*5/u);
  const localReturn = plugin.indexOf('if (reference === "OLLAMA_API_KEY" && localOllamaCredential)');
  const helperRead = plugin.indexOf('runHelper("get", reference)');
  assert.ok(localReturn >= 0 && helperRead > localReturn);
  assert.match(plugin, /KEYCHAIN_AUTHORIZATION_REQUIRED/u);
});

test("credential process-crash qualification is isolated, fake-backed, and release-gated", async () => {
  const [packageManifest, probe, gate, transaction, recoveryTests, release, makefile, build] = await Promise.all([
    readFile(join(process.cwd(), "Package.swift"), "utf8"),
    readFile(join(process.cwd(), "Tests", "CredentialTransactionCrashProbe", "main.swift"), "utf8"),
    readFile(join(process.cwd(), "scripts", "verify-credential-transaction-crash.sh"), "utf8"),
    readFile(join(process.cwd(), "Sources", "CredentialSecurity", "CredentialTransaction.swift"), "utf8"),
    readFile(join(process.cwd(), "Tests", "LocalHarnessTests", "CredentialTransactionRecoveryTests.swift"), "utf8"),
    readFile(join(process.cwd(), "scripts", "verify-release.sh"), "utf8"),
    readFile(join(process.cwd(), "Makefile"), "utf8"),
    readFile(join(process.cwd(), "scripts", "build-app.sh"), "utf8")
  ]);

  assert.match(packageManifest, /name:\s*"CredentialTransactionCrashProbe",\s*dependencies:\s*\["LocalHarnessCredentialSecurity"\],\s*path:\s*"Tests\/CredentialTransactionCrashProbe"/u);
  assert.match(probe, /final class FileBackedFakeCredentialValueStore:\s*CredentialValueStore/u);
  assert.match(probe, /CredentialTransactionCoordinator/u);
  assert.match(probe, /CHECKPOINT \\\(reached\.rawValue\)/u);
  assert.match(probe, /while true \{ _ = Darwin\.pause\(\) \}/u);
  assert.match(probe, /flock\(descriptor, LOCK_EX \| LOCK_NB\)/u);
  assert.match(probe, /LOCK_RELEASED/u);
  assert.doesNotMatch(probe, /^import Security$|SecItem|SecKeychain/mu);

  assert.match(gate, /mktemp -d \/private\/tmp\/fulmar-credential-crash-gate\.XXXXXX/u);
  assert.match(gate, /scenarios=\(create replace adopt remove repair-adopt repair-replace repair-remove unknown-record-remove\)/u);
  assert.match(probe, /repairAdoptingCurrentValue/u);
  assert.match(probe, /repairReplacingCurrentValue/u);
  assert.match(probe, /repairRemovingCurrentValue/u);
  assert.match(probe, /RECOVERY_ATTENTION/u);
  for (const checkpoint of [
    "afterJournalPrepared",
    "afterValueMutation",
    "afterValueVerification",
    "afterMetadataCommit",
    "afterFinalVerification",
    "afterJournalRemoval"
  ]) {
    assert.match(gate, new RegExp(`\\b${checkpoint}\\b`, "u"));
  }
  assert.match(gate, /\/bin\/kill -KILL "\$CHILD_PID"/u);
  assert.match(gate, /"\$killed_status" == "137"/u);
  for (const checkpoint of [
    "afterTemporaryWrite",
    "afterFileSynchronize",
    "afterRename",
    "afterDirectorySynchronize"
  ]) {
    assert.match(gate, new RegExp(`\\b${checkpoint}\\b`, "u"));
  }
  assert.match(gate, /mutate-persistence/u);
  assert.match(gate, /recover-persistence/u);
  assert.match(gate, /-c release/u);
  assert.match(gate, /nm -u/u);
  assert.match(gate, /otool -L/u);
  assert.match(gate, /"\$case_count" == "60"/u);
  assert.match(gate, /18 v2 foreground repairs/u);
  assert.match(gate, /6 token-bound unknown-record removals/u);
  assert.match(gate, /12 persistence boundaries/u);
  assert.match(gate, /file-backed fake store only/u);

  assert.match(transaction, /enum CredentialFileStatePersistenceCheckpoint:[\s\S]*afterTemporaryWrite[\s\S]*afterFileSynchronize[\s\S]*afterRename[\s\S]*afterDirectorySynchronize/u);
  assert.doesNotMatch(
    transaction,
    /public func repairRemovingCurrentRecord\(account: String\)/u
  );
  assert.match(
    transaction,
    /public func repairRemovingCurrentRecord\(\s*account: String,\s*expectedToken: String,/u
  );
  assert.match(transaction, /persistenceCheckpoint\(artifact, \.afterTemporaryWrite\)[\s\S]*fsync\(descriptor\)[\s\S]*persistenceCheckpoint\(artifact, \.afterFileSynchronize\)[\s\S]*renameat\([\s\S]*persistenceCheckpoint\(artifact, \.afterRename\)[\s\S]*synchronizeDirectory\(\)[\s\S]*persistenceCheckpoint\(artifact, \.afterDirectorySynchronize\)/u);
  assert.match(recoveryTests, /journalPersistenceFaultsRecoverTheExactPriorStateAtEveryDurabilityCheckpoint/u);
  assert.match(recoveryTests, /metadataPersistenceFaultsRecoverTheExactCommittedStateAtEveryDurabilityCheckpoint/u);
  assert.match(recoveryTests, /CredentialFileStatePersistenceCheckpoint\.allCases/g);

  assert.match(release, /verify-credential-transaction-crash\.sh/u);
  assert.match(release, /process-crash evidence, not a[\s\S]*physical power loss/u);
  assert.match(makefile, /credential-crash-test:\n\t\/bin\/zsh -f scripts\/verify-credential-transaction-crash\.sh/u);
  assert.doesNotMatch(build, /CredentialTransactionCrashProbe/u);
});

test("private release signing keeps helper identities stable across updates", async () => {
  const [build, creator, makefile, verifier, release, signatureVerifier, workflow, partitionHelper] = await Promise.all([
    readFile(join(process.cwd(), "scripts", "build-app.sh"), "utf8"),
    readFile(join(process.cwd(), "scripts", "create-local-signing-identity.sh"), "utf8"),
    readFile(join(process.cwd(), "Makefile"), "utf8"),
    readFile(join(process.cwd(), "scripts", "verify-stable-signing.sh"), "utf8"),
    readFile(join(process.cwd(), "scripts", "verify-release.sh"), "utf8"),
    readFile(join(process.cwd(), "scripts", "verify-code-signature.sh"), "utf8"),
    readFile(join(process.cwd(), ".github", "workflows", "verify-source.yml"), "utf8"),
    readFile(join(process.cwd(), "scripts", "set-signing-key-partition-list-from-fd.c"), "utf8")
  ]);
  assert.match(build, /LOCAL_HARNESS_REQUIRE_STABLE_SIGNING/u);
  assert.match(build, /--identifier "\$PRODUCT_BUNDLE_ID\.credential-helper"/u);
  assert.match(build, /--identifier "\$PRODUCT_BUNDLE_ID\.runtime-lease"/u);
  assert.match(build, /Fulmar Local Signing/u);
  assert.match(creator, /-x -T \/usr\/bin\/codesign/u);
  assert.doesNotMatch(creator, /security import[^\n]* -A(?:\s|$)/u);
  assert.doesNotMatch(creator, /add-trusted-cert/u);
  assert.match(creator, /fulmar-signing-proof/u);
  assert.match(creator, /LOCAL_HARNESS_SIGNING_KEYCHAIN/u);
  assert.match(creator, /set-signing-key-partition-list-from-fd\.c/u);
  assert.match(creator, /"\$partition_helper" "\$SIGNING_KEYCHAIN"/u);
  assert.match(creator, /"\$@" \{SIGNING_SECRET_FD\}<&-/u);
  assert.match(creator, /"\$partition_helper" "\$SIGNING_KEYCHAIN"[\s\S]*exec \{SIGNING_SECRET_FD\}<&-[\s\S]*unset FULMAR_SIGNING_SECRET_FD_V1/u);
  assert.match(creator, /unset FULMAR_SIGNING_SECRET_FD_V1[\s\S]*open\(my \$probe, "<&=196"\)[\s\S]*created="\$\(run_without_signing_secret certificate_hashes\)"/u);
  assert.doesNotMatch(creator, /(?:-P|-passout\s+pass:|-k)\s+"?\$?(?:passphrase|KEYCHAIN_PASSWORD)/u);
  assert.match(partitionHelper, /"set-key-partition-list",\s*"-S",\s*"apple-tool:,apple:",\s*"-s"/u);
  assert.doesNotMatch(partitionHelper, /"-k"|"-P"|pass:/u);
  assert.match(partitionHelper, /details\.st_nlink != 0/u);
  assert.match(partitionHelper, /details\.st_size > 513/u);
  assert.match(build, /SIGN_ARGS\+=\(--keychain "\$SIGNING_KEYCHAIN"\)/u);
  assertCIWorkflowSigningTransport(process.cwd(), workflow);
  assert.match(workflow, /run: make private-release/u);
  assert.doesNotMatch(workflow, /run: make build(?:\s|$)/u);
  assert.match(makefile, /private-release:/u);
  assert.match(verifier, /Signature=adhoc/u);
  assert.match(verifier, /certificate root = H/u);
  assert.match(verifier, /\.credential-helper/u);
  assert.match(verifier, /\.runtime-lease/u);
  assert.match(release, /verify-stable-signing\.sh/u);
  assert.match(release, /verify-runtime-lease\.sh/u);
  assert.doesNotMatch(release, /codesign -dvv[^\n]*\|\s*rg -q/u);
  assert.match(signatureVerifier, /CSSMERR_TP_NOT_TRUSTED/u);
  assert.match(signatureVerifier, /REMAINDER/u);
  assert.match(signatureVerifier, /LOCAL_HARNESS_ALLOW_PRIVATE_ROOT/u);
});
