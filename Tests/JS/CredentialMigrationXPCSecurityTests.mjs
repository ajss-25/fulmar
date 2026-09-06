import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, readdir, realpath, rename, rm, symlink, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { runInNewContext } from "node:vm";
import { rootWatchdogChildOptions } from "./RootWatchdogChildProcess.mjs";

const root = process.cwd();

function verifyMonitorCompletionHandling(source) {
  const start = source.indexOf("\nvalidateInputs();");
  assert.ok(start > 0, "the production monitor lifecycle must be present");
  const lifecycle = source.slice(start);
  const failStart = source.indexOf("\nfunction fail() {");
  const failEnd = source.indexOf("\nfunction bounded(", failStart);
  assert.ok(failStart > 0 && failEnd > failStart);
  for (const phase of ["input-validation", "preexisting-service-check", "waiting-for-service",
    "recording-service-identity", "waiting-for-client", "draining-service"]) {
    let diagnostic = "";
    const failure = new Error("fixture exit");
    assert.throws(() => runInNewContext(`${source.slice(failStart, failEnd)}\nfail();`, {
      phase,
      process: {
        stderr: { write(value) { diagnostic += value; } },
        exit(code) { assert.equal(code, 1); throw failure; }
      }
    }, { timeout: 1_000 }), (error) => error === failure);
    assert.equal(diagnostic, `Credential XPC exact-process evidence failed (${phase}).\n`);
  }
  for (const scenario of ["client-before-service", "normal", "service-between-snapshot-and-done",
    "ambiguous", "launch-timeout", "completion-timeout"]) {
    let now = 0;
    let scans = 0;
    let drained = false;
    let evidenced = false;
    let output = "";
    const identity = { pid: 1234, started: "fixture" };
    const failure = new Error("fixture monitor failure");
    const context = {
      Date: { now: () => now },
      validateInputs() {}, writeReady() {},
      exactProcesses() {
        scans += 1;
        if (scans === 1 || drained) return [];
        if (scenario === "service-between-snapshot-and-done" && scans === 2) return [];
        if (scenario === "client-before-service" || scenario === "launch-timeout") return [];
        return scenario === "ambiguous" ? [identity, identity] : [identity];
      },
      validateDone: () => !["launch-timeout", "completion-timeout"].includes(scenario),
      writeEvidence(value) { assert.equal(value, identity); evidenced = true; },
      drainExactProcesses() { assert.ok(evidenced); drained = true; },
      fail() { throw failure; },
      sleep(milliseconds) { now += milliseconds; },
      process: { stdout: { write(value) { output += value; } } }
    };
    if (scenario === "normal" || scenario === "service-between-snapshot-and-done") {
      runInNewContext(lifecycle, context, { timeout: 1_000 });
      assert.ok(evidenced && drained);
      assert.equal(output, "FULMAR_CREDENTIAL_XPC_PROCESS_DRAIN_OK\n");
    } else {
      assert.throws(() => runInNewContext(lifecycle, context, { timeout: 1_000 }),
        (error) => error === failure, scenario);
      assert.equal(output, "", scenario);
      assert.equal(drained, false, scenario);
      if (scenario === "client-before-service") {
        assert.equal(now, 0, "an exited client with no observed service must not masquerade as a drain timeout");
        assert.equal(evidenced, false);
      }
      if (scenario === "launch-timeout") assert.equal(now, 10_000);
      if (scenario === "completion-timeout") assert.equal(now, 20_000);
    }
  }
}

async function verifyCandidateAdmission(verifier) {
  const inspection = 'plutil -lint "$SERVICE_INFO" >/dev/null\n';
  assert.equal(verifier.split(inspection).length, 2, "the first metadata inspection must be unique");
  assert.match(verifier, /^#!\/bin\/zsh -f\nset -euo pipefail\n/u);
  assert.ok(verifier.indexOf(inspection) < verifier.indexOf('/usr/bin/codesign'));
  const fixtureRoot = await realpath(await mkdtemp(join(tmpdir(), "fulmar-migration-admission-")));
  await chmod(fixtureRoot, 0o700);
  try {
    const bin = join(fixtureRoot, "bin");
    const scratch = join(fixtureRoot, "scratch");
    await mkdir(bin, { mode: 0o700 });
    await mkdir(scratch, { mode: 0o700 });
    // Stop the real verifier at its first plist inspection. No candidate binary,
    // signing command or credential operation is executed by this fixture.
    const sentinel = "FULMAR_TEST_ADMISSION_REACHED_PLIST";
    await writeFile(join(bin, "plutil"), [
      "#!/bin/sh -p",
      '[ "$#" -eq 2 ] && [ "$1" = "-lint" ] && [ "$2" = "$EXPECTED_SERVICE_INFO" ] || exit 78',
      `printf '%s\\n' '${sentinel}' >&2`,
      "exit 79", ""
    ].join("\n"), { mode: 0o700 });
    const cases = [{ name: "valid", expected: 79 }];
    for (const key of ["app", "service", "info", "executable", "helper"]) {
      cases.push({ name: `missing-${key}`, key, mutation: "missing", expected: 1 });
      cases.push({ name: `linked-${key}`, key, mutation: "linked", expected: 1 });
    }
    for (const key of ["executable", "helper"]) {
      cases.push({ name: `non-executable-${key}`, key, mutation: "non-executable", expected: 1 });
    }
    for (const key of ["info", "executable", "helper"]) {
      cases.push({ name: `directory-${key}`, key, mutation: "directory", expected: 1 });
    }
    cases.push({ name: "noncanonical", mutation: "noncanonical", expected: 1 });
    cases.push({ name: "linked-parent", mutation: "linked-parent", expected: 1 });
    for (const item of cases) {
      const caseRoot = await mkdtemp(join(fixtureRoot, "case-"));
      const app = join(caseRoot, "Candidate with spaces.app");
      const service = join(app, "Contents/XPCServices/LocalHarnessCredentialMigrationService.xpc");
      const paths = {
        app, service,
        info: join(service, "Contents/Info.plist"),
        executable: join(service, "Contents/MacOS/LocalHarnessCredentialMigrationService"),
        helper: join(app, "Contents/MacOS/LocalHarnessCredentialHelper")
      };
      await mkdir(join(service, "Contents/MacOS"), { recursive: true });
      await mkdir(join(app, "Contents/MacOS"), { recursive: true });
      await writeFile(paths.info, "fixture metadata: never parsed\n");
      for (const path of [paths.executable, paths.helper]) {
        await writeFile(path, "#!/bin/sh -p\nexit 99\n", { mode: 0o755 });
      }
      let candidate = app;
      if (item.mutation === "missing" || item.mutation === "directory") {
        await rm(paths[item.key], { recursive: true });
        if (item.mutation === "directory") await mkdir(paths[item.key]);
      } else if (item.mutation === "linked") {
        const target = join(caseRoot, "link-target");
        await rename(paths[item.key], target);
        await symlink(target, paths[item.key]);
      } else if (item.mutation === "non-executable") {
        await chmod(paths[item.key], 0o644);
      } else if (item.mutation === "noncanonical") {
        candidate = `${caseRoot}/./Candidate with spaces.app`;
      } else if (item.mutation === "linked-parent") {
        const alias = join(fixtureRoot, "parent-alias");
        await symlink(caseRoot, alias);
        candidate = join(alias, "Candidate with spaces.app");
      }
      const result = spawnSync("/bin/zsh", ["-f", join(root, "scripts/verify-credential-migration-xpc.sh"), candidate],
        rootWatchdogChildOptions({
          encoding: "utf8", timeout: 5_000,
          env: { PATH: `${bin}:/usr/bin:/bin`, TMPDIR: scratch, EXPECTED_SERVICE_INFO: paths.info }
        }));
      assert.equal(result.error, undefined, `${item.name}: ${result.error}`);
      assert.equal(result.signal, null, item.name);
      assert.equal(result.status, item.expected, `${item.name}: ${result.stderr}`);
      assert.equal(result.stdout, "", item.name);
      assert.equal(result.stderr, item.expected === 79 ? `${sentinel}\n`
        : "Credential migration XPC verification requires one canonical packaged candidate.\n", item.name);
      assert.deepEqual(await readdir(scratch), [], `${item.name}: verifier temporary files were not removed`);
    }
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
  }
}

test("production credential migration uses mutually code-bound private XPC capabilities", async () => {
  const [client, service, protocol, manager, transaction, receipt, commit, acceptance] = await Promise.all([
    readFile(join(root, "Sources/LocalHarness/CredentialMigrationXPCClient.swift"), "utf8"),
    readFile(join(root, "Tools/CredentialMigrationService/main.swift"), "utf8"),
    readFile(join(root, "Sources/CredentialMigrationXPCProtocol/CredentialMigrationXPCProtocol.swift"), "utf8"),
    readFile(join(root, "Sources/LocalHarness/CredentialMigrationManager.swift"), "utf8"),
    readFile(join(root, "Sources/CredentialSecurity/CredentialTransaction.swift"), "utf8"),
    readFile(join(root, "Sources/CredentialSecurity/CredentialMigrationReceipt.swift"), "utf8"),
    readFile(join(root, "Sources/CredentialSecurity/CredentialMigrationCommitBoundary.swift"), "utf8"),
    readFile(join(root, "Sources/LocalHarness/CredentialMigrationXPCAcceptanceCoordinator.swift"), "utf8")
  ]);

  assert.match(protocol, /source: FileHandle,[\s\S]*sourceParent: FileHandle,[\s\S]*lease: FileHandle,/u);
  assert.match(client, /connection\.setCodeSigningRequirement\(serviceIdentity\.exactRequirement\)/u);
  assert.match(service, /connection\.setCodeSigningRequirement\(exactApplicationRequirement\)/u);
  assert.match(client, /and cdhash H/u);
  assert.match(service, /and cdhash H/u);
  assert.match(client, /designatedRequirement == helperIdentity\.designatedRequirement/u);
  assert.match(service, /serviceIdentity\.designatedRequirement == helperIdentity\.designatedRequirement/u);
  assert.match(client, /F_DUPFD_CLOEXEC/u);
  assert.match(client, /CredentialMigrationXPCSchema\.encode\(capabilities\.request\)/u);
  assert.match(client, /CredentialMigrationXPCSchema\.decodeResponse/u);
  assert.match(service, /fstatat\(sourceParent/u);
  assert.match(service, /ftruncate\(source, 0\)[\s\S]*fsync\(source\)/u);
  assert.match(transaction, /withAtomicMigrationBatch[\s\S]*for entry in changed\.reversed\(\)/u);
  assert.match(transaction, /guard current == entry\.value[\s\S]*batchRollbackIncomplete/u);
  assert.match(service, /CredentialMigrationCommitBoundary\.commit[\s\S]*ftruncate\(source, 0\)/u);
  assert.match(commit, /receiptStore\.write\(preparedReceipt\)[\s\S]*try truncate\(\)[\s\S]*catch \{[\s\S]*return \.recoveryRequired/u);
  assert.match(receipt, /HMAC<SHA256>/u);
  assert.match(receipt, /openat/u);
  assert.match(receipt, /renameat/u);
  assert.match(receipt, /fsync\(directoryDescriptor\)/u);
  assert.match(service, /CredentialMigrationXPCSchema\.decodeRequest/u);
  assert.match(service, /canonicalGraph == graphData/u);
  assert.match(service, /import JavaScriptCore/u);
  assert.match(service, /names\.length !== 74/u);
  assert.match(service, /cancellation\.cancel\(\.timedOut\)/u);
  assert.match(service, /MigrationHardStopGate[\s\S]*active = false[\s\S]*_exit\(124\)/u);
  assert.match(client, /uptimeNanoseconds >= clientDeadline[\s\S]*\.timedOut/u);
  assert.match(manager, /components\.requiresBundleIntegrity, componentLocator == nil[\s\S]*CredentialMigrationXPCClient\.run/u);
  assert.match(manager, /packaged migration never launches Node[\s\S]*components\.helper[\s\S]*components\.yaml/u);
  assert.match(manager, /CredentialMigrationLease\.withExclusiveLease/u);
  assert.match(acceptance, /\/private\/tmp\//u);
  assert.match(acceptance, /UUID\(\)\.uuidString\.lowercased\(\)/u);
  assert.match(acceptance, /CredentialMigrationXPCClient\.runAcceptance/u);
  assert.match(service, /case \.acceptance:[\s\S]*performAcceptance/u);
  assert.match(service, /performAcceptance[\s\S]*return CredentialMigrationXPCResponse\(status: \.success\)/u);
  assert.doesNotMatch(
    service.match(/private func performAcceptance[\s\S]*?\n\}/u)?.[0] ?? "",
    /credentialContext|SecItem|parseYAML|JavaScriptCore/u
  );
  assert.doesNotMatch(service, /Process\(|posix_spawn|execv|\/Runtime\/node|MigrateCredentials\.mjs/u);
});

test("XPC request and response bytes have one canonical exact schema", async () => {
  const [protocol, tests] = await Promise.all([
    readFile(join(root, "Sources/CredentialMigrationXPCProtocol/CredentialMigrationXPCProtocol.swift"), "utf8"),
    readFile(join(root, "Tests/LocalHarnessTests/CredentialMigrationXPCProtocolTests.swift"), "utf8")
  ]);

  assert.match(protocol, /exactKeys\(root,[\s\S]*deadlineNanoseconds[\s\S]*sourceParent[\s\S]*version/u);
  assert.match(protocol, /exactKeys\(root, \["records", "references", "status", "version"\]\)/u);
  assert.match(protocol, /CFGetTypeID\(raw as CFTypeRef\) == CFNumberGetTypeID\(\)/u);
  assert.match(protocol, /canonical == data/u);
  assert.match(tests, /unknownRoot[\s\S]*unknownNested[\s\S]*booleanVersion[\s\S]*floatingVersion[\s\S]*duplicateVersion/u);
  assert.match(tests, /booleanCount[\s\S]*floatingCount[\s\S]*duplicateStatus/u);
});

test("release assembly preserves helper ACL identity while pinning the exact service", async () => {
  const [build, release, verifier, liveVerifier, processMonitor, launcher, app, plist, entitlements, packageManifest] = await Promise.all([
    readFile(join(root, "scripts/build-app.sh"), "utf8"),
    readFile(join(root, "scripts/verify-release.sh"), "utf8"),
    readFile(join(root, "scripts/verify-credential-migration-xpc.sh"), "utf8"),
    readFile(join(root, "scripts/verify-credential-migration-xpc-live.sh"), "utf8"),
    readFile(join(root, "scripts/credential-xpc-live-process-monitor.mjs"), "utf8"),
    readFile(join(root, "Sources/LocalHarness/CredentialMigrationXPCAcceptanceLaunch.swift"), "utf8"),
    readFile(join(root, "Sources/LocalHarness/LocalHarnessApp.swift"), "utf8"),
    readFile(join(root, "Resources/CredentialMigrationService-Info.plist"), "utf8"),
    readFile(join(root, "Resources/CredentialMigrationService.entitlements"), "utf8"),
    readFile(join(root, "Package.swift"), "utf8")
  ]);

  assert.match(packageManifest, /name: "LocalHarnessCredentialMigrationService"/u);
  assert.match(build, /XPC_SERVICES_DIR="\$CONTENTS_DIR\/XPCServices"/u);
  assert.match(build, /MIGRATION_XPC_DIR="\$XPC_SERVICES_DIR\/LocalHarnessCredentialMigrationService\.xpc"/u);
  assert.match(build, /--identifier "\$PRODUCT_BUNDLE_ID\.credential-helper"[\s\S]*CredentialMigrationService\.entitlements/u);
  assert.match(release, /HELPER_DESIGNATED_REQUIREMENT[\s\S]*SERVICE_DESIGNATED_REQUIREMENT/u);
  assert.match(release, /verify-credential-migration-xpc\.sh/u);
  assert.match(release, /verify-credential-migration-xpc-live\.sh/u);
  assert.match(verifier, /_posix_spawn[\s\S]*_execve[\s\S]*_system/u);
  assert.match(verifier, /actual-entitlements[\s\S]*CredentialMigrationService\.entitlements/u);
  assert.match(liveVerifier, /--credential-migration-xpc-acceptance/u);
  assert.match(liveVerifier, /TIMEOUT_SECONDS=15/u);
  assert.match(liveVerifier, /FULMAR_CREDENTIAL_XPC_ACCEPTANCE_OK/u);
  assert.match(liveVerifier, /credential-xpc-live-process-monitor\.mjs/u);
  assert.match(liveVerifier, /service\.evidence/u);
  assert.match(liveVerifier, /ROOT_IDENTITY/u);
  assert.match(processMonitor, /proc|lsof/u);
  assert.match(processMonitor, /sameIdentity/u);
  assert.match(processMonitor, /exactTextIdentity/u);
  assert.match(processMonitor, /reviewedCDHash/u);
  assert.match(processMonitor, /process\.kill\(identity\.pid, signal\)/u);
  assert.doesNotMatch(processMonitor, /pkill|killall|pgrep/u);
  verifyMonitorCompletionHandling(processMonitor);
  assert.match(launcher, /arguments\.count == 2/u);
  assert.match(launcher, /genericFailure/u);
  assert.match(launcher, /CredentialMigrationXPCAcceptanceCoordinator\.run/u);
  assert.match(
    app,
    /static func main\(\) \{\s*if let status = CredentialMigrationXPCAcceptanceLaunch\.runIfRequested/u
  );
  assert.doesNotMatch(liveVerifier, /DEEPSEEK_API_KEY|OLLAMA_API_KEY|app\.localharness\.credentials/u);
  assert.match(plist, /<string>com\.angadjairath\.localharness\.credential-helper<\/string>/u);
  assert.match(plist, /<string>XPC!<\/string>/u);
  assert.match(entitlements, /com\.apple\.security\.app-sandbox[\s\S]*<true\/>/u);
  assert.match(
    entitlements,
    /com\.apple\.security\.temporary-exception\.files\.home-relative-path\.read-write[\s\S]*\/Library\/Application Support\/Local Harness\/CredentialMetadata\//u
  );
  assert.doesNotMatch(entitlements, /network\.client|network\.server|files\.user-selected/u);
  await verifyCandidateAdmission(verifier);
});
