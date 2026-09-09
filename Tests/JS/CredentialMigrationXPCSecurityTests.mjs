import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, readdir, realpath, rename, rm, symlink, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { runInNewContext } from "node:vm";
import { rootWatchdogChildOptions } from "./RootWatchdogChildProcess.mjs";

const root = process.cwd();

async function verifyMigrationPhaseDiagnostics(liveVerifier, migrationService) {
  const shell = liveVerifier, swift = migrationService, project = root;
  const body = /\n(import \{ spawnSync \} from "node:child_process";[\s\S]*?)\nFULMAR_MIGRATION_PHASE_DIAGNOSTIC\n/u.exec(shell)?.[1];
  assert.ok(body);
  const transformed = body.replace(/^import .*;\n/gmu, "")
    .replace('const { readAttestedRegularFileSync } = await import(pathToFileURL(join(project, "scripts/attested-regular-file.mjs")));',
      "const { readAttestedRegularFileSync } = fixture;");
  assert.ok(!transformed.includes("await import("));
  const fixtureRoot = "/private/tmp/fulmar-credential-xpc-live.phase-fixture";
  const executable = "/private/tmp/Fixture.app/Contents/XPCServices/LocalHarnessCredentialMigrationService.xpc/Contents/MacOS/LocalHarnessCredentialMigrationService";
  const fixtureNow = Date.UTC(2026, 8, 9, 18, 0, 8);
  const start = (fixtureNow / 1_000) - 8;
  const end = (fixtureNow / 1_000) - 1;
  const phaseLabels = [...swift.matchAll(/^    case \w+ = "([a-z-]+)"$/gmu)]
    .map(match => match[1]);
  assert.equal(phaseLabels.length, 16);
  const record = phase => ({ eventType: "logEvent", processID: 4321, processImagePath: executable,
    subsystem: "com.angadjairath.localharness.migration-diagnostic", category: "xpc-phase",
    timestamp: "2026-09-09 18:00:02.123456+0000", eventMessage: phase });
  const outcomes = [];
  for (const scenario of ["complete", "empty", "wrong-pid", "wrong-path", "wrong-subsystem", "wrong-category",
    "unknown-label", "wrong-time", "wrong-schema", "invalid-json", "log-timeout", "log-stderr",
    "oversize-log", "monitor-failed", "monitor-stderr", "done-mismatch", "invalid-evidence",
    "wrong-file-mode", "unsafe-root", "stale-window", "date-failed", "unsafe-executable", "expired-budget", "late-log-budget"]) {
    let output = "", queries = 0, fixtureClock = fixtureNow;
    const evidence = "pid=4321\nstarted=Wed Sep  9 18:00:00 2026\ncdhash=" + "a".repeat(40) + "\n";
    const rows = phaseLabels.map(record);
    if (scenario === "wrong-pid") rows[0].processID = 9876;
    if (scenario === "wrong-path") rows[0].processImagePath += ".other";
    if (scenario === "wrong-subsystem") rows[0].subsystem = "unrelated";
    if (scenario === "wrong-category") rows[0].category = "unrelated";
    if (scenario === "unknown-label") rows[0].eventMessage = "PRIVATE_FIXTURE_MUST_NOT_LEAK";
    if (scenario === "wrong-time") rows[0].timestamp = "2026-09-09 17:59:59.999999+0000";
    if (scenario === "wrong-schema") delete rows[0].processID;
    const files = new Map([
      ["monitor.stdout", scenario === "monitor-failed" ? "not-pass\n" : "FULMAR_CREDENTIAL_XPC_PROCESS_DRAIN_OK\n"],
      ["monitor.stderr", scenario === "monitor-stderr" ? "PRIVATE_FIXTURE_MUST_NOT_LEAK" : ""],
      ["client.done", scenario === "done-mismatch" ? "nope\n" : "done\n"],
      ["service.evidence", scenario === "invalid-evidence" ? "pid=OTHER\n" : evidence]
    ]);
    const fixture = { readAttestedRegularFileSync(path, options) {
      assert.equal(options.requireCurrentUser, true);
      assert.equal(options.requirePrivateMode, true);
      assert.equal(options.requireSingleLink, true);
      assert.equal(options.requireCanonicalPath, true);
      const bytes = Buffer.from(files.get(path.slice(fixtureRoot.length + 1)));
      if (bytes.length < options.minimumBytes || bytes.length > options.maximumBytes) throw 0;
      return { bytes, metadata: { mode: scenario === "wrong-file-mode" ? 0o640n : 0o600n } };
    } };
    const context = {
      fixture, Buffer, Number, JSON, Set, Math, createHash, join,
      Date: class extends Date { static now() { return fixtureClock; } },
      process: { argv: ["node", "-", project, fixtureRoot, "1:2:501:700",
        scenario === "unsafe-executable" ? executable + '"' : executable,
        String(scenario === "stale-window" ? start - 60 : start), String(end),
        String(scenario === "expired-budget" ? fixtureNow : fixtureNow + 4_000)],
        getuid: () => 501, stdout: { write: text => { output += text; } } },
      lstatSync: () => ({ isDirectory: () => true, isSymbolicLink: () => false,
        uid: 501, mode: scenario === "unsafe-root" ? 0o755 : 0o700, dev: 1, ino: 2 }),
      realpathSync: value => value,
      spawnSync(command, argumentsList, options) {
        assert.equal(options.killSignal, "SIGKILL");
        if (command === "/bin/date") {
          assert.equal(options.timeout, 500);
          if (scenario === "late-log-budget") fixtureClock += 3_500;
          return { status: scenario === "date-failed" ? 1 : 0, signal: null, stdout: String(start) + "\n", stderr: "" };
        }
        assert.equal(command, "/usr/bin/log");
        assert.equal(options.timeout, scenario === "late-log-budget" ? 250 : 2_000);
        assert.equal(options.maxBuffer, 128 * 1_024);
        assert.ok(argumentsList.includes(`@${start}`) && argumentsList.includes(`@${end + 1}`));
        assert.ok(argumentsList.at(-1).includes(`processIdentifier == 4321 AND processImagePath == "${executable}"`));
        queries += 1;
        return { status: scenario === "log-timeout" ? null : 0,
          signal: scenario === "log-timeout" ? "SIGKILL" : null,
          stderr: scenario === "log-stderr" ? "PRIVATE_FIXTURE_MUST_NOT_LEAK" : "",
          stdout: scenario === "oversize-log" ? "x".repeat(128 * 1_024 + 1)
            : scenario === "invalid-json" ? "not-json" : JSON.stringify(scenario === "empty" ? [] : rows) };
      }
    };
    await runInNewContext(`(async () => { ${transformed}\n })()`, context, { timeout: 1_000 });
    assert.ok(!output.includes("PRIVATE_FIXTURE") && !output.includes(executable) && !output.includes("4321"));
    if (["complete", "empty", "late-log-budget"].includes(scenario)) {
      assert.match(output, /^FULMAR_CREDENTIAL_XPC_PHASE_EVIDENCE_SHA256=[a-f0-9]{64}\n/u);
      assert.ok(output.includes("historical-correlation-only"));
      assert.equal(output.split("FULMAR_CREDENTIAL_XPC_PHASE=").length - 1, scenario === "empty" ? 0 : 16);
    } else assert.equal(output, "FULMAR_CREDENTIAL_XPC_PHASE_DIAGNOSTIC=unavailable\n", scenario);
    assert.ok(queries <= 1);
    outcomes.push({ scenario, passed: true, queries });
  }
}

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
  // Diagnostic-only phase telemetry must not become another acceptance channel.
  const migrationService = await readFile(join(root, "Tools/CredentialMigrationService/main.swift"), "utf8");
  assert.match(migrationService, /private enum MigrationDiagnosticPhase: String/u);
  assert.match(migrationService, /migrationDiagnosticLog\.notice\("\\\(phase\.rawValue, privacy: \.public\)"\)/u);
  assert.match(migrationService, /recordMigrationPhase\(\.serviceStartup\)[\s\S]*private let listenerDelegate/u);
  for (const [phase, argument, nested] of [["service", "serviceBundle", "false"], ["helper", "helper", "false"], ["application", "application", "true"]]) {
    const before = `recordMigrationPhase(.${phase}ValidationEntered)`;
    const inspection = `MigrationCodeIdentity.inspect(${argument}, nested: ${nested})`;
    const after = `recordMigrationPhase(.${phase}ValidationReturned)`;
    for (const marker of [before, inspection, after]) assert.equal(migrationService.split(marker).length, 2);
    assert.ok(migrationService.indexOf(before) < migrationService.indexOf(inspection));
    assert.ok(migrationService.indexOf(inspection) < migrationService.indexOf(after));
  }
  assert.match(migrationService, /recordMigrationPhase\(\.requestEntered\)\s+guard admission\.begin\(\)/u);
  assert.match(migrationService, /recordMigrationPhase\(\.connectionEntered\)\s+connection\.setCodeSigningRequirement\(exactApplicationRequirement\)/u);
  assert.match(migrationService, /recordMigrationPhase\(\.acceptanceMetadataEntered\)\s+try runAcceptanceMetadataCanary\(nonce: request\.acceptanceNonce\)\s+recordMigrationPhase\(\.acceptanceMetadataReturned\)/u);
  assert.match(migrationService, /if diagnosticAcceptance \{ recordMigrationPhase\(\.acceptanceReplyInvoked\) \}\s+reply\(encode\(response\)\)\s+if diagnosticAcceptance \{ recordMigrationPhase\(\.acceptanceReplyReturned\) \}/u);
  assert.match(liveVerifier, /CLIENT_CONTRACT:-.*failed.*MONITOR_STATUS:-.*0/u);
  assert.match(liveVerifier, /collect_migration_phase_diagnostics \|\| true/u);
  assert.match(liveVerifier, /readAttestedRegularFileSync[\s\S]*requireSingleLink: true, requireCanonicalPath: true/u);
  assert.match(liveVerifier, /timeout: remainingSpawnBudget\(2_000\), killSignal: "SIGKILL", maxBuffer: 128 \* 1_024/u);
  assert.match(liveVerifier, /run-with-watchdog\.sh" --inherit-root[\s\S]*--seconds 5 --max-rss-bytes 34359738368 --rss-grace-seconds 10[\s\S]*--emergency-rss-bytes 38654705664/u);
  assert.match(liveVerifier, /if zmodload zsh\/datetime 2>\/dev\/null; then/u);
  assert.doesNotMatch(liveVerifier, /\$\(\/bin\/date \+%s/u);
  assert.match(liveVerifier, /record\.processID !== Number\(match\[1\]\)[\s\S]*record\.processImagePath !== executable/u);
  assert.match(liveVerifier, /historical-correlation-only/u);
  assert.doesNotMatch(liveVerifier, /console\.(?:log|error)\(query|process\.(?:stdout|stderr)\.write\(query/u);
  await verifyMigrationPhaseDiagnostics(liveVerifier, migrationService);
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
