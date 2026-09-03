import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

const root = process.cwd();

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
});
