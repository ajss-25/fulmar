import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

const root = process.cwd();

test("every unattended backup-key path has both per-query and process-wide no-UI barriers", async () => {
  const helper = await readFile(join(root, "Tools", "CredentialHelper", "main.swift"), "utf8");
  assert.match(helper, /backupAuthenticationService\s*=\s*"com\.angadjairath\.localharness\.backup-authentication"/u);
  assert.match(helper, /backupAuthenticationAccount\s*=\s*"state-backup-manifest-v2"/u);
  assert.match(helper, /private func nonInteractiveBackupAuthenticationQuery\(\)[\s\S]*?LAContext\(\)[\s\S]*?interactionNotAllowed\s*=\s*true/u);
  assert.match(helper, /setKeychainInteraction\(0\)[\s\S]*?command == "backup-load-or-create"[\s\S]*?runBackupAuthenticationKeyLoadOrCreate/u);
  assert.match(helper, /added == errSecDuplicateItem[\s\S]*?lookupBackupAuthenticationKey\(nonInteractive: true\)/u);

  // Reject an unrelated immediate parent before walking the entire signed
  // bundle. Cold nested-code validation can exhaust the no-UI deadline even
  // though that caller can never be authorized. Accepted parents still take
  // the complete static/running-code checks and the final parent recheck.
  const parentAdmissionStart = helper.indexOf("private func exactPackagedApplicationIsImmediateParent()");
  const parentAdmissionEnd = helper.indexOf("private func matches(", parentAdmissionStart);
  assert.ok(parentAdmissionStart >= 0 && parentAdmissionEnd > parentAdmissionStart);
  const parentAdmission = helper.slice(parentAdmissionStart, parentAdmissionEnd);
  const parentPathCheck = parentAdmission.indexOf("proc_pidpath(candidateParent");
  const staticCodeCreation = parentAdmission.indexOf("SecStaticCodeCreateWithPath(");
  assert.ok(parentPathCheck >= 0 && staticCodeCreation > parentPathCheck,
    "an unrelated parent must be rejected before expensive whole-bundle signature validation");
  assert.match(parentAdmission, /proc_pidpath\(candidateParent[\s\S]*?\.resolvingSymlinksInPath\(\)\.standardizedFileURL == applicationExecutable else \{\s*return false\s*\}/u);
  assert.ok(parentAdmission.indexOf("proc_pidpath(parent") > staticCodeCreation,
    "the original late parent-path recheck must remain after static validation");
  assert.match(parentAdmission, /guard parent > 1, parent == candidateParent else \{ return false \}/u);
  assert.match(parentAdmission, /proc_pidpath\(parent[\s\S]*?\.resolvingSymlinksInPath\(\)\.standardizedFileURL == applicationExecutable else \{\s*return false\s*\}/u);
  assert.match(parentAdmission, /kSecCSCheckAllArchitectures \| kSecCSStrictValidate \| kSecCSCheckNestedCode/u);
  assert.match(parentAdmission, /SecCodeCheckValidity\([\s\S]*?exactRequirement[\s\S]*?getppid\(\) == parent/u);
  assert.match(parentAdmission, /SecStaticCodeCheckValidity\(staticCode, staticFlags, exactRequirement\) == errSecSuccess/u);

  // The foreground authorization and every cold-start backup read must use
  // the same helper identity. Dispatching the latter through the XPC service
  // selects a different Keychain reader even when the helper was approved.
  // This is deterministic native-only routing, never a fallback after denial.
  const entrypoint = helper.slice(helper.indexOf("let arguments = CommandLine.arguments"));
  const backupAdmission = entrypoint.slice(0, entrypoint.indexOf('if command == "backup-authorize-existing"'))
    .replace(/^\s*\/\/[^\n]*$/gmu, "");
  assert.match(backupAdmission, /let nativeBackupCommand = command == "backup-load-or-create"\s*\|\| command == "backup-read-existing"/u);
  assert.match(backupAdmission, /if nativeBackupCommand \{\s*guard arguments\.count == 2 else \{ fail\("native backup-key commands take no subject"\) \}\s*guard exactPackagedApplicationIsImmediateParent\(\) else \{\s*fail\("native backup-key access is unavailable"\)\s*\}\s*\} else \{\s*dispatchCredentialBrokerCommandIfNeeded\(command: command, arguments: arguments\)\s*\}/u);
  assert.doesNotMatch(backupAdmission, /runBackupAuthenticationKey|lookupBackupAuthenticationKey|SecItem|setKeychainInteraction/u);
  assert.equal((entrypoint.match(/dispatchCredentialBrokerCommandIfNeeded\(/gu) ?? []).length, 1,
    "a denied native backup reader must not be retried through another identity");
  assert.match(entrypoint, /setKeychainInteraction\(0\)[\s\S]*?if command == "backup-read-existing"[\s\S]*?runBackupAuthenticationKeyReadExisting\(\)/u);

  const loadOrCreateStart = helper.indexOf("private func runBackupAuthenticationKeyLoadOrCreate()");
  const foregroundStart = helper.indexOf("private func runBackupAuthenticationKeyForegroundAuthorization()");
  assert.ok(loadOrCreateStart >= 0 && foregroundStart > loadOrCreateStart);
  const unattendedBody = helper.slice(loadOrCreateStart, foregroundStart);
  assert.doesNotMatch(unattendedBody, /SecItemUpdate|SecItemDelete/u);
  assert.match(unattendedBody, /duplicate-race read/u);

  const describeStart = helper.indexOf('case "describe", "describe-record":');
  const setStart = helper.indexOf('case "set", "set-record":', describeStart);
  assert.ok(describeStart >= 0 && setStart > describeStart);
  const describeBody = helper.slice(describeStart, setStart);
  assert.match(describeBody, /coordinator\.metadata\(account: keychainAccount\)/u);
  assert.doesNotMatch(describeBody, /readConfiguredValue|SecItemCopyMatching/u);
  assert.match(describeBody, /metadata\.kind == "api-key"[\s\S]*metadata\.kind == "grant"/u);
  assert.match(describeBody, /metadata\.kind == "reference"/u);

  const broker = await readFile(join(root, "Tools", "CredentialBrokerService", "main.swift"), "utf8");
  const brokerDescribeStart = broker.indexOf("case .describe, .describeRecord:", broker.indexOf("switch request.operation {"));
  const brokerSetStart = broker.indexOf("case .set, .setRecord:", brokerDescribeStart);
  assert.ok(brokerDescribeStart >= 0 && brokerSetStart > brokerDescribeStart);
  const brokerDescribeBody = broker.slice(brokerDescribeStart, brokerSetStart);
  assert.match(brokerDescribeBody, /let metadata = try transaction\.metadata\(account: account\)/u);
  assert.doesNotMatch(brokerDescribeBody, /readConfiguredValue|SecItemCopyMatching|try\?/u);
  assert.match(brokerDescribeBody, /request\.operation == \.describeRecord\s*\? metadata\.kind == "api-key" \|\| metadata\.kind == "grant"\s*: metadata\.kind == "reference"/u);
  assert.match(brokerDescribeBody, /guard validKind else \{ throw BrokerError\.unsafeState \}/u);
  assert.match(brokerDescribeBody, /configured: metadata != nil/u);
  assert.match(brokerDescribeBody, /payload: Data\(\)/u);
});

test("the unattended-access probe is a read-existing command that can never create a key", async () => {
  const [helper, broker, protocolSource, brokerClient, client, manager] = await Promise.all([
    readFile(join(root, "Tools", "CredentialHelper", "main.swift"), "utf8"),
    readFile(join(root, "Tools", "CredentialBrokerService", "main.swift"), "utf8"),
    readFile(join(root, "Sources", "CredentialBrokerXPCProtocol", "CredentialBrokerXPCProtocol.swift"), "utf8"),
    readFile(join(root, "Tools", "CredentialHelper", "CredentialBrokerClient.swift"), "utf8"),
    readFile(join(root, "Sources", "LocalHarness", "StateBackupAuthenticationKeyClient.swift"), "utf8"),
    readFile(join(root, "Sources", "LocalHarness", "StateBackupManager.swift"), "utf8")
  ]);

  // The probe the window and startup paths use is the read-only command, never
  // the create-capable one: a probe that minted a replacement key would
  // silently invalidate every existing authenticated backup.
  const verify = client.slice(
    client.indexOf("func verifyUnattendedAccess(matching key: Data)"),
    client.indexOf("func admitValidatedKey(")
  );
  assert.ok(verify.length > 0);
  assert.match(verify, /run\(command: "backup-read-existing"/u);
  assert.doesNotMatch(verify, /backup-load-or-create|backup-authorize-existing/u);
  // A read-only probe that finds nothing reports unavailable rather than
  // falling through to creation.
  assert.match(client, /result\.exitStatus == 3[\s\S]*?BackupError\.authenticationKeyMissing/u);
  assert.match(manager, /case authenticationKeyMissing/u);
  assert.match(manager, /No key was created, replaced or deleted\./u);

  // Helper: the read-existing body performs one noninteractive lookup and no
  // mutation of any kind, and it is dispatched only after the process-wide
  // no-UI barrier is in force.
  const readExistingStart = helper.indexOf("private func runBackupAuthenticationKeyReadExisting()");
  const readExistingEnd = helper.indexOf("private func runBackupAuthenticationKeyForegroundAuthorization()");
  assert.ok(readExistingStart >= 0 && readExistingEnd > readExistingStart);
  const readExistingBody = helper.slice(readExistingStart, readExistingEnd);
  assert.match(readExistingBody, /lookupBackupAuthenticationKey\(nonInteractive: true\)/u);
  assert.match(readExistingBody, /existing\.status == errSecItemNotFound \{ exit\(3\) \}/u);
  assert.doesNotMatch(readExistingBody, /SecItemAdd|SecItemUpdate|SecItemDelete/u);
  assert.ok(helper.indexOf("setKeychainInteraction(0)") < helper.indexOf('if command == "backup-read-existing"'));

  // Broker: the read-existing operation is a plain read that returns nothing
  // when the item is absent, with no create, replace or delete path.
  const brokerReadStart = broker.indexOf("private func backupReadExisting()");
  assert.ok(brokerReadStart >= 0);
  const brokerReadBody = broker.slice(brokerReadStart, broker.indexOf("\n}", brokerReadStart));
  assert.match(brokerReadBody, /try keychainRead\([\s\S]*?service: backupAuthenticationService/u);
  assert.doesNotMatch(brokerReadBody, /SecItemAdd|SecItemUpdate|SecItemDelete|keychainWrite|keychainDelete/u);
  assert.match(protocolSource, /case backupReadExisting/u);
  assert.match(brokerClient, /case "backup-read-existing":\s*(?:return\s*)?\.backupReadExisting/u);
});

test("foreground authorization is explicit, read-only, bounded, and validated before caching", async () => {
  const [helper, client, manager, window, app] = await Promise.all([
    readFile(join(root, "Tools", "CredentialHelper", "main.swift"), "utf8"),
    readFile(join(root, "Sources", "LocalHarness", "StateBackupAuthenticationKeyClient.swift"), "utf8"),
    readFile(join(root, "Sources", "LocalHarness", "StateBackupManager.swift"), "utf8"),
    readFile(join(root, "Sources", "LocalHarness", "SecurityWindows.swift"), "utf8"),
    readFile(join(root, "Sources", "LocalHarness", "LocalHarnessApp.swift"), "utf8")
  ]);

  const foregroundFunction = helper.slice(
    helper.indexOf("private func runBackupAuthenticationKeyForegroundAuthorization()"),
    helper.indexOf("private func credentialMetadataDirectory")
  );
  assert.match(foregroundFunction, /lookupBackupAuthenticationKey\(nonInteractive: false\)/u);
  assert.doesNotMatch(foregroundFunction, /SecItemAdd|SecItemUpdate|SecItemDelete/u);
  assert.ok(helper.indexOf('command == "backup-authorize-existing"') < helper.indexOf("setKeychainInteraction(0)"));

  assert.match(client, /unattendedDeadline:\s*TimeInterval\s*=\s*3/u);
  assert.match(client, /foregroundAuthorizationDeadline:\s*TimeInterval\s*=\s*120/u);
  assert.match(client, /BoundedCredentialMigrationProcess\.run/u);
  assert.match(client, /case \.deadline[\s\S]*?BackupError\.authenticationTimedOut/u);
  assert.match(client, /result\.exitStatus == 5[\s\S]*?BackupError\.authenticationAuthorizationRequired/u);

  const authorizeManager = manager.slice(
    manager.indexOf("func authorizeAuthenticationKeyForForeground("),
    manager.indexOf("func authorizeAuthenticationKeyForForegroundAsync(")
  );
  assert.match(authorizeManager, /loadBackups\(key: key/u);
  assert.ok(authorizeManager.indexOf("loadBackups(key: key") < authorizeManager.indexOf("admitValidatedKey(candidate)"));
  assert.doesNotMatch(authorizeManager, /removeItem|SecItemDelete|SecItemUpdate/u);

  assert.match(window, /Authorize Backup Key…/u);
  assert.match(window, /Authorize Existing Key/u);
  assert.match(window, /will not replace or delete any Keychain item/u);
  assert.match(app, /Backup-key authorization is required/u);
  assert.match(app, /Keep Runtime Stopped/u);
  assert.match(app, /Backup key needs foreground attention/u);
  assert.match(app, /Background schedules remained stopped/u);
});

test("pre-controller credential paths pin the exact bundle components around execution", async () => {
  const [backup, migration] = await Promise.all([
    readFile(join(root, "Sources", "LocalHarness", "StateBackupAuthenticationKeyClient.swift"), "utf8"),
    readFile(join(root, "Sources", "LocalHarness", "CredentialMigrationManager.swift"), "utf8")
  ]);

  for (const source of [backup, migration]) {
    assert.match(source, /import CryptoKit/u);
    assert.match(source, /BundleIntegrityVerifier\.verify/u);
    assert.match(source, /lstat\(/u);
    assert.match(source, /st_mode\s*&\s*0o022\s*==\s*0/u);
    assert.match(source, /st_dev/u);
    assert.match(source, /st_ino/u);
    assert.match(source, /SHA256\.hash/u);
    const process = source.indexOf("result = try processRunner(");
    assert.ok(process > 0);
    assert.ok(source.indexOf("try revalidate(pinned)") < process);
    assert.ok(source.lastIndexOf("try revalidate(pinned)") > process);
  }

  assert.match(backup, /helper\.lastPathComponent == "LocalHarnessCredentialHelper"/u);
  assert.match(backup, /guard Bundle\.main\.bundleURL\.pathExtension != "app"/u);
  assert.match(migration, /requiredExecutableDirectory/u);
  assert.match(migration, /requiredResourceDirectory/u);
  assert.match(migration, /Runtime\/dsh\/node_modules\/yaml\/dist\/index\.js/u);
  assert.match(migration, /guard Bundle\.main\.bundleURL\.pathExtension != "app"/u);
});

test("the signer-change canary rejects unauthorized packaged backup access without probing the production key", async () => {
  const canary = await readFile(join(root, "Scripts", "verify-keychain-no-ui-transition.mjs"), "utf8");
  assert.match(canary, /const historicalHelper = process\.argv\[3\]/u);
  assert.match(canary, /assert\.notEqual\(historicalHelper, helper/u);
  assert.match(canary, /copyFile\(historicalHelper, legacy\)/u);
  assert.doesNotMatch(canary, /copyFile\(helper, legacy\)/u);
  assert.ok(canary.includes('const packagedHelper = /\\/[^/]+\\.app\\/Contents\\/MacOS\\/LocalHarnessCredentialHelper$/u.test(helper);'));
  assert.match(canary, /if \(packagedHelper\) \{\s*for \(const command of \["backup-load-or-create", "backup-read-existing"\]\) \{\s*const deniedBackupAccess = await run\(helper, \[command\]\)/u);
  assert.match(canary, /assert\.equal\(deniedBackupAccess\.signal, null\)/u);
  assert.match(canary, /deniedBackupAccess\.elapsedMilliseconds < 2_500/u);
  assert.match(canary, /assert\.equal\(deniedBackupAccess\.status, 2,/u);
  assert.match(canary, /assert\.equal\(deniedBackupAccess\.stdout\.length, 0,/u);
  assert.ok(canary.includes('assert.equal(deniedBackupAccess.stderr.toString("utf8"), "Credential helper: native backup-key access is unavailable\\n");'));
  assert.doesNotMatch(canary, /run\((?:helper|legacy), \["backup-/u);
  assert.doesNotMatch(canary, /currentBackupKey|changedSignatureBackupRead|retainedBackupKey/u);
  assert.match(canary, /unauthorized-access test, not live backup-key qualification/u);
  assert.match(canary, /Packaged backup parent rejection was not exercised by this standalone helper fixture/u);
  assert.match(canary, /app-owned backup reads and relaunch require separate live qualification/u);
  assert.match(canary, /run\(legacy, \["set", reference\], secret\)/u);
  assert.match(canary, /run\(helper, \["set", reference\], replacement\)/u);
  assert.match(canary, /a denied replacement mutated the existing credential/u);
  assert.match(canary, /the metadata-less credential was not atomically adopted and replaced/u);
  assert.doesNotMatch(canary, /backup-(?:unset|delete)/u);
});
