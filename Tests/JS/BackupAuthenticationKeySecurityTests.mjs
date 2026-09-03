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

test("the real-Keychain signer-change canary preserves the exact production backup key", async () => {
  const canary = await readFile(join(root, "Scripts", "verify-keychain-no-ui-transition.mjs"), "utf8");
  assert.match(canary, /helper, \["backup-load-or-create"\]/u);
  assert.match(canary, /legacy, \["backup-load-or-create"\]/u);
  assert.match(canary, /changed-signature backup read waited for authorization UI/u);
  assert.match(canary, /changed-signature probing mutated the backup key/u);
  assert.doesNotMatch(canary, /backup-(?:unset|delete)/u);
});
