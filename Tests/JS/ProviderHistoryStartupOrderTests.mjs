import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const app = new URL('../../Sources/LocalHarness/LocalHarnessApp.swift', import.meta.url);
const controller = new URL('../../Sources/LocalHarness/HarnessController.swift', import.meta.url);

test('provider history startup gate orders opaque roots before component readers', async () => {
  const source = await readFile(app, 'utf8');
  const start = source.indexOf('private func beginProviderHistoryStartupGate(');
  const end = source.indexOf('private func presentDeviceAttestationTrustRecovery(', start);
  assert.ok(start >= 0 && end > start, 'startup gate was not found');
  const gate = source.slice(start, end);
  const windowsStart = source.indexOf('private func buildWindows()');
  const windowsEnd = source.indexOf('\n    private func ', windowsStart + 20);
  assert.ok(windowsStart >= 0 && windowsEnd > windowsStart, 'window construction was not found');
  const windows = source.slice(windowsStart, windowsEnd);
  assert.doesNotMatch(windows, /BackupWindowController\(manager: backupManager\)|backupWindow\.on/,
    'window construction must not retain a pre-recovery Backups identity');

  const componentsStart = gate.indexOf('private func inspectCurrentAuxiliaryComponents(');
  assert.ok(componentsStart >= 0, 'deferred auxiliary component inspection was not found');
  const opaqueGate = gate.slice(0, componentsStart);
  const components = gate.slice(componentsStart);
  const home = gate.indexOf('preflightHarnessHomeRecoveryForBackgroundSchedule(');
  const auxiliary = gate.indexOf('auxiliary.preflight()');
  const backups = gate.indexOf('backups.privacyEpochPreflight()');
  const migration = gate.indexOf('RuntimeMigrationCoordinator.privacyEpochPreflight(');
  const auxiliaryInvocation = gate.indexOf('if background {', home);
  assert.ok(home >= 0, 'Harness-home preflight is missing');
  assert.ok(auxiliary >= 0 && auxiliaryInvocation > home,
    'auxiliary opaque gate is not invoked from the Harness-home completion');
  assert.ok(backups > auxiliary, 'backup component reader ran before opaque gate');
  assert.ok(migration > backups, 'migration reader ran before backup epoch preflight');
  assert.doesNotMatch(opaqueGate, /let backups = (?:self\.)?backupManager/,
    'opaque preflight captured the shared backup manager before recovery');
  assert.match(opaqueGate, /case \.success\(nil\):\s*self\.inspectCurrentAuxiliaryComponents\(/,
    'component readers are not restricted to the no-pending opaque result');
  assert.ok(components.indexOf('let backups = backupManager') < components.indexOf('backups.privacyEpochPreflight()'),
    'deferred component inspection is not bound to its backup manager');
  assert.match(opaqueGate,
    /presentAuxiliaryRecovery\(pending\)[\s\S]*?guard recovered else[\s\S]*?providerHistoryStartupGateToken = nil[\s\S]*?beginProviderHistoryStartupGate\(background: false, completion: completion\)/,
    'acknowledged recovery must recheck startup before admitting component readers');

  const showStart = source.indexOf('@objc func showBackups(');
  const showEnd = source.indexOf('\n    @objc func ', showStart + 20);
  assert.ok(showStart >= 0 && showEnd > showStart, 'backup presentation was not found');
  const show = source.slice(showStart, showEnd);
  const admitted = show.indexOf('guard providerHistoryStartupAdmitted else');
  const configure = show.indexOf('configureBackupWindow()');
  assert.ok(admitted >= 0 && configure > admitted,
    'backup UI can construct a manager before provider-history admission');

  const newStart = source.indexOf('@objc func newSession(');
  const newEnd = source.indexOf('\n    @objc func goBack(', newStart);
  assert.ok(newStart >= 0 && newEnd > newStart, 'new-session action was not found');
  const newSession = source.slice(newStart, newEnd);
  assert.doesNotMatch(newSession, /captureBeforeTurn|Creating workspace checkpoint/,
    'opening an empty conversation must not perform a redundant workspace checkpoint');
  assert.match(newSession, /guard mainSessionCanStart else/);
  assert.match(newSession, /mainWindow\.surface\.startNewSession\(\)/);

  const turnStart = source.indexOf('prepareTurnIn sessionID:');
  const turnEnd = source.indexOf('\n    func ', turnStart + 20);
  assert.ok(turnStart >= 0 && turnEnd > turnStart, 'actual agent-turn admission was not found');
  const turn = source.slice(turnStart, turnEnd);
  const authoritative = turn.indexOf('models.routable');
  const checkpoint = turn.indexOf('coordinator.captureBeforeTurn(');
  const admit = turn.indexOf('finish(.success(TurnPreparationBridgeResult(');
  assert.ok(authoritative >= 0 && checkpoint > authoritative && admit > checkpoint,
    'actual agent turns must still validate the session/model then checkpoint before admission');
});

test('retention and credential startup remain behind the provider-history gate', async () => {
  const source = await readFile(app, 'utf8');
  const launch = source.indexOf('beginProviderHistoryStartupGate(background: false)');
  const maintenance = source.indexOf('self.runStartupPrivacyMaintenance', launch);
  const protectedStartup = source.indexOf('self?.beginProtectedStartup()', maintenance);
  const credentials = source.indexOf('switch credentialMigration.startupRequirement', protectedStartup);
  assert.ok(launch >= 0 && maintenance > launch, 'retention is not gated by provider history');
  assert.ok(protectedStartup > maintenance, 'protected startup bypasses retention completion');
  assert.ok(credentials > protectedStartup, 'credential admission precedes protected startup');
});

test('runtime launch revalidates the retained home capability before sandboxed execution', async () => {
  const source = await readFile(controller, 'utf8');
  const start = source.indexOf('private func commitHarnessLaunch(');
  const end = source.indexOf('\n    private func ', start + 20);
  assert.ok(start >= 0 && end > start, 'commitHarnessLaunch was not found');
  const commit = source.slice(start, end);
  const vault = commit.indexOf('harnessHomeAdmissionVault.snapshot()');
  const revalidate = commit.indexOf('HarnessHomeAttestationStore.revalidateCapability(');
  const wrapped = commit.indexOf('runtimeWriteSandbox.wrappedLaunch(');
  const run = commit.indexOf('try process.run()');
  assert.ok(vault >= 0 && revalidate > vault, 'capability generation is not revalidated');
  assert.ok(wrapped > revalidate, 'sandbox wrapper is prepared before capability revalidation');
  assert.ok(run > wrapped, 'raw process launch bypasses sandbox wrapping');
});

test('Application Support identity is retained before any child store or startup gate', async () => {
  const appSource = await readFile(app, 'utf8');
  const launchStart = appSource.indexOf('func applicationDidFinishLaunching(');
  const launchEnd = appSource.indexOf('\n    func applicationShouldTerminateAfterLastWindowClosed', launchStart);
  assert.ok(launchStart >= 0 && launchEnd > launchStart, 'application launch method was not found');
  const launch = appSource.slice(launchStart, launchEnd);
  const acceptanceReturn = launch.indexOf('headlessHandoffAcceptanceMode = true');
  const admission = launch.indexOf('controller.admitApplicationSupportRoot()');
  const background = launch.indexOf('if CommandLine.arguments.contains("--background-schedule")');
  const windows = launch.indexOf('buildWindows()');
  const providerHistory = launch.indexOf('beginProviderHistoryStartupGate(background: false)');
  assert.ok(admission > acceptanceReturn,
    'the no-state headless acceptance branch no longer returns before admission');
  assert.ok(background > admission, 'background startup can construct child stores before admission');
  assert.ok(windows > admission, 'window construction can construct child stores before admission');
  assert.ok(providerHistory > windows, 'provider-history gate location unexpectedly changed');

  const controllerSource = await readFile(controller, 'utf8');
  const diagnosticsStart = controllerSource.indexOf('func diagnosticsDirectory()');
  const diagnosticsEnd = controllerSource.indexOf('\n    func harnessHomeDirectory()', diagnosticsStart);
  assert.ok(diagnosticsStart >= 0 && diagnosticsEnd > diagnosticsStart,
    'diagnosticsDirectory was not found');
  const diagnostics = controllerSource.slice(diagnosticsStart, diagnosticsEnd);
  assert.match(diagnostics, /admitApplicationSupportRoot\(\)/);
  assert.doesNotMatch(diagnostics, /createDirectory|setAttributes|chmod/,
    'diagnosticsDirectory still mutates an unauthenticated path');

  const failureStart = appSource.indexOf('private func failUnsafeApplicationSupportStartup(');
  const failureEnd = appSource.indexOf('\n    func applicationShouldTerminateAfterLastWindowClosed', failureStart);
  assert.ok(failureStart >= 0 && failureEnd > failureStart, 'typed startup failure handler was not found');
  const failure = appSource.slice(failureStart, failureEnd);
  for (const forbidden of [
    'activityStore', 'privacyLedger', 'notifications', 'diagnosticsDirectory',
    'pluginTrustStore', 'buildWindows', 'beginProviderHistoryStartupGate'
  ]) {
    assert.ok(!failure.includes(forbidden), `failure handler touches ${forbidden}`);
  }
});
