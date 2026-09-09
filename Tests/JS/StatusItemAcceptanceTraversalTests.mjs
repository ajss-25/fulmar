import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const project = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const sourcePath = join(project, "Tools", "StatusItemAcceptance", "main.swift");
const gatePath = join(project, "scripts", "verify-status-item-live.sh");
const releaseLockPath = join(project, "scripts", "release-lock.zsh");
const appSourcePath = join(project, "Sources", "LocalHarness", "LocalHarnessApp.swift");
const acceptanceSupportPath = join(
  project,
  "Sources",
  "LocalHarness",
  "StatusItemAcceptanceSupport.swift"
);
const isolationSourcePath = join(
  project,
  "Sources",
  "LocalHarness",
  "PhysicalHandoffAcceptanceEnvironment.swift"
);
const makefilePath = join(project, "Makefile");
const ollamaSecurityPath = join(project, "Sources", "LocalHarness", "OllamaRuntimeSecurity.swift");
const ollamaLaunchPlanPath = join(project, "Sources", "LocalHarness", "AppOwnedOllamaLaunchPlan.swift");
const harnessControllerPath = join(project, "Sources", "LocalHarness", "HarnessController.swift");

function section(source, start, end) {
  const startIndex = source.indexOf(start);
  const endIndex = source.indexOf(end, startIndex + start.length);
  assert.notEqual(startIndex, -1, `missing section start: ${start}`);
  assert.notEqual(endIndex, -1, `missing section end: ${end}`);
  return source.slice(startIndex, endIndex);
}

test("status-item acceptance never traverses application windows or table hierarchies", async () => {
  const source = await readFile(sourcePath, "utf8");
  assert.doesNotMatch(source, /roots\.isEmpty\s*\?\s*\[application\]/u);

  const statusSearch = section(
    source,
    "private func statusItems(in application: AXUIElement)",
    "private func waitForStatusMenu("
  );
  assert.match(statusSearch, /kAXExtrasMenuBarAttribute/u);
  assert.match(statusSearch, /maximumDepth:\s*1/u);
  assert.match(statusSearch, /maximumCount:\s*16/u);
  assert.match(statusSearch, /childAttributes:\s*\[kAXChildrenAttribute as String\]/u);
  assert.doesNotMatch(statusSearch, /descendants\(of:\s*application/u);
  assert.doesNotMatch(statusSearch, /kAXWindowsAttribute|kAXMenuBarAttribute|kAXShownMenuUIElementAttribute/u);
});

test("normal action acceptance reads only a bounded direct window list", async () => {
  const source = await readFile(sourcePath, "utf8");
  const windowSearch = section(
    source,
    "private func visibleApplicationWindows(in application: AXUIElement)",
    "private func waitForVisibleWindow("
  );
  assert.match(windowSearch, /kAXWindowsAttribute/u);
  assert.match(windowSearch, /maximumCount:\s*16/u);
  assert.match(windowSearch, /kAXWindowRole/u);
  assert.match(windowSearch, /kAXMinimizedAttribute/u);
  assert.doesNotMatch(windowSearch, /descendants\(|kAXChildrenAttribute|kAXRowsAttribute/u);

  const normalRun = section(
    source,
    "func runNormalMenuActions() throws",
    "private func runCycle("
  );
  assert.match(
    normalRun,
    /launchExactTarget\(\s*arguments:\s*\[\],\s*activates:\s*true,\s*protectedCleanup:\s*true\s*\)/u
  );
  assert.match(normalRun, /waitForActivation\(of:\s*running,\s*pid:\s*pid,\s*timeout:\s*10\)/u);
  assert.ok(normalRun.includes(String.raw`"Open \(productName)"`));
  assert.match(normalRun, /expectingWindow:\s*"Chat"/u);
  assert.ok(normalRun.includes(String.raw`expectingWindow: "\(productName) Settings"`));
  assert.doesNotMatch(normalRun, /newSession|HarnessRPC|Ollama|sendPrompt|generationRequest/u);

  const enabledPoll = section(
    source,
    "private func waitForEnabledCoreMenuItems(",
    "private func activateStatusMenuAction("
  );
  assert.match(enabledPoll, /Date\(\)\.addingTimeInterval\(timeout\)/u);
  assert.match(enabledPoll, /disabled\.isEmpty/u);
  assert.match(enabledPoll, /processHasExited\(pid\)/u);

  const foregroundProof = section(
    source,
    "private func waitForVisibleWindow(",
    "private func closeVisibleWindow("
  );
  assert.match(foregroundProof, /StatusItemAcceptanceSupport\.windowNames\(/u);
  assert.match(foregroundProof, /matchExpectedTitle:\s*title/u);
  assert.match(foregroundProof, /productName:\s*productName/u);
  assert.match(foregroundProof, /frameIntersectsVisibleDisplay/u);
  assert.match(foregroundProof, /kAXFocusedWindowAttribute/u);
  assert.match(foregroundProof, /CFEqual\(focused, match\.element\)/u);
  assert.match(foregroundProof, /NSRunningApplication\(processIdentifier:\s*pid\)\?\.isActive\s*==\s*true/u);

  const closeProof = section(
    source,
    "private func closeVisibleWindow(",
    "private func launchExactTarget("
  );
  assert.match(closeProof, /StatusItemAcceptanceSupport\.windowNames\(/u);
  assert.match(closeProof, /matchExpectedTitle:\s*title/u);
  assert.match(closeProof, /productName:\s*productName/u);

  const normalCleanup = section(
    source,
    "private func cleanupNormalLaunchedProcess(pid: pid_t)",
    "private func isExactTargetMainExecutable("
  );
  assert.match(normalCleanup, /running\.terminate\(\)/u);
  assert.match(normalCleanup, /waitForExit\(pid:\s*pid,\s*timeout:\s*45\)/u);
  assert.doesNotMatch(normalCleanup, /Darwin\.kill|_\s*=\s*kill\(/u);
});

test("every live UI gate defers before launch when the console is not an unlocked interactive session", async () => {
  const [source, support, gate] = await Promise.all([
    readFile(sourcePath, "utf8"),
    readFile(acceptanceSupportPath, "utf8"),
    readFile(gatePath, "utf8")
  ]);
  const runs = [
    section(source, "func run() throws", "func runHeadlessForegroundHandoff() throws"),
    section(source, "func runHeadlessForegroundHandoff() throws", "func runPhysicalBackgroundForegroundHandoff() throws"),
    section(source, "func runPhysicalBackgroundForegroundHandoff() throws", "private func createPhysicalHandoffFixture(modelStore: URL)"),
    section(source, "func runNormalMenuActions() throws", "private func runCycle(")
  ];
  for (const run of runs) {
    assert.match(run, /try requireUnlockedInteractiveSession\(\)/u);
  }

  const preflight = section(
    source,
    "private func interactiveSessionObservation()",
    "private func waitForActivation("
  );
  assert.match(preflight, /CGSessionCopyCurrentDictionary\(\)/u);
  assert.match(preflight, /kCGSSessionOnConsoleKey/u);
  assert.match(preflight, /kCGSessionLoginDoneKey/u);
  assert.match(preflight, /kCGSSessionUserIDKey/u);
  assert.match(preflight, /frontmostApplication/u);
  assert.match(preflight, /menuBarOwningApplication/u);
  assert.match(preflight, /AcceptanceError\.environmentallyDeferred/u);
  assert.match(preflight, /Unlock the Mac/u);

  assert.match(support, /interactiveSessionIsReady/u);
  assert.match(support, /sessionUserID\s*==\s*effectiveUserID/u);
  assert.match(support, /com\.apple\.loginwindow/u);
  assert.match(support, /com\.apple\.ScreenSaver/u);
  assert.match(gate, /-framework CoreGraphics/u);

  const activation = section(
    source,
    "private func waitForActivation(",
    "private func waitForAccessoryLaunchState("
  );
  assert.match(activation, /throws\s*->\s*Bool/u);
  assert.ok((activation.match(/try requireUnlockedInteractiveSession\(\)/gu)?.length ?? 0) >= 2);
  const diagnostics = section(source, "private func printDiagnostics(pid: pid_t)", "private func describe(_ frame: CGRect)");
  assert.match(diagnostics, /target\.activationPolicy\.rawValue/u);
  assert.match(diagnostics, /target\.isFinishedLaunching/u);
  assert.match(diagnostics, /target\.isHidden/u);
  assert.match(diagnostics, /target\.isActive/u);
  assert.match(diagnostics, /frontmostApplication/u);
  assert.match(diagnostics, /menuBarOwningApplication/u);
  const topLevel = section(
    source,
    "} catch let error as AcceptanceError {",
    "} catch {"
  );
  assert.match(topLevel, /case \.failed, \.launchRequestUnsettled:[\s\S]*exit\(1\)/u);
  assert.match(topLevel, /case \.thermallyDeferred, \.environmentallyDeferred:[\s\S]*exit\(75\)/u);
});

test("locked-session qualification is tri-state, stabilised, and rechecked throughout every interactive path", async () => {
  const [source, support] = await Promise.all([
    readFile(sourcePath, "utf8"),
    readFile(acceptanceSupportPath, "utf8")
  ]);
  assert.match(support, /enum InteractiveSessionState[\s\S]*case ready[\s\S]*case secureOrWrongUser[\s\S]*case indeterminate/u);
  assert.match(support, /static func interactiveSessionState\(/u);
  assert.match(support, /guard let onConsole, let loginDone, let sessionUserID/u);
  assert.match(support, /return \.indeterminate/u);
  assert.match(support, /return \.secureOrWrongUser/u);

  const preflight = section(
    source,
    "private func interactiveSessionObservation()",
    "private func waitForActivation("
  );
  assert.match(preflight, /interactiveSessionStabilizationTimeout/u);
  assert.match(preflight, /while observation\.state == \.indeterminate/u);
  assert.match(preflight, /observation\.state == \.secureOrWrongUser/u);
  assert.doesNotMatch(preflight, /CGSSessionScreenIsLocked|SACLockScreen|_CGS/u);

  const guardedSections = [
    section(source, "private func waitForPhysicalScheduleOccurrence(", "private func requireStartedPhysicalOccurrence("),
    section(source, "private func requestNormalOpenOfAccessory(", "private func waitForPhysicalForegroundReplacement("),
    section(source, "private func waitForPhysicalForegroundReplacement(", "private func openNormalMenuVerifyAndQuit("),
    section(source, "private func openNormalMenuVerifyAndQuit(", "private func waitForPhysicalForegroundReadyEvidence("),
    section(source, "private func waitForPhysicalForegroundReadyEvidence(", "private func waitForExactLocalReadyStatus("),
    section(source, "private func waitForExactLocalReadyStatus(", "private func verifyDisposablePhysicalEvidence("),
    section(source, "private func launchExactTarget(", "private func interactiveSessionObservation()"),
    section(source, "private func waitForAccessoryLaunchState(", "private func ensureNoTargetBundlePeer(")
  ];
  for (const guarded of guardedSections) {
    assert.match(guarded, /requireUnlockedInteractiveSession\(\)/u);
  }
  const physical = section(
    source,
    "func runPhysicalBackgroundForegroundHandoff() throws",
    "private func createPhysicalHandoffFixture(modelStore: URL)"
  );
  assert.match(physical, /while Date\(\) < settlementDeadline \{\s*try requireUnlockedInteractiveSession\(\)/u);
  const headless = section(source, "private func runHeadlessForegroundHandoffCycle(", "func runNormalMenuActions() throws");
  const sharedOpen = section(
    source,
    "private func requestNormalOpenOfAccessory(",
    "private func waitForPhysicalForegroundReplacement("
  );
  assert.match(sharedOpen, /try requireUnlockedInteractiveSession\(\)[\s\S]*NSWorkspace\.shared\.openApplication/u);
  assert.match(sharedOpen, /OpenRequestBarrier<NSRunningApplication>/u);
  assert.match(sharedOpen, /settleOpenRequest\(/u);
  assert.match(sharedOpen, /try recordProcessIdentity\(pid:\s*reopened\.processIdentifier\)/u);
  assert.match(sharedOpen, /catch \{[\s\S]*cleanupAllLaunchedTargetProcesses\(\s*protected:\s*protectedCleanup\s*\)/u);
  assert.match(
    headless,
    /requestNormalOpenOfAccessory\(\s*headless,\s*pid:\s*oldPID,\s*requiresNominalThermalState:\s*false,\s*protectedCleanup:\s*false\s*\)/u
  );
  assert.doesNotMatch(headless, /NSWorkspace\.shared\.openApplication/u);
});

test("Launch Services callbacks are generation-bound, settled, and unresolved requests fail hard", async () => {
  const [source, support] = await Promise.all([
    readFile(sourcePath, "utf8"),
    readFile(acceptanceSupportPath, "utf8")
  ]);
  assert.match(support, /final class OpenRequestBarrier<Payload>/u);
  assert.match(support, /private let lock = NSLock\(\)/u);
  assert.match(support, /suppliedGeneration == generation[\s\S]*case \.pending = resolution/u);
  assert.match(source, /private func settleOpenRequest\(/u);
  assert.match(source, /openRequestSettlementTimeout:\s*TimeInterval\s*=\s*60/u);
  assert.match(source, /throw AcceptanceError\.launchRequestUnsettled/u);
  assert.ok((source.match(/OpenRequestBarrier<NSRunningApplication>\(\)/gu)?.length ?? 0) >= 2);
  assert.ok((source.match(/barrier\.resolve\(\s*generation:\s*generation/gu)?.length ?? 0) >= 2);

  const launch = section(source, "private func launchExactTarget(", "private func interactiveSessionObservation()");
  assert.match(launch, /let settled = try settleOpenRequest\(/u);
  assert.match(launch, /canonicalBundleURL\(for:\s*application\) == appURL/u);
  assert.match(launch, /cleanupAllLaunchedTargetProcesses\(\s*protected:\s*protectedCleanup\s*\)/u);
  assert.match(launch, /safetyExitDisposition\([\s\S]*openRequestSettled:\s*requestSettled/u);
});

test("every interactive polling boundary rechecks the post-sleep session before terminal classification", async () => {
  const [source, support] = await Promise.all([
    readFile(sourcePath, "utf8"),
    readFile(acceptanceSupportPath, "utf8")
  ]);
  assert.match(support, /enum InteractiveTimeoutDisposition[\s\S]*environmentallyDeferred[\s\S]*candidateFailure/u);
  assert.match(support, /interactiveTimeoutDisposition\([\s\S]*postSleepSessionState == \.ready/u);
  assert.equal(
    source.match(/RunLoop\.current\.run/gu)?.length,
    27,
    "the polling inventory changed; classify every new sleep before updating this count"
  );

  const terminalGuard = section(
    source,
    "private func requireInteractiveTerminalBoundary(",
    "private func environmentalDeferral("
  );
  assert.match(terminalGuard, /try requireUnlockedInteractiveSession\(\)/u);
  assert.match(terminalGuard, /interactiveTimeoutDisposition\(/u);
  assert.match(terminalGuard, /case \.environmentallyDeferred[\s\S]*AcceptanceError\.environmentallyDeferred/u);
  assert.match(terminalGuard, /private func throwInteractiveTimeout\([\s\S]*requireInteractiveTerminalBoundary/u);

  const physical = section(
    source,
    "func runPhysicalBackgroundForegroundHandoff() throws",
    "private func createPhysicalHandoffFixture(modelStore: URL)"
  );
  const headless = section(
    source,
    "private func runHeadlessForegroundHandoffCycle(",
    "func runNormalMenuActions() throws"
  );
  const lightweight = section(source, "private func runCycle(", "private func openMenuVerifyAndQuit(");

  const pollingBlocks = [
    ["physical status settlement", section(physical, "let settlementDeadline =", "let statusItem =")],
    ["physical metadata settlement", section(physical, "// Let cfprefsd", "let after =")],
    ["physical scheduler occurrence", section(source, "private func waitForPhysicalScheduleOccurrence(", "private func requireStartedPhysicalOccurrence(")],
    ["physical foreground replacement", section(source, "private func waitForPhysicalForegroundReplacement(", "private func openNormalMenuVerifyAndQuit(")],
    ["physical ready evidence", section(source, "private func waitForPhysicalForegroundReadyEvidence(", "private func waitForExactLocalReadyStatus(")],
    ["physical local-ready AX", section(source, "private func waitForExactLocalReadyStatus(", "private func verifyDisposablePhysicalEvidence(")],
    ["headless accessory settlement", section(headless, "let settleDeadline =", "// This is the user-visible failure path")],
    ["headless foreground replacement", section(headless, "let handoffDeadline =", "let newPID =")],
    ["headless status settlement", section(headless, "let settlementDeadline =", "let initialItem =")],
    ["lightweight status settlement", section(lightweight, "let settlementDeadline =", "let application =")],
    ["core-menu enablement", section(source, "private func waitForEnabledCoreMenuItems(", "private func activateStatusMenuAction(")],
    ["visible window", section(source, "private func waitForVisibleWindow(", "private func closeVisibleWindow(")],
    ["close window", section(source, "private func closeVisibleWindow(", "private func launchExactTarget(")],
    ["foreground activation", section(source, "private func waitForActivation(", "private func waitForAccessoryLaunchState(")],
    ["accessory launch", section(source, "private func waitForAccessoryLaunchState(", "private func ensureNoTargetBundlePeer(")],
    ["captured child exit", section(source, "private func ensureCapturedProcessesExited(", "private func waitForProtectedExitCapturingDescendants(")],
    ["protected foreground exit", section(source, "private func waitForProtectedExitCapturingDescendants(", "private func physicalCleanupIsComplete(")],
    ["single status item", section(source, "private func waitForSingleStatusItem(", "private func collectStableGeometry(")],
    ["opened status menu", section(source, "private func waitForStatusMenu(", "private func menuItems(")]
  ];
  for (const [label, block] of pollingBlocks) {
    const sleepIndex = block.lastIndexOf("RunLoop.current.run");
    const boundaryIndex = Math.max(
      block.lastIndexOf("try requireInteractiveTerminalBoundary"),
      block.lastIndexOf("try throwInteractiveTimeout")
    );
    assert.ok(sleepIndex >= 0, `${label}: missing polling sleep`);
    assert.ok(boundaryIndex > sleepIndex, `${label}: missing post-sleep terminal boundary`);
  }

  const physicalTimeoutBlocks = pollingBlocks
    .filter(([label]) => label.startsWith("physical") || label === "captured child exit" || label === "protected foreground exit")
    .map(([, block]) => block);
  for (const block of physicalTimeoutBlocks) {
    assert.match(block, /requiresNominalThermalState:\s*true/u);
  }

  const openSettlement = section(source, "private func settleOpenRequest(", "private func requestNormalOpenOfAccessory(");
  const firstSafetyIndex = openSettlement.indexOf("safetyDeferral = try openRequestSafetyDeferral");
  const firstSnapshotIndex = openSettlement.indexOf("switch barrier.snapshot()");
  assert.ok(firstSafetyIndex >= 0 && firstSnapshotIndex > firstSafetyIndex);
  const finalCompletion = section(openSettlement, "// Close the boundary race", "case .pending:");
  assert.match(finalCompletion, /case let \.completed[\s\S]*openRequestSafetyDeferral\([\s\S]*return SettledOpenRequest/u);
  assert.match(openSettlement, /case \.pending:[\s\S]*AcceptanceError\.launchRequestUnsettled/u);

  const sessionStabilization = section(
    source,
    "private func requireUnlockedInteractiveSession() throws",
    "private func requireInteractiveTerminalBoundary("
  );
  const sessionSleepIndex = sessionStabilization.indexOf("RunLoop.current.run");
  const refreshedObservationIndex = sessionStabilization.indexOf(
    "observation = interactiveSessionObservation()",
    sessionSleepIndex
  );
  assert.ok(sessionSleepIndex >= 0 && refreshedObservationIndex > sessionSleepIndex);

  const stableGeometry = section(
    source,
    "private func collectStableGeometry(",
    "private func statusItems(in application: AXUIElement)"
  );
  const geometrySleepIndex = stableGeometry.indexOf("RunLoop.current.run");
  const geometrySessionIndex = stableGeometry.indexOf(
    "try requireUnlockedInteractiveSession()",
    geometrySleepIndex
  );
  const geometryTraversalIndex = stableGeometry.indexOf(
    "let matches = statusItems(in: application)",
    geometrySleepIndex
  );
  assert.ok(
    geometrySleepIndex >= 0
      && geometrySessionIndex > geometrySleepIndex
      && geometryTraversalIndex > geometrySessionIndex
  );

  const physicalQuit = section(source, "private func openNormalMenuVerifyAndQuit(", "private func waitForPhysicalForegroundReadyEvidence(");
  const normalRun = section(source, "func runNormalMenuActions() throws", "private func runCycle(");
  const lightweightQuit = section(source, "private func openMenuVerifyAndQuit(", "private func verifyLightweightMenuEnablement(");
  for (const block of [physicalQuit, normalRun, lightweight, lightweightQuit]) {
    assert.match(block, /waitFor(?:ProtectedExitCapturingDescendants|Exit)[\s\S]*try throwInteractiveTimeout/u);
  }
});

test("session-independent lifecycle polling performs a final state probe after its last sleep", async () => {
  const source = await readFile(sourcePath, "utf8");
  const descendants = section(
    source,
    "private func captureDescendantProcessIdentities(",
    "private func capturedProcessIsRunning("
  );
  assert.match(descendants, /for attempt in 0\.\.<3[\s\S]*if attempt < 2[\s\S]*RunLoop\.current\.run/u);

  const physicalCleanup = section(
    source,
    "private func physicalCleanupIsComplete(",
    "private func isDescendant("
  );
  assert.match(physicalCleanup, /func inventoryIsQuiescent\(\)/u);
  assert.match(physicalCleanup, /while Date\(\) < deadline[\s\S]*return inventoryIsQuiescent\(\)/u);

  const waitForExit = section(source, "private func waitForExit(", "private func processHasExited(");
  assert.match(waitForExit, /while Date\(\) < deadline[\s\S]*return processHasExited\(pid\)/u);

  const identity = section(source, "private func recordProcessIdentity(", "private func processIdentity(");
  assert.equal(identity.match(/if let identity = processIdentity\(pid:\s*pid\)/gu)?.length, 2);
  assert.match(identity, /while Date\(\) < deadline[\s\S]*throw AcceptanceError\.failed/u);

  const nonPhysicalCleanup = section(
    source,
    "private func nonPhysicalCleanupIsComplete(",
    "private func cleanupExactLaunchedProcess("
  );
  assert.match(nonPhysicalCleanup, /func currentObservation\(\)/u);
  assert.match(nonPhysicalCleanup, /while Date\(\) < deadline[\s\S]*return StatusItemAcceptanceSupport\.processInventoryIsQuiescent\(currentObservation\(\)\)/u);
});

test("interactive AX actions reclassify lock races before reporting candidate failures", async () => {
  const source = await readFile(sourcePath, "utf8");
  const action = section(
    source,
    "private func performInteractiveAXAction(",
    "private func waitForActivation("
  );
  assert.match(action, /try requireUnlockedInteractiveSession\(\)[\s\S]*AXUIElementPerformAction/u);
  const axIndex = action.indexOf("AXUIElementPerformAction");
  const postSessionIndex = action.indexOf("interactiveSessionObservation()", axIndex);
  const dispositionIndex = action.indexOf("interactiveTransportDisposition(", postSessionIndex);
  assert.ok(axIndex >= 0 && postSessionIndex > axIndex && dispositionIndex > postSessionIndex);
  assert.match(action, /case \.environmentallyDeferred[\s\S]*AcceptanceError\.environmentallyDeferred/u);
  assert.match(action, /case \.candidateFailure[\s\S]*AcceptanceError\.failed/u);

  const guardedActionSections = [
    section(source, "private func openNormalMenuVerifyAndQuit(", "private func waitForPhysicalForegroundReadyEvidence("),
    section(source, "private func openMenuVerifyAndQuit(", "private func verifyLightweightMenuEnablement("),
    section(source, "private func openStatusMenu(", "private func waitForEnabledCoreMenuItems("),
    section(source, "private func performMenuItem(", "private func visibleApplicationWindows("),
    section(source, "private func closeVisibleWindow(", "private func launchExactTarget(")
  ];
  for (const guarded of guardedActionSections) {
    assert.match(guarded, /performInteractiveAXAction/u);
  }
  const cycle = section(source, "private func runCycle(", "private func openMenuVerifyAndQuit(");
  assert.ok((cycle.match(/performInteractiveAXAction/gu)?.length ?? 0) >= 2);
});

test("post-launch deferral is temporary only after exact protected cleanup is proven", async () => {
  const source = await readFile(sourcePath, "utf8");
  const cleanup = section(
    source,
    "private func cleanupAllLaunchedTargetProcesses(protected: Bool) -> Bool",
    "private func isExactTargetMainExecutable("
  );
  assert.match(cleanup, /captureDescendantProcessIdentities/u);
  assert.match(cleanup, /nonPhysicalCleanupIsComplete/u);
  assert.match(cleanup, /ProcessInventoryObservation/u);
  assert.match(cleanup, /processInventoryIsQuiescent/u);
  assert.match(cleanup, /private func cleanupExactLaunchedProcess\(pid: pid_t\) -> Bool/u);
  assert.match(cleanup, /return waitForExit\(pid: pid, timeout: 2\)/u);
  const protectedCleanup = section(
    source,
    "private func cleanupNormalLaunchedProcess(pid: pid_t) -> Bool",
    "private func isExactTargetMainExecutable("
  );
  assert.match(protectedCleanup, /running\.terminate\(\)/u);
  assert.doesNotMatch(protectedCleanup, /Darwin\.kill|SIGTERM|SIGKILL/u);
  assert.match(protectedCleanup, /return false/u);

  const headlessCatch = section(source, "private func runHeadlessForegroundHandoffCycle(", "func runNormalMenuActions() throws");
  const normalCatch = section(source, "func runNormalMenuActions() throws", "private func runCycle(");
  const lightweightCatch = section(source, "private func runCycle(", "private func openMenuVerifyAndQuit(");
  for (const run of [headlessCatch, normalCatch, lightweightCatch]) {
    assert.match(run, /environmentalDeferral\(in: error\)/u);
    assert.match(run, /cleanupAllLaunchedTargetProcesses\(protected:/u);
    assert.match(run, /safetyExitDisposition\(/u);
    assert.match(run, /case \.hardFailure/u);
    assert.match(run, /AcceptanceError\.failed/u);
  }
  const physical = section(
    source,
    "func runPhysicalBackgroundForegroundHandoff() throws",
    "private func createPhysicalHandoffFixture(modelStore: URL)"
  );
  assert.match(
    physical,
    /safetyExitDisposition\([\s\S]*openRequestSettled:\s*requestIsSettled[\s\S]*cleanupComplete:\s*cleanupComplete[\s\S]*disposableStateRemoved:\s*fixtureWasRemoved/u
  );
  const diagnostics = section(source, "private func printDiagnostics(pid: pid_t)", "private func describe(_ frame: CGRect)");
  assert.match(diagnostics, /interactiveSessionObservation\(\)\.state == \.ready/u);
  assert.match(diagnostics, /skipped locked or indeterminate accessibility traversal/u);
});

test("headless handoff waits through placement recovery and presses one fresh stable identity", async () => {
  const source = await readFile(sourcePath, "utf8");
  assert.match(source, /headlessHandoffCycles\s*=\s*20/u);
  assert.match(source, /statusItemSettlement:\s*TimeInterval\s*=\s*2\.5/u);

  const headlessRun = section(
    source,
    "func runHeadlessForegroundHandoff() throws",
    "private func runHeadlessForegroundHandoffCycle("
  );
  assert.match(headlessRun, /for cycle in 1\.\.\.headlessHandoffCycles/u);

  const handoffCycle = section(
    source,
    "private func runHeadlessForegroundHandoffCycle(",
    "func runNormalMenuActions() throws"
  );
  const accessoryWaitIndex = handoffCycle.indexOf("try waitForAccessoryLaunchState(");
  const accessorySettleIndex = handoffCycle.indexOf("Date().addingTimeInterval(1.5)");
  const reopenIndex = handoffCycle.indexOf("try requestNormalOpenOfAccessory(");
  assert.ok(accessoryWaitIndex >= 0);
  assert.ok(accessorySettleIndex > accessoryWaitIndex);
  assert.ok(reopenIndex > accessorySettleIndex);
  assert.match(handoffCycle, /statusItems\(in:\s*oldApplication\)\.isEmpty/u);
  assert.match(handoffCycle, /visibleApplicationWindows\(in:\s*oldApplication\)\.isEmpty/u);
  const settleIndex = handoffCycle.indexOf("Date().addingTimeInterval(statusItemSettlement)");
  const initialIndex = handoffCycle.indexOf("let initialItem = try waitForSingleStatusItem");
  const stableIndex = handoffCycle.indexOf("let stable = try collectStableGeometry");
  const freshIndex = handoffCycle.indexOf("let freshItem = try waitForSingleStatusItem");
  const identityIndex = handoffCycle.indexOf("CFEqual(freshItem.element, stable.item.element)");
  const pressIndex = handoffCycle.indexOf("openMenuVerifyAndQuit(item: freshItem");
  assert.ok(settleIndex >= 0);
  assert.ok(initialIndex > settleIndex);
  assert.ok(stableIndex > initialIndex);
  assert.ok(freshIndex > stableIndex);
  assert.ok(identityIndex > freshIndex);
  assert.ok(pressIndex > identityIndex);
  assert.equal(handoffCycle.match(/openMenuVerifyAndQuit\(/gu)?.length, 1);
  assert.doesNotMatch(handoffCycle, /AXUIElementPerformAction/u);

  const stability = section(
    source,
    "private func collectStableGeometry(",
    "private func statusItems(in application: AXUIElement)"
  );
  assert.match(stability, /stableIdentity\s*=\s*initial\.element/u);
  assert.ok((stability.match(/CFEqual\(/gu)?.length ?? 0) >= 2);
  assert.match(stability, /StableStatusItemObservation\(item:\s*current,\s*frames:\s*frames\)/u);
  const dwellIndex = stability.indexOf("RunLoop.current.run(");
  const postDwellSessionIndex = stability.indexOf("try requireUnlockedInteractiveSession()", dwellIndex);
  const traversalIndex = stability.indexOf("let matches = statusItems(in: application)", dwellIndex);
  assert.ok(dwellIndex >= 0);
  assert.ok(postDwellSessionIndex > dwellIndex);
  assert.ok(traversalIndex > postDwellSessionIndex);

  const accessoryWait = section(
    source,
    "private func waitForAccessoryLaunchState(",
    "private func ensureNoTargetBundlePeer(excluding pid: pid_t)"
  );
  assert.match(accessoryWait, /Date\(\)\.addingTimeInterval\(timeout\)/u);
  assert.match(accessoryWait, /NSRunningApplication\(processIdentifier:\s*pid\)/u);
  assert.match(accessoryWait, /lastPolicy\s*==\s*\.accessory/u);
  assert.match(accessoryWait, /statusItems\(in:\s*accessibilityApplication\)\.isEmpty/u);
  assert.match(accessoryWait, /visibleApplicationWindows\(in:\s*accessibilityApplication\)\.isEmpty/u);
  assert.match(accessoryWait, /processHasExited\(pid\)/u);
});

test("physical scheduler handoff is real, disposable, fail-closed, and release-addressable", async () => {
  const [source, appSource, isolation, gate, makefile, ollamaSecurity, ollamaLaunchPlan, harnessController] = await Promise.all([
    readFile(sourcePath, "utf8"),
    readFile(appSourcePath, "utf8"),
    readFile(isolationSourcePath, "utf8"),
    readFile(gatePath, "utf8"),
    readFile(makefilePath, "utf8"),
    readFile(ollamaSecurityPath, "utf8"),
    readFile(ollamaLaunchPlanPath, "utf8"),
    readFile(harnessControllerPath, "utf8")
  ]);

  const physical = section(
    source,
    "func runPhysicalBackgroundForegroundHandoff() throws",
    "private func createPhysicalHandoffFixture(modelStore: URL)"
  );
  const occurrenceIndex = physical.indexOf("try waitForPhysicalScheduleOccurrence");
  const runtimeIndex = physical.indexOf("try requireExpectedRuntimeChildren");
  const startedIndex = physical.indexOf("try requireStartedPhysicalOccurrence");
  const oldDescendantsIndex = physical.indexOf("try captureDescendantProcessIdentities(of: oldPID)");
  const normalOpenIndex = physical.indexOf("try requestNormalOpenOfAccessory");
  const activationIndex = physical.indexOf("waitForActivation(of: foreground");
  const replacementIndex = physical.indexOf("waitForPhysicalForegroundReplacement");
  const windowIndex = physical.indexOf("waitForVisibleWindow(");
  const readyEvidenceIndex = physical.indexOf("waitForPhysicalForegroundReadyEvidence");
  const exactReadyStatusIndex = physical.indexOf("waitForExactLocalReadyStatus");
  const newDescendantsIndex = physical.indexOf("try captureDescendantProcessIdentities(of: newPID)");
  const stableIndex = physical.indexOf("collectStableGeometry(");
  const quitIndex = physical.indexOf("openNormalMenuVerifyAndQuit");
  const capturedExitIndex = physical.indexOf("ensureCapturedProcessesExited");
  const bundleExitIndex = physical.lastIndexOf("ensureNoTargetBundleOwnedProcessIsRunning");
  const cleanupIndex = physical.indexOf("ensureNoCandidateRuntimeProcessIsRunning");
  const exactEvidenceIndex = physical.indexOf("verifyDisposablePhysicalEvidence");
  const afterFingerprintIndex = physical.lastIndexOf("liveBoundaries.map(metadataFingerprint)");
  const modelFingerprintIndex = physical.lastIndexOf("metadataFingerprint(modelStore)");
  const removeFixtureIndex = physical.indexOf("try removeDisposablePhysicalFixture(fixture)");
  const removedFlagIndex = physical.indexOf("fixtureWasRemoved = true", removeFixtureIndex);
  assert.ok(occurrenceIndex >= 0);
  assert.ok(runtimeIndex > occurrenceIndex);
  assert.ok(startedIndex > runtimeIndex);
  assert.ok(oldDescendantsIndex > startedIndex);
  assert.ok(normalOpenIndex > oldDescendantsIndex);
  assert.ok(replacementIndex > normalOpenIndex);
  assert.ok(activationIndex > replacementIndex);
  assert.ok(windowIndex > replacementIndex);
  assert.ok(readyEvidenceIndex > windowIndex);
  assert.ok(exactReadyStatusIndex > readyEvidenceIndex);
  assert.ok(newDescendantsIndex > exactReadyStatusIndex);
  assert.ok(stableIndex > newDescendantsIndex);
  assert.ok(quitIndex > stableIndex);
  assert.ok(capturedExitIndex > quitIndex);
  assert.ok(bundleExitIndex > capturedExitIndex);
  assert.ok(cleanupIndex > bundleExitIndex);
  assert.ok(exactEvidenceIndex > cleanupIndex);
  assert.ok(afterFingerprintIndex > exactEvidenceIndex);
  assert.ok(modelFingerprintIndex > afterFingerprintIndex);
  assert.ok(removeFixtureIndex > modelFingerprintIndex);
  assert.ok(removedFlagIndex > removeFixtureIndex);
  assert.match(physical, /ProcessInfo\.processInfo\.thermalState\s*==\s*\.nominal/u);
  assert.match(physical, /let loginHome = try loginHomeDirectory\(\)/u);
  assert.match(physical, /liveUserStateBoundaries\(home:\s*loginHome\)/u);
  assert.match(physical, /liveUserModelStore\(home:\s*loginHome\)/u);
  assert.match(physical, /--background-schedule/u);
  assert.match(physical, /PhysicalHandoffFixture\.backgroundArgument/u);
  assert.ok((physical.match(/ensureNoTargetBundleOwnedProcessIsRunning\(\)/gu)?.length ?? 0) >= 2);
  assert.match(physical, /physicalCleanupIsComplete\(capturedChildren:\s*capturedChildren\)/u);
  assert.match(physical, /if requestIsSettled && cleanupComplete && !fixtureWasRemoved/u);
  assert.match(physical, /case \.failed, \.launchRequestUnsettled:/u);
  assert.match(
    physical,
    /requestNormalOpenOfAccessory\(\s*background,\s*pid:\s*oldPID,\s*requiresNominalThermalState:\s*true,\s*protectedCleanup:\s*true\s*\)/u
  );
  assert.doesNotMatch(physical, /DEEPSEEK_API_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY/u);

  const fixture = section(
    source,
    "private func createPhysicalHandoffFixture(modelStore: URL)",
    "private func packagedHarnessVersion()"
  );
  assert.match(fixture, /\/private\/tmp\/fulmar-physical-handoff\.XXXXXX/u);
  assert.match(fixture, /"installedVersion": runtimeVersion/u);
  assert.match(fixture, /"provider": "ollama"/u);
  assert.match(fixture, /"model": "qwen3\.8:27b-mlx"/u);
  assert.match(fixture, /"performanceProfile": "fast"/u);
  assert.match(fixture, /"boundary": "onDevice"/u);

  const fixtureEnvironment = section(
    source,
    "var launchEnvironment: [String: String]",
    "private struct ElementSnapshot"
  );
  assert.match(
    fixtureEnvironment,
    /var launchEnvironment:\s*\[String:\s*String\]\s*\{\s*\[\s*Self\.rootEnvironmentKey:\s*root\.path,\s*Self\.modelStoreEnvironmentKey:\s*modelStore\.path,\s*"HOME":\s*home\.path,\s*"CFFIXED_USER_HOME":\s*home\.path,\s*"TMPDIR":\s*temporaryDirectory\.path\s*\]\s*\}/su
  );
  assert.doesNotMatch(fixtureEnvironment, /ProcessInfo|merging|DEEPSEEK_API_KEY|SSH_AUTH_SOCK/u);

  assert.match(isolation, /root\.deletingLastPathComponent\(\)\.path\s*==\s*"\/private\/tmp"/u);
  assert.match(isolation, /metadata\.st_mode\s*&\s*0o777\s*==\s*0o700/u);
  assert.match(isolation, /requestsBackground\s*!=\s*requestsForeground/u);
  assert.match(isolation, /suppliedArguments\s*==\s*expectedArguments/u);
  assert.match(isolation, /\["--background-schedule", backgroundArgument\]/u);
  assert.match(isolation, /\[foregroundArgument\]/u);
  assert.match(isolation, /modelStoreEnvironmentKey/u);
  assert.match(isolation, /modelStore\.lastPathComponent\s*==\s*"models"/u);
  assert.match(isolation, /secureReadOnlySourceDirectory\(modelStore\)/u);
  assert.match(isolation, /"HOME": home\.path/u);
  assert.match(isolation, /"CFFIXED_USER_HOME": home\.path/u);
  assert.match(isolation, /"TMPDIR": temporaryDirectory\.path/u);
  assert.doesNotMatch(isolation, /ProcessInfo\.processInfo\.environment\.merging|DEEPSEEK_API_KEY|SSH_AUTH_SOCK/u);

  const foregroundEnvironment = section(
    isolation,
    "var foregroundEnvironment: [String: String]",
    "var foregroundReadyFile"
  );
  assert.match(
    foregroundEnvironment,
    /var foregroundEnvironment:\s*\[String:\s*String\]\s*\{\s*\[\s*Self\.rootEnvironmentKey:\s*root\.path,\s*Self\.modelStoreEnvironmentKey:\s*modelStore\.path,\s*"HOME":\s*home\.path,\s*"CFFIXED_USER_HOME":\s*home\.path,\s*"TMPDIR":\s*temporaryDirectory\.path\s*\]\s*\}/su
  );
  assert.doesNotMatch(foregroundEnvironment, /ProcessInfo|merging|DEEPSEEK_API_KEY|SSH_AUTH_SOCK/u);

  const foregroundReadyPublication = section(
    isolation,
    "func publishForegroundReady(selection: ModelSelection, boundary: DataBoundary) throws",
    "private static func securePrivateDirectory("
  );
  assert.match(foregroundReadyPublication, /selection\.route\s*==\s*ModelSelection\.defaultLocal\.route/u);
  assert.match(foregroundReadyPublication, /boundary\s*==\s*\.onDevice/u);
  assert.match(foregroundReadyPublication, /"schemaVersion":\s*1/u);
  assert.match(foregroundReadyPublication, /"state":\s*"ready"/u);
  assert.match(foregroundReadyPublication, /"provider":\s*selection\.route\.provider\.rawValue/u);
  assert.match(foregroundReadyPublication, /"model":\s*selection\.route\.model\.rawValue/u);
  assert.match(foregroundReadyPublication, /"boundary":\s*boundary\.rawValue/u);
  assert.match(foregroundReadyPublication, /O_WRONLY \| O_CREAT \| O_EXCL \| O_NOFOLLOW \| O_CLOEXEC/u);
  assert.match(foregroundReadyPublication, /0o600/u);
  assert.match(foregroundReadyPublication, /Darwin\.fsync\(descriptor\)\s*==\s*0/u);
  assert.match(foregroundReadyPublication, /metadata\.st_nlink\s*==\s*1/u);
  assert.match(foregroundReadyPublication, /metadata\.st_mode\s*&\s*0o777\s*==\s*0o600/u);

  const freshLaunch = section(
    appSource,
    "private func launchFreshForegroundInstance(",
    "private func canonicalCurrentApplicationURL()"
  );
  assert.match(freshLaunch, /physicalHandoffAcceptance\.foregroundArguments/u);
  assert.match(freshLaunch, /configuration\.environment\s*=\s*physicalHandoffAcceptance\.foregroundEnvironment/u);
  assert.doesNotMatch(freshLaunch, /configuration\.environment\s*=\s*ProcessInfo/u);
  const isolatedController = /HarnessController\(\s*applicationSupportDirectory:\s*physicalHandoffAcceptance\?\.applicationSupport,\s*modelStoreDirectory:\s*physicalHandoffAcceptance\?\.modelStore,\s*forbidCredentialHelper:\s*physicalHandoffAcceptance\s*!=\s*nil\s*\)/gu;
  assert.equal(appSource.match(isolatedController)?.length, 2);

  const foregroundPublication = section(
    appSource,
    "private func finishReadyState()",
    "private func closeAllRuntimeAdmissionsSynchronously()"
  );
  const readyGateIndex = foregroundPublication.indexOf("ThermalReadyStateAdmissionGate.perform");
  const admittedReadyMethodIndex = foregroundPublication.indexOf("private func finishThermallyAdmittedReadyState()");
  const inferencePromotionIndex = foregroundPublication.indexOf("promoteToFullInference");
  const holdReleaseIndex = foregroundPublication.indexOf("conversationService.resumeAfterQuiescence");
  const surfaceResumeIndex = foregroundPublication.indexOf("resumeTurnAdmissionsForFreshRuntime");
  const scheduleStartIndex = foregroundPublication.indexOf("scheduleManager.start()");
  const readyPublicationIndex = foregroundPublication.indexOf("publishForegroundReady(");
  const healthAcknowledgementIndex = foregroundPublication.indexOf("acknowledgeHealthy()");
  const waiterSuccessIndex = foregroundPublication.indexOf("protectedInferenceStartWaiter.resume(with: .success");
  assert.ok(readyGateIndex >= 0);
  assert.ok(admittedReadyMethodIndex > readyGateIndex);
  assert.ok(inferencePromotionIndex >= 0);
  assert.ok(inferencePromotionIndex > admittedReadyMethodIndex);
  assert.ok(holdReleaseIndex > inferencePromotionIndex);
  assert.ok(surfaceResumeIndex > holdReleaseIndex);
  assert.ok(scheduleStartIndex > surfaceResumeIndex);
  assert.ok(readyPublicationIndex > inferencePromotionIndex);
  assert.ok(healthAcknowledgementIndex > readyPublicationIndex);
  assert.ok(waiterSuccessIndex > healthAcknowledgementIndex);
  assert.match(
    foregroundPublication,
    /selectedLocalRuntimeBlocked:\s*thermalSafetyBlocksSelectedLocalRuntime[\s\S]*?onBlocked:[\s\S]*?enforceCurrentThermalBlockIfNeeded\(\)[\s\S]*?onAdmitted:[\s\S]*?finishThermallyAdmittedReadyState\(\)/u
  );
  assert.match(foregroundPublication, /physicalHandoffAcceptance\.mode\s*==\s*\.foreground/u);
  assert.match(foregroundPublication, /selection:\s*selection,\s*boundary:\s*\.onDevice/su);
  assert.match(foregroundPublication, /catch \{\s*failClosedAfterTopologyValidation\(error\)\s*return\s*\}/su);

  const thermalEnforcement = section(
    appSource,
    "private func enforceCurrentThermalBlockIfNeeded()",
    "private func startThermalSafetyMonitoring()"
  );
  assert.match(
    thermalEnforcement,
    /guard thermalSafetyBlocksSelectedLocalRuntime else \{ return false \}/u
  );
  assert.match(
    thermalEnforcement,
    /protectedInferenceStartWaiter\.resume\(with:\s*\.failure\(admissionError\)\)/u
  );
  assert.match(
    thermalEnforcement,
    /case \.ready, \.eco:[\s\S]*?presentThermalStatusInsteadOfReadyIfNeeded\(\)[\s\S]*?currentLocalRuntimeSafetyError\s*==\s*\.memoryPressure[\s\S]*?presentThermalEco\(reason:\s*\.memoryPressure\)/u
  );
  assert.doesNotMatch(thermalEnforcement, /case \.ready, \.eco:\s*return false/u);

  const backgroundPromotion = section(
    appSource,
    "promoteToFullInference: { [weak self] in",
    "runDueSchedules: { [weak self] in"
  );
  assert.match(
    backgroundPromotion,
    /ThermalRuntimeAdmissionPolicy\.promoteIfAdmitted\([\s\S]*?selectedLocalRuntimeBlocked:\s*self\.thermalSafetyBlocksSelectedLocalRuntime[\s\S]*?rpcClient\.promoteToFullInference/u
  );

  const protectedStartup = section(
    appSource,
    "private func beginProtectedStartup()",
    "private func offerCredentialMigration("
  );
  assert.match(
    protectedStartup,
    /nativeProviderStateRecovery\.inspect\(\)[\s\S]*?providerRecoveryContext\s*=\s*\.nativeState[\s\S]*?ThermalRuntimeAdmissionPolicy\.permitsRuntimeStart\([\s\S]*?providerControlPlaneOnly:\s*providerRecoveryContext\s*!=\s*nil/u
  );
  const selectedRuntimeStart = section(
    appSource,
    "private func startSelectedRuntimeMode()",
    "private func pollUntilReady("
  );
  assert.match(
    selectedRuntimeStart,
    /providerControlPlaneOnly\s*=\s*providerRecoveryContext\s*!=\s*nil[\s\S]*?permitsRuntimeStart\([\s\S]*?providerControlPlaneOnly:\s*providerControlPlaneOnly[\s\S]*?if providerControlPlaneOnly \{\s*controller\.prepareProviderRecovery\(\)\s*\} else \{\s*controller\.prepareAndStart\(\)/u
  );

  const headlessThermalRecovery = section(
    appSource,
    "private func recoverFromThermalCooldown()",
    "private func presentThermalEco("
  );
  assert.match(
    headlessThermalRecovery,
    /if thermalHeadlessMode[\s\S]*?resumeDeferredRuntimeLaunch\(\)\s*!=\s*true[\s\S]*?prepareAndLaunch\(\)/u
  );

  assert.match(ollamaSecurity, /modelStoreDirectory:\s*URL\?\s*=\s*nil/u);
  assert.match(ollamaSecurity, /getpwuid_r\(geteuid\(\)/u);
  assert.match(ollamaSecurity, /currentPOSIXHomeDirectory\(\)/u);
  assert.match(ollamaSecurity, /appendingPathComponent\("Applications", isDirectory: true\)[\s\S]*appendingPathComponent\("Ollama\.app", isDirectory: true\)/u);
  assert.doesNotMatch(ollamaSecurity, /ProcessInfo\.processInfo\.environment\["(?:PATH|HOME)"\]/u);
  assert.match(ollamaSecurity, /if let modelStoreDirectory \{\s*configuredStore = modelStoreDirectory\s*\} else \{[\s\S]*OllamaExecutableTrust\.currentPOSIXHomeDirectory\(\)/u);
  assert.match(ollamaLaunchPlan, /modelStoreDirectory:\s*modelStoreDirectory/u);
  const qwenOnlyOptimizations = section(
    ollamaLaunchPlan,
    "if modelConfiguration.optimizationQualification == .releaseQualifiedQwen",
    "return additions"
  );
  assert.match(qwenOnlyOptimizations, /OLLAMA_FLASH_ATTENTION/u);
  assert.match(qwenOnlyOptimizations, /OLLAMA_KV_CACHE_TYPE/u);
  const commonOllamaEnvironment = section(
    ollamaLaunchPlan,
    "var additions = [",
    "if modelConfiguration.optimizationQualification == .releaseQualifiedQwen"
  );
  assert.doesNotMatch(commonOllamaEnvironment, /OLLAMA_FLASH_ATTENTION|OLLAMA_KV_CACHE_TYPE/u);
  assert.match(harnessController, /modelConfiguration:\s*AppOwnedOllamaModelConfiguration/u);
  assert.match(harnessController, /ollamaModelConfiguration\s*==\s*modelConfiguration/u);
  assert.match(harnessController, /ownedOllama\.modelConfiguration\s*==\s*expectedConfiguration/u);
  assert.match(harnessController, /ollamaModelConfiguration\s*==\s*required\.modelConfiguration/u);
  assert.match(harnessController, /modelStoreDirectory:\s*self\.modelStoreOverride/u);

  const occurrenceWait = section(
    source,
    "private func waitForPhysicalScheduleOccurrence(",
    "private func requireStartedPhysicalOccurrence("
  );
  assert.match(occurrenceWait, /receiptURL\.lastPathComponent\s*==\s*"\\\(receipt\.id\.uuidString\)\.json"/u);
  assert.match(occurrenceWait, /receipt\.schemaVersion\s*==\s*1/u);
  assert.match(occurrenceWait, /receipt\.scheduleID\s*==\s*fixture\.scheduleID/u);
  assert.match(occurrenceWait, /receipt\.state\s*==\s*"started"/u);
  assert.match(occurrenceWait, /receipt\.result\s*==\s*nil/u);
  assert.match(occurrenceWait, /receipt\.disable\s*==\s*nil/u);
  assert.match(occurrenceWait, /receipt\.retrySoon\s*==\s*nil/u);

  const startedReceipt = section(
    source,
    "private func requireStartedPhysicalOccurrence(",
    "private func decodePrivatePhysicalJSON"
  );
  assert.match(startedReceipt, /receipt\.schemaVersion\s*==\s*1/u);
  assert.match(startedReceipt, /receipt\.id\s*==\s*occurrenceID/u);
  assert.match(startedReceipt, /receipt\.scheduleID\s*==\s*fixture\.scheduleID/u);
  assert.match(startedReceipt, /receipt\.state\s*==\s*"started"/u);
  assert.match(startedReceipt, /receipt\.result\s*==\s*nil/u);
  assert.match(startedReceipt, /receipt\.disable\s*==\s*nil/u);
  assert.match(startedReceipt, /receipt\.retrySoon\s*==\s*nil/u);

  const disposableEvidence = section(
    source,
    "private func verifyDisposablePhysicalEvidence(",
    "private func removeDisposablePhysicalFixture("
  );
  assert.match(disposableEvidence, /occurrenceEntries\.isEmpty/u);
  assert.match(disposableEvidence, /results\.count\s*==\s*1/u);
  assert.match(disposableEvidence, /results\[0\]\.standardizedFileURL\s*==\s*expectedResultURL\.standardizedFileURL/u);
  for (const contract of [
    /result\.schemaVersion\s*==\s*2/u,
    /result\.id\s*==\s*occurrenceID/u,
    /result\.scheduleID\s*==\s*fixture\.scheduleID/u,
    /result\.title\s*==\s*"Physical handoff release probe"/u,
    /result\.selection\.schemaVersion\s*==\s*1/u,
    /result\.selection\.route\.provider\s*==\s*"ollama"/u,
    /result\.selection\.route\.model\s*==\s*"qwen3\.8:27b-mlx"/u,
    /result\.selection\.performanceProfile\s*==\s*"fast"/u,
    /result\.boundary\s*==\s*"onDevice"/u,
    /result\.sessionID\s*==\s*nil/u,
    /result\.response\.isEmpty/u,
    /result\.failure\?\.code\s*==\s*"interrupted"/u,
    /result\.failure\?\.detail\s*==\s*nil/u,
    /result\.truncated\s*==\s*false/u
  ]) {
    assert.match(disposableEvidence, contract);
  }

  const readyEvidence = section(
    source,
    "private func waitForPhysicalForegroundReadyEvidence(",
    "private func waitForExactLocalReadyStatus("
  );
  for (const contract of [
    /evidence\.schemaVersion\s*==\s*1/u,
    /evidence\.state\s*==\s*"ready"/u,
    /evidence\.provider\s*==\s*"ollama"/u,
    /evidence\.model\s*==\s*"qwen3\.8:27b-mlx"/u,
    /evidence\.boundary\s*==\s*"onDevice"/u
  ]) {
    assert.match(readyEvidence, contract);
  }
  const exactReadyStatus = section(
    source,
    "private func waitForExactLocalReadyStatus(",
    "private func verifyDisposablePhysicalEvidence("
  );
  assert.match(exactReadyStatus, /let expected\s*=\s*"Ready · On this Mac"/u);
  assert.match(exactReadyStatus, /matches\.count\s*==\s*1/u);
  assert.match(exactReadyStatus, /matches\.count\s*>\s*1/u);
  assert.match(exactReadyStatus, /maximumDepth:\s*3/u);
  assert.match(exactReadyStatus, /maximumCount:\s*128/u);
  assert.match(exactReadyStatus, /maximumDepth:\s*5/u);
  assert.match(exactReadyStatus, /maximumCount:\s*256/u);

  const descendantCapture = section(
    source,
    "private func captureDescendantProcessIdentities(",
    "private func capturedProcessIsRunning("
  );
  assert.match(descendantCapture, /for attempt in 0\.\.<3/u);
  assert.match(descendantCapture, /if attempt < 2[\s\S]*RunLoop\.current\.run/u);
  assert.match(descendantCapture, /allBSDProcesses\(\)\.filter \{ isDescendant\(\$0\.pid, of:\s*ancestor\) \}/u);
  assert.match(descendantCapture, /processIdentity\(pid:\s*descendant\.pid\)/u);
  assert.match(descendantCapture, /kernelProcessExists\(descendant\.pid\)/u);

  const expectedChildren = section(
    source,
    "private func requireExpectedRuntimeChildren(",
    "private func captureDescendantProcessIdentities("
  );
  assert.match(expectedChildren, /allBSDProcesses\(\)/u);
  assert.match(expectedChildren, /processes\.filter \{ isDescendant\(\$0\.pid, of:\s*ancestor\) \}/u);
  assert.match(expectedChildren, /\$0\.executablePath\s*==\s*nodePath/u);
  assert.match(expectedChildren, /descendants\.contains\(where:\s*officialOllamaProcessIsValid\)/u);
  assert.match(expectedChildren, /return try captureDescendantProcessIdentities\(of:\s*ancestor\)/u);

  const capturedCleanup = section(
    source,
    "private func ensureCapturedProcessesExited(",
    "private func physicalCleanupIsComplete("
  );
  assert.match(capturedCleanup, /let exact = Set\(identities\)/u);
  assert.match(capturedCleanup, /exact\.allSatisfy\(\{ !capturedProcessIsRunning\(\$0\) \}\)/u);
  assert.match(capturedCleanup, /exact\.filter\(capturedProcessIsRunning\)/u);
  const completeCleanup = section(
    source,
    "private func physicalCleanupIsComplete(",
    "private func isDescendant("
  );
  assert.match(completeCleanup, /Set\(capturedChildren\)\.allSatisfy/u);
  assert.match(completeCleanup, /targetBundleOwnedProcesses\(\)\.isEmpty/u);
  assert.match(completeCleanup, /candidateRuntimeProcesses\(\)\.isEmpty/u);
  assert.match(completeCleanup, /physicalOllamaExecutablePaths\.contains\(\$0\.executablePath\)/u);

  const replacementCapture = section(
    source,
    "private func waitForPhysicalForegroundReplacement(",
    "private func openNormalMenuVerifyAndQuit("
  );
  assert.match(replacementCapture, /captureDescendantProcessIdentities\(of:\s*oldPID\)/u);
  const quitCapture = section(
    source,
    "private func openNormalMenuVerifyAndQuit(",
    "private func waitForPhysicalForegroundReadyEvidence("
  );
  assert.ok(quitCapture.indexOf("captureDescendantProcessIdentities(of: pid)") < quitCapture.indexOf("performMenuItem(quit"));

  const loginHome = section(
    source,
    "private func loginHomeDirectory()",
    "private func liveUserModelStore("
  );
  assert.match(loginHome, /getuid\(\)\s*==\s*geteuid\(\),\s*geteuid\(\)\s*!=\s*0/u);
  assert.match(loginHome, /getpwuid_r\(\s*geteuid\(\)/su);
  assert.match(loginHome, /record\.pw_uid\s*==\s*geteuid\(\)/u);
  assert.match(loginHome, /Darwin\.lstat\(home\.path, &metadata\)\s*==\s*0/u);
  assert.match(loginHome, /metadata\.st_uid\s*==\s*geteuid\(\)/u);
  assert.match(loginHome, /metadata\.st_mode\s*&\s*\(S_IWGRP \| S_IWOTH\)\s*==\s*0/u);
  assert.match(loginHome, /Darwin\.realpath\(home\.path, &canonicalBuffer\)\s*!=\s*nil/u);
  assert.doesNotMatch(loginHome, /ProcessInfo\.processInfo\.environment|homeDirectoryForCurrentUser/u);

  const liveModelStore = section(
    source,
    "private func liveUserModelStore(home: URL)",
    "private func liveUserStateBoundaries(home: URL)"
  );
  assert.match(liveModelStore, /home\s*\.appendingPathComponent\("\.ollama"/u);
  assert.match(liveModelStore, /\.appendingPathComponent\("models"/u);
  const liveBoundaries = section(
    source,
    "private func liveUserStateBoundaries(home: URL)",
    "private func metadataFingerprint("
  );
  assert.match(liveBoundaries, /home\.appendingPathComponent\("\.dsh",\s*isDirectory:\s*true\)/u);
  assert.match(liveBoundaries, /home\.appendingPathComponent\("Library\/Keychains",\s*isDirectory:\s*true\)/u);

  const bundleScan = section(
    source,
    "private func ensureNoTargetBundleOwnedProcessIsRunning()",
    "private func runningTargetBundleProcesses()"
  );
  assert.match(bundleScan, /targetBundleOwnedProcesses\(\)/u);
  assert.match(bundleScan, /allBSDProcesses\(\)\.filter/u);
  assert.match(bundleScan, /isExecutableOwnedByTargetBundle\(process\.executablePath\)/u);
  assert.match(bundleScan, /cursor\.pathExtension\s*==\s*"app"/u);
  assert.match(bundleScan, /Bundle\(url:\s*cursor\)\?\.bundleIdentifier\s*==\s*targetBundleIdentifier/u);

  const disposableRemoval = section(
    source,
    "private func removeDisposablePhysicalFixture(",
    "private func isPrivateRegularFile("
  );
  assert.match(disposableRemoval, /root\.deletingLastPathComponent\(\)\.path\s*==\s*"\/private\/tmp"/u);
  assert.match(disposableRemoval, /root\.lastPathComponent\.hasPrefix\(PhysicalHandoffFixture\.rootLeafPrefix\)/u);
  assert.match(disposableRemoval, /UInt64\(truncatingIfNeeded:\s*metadata\.st_dev\)\s*==\s*identity\.device/u);
  assert.match(disposableRemoval, /UInt64\(metadata\.st_ino\)\s*==\s*identity\.inode/u);
  assert.match(disposableRemoval, /Darwin\.realpath\(root\.path, &canonicalBuffer\)\s*!=\s*nil/u);
  assert.match(disposableRemoval, /FileManager\.default\.removeItem\(at:\s*root\)/u);
  assert.match(disposableRemoval, /Darwin\.lstat\(root\.path, &removedMetadata\)\s*!=\s*0,\s*errno\s*==\s*ENOENT/u);

  const appMain = section(appSource, "static func main()", "enum ProviderRecoveryContext");
  assert.ok(
    appMain.indexOf("PhysicalHandoffAcceptanceEnvironment.resolveIfRequested()")
      < appMain.indexOf("AppOwnedOllamaGenerationCanary.isRequested()"),
    "physical handoff isolation must reject mixed launch modes before any generation canary can run"
  );

  assert.match(gate, /--physical-background-handoff/u);
  assert.match(makefile, /^status-item-physical-background-handoff:/mu);
  assert.match(makefile, /^installed-status-item-physical-background-handoff:/mu);
});

test("thermal Ready deferral is generation-bound, one-shot, and restart-safe", async () => {
  const appSource = await readFile(appSourcePath, "utf8");
  const gate = section(
    appSource,
    "struct ThermalReadyFinalizationGate",
    "enum ProtectedThermalRecoveryPolicy"
  );
  assert.match(gate, /let generation:\s*UUID/u);
  assert.match(gate, /let endpoint:\s*HarnessEndpoint/u);
  assert.match(gate, /var identityChanged:\s*Bool/u);
  assert.match(
    gate,
    /endpointDidChange[\s\S]*?token\.identityChanged\s*=\s*true/u
  );
  assert.match(
    gate,
    /guard runtimeIsReady,[\s\S]*?!token\.identityChanged,[\s\S]*?token\.generation\s*==\s*currentGeneration,[\s\S]*?token\.endpoint\s*==\s*currentEndpoint[\s\S]*?restartAfterIdentityChange/u
  );
  assert.match(
    gate,
    /case \.verified:[\s\S]*?self\.token\s*=\s*nil[\s\S]*?return \.finalizeVerifiedRuntime/u
  );

  const endpointWiring = section(
    appSource,
    "thermalHeadlessMode = false\n        lastExternalApplication",
    "controller.onStateChange = { [weak self] state"
  );
  assert.ok(
    endpointWiring.indexOf("thermalReadyFinalization.endpointDidChange")
      < endpointWiring.indexOf("rpcClient.setControlPlaneEndpoint")
  );

  const stateHandler = section(
    appSource,
    "private func handle(_ state: HarnessController.State)",
    "private func showLoading("
  );
  assert.match(
    stateHandler,
    /case \.ready:[\s\S]*?thermalSafetyBlocksSelectedLocalRuntime[\s\S]*?deferAwaitingTopology[\s\S]*?verifyLiveProviderTopology[\s\S]*?finishReadyState\(\)/u
  );
  assert.match(stateHandler, /case \.startingHarness:[\s\S]*?thermalReadyFinalization\.clear\(\)/u);
  assert.match(stateHandler, /case \.stopped:[\s\S]*?thermalReadyFinalization\.clear\(\)/u);
  assert.match(stateHandler, /case \.failed[\s\S]*?thermalReadyFinalization\.clear\(\)/u);

  const readyFinalization = section(
    appSource,
    "private func finishReadyState()",
    "private func closeAllRuntimeAdmissionsSynchronously()"
  );
  assert.match(
    readyFinalization,
    /onBlocked:[\s\S]*?deferVerifiedTopology[\s\S]*?enforceCurrentThermalBlockIfNeeded\(\)/u
  );
  const admittedFinalization = section(
    readyFinalization,
    "private func finishThermallyAdmittedReadyState()",
    "/// The only synchronous entry into a protected runtime transition."
  );
  assert.ok(
    admittedFinalization.indexOf("promoteToFullInference")
      < admittedFinalization.indexOf("thermalReadyFinalization.clear()")
  );

  const recovery = section(
    appSource,
    "private func completeThermalNormalModeRecovery(",
    "private func suspendAdmissionsForPendingThermalNormalModeRecoveryIfNeeded()"
  );
  assert.match(
    recovery,
    /continueDeferredThermalReadyFinalizationIfPossible\(\)[\s\S]*?case \.awaitTopology:[\s\S]*?case \.finalizeVerifiedRuntime:[\s\S]*?finishReadyState\(\)[\s\S]*?case \.restartAfterIdentityChange:[\s\S]*?restartAfterStaleThermalReadyFinalization\(\)/u
  );
  assert.match(
    recovery,
    /restartAfterStaleThermalReadyFinalization[\s\S]*?closeAllRuntimeAdmissionsSynchronously\(\)[\s\S]*?stopOwnedServicesAndWait[\s\S]*?startSelectedRuntimeMode\(\)/u
  );

  const startup = section(
    appSource,
    "private func beginProtectedStartup()",
    "private func offerCredentialMigration("
  );
  assert.match(startup, /enforceCurrentThermalBlockIfNeeded\(\)[\s\S]*?thermalInitialStartupDeferred\s*=\s*true/u);
  assert.doesNotMatch(startup, /thermalReadyFinalization\.defer/u);

  const shutdown = section(
    appSource,
    "private func beginThermalRuntimeShutdown(",
    "private func recoverFromThermalCooldown()"
  );
  assert.match(shutdown, /thermalReadyFinalization\.clear\(\)[\s\S]*?stopOwnedServicesAndWait/u);
  const lock = section(
    appSource,
    "private func presentThermalLock(",
    "private func presentThermalNormalModeRecoveryFailure("
  );
  assert.match(lock, /thermalReadyFinalization\.clear\(\)/u);
});

test("peer detection distinguishes the app main executable from bundled runtime helpers", async () => {
  const source = await readFile(sourcePath, "utf8");
  const peerScan = section(
    source,
    "private func runningTargetBundleProcesses()",
    "private func allBSDProcesses()"
  );
  assert.match(peerScan, /isMainExecutableOfTargetBundle/u);
  assert.doesNotMatch(peerScan, /executableBelongsToExactTarget|bundleIdentifier\(forExecutablePath/u);

  const classifier = section(
    source,
    "private func isMainExecutableOfTargetBundle(",
    "private func describeBundleProcesses("
  );
  assert.match(classifier, /CFBundleExecutable/u);
  assert.match(classifier, /isBundleMainExecutable/u);
});

test("lightweight status acceptance cannot auto-enable uninitialised production actions", async () => {
  const source = await readFile(sourcePath, "utf8");
  const appSource = await readFile(appSourcePath, "utf8");
  const acceptanceMenu = section(
    appSource,
    "private func buildStatusItem(",
    "private func tearDownStatusItem()"
  );
  assert.match(acceptanceMenu, /menu\.autoenablesItems\s*=\s*false/u);
  assert.match(acceptanceMenu, /item\.isEnabled\s*=\s*false/u);
  assert.match(acceptanceMenu, /item\.action\s*!=\s*#selector\(NSApplication\.terminate/u);
  const enablementProof = section(
    source,
    "private func verifyLightweightMenuEnablement(",
    "private func openStatusMenu("
  );
  assert.match(enablementProof, /kAXEnabledAttribute/u);
  assert.match(enablementProof, /title\s*==\s*"Quit/u);
  assert.ok((source.match(/try verifyLightweightMenuEnablement\(items, pid:\s*pid\)/gu)?.length ?? 0) >= 2);
});

test("programmatic status teardown cannot persist a hidden autosave state", async () => {
  const appSource = await readFile(appSourcePath, "utf8");
  const removal = section(
    appSource,
    "private func removeStatusItem(",
    "private func tearDownStatusItem()"
  );
  const detachIndex = removal.indexOf("item.autosaveName = nil");
  const ownedRemovalIndex = removal.indexOf("owningStatusBar.removeStatusItem(item)");
  const fallbackRemovalIndex = removal.indexOf("NSStatusBar.system.removeStatusItem(item)");
  assert.ok(detachIndex >= 0, "teardown must detach the persistent identity");
  assert.ok(ownedRemovalIndex > detachIndex, "owned status-bar removal must follow identity detachment");
  assert.ok(fallbackRemovalIndex > detachIndex, "fallback status-bar removal must follow identity detachment");
  assert.doesNotMatch(removal, /item\.isVisible\s*=\s*false/u);
});

test("a new status identity is shown once without overriding later user visibility", async () => {
  const appSource = await readFile(appSourcePath, "utf8");
  const build = section(
    appSource,
    "private func buildStatusItem(",
    "private func tearDownStatusItem()"
  );
  const autosaveIndex = build.indexOf("statusItem?.autosaveName = StatusItemIcon.autosaveName");
  const initializeIndex = build.indexOf("StatusItemIcon.initializeVisibilityIfNeeded");
  const visibleIndex = build.lastIndexOf("statusItem?.isVisible = true");
  assert.ok(autosaveIndex >= 0);
  assert.ok(initializeIndex > autosaveIndex, "one-time visibility must follow autosave restoration");
  assert.ok(visibleIndex > initializeIndex, "the public visibility setter must be scoped to one-time initialization");
  assert.equal(build.match(/statusItem\?\.isVisible\s*=\s*true/gu)?.length, 2);
  assert.match(build, /if placementRecoveryAttempt > 0/u);
  assert.match(build, /else \{\s*StatusItemIcon\.initializeVisibilityIfNeeded/su);
});

test("off-screen status placement recovery is permission-free, user-respecting, and bounded", async () => {
  const appSource = await readFile(appSourcePath, "utf8");
  const recovery = section(
    appSource,
    "private func scheduleStatusItemPlacementVerification(",
    "private func removeStatusItem("
  );
  assert.match(recovery, /StatusItemIcon\.placementDecision/u);
  assert.match(recovery, /isCurrentItem:\s*self\.statusItem === item/u);
  assert.match(recovery, /isVisible:\s*item\.isVisible/u);
  assert.match(recovery, /frame:\s*item\.button\?\.window\?\.frame/u);
  assert.match(recovery, /screenFrames:\s*NSScreen\.screens\.map\(\\\.frame\)/u);
  assert.match(recovery, /StatusItemIcon\.recordPlacementDecision\(decision, recoveryAttempt:\s*attempt\)/u);
  assert.match(recovery, /case \.recreate\(let nextAttempt\)/u);
  assert.match(recovery, /buildStatusItem\(placementRecoveryAttempt: nextAttempt\)/u);
  assert.doesNotMatch(recovery, /AXUIElement|AXIsProcessTrusted|isVisible\s*=\s*false/u);

  const removal = section(
    appSource,
    "private func removeStatusItem(",
    "private func tearDownStatusItem()"
  );
  const detachIndex = removal.indexOf("item.autosaveName = nil");
  assert.ok(detachIndex >= 0);
  assert.ok(removal.indexOf("owningStatusBar.removeStatusItem(item)") > detachIndex);
  assert.ok(removal.indexOf("NSStatusBar.system.removeStatusItem(item)") > detachIndex);
});

test("menu-bar settings offers and schedules only an explicit bounded placement retry", async () => {
  const appSource = await readFile(appSourcePath, "utf8");
  const activation = section(
    appSource,
    "func applicationDidBecomeActive(",
    "func applicationShouldTerminate("
  );
  const settings = section(
    appSource,
    "@objc func showMenuBarSettings(",
    "@objc func installVerifiedUpdate("
  );
  assert.match(activation, /if retryStatusItemPlacementAfterSystemSettings/u);
  assert.match(activation, /retryStatusItemPlacementFromUserAction\(\)/u);
  assert.match(settings, /alert\.addButton\(withTitle:\s*"Retry Placement Now"\)/u);
  assert.match(settings, /retryStatusItemPlacementFromUserAction\(assertVisibility:\s*true\)/u);
  assert.match(settings, /retryStatusItemPlacementAfterSystemSettings\s*=\s*true/u);
  assert.match(settings, /if assertVisibility \{ item\.isVisible = true \}/u);
  assert.match(settings, /scheduleStatusItemPlacementVerification\(for:\s*item, attempt:\s*0\)/u);
  assert.match(settings, /StatusItemIcon\.beginPlacementVerification\(recoveryAttempt:\s*0\)/u);
  assert.doesNotMatch(settings, /while|repeat\s*\{/u);
});

test("opened-menu proof is scoped to the pressed item and requires visible geometry", async () => {
  const source = await readFile(sourcePath, "utf8");
  const menuSearch = section(
    source,
    "private func waitForStatusMenu(",
    "private func menuItems(in menu: AXUIElement)"
  );
  assert.match(menuSearch, /from statusItem:\s*AXUIElement/u);
  assert.match(menuSearch, /descendants\(\s*of:\s*statusItem/u);
  assert.match(menuSearch, /maximumDepth:\s*2/u);
  assert.match(menuSearch, /maximumCount:\s*64/u);
  assert.match(menuSearch, /snapshot\.frame\?\.width/u);
  assert.match(menuSearch, /snapshot\.frame\?\.height/u);
  assert.doesNotMatch(menuSearch, /descendants\(of:\s*application|kAXWindowsAttribute/u);
  assert.equal(menuSearch.match(/menuItems\(in:/gu)?.length, 1);
  assert.match(source, /accessibilityPollInterval:\s*TimeInterval\s*=\s*0\.25/u);
});

test("bounded accessibility traversal uses a cursor, exact identity, and child caps", async () => {
  const source = await readFile(sourcePath, "utf8");
  const traversal = section(
    source,
    "private func descendants(",
    "private func elements("
  );
  assert.match(traversal, /var cursor = 0/u);
  assert.match(traversal, /cursor < queue\.count/u);
  assert.match(traversal, /CFEqual\(\$0, element\)/u);
  assert.match(traversal, /maximumCount - result\.count - queued/u);
  assert.doesNotMatch(traversal, /removeFirst\(\)|CFHash\(/u);

  const elementReader = section(
    source,
    "private func elements(",
    "private func snapshot("
  );
  assert.match(elementReader, /maximumCount:\s*Int\s*=\s*64/u);
  assert.match(elementReader, /values\.prefix\(maximumCount - result\.count\)/u);
});

test("live status gates bind candidate and installed actions to one frozen release", async () => {
  const gate = await readFile(gatePath, "utf8");
  const releaseLock = await readFile(releaseLockPath, "utf8");
  assert.match(gate, /source "\$PROJECT_DIR\/scripts\/release-lock\.zsh"/u);
  assert.match(gate, /fulmar_acquire_release_lock[\s\S]*verify_exact_status_target/u);
  assert.match(releaseLock, /\/private\/tmp\/LocalHarnessBuild\.lock/u);
  assert.match(gate, /runtime-inventory\.mjs[\s\S]*verify "\$PROJECT_DIR\/VendorRuntime" "\$PROJECT_DIR\/VendorRuntime\.inventory\.json" VendorRuntime/u);
  assert.match(gate, /toolchain-inventory\.mjs[\s\S]*verify "\$PROJECT_DIR\/build\/toolchain-inventory\.json"/u);
  assert.ok((gate.match(/source-build-input-inventory\.mjs/gu)?.length ?? 0) >= 2);
  assert.match(gate, /source-build-input-inventory\.mjs[\s\S]*verify "\$PROJECT_DIR" "\$PROJECT_DIR\/build\/source-build-inputs\.json"/u);
  assert.match(gate, /verify-release-manifest\.mjs/u);
  assert.match(gate, /verify-zip-entries\.mjs/u);
  assert.match(gate, /verify-release-tree\.mjs" "\$candidate" "\$extracted"/u);
  assert.match(gate, /verify-release-tree\.mjs" "\$candidate" "\$installed"/u);
  assert.match(gate, /codesign --verify --deep --strict "\$candidate"/u);
  assert.match(gate, /codesign --verify --deep --strict "\$installed"/u);
  assert.match(gate, /accepts only the manifest-bound candidate or its exact installed copy/u);
  assert.match(gate, /refusing to infer status evidence from a stale installed app/u);
  assert.doesNotMatch(gate, /exec "\$EXECUTABLE"/u);
});
