import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

test("protected runtime failures retain only closed typed categories", async () => {
  const coordinator = await readFile(
    join(process.cwd(), "Sources/LocalHarness/ProtectedRuntimeMutationCoordinator.swift"),
    "utf8"
  );
  const start = coordinator.indexOf("enum ProtectedRuntimeMutationCoordinatorError");
  const end = coordinator.indexOf("/// Thread-safe authority", start);
  assert.ok(start >= 0 && end > start);
  const declaration = coordinator.slice(start, end);

  assert.doesNotMatch(declaration, /^\s*case\s+.*\bString\b/mu);
  assert.doesNotMatch(coordinator, /localizedDescription/u);
  assert.doesNotMatch(coordinator, /message\.contains\([^)]*previous verified state was restored/u);
  assert.match(declaration, /case previousVerifiedStateRestored/u);
  assert.match(declaration, /case transitionFailed\(ProtectedRuntimeTransitionFailure\)/u);
  assert.match(declaration, /case mutationAndRecoveryFailed\(kind: ProtectedRuntimeMutationKind\)/u);

  const consumers = await Promise.all([
    "LocalHarnessApp.swift",
    "ProviderCenterWindowController.swift",
    "ProviderSelectionTransaction.swift"
  ].map((name) => readFile(join(process.cwd(), "Sources/LocalHarness", name), "utf8")));
  for (const source of consumers) {
    assert.doesNotMatch(
      source,
      /ProtectedRuntimeMutationCoordinatorError\.(?:transitionFailed|mutationCommittedButRecoveryFailed|mutationOutcomeUncertainAndRecoveryFailed|mutationAndRecoveryFailed)\([\s\S]{0,240}?localizedDescription/u
    );
  }
});

test("passive workspace and MCP labels never embed full approved paths", async () => {
  const workspace = await readFile(
    join(process.cwd(), "Sources/LocalHarness/WorkspaceRecoveryWindowController.swift"),
    "utf8"
  );
  const mcp = await readFile(
    join(process.cwd(), "Sources/LocalHarness/MCPCenterWindowController.swift"),
    "utf8"
  );

  assert.doesNotMatch(workspace, /subtitle\.toolTip\s*=\s*operations\.approvedWorkspaceURL\.path/u);
  assert.doesNotMatch(workspace, /safeWorkspacePath/u);
  assert.doesNotMatch(mcp, /Relative to \\?\(projectRoot\.path\)/u);
  assert.doesNotMatch(mcp, /safeProjectRootPath/u);
  assert.match(workspace, /url\.lastPathComponent/u);
  assert.match(mcp, /url\.lastPathComponent/u);
});
