import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

const source = (relative) => readFile(join(process.cwd(), relative), "utf8");

test("public diagnostics, exports, quarantine metadata, and release tools use the Fulmar identity", async () => {
  const [runner, exporter, stager, patch, generation, materializer] = await Promise.all([
    source("Tools/SandboxRunner/main.swift"),
    source("Sources/LocalHarness/ConversationExporter.swift"),
    source("Sources/LocalHarness/SecureDownloadStager.swift"),
    source("Resources/LocalHarness.patch.yml"),
    source("Sources/LocalHarness/AppOwnedOllamaGenerationCanary.swift"),
    source("scripts/materialize-local-plugin-dependencies.mjs")
  ]);

  assert.match(runner, /fulmar-sandbox-runner:/u);
  assert.match(runner, /permission denied by Fulmar tool sandbox/u);
  assert.doesNotMatch(runner, /local-harness-sandbox-runner:/u);
  assert.doesNotMatch(runner, /permission denied by Local Harness sandbox/u);
  assert.match(exporter, /return "fulmar-\\\(label\)-\\\(timestamp\)\.\\\(format\.pathExtension\)"/u);
  assert.doesNotMatch(exporter, /return "local-harness-\\\(label\)-/u);
  assert.match(stager, /let value = "0083;\\\(timestamp\);\\\(ProductBrand\.displayName\);\\\(origin\)"/u);
  assert.doesNotMatch(stager, /0083;[^\n]*Local Harness/u);
  assert.match(patch, /fulmar-sandbox-runner:/u);
  assert.doesNotMatch(patch, /local-harness-sandbox-runner:/u);
  assert.match(generation, /ProductBrand\.displayName\) app-owned generation qualification failed/u);
  assert.doesNotMatch(generation, /Local Harness app-owned generation qualification failed/u);
  assert.match(materializer, /RELEASE_IDENTITY\.productDisplayName/u);
  assert.doesNotMatch(materializer, /Local Harness runtime-manifest materialization failed/u);
});

test("main and status menus retain visible labels and deterministic actions", async () => {
  const [app, shortcuts] = await Promise.all([
    source("Sources/LocalHarness/LocalHarnessApp.swift"),
    source("Sources/LocalHarness/MainMenuShortcutCatalog.swift")
  ]);
  const menuItems = [
    [/title: "About \\\(ProductBrand\.displayName\)", action: #selector\(showAbout\(_:\)\)/u, "About"],
    [/title: "Models & Providers", action: #selector\(showProviderCenter\(_:\)\)/u, "Models & Providers"],
    [/title: "\\\(ProductBrand\.displayName\) Diagnostics", action: #selector\(showDiagnostics\(_:\)\)/u, "Diagnostics"],
    [/title: "DeepSeek Harness Project", action: #selector\(openHarnessProject\(_:\)\)/u, "DeepSeek Harness Project"],
    [/title: "Open \\\(ProductBrand\.displayName\)", action: #selector\(showMainWindow\(_:\)\)/u, "Open Fulmar"]
  ];

  for (const [contract, label] of menuItems) {
    assert.match(app, contract, `${label} is missing or wired to the wrong action`);
  }
  for (const [contract, label] of [
    [/command\("settings", "Settings…", #selector\(AppDelegate\.showSettings\(_:\)\)/u, "Settings"],
    [/command\("new-session", "New Session", #selector\(AppDelegate\.newSession\(_:\)\)/u, "New Session"],
    [/command\("chat", "Chat", #selector\(AppDelegate\.showQuickChat\(_:\)\)/u, "Chat"],
    [/command\("command-center", "Command Center…", #selector\(AppDelegate\.showCommandCenter\(_:\)\)/u, "Command Center"]
  ]) {
    assert.match(shortcuts, contract, `${label} shortcut is missing or wired to the wrong action`);
  }
  assert.match(
    app,
    /withTitle: "Quit \\\(ProductBrand\.displayName\)", action: #selector\(NSApplication\.terminate\(_:\)\)/u
  );
  assert.match(app, /NSApp\.mainMenu = main/u);
  assert.match(app, /MainMenuShortcutCatalog\.builtMenuConsumesEveryCommandExactlyOnce\(main, target:\s*self\)/u);
  assert.match(app, /statusItem\?\.menu = menu/u);
  assert.match(app, /experimental developer-preview software that has not undergone a security audit/u);
  assert.match(app, /no sandbox or approval system guarantees isolation/u);
  assert.doesNotMatch(
    app,
    /title: "Install Verified Update…", action: #selector\(installVerifiedUpdate\(_:\)\)/u,
    "the unqualified launch-only updater must not be exposed in a public menu"
  );
  assert.match(app, /private static let verifiedInAppUpdatesEnabled = false/u);
  assert.match(app, /guard Self\.verifiedInAppUpdatesEnabled else \{/u);
});
