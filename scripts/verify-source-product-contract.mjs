#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { verifyDSHPromotionProvenanceAtRoot } from "./verify-dsh-promotion-provenance.mjs";

const root = path.resolve(process.argv[2] ?? path.join(import.meta.dirname, ".."));
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");
const fail = (message) => {
  process.stderr.write(`Source product contract failed: ${message}\n`);
  process.exit(1);
};

const identity = JSON.parse(read("Config/ReleaseIdentity.json"));
if (identity.schemaVersion !== 1) fail("unsupported release identity schema");
if (identity.productDisplayName !== "Fulmar") fail("unexpected visible product name");
if (identity.applicationBundleName !== `${identity.productDisplayName}.app`) fail("application bundle name drifted");
if (identity.releaseArchiveName !== `${identity.applicationBundleName}.zip`) fail("release archive name drifted");
if (!/^\d+\.\d+\.\d+$/.test(identity.appVersion)) fail("invalid app version");
if (!Number.isInteger(identity.appBuild) || identity.appBuild <= 0) fail("invalid app build");
if (!/^\d+\.0$/.test(identity.minimumMacOS)) fail("minimum macOS must be an exact supported major-version floor");
try {
  await verifyDSHPromotionProvenanceAtRoot(root);
} catch (error) {
  fail(`DSH promotion provenance is invalid: ${error instanceof Error ? error.message : String(error)}`);
}
const upstreamDSHWorkflow = read(".github/workflows/check-upstream-dsh.yml");
const expectedUpstreamDSHWorkflow = [
  "name: Check upstream DSH",
  "",
  "on:",
  "  workflow_dispatch:",
  "  schedule:",
  '    - cron: "23 5 * * *"',
  "",
  "permissions:",
  "  contents: read",
  "",
  "jobs:",
  "  observe:",
  "    runs-on: ubuntu-24.04",
  "    timeout-minutes: 10",
  "    steps:",
  "      - name: Check out source",
  "        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0",
  "        with:",
  "          persist-credentials: false",
  "",
  "      - name: Reject an unsafe tracked source index",
  "        run: /bin/bash -p scripts/verify-tracked-index.sh .",
  "",
  "      - name: Install exact Node runtime",
  "        uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0",
  "        with:",
  `          node-version: ${identity.runtime.nodeVersion}`,
  "",
  "      - name: Verify exact Node runtime",
  "        run: |",
  '          test "$(uname -s):$(uname -m)" = "Linux:x86_64"',
  '          node_path="$(command -v node)"',
  '          test -f "$node_path" && test ! -L "$node_path" && test -x "$node_path"',
  '          expected_sha="$(sed -nE \'s/^[[:space:]]*"nodeLinuxX64SHA256": "([a-f0-9]{64})",?$/\\1/p\' Config/ReleaseIdentity.json)"',
  '          test "${#expected_sha}" -eq 64',
  '          test "$(sha256sum "$node_path" | awk \'{ print $1 }\')" = "$expected_sha"',
  `          test "$("$node_path" --version)" = "v${identity.runtime.nodeVersion}"`,
  "",
  "      - name: Require reviewed acknowledgement of every monitored DSH channel",
  "        run: node scripts/check-dsh-upstream.mjs",
  ""
].join("\n");
if (upstreamDSHWorkflow !== expectedUpstreamDSHWorkflow) {
  fail("scheduled upstream DSH workflow drifted from its reviewed read-only observer contract");
}
const minimumMacOSMajor = identity.minimumMacOS.split(".", 1)[0];
const packageManifest = read("Package.swift");
if (!packageManifest.includes(`.macOS(.v${minimumMacOSMajor})`)) {
  fail("Package.swift deployment target does not match the release identity");
}

const vendorPatchManifest = JSON.parse(read("Config/VendorRuntimePatches.json"));
if (vendorPatchManifest.schemaVersion !== 1 || vendorPatchManifest.patches?.length !== 13) {
  fail("vendored runtime patch manifest is missing or unsupported");
}
const vendorMaterializer = read("scripts/materialize-vendor-runtime.mjs");
for (const expected of [
  "--ignore-scripts",
  "NPM_CONFIG_USERCONFIG: npmConfiguration",
  "NPM_CONFIG_GLOBALCONFIG: npmGlobalConfiguration",
  "NPM_CONFIG_CACHE: npmCache",
  "--replace-registry-host=never",
  'PATH: "/usr/bin:/bin:/usr/sbin:/sbin"',
  "HOME: npmHome",
  "TMPDIR: npmTemporary",
  "validateInstalledTopology",
  "assertHash(patched, patch.afterSHA256"
]) {
  if (!vendorMaterializer.includes(expected)) fail(`public runtime materializer is missing ${expected}`);
}
const nodeBootstrap = read("scripts/fetch-node-runtime.sh");
const bootstrapVersion = /^VERSION="([^"]+)"$/mu.exec(nodeBootstrap)?.[1];
const bootstrapExecutableSHA = /^EXPECTED_EXECUTABLE_SHA256="([0-9a-f]{64})"$/mu.exec(nodeBootstrap)?.[1];
if (bootstrapVersion !== identity.runtime.nodeVersion
    || bootstrapExecutableSHA !== identity.runtime.nodeSHA256) {
  fail("public Node bootstrap identity does not match the release identity");
}
for (const expected of [
  "mktemp -d /private/tmp/fulmar-node-bootstrap.XXXXXX",
  'mktemp -d "$VENDOR/.node-bootstrap.XXXXXX"',
  "--proto '=https'",
  "--tlsv1.2",
  "--noproxy '*'",
  "--proxy ''",
  "/usr/bin/curl --disable",
  "--no-same-owner",
  "EXPECTED_EXECUTABLE_SHA256",
  "existing pinned Node executable checksum is not reviewed",
  '/bin/mv -n "$EXTRACTED" "$DESTINATION"'
]) {
  if (!nodeBootstrap.includes(expected)) fail(`public Node bootstrap is missing ${expected}`);
}
const publicBootstrap = read("scripts/bootstrap-source-checkout.sh");
for (const expected of ["/usr/bin/env -i", "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "run_pinned_node", "verify-prefix"]) {
  if (!publicBootstrap.includes(expected)) fail(`public source bootstrap is missing ${expected}`);
}

const plist = read("Resources/Info.plist");
const plistValue = (key) => {
  const marker = `<key>${key}</key>`;
  const markerOffset = plist.indexOf(marker);
  if (markerOffset < 0 || plist.indexOf(marker, markerOffset + marker.length) >= 0) return undefined;
  const following = plist.slice(markerOffset + marker.length);
  return /^\s*<string>([^<]+)<\/string>/u.exec(following)?.[1];
};
if (plistValue("CFBundleDisplayName") !== identity.productDisplayName) fail("Info.plist display name drifted");
if (plistValue("CFBundleName") !== identity.productDisplayName) fail("Info.plist bundle name drifted");
if (plistValue("CFBundleIdentifier") !== identity.bundleIdentifier) fail("Info.plist bundle identifier drifted");
if (plistValue("CFBundleShortVersionString") !== identity.appVersion) fail("Info.plist version drifted");
if (Number(plistValue("CFBundleVersion")) !== identity.appBuild) fail("Info.plist build drifted");
if (plistValue("LSMinimumSystemVersion") !== identity.minimumMacOS) fail("Info.plist minimum macOS drifted");

const machoVerifier = read("scripts/verify-macho-compatibility.sh");
for (const expected of ["LC_BUILD_VERSION", "LC_VERSION_MIN_MACOSX", "lipo -archs", "minimum_code <= declared_minimum_code"]) {
  if (!machoVerifier.includes(expected)) fail(`Mach-O compatibility gate is missing ${expected}`);
}
for (const releaseScript of ["scripts/build-app.sh", "scripts/verify-release.sh", "scripts/prepare-public-release-assets.sh", "scripts/verify-public-distribution.sh"]) {
  if (!read(releaseScript).includes("verify-macho-compatibility.sh")) {
    fail(`${releaseScript} does not enforce the bundled Mach-O compatibility gate`);
  }
  if (!read(releaseScript).includes("verify-xpc-service-info.mjs")) {
    fail(`${releaseScript} does not enforce the exact credential XPC Info.plist schema`);
  }
}
for (const credentialVerifier of [
  "scripts/verify-credential-migration-xpc.sh",
  "scripts/verify-credential-broker-xpc.sh"
]) {
  if (!read(credentialVerifier).includes("verify-xpc-service-info.mjs")) {
    fail(`${credentialVerifier} does not enforce the exact credential XPC Info.plist schema`);
  }
}
const publicAssetPreparation = read("scripts/prepare-public-release-assets.sh");
for (const expected of [
  "source-build-input-inventory.mjs",
  "verify-static-security-summary.mjs",
  "verify-dependency-audit.mjs",
  "verify-retained-release-evidence.mjs",
  "EXPECTED_CANDIDATE_SHA256",
  "EXPECTED_CANDIDATE_VERSION",
  "EXPECTED_CANDIDATE_BUILD",
  "verify_expected_candidate_binding"
]) {
  if (!publicAssetPreparation.includes(expected)) fail(`public asset preparation is missing ${expected}`);
}
const publicDistributionVerification = read("scripts/verify-public-distribution.sh");
for (const expected of [
  "source-build-input-inventory.mjs",
  "verify-static-security-summary.mjs",
  "verify-dependency-audit.mjs",
  "verify-retained-release-evidence.mjs",
  "verify-notarization-evidence.mjs",
  "verify-public-external-evidence.mjs"
]) {
  if (!publicDistributionVerification.includes(expected)) fail(`public distribution verification is missing ${expected}`);
}
const publicReleaseOperator = read("scripts/run-public-release.sh");
for (const expected of [
  "LOCAL_HARNESS_SIGN_IDENTITY",
  "LOCAL_HARNESS_SIGNING_KEYCHAIN",
  "LOCAL_HARNESS_NOTARY_PROFILE",
  "LOCAL_HARNESS_SIGN_TIMESTAMP=1",
  "security find-identity -v -p codesigning",
  "retain-release-verification.sh",
  "verify-retained-release-evidence.mjs",
  "verify-notarization-evidence.mjs",
  "verify-release-tree.mjs",
  'xcrun stapler validate "$archived_app"',
  "verify-public-external-evidence.mjs",
  "prepare-public-release-assets.sh",
  "verify-public-distribution.sh",
  "make public-release-finalize",
  "Do not rebuild",
  "FULMAR_PUBLIC_RELEASE_TEST_SEAM",
  "fulmar-public-release-test.*",
  "run-public-release-test-seam.zsh"
]) {
  if (!publicReleaseOperator.includes(expected)) fail(`public release operator is missing ${expected}`);
}
if (publicReleaseOperator.indexOf("verify-public-external-evidence.mjs")
    >= publicReleaseOperator.lastIndexOf("prepare-public-release-assets.sh")
    || publicReleaseOperator.lastIndexOf("prepare-public-release-assets.sh")
      >= publicReleaseOperator.lastIndexOf("verify-public-distribution.sh")) {
  fail("public release operator does not close external evidence before final packaging and verification");
}
if (!/prepare-public-release-assets\.sh" \\\n+    "\$ARCHIVE" "\$MANIFEST" "\$PUBLIC_ASSETS" \\\n+    "\$CANDIDATE_SHA256" "\$CANDIDATE_VERSION" "\$CANDIDATE_BUILD"/u.test(publicReleaseOperator)) {
  fail("public release operator does not candidate-bind public asset preparation");
}
if ((publicAssetPreparation.match(/verify_expected_candidate_binding "\$MANIFEST" "\$ARCHIVE"/gu) ?? []).length !== 2
    || !/verify_expected_candidate_binding "\$MANIFEST" "\$ARCHIVE"\n"\$ATOMIC_PUBLISHER" publish/u.test(publicAssetPreparation)) {
  fail("public asset preparation does not rebind the expected live candidate before snapshot and atomic publication");
}
const makefile = read("Makefile");
if (!/^public-release: dsh-promotion-provenance-verify\n\t\/bin\/zsh -f scripts\/run-public-release\.sh$/mu.test(makefile)
    || !/^public-release-finalize: dsh-promotion-provenance-verify\n\t\/bin\/zsh -f scripts\/run-public-release\.sh --finalize$/mu.test(makefile)) {
  fail("Makefile does not expose the exact two-phase public release operator");
}

// Public onboarding must describe the same owner-selected licence state enforced by
// the byte-bound policy. This catches stale pre-selection copy that would otherwise
// pass the licence verifier while misleading reviewers and contributors.
for (const relative of [
  "CONTRIBUTING.md",
  ".github/PULL_REQUEST_TEMPLATE.md",
  "docs/BRAND_AND_RELEASE_IDENTITY.md",
  "docs/GETTING_STARTED.md"
]) {
  const document = read(relative);
  if (!document.includes("MIT License")) {
    fail(`${relative} does not identify the owner-selected MIT License`);
  }
  for (const stale of [
    "repository currently has no project licence",
    "No terms have been selected"
  ]) {
    if (document.includes(stale)) fail(`${relative} contains stale no-licence release copy`);
  }
  if (/lacks Developer ID signing, Apple notarization, clean-Mac release\s+qualification, a project licence/u.test(document)) {
    fail(`${relative} contains stale no-licence release copy`);
  }
}
const gettingStarted = read("docs/GETTING_STARTED.md");
for (const expected of ["semgrep==1.135.0", "semgrep --version", "make build"]) {
  if (!gettingStarted.includes(expected)) fail(`source-build guide is missing ${expected}`);
}

// These runtime bridges surface their errors directly in the conversation or
// native approval UI. Keep legacy storage/security identifiers unchanged, but
// never leak the retired product name through user-visible runtime copy.
for (const relative of [
  "Resources/RuntimeSecurityPreload.mjs",
  "Resources/DSHPlugins/client-security-bridge/client.js",
  "Resources/DSHPlugins/mcp-guarded/guarded-runtime.mjs",
  "Resources/DSHPlugins/performance-profile/index.mjs"
]) {
  const visibleCopy = read(relative).match(/(?:Error\(|throw new Error\()[\s\S]{0,160}Local Harness/u);
  if (visibleCopy) {
    fail(`${relative} contains the retired user-visible product name`);
  }
}

// Keep only intentional legacy storage, bundle, executable, and compatibility
// identifiers. These three surfaces are shown directly to people by macOS or
// by the export panel and must carry the current product identity.
const sandboxRunner = read("Tools/SandboxRunner/main.swift");
for (const expected of [
  "fulmar-sandbox-runner:",
  "permission denied by Fulmar tool sandbox"
]) {
  if (!sandboxRunner.includes(expected)) fail(`sandbox diagnostic branding is missing ${expected}`);
}
for (const retired of [
  "local-harness-sandbox-runner:",
  "permission denied by Local Harness sandbox"
]) {
  if (sandboxRunner.includes(retired)) fail(`sandbox diagnostic still exposes ${retired}`);
}

const conversationExporter = read("Sources/LocalHarness/ConversationExporter.swift");
if (!conversationExporter.includes('return "fulmar-\\(label)-\\(timestamp).\\(format.pathExtension)"')) {
  fail("conversation export suggestions do not use the Fulmar filename prefix");
}
if (conversationExporter.includes('return "local-harness-\\(label)-')) {
  fail("conversation export suggestions still expose the retired product name");
}

const downloadStager = read("Sources/LocalHarness/SecureDownloadStager.swift");
if (!downloadStager.includes('let value = "0083;\\(timestamp);\\(ProductBrand.displayName);\\(origin)"')) {
  fail("download quarantine metadata is not derived from the visible product identity");
}
if (/0083;[^\n]*Local Harness/u.test(downloadStager)) {
  fail("download quarantine metadata still exposes the retired product name");
}

const mainToolbar = read("Sources/LocalHarness/HarnessWindowController.swift");
for (const expected of [
  'NSToolbar(identifier: "Fulmar.MainToolbar.v2")',
  "toolbar.allowsUserCustomization = false",
  "toolbar.autosavesConfiguration = false",
  "toolbar.isVisible = true"
]) {
  if (!mainToolbar.includes(expected)) fail(`main toolbar migration is missing ${expected}`);
}

const appSource = read("Sources/LocalHarness/LocalHarnessApp.swift");
const shortcutCatalog = read("Sources/LocalHarness/MainMenuShortcutCatalog.swift");
for (const [title, action] of [
  ["Settings…", "showSettings"],
  ["New Session", "newSession"],
  ["Chat", "showQuickChat"],
  ["Command Center…", "showCommandCenter"]
]) {
  const escapedTitle = title.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  const catalogContract = new RegExp(`command\\([^\\n]+,\\s*"${escapedTitle}",\\s*#selector\\(AppDelegate\\.${action}\\(_:\\)\\)`, "u");
  if (!catalogContract.test(shortcutCatalog)) fail(`shortcut catalog item ${title} is not wired to ${action}`);
}
for (const [title, action] of [
  ['"About \\(ProductBrand.displayName)"', "showAbout"],
  ['"Models & Providers"', "showProviderCenter"],
  ['"\\(ProductBrand.displayName) Diagnostics"', "showDiagnostics"],
  ['"DeepSeek Harness Project"', "openHarnessProject"],
  ['"Open \\(ProductBrand.displayName)"', "showMainWindow"]
]) {
  const escapedTitle = title.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  const menuContract = new RegExp(`title:\\s*${escapedTitle},\\s*action:\\s*#selector\\(${action}\\(_:\\)\\)`, "u");
  if (!menuContract.test(appSource)) fail(`main/status menu item ${title} is not wired to ${action}`);
}
if (/title:\s*"Install Verified Update…",\s*action:\s*#selector\(installVerifiedUpdate\(_:\)\)/u.test(appSource)) {
  fail("the unqualified launch-only updater is still exposed in a public menu");
}
if (!appSource.includes("private static let verifiedInAppUpdatesEnabled = false")
    || !appSource.includes("guard Self.verifiedInAppUpdatesEnabled else {")) {
  fail("the unfinished in-app updater is not hard-disabled at its programmatic boundary");
}
if (!appSource.includes('withTitle: "Quit \\(ProductBrand.displayName)", action: #selector(NSApplication.terminate(_:))')) {
  fail("the Fulmar Quit item is not wired to application termination");
}

const releaseLabel = `Fulmar ${identity.appVersion} build ${identity.appBuild}`;
for (const relative of [
  "docs/ARCHITECTURE.md",
  "docs/DELIVERY_PLAN.md",
  "docs/OPERATIONS.md",
  "docs/PRIVACY.md",
  "docs/PRODUCT_SPEC.md",
  "docs/RAID.md",
  "docs/RELEASE_CHECKLIST.md",
  "docs/TEST_PLAN.md",
  "docs/THERMAL_SAFETY.md",
  "docs/THREAT_MODEL.md",
  "docs/UPDATE_AND_ROLLBACK.md",
  "docs/VENDORED_PATCHES.md"
]) {
  const heading = read(relative).split(/\r?\n/, 1)[0];
  if (!heading.includes(releaseLabel)) fail(`${relative} does not identify ${releaseLabel}`);
}

const readme = read("README.md");
if (!readme.includes(`The ${identity.appVersion} candidate is build ${identity.appBuild}.`)) {
  fail("README candidate identity drifted");
}
const updateAndRollback = read("docs/UPDATE_AND_ROLLBACK.md");
const privateInstallBuilds = [...updateAndRollback.matchAll(/^## Qualified private update to build (\d+)$/gmu)]
  .map((match) => Number(match[1]));
if (privateInstallBuilds.length !== 1 || privateInstallBuilds[0] !== identity.appBuild) {
  fail("private update installation build drifted");
}
for (const expected of [
  "make private-install-qualified",
  "make private-rollback-status",
  "make private-recovery-resume",
  "make private-recovery-finalize",
  "make private-recovery-cancel",
  "make private-recovery-reconcile",
  "make private-rollback-retire",
  "/Applications/Fulmar.app",
  "/Applications/.Fulmar.install-stage.<nonce>.app"
]) {
  if (!updateAndRollback.includes(expected)) fail(`private update workflow is missing ${expected}`);
}
for (const expected of [
  "Fast is 32K context / 4K output",
  "Balanced is 48K / 8K",
  "Deep is 64K / 16K",
  "| Fast | 32,768 | 4,096 |",
  "| Balanced | 49,152 | 8,192 |",
  "| Deep | 65,536 | 16,384 |"
]) {
  if (!readme.includes(expected)) fail(`README is missing current profile text: ${expected}`);
}

const productSpec = read("docs/PRODUCT_SPEC.md");
const operations = read("docs/OPERATIONS.md");
for (const stale of ["Fast 16K", "Balanced 32K", "Balanced · 32K", "Fast · 16K"]) {
  if (productSpec.includes(stale) || operations.includes(stale)) fail(`active documentation still contains ${stale}`);
}

const runtimePackage = JSON.parse(read("VendorRuntime/node_modules/@deepseek-ai/dsh/package.json"));
if (runtimePackage.version !== identity.runtime.deepseekHarnessVersion) fail("pinned DSH version drifted");
const mcpPackage = JSON.parse(read("VendorRuntime/node_modules/@deepseek-ai/dsh-mcp-client/package.json"));
if (mcpPackage.version !== identity.runtime.deepseekMCPClientVersion) fail("pinned DSH MCP client version drifted");

const capabilities = read("Sources/LocalHarness/ModelCapabilityCatalog.swift");
for (const model of ["deepseek-v4-flash", "deepseek-v4-pro", "deepseek-v4-flash-vision-exp"]) {
  if (!capabilities.includes(`ModelID(\"${model}\")`)) fail(`reviewed DeepSeek model contract is missing ${model}`);
}

const auxiliaryRouting = read("Sources/LocalHarness/AuxiliaryCapabilityRouting.swift");
for (const contract of [
  "enum AuxiliaryCapability",
  "struct AuxiliaryCapabilityRoute",
  "struct AuxiliaryCapabilityConsentGrant",
  "enum AuxiliaryCapabilityEgressPolicy",
  "ProviderNetworkOrigin.isLocalAddress",
  "matches.count <= 1"
]) {
  if (!auxiliaryRouting.includes(contract)) fail(`auxiliary capability isolation is missing ${contract}`);
}
if (auxiliaryRouting.includes("ProviderConsentState")) {
  fail("auxiliary capability routing must not accept conversation-provider consent");
}
const runtimePatch = read("Resources/LocalHarness.patch.yml");
for (const contract of [
  "fetchProvider: fulmar-approved-fetch",
  "name: '@local-harness/dsh-web-fetch-safe'",
  "search: false",
  "fetch: true",
  "fulmar-sandbox-runner:"
]) {
  if (!runtimePatch.includes(contract)) fail(`approved page-fetch product contract is missing ${contract}`);
}
if (!/- id: web-search-deepseek\s+disabled: true/u.test(runtimePatch)) {
  fail("local sessions must not expose unavailable DeepSeek web search");
}
const harnessController = read("Sources/LocalHarness/HarnessController.swift");
if (!harnessController.includes("static let ownedOllamaReadinessTimeout: TimeInterval = 90")) {
  fail("owned Ollama readiness budget must tolerate warm macOS resource reclamation");
}
for (const leaseContract of [
  'appendingPathComponent("LocalHarnessRuntimeLease")',
  'arguments: ["--fulmar-runtime-auth-stdin-v1", runtime.node.path] + nodeArguments',
  "process.standardInput = authenticationInput",
  "leaseIdentity: RuntimeLaunchPathIdentity"
]) {
  if (!harnessController.includes(leaseContract)) fail(`runtime parent-death lease is missing ${leaseContract}`);
}
for (const forbiddenEnvironmentSecret of [
  '"LOCAL_HARNESS_AUTH_TOKEN":',
  '"LOCAL_HARNESS_INSTANCE_NONCE":'
]) {
  if (harnessController.includes(forbiddenEnvironmentSecret)) {
    fail(`runtime launch must not publish private authentication through the environment: ${forbiddenEnvironmentSecret}`);
  }
}
const runtimeSecurity = read("Sources/LocalHarness/RuntimeSecurity.swift");
for (const authenticationContract of [
  'final class RuntimeAuthenticationInput',
  'before.st_nlink == 0',
  'after.st_nlink == 0',
  'Darwin.fcntl(descriptor, F_SETFD, FD_CLOEXEC)',
  'func takeForLaunch() throws -> FileHandle'
]) {
  if (!runtimeSecurity.includes(authenticationContract)) {
    fail(`runtime authentication descriptor is missing ${authenticationContract}`);
  }
}
const runtimePreload = read("Resources/RuntimeSecurityPreload.mjs");
for (const authenticationContract of [
  'fs.fstatSync(0, { bigint: true })',
  'before.nlink !== 0n',
  'fs.readSync(0, bytes',
  'fs.closeSync(0)'
]) {
  if (!runtimePreload.includes(authenticationContract)) {
    fail(`runtime preloader authentication consumer is missing ${authenticationContract}`);
  }
}
if (/const\s+(?:token|nonce)\s*=\s*process\.env\.LOCAL_HARNESS_/u.test(runtimePreload)) {
  fail("runtime preloader must not obtain private authentication from the child environment");
}
const runtimeLease = read("Tools/RuntimeLease/main.swift");
for (const leaseContract of [
  "DispatchSource.makeProcessSource",
  "Darwin.setpgid(0, 0)",
  "Darwin.kill(exactGroup, SIGTERM)",
  "Darwin.kill(exactGroup, SIGKILL)",
  "validateRuntimeAuthenticationInput()",
  "CommandLine.unsafeArgv.advanced(by: targetIndex)"
]) {
  if (!runtimeLease.includes(leaseContract)) fail(`runtime lease implementation is missing ${leaseContract}`);
}
const presetSanitizer = read("scripts/sanitize-agent-presets.mjs");
for (const contract of [
  'replaceSingleTopLevelRow(composition, "tool-web", approvedWebToolRow)',
  '"    search: false"',
  '"    fetch: true"',
  '"name: Fulmar Standard"'
]) {
  if (!presetSanitizer.includes(contract)) fail(`sanitized local-agent web contract is missing ${contract}`);
}
const commandCenter = read("Sources/LocalHarness/CommandCenterWindowController.swift");
for (const feature of ["Chat", "Agent Workspace", "Models & Providers", "Privacy Dashboard", "Diagnostics"]) {
  if (!read("Sources/LocalHarness/LocalHarnessApp.swift").includes(`title: \"${feature}\"`)) {
    fail(`Command Center is missing ${feature}`);
  }
}
if (!commandCenter.includes("terms.allSatisfy") || !commandCenter.includes("setAccessibilityLabel")) {
  fail("Command Center search/accessibility contract drifted");
}
if (!commandCenter.includes('window.subtitle = "Everything in \\(ProductBrand.displayName)"')) {
  fail("Command Center subtitle must render the product name instead of a literal interpolation token");
}

process.stdout.write(`Source product contract passed for ${releaseLabel}; DSH ${identity.runtime.deepseekHarnessVersion}.\n`);
