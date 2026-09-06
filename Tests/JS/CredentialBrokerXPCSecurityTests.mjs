import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

const root = process.cwd();
const source = (...parts) => readFile(join(root, ...parts), "utf8");

test("packaged credential CRUD crosses one mutually pinned private XPC boundary", async () => {
  const [protocol, client, service, helper] = await Promise.all([
    source("Sources", "CredentialBrokerXPCProtocol", "CredentialBrokerXPCProtocol.swift"),
    source("Tools", "CredentialHelper", "CredentialBrokerClient.swift"),
    source("Tools", "CredentialBrokerService", "main.swift"),
    source("Tools", "CredentialHelper", "main.swift")
  ]);

  assert.match(protocol, /request: NSData,[\s\S]*payload: NSData,[\s\S]*input: FileHandle,[\s\S]*output: FileHandle/u);
  assert.match(protocol, /maximumRequestBytes[\s\S]*maximumCredentialBytes[\s\S]*maximumResponsePayloadBytes/u);
  assert.match(protocol, /Set\(root\.keys\) == \[[\s\S]*acceptanceNonce[\s\S]*deadlineNanoseconds[\s\S]*version/u);
  assert.match(protocol, /canonical == data/u);
  assert.match(client, /connection\.setCodeSigningRequirement\(serviceIdentity\.exactRequirement\)/u);
  assert.match(service, /connection\.setCodeSigningRequirement\(helperRequirement\)/u);
  assert.match(client, /designatedRequirement == serviceIdentity\.designatedRequirement/u);
  assert.match(service, /serviceIdentity\.designatedRequirement == helperIdentity\.designatedRequirement/u);
  assert.match(client, /and cdhash H/u);
  assert.match(service, /and cdhash H/u);
  assert.match(helper, /dispatchCredentialBrokerCommandIfNeeded\(command: command, arguments: arguments\)/u);
  assert.match(helper, /exactPackagedApplicationIsImmediateParent/u);
  assert.match(helper, /SecCodeCopyGuestWithAttributes\(nil, attributes/u);
  assert.match(helper, /proc_pidpath\(parent/u);
  assert.match(
    helper,
    /backup-authorize-existing[\s\S]*guard exactPackagedApplicationIsImmediateParent\(\)[\s\S]*runBackupAuthenticationKeyForegroundAuthorization/u
  );
  assert.match(
    helper,
    /\["authorize", "repair-adopt"[\s\S]*guard exactPackagedApplicationIsImmediateParent\(\)[\s\S]*runForegroundCredentialOperation/u
  );
  assert.match(client, /#if DEBUG[\s\S]*return[\s\S]*#else[\s\S]*brokerClientFail\(\.invalidBundle\)/u);
  assert.match(service, /CredentialPrivateDirectory\.prepareMetadataDirectoryCapability/u);
  assert.match(service, /CredentialTransactionCoordinator/u);
  assert.match(service, /interactionNotAllowed = true/u);
  assert.doesNotMatch(service, /Process\(|posix_spawn|execv|\/Runtime\/node|JavaScriptCore|WebKit|Network/u);
});

test("broker transaction and byte-buffer unavailable states fail closed without traps", async () => {
  const [service, helper, migration, protocolTests] = await Promise.all([
    source("Tools", "CredentialBrokerService", "main.swift"),
    source("Tools", "CredentialHelper", "main.swift"),
    source("Tools", "CredentialMigrationService", "main.swift"),
    source("Tests", "LocalHarnessTests", "CredentialBrokerXPCProtocolTests.swift")
  ]);

  assert.match(service, /let transaction: CredentialTransactionCoordinator\?[\s\S]*guard let transaction else \{ throw BrokerError\.internalFailure \}/u);
  assert.doesNotMatch(service, /transaction!|baseAddress!|try!|fatalError/u);
  assert.doesNotMatch(helper, /baseAddress!|try!|fatalError/u);
  assert.doesNotMatch(migration, /baseAddress!|try!|fatalError/u);
  for (const text of [service, helper, migration]) {
    for (const occurrence of text.matchAll(/SecRandomCopyBytes\([^\n]+/gu)) {
      assert.doesNotMatch(occurrence[0], /!/u);
    }
  }
  assert.match(service, /guard storage\.count == 32, let baseAddress = storage\.baseAddress else/u);
  assert.match(helper, /guard storage\.count == 32, let baseAddress = storage\.baseAddress else/u);
  assert.match(migration, /guard storage\.count == 32, let baseAddress = storage\.baseAddress else/u);
  assert.match(protocolTests, /responseRejectsUnavailableOrAmbiguousWireStates/u);
  assert.match(protocolTests, /internalFailure/u);
});

test("broker release assembly is sandboxed, signed, verified, and has a bounded nonsecret canary", async () => {
  const [manifest, build, release, verifier, live, processMonitor, plist, entitlements, service, directory, helperVerifier, bootstrap] = await Promise.all([
    source("Package.swift"),
    source("scripts", "build-app.sh"),
    source("scripts", "verify-release.sh"),
    source("scripts", "verify-credential-broker-xpc.sh"),
    source("scripts", "verify-credential-broker-xpc-live.sh"),
    source("scripts", "credential-xpc-live-process-monitor.mjs"),
    source("Resources", "CredentialBrokerService-Info.plist"),
    source("Resources", "CredentialBrokerService.entitlements"),
    source("Tools", "CredentialBrokerService", "main.swift"),
    source("Sources", "CredentialSecurity", "CredentialPrivateDirectory.swift"),
    source("scripts", "verify-credential-helper.sh"),
    source("scripts", "credential-application-support-bootstrap.swift")
  ]);

  assert.match(manifest, /name: "LocalHarnessCredentialBrokerService"/u);
  assert.match(build, /BROKER_XPC_DIR="\$XPC_SERVICES_DIR\/LocalHarnessCredentialBrokerService\.xpc"/u);
  assert.match(build, /CredentialBrokerService\.entitlements/u);
  assert.match(release, /verify-credential-broker-xpc\.sh/u);
  assert.match(release, /verify-credential-broker-xpc-live\.sh/u);
  assert.match(verifier, /_posix_spawn[\s\S]*_execve[\s\S]*_system/u);
  assert.match(verifier, /CredentialBrokerService\.entitlements/u);
  assert.match(live, /TIMEOUT_SECONDS=15/u);
  assert.match(live, /broker-acceptance/u);
  assert.match(live, /FULMAR_CREDENTIAL_BROKER_ACCEPTANCE_OK/u);
  assert.match(live, /credential-xpc-live-process-monitor\.mjs/u);
  assert.match(live, /service\.evidence/u);
  assert.match(live, /ROOT_IDENTITY/u);
  assert.match(processMonitor, /sameIdentity/u);
  assert.match(processMonitor, /exactTextIdentity/u);
  assert.match(processMonitor, /candidate\.device === reviewedExecutableIdentity\.device/u);
  assert.match(processMonitor, /candidate\.inode === reviewedExecutableIdentity\.inode/u);
  assert.doesNotMatch(processMonitor, /pkill|killall|pgrep/u);
  assert.doesNotMatch(live, /DEEPSEEK_API_KEY|OLLAMA_API_KEY|app\.localharness\.credentials/u);
  assert.match(service, /UUID\(uuidString: nonce\)/u);
  assert.match(service, /credential-broker-acceptance/u);
  assert.match(service, /O_CREAT \| O_EXCL \| O_NOFOLLOW/u);
  assert.match(service, /SecItemDelete\(cleanupQuery/u);
  assert.match(plist, /<string>XPC!<\/string>/u);
  assert.match(entitlements, /com\.apple\.security\.app-sandbox[\s\S]*<true\/>/u);
  assert.match(entitlements, /CredentialMetadata\//u);
  assert.doesNotMatch(entitlements, /network\.client|network\.server|files\.user-selected/u);
  assert.match(directory, /open\(home\.path, O_SEARCH \| O_DIRECTORY \| O_NOFOLLOW \| O_CLOEXEC\)/u);
  assert.match(directory, /access: index == components\.count - 1 \? O_RDONLY : O_SEARCH/u);
  assert.match(directory, /openat\(parent, \$0, access \| O_DIRECTORY \| O_NOFOLLOW \| O_CLOEXEC\)/u);
  assert.match(helperVerifier, /credential-application-support-bootstrap\.swift[\s\S]*userInfo\(\)\.homedir[\s\S]*admit-application-support[\s\S]*verify-credential-helper-bounds\.mjs/u);
  assert.match(bootstrap, /ApplicationSupportRootAdmission\(url: url\)[\s\S]*admission\.admit\(\)/u);
  assert.doesNotMatch(bootstrap, /SecItem|SecKeychain|chmod\(|FileManager\.default\.createDirectory/u);
});
