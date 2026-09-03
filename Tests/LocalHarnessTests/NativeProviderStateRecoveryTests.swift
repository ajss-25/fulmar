import Darwin
import Foundation
import Testing
@testable import LocalHarness

private enum NativeResetPermitTestError: Error {
    case revoked
}

private func recoveryFixture() throws -> (UserDefaults, String, URL, NativeProviderStateRecovery) {
    let suite = "NativeProviderStateRecoveryTests-\(UUID().uuidString)"
    let defaults = try #require(UserDefaults(suiteName: suite))
    defaults.removePersistentDomain(forName: suite)
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("native-provider-recovery-\(UUID().uuidString)", isDirectory: true)
        .resolvingSymlinksInPath().standardizedFileURL
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
    return (
        defaults,
        suite,
        root,
        NativeProviderStateRecovery(
            defaults: defaults,
            applicationSupport: root,
            uuid: { UUID(uuidString: "00000000-0000-4000-8000-000000000001")! }
        )
    )
}

private func replaceRecoveryArchivePreservingSizeAndModificationTime(
    _ archive: NativeProviderStateRecoveryArchive,
    with replacement: Data
) throws {
    #expect(replacement.count == archive.byteCount)
    var original = stat()
    #expect(Darwin.lstat(archive.url.path, &original) == 0)
    let staged = archive.url.deletingLastPathComponent().appendingPathComponent(
        ".replacement-\(UUID().uuidString)",
        isDirectory: false
    )
    try replacement.write(to: staged, options: .withoutOverwriting)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: staged.path)
    let timestamps = [original.st_atimespec, original.st_mtimespec]
    let timestampResult = staged.path.withCString { path in
        timestamps.withUnsafeBufferPointer { values in
            Darwin.utimensat(AT_FDCWD, path, values.baseAddress, AT_SYMLINK_NOFOLLOW)
        }
    }
    #expect(timestampResult == 0)
    #expect(Darwin.rename(staged.path, archive.url.path) == 0)

    var installed = stat()
    #expect(Darwin.lstat(archive.url.path, &installed) == 0)
    #expect(installed.st_size == original.st_size)
    #expect(installed.st_mtimespec.tv_sec == original.st_mtimespec.tv_sec)
    #expect(installed.st_mtimespec.tv_nsec == original.st_mtimespec.tv_nsec)
    #expect(installed.st_dev != original.st_dev || installed.st_ino != original.st_ino)
}

@Suite(.serialized)
struct NativeProviderStateRecoveryTests {
    @Test func revokedLifecyclePermitStopsImmediatelyBeforeProviderNamespaceCommit() throws {
        let (defaults, suite, root, recovery) = try recoveryFixture()
        defer {
            defaults.removePersistentDomain(forName: suite)
            try? FileManager.default.removeItem(at: root)
        }
        let corrupt = Data("retain-corrupt-provider-state".utf8)
        defaults.set(corrupt, forKey: ModelProviderSettingsStore.settingsKey)
        let inspection = recovery.inspect()
        var validations = 0

        #expect(throws: NativeResetPermitTestError.revoked) {
            try recovery.resetAfterExplicitConfirmation(
                expected: inspection,
                validateBeforeCommit: {
                    validations += 1
                    throw NativeResetPermitTestError.revoked
                }
            )
        }

        #expect(validations == 1)
        #expect(defaults.data(forKey: ModelProviderSettingsStore.settingsKey) == corrupt)
        #expect(recovery.inspect() == inspection)
    }

    @Test func corruptAndFutureDocumentsAreTypedQuarantinedExactlyAndResetOnlyAfterConfirmation() throws {
        let (defaults, suite, root, recovery) = try recoveryFixture()
        defer {
            defaults.removePersistentDomain(forName: suite)
            try? FileManager.default.removeItem(at: root)
        }
        let corruptSettings = Data("not-json-but-preserve-me-exactly".utf8)
        let futureConsent = Data(#"{"schemaVersion":99,"activeProvider":null,"grants":[]}"#.utf8)
        defaults.set(corruptSettings, forKey: ModelProviderSettingsStore.settingsKey)
        defaults.set(futureConsent, forKey: ProviderConsentStore.stateKey)

        let inspection = recovery.inspect()
        #expect(inspection.issues.count == 2)
        #expect(inspection.issues.contains {
            $0.document == .modelSettings && $0.kind == .corrupt
                && $0.fingerprint.byteCount == corruptSettings.count
        })
        #expect(inspection.issues.contains {
            $0.document == .providerConsent
                && $0.kind == .futureSchema(
                    found: 99,
                    supported: ProviderConsentState.currentSchemaVersion
                )
        })
        #expect(defaults.data(forKey: ModelProviderSettingsStore.settingsKey) == corruptSettings)
        #expect(defaults.data(forKey: ProviderConsentStore.stateKey) == futureConsent)

        let receipt = try recovery.resetAfterExplicitConfirmation(expected: inspection)
        #expect(receipt.recoveryDirectory.lastPathComponent == NativeProviderStateRecovery.directoryName)
        #expect(try Data(contentsOf: #require(receipt.quarantinedFiles[.modelSettings])) == corruptSettings)
        #expect(try Data(contentsOf: #require(receipt.quarantinedFiles[.providerConsent])) == futureConsent)
        #expect(try ModelProviderSettingsStore(defaults: defaults).load()?.defaultSelection == .defaultLocal)
        let consent = try ProviderConsentStore(defaults: defaults).load()
        #expect(consent.activeProvider == nil)
        #expect(consent.grants.isEmpty)
        #expect(!recovery.inspect().requiresRecovery)

        for file in receipt.quarantinedFiles.values {
            var metadata = stat()
            #expect(Darwin.lstat(file.path, &metadata) == 0)
            #expect(metadata.st_mode & S_IFMT == S_IFREG)
            #expect(metadata.st_mode & 0o777 == 0o600)
            #expect(metadata.st_nlink == 1)
        }
    }

    @Test func confirmationIsBoundToExactBytesNotOnlyTheSameFailureKind() throws {
        let (defaults, suite, root, recovery) = try recoveryFixture()
        defer {
            defaults.removePersistentDomain(forName: suite)
            try? FileManager.default.removeItem(at: root)
        }
        defaults.set(Data("corrupt-a".utf8), forKey: ModelProviderSettingsStore.settingsKey)
        let inspection = recovery.inspect()
        defaults.set(Data("corrupt-b".utf8), forKey: ModelProviderSettingsStore.settingsKey)

        #expect(throws: NativeProviderStateRecoveryError.stateChanged) {
            try recovery.resetAfterExplicitConfirmation(expected: inspection)
        }
        #expect(defaults.data(forKey: ModelProviderSettingsStore.settingsKey) == Data("corrupt-b".utf8))
    }

    @Test func emptyCorruptDocumentIsQuarantinedAsExactZeroBytesBeforeReset() throws {
        let (defaults, suite, root, recovery) = try recoveryFixture()
        defer {
            defaults.removePersistentDomain(forName: suite)
            try? FileManager.default.removeItem(at: root)
        }
        defaults.set(Data(), forKey: ModelProviderSettingsStore.settingsKey)
        let inspection = recovery.inspect()
        #expect(inspection.issues.first?.kind == .corrupt)

        let receipt = try recovery.resetAfterExplicitConfirmation(expected: inspection)
        let copy = try #require(receipt.quarantinedFiles[.modelSettings])
        #expect(try Data(contentsOf: copy).isEmpty)
        #expect(try recovery.recoveryArchives().first?.byteCount == 0)
        #expect(try ModelProviderSettingsStore(defaults: defaults).load()?.defaultSelection == .defaultLocal)
    }

    @Test func secondConfirmationBoundaryAlsoCoversHugeInvalidStoredTypes() {
        let issue = NativeProviderStateIssue(
            document: .providerConsent,
            kind: .invalidStoredType,
            fingerprint: .init(
                encoding: .binaryPropertyList,
                byteCount: NativeProviderStateRecovery.maximumQuarantineBytes + 1,
                sha256: String(repeating: "a", count: 64)
            )
        )
        #expect(NativeProviderStateRecovery.requiresResetWithoutRecoveryCopy(issue))
    }

    @Test func oversizedInvalidDocumentHasABoundedExactRecoveryPath() throws {
        let (defaults, suite, root, recovery) = try recoveryFixture()
        defer {
            defaults.removePersistentDomain(forName: suite)
            try? FileManager.default.removeItem(at: root)
        }
        let oversized = Data(repeating: 0x78, count: NativeProviderStateRecovery.maximumDocumentBytes + 1)
        defaults.set(oversized, forKey: ModelProviderSettingsStore.settingsKey)
        let inspection = recovery.inspect()
        #expect(inspection.issues.map(\.kind) == [.oversized])

        let receipt = try recovery.resetAfterExplicitConfirmation(expected: inspection)
        #expect(try Data(contentsOf: #require(receipt.quarantinedFiles[.modelSettings])) == oversized)
        #expect(receipt.resetWithoutRecoveryCopy.isEmpty)
        #expect(try ModelProviderSettingsStore(defaults: defaults).load()?.defaultSelection == .defaultLocal)
    }

    @Test func oversizedBeyondRetentionRequiresTwoConfirmationsAndBindsTheExactFingerprint() throws {
        let (defaults, suite, root, recovery) = try recoveryFixture()
        defer {
            defaults.removePersistentDomain(forName: suite)
            try? FileManager.default.removeItem(at: root)
        }
        let byteCount = NativeProviderStateRecovery.maximumQuarantineBytes + 1
        let oversized = Data(repeating: 0x78, count: byteCount)
        let corruptConsent = Data("preserve-consent-exactly".utf8)
        defaults.set(oversized, forKey: ModelProviderSettingsStore.settingsKey)
        defaults.set(corruptConsent, forKey: ProviderConsentStore.stateKey)

        let firstInspection = recovery.inspect()
        #expect(firstInspection.affectedDocuments == Set([.modelSettings, .providerConsent]))
        #expect(firstInspection.issues.first(where: { $0.document == .modelSettings })?.fingerprint.byteCount
            == byteCount)

        // One confirmation is intentionally a no-op for an uncopyable value.
        #expect(throws: NativeProviderStateRecoveryError.oversizedConfirmationRequired) {
            try recovery.resetAfterExplicitConfirmation(expected: firstInspection)
        }
        #expect(defaults.data(forKey: ModelProviderSettingsStore.settingsKey) == oversized)
        #expect(defaults.data(forKey: ProviderConsentStore.stateKey) == corruptConsent)
        #expect(try recovery.recoveryArchives().isEmpty)

        // The second confirmation is tied to the exact type, byte count, and
        // SHA-256. Replacing the bytes with the same failure kind and size is
        // rejected before either native document changes.
        var replacement = oversized
        replacement[replacement.startIndex] = 0x79
        defaults.set(replacement, forKey: ModelProviderSettingsStore.settingsKey)
        #expect(throws: NativeProviderStateRecoveryError.stateChanged) {
            try recovery.resetOversizedAfterExplicitDoubleConfirmation(expected: firstInspection)
        }
        #expect(defaults.data(forKey: ModelProviderSettingsStore.settingsKey) == replacement)
        #expect(defaults.data(forKey: ProviderConsentStore.stateKey) == corruptConsent)
        #expect(try recovery.recoveryArchives().isEmpty)

        let exactSecondInspection = recovery.inspect()
        let receipt = try recovery.resetOversizedAfterExplicitDoubleConfirmation(
            expected: exactSecondInspection
        )
        #expect(receipt.resetWithoutRecoveryCopy == Set([.modelSettings]))
        #expect(Set(receipt.quarantinedFiles.keys) == Set([.providerConsent]))
        #expect(try Data(contentsOf: #require(receipt.quarantinedFiles[.providerConsent])) == corruptConsent)
        #expect(try ModelProviderSettingsStore(defaults: defaults).load()?.defaultSelection == .defaultLocal)
        let consent = try ProviderConsentStore(defaults: defaults).load()
        #expect(consent.activeProvider == nil)
        #expect(consent.grants.isEmpty)
        #expect(!recovery.inspect().requiresRecovery)
    }

    @Test func hostileRecoveryDirectoryPrepopulationFailsWithoutChangingStoredBytes() throws {
        let (defaults, suite, root, recovery) = try recoveryFixture()
        defer {
            defaults.removePersistentDomain(forName: suite)
            try? FileManager.default.removeItem(at: root)
        }
        let corrupt = Data("corrupt".utf8)
        defaults.set(corrupt, forKey: ModelProviderSettingsStore.settingsKey)
        let inspection = recovery.inspect()
        let directory = root.appendingPathComponent(NativeProviderStateRecovery.directoryName, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        try Data("unexpected".utf8).write(to: directory.appendingPathComponent("unexpected-node"))

        #expect(throws: NativeProviderStateRecoveryError.quarantineUnavailable) {
            try recovery.resetAfterExplicitConfirmation(expected: inspection)
        }
        #expect(defaults.data(forKey: ModelProviderSettingsStore.settingsKey) == corrupt)
    }

    @Test func nestedFutureModelSelectionIsReportedWithoutOverwritingIt() throws {
        let (defaults, suite, root, recovery) = try recoveryFixture()
        defer {
            defaults.removePersistentDomain(forName: suite)
            try? FileManager.default.removeItem(at: root)
        }
        let future = Data(#"{"schemaVersion":1,"defaultSelection":{"schemaVersion":7,"route":{"provider":"openai","model":"future"},"reasoningEffort":null,"performanceProfile":"balanced"}}"#.utf8)
        defaults.set(future, forKey: ModelProviderSettingsStore.settingsKey)

        #expect(recovery.inspect().issues.first?.kind == .futureSchema(found: 7, supported: 1))
        #expect(defaults.data(forKey: ModelProviderSettingsStore.settingsKey) == future)
    }

    @Test func validCloudSelectionWithoutMatchingConsentRequiresNoEgressRepairMode() throws {
        let (defaults, suite, root, recovery) = try recoveryFixture()
        defer {
            defaults.removePersistentDomain(forName: suite)
            try? FileManager.default.removeItem(at: root)
        }
        let selection = ModelSelection(
            route: ModelRoute(provider: BuiltInProviderDescriptors.openAI.id, model: ModelID("gpt-test"))
        )
        defaults.set(
            try JSONEncoder().encode(ModelProviderSettings(defaultSelection: selection)),
            forKey: ModelProviderSettingsStore.settingsKey
        )

        let missing = recovery.inspect()
        #expect(missing.issues.isEmpty)
        #expect(missing.routeIssue == .consentUnavailable)
        #expect(missing.requiresRecovery)
        #expect(!missing.permitsStateReset)

        try ProviderConsentStore(defaults: defaults).save(ProviderConsentState())
        #expect(recovery.inspect().routeIssue == .consentUnavailable)

        try ProviderConsentStore(defaults: defaults).activate(BuiltInProviderDescriptors.openAI)
        #expect(!recovery.inspect().requiresRecovery)
    }

    @Test func validLocalSelectionDoesNotRequireAConsentDocument() throws {
        let (defaults, suite, root, recovery) = try recoveryFixture()
        defer {
            defaults.removePersistentDomain(forName: suite)
            try? FileManager.default.removeItem(at: root)
        }
        defaults.set(
            try JSONEncoder().encode(ModelProviderSettings(defaultSelection: .defaultLocal)),
            forKey: ModelProviderSettingsStore.settingsKey
        )
        #expect(!recovery.inspect().requiresRecovery)
    }

    @Test func conflictingConsentGrantsAreTypedInvalidAndNeverChooseAnOrigin() throws {
        let (defaults, suite, root, recovery) = try recoveryFixture()
        defer {
            defaults.removePersistentDomain(forName: suite)
            try? FileManager.default.removeItem(at: root)
        }
        let selection = ModelSelection(
            route: ModelRoute(provider: ProviderID("gateway"), model: ModelID("model"))
        )
        defaults.set(
            try JSONEncoder().encode(ModelProviderSettings(defaultSelection: selection)),
            forKey: ModelProviderSettingsStore.settingsKey
        )
        let duplicateConsent = Data(#"{"schemaVersion":3,"activeProvider":"gateway","grants":[{"provider":"gateway","boundary":"cloud","origin":{"scheme":"https","host":"one.example.test","port":443},"credentialReference":"GATEWAY_API_KEY","explicitlyUnauthenticated":false},{"provider":"gateway","boundary":"cloud","origin":{"scheme":"https","host":"two.example.test","port":443},"credentialReference":"GATEWAY_API_KEY","explicitlyUnauthenticated":false}]}"#.utf8)
        defaults.set(duplicateConsent, forKey: ProviderConsentStore.stateKey)

        let inspection = recovery.inspect()
        #expect(inspection.issues.count == 1)
        #expect(inspection.issues.first?.document == .providerConsent)
        #expect(inspection.issues.first?.kind == .invalidContents)
        #expect(defaults.data(forKey: ProviderConsentStore.stateKey) == duplicateConsent)
    }

    @Test func decodedButUnboundedRouteIdentifiersRequireExplicitQuarantineAndReset() throws {
        let (defaults, suite, root, recovery) = try recoveryFixture()
        defer {
            defaults.removePersistentDomain(forName: suite)
            try? FileManager.default.removeItem(at: root)
        }
        let selection = ModelSelection(
            route: ModelRoute(provider: ProviderID("provider"), model: ModelID(String(repeating: "m", count: 513))),
            reasoningEffort: String(repeating: "r", count: 129)
        )
        let encoded = try JSONEncoder().encode(ModelProviderSettings(defaultSelection: selection))
        defaults.set(encoded, forKey: ModelProviderSettingsStore.settingsKey)

        let inspection = recovery.inspect()
        #expect(inspection.issues.count == 1)
        #expect(inspection.issues.first?.document == .modelSettings)
        #expect(inspection.issues.first?.kind == .invalidContents)
        #expect(defaults.data(forKey: ModelProviderSettingsStore.settingsKey) == encoded)

        _ = try recovery.resetAfterExplicitConfirmation(expected: inspection)
        #expect(try ModelProviderSettingsStore(defaults: defaults).load()?.defaultSelection == .defaultLocal)
    }

    @Test func fullPrivateRetentionDirectoryFailsClosedWithoutEvictingExistingCopies() throws {
        let (defaults, suite, root, recovery) = try recoveryFixture()
        defer {
            defaults.removePersistentDomain(forName: suite)
            try? FileManager.default.removeItem(at: root)
        }
        let directory = root.appendingPathComponent(NativeProviderStateRecovery.directoryName, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        for index in 0..<NativeProviderStateRecovery.maximumQuarantineFiles {
            let file = directory.appendingPathComponent("retained-\(index).recovery")
            try Data([UInt8(index)]).write(to: file, options: .withoutOverwriting)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        }
        let corrupt = Data("still-corrupt".utf8)
        defaults.set(corrupt, forKey: ModelProviderSettingsStore.settingsKey)

        #expect(throws: NativeProviderStateRecoveryError.quarantineCapacityReached) {
            try recovery.resetAfterExplicitConfirmation(expected: recovery.inspect())
        }
        #expect(defaults.data(forKey: ModelProviderSettingsStore.settingsKey) == corrupt)
        #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path).count
            == NativeProviderStateRecovery.maximumQuarantineFiles)

        let inventory = try recovery.recoveryArchives()
        #expect(inventory.count == NativeProviderStateRecovery.maximumQuarantineFiles)
        try recovery.deleteRecoveryArchiveAfterExplicitConfirmation(try #require(inventory.first))
        #expect(try recovery.recoveryArchives().count == NativeProviderStateRecovery.maximumQuarantineFiles - 1)

        let receipt = try recovery.resetAfterExplicitConfirmation(expected: recovery.inspect())
        #expect(try Data(contentsOf: #require(receipt.quarantinedFiles[.modelSettings])) == corrupt)
        let retained = try recovery.recoveryArchives()
        #expect(retained.count == NativeProviderStateRecovery.maximumQuarantineFiles)
        try recovery.clearRecoveryArchivesAfterExplicitConfirmation(expected: retained)
        #expect(try recovery.recoveryArchives().isEmpty)
    }

    @Test func recoveryInventoryStreamsAndRejectsAHostileWideDirectory() throws {
        let (defaults, suite, root, recovery) = try recoveryFixture()
        defer {
            defaults.removePersistentDomain(forName: suite)
            try? FileManager.default.removeItem(at: root)
        }
        let directory = root.appendingPathComponent(NativeProviderStateRecovery.directoryName, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        for index in 0..<256 {
            let file = directory.appendingPathComponent("wide-\(index).recovery")
            try Data().write(to: file)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        }
        #expect(throws: NativeProviderStateRecoveryError.quarantineUnavailable) {
            _ = try recovery.recoveryArchives()
        }
    }

    @Test func staleSingleArchiveConfirmationCannotDeleteSameSizeSameMtimeReplacement() throws {
        let (defaults, suite, root, recovery) = try recoveryFixture()
        defer {
            defaults.removePersistentDomain(forName: suite)
            try? FileManager.default.removeItem(at: root)
        }
        defaults.set(Data("original-corrupt-state".utf8), forKey: ModelProviderSettingsStore.settingsKey)
        _ = try recovery.resetAfterExplicitConfirmation(expected: recovery.inspect())
        let expected = try #require(recovery.recoveryArchives().first)
        let replacement = Data(repeating: 0x5A, count: expected.byteCount)
        try replaceRecoveryArchivePreservingSizeAndModificationTime(expected, with: replacement)

        #expect(throws: NativeProviderStateRecoveryError.stateChanged) {
            try recovery.deleteRecoveryArchiveAfterExplicitConfirmation(expected)
        }
        #expect(try Data(contentsOf: expected.url) == replacement)
        let current = try #require(recovery.recoveryArchives().first)
        #expect(current.byteCount == expected.byteCount)
        #expect(current.modifiedAt == expected.modifiedAt)
        #expect(current.inode != expected.inode || current.device != expected.device)
        #expect(current.contentSHA256 != expected.contentSHA256)
    }

    @Test func staleClearAllConfirmationPreservesEveryArchiveAfterSameSizeSameMtimeReplacement() throws {
        let (defaults, suite, root, recovery) = try recoveryFixture()
        defer {
            defaults.removePersistentDomain(forName: suite)
            try? FileManager.default.removeItem(at: root)
        }
        defaults.set(Data("corrupt-model-state".utf8), forKey: ModelProviderSettingsStore.settingsKey)
        defaults.set(Data("corrupt-consent-data".utf8), forKey: ProviderConsentStore.stateKey)
        _ = try recovery.resetAfterExplicitConfirmation(expected: recovery.inspect())
        let expected = try recovery.recoveryArchives()
        #expect(expected.count == 2)
        let replaced = try #require(expected.first)
        let replacement = Data(repeating: 0x59, count: replaced.byteCount)
        try replaceRecoveryArchivePreservingSizeAndModificationTime(replaced, with: replacement)

        #expect(throws: NativeProviderStateRecoveryError.stateChanged) {
            try recovery.clearRecoveryArchivesAfterExplicitConfirmation(expected: expected)
        }
        #expect(try recovery.recoveryArchives().count == 2)
        #expect(try Data(contentsOf: replaced.url) == replacement)
        for archive in expected.dropFirst() {
            #expect(FileManager.default.fileExists(atPath: archive.url.path))
        }
    }
}
