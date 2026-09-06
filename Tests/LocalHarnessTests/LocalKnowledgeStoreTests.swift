import Darwin
import Foundation
import Testing
@testable import LocalHarness

@Test func knowledgeNotesAreScopedSearchablePersistentAndStrictlyChunked() throws {
    let root = temporaryKnowledgeRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let store = try LocalKnowledgeStore(applicationSupportDirectory: root)
    let baseDate = Date(timeIntervalSinceReferenceDate: 800_000_000)

    let global = try store.createMemoryNote(
        title: "Global deployment handbook",
        text: "The zephyr launch protocol requires a signed checklist and a rollback owner.",
        scope: .global,
        createdAt: baseDate
    )
    let projectA = try store.createMemoryNote(
        title: "Project Atlas zephyr plan",
        text: Array(repeating: "Zephyr is the Atlas launch word with careful verification.", count: 900).joined(separator: " "),
        scope: .project("atlas"),
        createdAt: baseDate.addingTimeInterval(1)
    )
    _ = try store.createMemoryNote(
        title: "Project Borealis plan",
        text: Array(repeating: "Zephyr belongs to Borealis in this private project note.", count: 20).joined(separator: " "),
        scope: .project("borealis"),
        createdAt: baseDate.addingTimeInterval(2)
    )

    let atlasResults = try store.search(
        "zephyr launch",
        scope: .project("atlas", includeGlobal: true),
        limit: 50
    )
    #expect(!atlasResults.isEmpty)
    #expect(atlasResults.allSatisfy { $0.scope == .global || $0.scope == .project("atlas") })
    #expect(!atlasResults.contains { $0.scope == .project("borealis") })
    #expect(atlasResults == (try store.search(
        "zephyr launch",
        scope: .project("atlas", includeGlobal: true),
        limit: 50
    )))
    #expect(atlasResults.allSatisfy { $0.snippet.count <= LocalKnowledgeLimits.maximumSnippetCharacters })

    let projectOnly = try store.search("zephyr", scope: .project("atlas", includeGlobal: false), limit: 50)
    #expect(!projectOnly.isEmpty)
    #expect(projectOnly.allSatisfy { $0.scope == .project("atlas") })
    let globalOnly = try store.search("zephyr", scope: .globalOnly)
    #expect(globalOnly.map(\.documentID) == [global.id])

    #expect(projectA.chunkCount > 1)
    for index in 0..<projectA.chunkCount {
        let chunk = try store.context(documentID: projectA.id, chunkIndex: index)
        #expect(!chunk.text.isEmpty)
        #expect(chunk.text.count <= LocalKnowledgeLimits.chunkCharacters)
    }

    let updated = try store.updateMemoryNote(
        id: global.id,
        title: "Global release handbook",
        text: "The aurora release protocol supersedes the old launch note.",
        updatedAt: baseDate.addingTimeInterval(10)
    )
    #expect(updated.createdAt == global.createdAt)
    #expect(updated.updatedAt == baseDate.addingTimeInterval(10))
    #expect(try store.memoryNote(id: global.id).text.contains("aurora"))
    #expect(try store.search("aurora", scope: .globalOnly).first?.documentID == global.id)
    #expect((try store.search("signed checklist", scope: .globalOnly)).isEmpty)

    let reopened = try LocalKnowledgeStore(applicationSupportDirectory: root)
    #expect(try reopened.memoryNote(id: global.id).descriptor == updated)
    #expect(try reopened.listDocuments().count == 3)
    #expect(try reopened.search("aurora", scope: .globalOnly).first?.documentID == global.id)
}

@Test func knowledgeImportsSupportedTextFormatsWithoutPersistingSourcePaths() throws {
    let root = temporaryKnowledgeRoot()
    let imports = root.appendingPathComponent("Import Sources", isDirectory: true)
    try FileManager.default.createDirectory(at: imports, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let store = try LocalKnowledgeStore(applicationSupportDirectory: root.appendingPathComponent("App Support"))

    let fixtures: [(String, String, KnowledgeSourceKind)] = [
        ("brief.txt", "Plain text heliotrope memo", .plainText),
        ("notes.md", "# Notes\n\nMarkdown heliotrope content", .markdown),
        ("model.swift", "let heliotrope = \"source\"", .sourceCode),
        ("records.json", "{\"term\":\"heliotrope\",\"count\":2}", .json),
        ("events.jsonl", "{\"term\":\"heliotrope\"}\n{\"term\":\"second\"}\n", .json),
        ("table.csv", "name,value\nheliotrope,7\n", .csv)
    ]
    for fixture in fixtures {
        let url = imports.appendingPathComponent(fixture.0)
        try Data(fixture.1.utf8).write(to: url)
        let descriptor = try store.importFile(at: url, scope: .project("imports"))
        #expect(descriptor.sourceKind == fixture.2)
        #expect(descriptor.sourceName == fixture.0)
        #expect(descriptor.sourceSHA256.count == 64)
        #expect(descriptor.contentSHA256.count == 64)
    }

    let results = try store.search("heliotrope", scope: .project("imports", includeGlobal: false), limit: 20)
    #expect(results.count == fixtures.count)

    let objectDirectory = store.storageDirectory.appendingPathComponent("Objects", isDirectory: true)
    let storedBytes = try FileManager.default.contentsOfDirectory(at: objectDirectory, includingPropertiesForKeys: nil)
        .reduce(into: Data()) { output, url in output.append(try Data(contentsOf: url)) }
    let persisted = try #require(String(data: storedBytes, encoding: .utf8))
    #expect(!persisted.contains(imports.path))
    #expect(persisted.contains("brief.txt"))
}

@Test func knowledgeImportRejectsLinksDirectoriesOversizeInvalidUTF8BinaryAndMalformedData() throws {
    let root = temporaryKnowledgeRoot()
    let imports = root.appendingPathComponent("Sources", isDirectory: true)
    try FileManager.default.createDirectory(at: imports, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let store = try LocalKnowledgeStore(applicationSupportDirectory: root.appendingPathComponent("App"))

    let regular = imports.appendingPathComponent("regular.txt")
    try Data("safe".utf8).write(to: regular)
    let link = imports.appendingPathComponent("link.txt")
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: regular)
    #expect(throws: LocalKnowledgeStoreError.sourceIsSymbolicLink) {
        try store.importFile(at: link)
    }

    let directory = imports.appendingPathComponent("folder.txt", isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    #expect(throws: LocalKnowledgeStoreError.sourceIsNotRegularFile) {
        try store.importFile(at: directory)
    }

    let oversized = imports.appendingPathComponent("oversized.txt")
    try Data(repeating: 0x61, count: LocalKnowledgeLimits.maximumImportBytes + 1).write(to: oversized)
    #expect(throws: LocalKnowledgeStoreError.sourceTooLarge(
        maximumBytes: LocalKnowledgeLimits.maximumImportBytes
    )) {
        try store.importFile(at: oversized)
    }

    let invalidUTF8 = imports.appendingPathComponent("invalid.txt")
    try Data([0xFF, 0xFE, 0xFA]).write(to: invalidUTF8)
    #expect(throws: LocalKnowledgeStoreError.invalidUTF8) {
        try store.importFile(at: invalidUTF8)
    }

    let binary = imports.appendingPathComponent("binary.txt")
    try Data([0x61, 0x00, 0x62]).write(to: binary)
    #expect(throws: LocalKnowledgeStoreError.binaryContent) {
        try store.importFile(at: binary)
    }

    let badJSON = imports.appendingPathComponent("bad.json")
    try Data("{not-json}".utf8).write(to: badJSON)
    #expect(throws: LocalKnowledgeStoreError.invalidJSON) {
        try store.importFile(at: badJSON)
    }

    let unsupported = imports.appendingPathComponent("archive.docx")
    try Data("not supported".utf8).write(to: unsupported)
    #expect(throws: LocalKnowledgeStoreError.unsupportedFileType("docx")) {
        try store.importFile(at: unsupported)
    }
    #expect(try store.listDocuments().isEmpty)
}

@Test func knowledgeImportsExtractablePDFTextLocally() throws {
    let root = temporaryKnowledgeRoot()
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let pdfURL = root.appendingPathComponent("local-reference.pdf")
    try minimalTextPDF("Quartz heliotrope PDF knowledge").write(to: pdfURL)
    let store = try LocalKnowledgeStore(applicationSupportDirectory: root.appendingPathComponent("App"))

    let descriptor = try store.importFile(at: pdfURL, scope: .global)

    #expect(descriptor.sourceKind == .pdf)
    #expect(descriptor.sourceName == "local-reference.pdf")
    #expect(try store.search("heliotrope PDF", scope: .globalOnly).first?.documentID == descriptor.id)
}

@Test func knowledgeStorageUsesPrivateAtomicVersionedFilesAndManifestExports() throws {
    let root = temporaryKnowledgeRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let store = try LocalKnowledgeStore(applicationSupportDirectory: root)
    let timestamp = Date(timeIntervalSinceReferenceDate: 810_000_000)
    let global = try store.createMemoryNote(
        title: "Private note",
        text: "This content must not appear in a metadata-only export.",
        createdAt: timestamp
    )
    let project = try store.createMemoryNote(
        title: "Project note",
        text: "Scoped content",
        scope: .project("project-7"),
        createdAt: timestamp.addingTimeInterval(1)
    )

    let knowledgeRoot = store.storageDirectory
    let catalog = knowledgeRoot.appendingPathComponent("catalog.json")
    let objects = knowledgeRoot.appendingPathComponent("Objects", isDirectory: true)
    #expect(privateMode(of: knowledgeRoot) == 0o700)
    #expect(privateMode(of: objects) == 0o700)
    #expect(privateMode(of: catalog) == 0o600)
    for object in try FileManager.default.contentsOfDirectory(at: objects, includingPropertiesForKeys: nil) {
        #expect(privateMode(of: object) == 0o600)
    }
    let catalogObject = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: catalog)) as? [String: Any])
    #expect(catalogObject["schemaVersion"] as? Int == LocalKnowledgeStore.schemaVersion)
    #expect((catalogObject["generation"] as? Int ?? 0) >= 1)
    #expect(try FileManager.default.contentsOfDirectory(at: knowledgeRoot, includingPropertiesForKeys: nil)
        .allSatisfy { !$0.lastPathComponent.hasSuffix(".tmp") })

    let manifestData = try store.exportManifestData(generatedAt: timestamp)
    let manifest = try JSONDecoder().decode(KnowledgeExportManifest.self, from: manifestData)
    #expect(manifest.schemaVersion == LocalKnowledgeStore.schemaVersion)
    #expect(manifest.generatedAt == timestamp)
    #expect(Set(manifest.documents.map(\.id)) == Set([global.id, project.id]))
    #expect(!String(decoding: manifestData, as: UTF8.self).contains("must not appear"))

    let exportDirectory = root.appendingPathComponent("Explicit Exports", isDirectory: true)
    try FileManager.default.createDirectory(at: exportDirectory, withIntermediateDirectories: true)
    let exportURL = exportDirectory.appendingPathComponent("knowledge-manifest.json")
    try store.exportManifest(to: exportURL, generatedAt: timestamp)
    #expect(privateMode(of: exportURL) == 0o600)
    #expect(try Data(contentsOf: exportURL) == manifestData)

    #expect(try store.clear(scope: .project("project-7")) == 1)
    #expect(try store.listDocuments().map(\.id) == [global.id])
    #expect(try store.delete(id: global.id).id == global.id)
    #expect(try store.listDocuments().isEmpty)
    #expect(try LocalKnowledgeStore(applicationSupportDirectory: root).listDocuments().isEmpty)
}

@Test func corruptKnowledgeMetadataIsPreservedAndRecoveredWithoutLosingValidDocuments() throws {
    let root = temporaryKnowledgeRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let store = try LocalKnowledgeStore(applicationSupportDirectory: root)
    let note = try store.createMemoryNote(title: "Recoverable", text: "catalog recovery evidence")
    let catalog = store.storageDirectory.appendingPathComponent("catalog.json")
    let corruptCatalog = Data("not valid catalog JSON".utf8)
    try corruptCatalog.write(to: catalog, options: .atomic)
    try makePrivateFile(catalog)

    let recovered = try LocalKnowledgeStore(applicationSupportDirectory: root)
    _ = try recovered.listDocuments()

    #expect(recovered.recoveryReport.recoveredCatalog)
    #expect(recovered.recoveryReport.recoveredOrphanDocuments == 1)
    #expect(try recovered.memoryNote(id: note.id).text == "catalog recovery evidence")
    let recoveryDirectory = recovered.storageDirectory.appendingPathComponent("Recovery", isDirectory: true)
    let firstRecoveryPayloads = try FileManager.default.contentsOfDirectory(
        at: recoveryDirectory,
        includingPropertiesForKeys: nil
    ).map { try Data(contentsOf: $0) }
    #expect(firstRecoveryPayloads.contains(corruptCatalog))

    let corruptID = UUID()
    let corruptObject = recovered.storageDirectory
        .appendingPathComponent("Objects", isDirectory: true)
        .appendingPathComponent("\(corruptID.uuidString.lowercased()).json")
    let corruptObjectData = Data("{\"schemaVersion\":1,\"broken\":true}".utf8)
    try corruptObjectData.write(to: corruptObject)
    try makePrivateFile(corruptObject)
    let recoveredAgain = try LocalKnowledgeStore(applicationSupportDirectory: root)
    _ = try recoveredAgain.listDocuments()
    #expect(recoveredAgain.recoveryReport.quarantinedDocuments == 1)
    #expect(try recoveredAgain.memoryNote(id: note.id).descriptor.id == note.id)
    let allRecoveryPayloads = try FileManager.default.contentsOfDirectory(
        at: recoveryDirectory,
        includingPropertiesForKeys: nil
    ).map { try Data(contentsOf: $0) }
    #expect(allRecoveryPayloads.contains(corruptObjectData))
}

@Test func futureKnowledgeSchemasFailClosedWithoutChangingAnyBytes() throws {
    let root = temporaryKnowledgeRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let store = try LocalKnowledgeStore(applicationSupportDirectory: root)
    _ = try store.createMemoryNote(title: "Current", text: "current schema data")
    let catalog = store.storageDirectory.appendingPathComponent("catalog.json")
    var catalogObject = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: catalog)) as? [String: Any])
    catalogObject["schemaVersion"] = LocalKnowledgeStore.schemaVersion + 1
    let futureCatalog = try JSONSerialization.data(withJSONObject: catalogObject, options: [.sortedKeys])
    try futureCatalog.write(to: catalog, options: .atomic)
    try makePrivateFile(catalog)
    let recoveryDirectory = store.storageDirectory.appendingPathComponent("Recovery", isDirectory: true)
    let recoveryCount = try FileManager.default.contentsOfDirectory(at: recoveryDirectory, includingPropertiesForKeys: nil).count

    #expect(throws: LocalKnowledgeStoreError.futureSchema(
        found: LocalKnowledgeStore.schemaVersion + 1,
        supported: LocalKnowledgeStore.schemaVersion
    )) {
        let reopened = try LocalKnowledgeStore(applicationSupportDirectory: root)
        _ = try reopened.listDocuments()
    }
    #expect(try Data(contentsOf: catalog) == futureCatalog)
    #expect(try FileManager.default.contentsOfDirectory(at: recoveryDirectory, includingPropertiesForKeys: nil).count == recoveryCount)

    // A future-version orphan object also blocks opening before recovery or
    // cleanup can mutate the store.
    catalogObject["schemaVersion"] = LocalKnowledgeStore.schemaVersion
    try JSONSerialization.data(withJSONObject: catalogObject, options: [.sortedKeys]).write(to: catalog, options: .atomic)
    try makePrivateFile(catalog)
    let futureID = UUID()
    let futureObject = store.storageDirectory
        .appendingPathComponent("Objects", isDirectory: true)
        .appendingPathComponent("\(futureID.uuidString.lowercased()).json")
    let futureObjectData = Data("{\"schemaVersion\":99}".utf8)
    try futureObjectData.write(to: futureObject)
    try makePrivateFile(futureObject)
    #expect(throws: LocalKnowledgeStoreError.futureSchema(found: 99, supported: 1)) {
        let reopened = try LocalKnowledgeStore(applicationSupportDirectory: root)
        _ = try reopened.listDocuments()
    }
    #expect(try Data(contentsOf: futureObject) == futureObjectData)
}

@Test func knowledgeStoreRejectsSymlinkedOwnedStorageAndManifestDestinations() throws {
    let root = temporaryKnowledgeRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let appSupport = root.appendingPathComponent("App", isDirectory: true)
    let outside = root.appendingPathComponent("Outside", isDirectory: true)
    try FileManager.default.createDirectory(at: appSupport, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
    try FileManager.default.createSymbolicLink(
        at: appSupport.appendingPathComponent("Knowledge", isDirectory: true),
        withDestinationURL: outside
    )
    #expect(throws: LocalKnowledgeStoreError.unsafeStoreEntry("Knowledge")) {
        let store = try LocalKnowledgeStore(applicationSupportDirectory: appSupport)
        _ = try store.listDocuments()
    }

    try FileManager.default.removeItem(at: appSupport.appendingPathComponent("Knowledge"))
    let store = try LocalKnowledgeStore(applicationSupportDirectory: appSupport)
    _ = try store.createMemoryNote(title: "Safe", text: "safe local note")
    let outsideFile = outside.appendingPathComponent("unchanged.json")
    let original = Data("unchanged".utf8)
    try original.write(to: outsideFile)
    let exportLink = root.appendingPathComponent("manifest.json")
    try FileManager.default.createSymbolicLink(at: exportLink, withDestinationURL: outsideFile)
    #expect(throws: LocalKnowledgeStoreError.unsafeExportDestination) {
        try store.exportManifest(to: exportLink)
    }
    #expect(try Data(contentsOf: outsideFile) == original)
}

@Test func knowledgeConstructionIsMainThreadLazyAndDoesNotMaterializeStorage() async throws {
    let root = temporaryKnowledgeRoot()
    defer { try? FileManager.default.removeItem(at: root) }

    let store = try await MainActor.run {
        try LocalKnowledgeStore(applicationSupportDirectory: root)
    }

    #expect(store.availability == .idle)
    #expect(!FileManager.default.fileExists(atPath: store.storageDirectory.path))
    let synchronousResult: Result<[KnowledgeDocumentDescriptor], LocalKnowledgeStoreError> = await MainActor.run {
        do { return .success(try store.listDocuments()) }
        catch let error as LocalKnowledgeStoreError { return .failure(error) }
        catch { return .failure(.storageUnavailable) }
    }
    #expect(synchronousResult.failure == .operationRequiresBackground)
    #expect(store.availability == .idle)
    #expect(!FileManager.default.fileExists(atPath: store.storageDirectory.path))
}

@Test func knowledgeAsyncLoadCoalescesCallersAndPublishesOnlyAfterBootstrap() async throws {
    let root = temporaryKnowledgeRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let gate = KnowledgeBootstrapGate()
    let store = try LocalKnowledgeStore(
        applicationSupportDirectory: root,
        beforeBootstrap: { gate.block() }
    )
    let results = KnowledgeLoadResults()

    store.load { results.record($0) }
    #expect(await gate.waitUntilEntered())
    store.load { results.record($0) }
    #expect(store.availability == .loading)
    #expect(!FileManager.default.fileExists(atPath: store.storageDirectory.path))

    gate.release()
    let first = await results.next()
    let second = await results.next()
    #expect(first?.isSuccess == true)
    #expect(second?.isSuccess == true)
    #expect(store.availability == .ready)
    #expect(try await offMain { try store.listDocuments().isEmpty })
}

@Test func knowledgeCancelledLoadCompletesEveryWaiterWithoutPublishingPartialStateAndCanRetry() async throws {
    let root = temporaryKnowledgeRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let gate = KnowledgeBootstrapGate()
    let store = try LocalKnowledgeStore(
        applicationSupportDirectory: root,
        beforeBootstrap: { gate.block() }
    )
    let results = KnowledgeLoadResults()

    store.load { results.record($0) }
    #expect(await gate.waitUntilEntered())
    store.load { results.record($0) }
    store.cancelLoading()
    gate.release()

    #expect(await results.next()?.failure == .loadingCancelled)
    #expect(await results.next()?.failure == .loadingCancelled)
    #expect(store.availability == .idle)
    #expect(!FileManager.default.fileExists(atPath: store.storageDirectory.path))

    #expect((await loadKnowledgeStore(store, retry: true)).isSuccess)
    #expect(store.availability == .ready)
}

@Test func knowledgeUnavailableStateIsTypedPreservesBytesAndRetryPublishesAfterRepair() async throws {
    let root = temporaryKnowledgeRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let objects = try makePrivateKnowledgeLayout(at: root).objects
    let original = Data("unchanged".utf8)
    let hostileFiles = (0..<3).map { objects.appendingPathComponent("flood-\($0)") }
    for file in hostileFiles {
        try original.write(to: file)
        try makePrivateFile(file)
    }
    let store = try LocalKnowledgeStore(
        applicationSupportDirectory: root,
        bootstrapLimits: LocalKnowledgeBootstrapLimits(maximumObjectEntries: 2)
    )

    let failure = await loadKnowledgeStore(store)
    #expect(failure.failure == .directoryEntryLimitExceeded(maximum: 2))
    if case .unavailable = store.availability {} else { Issue.record("Expected a typed unavailable state") }
    for file in hostileFiles { #expect(try Data(contentsOf: file) == original) }

    for file in hostileFiles { try FileManager.default.removeItem(at: file) }
    #expect((await loadKnowledgeStore(store, retry: true)).isSuccess)
    #expect(store.availability == .ready)
    #expect(try await offMain { try store.listDocuments().isEmpty })
}

@Test func knowledgeStartupRejectsSparseOversizeLinksFIFOHardlinksAndPermissiveNodesWithoutBlocking() async throws {
    enum HostileKind: CaseIterable { case sparse, symlink, fifo, hardlink, permissive }
    for kind in HostileKind.allCases {
        let root = temporaryKnowledgeRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let layout = try makePrivateKnowledgeLayout(at: root)
        let object = layout.objects.appendingPathComponent("00000000-0000-0000-0000-000000000001.json")
        switch kind {
        case .sparse:
            let descriptor = Darwin.open(object.path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
            #expect(descriptor >= 0)
            if descriptor >= 0 {
                #expect(ftruncate(descriptor, 33) == 0)
                _ = Darwin.close(descriptor)
            }
        case .symlink:
            let target = root.appendingPathComponent("target")
            try Data("target".utf8).write(to: target)
            try FileManager.default.createSymbolicLink(at: object, withDestinationURL: target)
        case .fifo:
            #expect(Darwin.mkfifo(object.path, 0o600) == 0)
        case .hardlink:
            let source = root.appendingPathComponent("source")
            try Data("{}".utf8).write(to: source)
            try makePrivateFile(source)
            #expect(Darwin.link(source.path, object.path) == 0)
        case .permissive:
            try Data("{}".utf8).write(to: object)
            try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: object.path)
        }
        let limits = LocalKnowledgeBootstrapLimits(maximumRawObjectBytes: kind == .sparse ? 32 : 1_024)
        let store = try LocalKnowledgeStore(applicationSupportDirectory: root, bootstrapLimits: limits)
        let result = await loadKnowledgeStore(store)
        #expect(result.failure != nil)
        if case .unavailable = store.availability {} else { Issue.record("Hostile \(kind) node was not fail-closed") }
    }
}

@Test func knowledgeStartupBoundsAggregateNamesDeadlineDecodedCorpusAndIndex() async throws {
    let namesRoot = temporaryKnowledgeRoot()
    defer { try? FileManager.default.removeItem(at: namesRoot) }
    let namesObjects = try makePrivateKnowledgeLayout(at: namesRoot).objects
    for id in ["00000000-0000-0000-0000-000000000001.json", "00000000-0000-0000-0000-000000000002.json"] {
        let file = namesObjects.appendingPathComponent(id)
        try Data("{}".utf8).write(to: file)
        try makePrivateFile(file)
    }
    let nameLimited = try LocalKnowledgeStore(
        applicationSupportDirectory: namesRoot,
        bootstrapLimits: LocalKnowledgeBootstrapLimits(
            maximumFilenameBytes: 64,
            maximumAggregateFilenameBytes: 64
        )
    )
    #expect((await loadKnowledgeStore(nameLimited)).failure == .aggregateFilenameLimitExceeded(maximumBytes: 64))

    let timeoutRoot = temporaryKnowledgeRoot()
    defer { try? FileManager.default.removeItem(at: timeoutRoot) }
    let clock = AdvancingKnowledgeClock(step: 2)
    let timed = try LocalKnowledgeStore(
        applicationSupportDirectory: timeoutRoot,
        bootstrapLimits: LocalKnowledgeBootstrapLimits(bootstrapDeadlineSeconds: 1e-9),
        scanNow: { clock.read() }
    )
    #expect((await loadKnowledgeStore(timed)).failure == .storageScanTimedOut)

    let capacityRoot = temporaryKnowledgeRoot()
    defer { try? FileManager.default.removeItem(at: capacityRoot) }
    let capacityStore = try LocalKnowledgeStore(
        applicationSupportDirectory: capacityRoot,
        bootstrapLimits: LocalKnowledgeBootstrapLimits(
            maximumDocuments: 5,
            maximumDecodedTextBytes: 20
        )
    )
    #expect((await loadKnowledgeStore(capacityStore)).isSuccess)
    for index in 0..<4 {
        _ = try await offMain {
            try capacityStore.createMemoryNote(title: "Item \(index)", text: "abcde")
        }
    }
    let capacityFailure = await offMainResult {
        try capacityStore.createMemoryNote(title: "Overflow", text: "x")
    }
    #expect(capacityFailure.failure == .storeCapacityExceeded(maximumBytes: 20))
    #expect(try await offMain { try capacityStore.listDocuments().count } == 4)

    let countRoot = temporaryKnowledgeRoot()
    defer { try? FileManager.default.removeItem(at: countRoot) }
    let countStore = try LocalKnowledgeStore(
        applicationSupportDirectory: countRoot,
        bootstrapLimits: LocalKnowledgeBootstrapLimits(
            maximumDocuments: 4,
            maximumDecodedTextBytes: 1_024
        )
    )
    #expect((await loadKnowledgeStore(countStore)).isSuccess)
    for index in 0..<4 {
        _ = try await offMain {
            try countStore.createMemoryNote(title: "Count \(index)", text: "item \(index)")
        }
    }
    let countFailure = await offMainResult {
        try countStore.createMemoryNote(title: "Fifth", text: "overflow")
    }
    #expect(countFailure.failure == .documentLimitReached(maximum: 4))
    #expect(try await offMain { try countStore.listDocuments().count } == 4)

    let chunkRoot = temporaryKnowledgeRoot()
    defer { try? FileManager.default.removeItem(at: chunkRoot) }
    let chunkStore = try LocalKnowledgeStore(
        applicationSupportDirectory: chunkRoot,
        bootstrapLimits: LocalKnowledgeBootstrapLimits(maximumTotalChunks: 1)
    )
    #expect((await loadKnowledgeStore(chunkStore)).isSuccess)
    _ = try await offMain {
        try chunkStore.createMemoryNote(title: "First chunk", text: "first")
    }
    let chunkFailure = await offMainResult {
        try chunkStore.createMemoryNote(title: "Second chunk", text: "second")
    }
    #expect(chunkFailure.failure == .indexChunkLimitExceeded(maximumChunks: 1))
    #expect(try await offMain { try chunkStore.listDocuments().count } == 1)

    let indexRoot = temporaryKnowledgeRoot()
    defer { try? FileManager.default.removeItem(at: indexRoot) }
    let indexStore = try LocalKnowledgeStore(
        applicationSupportDirectory: indexRoot,
        bootstrapLimits: LocalKnowledgeBootstrapLimits(maximumIndexPostings: 3)
    )
    #expect((await loadKnowledgeStore(indexStore)).isSuccess)
    let indexFailure = await offMainResult {
        try indexStore.createMemoryNote(title: "Too many terms", text: "one two three four")
    }
    #expect(indexFailure.failure == .indexCapacityExceeded(maximumPostings: 3))
    #expect(try await offMain { try indexStore.listDocuments().isEmpty })
}

@Test func knowledgeLoadSerializesConcurrentMutationBehindOneTrustedSnapshot() async throws {
    let root = temporaryKnowledgeRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let gate = KnowledgeBootstrapGate()
    let store = try LocalKnowledgeStore(
        applicationSupportDirectory: root,
        beforeBootstrap: { gate.block() }
    )
    let results = KnowledgeLoadResults()
    store.load { results.record($0) }
    #expect(await gate.waitUntilEntered())

    let mutation = Task.detached {
        try store.createMemoryNote(title: "Serialized", text: "published after bootstrap")
    }
    gate.release()
    #expect(await results.next()?.isSuccess == true)
    let descriptor = try await mutation.value
    #expect(try await offMain { try store.listDocuments().map(\.id) } == [descriptor.id])
}

@Test func knowledgeTrashCleanupIsDeferredVisibleBoundedAndRetryable() async throws {
    let root = temporaryKnowledgeRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let trash = try makePrivateKnowledgeLayout(at: root).trash
    let hostile = trash.appendingPathComponent("blocked-cleanup")
    #expect(Darwin.mkfifo(hostile.path, 0o600) == 0)
    let store = try LocalKnowledgeStore(
        applicationSupportDirectory: root,
        bootstrapLimits: LocalKnowledgeBootstrapLimits(trashDeadlineSeconds: 0.5)
    )

    #expect((await loadKnowledgeStore(store)).isSuccess)
    #expect(store.availability == .ready)
    #expect(store.recoveryReport.trashCleanupIssue == nil)
    #expect(await eventuallyKnowledge { store.recoveryReport.trashCleanupIssue != nil })
    #expect(store.availability == .ready)

    #expect(Darwin.unlink(hostile.path) == 0)
    store.retryDeferredMaintenance()
    #expect(await eventuallyKnowledge {
        let report = store.recoveryReport
        return !report.trashCleanupPending && report.trashCleanupIssue == nil
    })
}

@Test func knowledgeMutationFailuresRollbackExactBytesAcrossEveryDurableBoundary() async throws {
    let boundaries: [LocalKnowledgeMutationBoundary] = [
        .journalDurable,
        .objectEvacuated(0),
        .catalogEvacuated,
        .replacementWritten(0),
        .objectDirectoryDurable,
        .catalogWritten,
        .rootDirectoryDurable
    ]
    for boundary in boundaries {
        let root = temporaryKnowledgeRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let injector = KnowledgeMutationFaultInjector()
        let store = try LocalKnowledgeStore(
            applicationSupportDirectory: root,
            mutationBoundary: { try injector.handle($0) }
        )
        #expect((await loadKnowledgeStore(store)).isSuccess)
        let note = try await offMain {
            try store.createMemoryNote(title: "Original", text: "durable original bytes")
        }
        let catalog = store.storageDirectory.appendingPathComponent("catalog.json")
        let object = store.storageDirectory
            .appendingPathComponent("Objects", isDirectory: true)
            .appendingPathComponent("\(note.id.uuidString.lowercased()).json")
        let originalCatalog = try Data(contentsOf: catalog)
        let originalObject = try Data(contentsOf: object)
        injector.arm([boundary], behavior: .fail)

        let result = await offMainResult {
            try store.updateMemoryNote(id: note.id, title: "Changed", text: "must roll back")
        }

        #expect(result.failure == .storageUnavailable)
        #expect(store.availability == .ready)
        #expect(try Data(contentsOf: catalog) == originalCatalog)
        #expect(try Data(contentsOf: object) == originalObject)
        #expect(try await offMain { try store.memoryNote(id: note.id).text } == "durable original bytes")
        let transactions = store.storageDirectory.appendingPathComponent("Transactions", isDirectory: true)
        #expect(try FileManager.default.contentsOfDirectory(at: transactions, includingPropertiesForKeys: nil).isEmpty)
    }
}

@Test func knowledgeProcessLossRollsBackEveryUncommittedBoundaryOnRelaunch() async throws {
    let boundaries: [LocalKnowledgeMutationBoundary] = [
        .journalDurable,
        .objectEvacuated(0),
        .catalogEvacuated,
        .replacementWritten(0),
        .objectDirectoryDurable,
        .catalogWritten,
        .rootDirectoryDurable
    ]
    for boundary in boundaries {
        let root = temporaryKnowledgeRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let injector = KnowledgeMutationFaultInjector()
        let store = try LocalKnowledgeStore(
            applicationSupportDirectory: root,
            mutationBoundary: { try injector.handle($0) }
        )
        #expect((await loadKnowledgeStore(store)).isSuccess)
        let note = try await offMain {
            try store.createMemoryNote(title: "Before crash", text: "old authoritative value")
        }
        injector.arm([boundary], behavior: .processLoss)
        _ = await offMainResult {
            try store.updateMemoryNote(id: note.id, title: "After crash", text: "uncommitted value")
        }

        let reopened = try LocalKnowledgeStore(applicationSupportDirectory: root)
        #expect((await loadKnowledgeStore(reopened)).isSuccess)
        #expect(try await offMain { try reopened.memoryNote(id: note.id).text } == "old authoritative value")
        let transactions = reopened.storageDirectory.appendingPathComponent("Transactions", isDirectory: true)
        #expect(try FileManager.default.contentsOfDirectory(at: transactions, includingPropertiesForKeys: nil).isEmpty)
    }
}

@Test func knowledgeDurableCommitMarkerSurvivesProcessLossAndReconcilesForward() async throws {
    let root = temporaryKnowledgeRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let injector = KnowledgeMutationFaultInjector()
    let store = try LocalKnowledgeStore(
        applicationSupportDirectory: root,
        mutationBoundary: { try injector.handle($0) }
    )
    #expect((await loadKnowledgeStore(store)).isSuccess)
    let note = try await offMain {
        try store.createMemoryNote(title: "Before", text: "old")
    }
    injector.arm([.commitMarkerDurable], behavior: .processLoss)
    _ = await offMainResult {
        try store.updateMemoryNote(id: note.id, title: "After", text: "durably committed")
    }

    let reopened = try LocalKnowledgeStore(applicationSupportDirectory: root)
    #expect((await loadKnowledgeStore(reopened)).isSuccess)
    let recovered = try await offMain { try reopened.memoryNote(id: note.id) }
    #expect(recovered.text == "durably committed")
    #expect(recovered.descriptor.title == "After")
}

@Test func knowledgeHistoricalCommittedJournalIsRetiredAfterLaterCommitAndRelaunch() async throws {
    let root = temporaryKnowledgeRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let injector = KnowledgeMutationFaultInjector()
    let store = try LocalKnowledgeStore(
        applicationSupportDirectory: root,
        mutationBoundary: { try injector.handle($0) }
    )
    #expect((await loadKnowledgeStore(store)).isSuccess)
    let note = try await offMain {
        try store.createMemoryNote(title: "Original", text: "generation one")
    }

    // Simulate the committed transaction being left in Transactions because its
    // post-commit move/parent fsync cleanup failed. The mutation is nevertheless
    // authoritative and must report success.
    injector.arm([.committedCleanupStarted], behavior: .fail)
    let firstUpdate = try await offMain {
        try store.updateMemoryNote(id: note.id, title: "First update", text: "generation two")
    }
    #expect(firstUpdate.title == "First update")
    let transactions = store.storageDirectory.appendingPathComponent("Transactions", isDirectory: true)
    #expect(try FileManager.default.contentsOfDirectory(
        at: transactions,
        includingPropertiesForKeys: nil
    ).count == 1)

    // A later successful mutation advances the catalog beyond the old committed
    // journal. Relaunch must recognize the journal as historical, retire it, and
    // preserve the newest fully validated state rather than failing closed.
    let secondUpdate = try await offMain {
        try store.updateMemoryNote(id: note.id, title: "Second update", text: "generation three")
    }
    #expect(secondUpdate.title == "Second update")

    let reopened = try LocalKnowledgeStore(applicationSupportDirectory: root)
    #expect((await loadKnowledgeStore(reopened)).isSuccess)
    let recovered = try await offMain { try reopened.memoryNote(id: note.id) }
    #expect(recovered.text == "generation three")
    #expect(recovered.descriptor.title == "Second update")
    #expect(try FileManager.default.contentsOfDirectory(
        at: transactions,
        includingPropertiesForKeys: nil
    ).isEmpty)
}

@Test func knowledgeJournalRecoversCreateDeleteAndClearWithoutFalseSuccess() async throws {
    enum Operation: CaseIterable { case create, delete, clear }
    for operation in Operation.allCases {
        let root = temporaryKnowledgeRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let injector = KnowledgeMutationFaultInjector()
        let store = try LocalKnowledgeStore(
            applicationSupportDirectory: root,
            mutationBoundary: { try injector.handle($0) }
        )
        #expect((await loadKnowledgeStore(store)).isSuccess)
        let first = try await offMain {
            try store.createMemoryNote(title: "First", text: "first retained")
        }
        let second = try await offMain {
            try store.createMemoryNote(title: "Second", text: "second retained")
        }
        injector.arm([.catalogWritten], behavior: .processLoss)
        switch operation {
        case .create:
            _ = await offMainResult {
                try store.createMemoryNote(title: "Uncommitted", text: "must disappear")
            }
        case .delete:
            _ = await offMainResult { try store.delete(id: first.id) }
        case .clear:
            _ = await offMainResult { try store.clear() }
        }

        let reopened = try LocalKnowledgeStore(applicationSupportDirectory: root)
        #expect((await loadKnowledgeStore(reopened)).isSuccess)
        let ids = try await offMain { Set(try reopened.listDocuments().map(\.id)) }
        #expect(ids == Set([first.id, second.id]))
        #expect(try await offMain { try reopened.listDocuments().contains { $0.title == "Uncommitted" } } == false)
    }
}

@Test func knowledgeRollbackFailureFailsClosedThenRelaunchCompletesRecovery() async throws {
    let root = temporaryKnowledgeRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let injector = KnowledgeMutationFaultInjector()
    let store = try LocalKnowledgeStore(
        applicationSupportDirectory: root,
        mutationBoundary: { try injector.handle($0) }
    )
    #expect((await loadKnowledgeStore(store)).isSuccess)
    let note = try await offMain {
        try store.createMemoryNote(title: "Stable", text: "stable value")
    }
    injector.arm([.catalogWritten, .rollbackStarted], behavior: .fail)

    let result = await offMainResult {
        try store.updateMemoryNote(id: note.id, title: "Indeterminate", text: "not authoritative")
    }

    #expect(result.failure == .mutationRollbackIncomplete)
    if case .unavailable = store.availability {} else { Issue.record("Expected fail-closed unavailable state") }
    #expect((await offMainResult { try store.listDocuments() }).failure == .mutationRollbackIncomplete)

    let reopened = try LocalKnowledgeStore(applicationSupportDirectory: root)
    #expect((await loadKnowledgeStore(reopened)).isSuccess)
    #expect(try await offMain { try reopened.memoryNote(id: note.id).text } == "stable value")
}

@Test func knowledgeProcessLossDuringRollbackResumesIdempotentlyOnRelaunch() async throws {
    for rollbackBoundary in [
        LocalKnowledgeMutationBoundary.rollbackObjectRestored(0),
        .rollbackCatalogRestored
    ] {
        let root = temporaryKnowledgeRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let injector = KnowledgeMutationFaultInjector()
        let store = try LocalKnowledgeStore(
            applicationSupportDirectory: root,
            mutationBoundary: { try injector.handle($0) }
        )
        #expect((await loadKnowledgeStore(store)).isSuccess)
        let note = try await offMain {
            try store.createMemoryNote(title: "Rollback source", text: "exact old rollback value")
        }
        injector.armPlan([
            (.catalogWritten, .fail),
            (rollbackBoundary, .processLoss)
        ])

        let result = await offMainResult {
            try store.updateMemoryNote(id: note.id, title: "Interrupted", text: "must not survive")
        }
        #expect(result.failure == .mutationRollbackIncomplete)
        if case .unavailable = store.availability {} else { Issue.record("Rollback interruption was not fail-closed") }

        let reopened = try LocalKnowledgeStore(applicationSupportDirectory: root)
        #expect((await loadKnowledgeStore(reopened)).isSuccess)
        let recovered = try await offMain { try reopened.memoryNote(id: note.id) }
        #expect(recovered.text == "exact old rollback value")
        #expect(recovered.descriptor.title == "Rollback source")
    }
}

private struct PrivateKnowledgeLayout {
    let root: URL
    let objects: URL
    let recovery: URL
    let trash: URL
}

private func makePrivateKnowledgeLayout(at applicationSupport: URL) throws -> PrivateKnowledgeLayout {
    let knowledge = applicationSupport.appendingPathComponent("Knowledge", isDirectory: true)
    let objects = knowledge.appendingPathComponent("Objects", isDirectory: true)
    let recovery = knowledge.appendingPathComponent("Recovery", isDirectory: true)
    let trash = knowledge.appendingPathComponent("Trash", isDirectory: true)
    for directory in [applicationSupport, knowledge, objects, recovery, trash] {
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
    }
    return PrivateKnowledgeLayout(root: knowledge, objects: objects, recovery: recovery, trash: trash)
}

private final class KnowledgeBootstrapGate: @unchecked Sendable {
    private let lock = NSLock()
    private var entered = false
    private var isReleased = false
    private let released = DispatchSemaphore(value: 0)

    func block() {
        lock.lock()
        if isReleased {
            lock.unlock()
            return
        }
        entered = true
        lock.unlock()
        released.wait()
    }

    func waitUntilEntered() async -> Bool {
        await eventuallyKnowledge { [self] in hasEntered() }
    }

    func release() {
        lock.lock()
        let shouldSignal = !isReleased
        isReleased = true
        lock.unlock()
        if shouldSignal { released.signal() }
    }

    private func hasEntered() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return entered
    }
}

private final class KnowledgeLoadResults: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [Result<Void, LocalKnowledgeStoreError>] = []

    func record(_ result: Result<Void, LocalKnowledgeStoreError>) {
        lock.lock()
        values.append(result)
        lock.unlock()
    }

    func next() async -> Result<Void, LocalKnowledgeStoreError>? {
        for _ in 0..<500 {
            if let result = take() { return result }
            try? await Task.sleep(for: .milliseconds(10))
        }
        return nil
    }

    private func take() -> Result<Void, LocalKnowledgeStoreError>? {
        lock.lock()
        defer { lock.unlock() }
        return values.isEmpty ? nil : values.removeFirst()
    }
}

private final class AdvancingKnowledgeClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value: UInt64 = 0
    private let step: UInt64

    init(step: UInt64) { self.step = step }

    func read() -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        let result = value
        value &+= step
        return result
    }
}

private final class KnowledgeMutationFaultInjector: @unchecked Sendable {
    enum Behavior { case fail, processLoss }

    private let lock = NSLock()
    private var actions: [(LocalKnowledgeMutationBoundary, Behavior)] = []

    func arm(_ targets: [LocalKnowledgeMutationBoundary], behavior: Behavior) {
        armPlan(targets.map { ($0, behavior) })
    }

    func armPlan(_ actions: [(LocalKnowledgeMutationBoundary, Behavior)]) {
        lock.lock()
        self.actions = actions
        lock.unlock()
    }

    func handle(_ boundary: LocalKnowledgeMutationBoundary) throws {
        lock.lock()
        guard let index = actions.firstIndex(where: { $0.0 == boundary }) else {
            lock.unlock()
            return
        }
        let action = actions.remove(at: index).1
        lock.unlock()
        switch action {
        case .fail:
            throw LocalKnowledgeStoreError.storageUnavailable
        case .processLoss:
            throw LocalKnowledgeSimulatedProcessLoss.interrupt
        }
    }
}

private func loadKnowledgeStore(
    _ store: LocalKnowledgeStore,
    retry: Bool = false
) async -> Result<Void, LocalKnowledgeStoreError> {
    await withCheckedContinuation { continuation in
        store.load(retry: retry) { continuation.resume(returning: $0) }
    }
}

private func offMain<T: Sendable>(
    _ operation: @escaping @Sendable () throws -> T
) async throws -> T {
    try await Task.detached(operation: operation).value
}

private func offMainResult<T: Sendable>(
    _ operation: @escaping @Sendable () throws -> T
) async -> Result<T, LocalKnowledgeStoreError> {
    await Task.detached {
        do {
            return .success(try operation())
        } catch let error as LocalKnowledgeStoreError {
            return .failure(error)
        } catch {
            return .failure(.storageUnavailable)
        }
    }.value
}

private func eventuallyKnowledge(
    _ predicate: @escaping @Sendable () -> Bool
) async -> Bool {
    for _ in 0..<500 {
        if predicate() { return true }
        try? await Task.sleep(for: .milliseconds(10))
    }
    return predicate()
}

private extension Result where Failure == LocalKnowledgeStoreError {
    var isSuccess: Bool {
        if case .success = self { return true }
        return false
    }

    var failure: LocalKnowledgeStoreError? {
        if case .failure(let error) = self { return error }
        return nil
    }
}

private func temporaryKnowledgeRoot() -> URL {
    FileManager.default.temporaryDirectory
        .appendingPathComponent("LocalKnowledgeTests-\(UUID().uuidString)", isDirectory: true)
}

private func privateMode(of url: URL) -> Int {
    let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
    return (attributes?[.posixPermissions] as? NSNumber)?.intValue ?? -1
}

private func makePrivateFile(_ url: URL) throws {
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
}

/// Produces a minimal single-page PDF whose text remains extractable by PDFKit.
private func minimalTextPDF(_ text: String) -> Data {
    let escaped = text
        .replacingOccurrences(of: "\\", with: "\\\\")
        .replacingOccurrences(of: "(", with: "\\(")
        .replacingOccurrences(of: ")", with: "\\)")
    let stream = "BT /F1 16 Tf 72 720 Td (\(escaped)) Tj ET"
    let objects = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        "<< /Length \(stream.utf8.count) >>\nstream\n\(stream)\nendstream",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
    ]
    var pdf = "%PDF-1.4\n"
    var offsets = [0]
    for (index, object) in objects.enumerated() {
        offsets.append(pdf.utf8.count)
        pdf += "\(index + 1) 0 obj\n\(object)\nendobj\n"
    }
    let xrefOffset = pdf.utf8.count
    pdf += "xref\n0 \(objects.count + 1)\n"
    pdf += "0000000000 65535 f \n"
    for offset in offsets.dropFirst() {
        pdf += String(format: "%010d 00000 n \n", offset)
    }
    pdf += "trailer\n<< /Size \(objects.count + 1) /Root 1 0 R >>\n"
    pdf += "startxref\n\(xrefOffset)\n%%EOF\n"
    return Data(pdf.utf8)
}
