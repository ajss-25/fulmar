import Foundation
import Darwin
import Testing
@testable import LocalHarness

private struct UpdateZIPFixtureEntry {
    let localPath: String
    let centralPath: String
    let mode: UInt32
    let data: Data
    let compressedData: Data?
    let declaredExpandedSize: Int?
    let method: UInt16
    let crc32: UInt32?

    init(
        _ path: String,
        mode: UInt32,
        data: Data = Data(),
        compressedData: Data? = nil,
        declaredExpandedSize: Int? = nil,
        method: UInt16 = 0,
        centralPath: String? = nil,
        crc32: UInt32? = nil
    ) {
        localPath = path
        self.centralPath = centralPath ?? path
        self.mode = mode
        self.data = data
        self.compressedData = compressedData
        self.declaredExpandedSize = declaredExpandedSize
        self.method = method
        self.crc32 = crc32
    }
}

private enum UpdateArchiveFixtureError: Error { case extractor }

private final class UpdateArchiveFixture {
    let root: URL
    let support: URL
    let archive: URL

    init(entries: [UpdateZIPFixtureEntry] = UpdateArchiveFixture.safeEntries) throws {
        // The production updater accepts only canonical storage paths. Use
        // /private/tmp rather than NSTemporaryDirectory's /var symlink so the
        // fixtures exercise the same no-symlink topology as Application Support.
        root = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
            .appendingPathComponent("local-harness-update-tests.\(UUID().uuidString)", isDirectory: true)
        support = root.appendingPathComponent("Local Harness", isDirectory: true)
        archive = root.appendingPathComponent("update.zip", isDirectory: false)
        try FileManager.default.createDirectory(at: support, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: support.path)
        try makeUpdateZIP(entries).write(to: archive, options: .withoutOverwriting)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: archive.path)
    }

    deinit { try? FileManager.default.removeItem(at: root) }

    static let safeEntries = [
        UpdateZIPFixtureEntry("Fulmar.app/", mode: 0o040755),
        UpdateZIPFixtureEntry("Fulmar.app/Contents/", mode: 0o040755),
        UpdateZIPFixtureEntry("Fulmar.app/Contents/Info.plist", mode: 0o100644)
    ]

    static let legitimateBinLinks: [(name: String, target: String)] = [
        ("is-docker", "../is-docker/cli.js"),
        ("is-inside-container", "../is-inside-container/cli.js"),
        ("loose-envify", "../loose-envify/cli.js"),
        ("node-which", "../which/bin/node-which"),
        ("js-yaml", "../js-yaml/bin/js-yaml.js"),
        ("pi-ai", "../@earendil-works/pi-ai/dist/cli.js"),
        ("semver", "../semver/bin/semver.js"),
        ("cordis", "../@deepseek-ai/cordis/bin.js"),
        ("yaml", "../yaml/bin.mjs"),
        ("anthropic-ai-sdk", "../@anthropic-ai/sdk/bin/cli"),
        ("openai", "../openai/bin/cli")
    ]

    static var legitimateBinEntries: [UpdateZIPFixtureEntry] {
        let root = "Fulmar.app/Contents/Resources/Runtime/dsh/node_modules"
        var directories: Set<String> = [
            "Fulmar.app",
            "Fulmar.app/Contents",
            "Fulmar.app/Contents/Resources",
            "Fulmar.app/Contents/Resources/Runtime",
            "Fulmar.app/Contents/Resources/Runtime/dsh",
            root,
            "\(root)/.bin"
        ]
        var files: [String] = []
        for (_, target) in legitimateBinLinks {
            var components = target.split(separator: "/").map(String.init)
            precondition(components.removeFirst() == "..")
            let file = "\(root)/\(components.joined(separator: "/"))"
            files.append(file)
            var parent = file.split(separator: "/").dropLast().map(String.init)
            while parent.count > 1 {
                directories.insert(parent.joined(separator: "/"))
                parent.removeLast()
            }
        }
        let orderedDirectories = directories.sorted {
            let leftDepth = $0.split(separator: "/").count
            let rightDepth = $1.split(separator: "/").count
            return leftDepth == rightDepth ? $0 < $1 : leftDepth < rightDepth
        }
        var entries = orderedDirectories.map { UpdateZIPFixtureEntry("\($0)/", mode: 0o040755) }
        entries += files.sorted().map {
            UpdateZIPFixtureEntry($0, mode: 0o100755, data: Data("#!/bin/sh\n".utf8))
        }
        entries += legitimateBinLinks.map {
            UpdateZIPFixtureEntry("\(root)/.bin/\($0.name)", mode: 0o120755, data: Data($0.target.utf8))
        }
        return entries
    }

    var updateRoot: URL { support.appendingPathComponent("Updates", isDirectory: true) }
    var stagedBase: URL { updateRoot.appendingPathComponent("Staged", isDirectory: true) }
}

private func updateArchiveLimits(
    archiveBytes: UInt64 = 1_024 * 1_024,
    entries: Int = 100,
    expandedBytes: UInt64 = 1_024 * 1_024,
    entryBytes: UInt64 = 1_024 * 1_024,
    pathBytes: Int = 4_096,
    depth: Int = 64
) -> UpdateArchiveLimits {
    UpdateArchiveLimits(
        maximumArchiveBytes: archiveBytes,
        maximumCentralDirectoryBytes: 256 * 1_024,
        maximumEntries: entries,
        maximumExpandedBytes: expandedBytes,
        maximumEntryBytes: entryBytes,
        maximumPathBytes: pathBytes,
        maximumPathDepth: depth
    )
}

private func makeTermResistantUpdateFixtureExecutable(in root: URL) throws -> URL {
    let executable = root.appendingPathComponent("hung-update-child")
    try Data("#!/bin/sh\ntrap '' TERM INT HUP\nwhile :; do /bin/sleep 1; done\n".utf8)
        .write(to: executable, options: .withoutOverwriting)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
    return executable
}

private func updateProcessGroupIsGone(_ processGroup: pid_t, timeout: TimeInterval = 2) -> Bool {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        if Darwin.kill(-processGroup, 0) != 0, errno == ESRCH { return true }
        usleep(10_000)
    }
    return Darwin.kill(-processGroup, 0) != 0 && errno == ESRCH
}

@Test func updateArchivePreflightAcceptsOnlyTheReviewedSingleAppTopology() throws {
    let fixture = try UpdateArchiveFixture()
    let inspection = try SecureUpdateArchive.inspect(fixture.archive, limits: updateArchiveLimits())
    #expect(inspection.applicationRootName == "Fulmar.app")
    #expect(inspection.expandedBytes == 0)
    #expect(inspection.archiveBytes > 22)
}

@Test func updateArchivePreflightRejectsAValidSingleAppUnderAnyNonReleaseName() throws {
    let fixture = try UpdateArchiveFixture(entries: [
        UpdateZIPFixtureEntry("Local Harness.app/", mode: 0o040755),
        UpdateZIPFixtureEntry("Local Harness.app/Contents/", mode: 0o040755),
        UpdateZIPFixtureEntry("Local Harness.app/Contents/Info.plist", mode: 0o100644)
    ])
    #expect(throws: UpdateError.self) {
        _ = try SecureUpdateArchive.inspect(fixture.archive, limits: updateArchiveLimits())
    }
}

@Test func updateArchiveAcceptsAndExtractsTheElevenReviewedNPMBinLinks() throws {
    let fixture = try UpdateArchiveFixture(entries: UpdateArchiveFixture.legitimateBinEntries)
    let inspection = try SecureUpdateArchive.inspect(fixture.archive, limits: updateArchiveLimits())
    #expect(inspection.applicationRootName == "Fulmar.app")
    #expect(inspection.expandedBytes > 0)

    let stager = UpdateArchiveStager(root: fixture.updateRoot, limits: updateArchiveLimits())
    let staged = try stager.stage(archive: fixture.archive)
    let bin = staged.appURL.appendingPathComponent(
        "Contents/Resources/Runtime/dsh/node_modules/.bin",
        isDirectory: true
    )
    for link in UpdateArchiveFixture.legitimateBinLinks {
        let actual = try FileManager.default.destinationOfSymbolicLink(
            atPath: bin.appendingPathComponent(link.name).path
        )
        #expect(actual == link.target)
    }
    stager.discard(staged)
}

@Test func updateArchiveStagerTightensLegacyOwnerOnlyStorageBeforeExtraction() throws {
    let fixture = try UpdateArchiveFixture()
    try FileManager.default.createDirectory(
        at: fixture.stagedBase,
        withIntermediateDirectories: true
    )
    for directory in [fixture.updateRoot, fixture.stagedBase] {
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o755],
            ofItemAtPath: directory.path
        )
    }

    let stager = UpdateArchiveStager(root: fixture.updateRoot, limits: updateArchiveLimits())
    let staged = try stager.stage(archive: fixture.archive)
    defer { stager.discard(staged) }

    for directory in [fixture.updateRoot, fixture.stagedBase] {
        let attributes = try FileManager.default.attributesOfItem(atPath: directory.path)
        #expect((attributes[.posixPermissions] as? NSNumber)?.uint16Value == 0o700)
    }
}

@Test func updateArchiveStagerOrphanSweepRemovesOnlyExactPrivateUUIDOperations() throws {
    let fileManager = FileManager.default
    let fixture = try UpdateArchiveFixture()
    try fileManager.createDirectory(at: fixture.stagedBase, withIntermediateDirectories: true)
    for directory in [fixture.updateRoot, fixture.stagedBase] {
        try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
    }
    let valid = fixture.stagedBase.appendingPathComponent(UUID().uuidString, isDirectory: true)
    try fileManager.createDirectory(at: valid, withIntermediateDirectories: false)
    try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: valid.path)
    try Data("orphan".utf8).write(to: valid.appendingPathComponent("payload"))

    let external = fixture.root.appendingPathComponent("External", isDirectory: true)
    let sentinel = external.appendingPathComponent("sentinel")
    try fileManager.createDirectory(at: external, withIntermediateDirectories: false)
    try Data("keep".utf8).write(to: sentinel)
    let linked = fixture.stagedBase.appendingPathComponent(UUID().uuidString, isDirectory: true)
    try fileManager.createSymbolicLink(at: linked, withDestinationURL: external)
    let unrecognized = fixture.stagedBase.appendingPathComponent("manual-recovery", isDirectory: true)
    try fileManager.createDirectory(at: unrecognized, withIntermediateDirectories: false)

    UpdateArchiveStager(root: fixture.updateRoot, limits: updateArchiveLimits())
        .discardOrphanedStages()

    #expect(!fileManager.fileExists(atPath: valid.path))
    #expect(fileManager.fileExists(atPath: linked.path))
    #expect(fileManager.fileExists(atPath: unrecognized.path))
    #expect(try Data(contentsOf: sentinel) == Data("keep".utf8))
}

@Test func updateArchiveRejectsEveryUnsafeSymlinkTargetAndTopology() throws {
    let root = UpdateZIPFixtureEntry("Fulmar.app/", mode: 0o040755)
    let targetFile = UpdateZIPFixtureEntry(
        "Fulmar.app/target",
        mode: 0o100644,
        data: Data("safe".utf8)
    )
    func link(_ target: Data, path: String = "Fulmar.app/link", mode: UInt32 = 0o120755) -> UpdateZIPFixtureEntry {
        UpdateZIPFixtureEntry(path, mode: mode, data: target)
    }

    let hostile: [[UpdateZIPFixtureEntry]] = [
        [root, targetFile, link(Data())],
        [root, targetFile, link(Data("/tmp/outside".utf8))],
        [root, targetFile, link(Data("C:/outside".utf8))],
        [root, targetFile, link(Data("../../outside".utf8))],
        [root, targetFile, link(Data("folder/../target".utf8))],
        [root, targetFile, link(Data("missing".utf8))],
        [root, targetFile, link(Data("Target".utf8))],
        [
            root,
            UpdateZIPFixtureEntry("Fulmar.app/target/", mode: 0o040755),
            link(Data("target".utf8))
        ],
        [
            root,
            link(Data("second".utf8), path: "Fulmar.app/first"),
            link(Data("target".utf8), path: "Fulmar.app/second"),
            targetFile
        ],
        [
            root,
            link(Data("second".utf8), path: "Fulmar.app/first"),
            link(Data("first".utf8), path: "Fulmar.app/second")
        ],
        [
            root,
            targetFile,
            link(Data("target".utf8)),
            UpdateZIPFixtureEntry("Fulmar.app/link/child", mode: 0o100644)
        ],
        [root, targetFile, link(Data("target/".utf8))],
        [root, targetFile, link(Data("target\\alias".utf8))],
        [root, targetFile, link(Data([0x1f]))],
        [root, targetFile, link(Data("target".utf8), mode: 0o120777)],
        [
            root,
            UpdateZIPFixtureEntry("Fulmar.app/special", mode: 0o010644),
            link(Data("special".utf8))
        ]
    ]

    for entries in hostile {
        let fixture = try UpdateArchiveFixture(entries: entries)
        #expect(throws: UpdateError.self) {
            _ = try SecureUpdateArchive.inspect(fixture.archive, limits: updateArchiveLimits())
        }
    }
}

@Test func updateArchiveRejectsSymlinkPayloadWhoseCRCDoesNotMatchMetadata() throws {
    let fixture = try UpdateArchiveFixture(entries: [
        UpdateZIPFixtureEntry("Fulmar.app/", mode: 0o040755),
        UpdateZIPFixtureEntry("Fulmar.app/target", mode: 0o100644),
        UpdateZIPFixtureEntry(
            "Fulmar.app/link",
            mode: 0o120755,
            data: Data("target".utf8),
            crc32: 0
        )
    ])
    #expect(throws: UpdateError.self) {
        _ = try SecureUpdateArchive.inspect(fixture.archive, limits: updateArchiveLimits())
    }
}

@Test(.disabled(
    if: ProcessInfo.processInfo.environment["LOCAL_HARNESS_UPDATE_ARCHIVE_TEST_PATH"] == nil,
    "Requires the release runner's exact frozen archive fixture."
))
func updateArchiveReleaseArtifactPassesTheSameNativePreflightWhenProvided() throws {
    let path = try #require(
        ProcessInfo.processInfo.environment["LOCAL_HARNESS_UPDATE_ARCHIVE_TEST_PATH"]
    )
    let fixture = try UpdateArchiveFixture()
    let stager = UpdateArchiveStager(root: fixture.updateRoot, limits: .production)
    let staged = try stager.stage(archive: URL(fileURLWithPath: path))
    #expect(staged.appURL.lastPathComponent == "Fulmar.app")
    #expect(FileManager.default.fileExists(
        atPath: staged.appURL.appendingPathComponent("Contents/Info.plist").path
    ))
    #expect(staged.stageRoot.deletingLastPathComponent() == fixture.stagedBase)
    stager.discard(staged)
    #expect(!FileManager.default.fileExists(atPath: staged.stageRoot.path))
}

@Test func updateArchivePreflightRejectsHostilePathsAliasesAndTypes() throws {
    let hostile: [[UpdateZIPFixtureEntry]] = [
        [
            UpdateZIPFixtureEntry("Fulmar.app/", mode: 0o040755),
            UpdateZIPFixtureEntry("Fulmar.app/../escape", mode: 0o100644)
        ],
        [UpdateZIPFixtureEntry("/Fulmar.app/", mode: 0o040755)],
        [UpdateZIPFixtureEntry("C:/Fulmar.app/", mode: 0o040755)],
        [
            UpdateZIPFixtureEntry("Fulmar.app/", mode: 0o040755),
            UpdateZIPFixtureEntry("Fulmar.app/item", mode: 0o100644),
            UpdateZIPFixtureEntry("Fulmar.app/item", mode: 0o100644)
        ],
        [
            UpdateZIPFixtureEntry("Fulmar.app/", mode: 0o040755),
            UpdateZIPFixtureEntry("Fulmar.app/Contents/", mode: 0o040755),
            UpdateZIPFixtureEntry("Fulmar.app/contents/", mode: 0o040755)
        ],
        [
            UpdateZIPFixtureEntry("Fulmar.app/", mode: 0o040755),
            UpdateZIPFixtureEntry("Fulmar.app/link", mode: 0o120777)
        ],
        [
            UpdateZIPFixtureEntry("Fulmar.app/", mode: 0o040755),
            UpdateZIPFixtureEntry("Fulmar.app/fifo", mode: 0o010644)
        ],
        [
            UpdateZIPFixtureEntry("First.app/", mode: 0o040755),
            UpdateZIPFixtureEntry("Second.app/", mode: 0o040755)
        ],
        [UpdateZIPFixtureEntry("Fulmar.app/", mode: 0o040777)],
        [
            UpdateZIPFixtureEntry("Fulmar.app/", mode: 0o040755),
            UpdateZIPFixtureEntry("Fulmar.app/tool", mode: 0o100644, method: 99)
        ]
    ]

    for entries in hostile {
        let fixture = try UpdateArchiveFixture(entries: entries)
        #expect(throws: UpdateError.self) {
            _ = try SecureUpdateArchive.inspect(fixture.archive, limits: updateArchiveLimits())
        }
    }
}

@Test func updateArchivePreflightRejectsCentralLocalNameDisagreement() throws {
    let fixture = try UpdateArchiveFixture(entries: [
        UpdateZIPFixtureEntry("Fulmar.app/", mode: 0o040755),
        UpdateZIPFixtureEntry(
            "../outside.txt",
            mode: 0o100644,
            centralPath: "Fulmar.app/safe.txt"
        )
    ])
    #expect(throws: UpdateError.self) {
        _ = try SecureUpdateArchive.inspect(fixture.archive, limits: updateArchiveLimits())
    }
}

@Test func updateArchivePreflightEnforcesArchiveEntryAndExpansionBounds() throws {
    let fixture = try UpdateArchiveFixture(entries: [
        UpdateZIPFixtureEntry("Fulmar.app/", mode: 0o040755),
        UpdateZIPFixtureEntry("Fulmar.app/large", mode: 0o100644, data: Data(repeating: 0, count: 32))
    ])

    #expect(throws: UpdateError.self) {
        _ = try SecureUpdateArchive.inspect(
            fixture.archive,
            limits: updateArchiveLimits(archiveBytes: UInt64(try Data(contentsOf: fixture.archive).count - 1))
        )
    }
    #expect(throws: UpdateError.self) {
        _ = try SecureUpdateArchive.inspect(fixture.archive, limits: updateArchiveLimits(entries: 1))
    }
    #expect(throws: UpdateError.self) {
        _ = try SecureUpdateArchive.inspect(
            fixture.archive,
            limits: updateArchiveLimits(expandedBytes: 31, entryBytes: 31)
        )
    }
}

@Test func updateArchivePreflightStreamsAndValidatesActualDeflateOutput() throws {
    let content = Data("validated deflate payload".utf8)
    let valid = try UpdateArchiveFixture(entries: [
        UpdateZIPFixtureEntry("Fulmar.app/", mode: 0o040755),
        UpdateZIPFixtureEntry(
            "Fulmar.app/content",
            mode: 0o100644,
            data: content,
            compressedData: updateFixtureRawDeflate(content),
            method: 8
        )
    ])
    _ = try SecureUpdateArchive.inspect(valid.archive, limits: updateArchiveLimits())

    let understated = try UpdateArchiveFixture(entries: [
        UpdateZIPFixtureEntry("Fulmar.app/", mode: 0o040755),
        UpdateZIPFixtureEntry(
            "Fulmar.app/content",
            mode: 0o100644,
            data: content,
            compressedData: updateFixtureRawDeflate(content),
            declaredExpandedSize: 1,
            method: 8
        )
    ])
    #expect(throws: UpdateError.self) {
        _ = try SecureUpdateArchive.inspect(understated.archive, limits: updateArchiveLimits())
    }

    let truncatedCompressed = updateFixtureRawDeflate(content).dropLast()
    let truncated = try UpdateArchiveFixture(entries: [
        UpdateZIPFixtureEntry("Fulmar.app/", mode: 0o040755),
        UpdateZIPFixtureEntry(
            "Fulmar.app/content",
            mode: 0o100644,
            data: content,
            compressedData: Data(truncatedCompressed),
            method: 8
        )
    ])
    #expect(throws: UpdateError.self) {
        _ = try SecureUpdateArchive.inspect(truncated.archive, limits: updateArchiveLimits())
    }
}

@Test func updateArchivePreflightRejectsLinkedAndHardLinkedArchives() throws {
    let fixture = try UpdateArchiveFixture()
    let linked = fixture.root.appendingPathComponent("linked.zip")
    try FileManager.default.createSymbolicLink(at: linked, withDestinationURL: fixture.archive)
    #expect(throws: UpdateError.self) {
        _ = try SecureUpdateArchive.inspect(linked, limits: updateArchiveLimits())
    }

    let hard = fixture.root.appendingPathComponent("hard.zip")
    try FileManager.default.linkItem(at: fixture.archive, to: hard)
    #expect(throws: UpdateError.self) {
        _ = try SecureUpdateArchive.inspect(fixture.archive, limits: updateArchiveLimits())
    }
}

@Test func updateArchiveStagerUsesPrivateContainedTopologyAndRealDitto() throws {
    let fixture = try UpdateArchiveFixture()
    let stager = UpdateArchiveStager(root: fixture.updateRoot, limits: updateArchiveLimits())
    let staged = try stager.stage(archive: fixture.archive)
    #expect(staged.appURL.lastPathComponent == "Fulmar.app")
    #expect(FileManager.default.fileExists(atPath: staged.appURL.appendingPathComponent("Contents/Info.plist").path))
    let attributes = try FileManager.default.attributesOfItem(atPath: staged.stageRoot.path)
    #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o700)
    #expect(staged.stageRoot.deletingLastPathComponent() == fixture.stagedBase)
    #expect(staged.appURL.deletingLastPathComponent().lastPathComponent == "Expanded")
    #expect(try FileManager.default.contentsOfDirectory(atPath: staged.stageRoot.path) == ["Expanded"])

    stager.discard(staged)
    #expect(!FileManager.default.fileExists(atPath: staged.stageRoot.path))
}

@Test func updateArchiveStagerBoundsAndCleansAHungDittoProcessGroup() throws {
    let fixture = try UpdateArchiveFixture()
    let executable = try makeTermResistantUpdateFixtureExecutable(in: fixture.root)
    var processGroup: pid_t = 0
    let stager = UpdateArchiveStager(
        root: fixture.updateRoot,
        limits: updateArchiveLimits(),
        extractor: { input, destination in
            try UpdateArchiveStager.extractWithBoundedProcess(
                input,
                destination,
                executable: executable,
                deadline: 0.1,
                terminationGrace: 0.05,
                onSpawn: { processGroup = $0 }
            )
        }
    )

    let started = Date()
    #expect(throws: UpdateError.self) { _ = try stager.stage(archive: fixture.archive) }
    #expect(Date().timeIntervalSince(started) < 2)
    #expect(processGroup > 1)
    #expect(updateProcessGroupIsGone(processGroup))
    #expect((try? FileManager.default.contentsOfDirectory(atPath: fixture.stagedBase.path))?.isEmpty == true)
}

@Test func updateGatekeeperAssessmentBoundsAndReapsAHungChildGroup() throws {
    let fixture = try UpdateArchiveFixture()
    let executable = try makeTermResistantUpdateFixtureExecutable(in: fixture.root)
    var processGroup: pid_t = 0
    let started = Date()
    let accepted = UpdateManager.gatekeeperAccepts(
        fixture.root,
        executable: executable,
        deadline: 0.1,
        terminationGrace: 0.05,
        onSpawn: { processGroup = $0 }
    )
    #expect(!accepted)
    #expect(Date().timeIntervalSince(started) < 2)
    #expect(processGroup > 1)
    #expect(updateProcessGroupIsGone(processGroup))
}

@Test func updateArchiveStagerExtractsTheImmutableUnlinkedSnapshot() throws {
    let fixture = try UpdateArchiveFixture()
    let original = try Data(contentsOf: fixture.archive)
    var extractedInput: Data?
    var observedLinks: nlink_t = 1
    var observedAccessMode: Int32 = O_WRONLY
    let stager = UpdateArchiveStager(
        root: fixture.updateRoot,
        limits: updateArchiveLimits(),
        extractor: { input, destination in
            var info = stat()
            #expect(fstat(input.fileDescriptor, &info) == 0)
            observedLinks = info.st_nlink
            observedAccessMode = fcntl(input.fileDescriptor, F_GETFL) & O_ACCMODE

            try FileManager.default.removeItem(at: fixture.archive)
            try Data("attacker replacement".utf8).write(to: fixture.archive, options: .withoutOverwriting)
            try input.seek(toOffset: 0)
            extractedInput = try input.readToEnd()

            let contents = destination.appendingPathComponent("Fulmar.app/Contents", isDirectory: true)
            try FileManager.default.createDirectory(at: contents, withIntermediateDirectories: true)
            let app = contents.deletingLastPathComponent()
            for directory in [app, contents] {
                try FileManager.default.setAttributes(
                    [.posixPermissions: 0o755],
                    ofItemAtPath: directory.path
                )
            }
            let infoPlist = contents.appendingPathComponent("Info.plist")
            try Data().write(to: infoPlist, options: .withoutOverwriting)
            // The isolated test launcher uses umask 077. Reproduce the exact
            // mode declared by UpdateArchiveFixture rather than inheriting the
            // caller's umask and tripping post-extraction attestation.
            try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: infoPlist.path)
        }
    )
    let staged = try stager.stage(archive: fixture.archive)
    #expect(extractedInput == original)
    #expect(observedLinks == 0)
    #expect(observedAccessMode == O_RDONLY)
    stager.discard(staged)
}

@Test func updateArchiveStagerRejectsPostExtractionSymlinkTargetMutation() throws {
    let entries = [
        UpdateZIPFixtureEntry("Fulmar.app/", mode: 0o040755),
        UpdateZIPFixtureEntry("Fulmar.app/target", mode: 0o100644, data: Data("safe".utf8)),
        UpdateZIPFixtureEntry("Fulmar.app/link", mode: 0o120755, data: Data("target".utf8))
    ]
    let fixture = try UpdateArchiveFixture(entries: entries)
    let stager = UpdateArchiveStager(
        root: fixture.updateRoot,
        limits: updateArchiveLimits(),
        extractor: { _, destination in
            let app = destination.appendingPathComponent("Fulmar.app", isDirectory: true)
            try FileManager.default.createDirectory(at: app, withIntermediateDirectories: true)
            try Data("safe".utf8).write(to: app.appendingPathComponent("target"), options: .withoutOverwriting)
            try FileManager.default.createSymbolicLink(
                atPath: app.appendingPathComponent("link").path,
                withDestinationPath: "other"
            )
        }
    )
    #expect(throws: UpdateError.self) { _ = try stager.stage(archive: fixture.archive) }
    #expect((try? FileManager.default.contentsOfDirectory(atPath: fixture.stagedBase.path))?.isEmpty == true)
}

@Test func updateArchiveStagerRejectsPostExtractionModeMutation() throws {
    let fixture = try UpdateArchiveFixture()
    let stager = UpdateArchiveStager(
        root: fixture.updateRoot,
        limits: updateArchiveLimits(),
        extractor: { _, destination in
            let contents = destination.appendingPathComponent("Fulmar.app/Contents", isDirectory: true)
            try FileManager.default.createDirectory(at: contents, withIntermediateDirectories: true)
            let info = contents.appendingPathComponent("Info.plist")
            try Data().write(to: info, options: .withoutOverwriting)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: info.path)
        }
    )
    #expect(throws: UpdateError.self) { _ = try stager.stage(archive: fixture.archive) }
    #expect((try? FileManager.default.contentsOfDirectory(atPath: fixture.stagedBase.path))?.isEmpty == true)
}

@Test func updateArchiveStagerCleansFailedExtractionAndUnexpectedOutput() throws {
    let extractionFailure = try UpdateArchiveFixture()
    let failing = UpdateArchiveStager(
        root: extractionFailure.updateRoot,
        limits: updateArchiveLimits(),
        extractor: { _, _ in throw UpdateArchiveFixtureError.extractor }
    )
    #expect(throws: UpdateError.self) { _ = try failing.stage(archive: extractionFailure.archive) }
    #expect((try? FileManager.default.contentsOfDirectory(atPath: extractionFailure.stagedBase.path))?.isEmpty == true)

    let extraOutput = try UpdateArchiveFixture()
    let injecting = UpdateArchiveStager(
        root: extraOutput.updateRoot,
        limits: updateArchiveLimits(),
        extractor: { _, destination in
            let contents = destination.appendingPathComponent("Fulmar.app/Contents", isDirectory: true)
            try FileManager.default.createDirectory(at: contents, withIntermediateDirectories: true)
            try Data().write(to: contents.appendingPathComponent("Info.plist"), options: .withoutOverwriting)
            try Data().write(to: contents.appendingPathComponent("unexpected"), options: .withoutOverwriting)
        }
    )
    #expect(throws: UpdateError.self) { _ = try injecting.stage(archive: extraOutput.archive) }
    #expect((try? FileManager.default.contentsOfDirectory(atPath: extraOutput.stagedBase.path))?.isEmpty == true)
}

@Test func updateArchiveStagerRejectsLinkedOutputAndLinkedStorageRoots() throws {
    let linkedOutput = try UpdateArchiveFixture()
    let outside = linkedOutput.root.appendingPathComponent("outside.txt")
    try Data("unchanged".utf8).write(to: outside, options: .withoutOverwriting)
    let injectingLink = UpdateArchiveStager(
        root: linkedOutput.updateRoot,
        limits: updateArchiveLimits(),
        extractor: { _, destination in
            let contents = destination.appendingPathComponent("Fulmar.app/Contents", isDirectory: true)
            try FileManager.default.createDirectory(at: contents, withIntermediateDirectories: true)
            try FileManager.default.createSymbolicLink(
                at: contents.appendingPathComponent("Info.plist"),
                withDestinationURL: outside
            )
        }
    )
    #expect(throws: UpdateError.self) { _ = try injectingLink.stage(archive: linkedOutput.archive) }
    #expect(try Data(contentsOf: outside) == Data("unchanged".utf8))
    #expect((try? FileManager.default.contentsOfDirectory(atPath: linkedOutput.stagedBase.path))?.isEmpty == true)

    let linkedStorage = try UpdateArchiveFixture()
    let attacker = linkedStorage.root.appendingPathComponent("attacker", isDirectory: true)
    try FileManager.default.createDirectory(at: attacker, withIntermediateDirectories: false)
    try FileManager.default.createSymbolicLink(at: linkedStorage.updateRoot, withDestinationURL: attacker)
    let stager = UpdateArchiveStager(root: linkedStorage.updateRoot, limits: updateArchiveLimits())
    #expect(throws: UpdateError.self) { _ = try stager.stage(archive: linkedStorage.archive) }
    #expect(try FileManager.default.contentsOfDirectory(atPath: attacker.path).isEmpty)
}

private func makeUpdateZIP(_ entries: [UpdateZIPFixtureEntry]) throws -> Data {
    guard entries.count <= Int(UInt16.max) else { throw UpdateError.invalidArchive }
    var local = Data()
    var centralRecords: [(entry: UpdateZIPFixtureEntry, offset: UInt32)] = []

    for entry in entries {
        let localName = Data(entry.localPath.utf8)
        let payload = entry.compressedData ?? entry.data
        guard localName.count <= Int(UInt16.max),
              let offset = UInt32(exactly: local.count),
              let compressedSize = UInt32(exactly: payload.count),
              let expandedSize = UInt32(exactly: entry.declaredExpandedSize ?? entry.data.count) else {
            throw UpdateError.invalidArchive
        }
        let crc = entry.crc32 ?? updateFixtureCRC32(entry.data)
        centralRecords.append((entry, offset))
        local.appendLE(UInt32(0x04034b50))
        local.appendLE(UInt16(20))
        local.appendLE(UInt16(0))
        local.appendLE(entry.method)
        local.appendLE(UInt16(0))
        local.appendLE(UInt16(0))
        local.appendLE(crc)
        local.appendLE(compressedSize)
        local.appendLE(expandedSize)
        local.appendLE(UInt16(localName.count))
        local.appendLE(UInt16(0))
        local.append(localName)
        local.append(payload)
    }

    let centralOffset = try #require(UInt32(exactly: local.count))
    var central = Data()
    for record in centralRecords {
        let name = Data(record.entry.centralPath.utf8)
        let payload = record.entry.compressedData ?? record.entry.data
        let compressedSize = try #require(UInt32(exactly: payload.count))
        let expandedSize = try #require(UInt32(
            exactly: record.entry.declaredExpandedSize ?? record.entry.data.count
        ))
        central.appendLE(UInt32(0x02014b50))
        central.appendLE(UInt16((3 << 8) | 20))
        central.appendLE(UInt16(20))
        central.appendLE(UInt16(0))
        central.appendLE(record.entry.method)
        central.appendLE(UInt16(0))
        central.appendLE(UInt16(0))
        central.appendLE(record.entry.crc32 ?? updateFixtureCRC32(record.entry.data))
        central.appendLE(compressedSize)
        central.appendLE(expandedSize)
        central.appendLE(UInt16(name.count))
        central.appendLE(UInt16(0))
        central.appendLE(UInt16(0))
        central.appendLE(UInt16(0))
        central.appendLE(UInt16(0))
        central.appendLE((record.entry.mode << 16) | 0x4000)
        central.appendLE(record.offset)
        central.append(name)
    }

    let centralSize = try #require(UInt32(exactly: central.count))
    var archive = local
    archive.append(central)
    archive.appendLE(UInt32(0x06054b50))
    archive.appendLE(UInt16(0))
    archive.appendLE(UInt16(0))
    archive.appendLE(UInt16(entries.count))
    archive.appendLE(UInt16(entries.count))
    archive.appendLE(centralSize)
    archive.appendLE(centralOffset)
    archive.appendLE(UInt16(0))
    return archive
}

private func updateFixtureRawDeflate(_ data: Data) -> Data {
    precondition(data.count <= Int(UInt16.max))
    let length = UInt16(data.count)
    var result = Data([0x01])
    result.appendLE(length)
    result.appendLE(~length)
    result.append(data)
    return result
}

private func updateFixtureCRC32(_ data: Data) -> UInt32 {
    var crc = UInt32.max
    for byte in data {
        crc ^= UInt32(byte)
        for _ in 0..<8 {
            crc = (crc >> 1) ^ ((crc & 1) == 0 ? 0 : 0xedb88320)
        }
    }
    return ~crc
}

private extension Data {
    mutating func appendLE<T: FixedWidthInteger>(_ value: T) {
        var littleEndian = value.littleEndian
        Swift.withUnsafeBytes(of: &littleEndian) { append(contentsOf: $0) }
    }
}
