import Darwin
import Foundation
import Testing
@testable import LocalHarness

private func withServiceLogStore(
    maxBytes: Int = 1_000_000,
    maximumLineBytes: Int = 64 * 1_024,
    _ body: (ServiceLogStore) throws -> Void
) throws {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("service-log-tests-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    try body(ServiceLogStore(
        directory: directory,
        maxBytes: maxBytes,
        maximumChunkBytes: maximumLineBytes
    ))
}

@Test func serviceLogStreamsRedactSecretsSplitAtEveryByteBoundary() throws {
    try withServiceLogStore { store in
        let secret = "every-boundary-private-value"
        let line = Data("Authorization: Bearer \(secret)\n".utf8)
        for split in 0...line.count {
            let stream = store.openStream(label: "stdout")
            store.append(line.prefix(split), to: stream)
            store.append(line.dropFirst(split), to: stream)
            store.finish(stream)
        }

        let logs = store.recentLogs(maxCharacters: 64_000)
        #expect(!logs.contains(secret))
        #expect(logs.components(separatedBy: "<redacted>").count - 1 == line.count + 1)
    }
}

@Test func serviceLogStreamsDoNotPersistIncompleteRawFragments() throws {
    try withServiceLogStore { store in
        let stream = store.openStream(label: "stdout")
        store.append(Data("API_KEY=unterminated-private-value".utf8), to: stream)

        #expect(store.recentLogs() == "No service log entries yet.")
        #expect(!FileManager.default.fileExists(atPath: store.logURL.path))

        store.finish(stream)
        let logs = store.recentLogs()
        #expect(!logs.contains("unterminated-private-value"))
        #expect(logs.contains("API_KEY=<redacted>"))
    }
}

@Test func serviceLogStreamsHandleCRLFAndInvalidUTF8AfterAssembly() throws {
    try withServiceLogStore { store in
        let stream = store.openStream(label: "stderr")
        store.append(Data("Authorization: Bearer crlf-private".utf8), to: stream)
        store.append(Data([0x0D]), to: stream)
        store.append(Data([0x0A, 0x69, 0x6E, 0x76, 0x61, 0x6C, 0x69, 0x64, 0x3A, 0xFF, 0x0A]), to: stream)
        store.finish(stream)

        let logs = store.recentLogs()
        #expect(!logs.contains("crlf-private"))
        #expect(!logs.contains("\r"))
        #expect(logs.contains("Authorization: Bearer <redacted>"))
        #expect(logs.contains("invalid:�"))
    }
}

@Test func serviceLogStreamsOmitOversizedLinesWithoutPersistingPrefixes() throws {
    try withServiceLogStore(maximumLineBytes: 16) { store in
        let stream = store.openStream(label: "stdout")
        store.append(Data("API_KEY=".utf8), to: stream)
        store.append(Data(String(repeating: "private", count: 20).utf8), to: stream)

        #expect(store.recentLogs() == "No service log entries yet.")

        store.append(Data("\nnext-line\n".utf8), to: stream)
        store.finish(stream)
        let logs = store.recentLogs()
        #expect(logs.contains("[diagnostic line omitted: oversized]"))
        #expect(logs.contains("next-line"))
        #expect(!logs.contains("API_KEY="))
        #expect(!logs.contains("private"))
    }
}

@Test func serviceLogStreamsRemainIndependentWhenInterleaved() throws {
    try withServiceLogStore { store in
        let stdout = store.openStream(label: "stdout")
        let stderr = store.openStream(label: "stderr")
        store.append(Data("API_".utf8), to: stdout)
        store.append(Data("Authorization: ".utf8), to: stderr)
        store.append(Data("KEY=stdout-private".utf8), to: stdout)
        store.append(Data("Bearer stderr-private".utf8), to: stderr)
        store.append(Data("\n".utf8), to: stderr)
        store.append(Data("\n".utf8), to: stdout)
        store.finish(stdout)
        store.finish(stderr)

        let logs = store.recentLogs()
        #expect(!logs.contains("stdout-private"))
        #expect(!logs.contains("stderr-private"))
        #expect(logs.contains("[stdout] API_KEY=<redacted>"))
        #expect(logs.contains("[stderr] Authorization: Bearer <redacted>"))
    }
}

@Test func serviceLogStreamsSerializeConcurrentWritersWithoutLeakingSecrets() throws {
    try withServiceLogStore { store in
        DispatchQueue.concurrentPerform(iterations: 64) { index in
            let stream = store.openStream(label: "worker-\(index)")
            store.append(Data("Authorization: Bearer ".utf8), to: stream)
            store.append(Data("concurrent-private-\(index)\n".utf8), to: stream)
            store.finish(stream)
        }

        let logs = store.recentLogs(maxCharacters: 64_000)
        for index in 0..<64 {
            #expect(!logs.contains("concurrent-private-\(index)"))
            #expect(logs.contains("[worker-\(index)] Authorization: Bearer <redacted>"))
        }
    }
}

@Test func serviceLogRedactsStandaloneProviderTokensAndMultilinePrivateKeys() throws {
    try withServiceLogStore { store in
        let assembled: ([String]) -> String = { $0.joined() }
        let secrets = [
            assembled(["eyJhbGciOiJ", "IUzI1NiJ9.", "eyJzdWIiOiI", "xMjM0NTY3ODkwIn0.", "signature12345"]),
            assembled(["AK", "IAABCDEFGHIJKLMNOP"]),
            assembled(["gh", "p_abcdefghijklmnopqrstuvwxyz123456"]),
            assembled(["xo", "xb-1234567890-abcdefghijklmnop"]),
            assembled(["h", "f_abcdefghijklmnopqrstuvwxyz123456"]),
            assembled(["AI", "zaABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"]),
            assembled(["s", "k-abcdefghijklmnopqrstuvwxyz"]),
            assembled(["r", "k_abcdefghijklmnopqrstuvwxyz"]),
            assembled(["a", "pi-abcdefghijklmnopqrstuvwxyz"])
        ]
        for secret in secrets {
            store.append(Data("provider output: \(secret)\n".utf8), label: "stderr")
        }

        let stream = store.openStream(label: "plugin")
        store.append(Data("-----BEG".utf8), to: stream)
        store.append(Data("IN PRIVATE KEY-----\n".utf8), to: stream)
        let privateKeyBody = assembled(["MIIEvQI", "BADANBgkqhkiG9w0BA-private-material"])
        store.append(Data("\(privateKeyBody)\n".utf8), to: stream)
        store.append(Data("-----END PRIVATE ".utf8), to: stream)
        store.append(Data("KEY-----\nafter-private-key\n".utf8), to: stream)
        store.finish(stream)

        let logs = store.recentLogs(maxCharacters: 64_000)
        for secret in secrets {
            #expect(!logs.contains(secret))
        }
        #expect(!logs.contains(privateKeyBody))
        #expect(logs.contains("[REDACTED PRIVATE KEY]"))
        #expect(logs.contains("after-private-key"))
        #expect(logs.contains("[REDACTED JWT]"))
        #expect(logs.contains("[REDACTED ACCESS KEY]"))
        #expect(logs.contains("[REDACTED TOKEN]"))
        #expect(logs.contains("[REDACTED API KEY]"))
    }
}

@Test func serviceLogFailsClosedForAnUnterminatedPrivateKeyBlock() throws {
    try withServiceLogStore { store in
        let stream = store.openStream(label: "plugin")
        store.append(Data("-----BEGIN EC PRIVATE KEY-----\n".utf8), to: stream)
        store.append(Data("unterminated-private-material\nmore-private-material".utf8), to: stream)
        store.finish(stream)

        let logs = store.recentLogs()
        #expect(logs.contains("[REDACTED PRIVATE KEY]"))
        #expect(!logs.contains("unterminated-private-material"))
        #expect(!logs.contains("more-private-material"))
    }
}

@Test func oversizedPrivateKeyBeginStillSuppressesFollowingKeyBodyLines() throws {
    try withServiceLogStore(maximumLineBytes: 16) { store in
        let stream = store.openStream(label: "plugin")
        let maximumType = String(repeating: "A", count: 32)
        store.append(Data("diagnostic-prefix-----BEGIN \(maximumType) PRIVATE KEY-----\n".utf8), to: stream)
        store.append(Data("secret-body\nsecond-secret\n".utf8), to: stream)
        store.append(Data("-----END \(maximumType) PRIVATE KEY-----\nafter-key\n".utf8), to: stream)
        store.finish(stream)

        let logs = store.recentLogs()
        #expect(logs.contains("[REDACTED PRIVATE KEY]"))
        #expect(!logs.contains("diagnostic-prefix"))
        #expect(!logs.contains("secret-body"))
        #expect(!logs.contains("second-secret"))
        #expect(logs.contains("after-key"))
    }
}

@Test func serviceLogStoreRejectsASymlinkedDirectoryWithoutWritingOutside() throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("service-log-directory-link-\(UUID().uuidString)", isDirectory: true)
    let outside = root.appendingPathComponent("outside", isDirectory: true)
    let linkedDirectory = root.appendingPathComponent("logs", isDirectory: true)
    try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createSymbolicLink(at: linkedDirectory, withDestinationURL: outside)

    let store = ServiceLogStore(directory: linkedDirectory)
    store.append(Data("must-not-escape\n".utf8), label: "test")

    #expect(!FileManager.default.fileExists(
        atPath: outside.appendingPathComponent("services.log").path
    ))
    #expect(store.recentLogs() == "No service log entries yet.")
    #expect(try linkedDirectory.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink == true)
}

@Test func serviceLogStoreReplacesAHardLinkedLogWithoutMutatingItsPeer() throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("service-log-hard-link-\(UUID().uuidString)", isDirectory: true)
    let directory = root.appendingPathComponent("logs", isDirectory: true)
    let outside = root.appendingPathComponent("outside.log")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
    try Data("outside-must-remain".utf8).write(to: outside)
    try FileManager.default.setAttributes([.posixPermissions: 0o640], ofItemAtPath: outside.path)
    let outsideModeBefore = try #require(
        FileManager.default.attributesOfItem(atPath: outside.path)[.posixPermissions] as? NSNumber
    ).intValue
    defer { try? FileManager.default.removeItem(at: root) }

    let store = ServiceLogStore(directory: directory)
    try FileManager.default.linkItem(at: outside, to: store.logURL)
    store.append(Data("private-replacement\n".utf8), label: "test")

    #expect(try String(contentsOf: outside, encoding: .utf8) == "outside-must-remain")
    let outsideModeAfter = try #require(
        FileManager.default.attributesOfItem(atPath: outside.path)[.posixPermissions] as? NSNumber
    ).intValue
    #expect(outsideModeAfter == outsideModeBefore)
    #expect(store.recentLogs() == "No service log entries yet.")
}

@Test func serviceLogStoreFailsClosedWhenItsRootIsDisplacedBetweenCalls() throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("service-log-root-displacement-\(UUID().uuidString)", isDirectory: true)
    let displaced = root.deletingLastPathComponent()
        .appendingPathComponent("service-log-root-displaced-\(UUID().uuidString)", isDirectory: true)
    defer {
        try? FileManager.default.removeItem(at: root)
        try? FileManager.default.removeItem(at: displaced)
    }
    let store = ServiceLogStore(directory: root)
    store.append(Data("original-entry\n".utf8), label: "test")
    let originalBytes = try Data(contentsOf: store.logURL)

    try FileManager.default.moveItem(at: root, to: displaced)
    try FileManager.default.createDirectory(
        at: root,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
    FileManager.default.createFile(
        atPath: store.logURL.path,
        contents: Data(),
        attributes: [.posixPermissions: 0o600]
    )

    store.append(Data("must-not-enter-replacement-root\n".utf8), label: "test")

    #expect(try Data(contentsOf: store.logURL).isEmpty)
    #expect(try Data(contentsOf: displaced.appendingPathComponent("services.log")) == originalBytes)
    #expect(store.recentLogs() == "No service log entries yet.")
}

@Test func serviceLogStoreRejectsAZeroByteLogReplacementBetweenCalls() throws {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("service-log-zero-replacement-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = ServiceLogStore(directory: directory)
    store.append(Data("original-entry\n".utf8), label: "test")

    try FileManager.default.removeItem(at: store.logURL)
    let replacementDescriptor = Darwin.open(
        store.logURL.path,
        O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
        mode_t(0o600)
    )
    #expect(replacementDescriptor >= 0)
    guard replacementDescriptor >= 0 else { return }
    defer { _ = Darwin.close(replacementDescriptor) }

    store.append(Data("must-not-enter-zero-replacement\n".utf8), label: "test")

    var replacementMetadata = stat()
    #expect(Darwin.fstat(replacementDescriptor, &replacementMetadata) == 0)
    #expect(replacementMetadata.st_size == 0)
    #expect(try Data(contentsOf: store.logURL).isEmpty)
    #expect(store.recentLogs() == "No service log entries yet.")
}
