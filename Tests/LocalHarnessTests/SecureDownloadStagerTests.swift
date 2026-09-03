import CryptoKit
import Darwin
import Foundation
import Testing
@testable import LocalHarness

@Suite("Hostile download staging")
struct SecureDownloadStagerTests {
    @Test("Filename normalization removes traversal, bidi, controls, invisible format, and excessive length")
    func filenameNormalization() {
        #expect(DownloadPath.safeFilename("../folder\\report:final.pdf") == "folder-report-final.pdf")
        #expect(DownloadPath.safeFilename("\u{202E}fdp.exe\u{0000}\u{200B}") == "fdp.exe")
        #expect(DownloadPath.safeFilename(" . . ") == "Download")
        #expect(DownloadPath.safeFilename("...", fallback: "\u{202E}/Fallback") == "Fallback")
        #expect(DownloadPath.safeFilename("／etc／passwd") == "etc-passwd")
        let long = String(repeating: "é", count: 180) + ".pdf"
        let safe = DownloadPath.safeFilename(long)
        #expect(safe.utf8.count <= 200)
        #expect(safe.hasSuffix(".pdf"))
    }

    @Test("Private staging is owner-only, exclusive, and collision-free")
    func privateStaging() throws {
        let fixture = try Fixture(maximumBytes: 1_024)
        defer { fixture.cleanup() }
        let first = try fixture.stager.prepare(suggestedFilename: "report.txt", reportedMIMEType: "text/plain", expectedContentLength: 5, sourceURL: URL(string: "http://127.0.0.1:3080/file?token=secret"))
        let second = try fixture.stager.prepare(suggestedFilename: "report.txt", reportedMIMEType: "text/plain", expectedContentLength: -1, sourceURL: nil)
        #expect(first.transferDirectory != second.transferDirectory)
        #expect(!FileManager.default.fileExists(atPath: first.incomingURL.path))
        let permissions = try #require((try FileManager.default.attributesOfItem(atPath: first.transferDirectory.path)[.posixPermissions]) as? NSNumber)
        #expect(permissions.intValue & 0o777 == 0o700)
    }

    @Test("Reported and streamed byte limits fail closed and clean up")
    func boundedBytes() throws {
        let fixture = try Fixture(maximumBytes: 16)
        defer { fixture.cleanup() }
        #expect(throws: SecureDownloadError.expectedSizeExceedsLimit(limit: 16)) {
            _ = try fixture.stager.prepare(suggestedFilename: "large.bin", reportedMIMEType: nil, expectedContentLength: 17, sourceURL: nil)
        }
        let pending = try fixture.stager.prepare(suggestedFilename: "large.txt", reportedMIMEType: "text/plain", expectedContentLength: -1, sourceURL: nil)
        try Data(repeating: 65, count: 17).write(to: pending.incomingURL)
        #expect(fixture.stager.inspectIncoming(pending) == .rejected("The download exceeded its byte limit."))
        #expect(throws: SecureDownloadError.sizeLimitExceeded(limit: 16)) {
            _ = try fixture.stager.finalize(pending)
        }
        #expect(!FileManager.default.fileExists(atPath: pending.transferDirectory.path))
    }

    @Test("Finalize hashes, writes private metadata, and applies macOS quarantine")
    func finalizationMetadata() throws {
        let fixture = try Fixture(maximumBytes: 4_096)
        defer { fixture.cleanup() }
        let data = Data("A harmless local report.\n".utf8)
        let pending = try fixture.stager.prepare(suggestedFilename: "report.txt", reportedMIMEType: "text/plain; charset=utf-8", expectedContentLength: Int64(data.count), sourceURL: URL(string: "http://127.0.0.1:3080/private?secret=yes"))
        try data.write(to: pending.incomingURL)
        #expect(fixture.stager.inspectIncoming(pending) == .inProgress(byteCount: Int64(data.count)))
        let artifact = try fixture.stager.finalize(pending)
        let expectedDigest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        #expect(artifact.sha256 == expectedDigest)
        #expect(artifact.byteCount == Int64(data.count))
        #expect(artifact.category == .passiveDocument)
        #expect(artifact.allowsManualPreview)
        #expect(artifact.quarantineApplied)
        try fixture.stager.validateForPreview(artifact)
        let permissions = try #require((try FileManager.default.attributesOfItem(atPath: artifact.fileURL.path)[.posixPermissions]) as? NSNumber)
        #expect(permissions.intValue & 0o777 == 0o600)
        let quarantine = try #require(readExtendedAttribute("com.apple.quarantine", at: artifact.fileURL))
        #expect(String(decoding: quarantine, as: UTF8.self).contains("Fulmar"))
        let metadataURL = artifact.fileURL.deletingLastPathComponent().appendingPathComponent(".download-metadata.json")
        let metadata = try String(contentsOf: metadataURL, encoding: .utf8)
        #expect(metadata.contains(expectedDigest))
        #expect(!metadata.contains("secret=yes"))
    }

    @Test("No executable, installer, script, archive, or active HTML receives preview permission", arguments: [
        ("manual.pdf", "application/pdf", Data([0xCF, 0xFA, 0xED, 0xFE, 0, 0, 0, 0]), DownloadSafetyCategory.suspicious),
        ("setup.pkg", "application/octet-stream", Data("package".utf8), DownloadSafetyCategory.installer),
        ("tool.sh", "text/plain", Data("#!/bin/zsh\necho unsafe".utf8), DownloadSafetyCategory.script),
        ("bundle.zip", "application/zip", Data([0x50, 0x4B, 0x03, 0x04, 0, 0]), DownloadSafetyCategory.archive),
        ("notes.txt", "text/plain", Data("<!doctype html><script>alert(1)</script>".utf8), DownloadSafetyCategory.suspicious)
    ])
    func dangerousTypesNeverPreview(filename: String, mime: String, data: Data, expectedCategory: DownloadSafetyCategory) {
        let assessment = DownloadContentInspector.assess(filename: filename, reportedMIMEType: mime, prefix: data)
        #expect(!assessment.allowsManualPreview)
        #expect(assessment.category == expectedCategory)
    }

    @Test("Passive magic, type, and MIME agree before preview is enabled", arguments: [
        ("report.pdf", "application/pdf", Data("%PDF-1.7\n".utf8), "application/pdf"),
        ("generic.pdf", "application/octet-stream", Data("%PDF-1.7\n".utf8), "application/pdf"),
        ("image.png", "image/png", Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]), "image/png"),
        ("data.json", "application/json", Data("{\"safe\":true}".utf8), "application/json")
    ])
    func passiveValidation(filename: String, mime: String, data: Data, detected: String) {
        let assessment = DownloadContentInspector.assess(filename: filename, reportedMIMEType: mime, prefix: data)
        #expect(assessment.category == .passiveDocument)
        #expect(assessment.allowsManualPreview)
        #expect(assessment.detectedMIMEType == detected)
        #expect(assessment.warnings.isEmpty)
    }

    @Test("MIME and extension mismatches disable preview")
    func mismatchValidation() {
        let executable = DownloadContentInspector.assess(
            filename: "quarterly-report.pdf",
            reportedMIMEType: "application/pdf",
            prefix: Data([0x4D, 0x5A, 0, 0, 0, 0])
        )
        #expect(executable.category == .suspicious)
        #expect(!executable.allowsManualPreview)
        #expect(executable.warnings.count == 2)

        let wrongImage = DownloadContentInspector.assess(
            filename: "photo.jpg",
            reportedMIMEType: "image/png",
            prefix: Data([0xFF, 0xD8, 0xFF, 0])
        )
        #expect(!wrongImage.allowsManualPreview)
        #expect(wrongImage.warnings.contains(where: { $0.contains("MIME") }))

        let fakeImage = DownloadContentInspector.assess(
            filename: "photo.png",
            reportedMIMEType: nil,
            prefix: Data("This is not image data.".utf8)
        )
        #expect(fakeImage.category == .suspicious)
        #expect(!fakeImage.allowsManualPreview)
    }

    @Test("Symlinks and non-regular incoming objects are rejected without touching their targets")
    func rejectsFilesystemSubstitution() throws {
        let fixture = try Fixture(maximumBytes: 1_024)
        defer { fixture.cleanup() }
        let target = fixture.root.appendingPathComponent("outside.txt")
        try Data("preserve me".utf8).write(to: target)
        let pending = try fixture.stager.prepare(suggestedFilename: "link.txt", reportedMIMEType: "text/plain", expectedContentLength: -1, sourceURL: nil)
        try FileManager.default.createSymbolicLink(at: pending.incomingURL, withDestinationURL: target)
        guard case .rejected = fixture.stager.inspectIncoming(pending) else {
            Issue.record("A symlink should never be accepted as an incoming download")
            return
        }
        #expect(throws: SecureDownloadError.unsafeFilesystemObject) {
            _ = try fixture.stager.finalize(pending)
        }
        #expect(try String(contentsOf: target, encoding: .utf8) == "preserve me")
    }

    @Test("Export is exclusive, verifies the validated digest, preserves existing files, and reapplies quarantine")
    func secureExport() throws {
        let fixture = try Fixture(maximumBytes: 4_096)
        defer { fixture.cleanup() }
        let data = Data("validated artifact".utf8)
        let pending = try fixture.stager.prepare(suggestedFilename: "artifact.txt", reportedMIMEType: "text/plain", expectedContentLength: Int64(data.count), sourceURL: nil)
        try data.write(to: pending.incomingURL)
        let artifact = try fixture.stager.finalize(pending)

        let spoofed = fixture.root.appendingPathComponent("safe\u{202E}txt.exe")
        #expect(throws: SecureDownloadError.unsafeFilename) {
            _ = try fixture.stager.export(artifact, to: spoofed)
        }

        let occupied = fixture.root.appendingPathComponent("occupied.txt")
        try Data("do not overwrite".utf8).write(to: occupied)
        #expect(throws: SecureDownloadError.destinationAlreadyExists) {
            _ = try fixture.stager.export(artifact, to: occupied)
        }
        #expect(try String(contentsOf: occupied, encoding: .utf8) == "do not overwrite")

        let destination = fixture.root.appendingPathComponent("saved.txt")
        let saved = try fixture.stager.export(artifact, to: destination)
        #expect(saved.fileURL == destination)
        #expect(try Data(contentsOf: destination) == data)
        #expect(readExtendedAttribute("com.apple.quarantine", at: destination) != nil)
        #expect(!FileManager.default.fileExists(atPath: artifact.fileURL.path))
    }

    @Test("Export detects post-validation tampering and leaves no destination")
    func exportTamperDetection() throws {
        let fixture = try Fixture(maximumBytes: 4_096)
        defer { fixture.cleanup() }
        let pending = try fixture.stager.prepare(suggestedFilename: "artifact.txt", reportedMIMEType: "text/plain", expectedContentLength: 4, sourceURL: nil)
        try Data("safe".utf8).write(to: pending.incomingURL)
        let artifact = try fixture.stager.finalize(pending)
        try Data("evil".utf8).write(to: artifact.fileURL)
        #expect(throws: SecureDownloadError.contentChanged) {
            try fixture.stager.validateForPreview(artifact)
        }
        let destination = fixture.root.appendingPathComponent("must-not-exist.txt")
        #expect(throws: SecureDownloadError.contentChanged) {
            _ = try fixture.stager.export(artifact, to: destination)
        }
        #expect(!FileManager.default.fileExists(atPath: destination.path))
    }

    @Test("A symlink cannot be used as the staging root")
    func rejectsSymlinkRoot() throws {
        let parent = FileManager.default.temporaryDirectory.appendingPathComponent("download-root-link-\(UUID().uuidString)")
        let target = parent.appendingPathComponent("target", isDirectory: true)
        let link = parent.appendingPathComponent("link", isDirectory: true)
        try FileManager.default.createDirectory(at: target, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
        defer { try? FileManager.default.removeItem(at: parent) }
        #expect(throws: SecureDownloadError.unsafeFilesystemObject) {
            _ = try SecureDownloadStager(stagingRoot: link, maximumBytes: 1_024)
        }
    }

    @Test("Stale cleanup is explicit, streamed, and leaves fresh transfers alone")
    func boundedStaleCleanup() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("download-cleanup-\(UUID().uuidString)", isDirectory: true)
        let staging = root.appendingPathComponent("staging", isDirectory: true)
        let stale = staging.appendingPathComponent("transfer-\(UUID().uuidString)", isDirectory: true)
        let fresh = staging.appendingPathComponent("transfer-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: stale, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: fresh, withIntermediateDirectories: true)
        try Data("stale".utf8).write(to: stale.appendingPathComponent("incoming.download"))
        let now = Date(timeIntervalSince1970: 2_000_000_000)
        try FileManager.default.setAttributes(
            [.modificationDate: now.addingTimeInterval(-7_200)],
            ofItemAtPath: stale.path
        )
        try FileManager.default.setAttributes(
            [.modificationDate: now],
            ofItemAtPath: fresh.path
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let stager = try SecureDownloadStager(stagingRoot: staging, maximumBytes: 1_024)
        // Construction never performs recursive maintenance on the caller.
        #expect(FileManager.default.fileExists(atPath: stale.path))
        let report = stager.cleanupStaleTransfers(olderThan: 3_600, now: now)
        #expect(report.status == .completed)
        #expect(report.removedTransfers == 1)
        #expect(!FileManager.default.fileExists(atPath: stale.path))
        #expect(FileManager.default.fileExists(atPath: fresh.path))
    }

    @Test("Wide and deep stale trees stop at the aggregate maintenance budget")
    func cleanupBudgetsWideAndDeepTrees() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("download-cleanup-bounds-\(UUID().uuidString)", isDirectory: true)
        let staging = root.appendingPathComponent("staging", isDirectory: true)
        try FileManager.default.createDirectory(at: staging, withIntermediateDirectories: true)
        let now = Date(timeIntervalSince1970: 2_000_000_000)
        for _ in 0..<8 {
            let transfer = staging.appendingPathComponent("transfer-\(UUID().uuidString)", isDirectory: true)
            try FileManager.default.createDirectory(at: transfer, withIntermediateDirectories: false)
            try FileManager.default.setAttributes(
                [.modificationDate: now.addingTimeInterval(-7_200)],
                ofItemAtPath: transfer.path
            )
        }
        defer { try? FileManager.default.removeItem(at: root) }
        let stager = try SecureDownloadStager(stagingRoot: staging, maximumBytes: 1_024)
        let wide = stager.cleanupStaleTransfers(
            olderThan: 3_600,
            now: now,
            limits: .init(maximumEntries: 2, maximumDepth: 4, duration: 1)
        )
        #expect(wide.status == .bounded)
        #expect(wide.inspectedEntries == 2)

        let deep = staging.appendingPathComponent("transfer-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: deep.appendingPathComponent("a/b/c", isDirectory: true),
            withIntermediateDirectories: true
        )
        try FileManager.default.setAttributes(
            [.modificationDate: now.addingTimeInterval(-7_200)],
            ofItemAtPath: deep.path
        )
        let deepReport = stager.cleanupStaleTransfers(
            olderThan: 3_600,
            now: now,
            limits: .init(maximumEntries: 100, maximumDepth: 1, duration: 1)
        )
        #expect(deepReport.status == .bounded)
        #expect(FileManager.default.fileExists(atPath: deep.path))
    }

    @Test("Stale cleanup unlinks hostile children without following them")
    func cleanupNeverFollowsLinks() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("download-cleanup-links-\(UUID().uuidString)", isDirectory: true)
        let staging = root.appendingPathComponent("staging", isDirectory: true)
        let transfer = staging.appendingPathComponent("transfer-\(UUID().uuidString)", isDirectory: true)
        let outside = root.appendingPathComponent("outside.txt")
        try FileManager.default.createDirectory(at: transfer, withIntermediateDirectories: true)
        try Data("preserve".utf8).write(to: outside)
        try FileManager.default.createSymbolicLink(
            at: transfer.appendingPathComponent("hostile-link"),
            withDestinationURL: outside
        )
        let now = Date(timeIntervalSince1970: 2_000_000_000)
        try FileManager.default.setAttributes(
            [.modificationDate: now.addingTimeInterval(-7_200)],
            ofItemAtPath: transfer.path
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let stager = try SecureDownloadStager(stagingRoot: staging, maximumBytes: 1_024)
        let report = stager.cleanupStaleTransfers(olderThan: 3_600, now: now)
        #expect(report.status == .completed)
        #expect(!FileManager.default.fileExists(atPath: transfer.path))
        #expect(try String(contentsOf: outside, encoding: .utf8) == "preserve")
    }
}

private struct Fixture {
    let root: URL
    let stager: SecureDownloadStager

    init(maximumBytes: Int64) throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("secure-download-tests-\(UUID().uuidString)", isDirectory: true)
        let staging = root.appendingPathComponent("staging", isDirectory: true)
        stager = try SecureDownloadStager(stagingRoot: staging, maximumBytes: maximumBytes)
    }

    func cleanup() {
        stager.cleanupOwnedArtifacts()
        try? FileManager.default.removeItem(at: root)
    }
}

private func readExtendedAttribute(_ name: String, at url: URL) -> Data? {
    let size = name.withCString { namePointer in
        getxattr(url.path, namePointer, nil, 0, 0, 0)
    }
    guard size > 0 else { return nil }
    var data = Data(count: size)
    let result = data.withUnsafeMutableBytes { rawBuffer in
        name.withCString { namePointer in
            getxattr(url.path, namePointer, rawBuffer.baseAddress, rawBuffer.count, 0, 0)
        }
    }
    return result == size ? data : nil
}
