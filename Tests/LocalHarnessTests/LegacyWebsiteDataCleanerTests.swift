import Darwin
import Foundation
import Testing
@testable import LocalHarness

@Suite(.serialized)
struct LegacyWebsiteDataCleanerTests {
    @Test func removesOnlyExactLegacyRootsWithoutFollowingNestedLinks() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let webKit = fixture.library.appendingPathComponent("WebKit/\(ProductBrand.bundleIdentifier)")
        let cache = fixture.caches.appendingPathComponent(ProductBrand.bundleIdentifier)
        try FileManager.default.createDirectory(at: webKit, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: cache, withIntermediateDirectories: true)
        try Data("old-cookie".utf8).write(to: webKit.appendingPathComponent("Cookies"))
        try FileManager.default.createSymbolicLink(
            at: cache.appendingPathComponent("outside"),
            withDestinationURL: fixture.outside
        )

        try fixture.cleaner.clear()

        #expect(!FileManager.default.fileExists(atPath: webKit.path))
        #expect(!FileManager.default.fileExists(atPath: cache.path))
        #expect(String(decoding: try Data(contentsOf: fixture.sentinel), as: UTF8.self) == "preserve")
        #expect(FileManager.default.fileExists(atPath: fixture.library.appendingPathComponent("keep").path))
    }

    @Test func rootSymlinkIsUnlinkedWithoutDeletingItsDestination() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let webKitParent = fixture.library.appendingPathComponent("WebKit")
        try FileManager.default.createDirectory(at: webKitParent, withIntermediateDirectories: true)
        let legacy = webKitParent.appendingPathComponent(ProductBrand.bundleIdentifier)
        try FileManager.default.createSymbolicLink(at: legacy, withDestinationURL: fixture.outside)

        try fixture.cleaner.clear()

        var metadata = stat()
        #expect(Darwin.lstat(legacy.path, &metadata) != 0 && errno == ENOENT)
        #expect(String(decoding: try Data(contentsOf: fixture.sentinel), as: UTF8.self) == "preserve")
    }

    @Test func unexpectedNodeTypeFailsClosedAndRemainsUntouched() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let webKitParent = fixture.library.appendingPathComponent("WebKit")
        try FileManager.default.createDirectory(at: webKitParent, withIntermediateDirectories: true)
        let legacy = webKitParent.appendingPathComponent(ProductBrand.bundleIdentifier)
        #expect(Darwin.mkfifo(legacy.path, S_IRUSR | S_IWUSR) == 0)

        #expect(throws: LegacyWebsiteDataCleanerError.self) { try fixture.cleaner.clear() }
        var metadata = stat()
        #expect(Darwin.lstat(legacy.path, &metadata) == 0)
        #expect(metadata.st_mode & S_IFMT == S_IFIFO)
    }

    private func makeFixture() throws -> (
        root: URL,
        library: URL,
        caches: URL,
        outside: URL,
        sentinel: URL,
        cleaner: LegacyWebsiteDataCleaner
    ) {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("LegacyWebsiteDataCleanerTests-\(UUID().uuidString)")
        let library = root.appendingPathComponent("Library")
        let caches = library.appendingPathComponent("Caches")
        let outside = root.appendingPathComponent("Outside")
        try FileManager.default.createDirectory(at: caches, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        try Data("keep".utf8).write(to: library.appendingPathComponent("keep"))
        let sentinel = outside.appendingPathComponent("sentinel")
        try Data("preserve".utf8).write(to: sentinel)
        let cleaner = LegacyWebsiteDataCleaner(
            libraryDirectory: library,
            cachesDirectory: caches
        )
        return (root, library, caches, outside, sentinel, cleaner)
    }
}
