import Foundation
import Testing
@testable import LocalHarness

@Suite("Secure attachment reader")
struct SecureAttachmentReaderTests {
    @Test("Reads bounded regular files and rejects symlinks and growth past the limit")
    func boundedRead() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("attachment-reader-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("image.png")
        try Data(repeating: 7, count: 128).write(to: file)
        #expect(try SecureAttachmentReader.readRegularFile(at: file, maximumBytes: 128).count == 128)
        #expect(throws: SecureAttachmentReaderError.tooLarge(maximumBytes: 127)) {
            _ = try SecureAttachmentReader.readRegularFile(at: file, maximumBytes: 127)
        }
        let link = root.appendingPathComponent("link.png")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: file)
        #expect(throws: SecureAttachmentReaderError.self) {
            _ = try SecureAttachmentReader.readRegularFile(at: link, maximumBytes: 128)
        }
    }

    @Test("Detects image content and rejects extension spoofing")
    func imageMagic() throws {
        let png = Data([137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 0])
        #expect(try SecureAttachmentReader.imageMediaType(for: png, filename: "safe.png") == .png)
        #expect(throws: SecureAttachmentReaderError.unsupportedImage) {
            _ = try SecureAttachmentReader.imageMediaType(for: png, filename: "spoof.jpg")
        }
        #expect(throws: SecureAttachmentReaderError.unsupportedImage) {
            _ = try SecureAttachmentReader.imageMediaType(for: Data("not an image".utf8), filename: "fake.png")
        }
    }
}
