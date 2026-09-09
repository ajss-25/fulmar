import Darwin
import Foundation
import Testing
@testable import LocalHarness

private func directoryEntry(
    bytes: [UInt8],
    recordByteCount: Int? = nil,
    terminator: UInt8 = 0
) -> dirent {
    var entry = dirent()
    let offset = MemoryLayout<dirent>.offset(of: \dirent.d_name)!
    entry.d_namlen = UInt16(bytes.count)
    entry.d_reclen = UInt16(recordByteCount ?? ((offset + bytes.count + 1 + 3) & ~3))
    withUnsafeMutablePointer(to: &entry.d_name) { pointer in
        pointer.withMemoryRebound(to: UInt8.self, capacity: bytes.count + 1) { destination in
            for (index, byte) in bytes.enumerated() { destination[index] = byte }
            destination[bytes.count] = terminator
        }
    }
    return entry
}

@Test func DarwinDirectoryEntryBoundsVariableLengthRecords() {
    let bytes = Array("safe-name.txt".utf8)
    var valid = directoryEntry(bytes: bytes)
    #expect(withUnsafeMutablePointer(to: &valid) { DarwinDirectoryEntry.name($0) } == "safe-name.txt")

    let offset = MemoryLayout<dirent>.offset(of: \dirent.d_name)!
    var exact = directoryEntry(bytes: bytes, recordByteCount: offset + bytes.count + 1)
    #expect(withUnsafeMutablePointer(to: &exact) { DarwinDirectoryEntry.name($0) } == "safe-name.txt")

    var beforeName = directoryEntry(bytes: bytes, recordByteCount: offset - 1)
    #expect(withUnsafeMutablePointer(to: &beforeName) { DarwinDirectoryEntry.name($0) } == nil)

    var truncated = directoryEntry(bytes: bytes, recordByteCount: offset + bytes.count)
    #expect(withUnsafeMutablePointer(to: &truncated) { DarwinDirectoryEntry.name($0) } == nil)

    var oversized = directoryEntry(bytes: bytes, recordByteCount: MemoryLayout<dirent>.size + 1)
    #expect(withUnsafeMutablePointer(to: &oversized) { DarwinDirectoryEntry.name($0) } == nil)

    var unterminated = directoryEntry(bytes: bytes, terminator: 65)
    #expect(withUnsafeMutablePointer(to: &unterminated) { DarwinDirectoryEntry.name($0) } == nil)
}

@Test func DarwinDirectoryEntryRejectsUnsafeOrInvalidNames() {
    for bytes in [[UInt8](), [0x66, 0x00, 0x6f], [0x61, 0x2f, 0x62], [0xff]] {
        var entry = directoryEntry(bytes: bytes)
        #expect(withUnsafeMutablePointer(to: &entry) { DarwinDirectoryEntry.name($0) } == nil)
    }

    let maximum = [UInt8](repeating: 0x78, count: Int(MAXNAMLEN))
    var maximumEntry = directoryEntry(bytes: maximum)
    #expect(withUnsafeMutablePointer(to: &maximumEntry) { DarwinDirectoryEntry.name($0) } == String(repeating: "x", count: Int(MAXNAMLEN)))

    var oversizedName = directoryEntry(bytes: maximum + [0x78])
    #expect(withUnsafeMutablePointer(to: &oversizedName) { DarwinDirectoryEntry.name($0) } == nil)
}

@Test func bundleDirectoryEnumerationSafelyCrossesLibcBufferBoundaries() throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("fulmar-dirent-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: root) }

    let expected = Set((0..<512).map { index in
        "entry-\(String(format: "%04d", index))-\(String(repeating: "x", count: index % 73))"
    } + [String(repeating: "m", count: Int(MAXNAMLEN))])
    for name in expected {
        let descriptor = Darwin.open(
            root.appendingPathComponent(name).path,
            O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC,
            S_IRUSR | S_IWUSR
        )
        #expect(descriptor >= 0)
        if descriptor >= 0 { _ = Darwin.close(descriptor) }
    }

    let observed = BundleSecurityIO.directoryEntryNames(
        at: root,
        inside: root,
        maximumEntries: expected.count
    )
    #expect(observed.map(Set.init) == expected)
}
