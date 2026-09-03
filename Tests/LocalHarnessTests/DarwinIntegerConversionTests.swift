import Darwin
import Foundation
import Testing

@Test func darwinIdentityIntegerConversionsPreserveEverySourceBit() {
    let highBitDevice: dev_t = Int32(bitPattern: 0x8000_0000)
    let encodedDevice = UInt64(truncatingIfNeeded: highBitDevice)
    #expect(encodedDevice == 0xffff_ffff_8000_0000)
    #expect(encodedDevice == UInt64(bitPattern: Int64(highBitDevice)))

    let highBitInode = ino_t(1) << 63
    #expect(Int64(bitPattern: highBitInode) == Int64.min)
}

@Test func repositorySwiftSourcesNeverUseTrappingDarwinIdentityConversions() throws {
    let repository = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
    let forbidden: [(String, NSRegularExpression)] = [
        (
            "signed dev_t converted with UInt64(_:)",
            try NSRegularExpression(
                pattern: #"(?<![A-Za-z0-9_])UInt64\s*\(\s*(?!truncatingIfNeeded:|bitPattern:)[^()\r\n]*\bst_dev\s*\)"#
            )
        ),
        (
            "known dev_t variable converted with UInt64(_:)",
            try NSRegularExpression(
                pattern: #"(?<![A-Za-z0-9_])UInt64\s*\(\s*device\s*\)"#
            )
        ),
        (
            "unsigned ino_t converted with Int64(_:)",
            try NSRegularExpression(
                pattern: #"(?<![A-Za-z0-9_])Int64\s*\(\s*(?!bitPattern:)[^()\r\n]*\bst_ino\s*\)"#
            )
        )
    ]
    var findings: [String] = []

    for directoryName in ["Sources", "Tools", "Tests"] {
        let directory = repository.appendingPathComponent(directoryName, isDirectory: true)
        guard let enumerator = FileManager.default.enumerator(
            at: directory,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        ) else {
            throw CocoaError(.fileReadUnknown)
        }
        for case let file as URL in enumerator where file.pathExtension == "swift" {
            let source = try String(contentsOf: file, encoding: .utf8)
            let searchRange = NSRange(source.startIndex..<source.endIndex, in: source)
            for (description, expression) in forbidden {
                for match in expression.matches(in: source, range: searchRange) {
                    let line = source.utf16.prefix(match.range.location).reduce(1) {
                        count, codeUnit in
                        codeUnit == 10 ? count + 1 : count
                    }
                    let relativePath = file.path.replacingOccurrences(
                        of: repository.path + "/",
                        with: ""
                    )
                    findings.append("\(relativePath):\(line): \(description)")
                }
            }
        }
    }

    #expect(
        findings.isEmpty,
        Comment(rawValue: findings.sorted().joined(separator: "\n"))
    )
}
