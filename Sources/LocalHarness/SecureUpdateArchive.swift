import Darwin
import Foundation
import LocalHarnessSandboxPolicy
import LocalHarnessUpdateSecurity
import zlib

struct UpdateArchiveLimits: Equatable {
    let maximumArchiveBytes: UInt64
    let maximumCentralDirectoryBytes: UInt64
    let maximumEntries: Int
    let maximumExpandedBytes: UInt64
    let maximumEntryBytes: UInt64
    let maximumPathBytes: Int
    let maximumPathDepth: Int

    static let production = UpdateArchiveLimits(
        maximumArchiveBytes: 1_024 * 1_024 * 1_024,
        maximumCentralDirectoryBytes: 64 * 1_024 * 1_024,
        maximumEntries: 100_000,
        maximumExpandedBytes: 2 * 1_024 * 1_024 * 1_024,
        maximumEntryBytes: 1_024 * 1_024 * 1_024,
        maximumPathBytes: 4_096,
        maximumPathDepth: 128
    )
}

private enum UpdateArchiveEntryType: Equatable {
    case directory
    case regularFile
    case symlink
}

private struct UpdateArchiveEntry {
    let path: String
    let rawName: Data
    let centralExtra: Data
    let type: UpdateArchiveEntryType
    let unixMode: UInt32
    let neededVersion: UInt16
    let flags: UInt16
    let method: UInt16
    let modifiedTime: UInt16
    let modifiedDate: UInt16
    let crc32: UInt32
    let compressedSize: UInt64
    let expandedSize: UInt64
    let localHeaderOffset: UInt64
    let symlinkTarget: String?
}

struct UpdateArchiveInspection {
    fileprivate let entries: [UpdateArchiveEntry]
    let applicationRootName: String
    let archiveBytes: UInt64
    let expandedBytes: UInt64
}

struct StagedUpdateArchive {
    let stageRoot: URL
    let appURL: URL
}

/// A deliberately narrow ZIP reader for app updates. It accepts the exact
/// single-disk, non-ZIP64, Unix archive topology emitted by the release build
/// and rejects path aliases or type metadata which different extractors could
/// interpret inconsistently.
enum SecureUpdateArchive {
    private static let localHeaderSignature: UInt32 = 0x04034b50
    private static let dataDescriptorSignature: UInt32 = 0x08074b50
    private static let centralHeaderSignature: UInt32 = 0x02014b50
    private static let endSignature: UInt32 = 0x06054b50
    private static let unixHost: UInt16 = 3
    private static let allowedExtraField: UInt16 = 0x5855

    static func inspect(
        _ archive: URL,
        limits: UpdateArchiveLimits = .production
    ) throws -> UpdateArchiveInspection {
        guard archive.isFileURL,
              limits.maximumArchiveBytes >= 22,
              limits.maximumCentralDirectoryBytes > 0,
              limits.maximumEntries > 0,
              limits.maximumExpandedBytes > 0,
              limits.maximumEntryBytes <= limits.maximumExpandedBytes,
              limits.maximumPathBytes > 0,
              limits.maximumPathDepth > 0 else {
            throw UpdateError.invalidArchive
        }

        let reader = try SecureArchiveReader(archive, maximumBytes: limits.maximumArchiveBytes)
        defer { reader.close() }
        return try inspect(reader, limits: limits)
    }

    fileprivate static func inspect(
        _ reader: SecureArchiveReader,
        limits: UpdateArchiveLimits
    ) throws -> UpdateArchiveInspection {
        guard reader.size >= 22 else { throw UpdateError.invalidArchive }

        // Production archives carry no comment, so the EOCD must be the final
        // 22 bytes. This also rejects trailing/polyglot payloads.
        let endOffset = reader.size - 22
        let end = try reader.read(offset: endOffset, count: 22)
        let entriesOnDisk = try end.u16(8)
        let totalEntries = try end.u16(10)
        guard try end.u32(0) == endSignature,
              try end.u16(4) == 0,
              try end.u16(6) == 0,
              entriesOnDisk == totalEntries,
              try end.u16(20) == 0 else {
            throw UpdateError.invalidArchive
        }
        let entryCount = Int(totalEntries)
        let centralBytes = UInt64(try end.u32(12))
        let centralOffset = UInt64(try end.u32(16))
        guard entryCount > 0,
              entryCount <= limits.maximumEntries,
              centralBytes > 0,
              centralBytes <= limits.maximumCentralDirectoryBytes,
              try checkedAdd(centralOffset, centralBytes) == endOffset else {
            throw UpdateError.invalidArchive
        }

        let central = try reader.read(offset: centralOffset, count: try boundedInt(centralBytes))
        var entries: [UpdateArchiveEntry] = []
        entries.reserveCapacity(entryCount)
        var cursor = 0
        var expandedBytes: UInt64 = 0
        var seenPaths: [String: String] = [:]
        var explicitTypes: [String: UpdateArchiveEntryType] = [:]
        var impliedDirectories: [String: String] = [:]
        var applicationRoot: String?
        var sawRootDirectory = false

        for _ in 0..<entryCount {
            guard central.count - cursor >= 46,
                  try central.u32(cursor) == centralHeaderSignature else {
                throw UpdateError.invalidArchive
            }
            let madeBy = try central.u16(cursor + 4)
            let needed = try central.u16(cursor + 6)
            let flags = try central.u16(cursor + 8)
            let method = try central.u16(cursor + 10)
            let modifiedTime = try central.u16(cursor + 12)
            let modifiedDate = try central.u16(cursor + 14)
            let crc = try central.u32(cursor + 16)
            let compressed = UInt64(try central.u32(cursor + 20))
            let expanded = UInt64(try central.u32(cursor + 24))
            let nameLength = Int(try central.u16(cursor + 28))
            let extraLength = Int(try central.u16(cursor + 30))
            let commentLength = Int(try central.u16(cursor + 32))
            let disk = try central.u16(cursor + 34)
            let internalAttributes = try central.u16(cursor + 36)
            let externalAttributes = try central.u32(cursor + 38)
            let localOffset = UInt64(try central.u32(cursor + 42))
            let variableLength = try checkedIntAdd(nameLength, try checkedIntAdd(extraLength, commentLength))
            let next = try checkedIntAdd(cursor + 46, variableLength)
            guard next <= central.count,
                  madeBy >> 8 == unixHost,
                  madeBy & 0xff == 20 || madeBy & 0xff == 21,
                  needed > 0,
                  needed <= 20,
                  flags == 0 || flags == 8,
                  method == 0 || method == 8,
                  nameLength > 0,
                  nameLength <= limits.maximumPathBytes,
                  commentLength == 0,
                  disk == 0,
                  internalAttributes == 0,
                  externalAttributes & 0xffff == 0x4000,
                  compressed != UInt64(UInt32.max),
                  expanded != UInt64(UInt32.max),
                  localOffset != UInt64(UInt32.max) else {
                throw UpdateError.invalidArchive
            }

            let rawName = try central.slice(cursor + 46, nameLength)
            let rawExtra = try central.slice(cursor + 46 + nameLength, extraLength)
            try validateCentralExtraFields(rawExtra)
            let unixMode = externalAttributes >> 16
            let fileType = unixMode & 0o170000
            let nameEndsInSlash = rawName.last == 0x2f
            let type: UpdateArchiveEntryType
            if fileType == 0o040000, nameEndsInSlash {
                type = .directory
                guard method == 0, crc == 0, compressed == 0, expanded == 0 else {
                    throw UpdateError.invalidArchive
                }
            } else if fileType == 0o100000, !nameEndsInSlash {
                type = .regularFile
            } else if fileType == 0o120000, !nameEndsInSlash {
                type = .symlink
                guard unixMode & 0o7777 == 0o755,
                      flags == 0,
                      method == 0,
                      compressed == expanded,
                      expanded > 0,
                      expanded <= UInt64(limits.maximumPathBytes) else {
                    throw UpdateError.invalidArchive
                }
            } else {
                // Devices, FIFOs, sockets, and ambiguous DOS-only entries are
                // never valid application update material. Symlinks are
                // accepted only after their exact stored target is proven to
                // be a safe in-archive regular file.
                throw UpdateError.invalidArchive
            }
            guard (type == .symlink || unixMode & 0o7022 == 0),
                  expanded <= limits.maximumEntryBytes,
                  method != 0 || compressed == expanded else {
                throw UpdateError.invalidArchive
            }
            expandedBytes = try checkedAdd(expandedBytes, expanded)
            guard expandedBytes <= limits.maximumExpandedBytes else { throw UpdateError.invalidArchive }

            let path = try normalizedPath(rawName, directory: type == .directory, limits: limits)
            let folded = foldedPath(path)
            guard seenPaths[folded] == nil else { throw UpdateError.invalidArchive }
            seenPaths[folded] = path
            explicitTypes[folded] = type

            let components = path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
            guard let rootComponent = components.first,
                  rootComponent == UpdateApplicationSecurity.expectedApplicationBundleName else {
                throw UpdateError.invalidArchive
            }
            if let applicationRoot {
                guard applicationRoot == rootComponent else { throw UpdateError.invalidArchive }
            } else {
                applicationRoot = rootComponent
            }
            if path == rootComponent {
                guard type == .directory else { throw UpdateError.invalidArchive }
                sawRootDirectory = true
            }

            if components.count > 1 {
                var prefix = components[0]
                for component in components.dropFirst().dropLast() {
                    prefix += "/\(component)"
                    let key = foldedPath(prefix)
                    if let prior = impliedDirectories[key], prior != prefix {
                        throw UpdateError.invalidArchive
                    }
                    impliedDirectories[key] = prefix
                }
            }

            entries.append(UpdateArchiveEntry(
                path: path,
                rawName: rawName,
                centralExtra: rawExtra,
                type: type,
                unixMode: unixMode,
                neededVersion: needed,
                flags: flags,
                method: method,
                modifiedTime: modifiedTime,
                modifiedDate: modifiedDate,
                crc32: crc,
                compressedSize: compressed,
                expandedSize: expanded,
                localHeaderOffset: localOffset,
                symlinkTarget: nil
            ))
            cursor = next
        }

        guard cursor == central.count,
              entries.count == entryCount,
              let applicationRoot,
              sawRootDirectory else {
            throw UpdateError.invalidArchive
        }
        for (parent, _) in impliedDirectories {
            if let explicit = explicitTypes[parent], explicit != .directory {
                throw UpdateError.invalidArchive
            }
        }

        entries = try validateLocalRecords(
            entries,
            reader: reader,
            centralOffset: centralOffset,
            applicationRoot: applicationRoot,
            limits: limits
        )
        try validateSymlinkTopology(entries, applicationRoot: applicationRoot)
        try reader.verifyUnchanged()
        return UpdateArchiveInspection(
            entries: entries,
            applicationRootName: applicationRoot,
            archiveBytes: reader.size,
            expandedBytes: expandedBytes
        )
    }

    private static func validateLocalRecords(
        _ entries: [UpdateArchiveEntry],
        reader: SecureArchiveReader,
        centralOffset: UInt64,
        applicationRoot: String,
        limits: UpdateArchiveLimits
    ) throws -> [UpdateArchiveEntry] {
        guard entries.first?.localHeaderOffset == 0 else { throw UpdateError.invalidArchive }
        var validated: [UpdateArchiveEntry] = []
        validated.reserveCapacity(entries.count)
        for index in entries.indices {
            let entry = entries[index]
            if index > entries.startIndex {
                guard entries[index - 1].localHeaderOffset < entry.localHeaderOffset else {
                    throw UpdateError.invalidArchive
                }
            }
            let fixed = try reader.read(offset: entry.localHeaderOffset, count: 30)
            guard try fixed.u32(0) == localHeaderSignature,
                  try fixed.u16(4) == entry.neededVersion,
                  try fixed.u16(6) == entry.flags,
                  try fixed.u16(8) == entry.method,
                  try fixed.u16(10) == entry.modifiedTime,
                  try fixed.u16(12) == entry.modifiedDate else {
                throw UpdateError.invalidArchive
            }
            let nameLength = Int(try fixed.u16(26))
            let extraLength = Int(try fixed.u16(28))
            guard nameLength == entry.rawName.count else { throw UpdateError.invalidArchive }
            let variable = try reader.read(
                offset: try checkedAdd(entry.localHeaderOffset, 30),
                count: try checkedIntAdd(nameLength, extraLength)
            )
            guard try variable.slice(0, nameLength) == entry.rawName else {
                throw UpdateError.invalidArchive
            }
            try validateLocalExtraFields(
                try variable.slice(nameLength, extraLength),
                centralExtra: entry.centralExtra
            )
            if entry.flags == 0 {
                guard try fixed.u32(14) == entry.crc32,
                      UInt64(try fixed.u32(18)) == entry.compressedSize,
                      UInt64(try fixed.u32(22)) == entry.expandedSize else {
                    throw UpdateError.invalidArchive
                }
            } else {
                guard try fixed.u32(14) == 0,
                      try fixed.u32(18) == 0,
                      try fixed.u32(22) == 0 else {
                    throw UpdateError.invalidArchive
                }
            }

            let dataOffset = try checkedAdd(
                entry.localHeaderOffset,
                UInt64(try checkedIntAdd(30, try checkedIntAdd(nameLength, extraLength)))
            )
            var recordEnd = try checkedAdd(dataOffset, entry.compressedSize)
            if entry.flags == 8 {
                let descriptor = try reader.read(offset: recordEnd, count: 16)
                guard try descriptor.u32(0) == dataDescriptorSignature,
                      try descriptor.u32(4) == entry.crc32,
                      UInt64(try descriptor.u32(8)) == entry.compressedSize,
                      UInt64(try descriptor.u32(12)) == entry.expandedSize else {
                    throw UpdateError.invalidArchive
                }
                recordEnd = try checkedAdd(recordEnd, 16)
            }
            let expectedEnd = index + 1 < entries.count ? entries[index + 1].localHeaderOffset : centralOffset
            guard recordEnd == expectedEnd else { throw UpdateError.invalidArchive }

            var symlinkTarget: String?
            if entry.type == .symlink {
                let rawTarget = try reader.read(
                    offset: dataOffset,
                    count: try boundedInt(entry.expandedSize)
                )
                guard crc32(rawTarget) == entry.crc32 else { throw UpdateError.invalidArchive }
                symlinkTarget = try normalizedSymlinkTarget(
                    rawTarget,
                    linkPath: entry.path,
                    applicationRoot: applicationRoot,
                    limits: limits
                ).target
            } else if entry.type == .regularFile {
                try validateRegularPayload(entry, dataOffset: dataOffset, reader: reader)
            }
            validated.append(UpdateArchiveEntry(
                path: entry.path,
                rawName: entry.rawName,
                centralExtra: entry.centralExtra,
                type: entry.type,
                unixMode: entry.unixMode,
                neededVersion: entry.neededVersion,
                flags: entry.flags,
                method: entry.method,
                modifiedTime: entry.modifiedTime,
                modifiedDate: entry.modifiedDate,
                crc32: entry.crc32,
                compressedSize: entry.compressedSize,
                expandedSize: entry.expandedSize,
                localHeaderOffset: entry.localHeaderOffset,
                symlinkTarget: symlinkTarget
            ))
        }
        return validated
    }

    private static func validateRegularPayload(
        _ entry: UpdateArchiveEntry,
        dataOffset: UInt64,
        reader: SecureArchiveReader
    ) throws {
        let chunkSize = 64 * 1_024
        var crcState: UInt32 = 0
        if entry.method == 0 {
            var consumed: UInt64 = 0
            while consumed < entry.compressedSize {
                let count = Int(min(UInt64(chunkSize), entry.compressedSize - consumed))
                let chunk = try reader.read(offset: try checkedAdd(dataOffset, consumed), count: count)
                crcState = chunk.withUnsafeBytes { updateCRC32(crcState, bytes: $0) }
                consumed = try checkedAdd(consumed, UInt64(count))
            }
            guard consumed == entry.expandedSize, crcState == entry.crc32 else {
                throw UpdateError.invalidArchive
            }
            return
        }

        guard entry.method == 8 else { throw UpdateError.invalidArchive }
        var stream = z_stream()
        guard inflateInit2_(
            &stream,
            -MAX_WBITS,
            ZLIB_VERSION,
            Int32(MemoryLayout<z_stream>.size)
        ) == Z_OK else {
            throw UpdateError.invalidArchive
        }
        defer { inflateEnd(&stream) }

        var compressedConsumed: UInt64 = 0
        var expandedProduced: UInt64 = 0
        var status = Int32(Z_OK)
        while compressedConsumed < entry.compressedSize, status != Z_STREAM_END {
            let count = Int(min(UInt64(chunkSize), entry.compressedSize - compressedConsumed))
            let chunk = try reader.read(
                offset: try checkedAdd(dataOffset, compressedConsumed),
                count: count
            )
            try chunk.withUnsafeBytes { inputBytes in
                guard let inputBase = inputBytes.bindMemory(to: Bytef.self).baseAddress else {
                    throw UpdateError.invalidArchive
                }
                stream.next_in = UnsafeMutablePointer(mutating: inputBase)
                stream.avail_in = uInt(count)
                while stream.avail_in > 0, status != Z_STREAM_END {
                    let availableBefore = stream.avail_in
                    var output = [UInt8](repeating: 0, count: chunkSize)
                    var produced = 0
                    status = output.withUnsafeMutableBytes { outputBytes in
                        stream.next_out = outputBytes.bindMemory(to: Bytef.self).baseAddress
                        stream.avail_out = uInt(outputBytes.count)
                        let result = inflate(&stream, Z_NO_FLUSH)
                        produced = outputBytes.count - Int(stream.avail_out)
                        return result
                    }
                    guard status == Z_OK || status == Z_STREAM_END,
                          produced > 0 || stream.avail_in < availableBefore else {
                        throw UpdateError.invalidArchive
                    }
                    if produced > 0 {
                        crcState = output.withUnsafeBytes {
                            updateCRC32(crcState, bytes: UnsafeRawBufferPointer(rebasing: $0[..<produced]))
                        }
                        expandedProduced = try checkedAdd(expandedProduced, UInt64(produced))
                        guard expandedProduced <= entry.expandedSize else {
                            throw UpdateError.invalidArchive
                        }
                    }
                }
                guard stream.avail_in == 0 else { throw UpdateError.invalidArchive }
            }
            compressedConsumed = try checkedAdd(compressedConsumed, UInt64(count))
        }
        guard status == Z_STREAM_END,
              compressedConsumed == entry.compressedSize,
              UInt64(stream.total_in) == entry.compressedSize,
              expandedProduced == entry.expandedSize,
              UInt64(stream.total_out) == entry.expandedSize,
              crcState == entry.crc32 else {
            throw UpdateError.invalidArchive
        }
    }

    private static func validateSymlinkTopology(
        _ entries: [UpdateArchiveEntry],
        applicationRoot: String
    ) throws {
        let exactTypes = Dictionary(uniqueKeysWithValues: entries.map { ($0.path, $0.type) })
        let symlinkPaths = Set(entries.lazy.filter { $0.type == .symlink }.map(\.path))

        for entry in entries {
            let components = entry.path.split(separator: "/").map(String.init)
            if components.count > 1 {
                var parent = components[0]
                for component in components.dropFirst().dropLast() {
                    parent += "/\(component)"
                    guard !symlinkPaths.contains(parent) else { throw UpdateError.invalidArchive }
                }
            }
            guard entry.type == .symlink else { continue }
            guard let target = entry.symlinkTarget,
                  let resolved = try? resolvedSymlinkPath(
                    target,
                    linkPath: entry.path,
                    applicationRoot: applicationRoot
                  ),
                  exactTypes[resolved] == .regularFile else {
                // This rejects dangling links, directory targets, special
                // targets, case aliases, chains, and cycles.
                throw UpdateError.invalidArchive
            }
        }
    }

    private static func normalizedSymlinkTarget(
        _ rawTarget: Data,
        linkPath: String,
        applicationRoot: String,
        limits: UpdateArchiveLimits
    ) throws -> (target: String, resolvedPath: String) {
        guard !rawTarget.isEmpty,
              rawTarget.count <= limits.maximumPathBytes,
              rawTarget.allSatisfy({ $0 >= 0x20 && $0 <= 0x7e }),
              let target = String(data: rawTarget, encoding: .utf8),
              target == target.precomposedStringWithCanonicalMapping,
              !target.hasPrefix("/"),
              !target.hasSuffix("/"),
              !target.contains("\\") else {
            throw UpdateError.invalidArchive
        }
        let components = target.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard !components.isEmpty,
              components.count <= limits.maximumPathDepth,
              components.allSatisfy({ !$0.isEmpty && $0 != "." && $0.utf8.count <= 255 }),
              components.contains(where: { $0 != ".." }) else {
            throw UpdateError.invalidArchive
        }

        // A normalized relative link may walk upward only as an initial run.
        // This is required by npm's reviewed `.bin -> ../package/...` links,
        // while rejecting disguised `package/../other` traversal aliases.
        var sawLeaf = false
        for component in components {
            if component == ".." {
                guard !sawLeaf else { throw UpdateError.invalidArchive }
            } else {
                sawLeaf = true
            }
        }
        guard let firstLeaf = components.first(where: { $0 != ".." }),
              !(firstLeaf.count == 2
                  && firstLeaf.first?.isASCII == true
                  && firstLeaf.first?.isLetter == true
                  && firstLeaf.last == ":") else {
            throw UpdateError.invalidArchive
        }
        let resolved = try resolvedSymlinkPath(
            target,
            linkPath: linkPath,
            applicationRoot: applicationRoot
        )
        return (target, resolved)
    }

    fileprivate static func resolvedSymlinkPath(
        _ target: String,
        linkPath: String,
        applicationRoot: String
    ) throws -> String {
        var resolved = linkPath.split(separator: "/").dropLast().map(String.init)
        guard resolved.first == applicationRoot else { throw UpdateError.invalidArchive }
        var sawLeaf = false
        for component in target.split(separator: "/", omittingEmptySubsequences: false).map(String.init) {
            guard !component.isEmpty, component != "." else { throw UpdateError.invalidArchive }
            if component == ".." {
                guard !sawLeaf, resolved.count > 1 else { throw UpdateError.invalidArchive }
                resolved.removeLast()
            } else {
                sawLeaf = true
                resolved.append(component)
            }
        }
        guard sawLeaf, resolved.first == applicationRoot else { throw UpdateError.invalidArchive }
        return resolved.joined(separator: "/")
    }

    private static func crc32(_ data: Data) -> UInt32 {
        data.withUnsafeBytes { updateCRC32(0, bytes: $0) }
    }

    private static func updateCRC32(_ initial: UInt32, bytes: UnsafeRawBufferPointer) -> UInt32 {
        guard !bytes.isEmpty, let base = bytes.bindMemory(to: Bytef.self).baseAddress else {
            return initial
        }
        return UInt32(zlib.crc32(uLong(initial), base, uInt(bytes.count)))
    }

    private static func validateCentralExtraFields(_ data: Data) throws {
        if data.isEmpty { return }
        guard data.count == 12,
              try data.u16(0) == allowedExtraField,
              try data.u16(2) == 8 else {
            throw UpdateError.invalidArchive
        }
    }

    private static func validateLocalExtraFields(_ data: Data, centralExtra: Data) throws {
        if centralExtra.isEmpty {
            guard data.isEmpty else { throw UpdateError.invalidArchive }
            return
        }
        // ditto's reviewed Unix `UX` encoding adds two 16-bit ownership fields
        // to the local record. Their values are not trusted; extraction must
        // still produce current-user-owned objects, and the timestamp payload
        // must exactly match the central directory.
        guard data.count == 16,
              (try data.u16(0)) == allowedExtraField,
              (try data.u16(2)) == 12,
              try data.slice(4, 8) == centralExtra.slice(4, 8) else {
            throw UpdateError.invalidArchive
        }
    }

    fileprivate static func normalizedPath(
        _ rawName: Data,
        directory: Bool,
        limits: UpdateArchiveLimits
    ) throws -> String {
        guard !rawName.isEmpty,
              rawName.count <= limits.maximumPathBytes,
              rawName.allSatisfy({ $0 >= 0x20 && $0 <= 0x7e }),
              let decoded = String(data: rawName, encoding: .utf8),
              !decoded.contains("\\"),
              !decoded.hasPrefix("/"),
              decoded == decoded.precomposedStringWithCanonicalMapping else {
            throw UpdateError.invalidArchive
        }
        let stripped: String
        if directory {
            guard decoded.hasSuffix("/"), !decoded.hasSuffix("//") else {
                throw UpdateError.invalidArchive
            }
            stripped = String(decoded.dropLast())
        } else {
            guard !decoded.hasSuffix("/") else { throw UpdateError.invalidArchive }
            stripped = decoded
        }
        let components = stripped.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard !components.isEmpty,
              components.count <= limits.maximumPathDepth,
              components.allSatisfy({ component in
                  !component.isEmpty && component != "." && component != ".."
                      && component.utf8.count <= 255
              }),
              !(components[0].count == 2
                  && components[0].first?.isASCII == true
                  && components[0].first?.isLetter == true
                  && components[0].last == ":") else {
            throw UpdateError.invalidArchive
        }
        return components.joined(separator: "/")
    }

    fileprivate static func foldedPath(_ path: String) -> String { path.lowercased() }

    fileprivate static func checkedAdd(_ left: UInt64, _ right: UInt64) throws -> UInt64 {
        let (value, overflow) = left.addingReportingOverflow(right)
        guard !overflow else { throw UpdateError.invalidArchive }
        return value
    }

    fileprivate static func checkedIntAdd(_ left: Int, _ right: Int) throws -> Int {
        let (value, overflow) = left.addingReportingOverflow(right)
        guard !overflow else { throw UpdateError.invalidArchive }
        return value
    }

    fileprivate static func boundedInt(_ value: UInt64) throws -> Int {
        guard let result = Int(exactly: value) else { throw UpdateError.invalidArchive }
        return result
    }
}

final class UpdateArchiveStager {
    typealias Extractor = (FileHandle, URL) throws -> Void

    private let fileManager: FileManager
    private let root: URL
    private let limits: UpdateArchiveLimits
    private let extractor: Extractor

    init(
        root: URL,
        limits: UpdateArchiveLimits = .production,
        fileManager: FileManager = .default,
        extractor: Extractor? = nil
    ) {
        // Preserve the caller's canonical spelling. URL.standardizedFileURL
        // rewrites macOS's canonical /private/tmp path to the /tmp symlink,
        // which would make the updater fail its own no-symlink policy.
        self.root = root
        self.limits = limits
        self.fileManager = fileManager
        self.extractor = extractor ?? Self.extractWithDitto
    }

    func stage(archive: URL) throws -> StagedUpdateArchive {
        let support = root.deletingLastPathComponent()
        try ensurePrivateDirectory(support, create: false)
        try ensurePrivateDirectory(root, create: true)
        let stagedBase = root.appendingPathComponent("Staged", isDirectory: true)
        try ensurePrivateDirectory(stagedBase, create: true)
        try ensureContainedDirectory(stagedBase, beneath: root)

        let stagedRoot = stagedBase.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try createExclusivePrivateDirectory(stagedRoot)
        try ensureContainedDirectory(stagedRoot, beneath: stagedBase)
        var keepStage = false
        defer {
            if !keepStage { try? fileManager.removeItem(at: stagedRoot) }
        }

        let expandedRoot = stagedRoot.appendingPathComponent("Expanded", isDirectory: true)
        try createExclusivePrivateDirectory(expandedRoot)
        try ensureContainedDirectory(expandedRoot, beneath: stagedRoot)

        // Snapshot the caller-controlled archive into an unlinked private file.
        // Preflight and extraction then consume the same read-only file
        // description, so renaming or mutating the original path cannot change
        // the bytes handed to ditto after validation.
        let snapshot = try SecureArchiveReader.privateSnapshot(
            of: archive,
            in: stagedRoot,
            maximumBytes: limits.maximumArchiveBytes
        )
        defer { snapshot.close() }
        let inspection = try SecureUpdateArchive.inspect(snapshot, limits: limits)
        let extractionInput = try snapshot.duplicatedFileHandle()
        defer { try? extractionInput.close() }

        do {
            try extractor(extractionInput, expandedRoot)
        } catch {
            throw UpdateError.invalidArchive
        }
        try snapshot.verifyUnchanged()
        try ensurePrivateDirectory(stagedRoot, create: false)
        try ensurePrivateDirectory(expandedRoot, create: false)
        try validateExtractedTree(expandedRoot, inspection: inspection)
        let candidate = expandedRoot.appendingPathComponent(inspection.applicationRootName, isDirectory: true)
        try ensureContainedDirectory(candidate, beneath: expandedRoot, requirePrivateMode: false)
        keepStage = true
        return StagedUpdateArchive(stageRoot: stagedRoot, appURL: candidate)
    }

    func discard(_ staged: StagedUpdateArchive) {
        guard staged.stageRoot == staged.appURL
            .deletingLastPathComponent()
            .deletingLastPathComponent() else { return }
        try? UpdateApplicationSecurity.discardPrivateStagedOperation(
            stagedApplication: staged.appURL,
            updatesRoot: root
        )
    }

    /// Called once when a new UpdateManager is created, before it can prepare
    /// any current operation. Only exact UUID children are considered; linked,
    /// permissive, foreign or raced entries fail closed and remain untouched.
    func discardOrphanedStages() {
        let stagedBase = root.appendingPathComponent("Staged", isDirectory: true)
        var metadata = stat()
        guard lstat(stagedBase.path, &metadata) == 0 else { return }
        do {
            try UpdateApplicationSecurity.preparePrivateOwnedDirectory(root.deletingLastPathComponent())
            try UpdateApplicationSecurity.preparePrivateOwnedDirectory(root)
            try UpdateApplicationSecurity.preparePrivateOwnedDirectory(stagedBase)
            for name in try fileManager.contentsOfDirectory(atPath: stagedBase.path) {
                guard UUID(uuidString: name) != nil else { continue }
                let operation = stagedBase.appendingPathComponent(name, isDirectory: true)
                let app = operation
                    .appendingPathComponent("Expanded", isDirectory: true)
                    .appendingPathComponent(
                        UpdateApplicationSecurity.expectedApplicationBundleName,
                        isDirectory: true
                    )
                try? UpdateApplicationSecurity.discardPrivateStagedOperation(
                    stagedApplication: app,
                    updatesRoot: root
                )
            }
        } catch {
            return
        }
    }

    private func validateExtractedTree(
        _ stage: URL,
        inspection: UpdateArchiveInspection
    ) throws {
        typealias ActualEntry = (type: UpdateArchiveEntryType, size: UInt64, mode: UInt32, target: String?)
        let expectedByPath = Dictionary(uniqueKeysWithValues: inspection.entries.map { ($0.path, $0) })
        var actual: [String: ActualEntry] = [:]
        var folded: [String: String] = [:]
        var totalBytes: UInt64 = 0
        var entryCount = 0
        let canonicalStage = try canonicalPath(stage)

        func visit(_ directory: URL, prefix: String, depth: Int) throws {
            guard depth <= limits.maximumPathDepth else { throw UpdateError.invalidArchive }
            let names = try fileManager.contentsOfDirectory(atPath: directory.path).sorted()
            for name in names {
                guard let raw = name.data(using: .utf8),
                      raw.allSatisfy({ $0 >= 0x20 && $0 <= 0x7e }),
                      name == name.precomposedStringWithCanonicalMapping,
                      !name.isEmpty,
                      name != ".",
                      name != "..",
                      name.utf8.count <= 255,
                      !name.contains("/"),
                      !name.contains("\\") else {
                    throw UpdateError.invalidArchive
                }
                entryCount += 1
                guard entryCount <= limits.maximumEntries else { throw UpdateError.invalidArchive }
                let path = prefix.isEmpty ? name : "\(prefix)/\(name)"
                guard path.utf8.count <= limits.maximumPathBytes else { throw UpdateError.invalidArchive }
                let key = SecureUpdateArchive.foldedPath(path)
                guard folded[key] == nil else { throw UpdateError.invalidArchive }
                folded[key] = path

                let child = directory.appendingPathComponent(name, isDirectory: false)
                var info = stat()
                guard lstat(child.path, &info) == 0,
                      info.st_uid == geteuid() else {
                    throw UpdateError.invalidArchive
                }
                let kind = info.st_mode & mode_t(S_IFMT)
                let mode = UInt32(info.st_mode & 0o7777)
                if kind == mode_t(S_IFDIR) {
                    actual[path] = (.directory, 0, mode, nil)
                    try visit(child, prefix: path, depth: depth + 1)
                } else if kind == mode_t(S_IFREG) {
                    guard info.st_nlink == 1, info.st_size >= 0 else { throw UpdateError.invalidArchive }
                    let size = UInt64(info.st_size)
                    guard size <= limits.maximumEntryBytes else { throw UpdateError.invalidArchive }
                    totalBytes = try SecureUpdateArchive.checkedAdd(totalBytes, size)
                    guard totalBytes <= limits.maximumExpandedBytes else { throw UpdateError.invalidArchive }
                    actual[path] = (.regularFile, size, mode, nil)
                } else if kind == mode_t(S_IFLNK) {
                    guard let expected = expectedByPath[path],
                          expected.type == .symlink,
                          let expectedTarget = expected.symlinkTarget,
                          info.st_nlink == 1,
                          info.st_size >= 0 else {
                        throw UpdateError.invalidArchive
                    }
                    let rawTarget = try readSymlink(child, maximumBytes: limits.maximumPathBytes)
                    guard rawTarget == Data(expectedTarget.utf8) else { throw UpdateError.invalidArchive }
                    let target = String(decoding: rawTarget, as: UTF8.self)
                    let resolved = try SecureUpdateArchive.resolvedSymlinkPath(
                        target,
                        linkPath: path,
                        applicationRoot: inspection.applicationRootName
                    )
                    let resolvedURL = resolved.split(separator: "/").reduce(stage) {
                        $0.appendingPathComponent(String($1), isDirectory: false)
                    }
                    var targetInfo = stat()
                    guard lstat(resolvedURL.path, &targetInfo) == 0,
                          targetInfo.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
                          targetInfo.st_uid == geteuid(),
                          targetInfo.st_nlink == 1,
                          try canonicalPath(resolvedURL).hasPrefix(canonicalStage + "/") else {
                        throw UpdateError.invalidArchive
                    }
                    let size = UInt64(rawTarget.count)
                    totalBytes = try SecureUpdateArchive.checkedAdd(totalBytes, size)
                    guard totalBytes <= limits.maximumExpandedBytes else { throw UpdateError.invalidArchive }
                    actual[path] = (.symlink, size, mode, target)
                } else {
                    throw UpdateError.invalidArchive
                }
            }
        }
        try visit(stage, prefix: "", depth: 0)

        guard entryCount == inspection.entries.count,
              totalBytes == inspection.expandedBytes else {
            throw UpdateError.invalidArchive
        }
        for expected in inspection.entries {
            guard let value = actual[expected.path],
                  value.type == expected.type,
                  value.size == expected.expandedSize,
                  value.target == expected.symlinkTarget,
                  (expected.type == .symlink || value.mode == expected.unixMode & 0o7777) else {
                throw UpdateError.invalidArchive
            }
        }
    }

    private func readSymlink(_ link: URL, maximumBytes: Int) throws -> Data {
        var buffer = [UInt8](repeating: 0, count: maximumBytes + 1)
        let count = buffer.withUnsafeMutableBytes { bytes in
            Darwin.readlink(link.path, bytes.baseAddress, bytes.count)
        }
        guard count > 0, count <= maximumBytes else { throw UpdateError.invalidArchive }
        return Data(buffer.prefix(count))
    }

    private func ensurePrivateDirectory(_ directory: URL, create: Bool) throws {
        var info = stat()
        if lstat(directory.path, &info) != 0 {
            guard create, errno == ENOENT,
                  mkdir(directory.path, 0o700) == 0 || errno == EEXIST,
                  lstat(directory.path, &info) == 0 else {
                throw UpdateError.invalidArchive
            }
        }
        do {
            try UpdateApplicationSecurity.preparePrivateOwnedDirectory(directory)
        } catch {
            throw UpdateError.invalidArchive
        }
    }

    private func createExclusivePrivateDirectory(_ directory: URL) throws {
        guard mkdir(directory.path, 0o700) == 0 else { throw UpdateError.invalidArchive }
        try ensurePrivateDirectory(directory, create: false)
    }

    private func ensureContainedDirectory(
        _ directory: URL,
        beneath parent: URL,
        requirePrivateMode: Bool = true
    ) throws {
        let canonicalParent = try canonicalPath(parent)
        let canonicalDirectory = try canonicalPath(directory)
        guard canonicalDirectory.hasPrefix(canonicalParent + "/") else {
            throw UpdateError.invalidArchive
        }
        var info = stat()
        guard lstat(directory.path, &info) == 0,
              info.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
              info.st_uid == geteuid(),
              !requirePrivateMode || info.st_mode & 0o7777 == 0o700 else {
            throw UpdateError.invalidArchive
        }
    }

    private func canonicalPath(_ url: URL) throws -> String {
        guard let resolved = realpath(url.path, nil) else { throw UpdateError.invalidArchive }
        defer { free(resolved) }
        return String(cString: resolved)
    }

    private static func extractWithDitto(_ archive: FileHandle, _ destination: URL) throws {
        try extractWithBoundedProcess(
            archive,
            destination,
            executable: URL(fileURLWithPath: "/usr/bin/ditto"),
            deadline: 300
        )
    }

    static func extractWithBoundedProcess(
        _ archive: FileHandle,
        _ destination: URL,
        executable: URL,
        deadline: TimeInterval,
        terminationGrace: TimeInterval = 0.25,
        onSpawn: ((pid_t) -> Void)? = nil
    ) throws {
        guard lseek(archive.fileDescriptor, 0, SEEK_SET) == 0 else { throw UpdateError.invalidArchive }
        let result: BoundedProcessGroupResult
        do {
            result = try BoundedProcessGroupRunner.run(
                executable: executable,
                arguments: [
                    "-x", "-k", "--norsrc", "--noextattr", "--noqtn", "--noacl",
                    "--nopersistRootless", "-", destination.path
                ],
                environment: ChildProcessEnvironment.make(nodeBin: nil),
                maximumStderrBytes: 64 * 1_024,
                deadline: deadline,
                terminationGrace: terminationGrace,
                standardInputDescriptor: archive.fileDescriptor,
                discardStandardOutput: true,
                onSpawn: onSpawn
            )
        } catch {
            throw UpdateError.invalidArchive
        }
        guard result.limit == nil,
              result.exitStatus == 0,
              result.terminationSignal == nil else { throw UpdateError.invalidArchive }
    }
}

private final class SecureArchiveReader {
    private struct Identity {
        let device: dev_t
        let inode: ino_t
        let mode: mode_t
        let links: nlink_t
        let owner: uid_t
        let size: off_t
        let modifiedSeconds: Int
        let modifiedNanoseconds: Int
        let changedSeconds: Int
        let changedNanoseconds: Int

        init(_ info: stat) {
            device = info.st_dev
            inode = info.st_ino
            mode = info.st_mode
            links = info.st_nlink
            owner = info.st_uid
            size = info.st_size
            modifiedSeconds = info.st_mtimespec.tv_sec
            modifiedNanoseconds = info.st_mtimespec.tv_nsec
            changedSeconds = info.st_ctimespec.tv_sec
            changedNanoseconds = info.st_ctimespec.tv_nsec
        }

        func matches(_ info: stat) -> Bool {
            device == info.st_dev && inode == info.st_ino && mode == info.st_mode
                && links == info.st_nlink && owner == info.st_uid && size == info.st_size
                && modifiedSeconds == info.st_mtimespec.tv_sec
                && modifiedNanoseconds == info.st_mtimespec.tv_nsec
                && changedSeconds == info.st_ctimespec.tv_sec
                && changedNanoseconds == info.st_ctimespec.tv_nsec
        }
    }

    let size: UInt64
    private let descriptor: Int32
    private let identity: Identity
    private var closed = false

    init(_ archive: URL, maximumBytes: UInt64) throws {
        var before = stat()
        guard lstat(archive.path, &before) == 0,
              before.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              before.st_nlink == 1,
              before.st_size >= 0,
              UInt64(before.st_size) <= maximumBytes else {
            throw UpdateError.invalidArchive
        }
        let opened = Darwin.open(archive.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard opened >= 0 else { throw UpdateError.invalidArchive }
        var after = stat()
        guard fstat(opened, &after) == 0,
              Identity(before).matches(after) else {
            Darwin.close(opened)
            throw UpdateError.invalidArchive
        }
        descriptor = opened
        identity = Identity(after)
        size = UInt64(after.st_size)
    }

    private init(descriptor: Int32, identity: Identity) throws {
        guard identity.mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              identity.links == 0,
              identity.owner == geteuid(),
              identity.size >= 0 else {
            Darwin.close(descriptor)
            throw UpdateError.invalidArchive
        }
        self.descriptor = descriptor
        self.identity = identity
        size = UInt64(identity.size)
    }

    static func privateSnapshot(
        of source: URL,
        in privateDirectory: URL,
        maximumBytes: UInt64
    ) throws -> SecureArchiveReader {
        let input = try SecureArchiveReader(source, maximumBytes: maximumBytes)
        defer { input.close() }

        let temporary = privateDirectory.appendingPathComponent(".Archive.\(UUID().uuidString)")
        let writer = Darwin.open(
            temporary.path,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            mode_t(0o600)
        )
        guard writer >= 0 else { throw UpdateError.invalidArchive }
        var readerDescriptor: Int32 = -1
        var linked = true
        defer {
            Darwin.close(writer)
            if readerDescriptor >= 0 { Darwin.close(readerDescriptor) }
            if linked { Darwin.unlink(temporary.path) }
        }

        guard fchmod(writer, 0o600) == 0 else { throw UpdateError.invalidArchive }
        var offset: UInt64 = 0
        let chunkBytes = 1024 * 1024
        while offset < input.size {
            let count = Int(min(UInt64(chunkBytes), input.size - offset))
            let data = try input.read(offset: offset, count: count)
            var written = 0
            while written < data.count {
                let result: Int = data.withUnsafeBytes { bytes in
                    guard let base = bytes.baseAddress else { return 0 }
                    return Darwin.write(writer, base.advanced(by: written), data.count - written)
                }
                if result < 0, errno == EINTR { continue }
                guard result > 0 else { throw UpdateError.invalidArchive }
                written += result
            }
            offset = try SecureUpdateArchive.checkedAdd(offset, UInt64(count))
        }
        guard fsync(writer) == 0 else { throw UpdateError.invalidArchive }
        try input.verifyUnchanged()

        var writtenInfo = stat()
        guard fstat(writer, &writtenInfo) == 0,
              writtenInfo.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              writtenInfo.st_mode & 0o7777 == 0o600,
              writtenInfo.st_uid == geteuid(),
              writtenInfo.st_nlink == 1,
              writtenInfo.st_size == off_t(input.size) else {
            throw UpdateError.invalidArchive
        }

        readerDescriptor = Darwin.open(temporary.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard readerDescriptor >= 0 else { throw UpdateError.invalidArchive }
        var readerInfo = stat()
        guard fstat(readerDescriptor, &readerInfo) == 0,
              Identity(writtenInfo).matches(readerInfo),
              Darwin.unlink(temporary.path) == 0 else {
            throw UpdateError.invalidArchive
        }
        linked = false
        var unlinkedInfo = stat()
        guard fstat(readerDescriptor, &unlinkedInfo) == 0,
              unlinkedInfo.st_nlink == 0,
              unlinkedInfo.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              unlinkedInfo.st_mode & 0o7777 == 0o600,
              unlinkedInfo.st_uid == geteuid(),
              unlinkedInfo.st_size == off_t(input.size) else {
            throw UpdateError.invalidArchive
        }
        try input.verifyUnchanged()

        let owned = readerDescriptor
        readerDescriptor = -1
        return try SecureArchiveReader(descriptor: owned, identity: Identity(unlinkedInfo))
    }

    func read(offset: UInt64, count: Int) throws -> Data {
        guard count >= 0,
              offset <= size,
              UInt64(count) <= size - offset,
              let fileOffset = off_t(exactly: offset) else {
            throw UpdateError.invalidArchive
        }
        var data = Data(count: count)
        var consumed = 0
        while consumed < count {
            let result: Int = data.withUnsafeMutableBytes { buffer in
                guard let base = buffer.baseAddress else { return 0 }
                return pread(descriptor, base.advanced(by: consumed), count - consumed, fileOffset + off_t(consumed))
            }
            if result < 0, errno == EINTR { continue }
            guard result > 0 else { throw UpdateError.invalidArchive }
            consumed += result
        }
        return data
    }

    func verifyUnchanged() throws {
        var current = stat()
        guard fstat(descriptor, &current) == 0, identity.matches(current) else {
            throw UpdateError.invalidArchive
        }
    }

    func duplicatedFileHandle() throws -> FileHandle {
        let duplicate = Darwin.dup(descriptor)
        guard duplicate >= 0, lseek(duplicate, 0, SEEK_SET) == 0 else {
            if duplicate >= 0 { Darwin.close(duplicate) }
            throw UpdateError.invalidArchive
        }
        return FileHandle(fileDescriptor: duplicate, closeOnDealloc: true)
    }

    func close() {
        guard !closed else { return }
        closed = true
        Darwin.close(descriptor)
    }

    deinit { close() }
}

private extension Data {
    func u16(_ offset: Int) throws -> UInt16 {
        guard offset >= 0, count - offset >= 2 else { throw UpdateError.invalidArchive }
        return UInt16(self[offset]) | UInt16(self[offset + 1]) << 8
    }

    func u32(_ offset: Int) throws -> UInt32 {
        guard offset >= 0, count - offset >= 4 else { throw UpdateError.invalidArchive }
        return UInt32(self[offset])
            | UInt32(self[offset + 1]) << 8
            | UInt32(self[offset + 2]) << 16
            | UInt32(self[offset + 3]) << 24
    }

    func slice(_ offset: Int, _ length: Int) throws -> Data {
        guard offset >= 0, length >= 0, count - offset >= length else {
            throw UpdateError.invalidArchive
        }
        return subdata(in: offset..<(offset + length))
    }
}
