import Darwin
import Foundation

final class ServiceLogStore: @unchecked Sendable {
    struct StreamID: Hashable, Sendable {
        fileprivate let value: UUID
    }

    private struct StreamState {
        let label: String
        var pending = Data()
        var isOversized = false
        var isInsidePrivateKeyBlock = false
        var oversizedPrivateKeyScanTail = Data()
        var oversizedLineHadPrivateKeyMaterial = false
        var oversizedLineOpenedPrivateKeyBlock = false
    }

    private struct FileIdentity: Equatable {
        let device: UInt64
        let inode: UInt64

        init(_ metadata: stat) {
            device = UInt64(truncatingIfNeeded: metadata.st_dev)
            inode = UInt64(metadata.st_ino)
        }
    }

    private enum CurrentLogState: Equatable {
        case absent
        case present(FileIdentity)
    }

    private struct RedactionPattern: @unchecked Sendable {
        let expression: NSRegularExpression
        let template: String

        init(
            _ pattern: String,
            options: NSRegularExpression.Options = [],
            template: String
        ) {
            expression = try! NSRegularExpression(pattern: pattern, options: options)
            self.template = template
        }
    }

    private static let privateKeyBegin = try! NSRegularExpression(
        pattern: #"-----BEGIN(?: [A-Z0-9]{1,32})? PRIVATE KEY-----"#,
        options: [.caseInsensitive]
    )
    private static let privateKeyEnd = try! NSRegularExpression(
        pattern: #"-----END(?: [A-Z0-9]{1,32})? PRIVATE KEY-----"#,
        options: [.caseInsensitive]
    )
    private static let redactionPatterns: [RedactionPattern] = [
        RedactionPattern(
            #"-----BEGIN(?: [A-Z0-9]{1,32})? PRIVATE KEY-----[\s\S]*?-----END(?: [A-Z0-9]{1,32})? PRIVATE KEY-----"#,
            options: [.caseInsensitive],
            template: "[REDACTED PRIVATE KEY]"
        ),
        RedactionPattern(#"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s\"']+"#, template: "$1<redacted>"),
        RedactionPattern(#"(?i)(x-local-harness-token\s*[:=]\s*)[^\s\"']+"#, template: "$1<redacted>"),
        RedactionPattern(
            #"(?i)((?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret|password|passwd)\s*[:=]\s*)[^\s,}\]]+"#,
            template: "$1<redacted>"
        ),
        RedactionPattern(
            #"(?i)(\"(?:apiKey|api_key|accessToken|access_token|secret|password|passwd|clientSecret|client_secret)\"\s*:\s*\")[^\"]+(\")"#,
            template: "$1<redacted>$2"
        ),
        RedactionPattern(#"(?i)(https?://[^\s:/]+:)[^@\s]+(@)"#, template: "$1<redacted>$2"),
        RedactionPattern(#"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"#, template: "[REDACTED JWT]"),
        RedactionPattern(#"\bAKIA[A-Z0-9]{16}\b"#, template: "[REDACTED ACCESS KEY]"),
        RedactionPattern(
            #"\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{20,}\b"#,
            options: [.caseInsensitive],
            template: "[REDACTED TOKEN]"
        ),
        RedactionPattern(
            #"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"#,
            options: [.caseInsensitive],
            template: "[REDACTED TOKEN]"
        ),
        RedactionPattern(#"\b(?:hf_[A-Za-z0-9]{20,}|AIza[A-Za-z0-9_-]{30,})\b"#, template: "[REDACTED API KEY]"),
        RedactionPattern(
            #"\b(?:sk|rk|api)[-_][A-Za-z0-9_-]{12,}\b"#,
            options: [.caseInsensitive],
            template: "[REDACTED API KEY]"
        )
    ]

    private static let oversizedLineMarker = Data("[diagnostic line omitted: oversized]\n".utf8)
    private static let currentLogFilename = "services.log"
    private static let previousLogFilename = "services.previous.log"

    let directory: URL
    let logURL: URL
    let previousLogURL: URL

    private let maxBytes: Int
    private let maximumChunkBytes: Int
    private let directoryCapability: RetainedPrivateDirectoryCapability?
    private let lock = NSLock()
    private var streams: [StreamID: StreamState] = [:]
    private var currentLogState: CurrentLogState = .absent
    private var storageUnavailable = false

    init(
        directory: URL,
        maxBytes: Int = 5_000_000,
        maximumChunkBytes: Int = 64 * 1_024,
        fileManager _: FileManager = .default
    ) {
        precondition(maxBytes > 0)
        precondition(maximumChunkBytes > 0)
        self.directory = directory
        self.maxBytes = maxBytes
        self.maximumChunkBytes = maximumChunkBytes
        logURL = directory.appendingPathComponent("services.log")
        previousLogURL = directory.appendingPathComponent("services.previous.log")

        let capability = try? RetainedPrivateDirectoryCapability(
            directoryURL: directory,
            createIfMissing: true
        )
        directoryCapability = capability
        guard let capability else {
            storageUnavailable = true
            return
        }
        do {
            currentLogState = try capability.withValidatedDescriptor { descriptor in
                try Self.inspectCurrentLogState(directoryDescriptor: descriptor)
            }
        } catch {
            storageUnavailable = true
        }
    }

    func append(_ data: Data, label: String) {
        guard !data.isEmpty else { return }
        let stream = openStream(label: label)
        append(data, to: stream)
        finish(stream)
    }

    /// Opens an independently buffered diagnostic stream. Bytes supplied to a
    /// stream are never persisted until a complete logical line is available,
    /// preventing credentials split across arbitrary pipe reads from evading
    /// redaction. Call `finish(_:)` at EOF so the final unterminated line can be
    /// sanitized and written.
    func openStream(label: String) -> StreamID {
        let identifier = StreamID(value: UUID())
        lock.lock()
        defer { lock.unlock() }
        streams[identifier] = StreamState(label: Self.singleLinePrefix(label, maximumBytes: 128))
        return identifier
    }

    func append(_ data: Data, to stream: StreamID) {
        guard !data.isEmpty else { return }
        lock.lock()
        defer { lock.unlock() }
        guard var state = streams.removeValue(forKey: stream) else { return }

        for byte in data {
            if byte == 0x0A {
                persistCompletedLineLocked(&state)
            } else if !state.isOversized {
                if state.pending.count < maximumChunkBytes {
                    state.pending.append(byte)
                } else {
                    // Never retain or persist a prefix of an oversized line: a
                    // credential could straddle the retained/discarded edge.
                    // Scan the bounded prefix before discarding it, then keep a
                    // tiny rolling marker window for the rest of the line so an
                    // oversized PEM BEGIN cannot expose following key-body lines.
                    for pendingByte in state.pending {
                        Self.observePrivateKeyMarker(byte: pendingByte, state: &state)
                    }
                    Self.observePrivateKeyMarker(byte: byte, state: &state)
                    state.pending.removeAll(keepingCapacity: false)
                    state.isOversized = true
                }
            } else {
                Self.observePrivateKeyMarker(byte: byte, state: &state)
            }
        }
        streams[stream] = state
    }

    func finish(_ stream: StreamID) {
        lock.lock()
        defer { lock.unlock() }
        guard var state = streams.removeValue(forKey: stream) else { return }
        if state.isOversized {
            let payload = Self.oversizedPayload(for: state, terminated: false)
            if !payload.isEmpty {
                persistLocked(payload, label: state.label)
            }
        } else if !state.pending.isEmpty, !state.isInsidePrivateKeyBlock {
            let text = String(decoding: state.pending, as: UTF8.self)
            if Self.contains(Self.privateKeyBegin, in: text),
               !Self.contains(Self.privateKeyEnd, in: text) {
                persistLocked(Data("[REDACTED PRIVATE KEY]".utf8), label: state.label)
            } else {
                persistLocked(Self.sanitized(state.pending), label: state.label)
            }
        }
        state.pending.removeAll(keepingCapacity: false)
    }

    private func persistCompletedLineLocked(_ state: inout StreamState) {
        let payload: Data
        if state.isOversized {
            payload = Self.oversizedPayload(for: state, terminated: true)
        } else {
            var line = state.pending
            if line.last == 0x0D { line.removeLast() }
            let text = String(decoding: line, as: UTF8.self)
            if state.isInsidePrivateKeyBlock {
                if Self.contains(Self.privateKeyEnd, in: text) {
                    state.isInsidePrivateKeyBlock = false
                }
                payload = Data()
            } else if Self.contains(Self.privateKeyBegin, in: text),
                      !Self.contains(Self.privateKeyEnd, in: text) {
                state.isInsidePrivateKeyBlock = true
                payload = Data("[REDACTED PRIVATE KEY]\n".utf8)
            } else {
                payload = Self.sanitized(line) + Data("\n".utf8)
            }
        }
        if !payload.isEmpty {
            persistLocked(payload, label: state.label)
        }
        state.pending.removeAll(keepingCapacity: true)
        state.isOversized = false
        state.oversizedPrivateKeyScanTail.removeAll(keepingCapacity: true)
        state.oversizedLineHadPrivateKeyMaterial = false
        state.oversizedLineOpenedPrivateKeyBlock = false
    }

    private static func observePrivateKeyMarker(byte: UInt8, state: inout StreamState) {
        if state.isInsidePrivateKeyBlock {
            state.oversizedLineHadPrivateKeyMaterial = true
        }
        state.oversizedPrivateKeyScanTail.append(byte)
        if state.oversizedPrivateKeyScanTail.count > 96 {
            state.oversizedPrivateKeyScanTail.removeFirst(
                state.oversizedPrivateKeyScanTail.count - 96
            )
        }
        // Both reviewed PEM delimiters end in '-', so avoid regex work for
        // ordinary diagnostic bytes while retaining cross-chunk recognition.
        guard byte == 0x2D else { return }
        let tail = String(decoding: state.oversizedPrivateKeyScanTail, as: UTF8.self)
        if contains(privateKeyBegin, in: tail), !state.isInsidePrivateKeyBlock {
            state.isInsidePrivateKeyBlock = true
            state.oversizedLineHadPrivateKeyMaterial = true
            state.oversizedLineOpenedPrivateKeyBlock = true
        }
        if contains(privateKeyEnd, in: tail), state.isInsidePrivateKeyBlock {
            state.isInsidePrivateKeyBlock = false
            state.oversizedLineHadPrivateKeyMaterial = true
        }
    }

    private static func oversizedPayload(for state: StreamState, terminated: Bool) -> Data {
        if state.oversizedLineHadPrivateKeyMaterial {
            guard state.oversizedLineOpenedPrivateKeyBlock else { return Data() }
            return Data((terminated ? "[REDACTED PRIVATE KEY]\n" : "[REDACTED PRIVATE KEY]").utf8)
        }
        return oversizedLineMarker
    }

    private func persistLocked(_ sanitized: Data, label: String) {
        guard !sanitized.isEmpty, !storageUnavailable, let directoryCapability else { return }
        do {
            try directoryCapability.withValidatedDescriptor { directoryDescriptor in
                try requireCurrentLogState(directoryDescriptor: directoryDescriptor)
                let prefix = "[\(ISO8601DateFormatter().string(from: Date()))] [\(label)] "
                var payload = Data(prefix.utf8)
                payload.append(sanitized)
                if payload.count > maxBytes {
                    payload = Data(payload.suffix(maxBytes))
                }

                let current = try readTail(
                    filename: Self.currentLogFilename,
                    directoryDescriptor: directoryDescriptor,
                    maximumBytes: maxBytes
                )
                try requireCurrentLogState(directoryDescriptor: directoryDescriptor)
                if current.count <= maxBytes - payload.count,
                   let appendedIdentity = try appendToVerifiedCurrent(
                       payload,
                       expectedBytes: current.count,
                       expectedState: currentLogState,
                       directoryDescriptor: directoryDescriptor
                   ) {
                    currentLogState = .present(appendedIdentity)
                    return
                }

                // Rotation is best effort, but bounding the active log is not. A
                // broken previous-log path can never make services.log grow.
                if !current.isEmpty {
                    _ = try? atomicWrite(
                        current,
                        filename: Self.previousLogFilename,
                        directoryDescriptor: directoryDescriptor
                    )
                }
                let identity = try atomicWrite(
                    payload,
                    filename: Self.currentLogFilename,
                    directoryDescriptor: directoryDescriptor
                )
                currentLogState = .present(identity)
            }
        } catch {
            // Diagnostics must never block the local service.
            storageUnavailable = true
        }
    }

    static func sanitized(_ data: Data) -> Data {
        Data(redactedDiagnosticText(String(decoding: data, as: UTF8.self)).utf8)
    }

    static func redactedDiagnosticText(_ value: String) -> String {
        var text = value
        for pattern in redactionPatterns {
            let range = NSRange(text.startIndex..., in: text)
            text = pattern.expression.stringByReplacingMatches(
                in: text,
                range: range,
                withTemplate: pattern.template
            )
        }
        let allowed = CharacterSet(charactersIn: "\n\r\t").union(.controlCharacters.inverted)
        text = String(text.unicodeScalars.map { allowed.contains($0) ? Character(String($0)) : "�" })
        return text
    }

    private static func contains(_ expression: NSRegularExpression, in value: String) -> Bool {
        expression.firstMatch(
            in: value,
            range: NSRange(value.startIndex..., in: value)
        ) != nil
    }

    func recentLogs(maxCharacters: Int = 16_000) -> String {
        lock.lock()
        defer { lock.unlock() }
        let characterLimit = max(1, min(maxCharacters, 64_000))
        let byteLimit = min(maxBytes, characterLimit * 4)
        guard !storageUnavailable, let directoryCapability else {
            return "No service log entries yet."
        }
        do {
            let data = try directoryCapability.withValidatedDescriptor { directoryDescriptor in
                try requireCurrentLogState(directoryDescriptor: directoryDescriptor)
                let data = try readTail(
                    filename: Self.currentLogFilename,
                    directoryDescriptor: directoryDescriptor,
                    maximumBytes: byteLimit
                )
                try requireCurrentLogState(directoryDescriptor: directoryDescriptor)
                return data
            }
            guard !data.isEmpty else { return "No service log entries yet." }
            return String(String(decoding: data, as: UTF8.self).suffix(characterLimit))
        } catch {
            storageUnavailable = true
            return "No service log entries yet."
        }
    }

    private static func inspectCurrentLogState(directoryDescriptor: Int32) throws -> CurrentLogState {
        let descriptor = Self.currentLogFilename.withCString { filename in
            Darwin.openat(directoryDescriptor, filename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        }
        if descriptor < 0, errno == ENOENT { return .absent }
        guard descriptor >= 0 else { throw CocoaError(.fileReadUnknown) }
        defer { _ = Darwin.close(descriptor) }
        var metadata = stat()
        var named = stat()
        guard Darwin.fstat(descriptor, &metadata) == 0,
              Self.isPrivateRegularLog(metadata),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor),
              Self.currentLogFilename.withCString({ filename in
                  Darwin.fstatat(directoryDescriptor, filename, &named, AT_SYMLINK_NOFOLLOW)
              }) == 0,
              FileIdentity(named) == FileIdentity(metadata)
        else {
            throw CocoaError(.fileReadUnsupportedScheme)
        }
        return .present(FileIdentity(metadata))
    }

    private func requireCurrentLogState(directoryDescriptor: Int32) throws {
        let actual = try Self.inspectCurrentLogState(directoryDescriptor: directoryDescriptor)
        guard actual == currentLogState else {
            throw CocoaError(.fileReadCorruptFile)
        }
    }

    private func appendToVerifiedCurrent(
        _ payload: Data,
        expectedBytes: Int,
        expectedState: CurrentLogState,
        directoryDescriptor: Int32
    ) throws -> FileIdentity? {
        guard case .present(let expectedIdentity) = expectedState else { return nil }
        let descriptor = Self.currentLogFilename.withCString { filename in
            Darwin.openat(
                directoryDescriptor,
                filename,
                O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC
            )
        }
        guard descriptor >= 0 else { return nil }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? handle.close() }
        var metadata = stat()
        guard Darwin.fstat(descriptor, &metadata) == 0,
              Self.isPrivateRegularLog(metadata),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor),
              FileIdentity(metadata) == expectedIdentity,
              metadata.st_size >= 0,
              Int(metadata.st_size) == expectedBytes,
              expectedBytes <= maxBytes - payload.count else { return nil }
        try handle.write(contentsOf: payload)
        try handle.synchronize()
        var after = stat()
        guard Darwin.fstat(descriptor, &after) == 0,
              Self.isPrivateRegularLog(after),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor),
              FileIdentity(after) == expectedIdentity,
              after.st_size == expectedBytes + payload.count,
              try Self.inspectCurrentLogState(directoryDescriptor: directoryDescriptor)
                == .present(expectedIdentity) else {
            throw CocoaError(.fileWriteUnknown)
        }
        return expectedIdentity
    }

    private func readTail(
        filename: String,
        directoryDescriptor: Int32,
        maximumBytes: Int
    ) throws -> Data {
        guard filename == Self.currentLogFilename || filename == Self.previousLogFilename else {
            throw CocoaError(.fileReadUnsupportedScheme)
        }
        let descriptor = filename.withCString { name in
            Darwin.openat(directoryDescriptor, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        }
        if descriptor < 0, errno == ENOENT { return Data() }
        guard descriptor >= 0 else { throw CocoaError(.fileReadUnknown) }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? handle.close() }
        var before = stat()
        guard Darwin.fstat(descriptor, &before) == 0,
              Self.isPrivateRegularLog(before),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor),
              before.st_size >= 0 else { throw CocoaError(.fileReadUnsupportedScheme) }
        let requested = min(maximumBytes, Int(before.st_size))
        try handle.seek(toOffset: UInt64(Int(before.st_size) - requested))
        let data = try handle.read(upToCount: requested) ?? Data()
        var after = stat()
        guard data.count == requested,
              Darwin.fstat(descriptor, &after) == 0,
              before.st_dev == after.st_dev,
              before.st_ino == after.st_ino,
              before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec else {
            throw CocoaError(.fileReadCorruptFile)
        }
        return data
    }

    private func atomicWrite(
        _ data: Data,
        filename: String,
        directoryDescriptor: Int32
    ) throws -> FileIdentity {
        guard data.count <= maxBytes else { throw CocoaError(.fileWriteUnknown) }
        guard filename == Self.currentLogFilename || filename == Self.previousLogFilename else {
            throw CocoaError(.fileWriteInvalidFileName)
        }
        let temporary = ".\(filename).\(UUID().uuidString).tmp"
        let descriptor = temporary.withCString { name in
            Darwin.openat(
                directoryDescriptor,
                name,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                S_IRUSR | S_IWUSR
            )
        }
        guard descriptor >= 0 else { throw CocoaError(.fileWriteUnknown) }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer {
            try? handle.close()
            _ = temporary.withCString { Darwin.unlinkat(directoryDescriptor, $0, 0) }
        }
        try handle.write(contentsOf: data)
        try handle.synchronize()
        var temporaryMetadata = stat()
        guard Darwin.fchmod(descriptor, S_IRUSR | S_IWUSR) == 0,
              Darwin.fstat(descriptor, &temporaryMetadata) == 0,
              temporaryMetadata.st_mode & S_IFMT == S_IFREG,
              temporaryMetadata.st_nlink == 1,
              temporaryMetadata.st_uid == geteuid(),
              temporaryMetadata.st_mode & 0o7777 == S_IRUSR | S_IWUSR,
              temporaryMetadata.st_size == data.count,
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor) else {
            throw CocoaError(.fileWriteNoPermission)
        }
        try handle.close()
        let status = temporary.withCString { source in
            filename.withCString { target in
                Darwin.renameat(directoryDescriptor, source, directoryDescriptor, target)
            }
        }
        guard status == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        let published = filename.withCString { name in
            Darwin.openat(directoryDescriptor, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        }
        guard published >= 0 else { throw CocoaError(.fileWriteUnknown) }
        defer { Darwin.close(published) }
        var publishedMetadata = stat()
        guard Darwin.fstat(published, &publishedMetadata) == 0,
              publishedMetadata.st_dev == temporaryMetadata.st_dev,
              publishedMetadata.st_ino == temporaryMetadata.st_ino,
              publishedMetadata.st_mode & S_IFMT == S_IFREG,
              publishedMetadata.st_nlink == 1,
              publishedMetadata.st_uid == geteuid(),
              publishedMetadata.st_mode & 0o7777 == S_IRUSR | S_IWUSR,
              publishedMetadata.st_size == data.count,
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(published),
              Darwin.fsync(directoryDescriptor) == 0 else {
            throw CocoaError(.fileWriteUnknown)
        }
        return FileIdentity(publishedMetadata)
    }

    private static func isPrivateRegularLog(_ metadata: stat) -> Bool {
        metadata.st_mode & S_IFMT == S_IFREG
            && metadata.st_nlink == 1
            && metadata.st_uid == geteuid()
            && metadata.st_mode & mode_t(0o7777) == mode_t(S_IRUSR | S_IWUSR)
    }

    private static func singleLinePrefix(_ value: String, maximumBytes: Int) -> String {
        let normalized = value.unicodeScalars.prefix(maximumBytes).map { scalar -> Character in
            CharacterSet.whitespacesAndNewlines.contains(scalar) || CharacterSet.controlCharacters.contains(scalar)
                ? "_" : Character(String(scalar))
        }
        var prefix = Data(String(normalized).utf8.prefix(maximumBytes))
        while !prefix.isEmpty, String(data: prefix, encoding: .utf8) == nil {
            prefix.removeLast()
        }
        return String(data: prefix, encoding: .utf8) ?? ""
    }
}
