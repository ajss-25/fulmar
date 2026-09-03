import Darwin
import Foundation

enum ConversationExportFormat: String, Codable, CaseIterable, Sendable {
    case markdown
    case json

    var pathExtension: String {
        switch self {
        case .markdown: return "md"
        case .json: return "json"
        }
    }

    var contentType: String {
        switch self {
        case .markdown: return "text/markdown; charset=utf-8"
        case .json: return "application/json"
        }
    }
}

enum ConversationExportTextRedaction: String, Codable, CaseIterable, Sendable {
    /// Preserves message text exactly after unsafe control characters are removed.
    /// This must be an explicit user choice because conversations commonly contain secrets.
    case none
    /// Replaces common credential forms. This is defense in depth, not a guarantee that
    /// arbitrary prose contains no private information.
    case detectedSecrets
    /// Replaces every message body while retaining conversation structure and metadata.
    case allContent
}

struct ConversationExportRedactionOptions: Codable, Equatable, Sendable {
    var text: ConversationExportTextRedaction
    var redactTitle: Bool
    var redactSessionIdentifier: Bool
    var redactTimestamps: Bool
    var redactRouteMetadata: Bool
    var redactAttachmentNames: Bool
    var redactAttachmentDigests: Bool

    /// Safe default for an export that remains useful as a transcript.
    static let recommended = ConversationExportRedactionOptions(
        text: .detectedSecrets,
        redactTitle: false,
        redactSessionIdentifier: true,
        redactTimestamps: false,
        redactRouteMetadata: false,
        redactAttachmentNames: true,
        redactAttachmentDigests: true
    )

    /// Explicit full-fidelity choice. Attachment bytes are never exported, even here.
    static let none = ConversationExportRedactionOptions(
        text: .none,
        redactTitle: false,
        redactSessionIdentifier: false,
        redactTimestamps: false,
        redactRouteMetadata: false,
        redactAttachmentNames: false,
        redactAttachmentDigests: false
    )

    /// Retains only roles, ordering, interruption state, and non-identifying attachment facts.
    static let structureOnly = ConversationExportRedactionOptions(
        text: .allContent,
        redactTitle: true,
        redactSessionIdentifier: true,
        redactTimestamps: true,
        redactRouteMetadata: true,
        redactAttachmentNames: true,
        redactAttachmentDigests: true
    )
}

enum ConversationExportAttachmentKind: String, Codable, CaseIterable, Sendable {
    case image
    case binary
}

/// Metadata is deliberately incapable of holding file paths or attachment bytes. This keeps
/// exports small and prevents a future caller from accidentally serializing a blob or data URL.
struct ConversationExportAttachmentMetadata: Codable, Equatable, Sendable {
    let kind: ConversationExportAttachmentKind
    let name: String?
    let mediaType: String?
    let byteCount: Int64?
    let sha256: String?

    init(
        kind: ConversationExportAttachmentKind,
        name: String? = nil,
        mediaType: String? = nil,
        byteCount: Int64? = nil,
        sha256: String? = nil
    ) {
        self.kind = kind
        self.name = name
        self.mediaType = mediaType
        self.byteCount = byteCount
        self.sha256 = sha256
    }
}

/// Attachment-aware export projection for live native chat. Durable history can use the
/// `SessionHistoryDetailSnapshot` entry point directly.
struct ConversationExportMessage: Equatable, Sendable {
    let sequence: Int
    let role: SessionTranscriptRole
    let text: String
    let date: Date
    let interrupted: Bool
    let source: SessionTranscriptSource?
    let attachments: [ConversationExportAttachmentMetadata]

    init(
        sequence: Int,
        role: SessionTranscriptRole,
        text: String,
        date: Date,
        interrupted: Bool = false,
        source: SessionTranscriptSource? = nil,
        attachments: [ConversationExportAttachmentMetadata] = []
    ) {
        self.sequence = sequence
        self.role = role
        self.text = text
        self.date = date
        self.interrupted = interrupted
        self.source = source
        self.attachments = attachments
    }

    init(
        transcript message: SessionTranscriptMessage,
        attachments: [ConversationExportAttachmentMetadata] = []
    ) {
        self.init(
            sequence: message.sequence,
            role: message.role,
            text: message.text,
            date: message.date,
            interrupted: message.interrupted,
            source: message.source,
            attachments: attachments
        )
    }

    /// Projects the final assistant event used by native conversation streaming. The caller
    /// supplies the already-consented data boundary because the wire event intentionally carries
    /// only opaque provider and model identifiers.
    init(
        assistantFinal message: HarnessAssistantFinalMessage,
        boundary: DataBoundary,
        attachments: [ConversationExportAttachmentMetadata] = []
    ) {
        let source: SessionTranscriptSource?
        if let provider = message.provider, let model = message.model {
            source = SessionTranscriptSource(
                route: ModelRoute(provider: provider, model: model),
                boundary: boundary
            )
        } else {
            source = nil
        }
        self.init(
            sequence: message.sequence,
            role: .assistant,
            text: message.text,
            date: Self.date(fromWireTime: message.time),
            interrupted: message.interrupted,
            source: source,
            attachments: attachments
        )
    }

    /// Converts a live prompt without retaining image data. Base64 is validated only enough to
    /// report its decoded byte count; it is never decoded, hashed, or copied into the message.
    static func userPrompt(
        sequence: Int,
        date: Date,
        content: [HarnessPromptContentPart],
        maximumEncodedAttachmentCharacters: Int = 32 * 1_024 * 1_024
    ) throws -> ConversationExportMessage {
        guard sequence >= 0, maximumEncodedAttachmentCharacters > 0 else {
            throw ConversationExportError.invalidMessage
        }
        var textParts: [String] = []
        var metadata: [ConversationExportAttachmentMetadata] = []
        for part in content {
            switch part {
            case .text(let value):
                textParts.append(value)
            case .image(let mediaType, let data, let name):
                guard data.utf8.count <= maximumEncodedAttachmentCharacters,
                      let decodedBytes = ConversationExportBase64.decodedByteCount(data) else {
                    throw ConversationExportError.invalidAttachmentMetadata
                }
                metadata.append(ConversationExportAttachmentMetadata(
                    kind: .image,
                    name: name,
                    mediaType: mediaType.rawValue,
                    byteCount: Int64(decodedBytes),
                    sha256: nil
                ))
            }
        }
        return ConversationExportMessage(
            sequence: sequence,
            role: .user,
            text: textParts.joined(separator: "\n"),
            date: date,
            attachments: metadata
        )
    }

    private static func date(fromWireTime value: Double) -> Date {
        let seconds = abs(value) > 100_000_000_000 ? value / 1_000 : value
        return Date(timeIntervalSince1970: seconds)
    }
}

struct ConversationExportRoute: Equatable, Sendable {
    let providerID: ProviderID
    let modelID: ModelID
    let providerName: String
    let modelName: String
    let reasoningEffort: String?
    let boundary: DataBoundary
    let routable: Bool

    init(_ metadata: SessionRouteMetadata) {
        providerID = metadata.route.provider
        modelID = metadata.route.model
        providerName = metadata.providerName
        modelName = metadata.modelName
        reasoningEffort = metadata.reasoningEffort
        boundary = metadata.boundary
        routable = metadata.routable
    }

    init(
        selection: HarnessWireModelSelection,
        boundary: DataBoundary,
        providerName: String? = nil,
        modelName: String? = nil,
        routable: Bool = true
    ) {
        providerID = selection.provider
        modelID = selection.model
        self.providerName = providerName ?? selection.provider.rawValue
        self.modelName = modelName ?? selection.model.rawValue
        reasoningEffort = selection.reasoningEffort
        self.boundary = boundary
        self.routable = routable
    }
}

struct ConversationExportLimits: Equatable, Sendable {
    let maximumMessages: Int
    let maximumMessageCharacters: Int
    let maximumMessageUTF8Bytes: Int
    let maximumTotalTextBytes: Int
    let maximumAttachments: Int
    let maximumAttachmentNameCharacters: Int
    let maximumOutputBytes: Int

    init(
        maximumMessages: Int = 5_000,
        maximumMessageCharacters: Int = 100_000,
        maximumMessageUTF8Bytes: Int = 400_000,
        maximumTotalTextBytes: Int = 12 * 1_024 * 1_024,
        maximumAttachments: Int = 5_000,
        maximumAttachmentNameCharacters: Int = 240,
        maximumOutputBytes: Int = 16 * 1_024 * 1_024
    ) {
        precondition(maximumMessages > 0)
        precondition(maximumMessageCharacters > 0 && maximumMessageUTF8Bytes > 0)
        precondition(maximumTotalTextBytes > 0 && maximumAttachments >= 0)
        precondition(maximumAttachmentNameCharacters > 0 && maximumOutputBytes > 0)
        self.maximumMessages = maximumMessages
        self.maximumMessageCharacters = maximumMessageCharacters
        self.maximumMessageUTF8Bytes = maximumMessageUTF8Bytes
        self.maximumTotalTextBytes = maximumTotalTextBytes
        self.maximumAttachments = maximumAttachments
        self.maximumAttachmentNameCharacters = maximumAttachmentNameCharacters
        self.maximumOutputBytes = maximumOutputBytes
    }
}

struct ConversationExportArtifact: Equatable, Sendable {
    let data: Data
    let suggestedFilename: String
    let contentType: String
    let format: ConversationExportFormat
    let messageCount: Int
    let attachmentCount: Int
    let sourceWasPartial: Bool
    let redaction: ConversationExportRedactionOptions
}

enum ConversationExportError: LocalizedError, Equatable {
    case invalidMessage
    case duplicateSequence(Int)
    case messageLimitExceeded(Int)
    case messageTooLarge(sequence: Int)
    case totalTextLimitExceeded(Int)
    case attachmentLimitExceeded(Int)
    case invalidAttachmentMetadata
    case outputLimitExceeded(Int)
    case invalidDestination
    case destinationAlreadyExists
    case filesystemFailure

    var errorDescription: String? {
        switch self {
        case .invalidMessage:
            return "The conversation contains an invalid message."
        case .duplicateSequence:
            return "The conversation contains duplicate message ordering information."
        case .messageLimitExceeded(let limit):
            return "The conversation has more than the \(limit) message export limit."
        case .messageTooLarge:
            return "A message is larger than the safe export limit."
        case .totalTextLimitExceeded(let limit):
            return "The conversation text is larger than the \(limit)-byte export limit."
        case .attachmentLimitExceeded(let limit):
            return "The conversation has more than the \(limit) attachment metadata limit."
        case .invalidAttachmentMetadata:
            return "The conversation contains invalid attachment metadata."
        case .outputLimitExceeded(let limit):
            return "The rendered export is larger than the \(limit)-byte limit."
        case .invalidDestination:
            return "The export destination is not a safe regular file location."
        case .destinationAlreadyExists:
            return "That export already exists. Choose a different filename."
        case .filesystemFailure:
            return "The conversation export could not be written safely."
        }
    }
}

enum ConversationExporter {
    static func prepare(
        from detail: SessionHistoryDetailSnapshot,
        title: String? = nil,
        attachmentsBySequence: [Int: [ConversationExportAttachmentMetadata]] = [:],
        format: ConversationExportFormat,
        redaction: ConversationExportRedactionOptions = .recommended,
        exportedAt: Date = Date(),
        limits: ConversationExportLimits = .init()
    ) throws -> ConversationExportArtifact {
        let loadedSequences = Set(detail.transcript.messages.map(\.sequence))
        guard attachmentsBySequence.keys.allSatisfy(loadedSequences.contains) else {
            throw ConversationExportError.invalidAttachmentMetadata
        }
        let messages = detail.transcript.messages.map {
            ConversationExportMessage(
                transcript: $0,
                attachments: attachmentsBySequence[$0.sequence] ?? []
            )
        }
        let route: ConversationExportRoute?
        switch detail.route {
        case .available(let metadata): route = ConversationExportRoute(metadata)
        case .unavailable: route = nil
        }
        return try prepare(
            sessionID: detail.sessionID,
            title: title,
            messages: messages,
            route: route,
            routeWasUnavailable: detail.route == .unavailable,
            sourceWasPartial: detail.transcript.olderBeforeSequence != nil,
            format: format,
            redaction: redaction,
            exportedAt: exportedAt,
            limits: limits
        )
    }

    static func prepare(
        session: HarnessConversationSession,
        boundary: DataBoundary,
        title: String? = nil,
        providerName: String? = nil,
        modelName: String? = nil,
        messages: [ConversationExportMessage],
        sourceWasPartial: Bool = false,
        format: ConversationExportFormat,
        redaction: ConversationExportRedactionOptions = .recommended,
        exportedAt: Date = Date(),
        limits: ConversationExportLimits = .init()
    ) throws -> ConversationExportArtifact {
        try prepare(
            sessionID: session.id,
            title: title,
            messages: messages,
            route: ConversationExportRoute(
                selection: session.selection,
                boundary: boundary,
                providerName: providerName,
                modelName: modelName
            ),
            routeWasUnavailable: false,
            sourceWasPartial: sourceWasPartial,
            format: format,
            redaction: redaction,
            exportedAt: exportedAt,
            limits: limits
        )
    }

    @discardableResult
    static func write(_ artifact: ConversationExportArtifact, to destination: URL) throws -> URL {
        guard destination.isFileURL,
              destination.path.hasPrefix("/"),
              destination.pathExtension.lowercased() == artifact.format.pathExtension,
              ConversationExportFilename.isSafeDestinationBasename(destination.lastPathComponent) else {
            throw ConversationExportError.invalidDestination
        }

        let parent = destination.deletingLastPathComponent().standardizedFileURL
        var parentBeforeOpen = stat()
        guard lstat(parent.path, &parentBeforeOpen) == 0,
              (parentBeforeOpen.st_mode & S_IFMT) == S_IFDIR else {
            throw ConversationExportError.invalidDestination
        }
        let parentDescriptor = Darwin.open(
            parent.path,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard parentDescriptor >= 0 else { throw ConversationExportError.invalidDestination }
        defer { Darwin.close(parentDescriptor) }

        var parentAfterOpen = stat()
        guard fstat(parentDescriptor, &parentAfterOpen) == 0,
              parentAfterOpen.st_dev == parentBeforeOpen.st_dev,
              parentAfterOpen.st_ino == parentBeforeOpen.st_ino else {
            throw ConversationExportError.invalidDestination
        }

        var existing = stat()
        if fstatat(parentDescriptor, destination.lastPathComponent, &existing, AT_SYMLINK_NOFOLLOW) == 0 {
            throw ConversationExportError.destinationAlreadyExists
        }
        guard errno == ENOENT else { throw ConversationExportError.invalidDestination }

        let temporaryName = ".local-harness-export-\(UUID().uuidString.lowercased()).tmp"
        let descriptor = openat(
            parentDescriptor,
            temporaryName,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            mode_t(0o600)
        )
        guard descriptor >= 0 else { throw ConversationExportError.filesystemFailure }
        var temporaryExists = true
        defer {
            Darwin.close(descriptor)
            if temporaryExists { unlinkat(parentDescriptor, temporaryName, 0) }
        }

        do {
            try writeAll(artifact.data, to: descriptor)
            guard fchmod(descriptor, mode_t(0o600)) == 0, fsync(descriptor) == 0 else {
                throw ConversationExportError.filesystemFailure
            }
            guard linkat(
                parentDescriptor,
                temporaryName,
                parentDescriptor,
                destination.lastPathComponent,
                0
            ) == 0 else {
                if errno == EEXIST { throw ConversationExportError.destinationAlreadyExists }
                throw ConversationExportError.filesystemFailure
            }
            if unlinkat(parentDescriptor, temporaryName, 0) == 0 {
                temporaryExists = false
            }
            _ = fsync(parentDescriptor)
            return destination.standardizedFileURL
        } catch let error as ConversationExportError {
            throw error
        } catch {
            throw ConversationExportError.filesystemFailure
        }
    }

    private static func prepare(
        sessionID: HarnessSessionID,
        title: String?,
        messages: [ConversationExportMessage],
        route: ConversationExportRoute?,
        routeWasUnavailable: Bool,
        sourceWasPartial: Bool,
        format: ConversationExportFormat,
        redaction: ConversationExportRedactionOptions,
        exportedAt: Date,
        limits: ConversationExportLimits
    ) throws -> ConversationExportArtifact {
        guard ConversationExportSafeText.validDate(exportedAt) else {
            throw ConversationExportError.invalidMessage
        }
        guard messages.count <= limits.maximumMessages else {
            throw ConversationExportError.messageLimitExceeded(limits.maximumMessages)
        }

        let ordered = messages.sorted { lhs, rhs in lhs.sequence < rhs.sequence }
        var previousSequence: Int?
        var projectedMessages: [ConversationExportPayload.Message] = []
        projectedMessages.reserveCapacity(ordered.count)
        var totalTextBytes = 0
        var totalAttachments = 0

        for message in ordered {
            guard message.sequence >= 0, ConversationExportSafeText.validDate(message.date) else {
                throw ConversationExportError.invalidMessage
            }
            if previousSequence == message.sequence {
                throw ConversationExportError.duplicateSequence(message.sequence)
            }
            previousSequence = message.sequence

            guard message.text.count <= limits.maximumMessageCharacters,
                  message.text.utf8.count <= limits.maximumMessageUTF8Bytes else {
                throw ConversationExportError.messageTooLarge(sequence: message.sequence)
            }
            let sanitized = ConversationExportSafeText.multiline(message.text)
            let redactedText: String
            switch redaction.text {
            case .none: redactedText = sanitized
            case .detectedSecrets: redactedText = ConversationExportSecretRedactor.redact(sanitized)
            case .allContent: redactedText = "[Message content redacted]"
            }
            let (nextTotal, overflow) = totalTextBytes.addingReportingOverflow(redactedText.utf8.count)
            guard !overflow, nextTotal <= limits.maximumTotalTextBytes else {
                throw ConversationExportError.totalTextLimitExceeded(limits.maximumTotalTextBytes)
            }
            totalTextBytes = nextTotal

            let (nextAttachmentTotal, attachmentOverflow) = totalAttachments.addingReportingOverflow(message.attachments.count)
            guard !attachmentOverflow, nextAttachmentTotal <= limits.maximumAttachments else {
                throw ConversationExportError.attachmentLimitExceeded(limits.maximumAttachments)
            }
            totalAttachments = nextAttachmentTotal
            let attachments = try message.attachments.map {
                try validatedAttachment($0, redaction: redaction, limits: limits)
            }

            let source: ConversationExportPayload.Source?
            if redaction.redactRouteMetadata || message.source == nil {
                source = nil
            } else if let value = message.source {
                source = ConversationExportPayload.Source(
                    provider: redactedMetadata(value.route.provider.rawValue, limit: 200, redaction: redaction),
                    model: redactedMetadata(value.route.model.rawValue, limit: 300, redaction: redaction),
                    boundary: value.boundary.rawValue
                )
            } else {
                source = nil
            }
            projectedMessages.append(ConversationExportPayload.Message(
                sequence: message.sequence,
                role: message.role.rawValue,
                timestamp: redaction.redactTimestamps ? nil : message.date,
                content: redactedText,
                interrupted: message.interrupted,
                source: source,
                attachments: attachments
            ))
        }

        let safeTitle: String?
        if redaction.redactTitle {
            safeTitle = nil
        } else {
            safeTitle = title.map { redactedMetadata($0, limit: 240, redaction: redaction) }
                .flatMap { $0.isEmpty ? nil : $0 }
        }
        let payloadRoute: ConversationExportPayload.Route?
        if redaction.redactRouteMetadata || route == nil {
            payloadRoute = nil
        } else if let route {
            payloadRoute = ConversationExportPayload.Route(
                providerID: redactedMetadata(route.providerID.rawValue, limit: 200, redaction: redaction),
                modelID: redactedMetadata(route.modelID.rawValue, limit: 300, redaction: redaction),
                providerName: redactedMetadata(route.providerName, limit: 200, redaction: redaction),
                modelName: redactedMetadata(route.modelName, limit: 300, redaction: redaction),
                reasoningEffort: route.reasoningEffort.map {
                    redactedMetadata($0, limit: 100, redaction: redaction)
                },
                boundary: route.boundary.rawValue,
                routable: route.routable
            )
        } else {
            payloadRoute = nil
        }
        let routeStatus: String
        if routeWasUnavailable || route == nil { routeStatus = "unavailable" }
        else if redaction.redactRouteMetadata { routeStatus = "redacted" }
        else { routeStatus = "available" }

        let payload = ConversationExportPayload(
            schemaVersion: 1,
            exportedAt: exportedAt,
            title: safeTitle,
            sessionIdentifier: redaction.redactSessionIdentifier
                ? nil
                : ConversationExportSafeText.inline(sessionID.rawValue, limit: 500),
            sessionIdentifierRedacted: redaction.redactSessionIdentifier,
            sourceWasPartial: sourceWasPartial,
            routeStatus: routeStatus,
            route: payloadRoute,
            redaction: redaction,
            messages: projectedMessages
        )

        let data: Data
        switch format {
        case .json:
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
            data = try encoder.encode(payload)
        case .markdown:
            data = Data(ConversationExportMarkdown.render(payload).utf8)
        }
        guard data.count <= limits.maximumOutputBytes else {
            throw ConversationExportError.outputLimitExceeded(limits.maximumOutputBytes)
        }

        let filename = ConversationExportFilename.suggested(
            title: safeTitle,
            latestMessageDate: redaction.redactTimestamps ? nil : ordered.last?.date,
            format: format
        )
        return ConversationExportArtifact(
            data: data,
            suggestedFilename: filename,
            contentType: format.contentType,
            format: format,
            messageCount: projectedMessages.count,
            attachmentCount: totalAttachments,
            sourceWasPartial: sourceWasPartial,
            redaction: redaction
        )
    }

    private static func redactedMetadata(
        _ value: String,
        limit: Int,
        redaction: ConversationExportRedactionOptions
    ) -> String {
        let safe = ConversationExportSafeText.inline(value, limit: limit)
        guard redaction.text == .detectedSecrets else { return safe }
        return ConversationExportSecretRedactor.redact(safe)
    }

    private static func validatedAttachment(
        _ value: ConversationExportAttachmentMetadata,
        redaction: ConversationExportRedactionOptions,
        limits: ConversationExportLimits
    ) throws -> ConversationExportPayload.Attachment {
        if let byteCount = value.byteCount, byteCount < 0 {
            throw ConversationExportError.invalidAttachmentMetadata
        }
        let mediaType: String?
        if let value = value.mediaType {
            guard ConversationExportSafeText.validMediaType(value) else {
                throw ConversationExportError.invalidAttachmentMetadata
            }
            mediaType = value.lowercased()
        } else {
            mediaType = nil
        }
        let digest: String?
        if let value = value.sha256 {
            guard value.utf8.count == 64,
                  value.unicodeScalars.allSatisfy({ scalar in
                      (48...57).contains(scalar.value)
                          || (65...70).contains(scalar.value)
                          || (97...102).contains(scalar.value)
                  }) else {
                throw ConversationExportError.invalidAttachmentMetadata
            }
            digest = redaction.redactAttachmentDigests ? nil : value.lowercased()
        } else {
            digest = nil
        }
        let name: String?
        if redaction.redactAttachmentNames {
            name = nil
        } else if let value = value.name {
            let (maximumNameBytes, byteLimitOverflow) = limits.maximumAttachmentNameCharacters
                .multipliedReportingOverflow(by: 4)
            guard value.count <= limits.maximumAttachmentNameCharacters,
                  !byteLimitOverflow,
                  value.utf8.count <= maximumNameBytes else {
                throw ConversationExportError.invalidAttachmentMetadata
            }
            name = ConversationExportSafeText.attachmentName(value, limit: limits.maximumAttachmentNameCharacters)
        } else {
            name = nil
        }
        return ConversationExportPayload.Attachment(
            kind: value.kind.rawValue,
            name: name,
            nameRedacted: redaction.redactAttachmentNames && value.name != nil,
            nameOmittedForSafety: !redaction.redactAttachmentNames && value.name != nil && name == nil,
            mediaType: mediaType,
            byteCount: value.byteCount,
            sha256: digest,
            digestRedacted: redaction.redactAttachmentDigests && value.sha256 != nil
        )
    }

    private static func writeAll(_ data: Data, to descriptor: Int32) throws {
        try data.withUnsafeBytes { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress else { return }
            var offset = 0
            while offset < rawBuffer.count {
                let result = Darwin.write(
                    descriptor,
                    baseAddress.advanced(by: offset),
                    rawBuffer.count - offset
                )
                if result < 0 {
                    if errno == EINTR { continue }
                    throw ConversationExportError.filesystemFailure
                }
                guard result > 0 else { throw ConversationExportError.filesystemFailure }
                offset += result
            }
        }
    }
}

private struct ConversationExportPayload: Encodable {
    struct Route: Encodable {
        let providerID: String
        let modelID: String
        let providerName: String
        let modelName: String
        let reasoningEffort: String?
        let boundary: String
        let routable: Bool
    }

    struct Source: Encodable {
        let provider: String
        let model: String
        let boundary: String
    }

    struct Attachment: Encodable {
        let kind: String
        let name: String?
        let nameRedacted: Bool
        let nameOmittedForSafety: Bool
        let mediaType: String?
        let byteCount: Int64?
        let sha256: String?
        let digestRedacted: Bool
    }

    struct Message: Encodable {
        let sequence: Int
        let role: String
        let timestamp: Date?
        let content: String
        let interrupted: Bool
        let source: Source?
        let attachments: [Attachment]
    }

    let schemaVersion: Int
    let exportedAt: Date
    let title: String?
    let sessionIdentifier: String?
    let sessionIdentifierRedacted: Bool
    let sourceWasPartial: Bool
    let routeStatus: String
    let route: Route?
    let redaction: ConversationExportRedactionOptions
    let messages: [Message]
}

private enum ConversationExportMarkdown {
    static func render(_ payload: ConversationExportPayload) -> String {
        var output: [String] = [
            "# \(ProductBrand.displayName) conversation",
            "",
            "This export contains message text and reviewed metadata only. Attachment bytes and local paths are never embedded.",
            "",
            "- Exported: \(code(iso8601(payload.exportedAt)))",
            "- Source: \(payload.sourceWasPartial ? "partial transcript" : "complete loaded transcript")",
            "- Session identifier: \(payload.sessionIdentifier.map(code) ?? (payload.sessionIdentifierRedacted ? "redacted" : "unavailable"))",
            "- Route: \(routeDescription(payload))",
            "- Text redaction: \(code(payload.redaction.text.rawValue))"
        ]
        if let title = payload.title { output.append("- Title: \(code(title))") }
        if payload.redaction.redactTitle { output.append("- Title: redacted") }
        output.append(contentsOf: ["", "---", ""])

        for message in payload.messages {
            output.append("## \(message.role == SessionTranscriptRole.user.rawValue ? "You" : "Assistant")")
            output.append("")
            output.append("- Sequence: \(message.sequence)")
            if let timestamp = message.timestamp { output.append("- Time: \(code(iso8601(timestamp)))") }
            if message.interrupted { output.append("- Status: interrupted") }
            if let source = message.source {
                output.append("- Source: \(code(source.provider)) / \(code(source.model)) · \(code(source.boundary))")
            }
            output.append("")
            output.append(fenced(message.content))
            if !message.attachments.isEmpty {
                output.append("")
                output.append("Attachments (metadata only):")
                output.append("")
                for attachment in message.attachments {
                    var facts = [attachment.kind]
                    if let name = attachment.name { facts.append("name \(code(name))") }
                    else if attachment.nameRedacted { facts.append("name redacted") }
                    else if attachment.nameOmittedForSafety { facts.append("unsafe name omitted") }
                    if let mediaType = attachment.mediaType { facts.append("type \(code(mediaType))") }
                    if let byteCount = attachment.byteCount { facts.append("\(byteCount) bytes") }
                    if let digest = attachment.sha256 { facts.append("SHA-256 \(code(digest))") }
                    else if attachment.digestRedacted { facts.append("digest redacted") }
                    output.append("- " + facts.joined(separator: "; "))
                }
            }
            output.append(contentsOf: ["", "---", ""])
        }
        return output.joined(separator: "\n") + "\n"
    }

    private static func routeDescription(_ payload: ConversationExportPayload) -> String {
        guard let route = payload.route else { return payload.routeStatus }
        return "\(code(route.providerName)) / \(code(route.modelName)) · \(code(route.boundary))"
    }

    private static func fenced(_ value: String) -> String {
        let backticks = longestRun(of: "`", in: value)
        let tildes = longestRun(of: "~", in: value)
        let character: Character = backticks <= tildes ? "`" : "~"
        let length = max(3, min(backticks, tildes) + 1)
        let fence = String(repeating: String(character), count: length)
        return fence + "\n" + value + (value.hasSuffix("\n") ? "" : "\n") + fence
    }

    private static func longestRun(of target: Character, in value: String) -> Int {
        var longest = 0
        var current = 0
        for character in value {
            if character == target {
                current += 1
                longest = max(longest, current)
            } else {
                current = 0
            }
        }
        return longest
    }

    private static func code(_ value: String) -> String {
        let run = longestRun(of: "`", in: value)
        let delimiter = String(repeating: "`", count: max(1, run + 1))
        return delimiter + " " + value + " " + delimiter
    }

    private static func iso8601(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        return formatter.string(from: date)
    }
}

enum ConversationExportFilename {
    static func suggested(
        title: String?,
        latestMessageDate: Date?,
        format: ConversationExportFormat
    ) -> String {
        let slug = asciiSlug(title ?? "")
        let label = slug.isEmpty ? "conversation" : String(slug.prefix(48))
        let timestamp = latestMessageDate.map(utcTimestamp) ?? "undated"
        return "fulmar-\(label)-\(timestamp).\(format.pathExtension)"
    }

    static func isSafeDestinationBasename(_ value: String) -> Bool {
        guard !value.isEmpty,
              value != ".",
              value != "..",
              !value.hasPrefix("."),
              !value.hasSuffix("."),
              !value.hasSuffix(" "),
              value.utf8.count <= 240,
              Array(value.utf8) == Array(value.precomposedStringWithCanonicalMapping.utf8) else { return false }
        return value.unicodeScalars.allSatisfy { scalar in
            scalar != "/" && scalar != "\\" && scalar != ":"
                && !CharacterSet.controlCharacters.contains(scalar)
                && !ConversationExportSafeText.isBidirectionalControl(scalar.value)
        }
    }

    private static func asciiSlug(_ value: String) -> String {
        let folded = value.folding(options: [.diacriticInsensitive, .widthInsensitive], locale: Locale(identifier: "en_US_POSIX"))
        var result = ""
        var pendingSeparator = false
        for scalar in folded.lowercased().unicodeScalars {
            let isLetter = (65...90).contains(scalar.value) || (97...122).contains(scalar.value)
            let isNumber = (48...57).contains(scalar.value)
            if isLetter || isNumber {
                if pendingSeparator, !result.isEmpty { result.append("-") }
                result.unicodeScalars.append(scalar)
                pendingSeparator = false
            } else {
                pendingSeparator = true
            }
        }
        return result
    }

    private static func utcTimestamp(_ date: Date) -> String {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0)!
        let components = calendar.dateComponents([.year, .month, .day, .hour, .minute, .second], from: date)
        return String(
            format: "%04d%02d%02d-%02d%02d%02d",
            locale: Locale(identifier: "en_US_POSIX"),
            components.year ?? 0,
            components.month ?? 0,
            components.day ?? 0,
            components.hour ?? 0,
            components.minute ?? 0,
            components.second ?? 0
        )
    }
}

private enum ConversationExportSafeText {
    static func validDate(_ value: Date) -> Bool {
        let seconds = value.timeIntervalSince1970
        // The rendered formats use the RFC 3339 four-digit year range.
        return seconds.isFinite
            && seconds >= -62_135_769_600
            && seconds <= 253_402_300_799
    }

    static func inline(_ value: String, limit: Int) -> String {
        let flattened = sanitized(value)
            .split(whereSeparator: \Character.isWhitespace)
            .joined(separator: " ")
        guard flattened.count > limit else { return flattened }
        return String(flattened.prefix(max(0, limit - 1))) + "…"
    }

    static func multiline(_ value: String) -> String { sanitized(value) }

    static func attachmentName(_ value: String, limit: Int) -> String? {
        let normalized = inline(value, limit: limit)
        guard !normalized.isEmpty,
              normalized != ".",
              normalized != "..",
              !normalized.contains("/"),
              !normalized.contains("\\"),
              !normalized.hasPrefix("."),
              !normalized.hasSuffix("."),
              !normalized.hasSuffix(" ") else { return nil }
        return normalized
    }

    static func validMediaType(_ value: String) -> Bool {
        guard value.count >= 3, value.count <= 127,
              value.filter({ $0 == "/" }).count == 1 else { return false }
        return value.unicodeScalars.allSatisfy { scalar in
            let isAlphaNumeric = (48...57).contains(scalar.value)
                || (65...90).contains(scalar.value)
                || (97...122).contains(scalar.value)
            return isAlphaNumeric || "!#$&^_.+-/".unicodeScalars.contains(scalar)
        }
    }

    static func isBidirectionalControl(_ value: UInt32) -> Bool {
        value == 0x061C || value == 0x200E || value == 0x200F
            || (0x202A...0x202E).contains(value)
            || (0x2066...0x2069).contains(value)
    }

    private static func sanitized(_ value: String) -> String {
        let normalized = value.replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
        var result = ""
        result.reserveCapacity(min(normalized.utf8.count, 100_000))
        for scalar in normalized.unicodeScalars {
            if scalar == "\n" || scalar == "\t" {
                result.unicodeScalars.append(scalar)
            } else if !CharacterSet.controlCharacters.contains(scalar),
                      !isBidirectionalControl(scalar.value) {
                result.unicodeScalars.append(scalar)
            }
        }
        return result
    }
}

private enum ConversationExportSecretRedactor {
    private struct Pattern: @unchecked Sendable {
        let expression: NSRegularExpression
        let template: String

        init(_ pattern: String, options: NSRegularExpression.Options = [], template: String) {
            // Constants are covered by unit tests; a programming error should fail at launch,
            // never silently disable an expected privacy rule.
            expression = try! NSRegularExpression(pattern: pattern, options: options)
            self.template = template
        }
    }

    private static let patterns: [Pattern] = [
        Pattern(
            #"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----[\s\S]*?-----END(?: [A-Z0-9]+)? PRIVATE KEY-----"#,
            options: [.caseInsensitive],
            template: "[REDACTED PRIVATE KEY]"
        ),
        Pattern(#"\b(https?://)[^/\s:@]+:[^/\s@]+@"#, options: [.caseInsensitive], template: "$1[REDACTED]@"),
        Pattern(#"\b(Bearer)\s+[A-Za-z0-9._~+/=-]{8,}"#, options: [.caseInsensitive], template: "$1 [REDACTED]"),
        Pattern(
            #"\b(api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|secret|client[_-]?secret)(\s*[:=]\s*)([\"'])[^\"'\r\n]{1,4096}\3"#,
            options: [.caseInsensitive],
            template: "$1$2[REDACTED]"
        ),
        Pattern(
            #"\b(api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|secret|client[_-]?secret)(\s*[:=]\s*)[^\s\"',;]{3,}"#,
            options: [.caseInsensitive],
            template: "$1$2[REDACTED]"
        ),
        Pattern(#"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"#, template: "[REDACTED JWT]"),
        Pattern(#"\bAKIA[A-Z0-9]{16}\b"#, template: "[REDACTED ACCESS KEY]"),
        Pattern(#"\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{20,}\b"#, options: [.caseInsensitive], template: "[REDACTED TOKEN]"),
        Pattern(#"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"#, options: [.caseInsensitive], template: "[REDACTED TOKEN]"),
        Pattern(#"\b(?:hf_[A-Za-z0-9]{20,}|AIza[A-Za-z0-9_-]{30,})\b"#, template: "[REDACTED API KEY]"),
        Pattern(#"\b(?:sk|rk|api)[-_][A-Za-z0-9_-]{12,}\b"#, options: [.caseInsensitive], template: "[REDACTED API KEY]")
    ]

    static func redact(_ value: String) -> String {
        patterns.reduce(value) { partial, pattern in
            let range = NSRange(partial.startIndex..<partial.endIndex, in: partial)
            return pattern.expression.stringByReplacingMatches(
                in: partial,
                range: range,
                withTemplate: pattern.template
            )
        }
    }
}

private enum ConversationExportBase64 {
    static func decodedByteCount(_ value: String) -> Int? {
        var meaningful = 0
        var padding = 0
        var sawPadding = false
        for scalar in value.unicodeScalars {
            if CharacterSet.whitespacesAndNewlines.contains(scalar) { continue }
            if scalar == "=" {
                sawPadding = true
                padding += 1
                guard padding <= 2 else { return nil }
            } else {
                let isAlphaNumeric = (48...57).contains(scalar.value)
                    || (65...90).contains(scalar.value)
                    || (97...122).contains(scalar.value)
                guard !sawPadding, isAlphaNumeric || scalar == "+" || scalar == "/" else { return nil }
            }
            meaningful += 1
        }
        guard meaningful > 0, meaningful.isMultiple(of: 4) else { return nil }
        let groups = meaningful / 4
        let (bytes, overflow) = groups.multipliedReportingOverflow(by: 3)
        guard !overflow, bytes >= padding else { return nil }
        return bytes - padding
    }
}
