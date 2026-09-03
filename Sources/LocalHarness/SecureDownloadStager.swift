import CryptoKit
import Darwin
import Foundation
import UniformTypeIdentifiers

enum DownloadSafetyCategory: String, Codable, Equatable {
    case passiveDocument
    case unknown
    case archive
    case activeWebContent
    case script
    case installer
    case executable
    case suspicious

    var displayName: String {
        switch self {
        case .passiveDocument: return "Previewable document"
        case .unknown: return "Unknown content"
        case .archive: return "Archive"
        case .activeWebContent: return "Active web content"
        case .script: return "Script or source code"
        case .installer: return "Installer or disk image"
        case .executable: return "Executable software"
        case .suspicious: return "Content mismatch"
        }
    }
}

struct DownloadContentAssessment: Equatable {
    let detectedMIMEType: String?
    let typeIdentifier: String?
    let category: DownloadSafetyCategory
    let allowsManualPreview: Bool
    let warnings: [String]
}

struct StagedDownloadArtifact: Equatable {
    let fileURL: URL
    let displayFilename: String
    let byteCount: Int64
    let sha256: String
    let reportedMIMEType: String?
    let detectedMIMEType: String?
    let typeIdentifier: String?
    let category: DownloadSafetyCategory
    let allowsManualPreview: Bool
    let warnings: [String]
    let quarantineApplied: Bool
}

enum StagedDownloadUserAction: Equatable {
    case saved
    case previewRequested
}

struct PendingDownloadDestination: Equatable {
    let transferDirectory: URL
    let incomingURL: URL
    let displayFilename: String
    let reportedMIMEType: String?
    let sourceOrigin: String?
}

enum IncomingDownloadInspection: Equatable {
    case notCreated
    case inProgress(byteCount: Int64)
    case rejected(String)
}

enum SecureDownloadError: LocalizedError, Equatable {
    case stagingUnavailable(String)
    case expectedSizeExceedsLimit(limit: Int64)
    case sizeLimitExceeded(limit: Int64)
    case unsafeFilesystemObject
    case unsafeFilename
    case destinationAlreadyExists
    case contentChanged
    case quarantineFailed

    var errorDescription: String? {
        switch self {
        case .stagingUnavailable(let detail): return "Secure download staging is unavailable: \(detail)"
        case .expectedSizeExceedsLimit(let limit): return "The server reports a file larger than the \(ByteCountFormatter.string(fromByteCount: limit, countStyle: .file)) download limit."
        case .sizeLimitExceeded(let limit): return "The download exceeded the \(ByteCountFormatter.string(fromByteCount: limit, countStyle: .file)) limit and was removed."
        case .unsafeFilesystemObject: return "The downloaded item was replaced by an unsafe file-system object and was removed."
        case .unsafeFilename: return "The chosen filename contains hidden, directional, control, or path characters. Choose a plain filename."
        case .destinationAlreadyExists: return "That destination already exists. Choose a different filename."
        case .contentChanged: return "The staged download changed after validation and was not saved."
        case .quarantineFailed: return "macOS quarantine metadata could not be applied, so the download was removed."
        }
    }
}

enum DownloadContentInspector {
    private enum SignatureKind: String {
        case empty, pdf, png, jpeg, gif, webp, zip, gzip, bzip2, xz, sevenZip, rar
        case macho, elf, windowsExecutable, script, html, svg, json, text, unknown

        var mimeType: String? {
            switch self {
            case .pdf: return "application/pdf"
            case .png: return "image/png"
            case .jpeg: return "image/jpeg"
            case .gif: return "image/gif"
            case .webp: return "image/webp"
            case .zip: return "application/zip"
            case .gzip: return "application/gzip"
            case .bzip2: return "application/x-bzip2"
            case .xz: return "application/x-xz"
            case .sevenZip: return "application/x-7z-compressed"
            case .rar: return "application/vnd.rar"
            case .html: return "text/html"
            case .svg: return "image/svg+xml"
            case .json: return "application/json"
            case .text, .script: return "text/plain"
            case .macho, .elf, .windowsExecutable: return "application/x-executable"
            case .empty, .unknown: return nil
            }
        }
    }

    private static let executableExtensions: Set<String> = [
        "action", "app", "bin", "bundle", "class", "com", "component", "driver", "dylib", "exe",
        "framework", "kext", "mdimporter", "out", "plugin", "prefpane", "qlgenerator", "saver", "service",
        "so", "tool", "wasm", "xpc"
    ]
    private static let installerExtensions: Set<String> = [
        "dist", "distribution", "dmg", "img", "ipa", "iso", "mobileconfig", "mobileprovision", "mpkg", "pkg", "provisionprofile"
    ]
    private static let scriptExtensions: Set<String> = [
        "applescript", "bat", "bash", "cjs", "cmd", "command", "expect", "fish", "groovy", "js", "jsx",
        "lua", "mjs", "php", "pl", "ps1", "py", "r", "rb", "scpt", "sh", "swift", "tcl", "ts", "tsx", "vbs", "zsh"
    ]
    private static let archiveExtensions: Set<String> = [
        "7z", "bz", "bz2", "cab", "cpio", "gz", "jar", "lz", "lz4", "rar", "tar", "tgz", "txz", "xz", "zip", "zst"
    ]
    private static let activeWebExtensions: Set<String> = ["htm", "html", "mht", "mhtml", "svg", "webarchive", "webloc", "xhtml"]
    private static let passiveZIPContainers: Set<String> = ["docx", "epub", "key", "numbers", "pages", "pptx", "xlsx"]
    private static let passiveImageExtensions: Set<String> = ["gif", "jpeg", "jpg", "png", "webp"]
    private static let genericMIMETypes: Set<String> = ["application/octet-stream", "binary/octet-stream"]

    static func assess(filename: String, reportedMIMEType: String?, prefix: Data) -> DownloadContentAssessment {
        let ext = (filename as NSString).pathExtension.lowercased()
        let normalizedReported = normalizeMIME(reportedMIMEType)
        let signature = signatureKind(prefix)
        let type = ext.isEmpty ? nil : UTType(filenameExtension: ext)
        var warnings: [String] = []

        let extensionCategory = categoryForExtension(ext, type: type)
        let signatureCategory = categoryForSignature(signature, extension: ext)
        let mimeCategory = categoryForMIME(normalizedReported)

        if isConcrete(normalizedReported), !mime(normalizedReported, isCompatibleWith: signature, extension: ext) {
            warnings.append("The server's MIME type does not match the downloaded content.")
        }
        if extensionCategory == .passiveDocument, isDangerous(signatureCategory) {
            warnings.append("The filename extension disguises active or executable content.")
        } else if signature == .pdf, !ext.isEmpty, ext != "pdf" {
            warnings.append("The filename extension does not match the PDF content.")
        } else if [.png, .jpeg, .gif, .webp].contains(signature), !imageExtension(ext, matches: signature) {
            warnings.append("The filename extension does not match the image content.")
        }
        if !isDangerous(signatureCategory) {
            if ext == "pdf", signature != .pdf, signature != .empty {
                warnings.append("The PDF filename does not match the downloaded content.")
            } else if passiveImageExtensions.contains(ext), !imageExtension(ext, matches: signature), signature != .empty {
                warnings.append("The image filename does not match the downloaded content.")
            } else if ext == "json", signature != .json, signature != .empty {
                warnings.append("The JSON filename does not match the downloaded content.")
            } else if passiveZIPContainers.contains(ext), signature != .zip, signature != .empty {
                warnings.append("The document container does not match the downloaded content.")
            }
        }

        var category = resolvedCategory(
            extensionCategory: extensionCategory,
            signatureCategory: signatureCategory,
            mimeCategory: mimeCategory
        )
        if !warnings.isEmpty && category == .passiveDocument { category = .suspicious }
        if warnings.contains(where: { $0.contains("disguises") }) { category = .suspicious }

        let detectedMIME = signature.mimeType ?? normalizedReported
        let allowsPreview = category == .passiveDocument && warnings.isEmpty && signature != .empty
        return DownloadContentAssessment(
            detectedMIMEType: detectedMIME,
            typeIdentifier: type?.identifier,
            category: category,
            allowsManualPreview: allowsPreview,
            warnings: warnings
        )
    }

    private static func normalizeMIME(_ value: String?) -> String? {
        guard let raw = value?.split(separator: ";", maxSplits: 1).first else { return nil }
        let normalized = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return normalized.isEmpty ? nil : normalized
    }

    private static func signatureKind(_ data: Data) -> SignatureKind {
        let bytes = [UInt8](data.prefix(8))
        if data.isEmpty { return .empty }
        if data.starts(with: Data("%PDF-".utf8)) { return .pdf }
        if bytes.starts(with: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) { return .png }
        if bytes.starts(with: [0xFF, 0xD8, 0xFF]) { return .jpeg }
        if data.starts(with: Data("GIF87a".utf8)) || data.starts(with: Data("GIF89a".utf8)) { return .gif }
        if data.count >= 12,
           data.prefix(4) == Data("RIFF".utf8),
           data.dropFirst(8).prefix(4) == Data("WEBP".utf8) { return .webp }
        if bytes.starts(with: [0x50, 0x4B, 0x03, 0x04]) || bytes.starts(with: [0x50, 0x4B, 0x05, 0x06]) || bytes.starts(with: [0x50, 0x4B, 0x07, 0x08]) { return .zip }
        if bytes.starts(with: [0x1F, 0x8B]) { return .gzip }
        if data.starts(with: Data("BZh".utf8)) { return .bzip2 }
        if bytes.starts(with: [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]) { return .xz }
        if bytes.starts(with: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) { return .sevenZip }
        if bytes.starts(with: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07]) { return .rar }
        if isMachO(bytes) { return .macho }
        if bytes.starts(with: [0x7F, 0x45, 0x4C, 0x46]) { return .elf }
        if bytes.starts(with: [0x4D, 0x5A]) { return .windowsExecutable }

        let prefix = String(decoding: data.prefix(16_384), as: UTF8.self)
        let trimmed = prefix.trimmingCharacters(in: .whitespacesAndNewlines)
        let lower = trimmed.lowercased()
        if trimmed.hasPrefix("#!") { return .script }
        if let first = trimmed.first, first == "{" || first == "[",
           (try? JSONSerialization.jsonObject(with: Data(trimmed.utf8))) != nil { return .json }
        if lower.contains("<svg") { return .svg }
        let activeHTMLMarkers = ["<!doctype html", "<html", "<script", "<iframe", "<object", "<embed", "<meta http-equiv", "javascript:"]
        if activeHTMLMarkers.contains(where: lower.contains) { return .html }
        if looksLikeText(data) { return .text }
        return .unknown
    }

    private static func looksLikeText(_ data: Data) -> Bool {
        let sample = data.prefix(16_384)
        if sample.contains(0) { return false }
        var printable = 0
        for byte in sample {
            if byte == 0x09 || byte == 0x0A || byte == 0x0D || byte >= 0x20 { printable += 1 }
        }
        return sample.isEmpty || Double(printable) / Double(sample.count) >= 0.92
    }

    private static func isMachO(_ bytes: [UInt8]) -> Bool {
        guard bytes.count >= 4 else { return false }
        let magic = Array(bytes.prefix(4))
        return magic == [0xFE, 0xED, 0xFA, 0xCE]
            || magic == [0xCE, 0xFA, 0xED, 0xFE]
            || magic == [0xFE, 0xED, 0xFA, 0xCF]
            || magic == [0xCF, 0xFA, 0xED, 0xFE]
            || magic == [0xCA, 0xFE, 0xBA, 0xBE]
            || magic == [0xBE, 0xBA, 0xFE, 0xCA]
    }

    private static func categoryForExtension(_ ext: String, type: UTType?) -> DownloadSafetyCategory {
        if executableExtensions.contains(ext) || type?.conforms(to: .executable) == true { return .executable }
        if installerExtensions.contains(ext) { return .installer }
        if scriptExtensions.contains(ext) || type?.conforms(to: .sourceCode) == true { return .script }
        if activeWebExtensions.contains(ext) || type?.conforms(to: .html) == true { return .activeWebContent }
        if passiveZIPContainers.contains(ext) { return .passiveDocument }
        if archiveExtensions.contains(ext) || type?.conforms(to: .archive) == true { return .archive }
        if type?.conforms(to: .pdf) == true || type?.conforms(to: .image) == true || type?.conforms(to: .plainText) == true || type?.conforms(to: .json) == true {
            return .passiveDocument
        }
        return ext.isEmpty ? .unknown : .passiveDocument
    }

    private static func categoryForSignature(_ signature: SignatureKind, extension ext: String) -> DownloadSafetyCategory {
        switch signature {
        case .macho, .elf, .windowsExecutable: return .executable
        case .script: return .script
        case .html, .svg: return .activeWebContent
        case .zip where passiveZIPContainers.contains(ext): return .passiveDocument
        case .zip, .gzip, .bzip2, .xz, .sevenZip, .rar: return .archive
        case .pdf, .png, .jpeg, .gif, .webp, .json, .text: return .passiveDocument
        case .empty, .unknown: return .unknown
        }
    }

    private static func categoryForMIME(_ mime: String?) -> DownloadSafetyCategory {
        guard let mime else { return .unknown }
        if ["text/html", "application/xhtml+xml", "image/svg+xml"].contains(mime) { return .activeWebContent }
        if mime.contains("javascript") || mime.contains("shell") || mime.contains("script")
            || ["application/x-sh", "application/x-csh", "application/x-httpd-php", "text/x-python", "text/x-perl"].contains(mime) { return .script }
        if mime.contains("executable") || mime == "application/x-mach-binary" { return .executable }
        if mime.contains("installer") || mime == "application/x-apple-diskimage" { return .installer }
        if mime.contains("zip") || mime.contains("compressed") || mime.contains("archive") || mime.contains("tar") || mime == "application/gzip" { return .archive }
        if mime.hasPrefix("text/") || mime.hasPrefix("image/") || mime == "application/pdf" || mime == "application/json" { return .passiveDocument }
        return .unknown
    }

    private static func resolvedCategory(
        extensionCategory: DownloadSafetyCategory,
        signatureCategory: DownloadSafetyCategory,
        mimeCategory: DownloadSafetyCategory
    ) -> DownloadSafetyCategory {
        let rank: [DownloadSafetyCategory: Int] = [
            .passiveDocument: 0, .unknown: 1, .archive: 2, .activeWebContent: 3,
            .script: 4, .installer: 5, .executable: 6, .suspicious: 7
        ]
        let dangerous = [extensionCategory, signatureCategory, mimeCategory].filter(isDangerous)
        if let highest = dangerous.max(by: { rank[$0, default: 0] < rank[$1, default: 0] }) { return highest }
        guard extensionCategory == .passiveDocument,
              signatureCategory == .passiveDocument,
              mimeCategory == .passiveDocument || mimeCategory == .unknown else {
            return .unknown
        }
        return .passiveDocument
    }

    private static func isDangerous(_ category: DownloadSafetyCategory) -> Bool {
        [.archive, .activeWebContent, .script, .installer, .executable, .suspicious].contains(category)
    }

    private static func isConcrete(_ mime: String?) -> Bool {
        guard let mime else { return false }
        return !genericMIMETypes.contains(mime)
    }

    private static func mime(_ reported: String?, isCompatibleWith signature: SignatureKind, extension ext: String) -> Bool {
        guard let reported, isConcrete(reported) else { return true }
        if signature == .empty || signature == .unknown { return true }
        switch signature {
        case .pdf: return reported == "application/pdf"
        case .png: return reported == "image/png"
        case .jpeg: return reported == "image/jpeg" || reported == "image/jpg"
        case .gif: return reported == "image/gif"
        case .webp: return reported == "image/webp"
        case .html: return reported == "text/html" || reported == "application/xhtml+xml"
        case .svg: return reported == "image/svg+xml" || reported == "text/xml" || reported == "application/xml"
        case .json: return reported == "application/json" || reported.hasSuffix("+json") || reported == "text/plain"
        case .text, .script: return reported.hasPrefix("text/") || reported.contains("script") || reported.contains("javascript")
        case .zip where passiveZIPContainers.contains(ext): return reported.contains("officedocument") || reported.contains("epub") || reported.contains("zip") || genericMIMETypes.contains(reported)
        case .zip: return reported.contains("zip") || reported.contains("archive")
        case .gzip: return reported == "application/gzip" || reported.contains("gzip")
        case .bzip2: return reported.contains("bzip")
        case .xz: return reported.contains("xz")
        case .sevenZip: return reported.contains("7z")
        case .rar: return reported.contains("rar")
        case .macho, .elf, .windowsExecutable: return reported.contains("executable") || reported.contains("binary") || genericMIMETypes.contains(reported)
        case .empty, .unknown: return true
        }
    }

    private static func imageExtension(_ ext: String, matches signature: SignatureKind) -> Bool {
        switch signature {
        case .png: return ext == "png"
        case .jpeg: return ext == "jpg" || ext == "jpeg"
        case .gif: return ext == "gif"
        case .webp: return ext == "webp"
        default: return false
        }
    }
}

struct SecureDownloadCleanupLimits: Equatable, Sendable {
    var maximumEntries: Int = 20_000
    var maximumDepth: Int = 32
    var duration: TimeInterval = 3

    var isValid: Bool {
        maximumEntries > 0 && maximumEntries <= 100_000
            && maximumDepth > 0 && maximumDepth <= 64
            && duration.isFinite && duration > 0 && duration <= 30
    }
}

enum SecureDownloadCleanupStatus: Equatable, Sendable {
    case completed
    case bounded
    case unsafeEntriesRetained
}

struct SecureDownloadCleanupReport: Equatable, Sendable {
    let status: SecureDownloadCleanupStatus
    let inspectedEntries: Int
    let removedTransfers: Int
}

final class SecureDownloadStager: @unchecked Sendable {
    static let defaultMaximumBytes: Int64 = 512 * 1_024 * 1_024

    let stagingRoot: URL
    let maximumBytes: Int64
    private let fileManager: FileManager
    private let ownershipLock = NSLock()
    private var ownedTransferDirectories: Set<URL> = []

    convenience init(maximumBytes: Int64 = SecureDownloadStager.defaultMaximumBytes) throws {
        let applicationSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        let root = applicationSupport
            .appendingPathComponent("Local Harness", isDirectory: true)
            .appendingPathComponent("Download Staging", isDirectory: true)
        try self.init(stagingRoot: root, maximumBytes: maximumBytes)
    }

    init(stagingRoot: URL, maximumBytes: Int64, fileManager: FileManager = .default) throws {
        guard maximumBytes > 0 else { throw SecureDownloadError.stagingUnavailable("The byte limit is invalid.") }
        self.stagingRoot = stagingRoot.standardizedFileURL
        self.maximumBytes = maximumBytes
        self.fileManager = fileManager
        try Self.preparePrivateDirectory(self.stagingRoot, fileManager: fileManager)
    }

    /// Maintenance is deliberately detached from main-window construction.
    /// All enumeration and recursive deletion remains no-follow and bounded.
    func startMaintenance() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            _ = self?.cleanupStaleTransfers(olderThan: 24 * 60 * 60)
        }
    }

    func prepare(
        suggestedFilename: String,
        reportedMIMEType: String?,
        expectedContentLength: Int64,
        sourceURL: URL?
    ) throws -> PendingDownloadDestination {
        if expectedContentLength > maximumBytes {
            throw SecureDownloadError.expectedSizeExceedsLimit(limit: maximumBytes)
        }
        let directory = try createExclusiveTransferDirectory()
        let incoming = directory.appendingPathComponent("incoming-\(UUID().uuidString).download", isDirectory: false)
        let pending = PendingDownloadDestination(
            transferDirectory: directory,
            incomingURL: incoming,
            displayFilename: DownloadPath.safeFilename(suggestedFilename),
            reportedMIMEType: reportedMIMEType,
            sourceOrigin: Self.safeOrigin(from: sourceURL)
        )
        _ = ownershipLock.withLock { ownedTransferDirectories.insert(directory) }
        return pending
    }

    func inspectIncoming(_ pending: PendingDownloadDestination) -> IncomingDownloadInspection {
        guard owns(pending.transferDirectory), pending.incomingURL.deletingLastPathComponent().standardizedFileURL == pending.transferDirectory.standardizedFileURL else {
            return .rejected("The staging destination escaped its private directory.")
        }
        var status = stat()
        if lstat(pending.incomingURL.path, &status) != 0 {
            return errno == ENOENT ? .notCreated : .rejected("The staging file could not be inspected.")
        }
        guard (status.st_mode & S_IFMT) == S_IFREG, status.st_nlink == 1 else {
            return .rejected("The staging file is not a private regular file.")
        }
        let size = Int64(status.st_size)
        if size > maximumBytes { return .rejected("The download exceeded its byte limit.") }
        return .inProgress(byteCount: size)
    }

    func finalize(_ pending: PendingDownloadDestination) throws -> StagedDownloadArtifact {
        guard owns(pending.transferDirectory), pending.incomingURL.deletingLastPathComponent().standardizedFileURL == pending.transferDirectory.standardizedFileURL else {
            throw SecureDownloadError.unsafeFilesystemObject
        }

        let finalURL = pending.transferDirectory.appendingPathComponent(pending.displayFilename, isDirectory: false)
        var prefix = Data()
        let digestAndSize: (String, Int64)
        do {
            digestAndSize = try copySecurely(
                from: pending.incomingURL,
                to: finalURL,
                expectedDigest: nil,
                quarantineOrigin: pending.sourceOrigin,
                capturePrefix: &prefix
            )
            try fileManager.removeItem(at: pending.incomingURL)
        } catch {
            discard(pending)
            throw error
        }

        let assessment = DownloadContentInspector.assess(
            filename: pending.displayFilename,
            reportedMIMEType: pending.reportedMIMEType,
            prefix: prefix
        )
        let artifact = StagedDownloadArtifact(
            fileURL: finalURL,
            displayFilename: pending.displayFilename,
            byteCount: digestAndSize.1,
            sha256: digestAndSize.0,
            reportedMIMEType: pending.reportedMIMEType,
            detectedMIMEType: assessment.detectedMIMEType,
            typeIdentifier: assessment.typeIdentifier,
            category: assessment.category,
            allowsManualPreview: assessment.allowsManualPreview,
            warnings: assessment.warnings,
            quarantineApplied: true
        )

        do {
            try writeMetadata(for: artifact, sourceOrigin: pending.sourceOrigin, in: pending.transferDirectory)
        } catch {
            discard(pending)
            throw error
        }
        return artifact
    }

    func export(_ artifact: StagedDownloadArtifact, to destination: URL) throws -> StagedDownloadArtifact {
        guard owns(artifact.fileURL.deletingLastPathComponent()) else { throw SecureDownloadError.unsafeFilesystemObject }
        let standardizedDestination = destination.standardizedFileURL
        guard standardizedDestination.lastPathComponent == destination.lastPathComponent,
              !standardizedDestination.lastPathComponent.isEmpty else {
            throw SecureDownloadError.unsafeFilesystemObject
        }
        guard DownloadPath.safeFilename(destination.lastPathComponent) == destination.lastPathComponent else {
            throw SecureDownloadError.unsafeFilename
        }

        var unusedPrefix = Data()
        var createdDestination = false
        do {
            let copied = try copySecurely(
                from: artifact.fileURL,
                to: standardizedDestination,
                expectedDigest: artifact.sha256,
                quarantineOrigin: nil,
                capturePrefix: &unusedPrefix
            )
            createdDestination = true
            guard copied.1 == artifact.byteCount else {
                unlinkSecurely(standardizedDestination)
                createdDestination = false
                throw SecureDownloadError.contentChanged
            }
        } catch {
            if createdDestination { unlinkSecurely(standardizedDestination) }
            throw error
        }

        let exported = StagedDownloadArtifact(
            fileURL: standardizedDestination,
            displayFilename: standardizedDestination.lastPathComponent,
            byteCount: artifact.byteCount,
            sha256: artifact.sha256,
            reportedMIMEType: artifact.reportedMIMEType,
            detectedMIMEType: artifact.detectedMIMEType,
            typeIdentifier: artifact.typeIdentifier,
            category: artifact.category,
            allowsManualPreview: artifact.allowsManualPreview,
            warnings: artifact.warnings,
            quarantineApplied: true
        )
        discardDirectory(artifact.fileURL.deletingLastPathComponent())
        return exported
    }

    func validateForPreview(_ artifact: StagedDownloadArtifact) throws {
        guard artifact.allowsManualPreview,
              owns(artifact.fileURL.deletingLastPathComponent()) else {
            throw SecureDownloadError.unsafeFilesystemObject
        }
        var prefix = Data()
        let observed = try digestSecurely(from: artifact.fileURL, capturePrefix: &prefix)
        guard observed.0 == artifact.sha256, observed.1 == artifact.byteCount else {
            throw SecureDownloadError.contentChanged
        }
        let reassessment = DownloadContentInspector.assess(
            filename: artifact.displayFilename,
            reportedMIMEType: artifact.reportedMIMEType,
            prefix: prefix
        )
        guard reassessment.allowsManualPreview,
              reassessment.category == artifact.category,
              reassessment.detectedMIMEType == artifact.detectedMIMEType,
              reassessment.warnings == artifact.warnings else {
            throw SecureDownloadError.contentChanged
        }
    }

    func discard(_ pending: PendingDownloadDestination) {
        discardDirectory(pending.transferDirectory)
    }

    func discard(_ artifact: StagedDownloadArtifact) {
        guard owns(artifact.fileURL.deletingLastPathComponent()) else { return }
        discardDirectory(artifact.fileURL.deletingLastPathComponent())
    }

    func cleanupOwnedArtifacts() {
        let directories = ownershipLock.withLock { Array(ownedTransferDirectories) }
        directories.forEach(discardDirectory)
    }

    private func createExclusiveTransferDirectory() throws -> URL {
        for _ in 0..<16 {
            let candidate = stagingRoot.appendingPathComponent("transfer-\(UUID().uuidString)", isDirectory: true)
            if mkdir(candidate.path, 0o700) == 0 { return candidate }
            if errno != EEXIST {
                throw SecureDownloadError.stagingUnavailable(String(cString: strerror(errno)))
            }
        }
        throw SecureDownloadError.stagingUnavailable("Could not allocate a unique transfer directory.")
    }

    private func copySecurely(
        from source: URL,
        to destination: URL,
        expectedDigest: String?,
        quarantineOrigin: String?,
        capturePrefix: inout Data
    ) throws -> (String, Int64) {
        guard source.deletingLastPathComponent().standardizedFileURL.path.hasPrefix(stagingRoot.path + "/") else {
            throw SecureDownloadError.unsafeFilesystemObject
        }
        let sourceParent = source.deletingLastPathComponent()
        let sourceParentDescriptor = open(sourceParent.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard sourceParentDescriptor >= 0 else { throw SecureDownloadError.unsafeFilesystemObject }
        defer { close(sourceParentDescriptor) }
        var sourceStatus = stat()
        guard fstatat(sourceParentDescriptor, source.lastPathComponent, &sourceStatus, AT_SYMLINK_NOFOLLOW) == 0,
              (sourceStatus.st_mode & S_IFMT) == S_IFREG,
              sourceStatus.st_nlink == 1 else {
            throw SecureDownloadError.unsafeFilesystemObject
        }

        let input = openat(sourceParentDescriptor, source.lastPathComponent, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard input >= 0 else { throw SecureDownloadError.unsafeFilesystemObject }
        defer { close(input) }
        var openedStatus = stat()
        guard fstat(input, &openedStatus) == 0,
              (openedStatus.st_mode & S_IFMT) == S_IFREG,
              openedStatus.st_dev == sourceStatus.st_dev,
              openedStatus.st_ino == sourceStatus.st_ino else {
            throw SecureDownloadError.unsafeFilesystemObject
        }

        let parent = destination.deletingLastPathComponent()
        var parentStatus = stat()
        guard lstat(parent.path, &parentStatus) == 0, (parentStatus.st_mode & S_IFMT) == S_IFDIR else {
            throw SecureDownloadError.unsafeFilesystemObject
        }
        let parentDescriptor = open(parent.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parentDescriptor >= 0 else { throw SecureDownloadError.unsafeFilesystemObject }
        defer { close(parentDescriptor) }
        var openedParentStatus = stat()
        guard fstat(parentDescriptor, &openedParentStatus) == 0,
              openedParentStatus.st_dev == parentStatus.st_dev,
              openedParentStatus.st_ino == parentStatus.st_ino else {
            throw SecureDownloadError.unsafeFilesystemObject
        }
        let output = openat(parentDescriptor, destination.lastPathComponent, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard output >= 0 else {
            if errno == EEXIST { throw SecureDownloadError.destinationAlreadyExists }
            throw SecureDownloadError.stagingUnavailable(String(cString: strerror(errno)))
        }
        var succeeded = false
        defer {
            close(output)
            if !succeeded { unlinkat(parentDescriptor, destination.lastPathComponent, 0) }
        }

        var hasher = SHA256()
        var total: Int64 = 0
        var buffer = [UInt8](repeating: 0, count: 64 * 1_024)
        while true {
            let count = readRetrying(input, into: &buffer)
            if count < 0 { throw SecureDownloadError.stagingUnavailable(String(cString: strerror(errno))) }
            if count == 0 { break }
            total += Int64(count)
            guard total <= maximumBytes else { throw SecureDownloadError.sizeLimitExceeded(limit: maximumBytes) }
            let chunk = Data(buffer[0..<count])
            hasher.update(data: chunk)
            if capturePrefix.count < 16_384 {
                capturePrefix.append(chunk.prefix(16_384 - capturePrefix.count))
            }
            try writeAll(output, bytes: buffer, count: count)
        }
        let digest = hasher.finalize().map { String(format: "%02x", $0) }.joined()
        if let expectedDigest, digest != expectedDigest { throw SecureDownloadError.contentChanged }
        try applyQuarantine(toDescriptor: output, sourceOrigin: quarantineOrigin)
        guard fsync(output) == 0 else { throw SecureDownloadError.stagingUnavailable(String(cString: strerror(errno))) }
        succeeded = true
        return (digest, total)
    }

    private func digestSecurely(from source: URL, capturePrefix: inout Data) throws -> (String, Int64) {
        guard source.deletingLastPathComponent().standardizedFileURL.path.hasPrefix(stagingRoot.path + "/") else {
            throw SecureDownloadError.unsafeFilesystemObject
        }
        let parentDescriptor = open(source.deletingLastPathComponent().path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parentDescriptor >= 0 else { throw SecureDownloadError.unsafeFilesystemObject }
        defer { close(parentDescriptor) }

        var pathStatus = stat()
        guard fstatat(parentDescriptor, source.lastPathComponent, &pathStatus, AT_SYMLINK_NOFOLLOW) == 0,
              (pathStatus.st_mode & S_IFMT) == S_IFREG,
              pathStatus.st_nlink == 1 else {
            throw SecureDownloadError.unsafeFilesystemObject
        }
        let descriptor = openat(parentDescriptor, source.lastPathComponent, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw SecureDownloadError.unsafeFilesystemObject }
        defer { close(descriptor) }
        var openedStatus = stat()
        guard fstat(descriptor, &openedStatus) == 0,
              openedStatus.st_dev == pathStatus.st_dev,
              openedStatus.st_ino == pathStatus.st_ino,
              (openedStatus.st_mode & S_IFMT) == S_IFREG else {
            throw SecureDownloadError.unsafeFilesystemObject
        }

        var hasher = SHA256()
        var total: Int64 = 0
        var buffer = [UInt8](repeating: 0, count: 64 * 1_024)
        while true {
            let count = readRetrying(descriptor, into: &buffer)
            if count < 0 { throw SecureDownloadError.stagingUnavailable(String(cString: strerror(errno))) }
            if count == 0 { break }
            total += Int64(count)
            guard total <= maximumBytes else { throw SecureDownloadError.sizeLimitExceeded(limit: maximumBytes) }
            let chunk = Data(buffer[0..<count])
            hasher.update(data: chunk)
            if capturePrefix.count < 16_384 { capturePrefix.append(chunk.prefix(16_384 - capturePrefix.count)) }
        }
        return (hasher.finalize().map { String(format: "%02x", $0) }.joined(), total)
    }

    private func writeMetadata(for artifact: StagedDownloadArtifact, sourceOrigin: String?, in directory: URL) throws {
        struct Metadata: Codable {
            let version: Int
            let filename: String
            let byteCount: Int64
            let sha256: String
            let reportedMIMEType: String?
            let detectedMIMEType: String?
            let typeIdentifier: String?
            let category: String
            let allowsManualPreview: Bool
            let warnings: [String]
            let sourceOrigin: String?
        }
        let metadata = Metadata(
            version: 1,
            filename: artifact.displayFilename,
            byteCount: artifact.byteCount,
            sha256: artifact.sha256,
            reportedMIMEType: artifact.reportedMIMEType,
            detectedMIMEType: artifact.detectedMIMEType,
            typeIdentifier: artifact.typeIdentifier,
            category: artifact.category.rawValue,
            allowsManualPreview: artifact.allowsManualPreview,
            warnings: artifact.warnings,
            sourceOrigin: sourceOrigin
        )
        let data = try JSONEncoder().encode(metadata)
        let parentDescriptor = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parentDescriptor >= 0 else { throw SecureDownloadError.unsafeFilesystemObject }
        defer { close(parentDescriptor) }
        let descriptor = openat(parentDescriptor, ".download-metadata.json", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw SecureDownloadError.stagingUnavailable(String(cString: strerror(errno))) }
        defer { close(descriptor) }
        try data.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress else { return }
            var offset = 0
            while offset < rawBuffer.count {
                let written = Darwin.write(descriptor, base.advanced(by: offset), rawBuffer.count - offset)
                if written < 0 {
                    if errno == EINTR { continue }
                    throw SecureDownloadError.stagingUnavailable(String(cString: strerror(errno)))
                }
                offset += written
            }
        }
        guard fsync(descriptor) == 0 else { throw SecureDownloadError.stagingUnavailable(String(cString: strerror(errno))) }
    }

    private func applyQuarantine(toDescriptor descriptor: Int32, sourceOrigin: String?) throws {
        let timestamp = String(Int(Date().timeIntervalSince1970), radix: 16)
        let origin = (sourceOrigin ?? "").replacingOccurrences(of: ";", with: "").replacingOccurrences(of: "\n", with: "")
        let value = "0083;\(timestamp);\(ProductBrand.displayName);\(origin)"
        var status = stat()
        guard fstat(descriptor, &status) == 0, (status.st_mode & S_IFMT) == S_IFREG else {
            throw SecureDownloadError.quarantineFailed
        }
        let result = value.withCString { valuePointer in
            "com.apple.quarantine".withCString { namePointer in
                fsetxattr(descriptor, namePointer, valuePointer, strlen(valuePointer), 0, 0)
            }
        }
        guard result == 0 else { throw SecureDownloadError.quarantineFailed }
    }

    private func unlinkSecurely(_ url: URL) {
        let parentDescriptor = open(url.deletingLastPathComponent().path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parentDescriptor >= 0 else { return }
        defer { close(parentDescriptor) }
        unlinkat(parentDescriptor, url.lastPathComponent, 0)
    }

    @discardableResult
    func cleanupStaleTransfers(
        olderThan age: TimeInterval,
        now: Date = Date(),
        limits: SecureDownloadCleanupLimits = SecureDownloadCleanupLimits()
    ) -> SecureDownloadCleanupReport {
        guard age.isFinite, age >= 0, limits.isValid else {
            return SecureDownloadCleanupReport(status: .bounded, inspectedEntries: 0, removedTransfers: 0)
        }
        let rootDescriptor = Darwin.open(
            stagingRoot.path,
            O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard rootDescriptor >= 0 else {
            return SecureDownloadCleanupReport(status: .unsafeEntriesRetained, inspectedEntries: 0, removedTransfers: 0)
        }
        defer { Darwin.close(rootDescriptor) }
        let iterationDescriptor = Darwin.dup(rootDescriptor)
        guard iterationDescriptor >= 0, let stream = fdopendir(iterationDescriptor) else {
            if iterationDescriptor >= 0 { Darwin.close(iterationDescriptor) }
            return SecureDownloadCleanupReport(status: .unsafeEntriesRetained, inspectedEntries: 0, removedTransfers: 0)
        }
        defer { closedir(stream) }

        var budget = CleanupBudget(limits: limits)
        var removed = 0
        var retainedUnsafe = false
        let cutoff = now.timeIntervalSince1970 - age
        while true {
            guard budget.isWithinDeadline else {
                return SecureDownloadCleanupReport(status: .bounded, inspectedEntries: budget.inspected, removedTransfers: removed)
            }
            errno = 0
            guard let entry = readdir(stream) else {
                let status: SecureDownloadCleanupStatus
                if errno != 0 { status = .unsafeEntriesRetained }
                else { status = retainedUnsafe ? .unsafeEntriesRetained : .completed }
                return SecureDownloadCleanupReport(status: status, inspectedEntries: budget.inspected, removedTransfers: removed)
            }
            guard let name = Self.directoryEntryName(entry) else {
                guard budget.consume() else {
                    return SecureDownloadCleanupReport(status: .bounded, inspectedEntries: budget.inspected, removedTransfers: removed)
                }
                retainedUnsafe = true
                continue
            }
            if name == "." || name == ".." { continue }
            guard budget.consume() else {
                return SecureDownloadCleanupReport(status: .bounded, inspectedEntries: budget.inspected, removedTransfers: removed)
            }
            guard Self.isTransferDirectoryName(name) else { continue }
            var metadata = stat()
            guard fstatat(rootDescriptor, name, &metadata, AT_SYMLINK_NOFOLLOW) == 0,
                  metadata.st_mode & S_IFMT == S_IFDIR,
                  metadata.st_uid == geteuid(),
                  metadata.st_mode & (S_IWGRP | S_IWOTH) == 0 else {
                retainedUnsafe = true
                continue
            }
            let modificationTime = TimeInterval(metadata.st_mtimespec.tv_sec)
                + TimeInterval(metadata.st_mtimespec.tv_nsec) / 1_000_000_000
            guard modificationTime < cutoff else { continue }
            do {
                try removeTree(
                    named: name,
                    parentDescriptor: rootDescriptor,
                    depth: 0,
                    alreadyConsumed: true,
                    budget: &budget
                )
                removed += 1
            } catch CleanupFailure.bounded {
                return SecureDownloadCleanupReport(status: .bounded, inspectedEntries: budget.inspected, removedTransfers: removed)
            } catch {
                retainedUnsafe = true
            }
        }
    }

    private enum CleanupFailure: Error { case bounded, unsafe }

    private struct CleanupBudget {
        let maximumEntries: Int
        let maximumDepth: Int
        let deadline: UInt64
        var inspected = 0

        init(limits: SecureDownloadCleanupLimits) {
            maximumEntries = limits.maximumEntries
            maximumDepth = limits.maximumDepth
            let started = DispatchTime.now().uptimeNanoseconds
            let delta = UInt64(limits.duration * 1_000_000_000)
            let sum = started.addingReportingOverflow(delta)
            deadline = sum.overflow ? UInt64.max : sum.partialValue
        }

        var isWithinDeadline: Bool { DispatchTime.now().uptimeNanoseconds < deadline }

        mutating func consume() -> Bool {
            guard isWithinDeadline, inspected < maximumEntries else { return false }
            inspected += 1
            return true
        }
    }

    private func removeTree(
        named name: String,
        parentDescriptor: Int32,
        depth: Int,
        alreadyConsumed: Bool,
        budget: inout CleanupBudget
    ) throws {
        guard budget.isWithinDeadline, depth <= budget.maximumDepth else {
            throw CleanupFailure.bounded
        }
        if !alreadyConsumed, !budget.consume() { throw CleanupFailure.bounded }
        var metadata = stat()
        guard fstatat(parentDescriptor, name, &metadata, AT_SYMLINK_NOFOLLOW) == 0 else {
            throw CleanupFailure.unsafe
        }
        if metadata.st_mode & S_IFMT != S_IFDIR {
            guard unlinkat(parentDescriptor, name, 0) == 0 else { throw CleanupFailure.unsafe }
            return
        }
        let descriptor = openat(
            parentDescriptor,
            name,
            O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else { throw CleanupFailure.unsafe }
        defer { Darwin.close(descriptor) }
        var opened = stat()
        guard Darwin.fstat(descriptor, &opened) == 0,
              opened.st_dev == metadata.st_dev,
              opened.st_ino == metadata.st_ino,
              opened.st_mode & S_IFMT == S_IFDIR,
              opened.st_uid == geteuid() else { throw CleanupFailure.unsafe }

        let iterationDescriptor = Darwin.dup(descriptor)
        guard iterationDescriptor >= 0, let stream = fdopendir(iterationDescriptor) else {
            if iterationDescriptor >= 0 { Darwin.close(iterationDescriptor) }
            throw CleanupFailure.unsafe
        }
        while true {
            guard budget.isWithinDeadline else {
                closedir(stream)
                throw CleanupFailure.bounded
            }
            errno = 0
            guard let entry = readdir(stream) else {
                let failed = errno != 0
                closedir(stream)
                if failed { throw CleanupFailure.unsafe }
                break
            }
            guard let child = Self.directoryEntryName(entry) else {
                closedir(stream)
                throw CleanupFailure.unsafe
            }
            if child == "." || child == ".." { continue }
            try removeTree(
                named: child,
                parentDescriptor: descriptor,
                depth: depth + 1,
                alreadyConsumed: false,
                budget: &budget
            )
        }
        var current = stat()
        guard fstatat(parentDescriptor, name, &current, AT_SYMLINK_NOFOLLOW) == 0,
              current.st_dev == opened.st_dev,
              current.st_ino == opened.st_ino,
              unlinkat(parentDescriptor, name, AT_REMOVEDIR) == 0 else {
            throw CleanupFailure.unsafe
        }
    }

    private static func directoryEntryName(_ entry: UnsafeMutablePointer<dirent>) -> String? {
        guard let name = DarwinDirectoryEntry.name(entry),
              !name.contains("/"), !name.contains("\0") else { return nil }
        return name
    }

    private static func isTransferDirectoryName(_ name: String) -> Bool {
        let prefix = "transfer-"
        guard name.hasPrefix(prefix) else { return false }
        return UUID(uuidString: String(name.dropFirst(prefix.count))) != nil
    }

    private func owns(_ directory: URL) -> Bool {
        ownershipLock.withLock { ownedTransferDirectories.contains(directory.standardizedFileURL) }
    }

    private func discardDirectory(_ directory: URL) {
        let standardized = directory.standardizedFileURL
        let removed = ownershipLock.withLock { ownedTransferDirectories.remove(standardized) != nil }
        guard removed, standardized.deletingLastPathComponent() == stagingRoot else { return }
        try? fileManager.removeItem(at: standardized)
    }

    private static func preparePrivateDirectory(_ url: URL, fileManager: FileManager) throws {
        do {
            try fileManager.createDirectory(at: url, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            guard url.standardizedFileURL == url.resolvingSymlinksInPath().standardizedFileURL else {
                throw SecureDownloadError.unsafeFilesystemObject
            }
            var pathStatus = stat()
            guard lstat(url.path, &pathStatus) == 0,
                  pathStatus.st_mode & S_IFMT == S_IFDIR,
                  pathStatus.st_uid == geteuid() else {
                throw SecureDownloadError.unsafeFilesystemObject
            }
            let descriptor = open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard descriptor >= 0 else { throw SecureDownloadError.unsafeFilesystemObject }
            defer { close(descriptor) }
            var opened = stat()
            guard fstat(descriptor, &opened) == 0,
                  opened.st_dev == pathStatus.st_dev,
                  opened.st_ino == pathStatus.st_ino,
                  opened.st_mode & S_IFMT == S_IFDIR,
                  opened.st_uid == geteuid() else {
                throw SecureDownloadError.unsafeFilesystemObject
            }
            guard fchmod(descriptor, 0o700) == 0 else {
                throw SecureDownloadError.stagingUnavailable(String(cString: strerror(errno)))
            }
        } catch let error as SecureDownloadError {
            throw error
        } catch {
            throw SecureDownloadError.stagingUnavailable(error.localizedDescription)
        }
    }

    private static func safeOrigin(from url: URL?) -> String? {
        guard let url, let scheme = url.scheme, let host = url.host else { return nil }
        var components = URLComponents()
        components.scheme = scheme
        components.host = host
        components.port = url.port
        return components.url?.absoluteString
    }
}

private func readRetrying(_ descriptor: Int32, into buffer: inout [UInt8]) -> Int {
    while true {
        let result = buffer.withUnsafeMutableBytes { rawBuffer in
            Darwin.read(descriptor, rawBuffer.baseAddress, rawBuffer.count)
        }
        if result < 0 && errno == EINTR { continue }
        return result
    }
}

private func writeAll(_ descriptor: Int32, bytes: [UInt8], count: Int) throws {
    try bytes.withUnsafeBytes { rawBuffer in
        guard let base = rawBuffer.baseAddress else { return }
        var offset = 0
        while offset < count {
            let result = Darwin.write(descriptor, base.advanced(by: offset), count - offset)
            if result < 0 {
                if errno == EINTR { continue }
                throw SecureDownloadError.stagingUnavailable(String(cString: strerror(errno)))
            }
            offset += result
        }
    }
}

private extension NSLock {
    func withLock<T>(_ body: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try body()
    }
}
