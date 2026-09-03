import Darwin
import Foundation

struct BrowserAnnotation: Codable, Equatable, Sendable {
    let id: UUID
    let createdAt: Date
    let url: String
    let selectedText: String
    let note: String
}

enum BrowserCaptureLimits {
    static let pageTextCharacters = 256 * 1_024
    static let selectedTextCharacters = 16 * 1_024
    static let noteCharacters = 4 * 1_024
    static let urlCharacters = 2_048
    static let annotations = 500
    static let annotationFileBytes = 4 * 1_024 * 1_024
    static let annotationLineBytes = 256 * 1_024

    static func bounded(_ value: String, characters: Int) -> String {
        guard value.count > characters else { return value }
        return String(value.prefix(characters))
    }
}

/// A bounded JSON-lines store. Rewriting on save is intentional: it makes the
/// total storage ceiling enforceable and keeps the file recoverable if a prior
/// version or external process left malformed or oversized records behind.
final class BrowserAnnotationStore {
    enum StoreError: Error {
        case recordTooLarge
        case unsafeStorage
    }

    private let fileURL: URL

    init(fileURL: URL) {
        self.fileURL = fileURL
    }

    func makeAnnotation(url: URL, selectedText: String, note: String, now: Date = Date()) -> BrowserAnnotation {
        BrowserAnnotation(
            id: UUID(),
            createdAt: now,
            url: BrowserCaptureLimits.bounded(url.absoluteString, characters: BrowserCaptureLimits.urlCharacters),
            selectedText: BrowserCaptureLimits.bounded(selectedText, characters: BrowserCaptureLimits.selectedTextCharacters),
            note: BrowserCaptureLimits.bounded(note, characters: BrowserCaptureLimits.noteCharacters)
        )
    }

    func append(_ annotation: BrowserAnnotation) throws {
        var annotations = readAll()
        annotations.append(annotation)
        if annotations.count > BrowserCaptureLimits.annotations {
            annotations.removeFirst(annotations.count - BrowserCaptureLimits.annotations)
        }

        var encoded = try encodedLines(annotations)
        while encoded.count > BrowserCaptureLimits.annotationFileBytes, annotations.count > 1 {
            annotations.removeFirst()
            encoded = try encodedLines(annotations)
        }
        guard encoded.count <= BrowserCaptureLimits.annotationFileBytes else {
            throw StoreError.recordTooLarge
        }

        try atomicPrivateWrite(encoded)
    }

    func readAll() -> [BrowserAnnotation] {
        let descriptor = Darwin.open(fileURL.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else { return [] }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_nlink == 1,
              metadata.st_size <= BrowserCaptureLimits.annotationFileBytes
        else {
            Darwin.close(descriptor)
            return []
        }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? handle.close() }
        guard let data = try? handle.read(upToCount: BrowserCaptureLimits.annotationFileBytes + 1),
              data.count <= BrowserCaptureLimits.annotationFileBytes
        else { return [] }

        let decoded = data.split(separator: 0x0A, omittingEmptySubsequences: true).suffix(BrowserCaptureLimits.annotations).compactMap { line -> BrowserAnnotation? in
            guard line.count <= BrowserCaptureLimits.annotationLineBytes else { return nil }
            return try? JSONDecoder().decode(BrowserAnnotation.self, from: Data(line))
        }
        return decoded.filter { annotation in
            annotation.url.count <= BrowserCaptureLimits.urlCharacters &&
                annotation.selectedText.count <= BrowserCaptureLimits.selectedTextCharacters &&
                annotation.note.count <= BrowserCaptureLimits.noteCharacters
        }
    }

    private func encodedLines(_ annotations: [BrowserAnnotation]) throws -> Data {
        var output = Data()
        for annotation in annotations {
            let line = try JSONEncoder().encode(annotation)
            guard line.count <= BrowserCaptureLimits.annotationLineBytes else {
                throw StoreError.recordTooLarge
            }
            output.append(line)
            output.append(0x0A)
        }
        return output
    }

    private func atomicPrivateWrite(_ data: Data) throws {
        let fileManager = FileManager.default
        let directory = fileURL.deletingLastPathComponent()
        if !fileManager.fileExists(atPath: directory.path) {
            try fileManager.createDirectory(
                at: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        }
        var directoryMetadata = stat()
        guard lstat(directory.path, &directoryMetadata) == 0,
              directoryMetadata.st_mode & S_IFMT == S_IFDIR
        else { throw StoreError.unsafeStorage }
        try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)

        let temporary = directory.appendingPathComponent(".annotations.\(UUID().uuidString).tmp")
        let descriptor = Darwin.open(
            temporary.path,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            S_IRUSR | S_IWUSR
        )
        guard descriptor >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        do {
            try handle.write(contentsOf: data)
            try handle.synchronize()
            try handle.close()
            let result = temporary.path.withCString { source in
                fileURL.path.withCString { destination in Darwin.rename(source, destination) }
            }
            guard result == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
        } catch {
            try? handle.close()
            try? fileManager.removeItem(at: temporary)
            throw error
        }
    }
}
