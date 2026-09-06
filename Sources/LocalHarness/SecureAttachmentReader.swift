import Darwin
import Foundation

enum SecureAttachmentReaderError: Error, Equatable, LocalizedError {
    case unsafePath
    case notRegularFile
    case tooLarge(maximumBytes: Int)
    case unreadable
    case unsupportedImage

    var errorDescription: String? {
        switch self {
        case .unsafePath: return "The selected attachment path is not safe to read."
        case .notRegularFile: return "Only regular files can be attached."
        case .tooLarge(let maximum): return "The attachment exceeds the \(maximum)-byte limit."
        case .unreadable: return "The selected attachment could not be read safely."
        case .unsupportedImage: return "The file contents are not a supported PNG, JPEG, WebP, or GIF image."
        }
    }
}

/// Opens user-selected files without following a final symlink and bounds every
/// read even if the file changes after the picker returns.
enum SecureAttachmentReader {
    static func readRegularFile(at url: URL, maximumBytes: Int) throws -> Data {
        guard url.isFileURL, url.path.hasPrefix("/"), maximumBytes > 0 else {
            throw SecureAttachmentReaderError.unsafePath
        }
        let descriptor: Int32 = url.withUnsafeFileSystemRepresentation { path in
            guard let path else { return -1 }
            return Darwin.open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard descriptor >= 0 else {
            if errno == ELOOP { throw SecureAttachmentReaderError.notRegularFile }
            throw SecureAttachmentReaderError.unreadable
        }
        defer { Darwin.close(descriptor) }

        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0 else { throw SecureAttachmentReaderError.unreadable }
        guard (metadata.st_mode & S_IFMT) == S_IFREG else { throw SecureAttachmentReaderError.notRegularFile }
        guard metadata.st_size >= 0, metadata.st_size <= off_t(maximumBytes) else {
            throw SecureAttachmentReaderError.tooLarge(maximumBytes: maximumBytes)
        }

        var output = Data()
        output.reserveCapacity(min(Int(metadata.st_size), maximumBytes))
        var buffer = [UInt8](repeating: 0, count: min(64 * 1_024, maximumBytes + 1))
        while true {
            let count = Darwin.read(descriptor, &buffer, buffer.count)
            if count == 0 { break }
            if count < 0 {
                if errno == EINTR { continue }
                throw SecureAttachmentReaderError.unreadable
            }
            guard count <= maximumBytes - output.count else {
                throw SecureAttachmentReaderError.tooLarge(maximumBytes: maximumBytes)
            }
            output.append(contentsOf: buffer.prefix(count))
        }
        return output
    }

    static func imageMediaType(for data: Data, filename: String) throws -> HarnessImageMediaType {
        let bytes = [UInt8](data.prefix(12))
        let detected: HarnessImageMediaType?
        if bytes.count >= 8, bytes[0..<8].elementsEqual([137, 80, 78, 71, 13, 10, 26, 10]) {
            detected = .png
        } else if bytes.count >= 3, bytes[0] == 0xFF, bytes[1] == 0xD8, bytes[2] == 0xFF {
            detected = .jpeg
        } else if bytes.count >= 6,
                  String(bytes: bytes[0..<6], encoding: .ascii).map({ $0 == "GIF87a" || $0 == "GIF89a" }) == true {
            detected = .gif
        } else if bytes.count >= 12,
                  String(bytes: bytes[0..<4], encoding: .ascii) == "RIFF",
                  String(bytes: bytes[8..<12], encoding: .ascii) == "WEBP" {
            detected = .webp
        } else {
            detected = nil
        }
        guard let detected else { throw SecureAttachmentReaderError.unsupportedImage }

        let expected: HarnessImageMediaType?
        switch URL(fileURLWithPath: filename).pathExtension.lowercased() {
        case "png": expected = .png
        case "jpg", "jpeg": expected = .jpeg
        case "gif": expected = .gif
        case "webp": expected = .webp
        default: expected = nil
        }
        guard expected == detected else { throw SecureAttachmentReaderError.unsupportedImage }
        return detected
    }
}
