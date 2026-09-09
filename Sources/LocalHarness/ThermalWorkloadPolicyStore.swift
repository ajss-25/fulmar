import Darwin
import Foundation

enum ThermalWorkloadMode: String, Codable, Equatable, Sendable {
    case normal
    case eco
}

struct ThermalWorkloadPolicyDocument: Codable, Equatable, Sendable {
    static let schemaVersion = 1
    static let ecoMaximumOutputTokens = 2_048
    static let ecoMinimumDelayMilliseconds = 5_000

    let schemaVersion: Int
    let mode: ThermalWorkloadMode
    let ecoMaxOutputTokens: Int
    let minimumDelayMilliseconds: Int

    static func production(_ mode: ThermalWorkloadMode) -> ThermalWorkloadPolicyDocument {
        ThermalWorkloadPolicyDocument(
            schemaVersion: schemaVersion,
            mode: mode,
            ecoMaxOutputTokens: ecoMaximumOutputTokens,
            minimumDelayMilliseconds: ecoMinimumDelayMilliseconds
        )
    }
}

enum ThermalWorkloadPolicyStoreError: LocalizedError, Equatable {
    case unsafeStorage
    case storageUnavailable

    var errorDescription: String? {
        switch self {
        case .unsafeStorage:
            return "Adaptive thermal controls are unavailable because their private policy file is unsafe."
        case .storageUnavailable:
            return "Adaptive thermal controls could not create their private policy file."
        }
    }
}

/// A tiny native-to-DSH control plane containing no prompt, response, path,
/// model, provider, credential, or session data. The native thermal monitor
/// atomically changes only `normal`/`eco`; the reviewed performance plugin
/// revalidates and applies the fixed cap at every local model request.
enum ThermalWorkloadPolicyStore {
    static let fileName = "thermal-workload-policy.json"
    static let maximumFileBytes = 1_024

    static func storageURL(applicationSupport: URL) -> URL {
        applicationSupport
            .appendingPathComponent(GenerationTelemetrySpool.directoryName, isDirectory: true)
            .appendingPathComponent(fileName, isDirectory: false)
    }

    @discardableResult
    static func prepare(
        applicationSupport: URL,
        fileManager: FileManager = .default
    ) throws -> URL {
        _ = try GenerationTelemetrySpool.prepare(
            applicationSupport: applicationSupport,
            fileManager: fileManager
        )
        let file = storageURL(applicationSupport: applicationSupport)
        if !nodeExists(file) {
            try replace(file, with: .production(.normal))
        }
        _ = try read(applicationSupport: applicationSupport)
        return file
    }

    static func read(applicationSupport: URL) throws -> ThermalWorkloadPolicyDocument {
        let file = storageURL(applicationSupport: applicationSupport)
        guard secureFile(file) else { throw ThermalWorkloadPolicyStoreError.unsafeStorage }
        let descriptor = Darwin.open(file.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw ThermalWorkloadPolicyStoreError.storageUnavailable }
        defer { Darwin.close(descriptor) }
        var metadata = stat()
        guard Darwin.fstat(descriptor, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_uid == geteuid(),
              metadata.st_nlink == 1,
              metadata.st_mode & (S_IRWXG | S_IRWXO) == 0,
              metadata.st_size > 0,
              metadata.st_size <= maximumFileBytes else {
            throw ThermalWorkloadPolicyStoreError.unsafeStorage
        }
        var bytes = [UInt8](repeating: 0, count: Int(metadata.st_size))
        var offset = 0
        while offset < bytes.count {
            let remaining = bytes.count - offset
            let count = bytes.withUnsafeMutableBytes { buffer in
                Darwin.read(descriptor, buffer.baseAddress!.advanced(by: offset), remaining)
            }
            guard count > 0 else { throw ThermalWorkloadPolicyStoreError.storageUnavailable }
            offset += count
        }
        guard let value = try? JSONDecoder().decode(ThermalWorkloadPolicyDocument.self, from: Data(bytes)),
              value == .production(value.mode) else {
            throw ThermalWorkloadPolicyStoreError.unsafeStorage
        }
        return value
    }

    static func setMode(
        _ mode: ThermalWorkloadMode,
        applicationSupport: URL,
        fileManager: FileManager = .default
    ) throws {
        let file = try prepare(applicationSupport: applicationSupport, fileManager: fileManager)
        if try read(applicationSupport: applicationSupport).mode == mode { return }
        try replace(file, with: .production(mode))
        guard try read(applicationSupport: applicationSupport).mode == mode else {
            throw ThermalWorkloadPolicyStoreError.storageUnavailable
        }
    }

    private static func replace(
        _ destination: URL,
        with document: ThermalWorkloadPolicyDocument
    ) throws {
        let directory = destination.deletingLastPathComponent()
        guard secureDirectory(directory) else { throw ThermalWorkloadPolicyStoreError.unsafeStorage }
        if nodeExists(destination), !secureFile(destination) {
            throw ThermalWorkloadPolicyStoreError.unsafeStorage
        }
        let temporary = directory.appendingPathComponent(".\(fileName).\(UUID().uuidString).tmp")
        let descriptor = Darwin.open(
            temporary.path,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            S_IRUSR | S_IWUSR
        )
        guard descriptor >= 0 else { throw ThermalWorkloadPolicyStoreError.storageUnavailable }
        var descriptorOpen = true
        var shouldRemoveTemporary = true
        defer {
            if descriptorOpen { _ = Darwin.close(descriptor) }
            if shouldRemoveTemporary { _ = Darwin.unlink(temporary.path) }
        }

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(document)
        guard data.count <= maximumFileBytes,
              data.withUnsafeBytes({ buffer -> Bool in
                  var offset = 0
                  while offset < buffer.count {
                      let count = Darwin.write(
                          descriptor,
                          buffer.baseAddress!.advanced(by: offset),
                          buffer.count - offset
                      )
                      guard count > 0 else { return false }
                      offset += count
                  }
                  return true
              }),
              Darwin.fsync(descriptor) == 0 else {
            throw ThermalWorkloadPolicyStoreError.storageUnavailable
        }
        guard Darwin.close(descriptor) == 0 else {
            throw ThermalWorkloadPolicyStoreError.storageUnavailable
        }
        descriptorOpen = false
        if nodeExists(destination), !secureFile(destination) {
            throw ThermalWorkloadPolicyStoreError.unsafeStorage
        }
        guard Darwin.rename(temporary.path, destination.path) == 0 else {
            throw ThermalWorkloadPolicyStoreError.storageUnavailable
        }
        shouldRemoveTemporary = false
        let directoryDescriptor = Darwin.open(directory.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard directoryDescriptor >= 0 else { throw ThermalWorkloadPolicyStoreError.storageUnavailable }
        let synced = Darwin.fsync(directoryDescriptor) == 0
        let closed = Darwin.close(directoryDescriptor) == 0
        guard synced, closed, secureFile(destination) else {
            throw ThermalWorkloadPolicyStoreError.storageUnavailable
        }
    }

    private static func nodeExists(_ url: URL) -> Bool {
        var metadata = stat()
        if Darwin.lstat(url.path, &metadata) == 0 { return true }
        return errno != ENOENT
    }

    private static func secureDirectory(_ url: URL) -> Bool {
        var metadata = stat()
        return Darwin.lstat(url.path, &metadata) == 0
            && metadata.st_mode & S_IFMT == S_IFDIR
            && metadata.st_uid == geteuid()
            && metadata.st_mode & (S_IRWXG | S_IRWXO) == 0
    }

    private static func secureFile(_ url: URL) -> Bool {
        var metadata = stat()
        return Darwin.lstat(url.path, &metadata) == 0
            && metadata.st_mode & S_IFMT == S_IFREG
            && metadata.st_uid == geteuid()
            && metadata.st_nlink == 1
            && metadata.st_mode & (S_IRWXG | S_IRWXO) == 0
            && metadata.st_size > 0
            && metadata.st_size <= maximumFileBytes
    }
}
