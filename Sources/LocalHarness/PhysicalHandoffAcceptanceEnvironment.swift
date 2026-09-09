import Darwin
import Foundation

/// Release-qualification-only isolation for the one physical scheduler-to-
/// foreground handoff gate. The ordinary product never propagates its launch
/// environment. This narrowly scoped path carries only a validated disposable
/// HOME boundary into the fresh foreground process, so the physical gate can
/// exercise the real runtime without touching the signed-in user's Fulmar
/// state or preferences.
struct PhysicalHandoffAcceptanceEnvironment: Equatable, Sendable {
    struct RuntimeDirectories: Equatable, Sendable {
        let fileManagerHome: URL
        let foundationHome: URL
        let applicationSupport: URL
        let temporaryDirectory: URL

        static func current() -> Self? {
            guard let applicationSupport = FileManager.default.urls(
                for: .applicationSupportDirectory,
                in: .userDomainMask
            ).first else { return nil }
            return Self(
                fileManagerHome: FileManager.default.homeDirectoryForCurrentUser,
                foundationHome: URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true),
                applicationSupport: applicationSupport,
                temporaryDirectory: URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            )
        }
    }

    enum Mode: Equatable, Sendable {
        case background
        case foreground
    }

    enum ValidationError: Error, Equatable, LocalizedError {
        case invalidArguments
        case invalidEnvironment
        case unsafeRoot
        case publicationFailed

        var errorDescription: String? {
            switch self {
            case .invalidArguments:
                return "The physical handoff acceptance arguments are incomplete or conflicting."
            case .invalidEnvironment:
                return "The physical handoff acceptance environment does not match its disposable root."
            case .unsafeRoot:
                return "The physical handoff acceptance root is missing, linked, not private, or outside /private/tmp."
            case .publicationFailed:
                return "The physical handoff acceptance process could not publish its private ready evidence."
            }
        }
    }

    static let backgroundArgument = "--physical-background-handoff-acceptance"
    static let foregroundArgument = "--physical-background-handoff-foreground-acceptance"
    static let rootEnvironmentKey = "LOCAL_HARNESS_PHYSICAL_HANDOFF_ROOT"
    static let modelStoreEnvironmentKey = "LOCAL_HARNESS_PHYSICAL_HANDOFF_MODEL_STORE"
    static let rootLeafPrefix = "fulmar-physical-handoff."
    static let foregroundReadyFileName = "foreground-ready.json"

    let mode: Mode
    let root: URL
    let home: URL
    let temporaryDirectory: URL
    let applicationSupport: URL
    let modelStore: URL

    static func resolveIfRequested(
        arguments: [String] = CommandLine.arguments,
        environment: [String: String] = ProcessInfo.processInfo.environment,
        runtimeDirectories suppliedRuntimeDirectories: RuntimeDirectories? = nil
    ) throws -> Self? {
        let requestsBackground = arguments.contains(backgroundArgument)
        let requestsForeground = arguments.contains(foregroundArgument)
        guard requestsBackground || requestsForeground else { return nil }

        let suppliedArguments = Array(arguments.dropFirst())
        let expectedArguments = requestsBackground
            ? ["--background-schedule", backgroundArgument]
            : [foregroundArgument]
        guard requestsBackground != requestsForeground,
              suppliedArguments == expectedArguments else {
            throw ValidationError.invalidArguments
        }

        guard let rawRoot = environment[rootEnvironmentKey],
              !rawRoot.isEmpty,
              rawRoot.utf8.count <= 1_024,
              !rawRoot.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else {
            throw ValidationError.invalidEnvironment
        }

        let root = URL(fileURLWithPath: rawRoot, isDirectory: true)
        let home = root.appendingPathComponent("home", isDirectory: true)
        let temporaryDirectory = root.appendingPathComponent("temp", isDirectory: true)
        let library = home.appendingPathComponent("Library", isDirectory: true)
        let supportParent = library.appendingPathComponent("Application Support", isDirectory: true)
        let applicationSupport = supportParent.appendingPathComponent("Local Harness", isDirectory: true)
        guard let rawModelStore = environment[modelStoreEnvironmentKey],
              !rawModelStore.isEmpty,
              rawModelStore.utf8.count <= 1_024,
              !rawModelStore.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else {
            throw ValidationError.invalidEnvironment
        }
        let modelStore = URL(fileURLWithPath: rawModelStore, isDirectory: true)
        guard root.path == rawRoot,
              modelStore.path == rawModelStore,
              environment["HOME"] == home.path,
              environment["CFFIXED_USER_HOME"] == home.path,
              environment["TMPDIR"] == temporaryDirectory.path else {
            throw ValidationError.invalidEnvironment
        }

        guard root.deletingLastPathComponent().path == "/private/tmp",
              root.lastPathComponent.hasPrefix(rootLeafPrefix),
              root.lastPathComponent.utf8.count > rootLeafPrefix.utf8.count,
              securePrivateDirectory(root),
              securePrivateDirectory(home),
              securePrivateDirectory(temporaryDirectory),
              securePrivateDirectory(library),
              securePrivateDirectory(supportParent),
              securePrivateDirectory(applicationSupport),
              canonicalPath(root.path) == root.path,
              canonicalPath(home.path) == home.path,
              canonicalPath(temporaryDirectory.path) == temporaryDirectory.path,
              modelStore.lastPathComponent == "models",
              modelStore.deletingLastPathComponent().lastPathComponent == ".ollama",
              secureReadOnlySourceDirectory(modelStore),
              canonicalPath(modelStore.path) == modelStore.path else {
            throw ValidationError.unsafeRoot
        }

        guard let runtimeDirectories = suppliedRuntimeDirectories ?? RuntimeDirectories.current(),
              canonicalPath(runtimeDirectories.fileManagerHome.path) == home.path,
              canonicalPath(runtimeDirectories.foundationHome.path) == home.path,
              canonicalPath(runtimeDirectories.applicationSupport.path) == supportParent.path,
              canonicalPath(runtimeDirectories.temporaryDirectory.path) == temporaryDirectory.path else {
            throw ValidationError.invalidEnvironment
        }

        return Self(
            mode: requestsBackground ? .background : .foreground,
            root: root,
            home: home,
            temporaryDirectory: temporaryDirectory,
            applicationSupport: applicationSupport,
            modelStore: modelStore
        )
    }

    var foregroundArguments: [String] { [Self.foregroundArgument] }

    /// Never inherit the complete scheduler environment. In particular, API
    /// keys, SSH agent sockets, dynamic-loader controls and test-runner state
    /// are intentionally absent.
    var foregroundEnvironment: [String: String] {
        [
            Self.rootEnvironmentKey: root.path,
            Self.modelStoreEnvironmentKey: modelStore.path,
            "HOME": home.path,
            "CFFIXED_USER_HOME": home.path,
            "TMPDIR": temporaryDirectory.path
        ]
    }

    var foregroundReadyFile: URL {
        root.appendingPathComponent(Self.foregroundReadyFileName, isDirectory: false)
    }

    func publishForegroundReady(selection: ModelSelection, boundary: DataBoundary) throws {
        guard mode == .foreground,
              selection.route == ModelSelection.defaultLocal.route,
              boundary == .onDevice,
              Self.securePrivateDirectory(root),
              Self.canonicalPath(root.path) == root.path else {
            throw ValidationError.publicationFailed
        }
        let payload = try JSONSerialization.data(
            withJSONObject: [
                "schemaVersion": 1,
                "state": "ready",
                "provider": selection.route.provider.rawValue,
                "model": selection.route.model.rawValue,
                "boundary": boundary.rawValue
            ],
            options: [.sortedKeys]
        )
        let descriptor = Darwin.open(
            foregroundReadyFile.path,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            0o600
        )
        guard descriptor >= 0 else { throw ValidationError.publicationFailed }
        var closeRequired = true
        defer { if closeRequired { _ = Darwin.close(descriptor) } }
        let written = payload.withUnsafeBytes { buffer -> Bool in
            guard let base = buffer.baseAddress else { return payload.isEmpty }
            var offset = 0
            while offset < buffer.count {
                let result = Darwin.write(descriptor, base.advanced(by: offset), buffer.count - offset)
                if result > 0 { offset += result; continue }
                if result < 0, errno == EINTR { continue }
                return false
            }
            return true
        }
        guard written, Darwin.fsync(descriptor) == 0, Darwin.close(descriptor) == 0 else {
            throw ValidationError.publicationFailed
        }
        closeRequired = false
        var metadata = stat()
        guard Darwin.lstat(foregroundReadyFile.path, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_uid == geteuid(),
              metadata.st_nlink == 1,
              metadata.st_mode & 0o777 == 0o600 else {
            throw ValidationError.publicationFailed
        }
    }

    private static func securePrivateDirectory(_ url: URL) -> Bool {
        var metadata = stat()
        return Darwin.lstat(url.path, &metadata) == 0
            && metadata.st_mode & S_IFMT == S_IFDIR
            && metadata.st_uid == geteuid()
            && metadata.st_nlink >= 2
            && metadata.st_mode & 0o777 == 0o700
    }

    private static func secureReadOnlySourceDirectory(_ url: URL) -> Bool {
        var metadata = stat()
        return Darwin.lstat(url.path, &metadata) == 0
            && metadata.st_mode & S_IFMT == S_IFDIR
            && metadata.st_uid == geteuid()
            && metadata.st_nlink >= 2
            && metadata.st_mode & (S_IWGRP | S_IWOTH) == 0
    }

    private static func canonicalPath(_ path: String) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(PATH_MAX))
        guard Darwin.realpath(path, &buffer) != nil else { return nil }
        return String(cString: buffer)
    }
}
