import Darwin
import Foundation
import LocalHarnessSandboxPolicy
import Security

public enum SchedulerHelperLaunchError: Error, Equatable {
    case invalidExecutablePath
    case invalidBundleTopology
    case invalidSignature
    case applicationChanged
}

private struct SchedulerLaunchNodeIdentity: Equatable {
    let device: UInt64
    let inode: UInt64
    let mode: mode_t
    let owner: uid_t
    let linkCount: UInt64
    let byteCount: Int64
    let modificationSeconds: Int64
    let modificationNanoseconds: Int64
}

private struct SchedulerStorageNodeIdentity: Equatable {
    let device: UInt64
    let inode: UInt64
    let mode: mode_t
    let owner: uid_t
    let group: gid_t
    let linkCount: UInt64
    let byteCount: Int64
    let modificationSeconds: Int64
    let modificationNanoseconds: Int64
    let changeSeconds: Int64
    let changeNanoseconds: Int64
}

struct SchedulerWakePolicyTestHooks {
    let afterOpeningScheduleDirectory: (() throws -> Void)?
    let afterOpeningSchedulesFile: (() throws -> Void)?

    init(
        afterOpeningScheduleDirectory: (() throws -> Void)? = nil,
        afterOpeningSchedulesFile: (() throws -> Void)? = nil
    ) {
        self.afterOpeningScheduleDirectory = afterOpeningScheduleDirectory
        self.afterOpeningSchedulesFile = afterOpeningSchedulesFile
    }
}

public struct SchedulerHelperLaunchPlan: Equatable {
    public let applicationURL: URL
    public let openArguments: [String]
    fileprivate let topology: [SchedulerLaunchNodeIdentity]
}

/// Fail-closed decision logic for the minute-scale launchd helper. It validates
/// both private storage and the supported schedule schema before the helper is
/// allowed to wake the heavyweight app runtime.
public enum SchedulerWakePolicy {
    public static let maximumDocumentBytes = 5 * 1_024 * 1_024
    public static let maximumScheduleCount = 1_000
    public static let applicationBundleIdentifier = "com.angadjairath.localharness"

    /// Runs the exact Launch Services handoff as its own process group. A wedged
    /// `open` process can no longer suppress every later StartInterval wake.
    public static func runLaunchProcess(
        executable: URL = URL(fileURLWithPath: "/usr/bin/open"),
        arguments: [String],
        environment: [String: String],
        deadline: TimeInterval = 15,
        terminationGrace: TimeInterval = 0.25,
        onSpawn: ((pid_t) -> Void)? = nil
    ) -> Int32 {
        guard let result = try? BoundedProcessGroupRunner.run(
            executable: executable,
            arguments: arguments,
            environment: environment,
            maximumStderrBytes: 64 * 1_024,
            deadline: deadline,
            terminationGrace: terminationGrace,
            discardStandardOutput: true,
            onSpawn: onSpawn
        ), result.limit == nil, result.terminationSignal == nil else { return 1 }
        return result.exitStatus ?? 1
    }

    /// Resolves the kernel-reported executable path instead of trusting argv,
    /// cwd, Launch Services registration, or an ambient bundle identifier.
    public static func currentExecutableURL() -> URL? {
        var capacity = UInt32(PATH_MAX)
        var bytes = [CChar](repeating: 0, count: Int(capacity))
        if _NSGetExecutablePath(&bytes, &capacity) != 0 {
            bytes = [CChar](repeating: 0, count: Int(capacity))
            guard _NSGetExecutablePath(&bytes, &capacity) == 0 else { return nil }
        }
        return URL(fileURLWithPath: String(cString: bytes), isDirectory: false).standardizedFileURL
    }

    /// Builds a plan for the one exact enclosing app copy. The injectable
    /// validator is a deterministic test seam; production uses nested strict
    /// code-signature validation below.
    public static func launchPlan(
        helperExecutable: URL,
        signatureValidator: (_ application: URL, _ helper: URL) -> Bool
    ) throws -> SchedulerHelperLaunchPlan {
        let application = try enclosingApplication(for: helperExecutable)
        let before = try captureLaunchTopology(application: application, helper: helperExecutable)
        guard signatureValidator(application, helperExecutable) else {
            throw SchedulerHelperLaunchError.invalidSignature
        }
        let after = try captureLaunchTopology(application: application, helper: helperExecutable)
        guard before == after else { throw SchedulerHelperLaunchError.applicationChanged }
        return SchedulerHelperLaunchPlan(
            applicationURL: application,
            openArguments: ["-gj", application.path, "--args", "--background-schedule"],
            topology: after
        )
    }

    public static func validatedLaunchPlan(
        helperExecutable: URL
    ) throws -> SchedulerHelperLaunchPlan {
        try launchPlan(
            helperExecutable: helperExecutable,
            signatureValidator: strictNestedSignatureIsValid(application:helper:)
        )
    }

    /// Re-lstats and revalidates the exact same paths immediately before
    /// handing the absolute app URL to `/usr/bin/open`.
    public static func revalidate(
        _ plan: SchedulerHelperLaunchPlan,
        helperExecutable: URL,
        signatureValidator: (_ application: URL, _ helper: URL) -> Bool
    ) throws {
        let application = try enclosingApplication(for: helperExecutable)
        guard application == plan.applicationURL else {
            throw SchedulerHelperLaunchError.applicationChanged
        }
        let before = try captureLaunchTopology(application: application, helper: helperExecutable)
        guard before == plan.topology,
              signatureValidator(application, helperExecutable) else {
            throw SchedulerHelperLaunchError.applicationChanged
        }
        let after = try captureLaunchTopology(application: application, helper: helperExecutable)
        guard after == plan.topology else { throw SchedulerHelperLaunchError.applicationChanged }
    }

    public static func revalidate(
        _ plan: SchedulerHelperLaunchPlan,
        helperExecutable: URL
    ) throws {
        try revalidate(
            plan,
            helperExecutable: helperExecutable,
            signatureValidator: strictNestedSignatureIsValid(application:helper:)
        )
    }

    public static func shouldWake(
        schedulesURL: URL,
        now: Date = Date()
    ) -> Bool {
        shouldWake(schedulesURL: schedulesURL, now: now, hooks: SchedulerWakePolicyTestHooks())
    }

    static func shouldWake(
        schedulesURL: URL,
        now: Date,
        hooks: SchedulerWakePolicyTestHooks
    ) -> Bool {
        guard let data = readPrivateRegularFile(schedulesURL, hooks: hooks),
              let schedules = try? JSONDecoder().decode([WakeSchedule].self, from: data),
              schedules.count <= maximumScheduleCount else {
            return false
        }
        return schedules.contains { $0.enabled && $0.nextRun <= now }
    }

    private static func enclosingApplication(for helper: URL) throws -> URL {
        guard helper.isFileURL,
              helper.path.hasPrefix("/"),
              helper.path == helper.standardizedFileURL.path,
              helper.lastPathComponent == "LocalHarnessSchedulerHelper" else {
            throw SchedulerHelperLaunchError.invalidExecutablePath
        }
        let macOS = helper.deletingLastPathComponent()
        let contents = macOS.deletingLastPathComponent()
        let application = contents.deletingLastPathComponent()
        guard macOS.lastPathComponent == "MacOS",
              contents.lastPathComponent == "Contents",
              application.pathExtension == "app",
              application.deletingLastPathComponent() != application,
              helper.resolvingSymlinksInPath().standardizedFileURL == helper.standardizedFileURL,
              application.resolvingSymlinksInPath().standardizedFileURL == application.standardizedFileURL else {
            throw SchedulerHelperLaunchError.invalidBundleTopology
        }
        return application.standardizedFileURL
    }

    private static func captureLaunchTopology(
        application: URL,
        helper: URL
    ) throws -> [SchedulerLaunchNodeIdentity] {
        let contents = application.appendingPathComponent("Contents", isDirectory: true)
        let macOS = contents.appendingPathComponent("MacOS", isDirectory: true)
        let info = contents.appendingPathComponent("Info.plist", isDirectory: false)
        let nodes: [(URL, mode_t)] = [
            (application, mode_t(S_IFDIR)),
            (contents, mode_t(S_IFDIR)),
            (macOS, mode_t(S_IFDIR)),
            (helper, mode_t(S_IFREG)),
            (info, mode_t(S_IFREG))
        ]
        return try nodes.map { url, expectedType in
            var value = stat()
            guard lstat(url.path, &value) == 0,
                  (value.st_mode & S_IFMT) == expectedType,
                  (value.st_uid == 0 || value.st_uid == geteuid()),
                  (value.st_mode & 0o022) == 0,
                  (expectedType != S_IFREG || value.st_nlink == 1),
                  (url != helper || (value.st_mode & 0o111) != 0) else {
                throw SchedulerHelperLaunchError.invalidBundleTopology
            }
            return SchedulerLaunchNodeIdentity(
                device: UInt64(truncatingIfNeeded: value.st_dev),
                inode: UInt64(value.st_ino),
                mode: value.st_mode,
                owner: value.st_uid,
                linkCount: UInt64(value.st_nlink),
                byteCount: Int64(value.st_size),
                modificationSeconds: Int64(value.st_mtimespec.tv_sec),
                modificationNanoseconds: Int64(value.st_mtimespec.tv_nsec)
            )
        }
    }

    private static func strictNestedSignatureIsValid(
        application: URL,
        helper: URL
    ) -> Bool {
        var appCode: SecStaticCode?
        var helperCode: SecStaticCode?
        let strictFlags = SecCSFlags(
            rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate | kSecCSCheckNestedCode
        )
        guard SecStaticCodeCreateWithPath(application as CFURL, [], &appCode) == errSecSuccess,
              let appCode,
              SecStaticCodeCheckValidity(appCode, strictFlags, nil) == errSecSuccess,
              SecStaticCodeCreateWithPath(helper as CFURL, [], &helperCode) == errSecSuccess,
              let helperCode,
              SecStaticCodeCheckValidity(
                helperCode,
                SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate),
                nil
              ) == errSecSuccess else { return false }

        var information: CFDictionary?
        guard SecCodeCopySigningInformation(
            appCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &information
        ) == errSecSuccess,
              let values = information as? [String: Any],
              values[kSecCodeInfoIdentifier as String] as? String == applicationBundleIdentifier,
              let cdHash = values[kSecCodeInfoUnique as String] as? Data,
              !cdHash.isEmpty,
              cdHash.count <= 64 else { return false }
        return true
    }

    private static func readPrivateRegularFile(
        _ url: URL,
        hooks: SchedulerWakePolicyTestHooks
    ) -> Data? {
        guard url.isFileURL,
              url.path.hasPrefix("/"),
              url.path == url.standardizedFileURL.path else { return nil }

        let scheduleDirectoryURL = url.deletingLastPathComponent()
        let applicationSupportURL = scheduleDirectoryURL.deletingLastPathComponent()
        let scheduleDirectoryName = scheduleDirectoryURL.lastPathComponent
        let schedulesFileName = url.lastPathComponent
        guard applicationSupportURL != scheduleDirectoryURL,
              scheduleDirectoryURL != url,
              validLeaf(scheduleDirectoryName),
              validLeaf(schedulesFileName) else { return nil }

        var declaredApplicationSupport = stat()
        guard lstat(applicationSupportURL.path, &declaredApplicationSupport) == 0,
              securePrivateDirectory(declaredApplicationSupport) else { return nil }
        let applicationSupportIdentity = storageIdentity(declaredApplicationSupport)
        let applicationSupportDescriptor = open(
            applicationSupportURL.path,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
        )
        guard applicationSupportDescriptor >= 0 else { return nil }
        defer { _ = close(applicationSupportDescriptor) }

        var openedApplicationSupport = stat()
        guard fstat(applicationSupportDescriptor, &openedApplicationSupport) == 0,
              securePrivateDirectory(openedApplicationSupport),
              storageIdentity(openedApplicationSupport) == applicationSupportIdentity,
              descriptorHasNoExtendedACL(applicationSupportDescriptor) else { return nil }

        var declaredScheduleDirectory = stat()
        guard scheduleDirectoryName.withCString({
            fstatat(
                applicationSupportDescriptor,
                $0,
                &declaredScheduleDirectory,
                AT_SYMLINK_NOFOLLOW
            )
        }) == 0,
              securePrivateDirectory(declaredScheduleDirectory) else { return nil }
        let scheduleDirectoryIdentity = storageIdentity(declaredScheduleDirectory)
        let scheduleDirectoryDescriptor = scheduleDirectoryName.withCString {
            openat(
                applicationSupportDescriptor,
                $0,
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
            )
        }
        guard scheduleDirectoryDescriptor >= 0 else { return nil }
        defer { _ = close(scheduleDirectoryDescriptor) }

        var openedScheduleDirectory = stat()
        var reboundScheduleDirectory = stat()
        guard fstat(scheduleDirectoryDescriptor, &openedScheduleDirectory) == 0,
              securePrivateDirectory(openedScheduleDirectory),
              storageIdentity(openedScheduleDirectory) == scheduleDirectoryIdentity,
              scheduleDirectoryName.withCString({
                  fstatat(
                      applicationSupportDescriptor,
                      $0,
                      &reboundScheduleDirectory,
                      AT_SYMLINK_NOFOLLOW
                  )
              }) == 0,
              storageIdentity(reboundScheduleDirectory) == scheduleDirectoryIdentity,
              descriptorHasNoExtendedACL(scheduleDirectoryDescriptor) else { return nil }

        if let hook = hooks.afterOpeningScheduleDirectory {
            do { try hook() } catch { return nil }
        }

        var declaredSchedulesFile = stat()
        guard schedulesFileName.withCString({
            fstatat(
                scheduleDirectoryDescriptor,
                $0,
                &declaredSchedulesFile,
                AT_SYMLINK_NOFOLLOW
            )
        }) == 0,
              securePrivateRegularFile(declaredSchedulesFile) else { return nil }
        let schedulesFileIdentity = storageIdentity(declaredSchedulesFile)
        let schedulesFileDescriptor = schedulesFileName.withCString {
            openat(
                scheduleDirectoryDescriptor,
                $0,
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
            )
        }
        guard schedulesFileDescriptor >= 0 else { return nil }
        defer { _ = close(schedulesFileDescriptor) }

        var openedSchedulesFile = stat()
        var reboundSchedulesFile = stat()
        guard fstat(schedulesFileDescriptor, &openedSchedulesFile) == 0,
              securePrivateRegularFile(openedSchedulesFile),
              storageIdentity(openedSchedulesFile) == schedulesFileIdentity,
              schedulesFileName.withCString({
                  fstatat(
                      scheduleDirectoryDescriptor,
                      $0,
                      &reboundSchedulesFile,
                      AT_SYMLINK_NOFOLLOW
                  )
              }) == 0,
              storageIdentity(reboundSchedulesFile) == schedulesFileIdentity,
              descriptorHasNoExtendedACL(schedulesFileDescriptor) else { return nil }

        if let hook = hooks.afterOpeningSchedulesFile {
            do { try hook() } catch { return nil }
        }

        let expected = Int(openedSchedulesFile.st_size)
        var bytes = [UInt8](repeating: 0, count: expected)
        var offset = 0
        while offset < expected {
            let count = bytes.withUnsafeMutableBytes { buffer in
                Darwin.read(
                    schedulesFileDescriptor,
                    buffer.baseAddress!.advanced(by: offset),
                    expected - offset
                )
            }
            if count < 0 {
                if errno == EINTR { continue }
                return nil
            }
            guard count > 0 else { return nil }
            offset += count
        }

        var trailing: UInt8 = 0
        while true {
            let count = Darwin.read(schedulesFileDescriptor, &trailing, 1)
            if count < 0, errno == EINTR { continue }
            guard count == 0 else { return nil }
            break
        }

        var finalSchedulesFile = stat()
        var finalNamedSchedulesFile = stat()
        var finalScheduleDirectory = stat()
        var finalNamedScheduleDirectory = stat()
        var finalApplicationSupport = stat()
        var finalNamedApplicationSupport = stat()
        guard fstat(schedulesFileDescriptor, &finalSchedulesFile) == 0,
              securePrivateRegularFile(finalSchedulesFile),
              storageIdentity(finalSchedulesFile) == schedulesFileIdentity,
              schedulesFileName.withCString({
                  fstatat(
                      scheduleDirectoryDescriptor,
                      $0,
                      &finalNamedSchedulesFile,
                      AT_SYMLINK_NOFOLLOW
                  )
              }) == 0,
              storageIdentity(finalNamedSchedulesFile) == schedulesFileIdentity,
              descriptorHasNoExtendedACL(schedulesFileDescriptor),
              fstat(scheduleDirectoryDescriptor, &finalScheduleDirectory) == 0,
              securePrivateDirectory(finalScheduleDirectory),
              storageIdentity(finalScheduleDirectory) == scheduleDirectoryIdentity,
              scheduleDirectoryName.withCString({
                  fstatat(
                      applicationSupportDescriptor,
                      $0,
                      &finalNamedScheduleDirectory,
                      AT_SYMLINK_NOFOLLOW
                  )
              }) == 0,
              storageIdentity(finalNamedScheduleDirectory) == scheduleDirectoryIdentity,
              descriptorHasNoExtendedACL(scheduleDirectoryDescriptor),
              fstat(applicationSupportDescriptor, &finalApplicationSupport) == 0,
              securePrivateDirectory(finalApplicationSupport),
              storageIdentity(finalApplicationSupport) == applicationSupportIdentity,
              lstat(applicationSupportURL.path, &finalNamedApplicationSupport) == 0,
              storageIdentity(finalNamedApplicationSupport) == applicationSupportIdentity,
              descriptorHasNoExtendedACL(applicationSupportDescriptor) else { return nil }
        return Data(bytes)
    }

    private static func validLeaf(_ value: String) -> Bool {
        !value.isEmpty && value != "." && value != ".." &&
            !value.contains("/") && !value.contains("\0")
    }

    private static func securePrivateDirectory(_ value: stat) -> Bool {
        (value.st_mode & S_IFMT) == S_IFDIR &&
            value.st_uid == geteuid() &&
            (value.st_mode & 0o077) == 0
    }

    private static func securePrivateRegularFile(_ value: stat) -> Bool {
        (value.st_mode & S_IFMT) == S_IFREG &&
            value.st_uid == geteuid() &&
            value.st_nlink == 1 &&
            (value.st_mode & 0o077) == 0 &&
            value.st_size >= 0 &&
            value.st_size <= off_t(maximumDocumentBytes)
    }

    private static func descriptorHasNoExtendedACL(_ descriptor: Int32) -> Bool {
        errno = 0
        guard let accessControlList = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
            return errno == ENOENT
        }
        _ = acl_free(UnsafeMutableRawPointer(accessControlList))
        return false
    }

    private static func storageIdentity(_ value: stat) -> SchedulerStorageNodeIdentity {
        SchedulerStorageNodeIdentity(
            device: UInt64(truncatingIfNeeded: value.st_dev),
            inode: UInt64(value.st_ino),
            mode: value.st_mode,
            owner: value.st_uid,
            group: value.st_gid,
            linkCount: UInt64(value.st_nlink),
            byteCount: Int64(value.st_size),
            modificationSeconds: Int64(value.st_mtimespec.tv_sec),
            modificationNanoseconds: Int64(value.st_mtimespec.tv_nsec),
            changeSeconds: Int64(value.st_ctimespec.tv_sec),
            changeNanoseconds: Int64(value.st_ctimespec.tv_nsec)
        )
    }
}

private struct WakeSchedule: Decodable {
    private static let currentSchemaVersion = 2

    let enabled: Bool
    let nextRun: Date
    /// Retained so v2 unattended consent can be bound to the exact decoded
    /// provider/model route. The helper does not resolve provider catalogs or
    /// endpoints; the main ScheduleManager remains authoritative for those.
    let selection: WakeSelection?

    private enum CodingKeys: String, CodingKey {
        case schemaVersion, id, title, prompt, model, selection, boundary
        case unattendedConsent, intervalSeconds, timeoutSeconds, nextRun, enabled, lastRun
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let version = try container.decodeIfPresent(Int.self, forKey: .schemaVersion)
        let decodedEnabled = try container.decode(Bool.self, forKey: .enabled)
        _ = try container.decode(UUID.self, forKey: .id)
        let title = try container.decode(String.self, forKey: .title)
        let prompt = try container.decode(String.self, forKey: .prompt)
        guard Self.safeTitle(title), Self.safePrompt(prompt) else {
            throw WakeValidationError.invalidDocument
        }

        let interval = try container.decode(TimeInterval.self, forKey: .intervalSeconds)
        let normalizedInterval = version == nil && interval > 0 ? max(60, interval) : interval
        guard Self.validInterval(normalizedInterval) else { throw WakeValidationError.invalidDocument }

        if version == nil {
            guard !container.contains(.selection),
                  !container.contains(.boundary),
                  !container.contains(.unattendedConsent) else {
                throw WakeValidationError.invalidDocument
            }
            guard Self.safeIdentifier(try container.decode(String.self, forKey: .model)) else {
                throw WakeValidationError.invalidDocument
            }
            selection = nil
        } else {
            guard version == Self.currentSchemaVersion else { throw WakeValidationError.invalidDocument }
            let decodedSelection = try container.decode(WakeSelection.self, forKey: .selection)
            let boundary = try container.decode(WakeBoundary.self, forKey: .boundary)
            let consent = try container.decodeIfPresent(
                WakeConsent.self,
                forKey: .unattendedConsent
            )
            switch boundary {
            case .onDevice:
                guard consent == nil else { throw WakeValidationError.invalidDocument }
            case .localNetwork, .cloud:
                guard !decodedEnabled || consent?.valid(
                    for: decodedSelection,
                    boundary: boundary
                ) == true else {
                    throw WakeValidationError.invalidDocument
                }
            }
            selection = decodedSelection
            let timeout = try container.decode(TimeInterval.self, forKey: .timeoutSeconds)
            guard timeout.isFinite, (30...7_200).contains(timeout) else {
                throw WakeValidationError.invalidDocument
            }
        }

        let decodedNextRun = try container.decode(Date.self, forKey: .nextRun)
        guard decodedNextRun.timeIntervalSinceReferenceDate.isFinite else {
            throw WakeValidationError.invalidDocument
        }
        if let lastRun = try container.decodeIfPresent(Date.self, forKey: .lastRun),
           !lastRun.timeIntervalSinceReferenceDate.isFinite {
            throw WakeValidationError.invalidDocument
        }
        nextRun = decodedNextRun
        enabled = decodedEnabled
    }

    private static func safeTitle(_ value: String) -> Bool {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return !trimmed.isEmpty && trimmed.count <= 200 && !containsControls(trimmed)
    }

    private static func safePrompt(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 200_000
    }

    fileprivate static func safeIdentifier(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 512 && !containsControls(value)
    }

    private static func validInterval(_ value: TimeInterval) -> Bool {
        value.isFinite && (value == 0 || (value >= 60 && value <= 10 * 365 * 86_400))
    }

    private static func containsControls(_ value: String) -> Bool {
        value.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
    }
}

private struct WakeSelection: Decodable {
    let schemaVersion: Int
    let route: WakeRoute
    let reasoningEffort: String?
    let performanceProfile: String

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
        route = try container.decode(WakeRoute.self, forKey: .route)
        reasoningEffort = try container.decodeIfPresent(String.self, forKey: .reasoningEffort)
        performanceProfile = try container.decode(String.self, forKey: .performanceProfile)
        let effortIsSafe = reasoningEffort.map {
            $0.utf8.count <= 512 && !$0.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
        } ?? true
        guard schemaVersion == 1,
              WakeSchedule.safeIdentifier(route.provider),
              WakeSchedule.safeIdentifier(route.model),
              effortIsSafe,
              ["fast", "balanced", "deep", "compatibility"].contains(performanceProfile) else {
            throw WakeValidationError.invalidDocument
        }
    }

    private enum CodingKeys: String, CodingKey {
        case schemaVersion, route, reasoningEffort, performanceProfile
    }
}

private struct WakeRoute: Decodable {
    let provider: String
    let model: String
}

private enum WakeBoundary: String, Decodable {
    case onDevice
    case localNetwork
    case cloud
}

private struct WakeConsent: Decodable {
    let schemaVersion: Int
    let provider: String
    let model: String
    let boundary: WakeBoundary
    let origin: WakeOrigin?
    let grantedAt: Date

    func valid(for selection: WakeSelection, boundary scheduleBoundary: WakeBoundary) -> Bool {
        guard schemaVersion == 2,
              scheduleBoundary != .onDevice,
              boundary == scheduleBoundary,
              provider == selection.route.provider,
              model == selection.route.model,
              WakeSchedule.safeIdentifier(provider),
              WakeSchedule.safeIdentifier(model),
              grantedAt.timeIntervalSinceReferenceDate.isFinite,
              origin?.isValid == true else { return false }
        return true
    }
}

private struct WakeOrigin: Decodable {
    let scheme: String
    let host: String
    let port: Int

    var isValid: Bool {
        guard (scheme == "http" || scheme == "https"),
              !host.isEmpty, host.utf8.count <= 253,
              host == host.lowercased(),
              !host.hasPrefix("["), !host.hasSuffix("]"), !host.hasSuffix("."),
              !host.unicodeScalars.contains(where: {
                  CharacterSet.controlCharacters.contains($0) ||
                      CharacterSet.whitespacesAndNewlines.contains($0)
              }),
              (1...65_535).contains(port) else { return false }
        let serializedHost: String
        if host.contains(":") {
            // Foundation requires bracketed IPv6 literals when a host is
            // assembled with URLComponents, even though ProviderEndpointOrigin
            // deliberately persists the normalized, unbracketed host. Validate
            // the literal before adding URL syntax so arbitrary colon-bearing
            // strings cannot pass via URLComponents' permissive parser.
            var address = in6_addr()
            guard host.withCString({ inet_pton(AF_INET6, $0, &address) }) == 1 else {
                return false
            }
            serializedHost = "[\(host)]"
        } else {
            serializedHost = host
        }
        var components = URLComponents()
        components.scheme = scheme
        components.host = serializedHost
        components.port = port
        guard let url = components.url,
              let reparsed = URLComponents(url: url, resolvingAgainstBaseURL: false),
              reparsed.scheme == scheme,
              reparsed.host.map(Self.normalizedHost) == host,
              reparsed.port == port,
              reparsed.user == nil, reparsed.password == nil,
              reparsed.query == nil, reparsed.fragment == nil else { return false }
        return true
    }

    private static func normalizedHost(_ value: String) -> String {
        value.lowercased()
            .trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
            .trimmingCharacters(in: CharacterSet(charactersIn: "."))
    }
}

private enum WakeValidationError: Error {
    case invalidDocument
}
