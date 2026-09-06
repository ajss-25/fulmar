import Darwin
import Foundation
import LocalHarnessCredentialMigrationXPCProtocol

enum CredentialMigrationXPCAcceptanceLaunchError: Error, Equatable, Sendable {
    case invalidArguments
    case invalidPackagedLayout
}

struct CredentialMigrationXPCAcceptanceLaunchConfiguration: Equatable, Sendable {
    let serviceBundleURL: URL
    let helperURL: URL
}

/// Runs the migration-service physical canary before AppKit, WebKit, the DSH
/// runtime, provider state, or ordinary startup maintenance can be created.
/// The one-shot wire contract intentionally emits only a fixed sentinel or a
/// fixed generic failure followed, for known typed failures only, by a fixed
/// category. Paths, identities, provider references, and arbitrary error text
/// never cross stdout/stderr.
enum CredentialMigrationXPCAcceptanceLaunch {
    static let successSentinel = "FULMAR_CREDENTIAL_XPC_ACCEPTANCE_OK\n"
    static let genericFailure = "Fulmar credential XPC acceptance failed.\n"

    typealias Invocation = (
        _ serviceBundleURL: URL,
        _ helperURL: URL
    ) throws -> Void

    static func runIfRequested(
        arguments: [String],
        executableURL: URL,
        standardOutput: FileHandle = .standardOutput,
        standardError: FileHandle = .standardError,
        invocation: Invocation = { service, helper in
            try CredentialMigrationXPCAcceptanceCoordinator.run(
                serviceBundleURL: service,
                helperURL: helper
            )
        }
    ) -> Int32? {
        let requested = arguments.contains(CredentialMigrationXPCAcceptanceCoordinator.launchArgument)
        do {
            guard let configuration = try configurationIfRequested(
                arguments: arguments,
                executableURL: executableURL
            ) else { return nil }
            try invocation(configuration.serviceBundleURL, configuration.helperURL)
            standardOutput.write(Data(successSentinel.utf8))
            return EX_OK
        } catch {
            guard requested else { return nil }
            standardError.write(Data(failureMessage(for: error).utf8))
            return EX_CONFIG
        }
    }

    /// A failed physical canary must distinguish its boundary without printing
    /// localizedDescription, NSError contents, associated paths, or identities.
    /// Unknown errors retain the original generic-only response.
    static func failureMessage(for error: any Error) -> String {
        let category: String
        switch error {
        case let failure as CredentialMigrationXPCClientError:
            switch failure {
            case .serviceMissing: category = "client-service-missing"
            case .serviceIdentityMismatch: category = "client-service-identity-mismatch"
            case .invalidCapabilities: category = "client-invalid-capabilities"
            case .unavailable: category = "client-unavailable"
            case .interrupted: category = "client-interrupted"
            case .timedOut: category = "client-timed-out"
            case .sourceChanged: category = "client-source-changed"
            case .invalidResponse: category = "client-invalid-response"
            case .service(let status):
                // This is a closed protocol enum, never service-provided text.
                category = "service-" + status.rawValue
            }
        case let failure as CredentialMigrationXPCAcceptanceError:
            switch failure {
            case .invalidConfiguration: category = "canary-invalid-configuration"
            case .unsafeFixture: category = "canary-unsafe-fixture"
            case .invalidResponse: category = "canary-invalid-response"
            case .cleanupFailed: category = "canary-cleanup-failed"
            }
        default:
            return genericFailure
        }
        return genericFailure + "FULMAR_CREDENTIAL_XPC_FAILURE=" + category + "\n"
    }

    static func configurationIfRequested(
        arguments: [String],
        executableURL: URL
    ) throws -> CredentialMigrationXPCAcceptanceLaunchConfiguration? {
        let launchArgument = CredentialMigrationXPCAcceptanceCoordinator.launchArgument
        guard arguments.contains(launchArgument) else { return nil }
        guard arguments.count == 2,
              arguments[1] == launchArgument,
              !arguments[0].isEmpty,
              !arguments[0].contains("\0") else {
            throw CredentialMigrationXPCAcceptanceLaunchError.invalidArguments
        }

        // `standardizedFileURL` and `resolvingSymlinksInPath()` both strip the
        // canonical `/private` prefix that `realpath(3)` reports for extracted
        // candidates under `/private/tmp`. Keep the caller's exact spelling and
        // require it to be realpath-canonical instead.
        let executable = executableURL
        let macOSDirectory = executable.deletingLastPathComponent()
        let contents = macOSDirectory.deletingLastPathComponent()
        let application = contents.deletingLastPathComponent()
        let helper = macOSDirectory.appendingPathComponent(
            "LocalHarnessCredentialHelper",
            isDirectory: false
        )
        let service = contents.appendingPathComponent("XPCServices", isDirectory: true)
            .appendingPathComponent(
                CredentialMigrationXPCConstants.serviceBundleName,
                isDirectory: true
            )

        guard executable.isFileURL,
              executable.path.hasPrefix("/"),
              executable.lastPathComponent == "LocalHarness",
              executable.path == arguments[0],
              isCanonicalRealPath(executable),
              macOSDirectory.lastPathComponent == "MacOS",
              contents.lastPathComponent == "Contents",
              application.pathExtension == "app",
              isCanonicalRealPath(application),
              helper.deletingLastPathComponent().path == macOSDirectory.path,
              service.deletingLastPathComponent().lastPathComponent == "XPCServices",
              service.deletingLastPathComponent().deletingLastPathComponent().path
                == contents.path else {
            throw CredentialMigrationXPCAcceptanceLaunchError.invalidPackagedLayout
        }
        return CredentialMigrationXPCAcceptanceLaunchConfiguration(
            serviceBundleURL: service,
            helperURL: helper
        )
    }

    /// Foundation's `resolvingSymlinksInPath()` strips the `/private` prefix
    /// on macOS even though `realpath(3)` reports `/private/tmp` as the
    /// canonical directory. Compare against `realpath(3)` so the packaged
    /// layout check rejects real symlink components without rejecting the
    /// canonical `/private`-prefixed spelling used by extracted candidates.
    private static func isCanonicalRealPath(_ url: URL) -> Bool {
        guard let resolved = url.path.withCString({ Darwin.realpath($0, nil) }) else {
            return false
        }
        defer { free(resolved) }
        return String(cString: resolved) == url.path
    }
}
