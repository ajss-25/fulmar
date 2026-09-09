import Foundation

enum StatusItemAcceptanceSupport {
    enum InteractiveSessionState: Equatable {
        case ready
        case secureOrWrongUser
        case indeterminate
    }

    enum InteractiveTransportDisposition: Equatable {
        case accepted
        case environmentallyDeferred
        case candidateFailure
    }

    enum InteractiveTimeoutDisposition: Equatable {
        case environmentallyDeferred
        case candidateFailure
    }

    enum SafetyExitDisposition: Equatable {
        case deferred
        case hardFailure
    }

    struct ProcessInventoryObservation: Equatable {
        let launchedIdentityRunning: Bool
        let capturedChildRunning: Bool
        let targetInventoryComplete: Bool
        let targetOwnedProcessCount: Int
        let runtimeInventoryComplete: Bool
        let candidateRuntimeProcessCount: Int
    }

    enum OpenRequestResolution<Payload> {
        case pending
        case completed(payload: Payload?, errorDescription: String?)
    }

    final class OpenRequestBarrier<Payload>: @unchecked Sendable {
        let generation = UUID()

        private let lock = NSLock()
        private var resolution: OpenRequestResolution<Payload> = .pending

        @discardableResult
        func resolve(
            generation suppliedGeneration: UUID,
            payload: Payload?,
            errorDescription: String?
        ) -> Bool {
            lock.lock()
            defer { lock.unlock() }
            guard suppliedGeneration == generation,
                  case .pending = resolution else { return false }
            resolution = .completed(payload: payload, errorDescription: errorDescription)
            return true
        }

        func snapshot() -> OpenRequestResolution<Payload> {
            lock.lock()
            defer { lock.unlock() }
            return resolution
        }
    }

    enum PIDBufferDisposition: Equatable {
        case complete(count: Int)
        case grow(nextCapacity: Int)
        case invalid
    }

    static func boundedPIDCount(reportedCount: Int32, capacity: Int) -> Int {
        guard reportedCount > 0, capacity > 0 else { return 0 }
        return min(Int(reportedCount), capacity)
    }

    static func pidBufferDisposition(
        reportedCount: Int32,
        capacity: Int,
        canRetry: Bool
    ) -> PIDBufferDisposition {
        guard reportedCount > 0, capacity > 0 else { return .invalid }
        let count = boundedPIDCount(reportedCount: reportedCount, capacity: capacity)
        if count < capacity { return .complete(count: count) }
        guard canRetry, capacity <= Int.max / 2 else { return .invalid }
        return .grow(nextCapacity: capacity * 2)
    }

    static func decodeProcessPath(buffer: [CChar], reportedLength: Int32) -> String? {
        let length = Int(reportedLength)
        guard length > 0,
              length < buffer.count,
              buffer[length] == 0 else { return nil }
        let bytes = buffer.prefix(length).prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        guard !bytes.isEmpty else { return nil }
        return String(bytes: bytes, encoding: .utf8)
    }

    static func isBundleMainExecutable(
        executablePath: String,
        bundlePath: String,
        executableName: String
    ) -> Bool {
        guard !executableName.isEmpty,
              executableName != ".",
              executableName != "..",
              !executableName.contains("/"),
              !executableName.contains("\\"),
              URL(fileURLWithPath: bundlePath).pathExtension == "app" else { return false }
        let supplied = URL(fileURLWithPath: executablePath)
            .standardizedFileURL
            .resolvingSymlinksInPath()
        let expected = URL(fileURLWithPath: bundlePath, isDirectory: true)
            .appendingPathComponent("Contents", isDirectory: true)
            .appendingPathComponent("MacOS", isDirectory: true)
            .appendingPathComponent(executableName, isDirectory: false)
            .standardizedFileURL
            .resolvingSymlinksInPath()
        return supplied == expected
    }

    static func frameIntersectsVisibleDisplay(_ frame: CGRect, displays: [CGRect]) -> Bool {
        guard frame.width > 0, frame.height > 0 else { return false }
        return displays.contains { display in
            guard display.width > 0, display.height > 0 else { return false }
            let intersection = frame.intersection(display)
            return !intersection.isNull && intersection.width > 0 && intersection.height > 0
        }
    }

    /// AppKit exposes a titled window with a subtitle to Accessibility as
    /// "<title> – <subtitle>" on current macOS releases. The Agent Workspace
    /// deliberately changes that subtitle when the selected model route
    /// changes, while every other acceptance window has a stable exact title.
    static func windowNames(
        _ names: [String],
        matchExpectedTitle expectedTitle: String,
        productName: String
    ) -> Bool {
        guard !expectedTitle.isEmpty, !productName.isEmpty else { return false }
        if names.contains(expectedTitle) { return true }
        guard expectedTitle == productName else { return false }
        let dynamicMainWindowPrefix = "\(productName) – "
        return names.contains { name in
            guard name.hasPrefix(dynamicMainWindowPrefix) else { return false }
            return !name.dropFirst(dynamicMainWindowPrefix.count)
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .isEmpty
        }
    }

    static func interactiveSessionIsReady(
        onConsole: Bool?,
        loginDone: Bool?,
        sessionUserID: UInt32?,
        effectiveUserID: UInt32,
        frontmostBundleIdentifier: String?,
        menuBarOwnerBundleIdentifier: String?
    ) -> Bool {
        interactiveSessionState(
            onConsole: onConsole,
            loginDone: loginDone,
            sessionUserID: sessionUserID,
            effectiveUserID: effectiveUserID,
            frontmostBundleIdentifier: frontmostBundleIdentifier,
            menuBarOwnerBundleIdentifier: menuBarOwnerBundleIdentifier
        ) == .ready
    }

    static func interactiveTransportDisposition(
        transportAccepted: Bool,
        postActionSessionState: InteractiveSessionState
    ) -> InteractiveTransportDisposition {
        guard postActionSessionState == .ready else {
            return .environmentallyDeferred
        }
        return transportAccepted ? .accepted : .candidateFailure
    }

    static func interactiveTimeoutDisposition(
        postSleepSessionState: InteractiveSessionState
    ) -> InteractiveTimeoutDisposition {
        postSleepSessionState == .ready
            ? .candidateFailure
            : .environmentallyDeferred
    }

    static func safetyExitDisposition(
        openRequestSettled: Bool,
        cleanupComplete: Bool,
        disposableStateRemoved: Bool
    ) -> SafetyExitDisposition {
        guard openRequestSettled, cleanupComplete, disposableStateRemoved else {
            return .hardFailure
        }
        return .deferred
    }

    static func processInventoryIsQuiescent(
        _ observation: ProcessInventoryObservation
    ) -> Bool {
        !observation.launchedIdentityRunning
            && !observation.capturedChildRunning
            && observation.targetInventoryComplete
            && observation.targetOwnedProcessCount == 0
            && observation.runtimeInventoryComplete
            && observation.candidateRuntimeProcessCount == 0
    }

    static func interactiveSessionState(
        onConsole: Bool?,
        loginDone: Bool?,
        sessionUserID: UInt32?,
        effectiveUserID: UInt32,
        frontmostBundleIdentifier: String?,
        menuBarOwnerBundleIdentifier: String?
    ) -> InteractiveSessionState {
        guard let onConsole, let loginDone, let sessionUserID else {
            return .indeterminate
        }
        guard onConsole, loginDone, sessionUserID == effectiveUserID else {
            return .secureOrWrongUser
        }

        func isSecureSessionOwner(_ identifier: String) -> Bool {
            identifier == "com.apple.loginwindow"
                || identifier.hasPrefix("com.apple.ScreenSaver")
        }
        if let frontmostBundleIdentifier,
           isSecureSessionOwner(frontmostBundleIdentifier) {
            return .secureOrWrongUser
        }
        if let menuBarOwnerBundleIdentifier,
           isSecureSessionOwner(menuBarOwnerBundleIdentifier) {
            return .secureOrWrongUser
        }
        guard let frontmostBundleIdentifier,
              !frontmostBundleIdentifier.isEmpty,
              let menuBarOwnerBundleIdentifier,
              !menuBarOwnerBundleIdentifier.isEmpty else {
            return .indeterminate
        }
        return .ready
    }
}
