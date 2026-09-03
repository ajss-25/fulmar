import AppKit
import WebKit

enum HarnessWebSurfaceFailure: Equatable, Sendable {
    case navigationUnavailable
    case navigationSecurityFailure
    case freshSessionVerification
    case downloadStagingUnavailable
    case downloadRejected
    case downloadTransferFailed
    case downloadFinalizationFailed
    case downloadPreviewBlocked
    case downloadSaveFailed

    var message: String {
        switch self {
        case .navigationUnavailable:
            return "The Agent Workspace is not reachable yet. Fulmar kept agent work locked; check Local Service Status and try again."
        case .navigationSecurityFailure:
            return "The Agent Workspace could not be displayed securely. Fulmar blocked the page and kept agent work locked."
        case .freshSessionVerification:
            return "Fresh task verification failed. Fulmar could not prove that Harness opened a different empty task, so no prompt was sent."
        case .downloadStagingUnavailable:
            return "Secure download staging is unavailable. Nothing was opened or copied into Downloads."
        case .downloadRejected:
            return "The download did not pass Fulmar's safety checks and was removed."
        case .downloadTransferFailed:
            return "The download transfer did not complete. Any private staging copy was removed."
        case .downloadFinalizationFailed:
            return "The downloaded file could not be validated safely and was removed."
        case .downloadPreviewBlocked:
            return "Preview was blocked because the staged file no longer matched its validated content."
        case .downloadSaveFailed:
            return "The validated download was not saved. No existing file was replaced."
        }
    }
}

/// The Web surface is a trust boundary: WebKit, DSH, providers, filesystem
/// APIs, and download metadata can all supply attacker-controlled text. Only
/// bounded app-owned copy crosses into native labels, alerts, accessibility
/// announcements, or delegate diagnostics.
enum HarnessWebPresentationPolicy {
    private static let secretPatterns: [NSRegularExpression] = [
        try! NSRegularExpression(
            pattern: #"\b(Bearer)\s+[A-Za-z0-9._~+/=-]{8,}"#,
            options: [.caseInsensitive]
        ),
        try! NSRegularExpression(
            pattern: #"\b(api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|secret|client[_-]?secret)(\s*[:=]\s*)[^\s\"',;]{3,}"#,
            options: [.caseInsensitive]
        ),
        try! NSRegularExpression(
            pattern: #"\b(?:sk|rk|api)[-_][A-Za-z0-9_-]{12,}\b"#,
            options: [.caseInsensitive]
        )
    ]
    private static let URLPattern = try! NSRegularExpression(
        pattern: #"\b(?:https?|file)://[^\s]+"#,
        options: [.caseInsensitive]
    )
    private static let absolutePathPattern = try! NSRegularExpression(
        pattern: #"(?<![A-Za-z0-9])/(?:[^\s/]+/)*[^\s.,;:]+"#
    )

    static func appText(_ value: String, limit: Int = 640, fallback: String) -> String {
        guard limit > 0 else { return fallback }
        var scalars = String.UnicodeScalarView()
        scalars.reserveCapacity(min(value.unicodeScalars.count, limit * 2))
        // Canonical composition removes representation ambiguity without
        // rewriting deliberate UI punctuation (for example, an ellipsis into
        // three periods) as compatibility normalization would.
        for scalar in value.precomposedStringWithCanonicalMapping.unicodeScalars {
            switch scalar.value {
            case 0x09, 0x0A, 0x0D:
                scalars.append(" ")
            case 0x061C, 0x200E, 0x200F, 0x202A...0x202E, 0x2066...0x2069:
                continue
            default:
                guard !CharacterSet.controlCharacters.contains(scalar),
                      scalar.properties.generalCategory != .format else { continue }
                scalars.append(scalar)
            }
            guard scalars.count < limit * 4 else { break }
        }
        var cleaned = String(scalars).split(whereSeparator: \Character.isWhitespace).joined(separator: " ")
        cleaned = replacingMatches(URLPattern, in: cleaned, template: "[redacted address]")
        cleaned = replacingMatches(absolutePathPattern, in: cleaned, template: "[redacted path]")
        for pattern in secretPatterns {
            cleaned = replacingMatches(pattern, in: cleaned, template: "[REDACTED]")
        }
        guard !cleaned.isEmpty else { return fallback }
        let bounded = String(cleaned.prefix(limit))
        return bounded.count < cleaned.count ? bounded + "…" : bounded
    }

    static func externalDestination(_ url: URL) -> String {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.scheme == "https",
              let host = components.host,
              !host.isEmpty else {
            return "an approved HTTPS site"
        }
        let safeHost = appText(host.lowercased(), limit: 253, fallback: "approved site")
        let port = components.port.map { ":\($0)" } ?? ""
        let hasPrivateSuffix = !(components.percentEncodedPath.isEmpty || components.percentEncodedPath == "/")
            || components.query != nil || components.fragment != nil
        return "https://\(safeHost)\(port)" + (hasPrivateSuffix ? " (private path or query hidden)" : "")
    }

    static func downloadFilename(_ value: String) -> String {
        appText(
            DownloadPath.safeFilename(value, fallback: "Download"),
            limit: 200,
            fallback: "Download"
        )
    }

    static func failure(for error: Error, provisionalNavigation: Bool) -> HarnessWebSurfaceFailure {
        let nsError = error as NSError
        if nsError.domain == NSURLErrorDomain {
            switch nsError.code {
            case NSURLErrorTimedOut,
                 NSURLErrorCannotFindHost,
                 NSURLErrorCannotConnectToHost,
                 NSURLErrorNetworkConnectionLost,
                 NSURLErrorDNSLookupFailed,
                 NSURLErrorNotConnectedToInternet,
                 NSURLErrorInternationalRoamingOff,
                 NSURLErrorDataNotAllowed:
                return .navigationUnavailable
            default:
                break
            }
        }
        return provisionalNavigation ? .navigationUnavailable : .navigationSecurityFailure
    }

    static func downloadFailure(_ error: Error, phase: HarnessDownloadFailurePhase) -> HarnessWebSurfaceFailure {
        switch phase {
        case .staging:
            return error is SecureDownloadError ? .downloadRejected : .downloadStagingUnavailable
        case .transfer:
            return .downloadTransferFailed
        case .finalization:
            return .downloadFinalizationFailed
        case .preview:
            return .downloadPreviewBlocked
        case .save:
            return .downloadSaveFailed
        }
    }

    private static func replacingMatches(
        _ expression: NSRegularExpression,
        in value: String,
        template: String
    ) -> String {
        let range = NSRange(value.startIndex..<value.endIndex, in: value)
        return expression.stringByReplacingMatches(in: value, range: range, withTemplate: template)
    }
}

enum HarnessDownloadFailurePhase: Equatable, Sendable {
    case staging
    case transfer
    case finalization
    case preview
    case save
}

struct HarnessExternalLinkPresentation: Equatable, Sendable {
    let destination: String
}

struct HarnessDownloadReviewPresentation: Equatable, Sendable {
    let filename: String
    let sizeAndCategory: String
    let detectedContent: String?
    let sha256: String
    let warningCount: Int
    let allowsPreview: Bool
}

enum HarnessDownloadReviewChoice: Equatable, Sendable {
    case preview
    case save
    case discard
}

struct HarnessDownloadSavePresentation: Equatable, Sendable {
    let suggestedFilename: String
}

struct HarnessDownloadFailurePresentation: Equatable, Sendable {
    let message: String
}

@MainActor
struct HarnessWebViewInteractions {
    var confirmExternalLink: (HarnessExternalLinkPresentation) -> Bool
    var reviewDownload: (HarnessDownloadReviewPresentation) -> HarnessDownloadReviewChoice
    var chooseSaveDestination: (HarnessDownloadSavePresentation) -> URL?
    var showDownloadFailure: (HarnessDownloadFailurePresentation, NSWindow?) -> Void

    static let live = HarnessWebViewInteractions(
        confirmExternalLink: { presentation in
            let alert = NSAlert()
            alert.messageText = "Open link in your default browser?"
            alert.informativeText = "Destination: \(presentation.destination)\n\nThis leaves \(ProductBrand.displayName) and uses your normal browser profile. The agent cannot control that browser."
            alert.alertStyle = .informational
            alert.addButton(withTitle: "Open Default Browser")
            alert.addButton(withTitle: "Cancel")
            return alert.runModal() == .alertFirstButtonReturn
        },
        reviewDownload: { presentation in
            let alert = NSAlert()
            alert.messageText = "Download staged safely"
            var details = [
                presentation.filename,
                presentation.sizeAndCategory,
            ]
            if let detectedContent = presentation.detectedContent {
                details.append("Detected content: \(detectedContent)")
            }
            details.append("SHA-256: \(presentation.sha256)")
            details.append("Nothing has been opened or copied into Downloads.")
            if presentation.warningCount > 0 {
                details.append("\nFulmar found \(presentation.warningCount) content safety warning\(presentation.warningCount == 1 ? "" : "s").")
            }
            alert.informativeText = details.joined(separator: "\n")
            if presentation.allowsPreview {
                alert.alertStyle = .informational
                alert.addButton(withTitle: "Preview")
                alert.addButton(withTitle: "Save…")
                alert.addButton(withTitle: "Discard")
                switch alert.runModal() {
                case .alertFirstButtonReturn: return .preview
                case .alertSecondButtonReturn: return .save
                default: return .discard
                }
            }
            alert.alertStyle = .warning
            alert.informativeText += "\n\nPreview is disabled for this content type. You can save it explicitly or discard it."
            alert.addButton(withTitle: "Save…")
            alert.addButton(withTitle: "Discard")
            return alert.runModal() == .alertFirstButtonReturn ? .save : .discard
        },
        chooseSaveDestination: { presentation in
            let panel = NSSavePanel()
            panel.title = "Save validated download"
            panel.message = "The file will keep its macOS quarantine metadata. Existing files are never overwritten by the download service."
            if let downloads = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first {
                panel.directoryURL = downloads
                panel.nameFieldStringValue = DownloadPath.uniqueURL(
                    in: downloads,
                    suggestedFilename: presentation.suggestedFilename
                ).lastPathComponent
            } else {
                panel.nameFieldStringValue = presentation.suggestedFilename
            }
            panel.canCreateDirectories = true
            panel.isExtensionHidden = false
            guard panel.runModal() == .OK else { return nil }
            return panel.url
        },
        showDownloadFailure: { presentation, window in
            guard let window, window.attachedSheet == nil else { return }
            let alert = NSAlert()
            alert.messageText = "Download not completed"
            alert.informativeText = presentation.message
            alert.alertStyle = .warning
            alert.addButton(withTitle: "OK")
            alert.beginSheetModal(for: window)
        }
    )
}

@MainActor
struct HarnessWebSurfaceOperations {
    var startFreshSession: (
        WKWebView,
        @escaping @MainActor @Sendable (Result<Any, Error>) -> Void
    ) -> Void

    static let live = HarnessWebSurfaceOperations(
        startFreshSession: { webView, completion in
            webView.callAsyncJavaScript(
                FreshSessionBrowserHandshake.javaScript,
                arguments: [:],
                in: nil,
                in: .page,
                completionHandler: completion
            )
        }
    )
}

struct HarnessDownloadOperations {
    var prepare: (String, String?, Int64, URL?) throws -> PendingDownloadDestination
    var inspect: (PendingDownloadDestination) -> IncomingDownloadInspection
    var finalize: (PendingDownloadDestination) throws -> StagedDownloadArtifact
    var validateForPreview: (StagedDownloadArtifact) throws -> Void
    var export: (StagedDownloadArtifact, URL) throws -> StagedDownloadArtifact
    var discardPending: (PendingDownloadDestination) -> Void
    var discardArtifact: (StagedDownloadArtifact) -> Void
    var cleanup: () -> Void

    static func live() throws -> HarnessDownloadOperations {
        let stager = try SecureDownloadStager()
        stager.startMaintenance()
        return HarnessDownloadOperations(
            prepare: { try stager.prepare(
                suggestedFilename: $0,
                reportedMIMEType: $1,
                expectedContentLength: $2,
                sourceURL: $3
            ) },
            inspect: stager.inspectIncoming,
            finalize: stager.finalize,
            validateForPreview: stager.validateForPreview,
            export: stager.export,
            discardPending: stager.discard,
            discardArtifact: stager.discard,
            cleanup: stager.cleanupOwnedArtifacts
        )
    }
}

enum FreshSessionBridgeValidation {
    static func sessionID(from value: Any) -> HarnessSessionID? {
        guard let text = value as? String,
              text.utf8.count <= 2_048,
              let data = text.data(using: .utf8),
              let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              Set(root.keys) == Set(["ok", "proof"]),
              root["ok"] as? Bool == true,
              let proof = root["proof"] as? [String: Any],
              Set(proof.keys) == Set(["created", "current"])
                || Set(proof.keys) == Set(["before", "created", "current"]),
              let created = proof["created"] as? String,
              let current = proof["current"] as? String,
              safeIdentity(created),
              safeIdentity(current) else {
            return nil
        }
        let before: String?
        if let rawBefore = proof["before"] {
            if rawBefore is NSNull {
                before = nil
            } else if let string = rawBefore as? String, safeIdentity(string) {
                before = string
            } else {
                return nil
            }
        } else {
            before = nil
        }
        guard current == created, before != created else { return nil }
        return HarnessSessionID(created)
    }

    private static func safeIdentity(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 512 && value.unicodeScalars.allSatisfy {
            !CharacterSet.controlCharacters.contains($0) && $0.properties.generalCategory != .format
        }
    }
}

enum FreshSessionBrowserHandshake {
    static let javaScript = """
    const deadline = performance.now() + 15_000;
    let bridge;
    while (performance.now() < deadline) {
      const candidate = window.__localHarnessSecurityBridge;
      if (candidate && typeof candidate.startFreshSession === 'function') {
        bridge = candidate;
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    if (!bridge) {
      return JSON.stringify({ ok: false, error: 'The DSH browser bridge did not become ready within 15 seconds.' });
    }
    try {
      const proof = await bridge.startFreshSession();
      return JSON.stringify({ ok: true, proof });
    } catch (error) {
      const detail = typeof error?.message === 'string' ? error.message : 'The DSH browser bridge rejected the fresh task.';
      return JSON.stringify({ ok: false, error: detail.slice(0, 512) });
    }
    """
}

/// Small deterministic state machine for the security overlay. A requirement
/// is cleared only by the matching native validation attempt; page reloads,
/// failed JavaScript, endpoint replacement, and stale callbacks leave it
/// latched fail-closed.
struct FreshSessionRequirementState: Equatable {
    private(set) var isRequired = false
    private(set) var activeAttempt: UUID?
    var permitsTurnPreparation: Bool { !isRequired && activeAttempt == nil }

    mutating func require() {
        isRequired = true
    }

    mutating func begin(attempt: UUID = UUID()) -> UUID? {
        guard isRequired, activeAttempt == nil else { return nil }
        activeAttempt = attempt
        return attempt
    }

    mutating func succeed(_ attempt: UUID) -> Bool {
        guard isRequired, activeAttempt == attempt else { return false }
        activeAttempt = nil
        isRequired = false
        return true
    }

    mutating func fail(_ attempt: UUID) -> Bool {
        guard isRequired, activeAttempt == attempt else { return false }
        activeAttempt = nil
        return true
    }

    mutating func invalidateAttempt() {
        activeAttempt = nil
    }
}

struct TurnPreparationBridgeResult: Equatable, Sendable {
    enum Mode: String, Equatable, Sendable {
        case protected
        case readOnly
    }

    let mode: Mode
    let message: String?
}

enum RecoveryBridgeRequest: Equatable, Sendable {
    case prepare(operationID: UUID, sessionID: HarnessSessionID)
    case cancel(operationID: UUID)

    static func decode(_ body: [String: Any]) -> RecoveryBridgeRequest? {
        guard hasExactProtocolVersion(body["version"]),
              let action = body["action"] as? String,
              let rawOperationID = body["operationID"] as? String,
              rawOperationID.utf8.count == 36,
              let operationID = UUID(uuidString: rawOperationID),
              isRFC4122Version4(operationID) else { return nil }
        if action == "cancel",
           Set(body.keys) == Set(["version", "action", "operationID"]) {
            return .cancel(operationID: operationID)
        }
        guard action == "prepare",
              Set(body.keys) == Set(["version", "action", "operationID", "sessionID"]),
              let rawSessionID = body["sessionID"] as? String,
              !rawSessionID.isEmpty,
              rawSessionID.utf8.count <= 512,
              !rawSessionID.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else {
            return nil
        }
        return .prepare(operationID: operationID, sessionID: HarnessSessionID(rawSessionID))
    }

    /// JavaScript has one numeric type, so WebKit may bridge the integer `2`
    /// with a floating NSNumber representation. Validate integer semantics
    /// without `intValue` coercion: booleans, strings, non-finite values and
    /// fractional values such as 2.9 must never select protocol v2.
    private static func hasExactProtocolVersion(_ rawValue: Any?) -> Bool {
        guard let number = rawValue as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID(),
              number.doubleValue.isFinite,
              number.doubleValue.rounded(.towardZero) == number.doubleValue,
              number.int64Value == 2 else {
            return false
        }
        return true
    }

    /// UUID(string:) validates syntax but does not enforce the security
    /// properties of an operation nonce. Require both the RFC 4122 variant
    /// (`10xxxxxx`) and random version 4 (`0100xxxx`) bits independently.
    private static func isRFC4122Version4(_ operationID: UUID) -> Bool {
        var rawUUID = operationID.uuid
        return withUnsafeBytes(of: &rawUUID) { bytes in
            (bytes[6] & 0xF0) == 0x40 && (bytes[8] & 0xC0) == 0x80
        }
    }
}

/// Validates the small native capability request used to bind the embedded
/// Harness page to a native performance profile. WebKit bridges JavaScript
/// numbers through NSNumber, where `intValue` would otherwise accept values
/// such as `true` and `1.9`. The workspace is native-owned, but it still must
/// be a bounded canonical absolute path before it crosses into page script.
enum PerformanceBridgeRequestValidation {
    static func accepts(body: [String: Any], workspacePath: String) -> Bool {
        Set(body.keys) == Set(["version"])
            && hasExactProtocolVersion(body["version"])
            && isSafeCanonicalWorkspacePath(workspacePath)
    }

    static func hasExactProtocolVersion(_ rawValue: Any?) -> Bool {
        guard let number = rawValue as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID(),
              number.doubleValue.isFinite,
              number.doubleValue.rounded(.towardZero) == number.doubleValue,
              number.int64Value == 1 else {
            return false
        }
        return true
    }

    static func isSafeCanonicalWorkspacePath(_ value: String) -> Bool {
        guard value != "/",
              value.hasPrefix("/"),
              value.utf8.count <= 4_096,
              value.unicodeScalars.allSatisfy({
                  !CharacterSet.controlCharacters.contains($0)
                      && $0.properties.generalCategory != .format
              }) else {
            return false
        }
        return (value as NSString).standardizingPath == value
    }
}

@MainActor
protocol HarnessWebViewControllerDelegate: AnyObject {
    func webSurface(_ surface: HarnessWebViewController, didOpenExternalURL url: URL)
    func webSurface(_ surface: HarnessWebViewController, didCompleteDownload artifact: StagedDownloadArtifact, action: StagedDownloadUserAction)
    func webSurface(_ surface: HarnessWebViewController, didFailWith message: String)
    /// Confirms the browser bridge created an empty session in the exact
    /// approved workspace with the currently selected provider/model route.
    func webSurface(
        _ surface: HarnessWebViewController,
        validateFreshSession sessionID: HarnessSessionID,
        completion: @escaping (Result<Void, Error>) -> Void
    )
    /// Creates the native Workspace recovery point that must settle before
    /// the embedded composer may submit this session's prompt.
    func webSurface(
        _ surface: HarnessWebViewController,
        prepareTurnIn sessionID: HarnessSessionID,
        operationID: UUID,
        completion: @escaping (Result<TurnPreparationBridgeResult, Error>) -> Void
    )
    func webSurface(_ surface: HarnessWebViewController, cancelTurnPreparation operationID: UUID)
    /// Mints a caller-owned opaque identity that binds a newly created browser
    /// session to the native performance profile selected for this runtime.
    func performanceSessionID(for surface: HarnessWebViewController) -> HarnessSessionID?
    /// Returns the one canonical native Workspace that every interactive,
    /// scheduled, Skill, MCP, recovery, and sandbox path is authorized to use.
    func approvedWorkspacePath(for surface: HarnessWebViewController) -> String?
}

private final class HarnessReplyScriptHandler: NSObject, WKScriptMessageHandlerWithReply {
    var receive: ((WKScriptMessage, @escaping (Any?, String?) -> Void) -> Void)?

    func userContentController(
        _ userContentController: WKUserContentController,
        didReceive message: WKScriptMessage,
        replyHandler: @escaping (Any?, String?) -> Void
    ) {
        guard let receive else {
            replyHandler(nil, "\(ProductBrand.displayName) native recovery is unavailable.")
            return
        }
        receive(message, replyHandler)
    }
}

private final class HarnessBridgeReplyOnce {
    private var didReply = false
    private let replyHandler: (Any?, String?) -> Void

    init(_ replyHandler: @escaping (Any?, String?) -> Void) {
        self.replyHandler = replyHandler
    }

    func send(_ value: Any?, error: String?) {
        guard !didReply else { return }
        didReply = true
        replyHandler(value, error)
    }
}

final class HarnessWebViewController: NSViewController, WKNavigationDelegate, WKUIDelegate, WKDownloadDelegate {
    private static let recoveryMessageName = "localHarnessRecovery"
    private static let performanceMessageName = "localHarnessPerformance"
    weak var delegate: HarnessWebViewControllerDelegate?

    let webView: WKWebView
    private var endpoint: HarnessEndpoint?
    private var securityPolicy: NavigationSecurityPolicy?
    private let dataStore: WKWebsiteDataStore
    private let preferences: PreferencesStore
    private let interactions: HarnessWebViewInteractions
    private let operations: HarnessWebSurfaceOperations
    private let displayPolicy: NativeAccessibilityDisplayPolicy
    private let typography: NativeTypographyPolicy
    private var accessibilityDisplayObserver: NativeAccessibilityDisplayObserver?
    private let recoveryScriptHandler: HarnessReplyScriptHandler
    private let performanceScriptHandler: HarnessReplyScriptHandler
    private let loadingView = AppearanceAwareLayerView()
    private let spinner = NSProgressIndicator()
    private let loadingLabel = NSTextField(labelWithString: "Starting your local workspace…")
    private let recoveryActions = NSStackView()
    private let retryRecoveryButton = NSButton(title: "Retry Verification", target: nil, action: nil)
    private let chooseLocalModelButton = NSButton(title: "Choose Installed Local Model", target: nil, action: nil)
    private let openProvidersButton = NSButton(title: "Models & Providers", target: nil, action: nil)
    private let resetNativeStateButton = NSButton(title: "Reset Damaged State…", target: nil, action: nil)
    private let freshSessionActions = NSStackView()
    private let retryFreshSessionButton = NSButton(title: "Try New Task Again", target: nil, action: nil)
    private let reloadFreshSessionButton = NSButton(title: "Reload Agent Workspace", target: nil, action: nil)
    private let thermalDetailLabel = NSTextField(labelWithString: "")
    private let thermalActions = NSStackView()
    private let thermalProvidersButton = NSButton(title: "Switch Model or Provider", target: nil, action: nil)
    private let thermalPerformanceButton = NSButton(title: "Performance Details", target: nil, action: nil)
    private var retryRecoveryAction: (() -> Void)?
    private var chooseLocalModelAction: (() -> Void)?
    private var openProvidersAction: (() -> Void)?
    private var resetNativeStateAction: (() -> Void)?
    private var thermalProvidersAction: (() -> Void)?
    private var thermalPerformanceAction: (() -> Void)?
    private(set) var isProviderRecoveryVisible = false
    private(set) var isFreshSessionFailureVisible = false
    private(set) var isThermalCooldownVisible = false
    private var spinnerIsBusy = false
    private let downloadOperations: HarnessDownloadOperations?
    private let downloadProcessingQueue = DispatchQueue(label: "app.localharness.secure-downloads", qos: .utility)
    private var activeDownloads: [UUID: ActiveWebDownload] = [:]
    private var webDownloadOperationIDs: [ObjectIdentifier: UUID] = [:]
    private var activeArtifactOperations: Set<String> = []
    private var boundaryGeneration: UInt64 = 0
    private var navigationGenerations: [ObjectIdentifier: UInt64] = [:]
    private var externalHandoffInProgress = false
    private var freshSessionRequirement = FreshSessionRequirementState()
    private(set) var hasLoadedHarness = false
    /// Native admission is closed before every lifecycle transition reaches
    /// its first suspension point. A Web prompt that already crossed the
    /// checkpoint may race toward the old DSH process, but the shared mutation
    /// gate cannot run any protected write until that exact process has exited.
    private var turnAdmissionsSuspended = true
    /// Injectable only for native tests. Production leaves this nil so the
    /// exact normalized HTTPS destination is shown by the real AppKit alert.
    var externalLinkConfirmationHandler: ((URL) -> Bool)?

    convenience init(
        dataStore: WKWebsiteDataStore,
        preferences: PreferencesStore,
        displayPolicy: NativeAccessibilityDisplayPolicy = .live,
        typography: NativeTypographyPolicy = .standard
    ) {
        self.init(
            dataStore: dataStore,
            preferences: preferences,
            interactions: nil,
            operations: nil,
            downloadOperations: try? HarnessDownloadOperations.live(),
            displayPolicy: displayPolicy,
            typography: typography
        )
    }

    init(
        dataStore: WKWebsiteDataStore,
        preferences: PreferencesStore,
        interactions: HarnessWebViewInteractions?,
        operations: HarnessWebSurfaceOperations?,
        downloadOperations: HarnessDownloadOperations?,
        displayPolicy: NativeAccessibilityDisplayPolicy = .live,
        typography: NativeTypographyPolicy = .standard
    ) {
        self.dataStore = dataStore
        self.preferences = preferences
        self.interactions = interactions ?? .live
        self.operations = operations ?? .live
        self.downloadOperations = downloadOperations
        self.displayPolicy = displayPolicy
        self.typography = typography

        let scriptHandler = HarnessReplyScriptHandler()
        let profileHandler = HarnessReplyScriptHandler()
        recoveryScriptHandler = scriptHandler
        performanceScriptHandler = profileHandler
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = dataStore
        configuration.preferences.isElementFullscreenEnabled = true
        configuration.preferences.isFraudulentWebsiteWarningEnabled = true
        configuration.preferences.javaScriptCanOpenWindowsAutomatically = false
        configuration.userContentController.addScriptMessageHandler(
            scriptHandler,
            contentWorld: .page,
            name: Self.recoveryMessageName
        )
        configuration.userContentController.addScriptMessageHandler(
            profileHandler,
            contentWorld: .page,
            name: Self.performanceMessageName
        )
        webView = WKWebView(frame: .zero, configuration: configuration)
        super.init(nibName: nil, bundle: nil)
        scriptHandler.receive = { [weak self] message, reply in
            self?.handleRecoveryMessage(message, reply: reply)
                ?? reply(nil, "\(ProductBrand.displayName) native recovery is unavailable.")
        }
        profileHandler.receive = { [weak self] message, reply in
            self?.handlePerformanceMessage(message, reply: reply)
                ?? reply(nil, "\(ProductBrand.displayName) native performance policy is unavailable.")
        }
        webView.navigationDelegate = self
        webView.uiDelegate = self
        webView.allowsMagnification = true
        webView.allowsBackForwardNavigationGestures = true
        accessibilityDisplayObserver = NativeAccessibilityDisplayObserver { [weak self] in
            self?.refreshAccessibilityDisplayOptions()
        }
    }

    deinit {
        webView.configuration.userContentController.removeScriptMessageHandler(
            forName: Self.recoveryMessageName,
            contentWorld: .page
        )
        webView.configuration.userContentController.removeScriptMessageHandler(
            forName: Self.performanceMessageName,
            contentWorld: .page
        )
        recoveryScriptHandler.receive = nil
        performanceScriptHandler.receive = nil
        activeDownloads.values.forEach {
            $0.stopMonitoring()
            $0.download?.cancel { _ in }
            downloadOperations?.discardPending($0.pending)
        }
        downloadOperations?.cleanup()
    }

    private func handleRecoveryMessage(
        _ message: WKScriptMessage,
        reply: @escaping (Any?, String?) -> Void
    ) {
        let replyOnce = HarnessBridgeReplyOnce(reply)
        guard message.frameInfo.isMainFrame,
              let endpoint,
              let frameOrigin = message.frameInfo.request.url.flatMap(ProviderEndpointOrigin.init(url:)),
              let expectedOrigin = ProviderEndpointOrigin(url: endpoint.baseURL),
              frameOrigin == expectedOrigin,
              let body = message.body as? [String: Any],
              let request = RecoveryBridgeRequest.decode(body),
              let delegate else {
            replyOnce.send(nil, error: "\(ProductBrand.displayName) rejected an invalid recovery request.")
            return
        }
        if case .cancel(let operationID) = request {
            delegate.webSurface(self, cancelTurnPreparation: operationID)
            replyOnce.send(["ok": true], error: nil)
            return
        }
        guard !turnAdmissionsSuspended else {
            replyOnce.send(nil, error: "\(ProductBrand.displayName) is securing a runtime change. Start a fresh task after it is ready.")
            return
        }
        guard freshSessionRequirement.permitsTurnPreparation else {
            replyOnce.send(nil, error: "\(ProductBrand.displayName) requires a verified fresh task before another turn can start.")
            return
        }
        guard case .prepare(let operationID, let sessionID) = request else {
            replyOnce.send(nil, error: "\(ProductBrand.displayName) rejected an invalid recovery request.")
            return
        }
        let generation = boundaryGeneration
        delegate.webSurface(
            self,
            prepareTurnIn: sessionID,
            operationID: operationID
        ) { result in
            DispatchQueue.main.async {
                guard self.boundaryGeneration == generation,
                      !self.turnAdmissionsSuspended,
                      self.freshSessionRequirement.permitsTurnPreparation else {
                    replyOnce.send(nil, error: "\(ProductBrand.displayName) rejected a stale recovery result.")
                    return
                }
                switch result {
                case .success(let protection):
                    var response: [String: Any] = [
                        "ok": true,
                        "mode": protection.mode.rawValue
                    ]
                    if let message = protection.message {
                        response["message"] = HarnessWebPresentationPolicy.appText(
                            message,
                            limit: 400,
                            fallback: "Recovery protection is active."
                        )
                    }
                    replyOnce.send(response, error: nil)
                case .failure:
                    replyOnce.send(nil, error: "\(ProductBrand.displayName) could not create a protected recovery point.")
                }
            }
        }
    }

    private func handlePerformanceMessage(
        _ message: WKScriptMessage,
        reply: @escaping (Any?, String?) -> Void
    ) {
        guard message.frameInfo.isMainFrame,
              let endpoint,
              let frameOrigin = message.frameInfo.request.url.flatMap(ProviderEndpointOrigin.init(url:)),
              let expectedOrigin = ProviderEndpointOrigin(url: endpoint.baseURL),
              frameOrigin == expectedOrigin,
              let body = message.body as? [String: Any],
              let sessionID = delegate?.performanceSessionID(for: self),
              PerformanceSessionIdentity.profile(from: sessionID) != nil,
              let workspacePath = delegate?.approvedWorkspacePath(for: self),
              PerformanceBridgeRequestValidation.accepts(
                  body: body,
                  workspacePath: workspacePath
              ) else {
            reply(nil, "\(ProductBrand.displayName) rejected an invalid performance-profile request.")
            return
        }
        reply([
            "ok": true,
            "sessionID": sessionID.rawValue,
            "workspacePath": workspacePath
        ], nil)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func loadView() {
        let root = NSView()
        root.translatesAutoresizingMaskIntoConstraints = false
        webView.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(webView)

        loadingView.semanticBackgroundColor = .windowBackgroundColor
        loadingView.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(loadingView)

        spinner.style = .spinning
        spinner.controlSize = .large
        spinner.translatesAutoresizingMaskIntoConstraints = false
        loadingView.addSubview(spinner)

        loadingLabel.font = typography.font(for: .workspaceStatus)
        loadingLabel.textColor = .secondaryLabelColor
        loadingLabel.alignment = .center
        loadingLabel.lineBreakMode = .byWordWrapping
        loadingLabel.maximumNumberOfLines = 6
        loadingLabel.cell?.truncatesLastVisibleLine = false
        loadingLabel.setAccessibilityRole(.staticText)
        loadingLabel.setAccessibilityLabel("Workspace status")
        loadingLabel.translatesAutoresizingMaskIntoConstraints = false
        loadingView.addSubview(loadingLabel)

        for button in [retryRecoveryButton, chooseLocalModelButton, openProvidersButton, resetNativeStateButton] {
            button.bezelStyle = .rounded
        }
        retryRecoveryButton.target = self
        retryRecoveryButton.action = #selector(retryProviderRecovery(_:))
        retryRecoveryButton.keyEquivalent = "\r"
        retryRecoveryButton.setAccessibilityLabel("Retry provider verification")
        retryRecoveryButton.setAccessibilityHelp("Checks the selected provider and model again without starting an agent task.")
        chooseLocalModelButton.target = self
        chooseLocalModelButton.action = #selector(chooseLocalModelForRecovery(_:))
        chooseLocalModelButton.setAccessibilityLabel("Choose an installed local model")
        chooseLocalModelButton.setAccessibilityHelp("Opens Local Models so an installed Ollama model can be selected while agent work remains blocked.")
        chooseLocalModelButton.isHidden = true
        chooseLocalModelButton.isEnabled = false
        openProvidersButton.target = self
        openProvidersButton.action = #selector(openProviderRecoverySettings(_:))
        openProvidersButton.keyEquivalent = ","
        openProvidersButton.keyEquivalentModifierMask = [.command]
        openProvidersButton.setAccessibilityLabel("Open Models and Providers")
        openProvidersButton.setAccessibilityHelp("Opens Models & Providers to repair the selected provider or change the selected local model while agent work remains blocked.")
        resetNativeStateButton.target = self
        resetNativeStateButton.action = #selector(resetProviderRecoveryState(_:))
        resetNativeStateButton.setAccessibilityLabel("Reset damaged provider state")
        resetNativeStateButton.setAccessibilityHelp("Creates private recovery copies, then resets only the damaged native provider records after confirmation.")
        recoveryActions.orientation = .horizontal
        recoveryActions.alignment = .centerY
        recoveryActions.spacing = 8
        recoveryActions.translatesAutoresizingMaskIntoConstraints = false
        recoveryActions.isHidden = true
        for button in [retryRecoveryButton, chooseLocalModelButton, openProvidersButton, resetNativeStateButton] {
            recoveryActions.addArrangedSubview(button)
        }
        loadingView.addSubview(recoveryActions)

        for button in [retryFreshSessionButton, reloadFreshSessionButton] {
            button.bezelStyle = .rounded
        }
        retryFreshSessionButton.target = self
        retryFreshSessionButton.action = #selector(retryFreshSession(_:))
        retryFreshSessionButton.keyEquivalent = "\r"
        retryFreshSessionButton.setAccessibilityLabel("Try creating a new task again")
        retryFreshSessionButton.setAccessibilityHelp("Retries the verified fresh-task handshake. No prompt is sent until verification succeeds.")
        reloadFreshSessionButton.target = self
        reloadFreshSessionButton.action = #selector(reloadAfterFreshSessionFailure(_:))
        reloadFreshSessionButton.keyEquivalent = "r"
        reloadFreshSessionButton.keyEquivalentModifierMask = [.command]
        reloadFreshSessionButton.setAccessibilityLabel("Reload Agent Workspace")
        reloadFreshSessionButton.setAccessibilityHelp("Reloads the embedded Harness page, then creates and verifies a fresh task before unlocking the composer.")
        freshSessionActions.orientation = .horizontal
        freshSessionActions.alignment = .centerY
        freshSessionActions.spacing = 8
        freshSessionActions.translatesAutoresizingMaskIntoConstraints = false
        freshSessionActions.isHidden = true
        freshSessionActions.addArrangedSubview(retryFreshSessionButton)
        freshSessionActions.addArrangedSubview(reloadFreshSessionButton)
        loadingView.addSubview(freshSessionActions)

        thermalDetailLabel.font = typography.font(for: .workspaceDetail)
        thermalDetailLabel.textColor = .secondaryLabelColor
        thermalDetailLabel.alignment = .center
        thermalDetailLabel.maximumNumberOfLines = 4
        thermalDetailLabel.setAccessibilityRole(.staticText)
        thermalDetailLabel.setAccessibilityLabel("Local AI protection details")
        thermalDetailLabel.translatesAutoresizingMaskIntoConstraints = false
        thermalDetailLabel.isHidden = true
        loadingView.addSubview(thermalDetailLabel)

        for button in [thermalProvidersButton, thermalPerformanceButton] {
            button.bezelStyle = .rounded
        }
        thermalProvidersButton.target = self
        thermalProvidersButton.action = #selector(openThermalProviders(_:))
        thermalProvidersButton.keyEquivalent = ","
        thermalProvidersButton.keyEquivalentModifierMask = [.command]
        thermalProvidersButton.setAccessibilityLabel("Switch model or provider")
        thermalProvidersButton.setAccessibilityHelp("Choose an approved cloud provider while the selected local model cools, or keep work on this Mac.")
        thermalPerformanceButton.target = self
        thermalPerformanceButton.action = #selector(openThermalPerformance(_:))
        thermalPerformanceButton.keyEquivalent = "p"
        thermalPerformanceButton.keyEquivalentModifierMask = [.command, .option]
        thermalPerformanceButton.setAccessibilityLabel("Open thermal performance details")
        thermalActions.orientation = .horizontal
        thermalActions.alignment = .centerY
        thermalActions.spacing = 8
        thermalActions.translatesAutoresizingMaskIntoConstraints = false
        thermalActions.isHidden = true
        thermalActions.addArrangedSubview(thermalProvidersButton)
        thermalActions.addArrangedSubview(thermalPerformanceButton)
        loadingView.addSubview(thermalActions)

        NSLayoutConstraint.activate([
            webView.topAnchor.constraint(equalTo: root.topAnchor),
            webView.leadingAnchor.constraint(equalTo: root.leadingAnchor),
            webView.trailingAnchor.constraint(equalTo: root.trailingAnchor),
            webView.bottomAnchor.constraint(equalTo: root.bottomAnchor),

            loadingView.topAnchor.constraint(equalTo: root.topAnchor),
            loadingView.leadingAnchor.constraint(equalTo: root.leadingAnchor),
            loadingView.trailingAnchor.constraint(equalTo: root.trailingAnchor),
            loadingView.bottomAnchor.constraint(equalTo: root.bottomAnchor),

            spinner.centerXAnchor.constraint(equalTo: loadingView.centerXAnchor),
            spinner.centerYAnchor.constraint(equalTo: loadingView.centerYAnchor, constant: -20),
            loadingLabel.topAnchor.constraint(equalTo: spinner.bottomAnchor, constant: 16),
            loadingLabel.centerXAnchor.constraint(equalTo: loadingView.centerXAnchor),
            loadingLabel.leadingAnchor.constraint(greaterThanOrEqualTo: loadingView.leadingAnchor, constant: 32),
            loadingLabel.trailingAnchor.constraint(lessThanOrEqualTo: loadingView.trailingAnchor, constant: -32),
            loadingLabel.widthAnchor.constraint(lessThanOrEqualToConstant: 560),
            recoveryActions.topAnchor.constraint(equalTo: loadingLabel.bottomAnchor, constant: 18),
            recoveryActions.centerXAnchor.constraint(equalTo: loadingView.centerXAnchor),
            recoveryActions.leadingAnchor.constraint(greaterThanOrEqualTo: loadingView.leadingAnchor, constant: 24),
            recoveryActions.trailingAnchor.constraint(lessThanOrEqualTo: loadingView.trailingAnchor, constant: -24),

            freshSessionActions.topAnchor.constraint(equalTo: loadingLabel.bottomAnchor, constant: 18),
            freshSessionActions.centerXAnchor.constraint(equalTo: loadingView.centerXAnchor),
            freshSessionActions.leadingAnchor.constraint(greaterThanOrEqualTo: loadingView.leadingAnchor, constant: 24),
            freshSessionActions.trailingAnchor.constraint(lessThanOrEqualTo: loadingView.trailingAnchor, constant: -24),

            thermalDetailLabel.topAnchor.constraint(equalTo: loadingLabel.bottomAnchor, constant: 12),
            thermalDetailLabel.centerXAnchor.constraint(equalTo: loadingView.centerXAnchor),
            thermalDetailLabel.leadingAnchor.constraint(greaterThanOrEqualTo: loadingView.leadingAnchor, constant: 32),
            thermalDetailLabel.trailingAnchor.constraint(lessThanOrEqualTo: loadingView.trailingAnchor, constant: -32),
            thermalDetailLabel.widthAnchor.constraint(lessThanOrEqualToConstant: 620),
            thermalActions.topAnchor.constraint(equalTo: thermalDetailLabel.bottomAnchor, constant: 18),
            thermalActions.centerXAnchor.constraint(equalTo: loadingView.centerXAnchor),
            thermalActions.leadingAnchor.constraint(greaterThanOrEqualTo: loadingView.leadingAnchor, constant: 24),
            thermalActions.trailingAnchor.constraint(lessThanOrEqualTo: loadingView.trailingAnchor, constant: -24)
        ])
        view = root
        showLoading("Starting your local workspace…")
    }

    func showLoading(_ message: String) {
        loadViewIfNeeded()
        clearProviderRecoveryPresentation()
        clearFreshSessionFailurePresentation()
        clearThermalCooldownPresentation()
        loadingView.semanticBackgroundColor = .windowBackgroundColor
        loadingView.backgroundAlpha = 1
        let safeMessage = HarnessWebPresentationPolicy.appText(
            message,
            fallback: "Fulmar is preparing the Agent Workspace…"
        )
        loadingLabel.stringValue = safeMessage
        loadingLabel.toolTip = safeMessage
        loadingView.isHidden = false
        presentSpinnerRespectingAccessibility()
    }

    func showFailure(_ message: String) {
        loadViewIfNeeded()
        clearProviderRecoveryPresentation()
        clearFreshSessionFailurePresentation()
        clearThermalCooldownPresentation()
        loadingView.semanticBackgroundColor = .windowBackgroundColor
        loadingView.backgroundAlpha = 1
        let safeMessage = HarnessWebPresentationPolicy.appText(
            message,
            fallback: HarnessWebSurfaceFailure.navigationSecurityFailure.message
        )
        loadingLabel.stringValue = safeMessage
        loadingLabel.toolTip = safeMessage
        loadingView.isHidden = false
        setSpinnerBusy(false)
        AccessibilityAnnouncement.post(safeMessage, priority: .high, element: loadingView)
    }

    /// A failed fresh-task handshake is recoverable without weakening the
    /// fail-closed composer gate. Keep low-level WebKit text out of the primary
    /// message and provide explicit retry/reload paths that both require a new
    /// native session proof before any prompt can be admitted.
    func showFreshSessionFailure() {
        loadViewIfNeeded()
        clearProviderRecoveryPresentation()
        clearThermalCooldownPresentation()
        loadingView.semanticBackgroundColor = .windowBackgroundColor
        loadingView.backgroundAlpha = 1
        let message = "Fulmar could not verify that DeepSeek Harness opened a different empty task. No prompt was sent, and the composer remains locked. Try again or reload the Agent Workspace."
        loadingLabel.stringValue = message
        loadingLabel.toolTip = message
        loadingView.isHidden = false
        setSpinnerBusy(false)
        retryFreshSessionButton.isEnabled = true
        reloadFreshSessionButton.isEnabled = true
        freshSessionActions.isHidden = false
        isFreshSessionFailureVisible = true
        AccessibilityAnnouncement.post(message, priority: .high, element: loadingView)
    }

    func showThermalCooldown(
        headline: String,
        detail: String,
        openProviders: @escaping () -> Void,
        openPerformance: @escaping () -> Void
    ) {
        loadViewIfNeeded()
        clearProviderRecoveryPresentation()
        clearFreshSessionFailurePresentation()
        loadingView.semanticBackgroundColor = .windowBackgroundColor
        loadingView.backgroundAlpha = displayPolicy.reducesTransparency ? 1 : 0.90
        let safeHeadline = HarnessWebPresentationPolicy.appText(
            headline,
            limit: 180,
            fallback: "Local AI paused safely"
        )
        let safeDetail = HarnessWebPresentationPolicy.appText(
            detail,
            limit: 640,
            fallback: "Your completed work remains saved while Fulmar waits for safe operating conditions."
        )
        loadingLabel.stringValue = safeHeadline
        loadingLabel.toolTip = safeHeadline
        thermalDetailLabel.stringValue = safeDetail
        thermalDetailLabel.toolTip = safeDetail
        thermalProvidersAction = openProviders
        thermalPerformanceAction = openPerformance
        thermalDetailLabel.isHidden = false
        thermalActions.isHidden = false
        thermalProvidersButton.isEnabled = true
        thermalPerformanceButton.isEnabled = true
        loadingView.isHidden = false
        presentSpinnerRespectingAccessibility()
        isThermalCooldownVisible = true
        AccessibilityAnnouncement.post("\(safeHeadline) \(safeDetail)", priority: .high, element: loadingView)
    }

    func clearThermalCooldownPresentation() {
        thermalProvidersAction = nil
        thermalPerformanceAction = nil
        thermalDetailLabel.isHidden = true
        thermalActions.isHidden = true
        thermalProvidersButton.isEnabled = false
        thermalPerformanceButton.isEnabled = false
        isThermalCooldownVisible = false
    }

    /// The adjacent text carries the complete state. With Reduce Motion active
    /// an indeterminate animation adds no information, so remove it while
    /// keeping the status and every recovery action available.
    private func presentSpinnerRespectingAccessibility() {
        setSpinnerBusy(true)
    }

    private func setSpinnerBusy(_ busy: Bool) {
        spinnerIsBusy = busy
        displayPolicy.progressIndicatorPresentation(isBusy: busy).apply(to: spinner)
    }

    private func refreshAccessibilityDisplayOptions() {
        guard isViewLoaded else { return }
        displayPolicy.progressIndicatorPresentation(isBusy: spinnerIsBusy).apply(to: spinner)
        if isThermalCooldownVisible {
            loadingView.backgroundAlpha = displayPolicy.reducesTransparency ? 1 : 0.90
        }
    }

    /// Presents only the typed, authenticated provider-recovery state. Generic
    /// runtime, bundle, sandbox, and integrity failures use `showFailure` and
    /// therefore never expose these mutation actions.
    func showProviderRecovery(
        _ message: String,
        allowsNativeStateReset: Bool,
        retry: @escaping () -> Void,
        chooseLocalModel: (() -> Void)?,
        openProviders: @escaping () -> Void,
        resetNativeState: (() -> Void)?
    ) {
        loadViewIfNeeded()
        clearFreshSessionFailurePresentation()
        clearThermalCooldownPresentation()
        loadingView.semanticBackgroundColor = .windowBackgroundColor
        loadingView.backgroundAlpha = 1
        let safeMessage = HarnessWebPresentationPolicy.appText(
            message,
            fallback: "The selected provider route could not be verified. Agent work remains blocked."
        )
        loadingLabel.stringValue = safeMessage
        loadingLabel.toolTip = safeMessage
        loadingView.isHidden = false
        setSpinnerBusy(false)
        retryRecoveryAction = retry
        chooseLocalModelAction = chooseLocalModel
        openProvidersAction = openProviders
        resetNativeStateAction = resetNativeState
        chooseLocalModelButton.isHidden = chooseLocalModel == nil
        resetNativeStateButton.isHidden = !allowsNativeStateReset || resetNativeState == nil
        retryRecoveryButton.isEnabled = true
        chooseLocalModelButton.isEnabled = chooseLocalModel != nil
        openProvidersButton.isEnabled = true
        resetNativeStateButton.isEnabled = allowsNativeStateReset && resetNativeState != nil
        recoveryActions.isHidden = false
        isProviderRecoveryVisible = true
        AccessibilityAnnouncement.post(safeMessage, priority: .high, element: loadingView)
    }

    private func clearProviderRecoveryPresentation() {
        retryRecoveryAction = nil
        chooseLocalModelAction = nil
        openProvidersAction = nil
        resetNativeStateAction = nil
        chooseLocalModelButton.isHidden = true
        recoveryActions.isHidden = true
        retryRecoveryButton.isEnabled = false
        chooseLocalModelButton.isEnabled = false
        openProvidersButton.isEnabled = false
        resetNativeStateButton.isEnabled = false
        isProviderRecoveryVisible = false
    }

    private func clearFreshSessionFailurePresentation() {
        freshSessionActions.isHidden = true
        retryFreshSessionButton.isEnabled = false
        reloadFreshSessionButton.isEnabled = false
        isFreshSessionFailureVisible = false
    }

    @objc private func retryProviderRecovery(_ sender: Any?) {
        guard isProviderRecoveryVisible, retryRecoveryButton.isEnabled else { return }
        retryRecoveryAction?()
    }

    @objc private func openProviderRecoverySettings(_ sender: Any?) {
        guard isProviderRecoveryVisible, openProvidersButton.isEnabled else { return }
        openProvidersAction?()
    }

    @objc private func chooseLocalModelForRecovery(_ sender: Any?) {
        guard isProviderRecoveryVisible, chooseLocalModelButton.isEnabled else { return }
        chooseLocalModelAction?()
    }

    @objc private func resetProviderRecoveryState(_ sender: Any?) {
        guard isProviderRecoveryVisible, resetNativeStateButton.isEnabled else { return }
        resetNativeStateAction?()
    }

    @objc private func retryFreshSession(_ sender: Any?) {
        guard isFreshSessionFailureVisible, retryFreshSessionButton.isEnabled else { return }
        showLoading("Creating and verifying a fresh Harness task…")
        startNewSession()
    }

    @objc private func reloadAfterFreshSessionFailure(_ sender: Any?) {
        guard isFreshSessionFailureVisible, reloadFreshSessionButton.isEnabled else { return }
        showLoading("Reloading the Agent Workspace…")
        reload()
    }

    @objc private func openThermalProviders(_ sender: Any?) {
        guard isThermalCooldownVisible, thermalProvidersButton.isEnabled else { return }
        thermalProvidersAction?()
    }

    @objc private func openThermalPerformance(_ sender: Any?) {
        guard isThermalCooldownVisible, thermalPerformanceButton.isEnabled else { return }
        thermalPerformanceAction?()
    }

    func configure(endpoint: HarnessEndpoint?) {
        guard self.endpoint != endpoint else { return }
        boundaryGeneration &+= 1
        webView.stopLoading()
        navigationGenerations.removeAll(keepingCapacity: true)
        freshSessionRequirement.invalidateAttempt()
        invalidateDownloadsForBoundaryChange()
        if endpoint == nil { turnAdmissionsSuspended = true }
        self.endpoint = endpoint
        securityPolicy = endpoint.map { NavigationSecurityPolicy(port: $0.baseURL.port ?? -1) }
        hasLoadedHarness = false
        if endpoint == nil { showLoading("Securing your local workspace…") }
    }

    private func invalidateDownloadsForBoundaryChange() {
        let downloads = activeDownloads.values
        activeDownloads.removeAll(keepingCapacity: true)
        webDownloadOperationIDs.removeAll(keepingCapacity: true)
        for active in downloads {
            active.cancelledByPolicy = true
            active.stopMonitoring()
            active.download?.cancel { _ in }
            downloadOperations?.discardPending(active.pending)
        }
        activeArtifactOperations.removeAll(keepingCapacity: true)
        if let downloadOperations {
            downloadProcessingQueue.async {
                downloadOperations.cleanup()
            }
        }
    }

    /// Must be called synchronously by the global mutation/termination gate.
    /// It blocks every future native checkpoint even if WebKit is between an
    /// acknowledged checkpoint and its JavaScript `priorSend` continuation.
    func suspendTurnAdmissions() {
        turnAdmissionsSuspended = true
    }

    /// A closed page is never reopened in place. The host calls this only for
    /// a topology-verified endpoint immediately before loading a fresh page and
    /// requiring a newly host-validated session.
    func resumeTurnAdmissionsForFreshRuntime() {
        guard endpoint != nil else { return }
        turnAdmissionsSuspended = false
    }

    /// A memory warning does not replace the authenticated runtime or page. It
    /// closes only new native checkpoints, so the same verified page can be
    /// reopened after the host has observed the full recovery window.
    func resumeTurnAdmissionsAfterResourcePressure() {
        guard endpoint != nil else { return }
        turnAdmissionsSuspended = false
    }

    func loadHarness(force: Bool = false) {
        loadViewIfNeeded()
        guard let endpoint else {
            showLoading("Waiting for the private runtime…")
            return
        }
        guard force || !hasLoadedHarness else { return }
        showLoading("Opening DeepSeek Harness…")
        var request = endpoint.authenticatedRequest(to: endpoint.bootstrapURL)
        request.httpShouldHandleCookies = true
        trackNavigation(webView.load(request))
    }

    func reload() {
        freshSessionRequirement.invalidateAttempt()
        if hasLoadedHarness {
            trackNavigation(webView.reload())
        } else {
            loadHarness(force: true)
        }
    }

    func goBack() {
        if webView.canGoBack { trackNavigation(webView.goBack()) }
    }

    func goForward() {
        if webView.canGoForward { trackNavigation(webView.goForward()) }
    }

    func startNewSession() {
        freshSessionRequirement.require()
        guard hasLoadedHarness else {
            loadHarness(force: true)
            return
        }
        guard let attempt = freshSessionRequirement.begin() else { return }
        let generation = boundaryGeneration
        showLoading("Creating and verifying a fresh Harness task…")
        operations.startFreshSession(webView) { [weak self] result in
            guard let self, self.boundaryGeneration == generation else { return }
                switch result {
                case .success(let value):
                    guard let sessionID = FreshSessionBridgeValidation.sessionID(from: value) else {
                        self.failFreshSession(attempt: attempt, generation: generation)
                        return
                    }
                    guard let delegate = self.delegate else {
                        self.failFreshSession(attempt: attempt, generation: generation)
                        return
                    }
                    delegate.webSurface(self, validateFreshSession: sessionID) { [weak self] validation in
                        DispatchQueue.main.async {
                            guard let self, self.boundaryGeneration == generation else { return }
                            switch validation {
                            case .success:
                                guard self.freshSessionRequirement.succeed(attempt) else { return }
                                self.setSpinnerBusy(false)
                                self.loadingView.isHidden = true
                            case .failure:
                                self.failFreshSession(attempt: attempt, generation: generation)
                            }
                        }
                    }
                case .failure:
                    self.failFreshSession(attempt: attempt, generation: generation)
                }
        }
    }

    private func failFreshSession(attempt: UUID, generation: UInt64) {
        guard boundaryGeneration == generation else { return }
        guard freshSessionRequirement.fail(attempt) else { return }
        showFreshSessionFailure()
        delegate?.webSurface(self, didFailWith: HarnessWebSurfaceFailure.freshSessionVerification.message)
    }

    /// Provider changes are security-boundary changes. The embedded Harness
    /// must not silently carry prompt, tool, or skill context from the previous
    /// route into the newly selected route after the runtime restarts.
    func requireFreshSessionAfterNextLoad() {
        freshSessionRequirement.require()
    }

    func openModelsAndProviders(completion: @escaping (Bool) -> Void) {
        guard hasLoadedHarness else { completion(false); return }
        let script = """
        (async () => {
          const elements = () => Array.from(document.querySelectorAll('button, a, [role="button"], [role="menuitem"], [role="tab"]'));
          const label = (element) => [element.textContent, element.getAttribute('aria-label'), element.getAttribute('title')]
            .filter(Boolean).join(' ').replace(/\\s+/g, ' ').trim().toLowerCase();
          const clickNamed = (pattern) => {
            const target = elements().find((element) => pattern.test(label(element)));
            if (!target) return false;
            target.click();
            return true;
          };
          if (clickNamed(/^(models|models & providers|model providers)$/i)) return true;
          if (!clickNamed(/^(settings|preferences)$/i)) return false;
          await new Promise((resolve) => setTimeout(resolve, 250));
          return clickNamed(/^(models|models & providers|model providers)$/i);
        })();
        """
        webView.evaluateJavaScript(script) { value, error in
            DispatchQueue.main.async { completion(error == nil && value as? Bool == true) }
        }
    }

    func zoomIn() {
        webView.pageZoom = min(webView.pageZoom + 0.1, 3.0)
    }

    func zoomOut() {
        webView.pageZoom = max(webView.pageZoom - 0.1, 0.5)
    }

    func actualSize() {
        webView.pageZoom = 1.0
    }

    func pasteImage(_ image: NSImage) {
        attachImage(image, filename: "Appshot.png", accessibleText: nil, completion: nil)
    }

    func attachImage(_ image: NSImage, filename: String, accessibleText: String?, completion: ((Bool) -> Void)?) {
        guard let tiff = image.tiffRepresentation,
              let bitmap = NSBitmapImageRep(data: tiff),
              let png = bitmap.representation(using: .png, properties: [:]) else {
            completion?(false)
            return
        }
        let payload: [String: Any] = [
            "base64": png.base64EncodedString(),
            "filename": DownloadPath.safeFilename(filename, fallback: "Appshot.png"),
            "accessibleText": accessibleText ?? ""
        ]
        let script = """
        (() => {
          const binary = atob(payload.base64);
          const bytes = new Uint8Array(binary.length);
          for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
          const file = new File([bytes], payload.filename, { type: 'image/png' });
          const transfer = new DataTransfer();
          transfer.items.add(file);
          const input = document.querySelector('input[type="file"]');
          if (input) {
            input.files = transfer.files;
            input.dispatchEvent(new Event('change', { bubbles: true }));
          } else {
            const target = document.querySelector('textarea') || document.querySelector('[contenteditable="true"]');
            if (!target) return false;
            target.focus();
            target.dispatchEvent(new ClipboardEvent('paste', { clipboardData: transfer, bubbles: true }));
          }
          if (payload.accessibleText) {
            const target = document.querySelector('textarea') || document.querySelector('[contenteditable="true"]');
            if (target && 'value' in target) {
              const prefix = target.value ? target.value + '\n\n' : '';
              target.value = prefix + '[Accessible text from appshot]\n' + payload.accessibleText;
              target.dispatchEvent(new Event('input', { bubbles: true }));
            }
          }
          return true;
        })();
        """
        webView.callAsyncJavaScript(script, arguments: ["payload": payload], in: nil, in: .page) { result in
            DispatchQueue.main.async {
                switch result { case .success(let value): completion?(value as? Bool == true); case .failure: completion?(false) }
            }
        }
    }

    func clearWebData(completion: @escaping () -> Void) {
        let types = WKWebsiteDataStore.allWebsiteDataTypes()
        dataStore.removeData(ofTypes: types, modifiedSince: .distantPast) {
            DispatchQueue.main.async { completion() }
        }
    }

    func performFindAction(_ sender: Any?) {
        webView.performTextFinderAction(sender)
    }

    func webView(_ webView: WKWebView, didStartProvisionalNavigation navigation: WKNavigation!) {
        trackNavigation(navigation)
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        guard consumeCurrentNavigation(navigation),
              let currentURL = webView.url,
              currentURL.scheme == "http",
              securityPolicy?.permitsEmbeddedNavigation(to: currentURL) == true else {
            return
        }
        hasLoadedHarness = true
        if freshSessionRequirement.isRequired {
            startNewSession()
        } else {
            setSpinnerBusy(false)
            loadingView.isHidden = true
        }
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        guard consumeCurrentNavigation(navigation) else { return }
        freshSessionRequirement.invalidateAttempt()
        if isBenignNavigationCancellation(error) { return }
        let message = HarnessWebPresentationPolicy.failure(
            for: error,
            provisionalNavigation: false
        ).message
        showFailure(message)
        delegate?.webSurface(self, didFailWith: message)
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        guard consumeCurrentNavigation(navigation) else { return }
        freshSessionRequirement.invalidateAttempt()
        if isBenignNavigationCancellation(error) { return }
        let message = HarnessWebPresentationPolicy.failure(
            for: error,
            provisionalNavigation: true
        ).message
        showFailure(message)
        delegate?.webSurface(self, didFailWith: message)
    }

    private func trackNavigation(_ navigation: WKNavigation?) {
        guard let navigation else { return }
        // A WKWebView has one main-frame navigation at a time. Replacing the
        // tracked identity makes late finish/failure callbacks from a stopped,
        // reloaded, or superseded page inert.
        navigationGenerations.removeAll(keepingCapacity: true)
        navigationGenerations[ObjectIdentifier(navigation)] = boundaryGeneration
    }

    private func consumeCurrentNavigation(_ navigation: WKNavigation?) -> Bool {
        guard let navigation else { return false }
        let key = ObjectIdentifier(navigation)
        guard let generation = navigationGenerations.removeValue(forKey: key) else { return false }
        return generation == boundaryGeneration
    }

    private func isBenignNavigationCancellation(_ error: Error) -> Bool {
        let nsError = error as NSError
        return nsError.domain == NSURLErrorDomain && nsError.code == NSURLErrorCancelled
    }

    func webView(
        _ webView: WKWebView,
        decidePolicyFor navigationAction: WKNavigationAction,
        decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
    ) {
        guard let url = navigationAction.request.url else {
            decisionHandler(.cancel)
            return
        }
        if securityPolicy?.permitsEmbeddedNavigation(to: url) == true {
            decisionHandler(navigationAction.shouldPerformDownload ? .download : .allow)
        } else if securityPolicy?.normalizedExternalHTTPSURL(url) != nil {
            requestExternalBrowserHandoff(url)
            decisionHandler(.cancel)
        } else {
            decisionHandler(.cancel)
        }
    }

    func webView(
        _ webView: WKWebView,
        decidePolicyFor navigationResponse: WKNavigationResponse,
        decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void
    ) {
        guard let responseURL = navigationResponse.response.url,
              securityPolicy?.permitsEmbeddedNavigation(to: responseURL) == true else {
            decisionHandler(.cancel)
            return
        }
        let disposition = (navigationResponse.response as? HTTPURLResponse)?
            .value(forHTTPHeaderField: "Content-Disposition")?.lowercased() ?? ""
        if disposition.contains("attachment") || !navigationResponse.canShowMIMEType {
            decisionHandler(.download)
        } else {
            decisionHandler(.allow)
        }
    }

    func webView(
        _ webView: WKWebView,
        createWebViewWith configuration: WKWebViewConfiguration,
        for navigationAction: WKNavigationAction,
        windowFeatures: WKWindowFeatures
    ) -> WKWebView? {
        guard let url = navigationAction.request.url else { return nil }
        if securityPolicy?.permitsEmbeddedNavigation(to: url) == true {
            trackNavigation(webView.load(URLRequest(url: url)))
        } else if securityPolicy?.normalizedExternalHTTPSURL(url) != nil {
            requestExternalBrowserHandoff(url)
        }
        return nil
    }

    func requestExternalBrowserHandoff(_ candidateURL: URL) {
        guard let url = securityPolicy?.normalizedExternalHTTPSURL(candidateURL),
              !externalHandoffInProgress else { return }
        externalHandoffInProgress = true
        defer { externalHandoffInProgress = false }
        if preferences.confirmExternalLinks {
            let approved: Bool
            if let externalLinkConfirmationHandler {
                approved = externalLinkConfirmationHandler(url)
            } else {
                approved = interactions.confirmExternalLink(HarnessExternalLinkPresentation(
                    destination: HarnessWebPresentationPolicy.externalDestination(url)
                ))
            }
            guard approved else { return }
        }
        delegate?.webSurface(self, didOpenExternalURL: url)
    }

    func webView(_ webView: WKWebView, navigationAction: WKNavigationAction, didBecome download: WKDownload) {
        download.delegate = self
    }

    func webView(_ webView: WKWebView, navigationResponse: WKNavigationResponse, didBecome download: WKDownload) {
        download.delegate = self
    }

    func download(
        _ download: WKDownload,
        decideDestinationUsing response: URLResponse,
        suggestedFilename: String,
        completionHandler: @escaping (URL?) -> Void
    ) {
        let webKey = ObjectIdentifier(download)
        guard webDownloadOperationIDs[webKey] == nil else {
            completionHandler(nil)
            reportDownloadFailure(.downloadRejected)
            return
        }
        let operationID = UUID()
        webDownloadOperationIDs[webKey] = operationID
        let destination = beginDownloadTransfer(
            operationID: operationID,
            response: response,
            suggestedFilename: suggestedFilename,
            download: download
        )
        if destination == nil { webDownloadOperationIDs.removeValue(forKey: webKey) }
        completionHandler(destination)
    }

    /// Operation-ID core shared by WebKit and deterministic boundary tests.
    /// The UUID is caller-owned, replay-protected for the active transfer, and
    /// never displayed or persisted.
    @discardableResult
    func beginDownloadTransfer(
        operationID: UUID,
        response: URLResponse,
        suggestedFilename: String,
        download: WKDownload? = nil
    ) -> URL? {
        guard let downloadOperations else {
            reportDownloadFailure(.downloadStagingUnavailable)
            return nil
        }
        guard activeDownloads[operationID] == nil else {
            reportDownloadFailure(.downloadRejected)
            return nil
        }
        do {
            let pending = try downloadOperations.prepare(
                suggestedFilename,
                response.mimeType,
                response.expectedContentLength,
                response.url
            )
            let active = ActiveWebDownload(
                pending: pending,
                download: download,
                generation: boundaryGeneration
            )
            activeDownloads[operationID] = active
            if let download {
                startMonitoring(
                    download,
                    operationID: operationID,
                    active: active,
                    operations: downloadOperations
                )
            }
            return pending.incomingURL
        } catch {
            reportDownloadFailure(HarnessWebPresentationPolicy.downloadFailure(error, phase: .staging))
            return nil
        }
    }

    func downloadDidFinish(_ download: WKDownload) {
        let webKey = ObjectIdentifier(download)
        guard let operationID = webDownloadOperationIDs.removeValue(forKey: webKey) else { return }
        finishDownloadTransfer(operationID: operationID)
    }

    func finishDownloadTransfer(operationID: UUID) {
        guard let active = activeDownloads.removeValue(forKey: operationID), let downloadOperations else { return }
        active.stopMonitoring()
        guard active.generation == boundaryGeneration else {
            downloadOperations.discardPending(active.pending)
            return
        }
        let generation = active.generation
        downloadProcessingQueue.async { [weak self] in
            let result = Result { try downloadOperations.finalize(active.pending) }
            DispatchQueue.main.async {
                guard let self else {
                    if case .success(let artifact) = result { downloadOperations.discardArtifact(artifact) }
                    else { downloadOperations.discardPending(active.pending) }
                    return
                }
                guard self.boundaryGeneration == generation else {
                    if case .success(let artifact) = result { downloadOperations.discardArtifact(artifact) }
                    else { downloadOperations.discardPending(active.pending) }
                    return
                }
                switch result {
                case .success(let artifact):
                    self.reviewStagedDownload(artifact, operations: downloadOperations, generation: generation)
                case .failure(let error):
                    downloadOperations.discardPending(active.pending)
                    self.reportDownloadFailure(HarnessWebPresentationPolicy.downloadFailure(error, phase: .finalization))
                }
            }
        }
    }

    func download(_ download: WKDownload, didFailWithError error: Error, resumeData: Data?) {
        let webKey = ObjectIdentifier(download)
        guard let operationID = webDownloadOperationIDs.removeValue(forKey: webKey) else { return }
        failDownloadTransfer(operationID: operationID, error: error)
    }

    func failDownloadTransfer(operationID: UUID, error: Error) {
        guard let active = activeDownloads.removeValue(forKey: operationID) else { return }
        active.stopMonitoring()
        downloadOperations?.discardPending(active.pending)
        if active.cancelledByPolicy { return }
        reportDownloadFailure(HarnessWebPresentationPolicy.downloadFailure(error, phase: .transfer))
    }

    private func startMonitoring(
        _ download: WKDownload,
        operationID: UUID,
        active: ActiveWebDownload,
        operations: HarnessDownloadOperations
    ) {
        let monitor = DispatchSource.makeTimerSource(queue: .main)
        active.monitor = monitor
        monitor.schedule(deadline: .now() + .milliseconds(100), repeating: .milliseconds(100), leeway: .milliseconds(25))
        monitor.setEventHandler { [weak self, weak download] in
            guard let self, let download, self.activeDownloads[operationID] === active else { return }
            guard active.generation == self.boundaryGeneration else {
                active.cancelledByPolicy = true
                active.stopMonitoring()
                self.activeDownloads.removeValue(forKey: operationID)
                self.webDownloadOperationIDs.removeValue(forKey: ObjectIdentifier(download))
                download.cancel { _ in }
                operations.discardPending(active.pending)
                return
            }
            guard case .rejected = operations.inspect(active.pending) else { return }
            active.cancelledByPolicy = true
            active.stopMonitoring()
            self.activeDownloads.removeValue(forKey: operationID)
            self.webDownloadOperationIDs.removeValue(forKey: ObjectIdentifier(download))
            download.cancel { _ in }
            operations.discardPending(active.pending)
            self.reportDownloadFailure(.downloadRejected)
        }
        monitor.resume()
    }

    func reviewStagedDownload(
        _ artifact: StagedDownloadArtifact,
        operations: HarnessDownloadOperations,
        generation: UInt64? = nil
    ) {
        let generation = generation ?? boundaryGeneration
        guard generation == boundaryGeneration else {
            operations.discardArtifact(artifact)
            return
        }
        let operationKey = artifactOperationKey(artifact)
        guard activeArtifactOperations.insert(operationKey).inserted else { return }
        let size = ByteCountFormatter.string(fromByteCount: artifact.byteCount, countStyle: .file)
        let presentation = HarnessDownloadReviewPresentation(
            filename: HarnessWebPresentationPolicy.downloadFilename(artifact.displayFilename),
            sizeAndCategory: "\(size) · \(artifact.category.displayName)",
            detectedContent: safeMIMEType(artifact.detectedMIMEType),
            sha256: safeDigest(artifact.sha256),
            warningCount: min(artifact.warnings.count, 999),
            allowsPreview: artifact.allowsManualPreview
        )
        switch interactions.reviewDownload(presentation) {
        case .preview where artifact.allowsManualPreview:
            validateAndPreview(
                artifact,
                operations: operations,
                generation: generation,
                operationKey: operationKey
            )
        case .save:
            saveStagedDownload(
                artifact,
                operations: operations,
                generation: generation,
                operationKey: operationKey
            )
        case .preview, .discard:
            activeArtifactOperations.remove(operationKey)
            operations.discardArtifact(artifact)
        }
    }

    private func validateAndPreview(
        _ artifact: StagedDownloadArtifact,
        operations: HarnessDownloadOperations,
        generation: UInt64,
        operationKey: String
    ) {
        downloadProcessingQueue.async { [weak self] in
            let result = Result { try operations.validateForPreview(artifact) }
            DispatchQueue.main.async {
                guard let self else {
                    operations.discardArtifact(artifact)
                    return
                }
                self.activeArtifactOperations.remove(operationKey)
                guard self.boundaryGeneration == generation else {
                    operations.discardArtifact(artifact)
                    return
                }
                switch result {
                case .success:
                    self.delegate?.webSurface(self, didCompleteDownload: artifact, action: .previewRequested)
                case .failure(let error):
                    operations.discardArtifact(artifact)
                    self.reportDownloadFailure(HarnessWebPresentationPolicy.downloadFailure(error, phase: .preview))
                }
            }
        }
    }

    private func saveStagedDownload(
        _ artifact: StagedDownloadArtifact,
        operations: HarnessDownloadOperations,
        generation: UInt64,
        operationKey: String
    ) {
        let destination = interactions.chooseSaveDestination(HarnessDownloadSavePresentation(
            suggestedFilename: HarnessWebPresentationPolicy.downloadFilename(artifact.displayFilename)
        ))
        guard let destination, destination.isFileURL else {
            activeArtifactOperations.remove(operationKey)
            operations.discardArtifact(artifact)
            if destination != nil { reportDownloadFailure(.downloadSaveFailed) }
            return
        }

        downloadProcessingQueue.async { [weak self] in
            let result = Result { try operations.export(artifact, destination) }
            DispatchQueue.main.async {
                guard let self else {
                    if case .failure = result { operations.discardArtifact(artifact) }
                    return
                }
                self.activeArtifactOperations.remove(operationKey)
                guard self.boundaryGeneration == generation else {
                    if case .failure = result { operations.discardArtifact(artifact) }
                    return
                }
                switch result {
                case .success(let saved): self.delegate?.webSurface(self, didCompleteDownload: saved, action: .saved)
                case .failure(let error):
                    operations.discardArtifact(artifact)
                    self.reportDownloadFailure(HarnessWebPresentationPolicy.downloadFailure(error, phase: .save))
                }
            }
        }
    }

    private func artifactOperationKey(_ artifact: StagedDownloadArtifact) -> String {
        artifact.sha256 + "|" + artifact.fileURL.standardizedFileURL.path
    }

    private func safeMIMEType(_ value: String?) -> String? {
        guard let value, value.utf8.count <= 127,
              value.filter({ $0 == "/" }).count == 1,
              value.unicodeScalars.allSatisfy({ scalar in
                  let alphaNumeric = (48...57).contains(scalar.value)
                      || (65...90).contains(scalar.value)
                      || (97...122).contains(scalar.value)
                  return alphaNumeric || "!#$&^_.+-/".unicodeScalars.contains(scalar)
              }) else { return nil }
        return value
    }

    private func safeDigest(_ value: String) -> String {
        guard value.utf8.count == 64,
              value.unicodeScalars.allSatisfy({
                  (48...57).contains($0.value) || (65...70).contains($0.value) || (97...102).contains($0.value)
              }) else { return "Unavailable" }
        return value.lowercased()
    }

    private func reportDownloadFailure(_ failure: HarnessWebSurfaceFailure) {
        let message = failure.message
        delegate?.webSurface(self, didFailWith: message)
        interactions.showDownloadFailure(
            HarnessDownloadFailurePresentation(message: message),
            viewIfLoaded?.window
        )
    }
}

private final class ActiveWebDownload {
    let pending: PendingDownloadDestination
    weak var download: WKDownload?
    var monitor: DispatchSourceTimer?
    var cancelledByPolicy = false
    let generation: UInt64

    init(pending: PendingDownloadDestination, download: WKDownload?, generation: UInt64) {
        self.pending = pending
        self.download = download
        self.generation = generation
    }

    func stopMonitoring() {
        monitor?.cancel()
        monitor = nil
    }
}
