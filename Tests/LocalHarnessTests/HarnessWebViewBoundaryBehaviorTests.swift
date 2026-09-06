import AppKit
import Testing
import WebKit
@testable import LocalHarness

private struct HostileWebBoundaryError: LocalizedError {
    let errorDescription: String? = "\u{202E}Bearer super-secret-token-123456 https://evil.example/leak?api_key=sk-abcdefghijklmnop /Users/alice/private.txt"
}

@MainActor
private final class WebBoundaryDelegateProbe: HarnessWebViewControllerDelegate {
    var openedURLs: [URL] = []
    var failures: [String] = []
    var downloads: [(StagedDownloadArtifact, StagedDownloadUserAction)] = []
    var validation: Result<Void, Error> = .success(())

    func webSurface(_ surface: HarnessWebViewController, didOpenExternalURL url: URL) {
        openedURLs.append(url)
    }

    func webSurface(
        _ surface: HarnessWebViewController,
        didCompleteDownload artifact: StagedDownloadArtifact,
        action: StagedDownloadUserAction
    ) {
        downloads.append((artifact, action))
    }

    func webSurface(_ surface: HarnessWebViewController, didFailWith message: String) {
        failures.append(message)
    }

    func webSurface(
        _ surface: HarnessWebViewController,
        validateFreshSession sessionID: HarnessSessionID,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        completion(validation)
    }

    func webSurface(
        _ surface: HarnessWebViewController,
        prepareTurnIn sessionID: HarnessSessionID,
        operationID: UUID,
        completion: @escaping (Result<TurnPreparationBridgeResult, Error>) -> Void
    ) {
        completion(.failure(CancellationError()))
    }

    func webSurface(_ surface: HarnessWebViewController, cancelTurnPreparation operationID: UUID) {}
    func performanceSessionID(for surface: HarnessWebViewController) -> HarnessSessionID? { nil }
    func approvedWorkspacePath(for surface: HarnessWebViewController) -> String? { nil }
}

private final class DownloadBoundaryProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [String: Int] = [:]
    private var validationStartedStorage = false

    func increment(_ key: String) {
        lock.withLock { storage[key, default: 0] += 1 }
    }

    func count(_ key: String) -> Int {
        lock.withLock { storage[key, default: 0] }
    }

    func markValidationStarted() {
        lock.withLock { validationStartedStorage = true }
    }

    var validationStarted: Bool {
        lock.withLock { validationStartedStorage }
    }
}

@MainActor
private func testInteractions(
    confirm: @escaping (HarnessExternalLinkPresentation) -> Bool = { _ in false },
    review: @escaping (HarnessDownloadReviewPresentation) -> HarnessDownloadReviewChoice = { _ in .discard },
    save: @escaping (HarnessDownloadSavePresentation) -> URL? = { _ in nil },
    failure: @escaping (HarnessDownloadFailurePresentation, NSWindow?) -> Void = { _, _ in }
) -> HarnessWebViewInteractions {
    HarnessWebViewInteractions(
        confirmExternalLink: confirm,
        reviewDownload: review,
        chooseSaveDestination: save,
        showDownloadFailure: failure
    )
}

private func testPendingDownload() -> PendingDownloadDestination {
    let directory = URL(fileURLWithPath: "/private/tmp/fulmar-hidden-transfer", isDirectory: true)
    return PendingDownloadDestination(
        transferDirectory: directory,
        incomingURL: directory.appendingPathComponent("incoming.download"),
        displayFilename: "report.pdf",
        reportedMIMEType: "application/pdf",
        sourceOrigin: "https://secret.example"
    )
}

private func testArtifact(
    filename: String = "report.pdf",
    sha256: String = String(repeating: "a", count: 64),
    mimeType: String? = "application/pdf",
    allowsPreview: Bool = true,
    warnings: [String] = []
) -> StagedDownloadArtifact {
    StagedDownloadArtifact(
        fileURL: URL(fileURLWithPath: "/private/tmp/fulmar-secret-staging/private-file"),
        displayFilename: filename,
        byteCount: 1_024,
        sha256: sha256,
        reportedMIMEType: mimeType,
        detectedMIMEType: mimeType,
        typeIdentifier: "com.adobe.pdf",
        category: .passiveDocument,
        allowsManualPreview: allowsPreview,
        warnings: warnings,
        quarantineApplied: true
    )
}

private func testDownloadOperations(
    probe: DownloadBoundaryProbe,
    pending: PendingDownloadDestination = testPendingDownload(),
    artifact: StagedDownloadArtifact = testArtifact(),
    prepare: ((String, String?, Int64, URL?) throws -> PendingDownloadDestination)? = nil,
    finalize: ((PendingDownloadDestination) throws -> StagedDownloadArtifact)? = nil,
    validate: ((StagedDownloadArtifact) throws -> Void)? = nil,
    export: ((StagedDownloadArtifact, URL) throws -> StagedDownloadArtifact)? = nil
) -> HarnessDownloadOperations {
    HarnessDownloadOperations(
        prepare: prepare ?? { _, _, _, _ in
            probe.increment("prepare")
            return pending
        },
        inspect: { _ in .notCreated },
        finalize: finalize ?? { _ in
            probe.increment("finalize")
            return artifact
        },
        validateForPreview: validate ?? { _ in probe.increment("validate") },
        export: export ?? { _, destination in
            probe.increment("export")
            return StagedDownloadArtifact(
                fileURL: destination,
                displayFilename: destination.lastPathComponent,
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
        },
        discardPending: { _ in probe.increment("discard-pending") },
        discardArtifact: { _ in probe.increment("discard-artifact") },
        cleanup: { probe.increment("cleanup") }
    )
}

@MainActor
private func eventually(
    attempts: Int = 200,
    condition: @escaping @MainActor () -> Bool
) async -> Bool {
    for _ in 0..<attempts {
        if condition() { return true }
        try? await Task.sleep(for: .milliseconds(10))
    }
    return condition()
}

@Test
func webPresentationPolicyBoundsRedactsAndRemovesDirectionalControls() throws {
    let hostile = "\u{202E}Bearer super-secret-token-123456 https://evil.example/leak?api_key=sk-abcdefghijklmnop /Users/alice/private.txt api_key=topsecret "
        + String(repeating: "x", count: 2_000)
    let safe = HarnessWebPresentationPolicy.appText(hostile, limit: 180, fallback: "Fallback")

    #expect(safe.count <= 181)
    #expect(!safe.contains("\u{202E}"))
    #expect(!safe.contains("super-secret"))
    #expect(!safe.contains("evil.example"))
    #expect(!safe.contains("/Users/alice"))
    #expect(!safe.contains("topsecret"))
    #expect(safe.contains("[REDACTED]"))
    #expect(safe.contains("[redacted address]"))
    #expect(safe.contains("[redacted path]"))

    let external = try #require(URL(string: "https://Example.com:8443/private/sk-abcdefghijklmnop?q=secret#fragment"))
    #expect(HarnessWebPresentationPolicy.externalDestination(external) == "https://example.com:8443 (private path or query hidden)")
}

@Test
func freshSessionProofValidationRejectsHostileStaleAndOversizedProofs() {
    let valid = #"{"ok":true,"proof":{"before":"old","created":"new-session","current":"new-session"}}"#
    #expect(FreshSessionBridgeValidation.sessionID(from: valid) == HarnessSessionID("new-session"))

    let hostileValues: [Any] = [
        #"{"ok":false,"error":"Bearer secret /Users/alice/private"}"#,
        #"{"ok":true,"proof":{"before":"same","created":"same","current":"same"}}"#,
        #"{"ok":true,"proof":{"before":"old","created":"new","current":"other"}}"#,
        "{\"ok\":true,\"proof\":{\"before\":\"old\",\"created\":\"bad\u{202E}id\",\"current\":\"bad\u{202E}id\"}}",
        #"{"ok":true,"proof":{"before":"old","created":"new","current":"new","extra":true}}"#,
        String(repeating: "x", count: 2_049),
        42
    ]
    for hostile in hostileValues {
        #expect(FreshSessionBridgeValidation.sessionID(from: hostile) == nil)
    }
}

@Test
func performanceBridgeRequiresExactVersionAndCanonicalBoundedWorkspace() {
    let safePath = "/Users/alice/Agent Workspace"
    let acceptedVersions: [Any] = [NSNumber(value: 1), NSNumber(value: 1.0)]
    for version in acceptedVersions {
        #expect(PerformanceBridgeRequestValidation.accepts(
            body: ["version": version],
            workspacePath: safePath
        ))
    }

    let rejectedVersions: [Any] = [
        NSNumber(value: true),
        NSNumber(value: 1.9),
        NSNumber(value: Double.nan),
        NSNumber(value: Double.infinity),
        NSNumber(value: 0),
        NSNumber(value: 2),
        "1",
        NSNull()
    ]
    for version in rejectedVersions {
        #expect(!PerformanceBridgeRequestValidation.accepts(
            body: ["version": version],
            workspacePath: safePath
        ))
    }
    #expect(!PerformanceBridgeRequestValidation.accepts(
        body: ["version": NSNumber(value: 1), "extra": true],
        workspacePath: safePath
    ))

    let rejectedPaths = [
        "",
        "/",
        "relative/workspace",
        "/Users/alice/Workspace/../private",
        "/Users/alice/Workspace/",
        "/Users/alice/Work\0space",
        "/Users/alice/Work\nspace",
        "/Users/alice/Work\u{202E}space",
        "/" + String(repeating: "x", count: 4_096)
    ]
    for path in rejectedPaths {
        #expect(!PerformanceBridgeRequestValidation.accepts(
            body: ["version": NSNumber(value: 1)],
            workspacePath: path
        ))
    }
}

@Test
func allHostileErrorPhasesResolveToBoundedAppOwnedCopy() {
    let hostile = HostileWebBoundaryError()
    let failures = [
        HarnessWebPresentationPolicy.failure(for: hostile, provisionalNavigation: false),
        HarnessWebPresentationPolicy.failure(for: hostile, provisionalNavigation: true),
        HarnessWebPresentationPolicy.downloadFailure(hostile, phase: .staging),
        HarnessWebPresentationPolicy.downloadFailure(hostile, phase: .transfer),
        HarnessWebPresentationPolicy.downloadFailure(hostile, phase: .finalization),
        HarnessWebPresentationPolicy.downloadFailure(hostile, phase: .preview),
        HarnessWebPresentationPolicy.downloadFailure(hostile, phase: .save)
    ]
    for failure in failures {
        #expect(failure.message.utf8.count <= 180)
        #expect(!failure.message.contains("secret"))
        #expect(!failure.message.contains("evil.example"))
        #expect(!failure.message.contains("/Users"))
        #expect(!failure.message.contains("\u{202E}"))
    }
}

@Test @MainActor
func navigationErrorsAreAppOwnedWhileCancellationAndStaleCallbacksAreInert() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    var downloadFailures: [String] = []
    let surface = HarnessWebViewController(
        dataStore: .nonPersistent(),
        preferences: .shared,
        interactions: testInteractions(failure: { presentation, _ in downloadFailures.append(presentation.message) }),
        operations: nil,
        downloadOperations: nil
    )
    let delegate = WebBoundaryDelegateProbe()
    surface.delegate = delegate
    let firstEndpoint = HarnessEndpoint(
        baseURL: URL(string: "http://127.0.0.1:3080/")!,
        token: "one",
        nonce: "one",
        processIdentifier: 1
    )
    surface.configure(endpoint: firstEndpoint)
    // WKNavigation's public NSObject initializer does not create a valid
    // WebKit-owned navigation and traps during deallocation on macOS 26.
    // Retain a donor view and use real navigation handles returned by WebKit.
    let navigationDonor = WKWebView(frame: .zero, configuration: WKWebViewConfiguration())

    let failed = try #require(navigationDonor.loadHTMLString("<p>failed</p>", baseURL: firstEndpoint.baseURL))
    navigationDonor.stopLoading()
    surface.webView(surface.webView, didStartProvisionalNavigation: failed)
    surface.webView(surface.webView, didFailProvisionalNavigation: failed, withError: HostileWebBoundaryError())
    #expect(delegate.failures == [HarnessWebSurfaceFailure.navigationUnavailable.message])

    let cancelled = try #require(navigationDonor.loadHTMLString("<p>cancelled</p>", baseURL: firstEndpoint.baseURL))
    navigationDonor.stopLoading()
    surface.webView(surface.webView, didStartProvisionalNavigation: cancelled)
    surface.webView(
        surface.webView,
        didFailProvisionalNavigation: cancelled,
        withError: NSError(domain: NSURLErrorDomain, code: NSURLErrorCancelled)
    )
    #expect(delegate.failures.count == 1)

    let stale = try #require(navigationDonor.loadHTMLString("<p>stale</p>", baseURL: firstEndpoint.baseURL))
    navigationDonor.stopLoading()
    surface.webView(surface.webView, didStartProvisionalNavigation: stale)
    surface.configure(endpoint: HarnessEndpoint(
        baseURL: URL(string: "http://127.0.0.1:3081/")!,
        token: "two",
        nonce: "two",
        processIdentifier: 2
    ))
    surface.webView(surface.webView, didFail: stale, withError: HostileWebBoundaryError())
    #expect(delegate.failures.count == 1)
    #expect(downloadFailures.isEmpty)
}

@Test @MainActor
func externalLinkInteractionHidesPrivateSuffixAndRejectsReentrantDuplicateHandoffs() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let suite = "FulmarWebBoundaryExternal.\(UUID().uuidString)"
    let defaults = try #require(UserDefaults(suiteName: suite))
    defer { defaults.removePersistentDomain(forName: suite) }
    let preferences = PreferencesStore(defaults: defaults)
    preferences.confirmExternalLinks = true
    var presentations: [HarnessExternalLinkPresentation] = []
    var surface: HarnessWebViewController!
    let interactions = testInteractions(confirm: { presentation in
        presentations.append(presentation)
        surface.requestExternalBrowserHandoff(URL(string: "https://example.com/reentrant")!)
        return true
    })
    surface = HarnessWebViewController(
        dataStore: .nonPersistent(),
        preferences: preferences,
        interactions: interactions,
        operations: nil,
        downloadOperations: nil
    )
    surface.configure(endpoint: HarnessEndpoint(
        baseURL: URL(string: "http://127.0.0.1:3080/")!,
        token: "test",
        nonce: "test",
        processIdentifier: 3
    ))
    let delegate = WebBoundaryDelegateProbe()
    surface.delegate = delegate

    surface.requestExternalBrowserHandoff(URL(string: "https://EXAMPLE.com:8443/private/sk-abcdefghijklmnop?q=secret")!)
    #expect(presentations == [HarnessExternalLinkPresentation(
        destination: "https://example.com:8443 (private path or query hidden)"
    )])
    #expect(delegate.openedURLs.map(\.absoluteString) == [
        "https://example.com:8443/private/sk-abcdefghijklmnop?q=secret"
    ])

    surface.requestExternalBrowserHandoff(URL(string: "https://user:password@example.com/private")!)
    #expect(presentations.count == 1)
    #expect(delegate.openedURLs.count == 1)
}

@Test @MainActor
func downloadStageDuplicateTransferAndUnavailablePathsFailClosedWithoutLeakage() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let response = URLResponse(
        url: URL(string: "http://127.0.0.1:3080/download")!,
        mimeType: "application/pdf",
        expectedContentLength: 1_024,
        textEncodingName: nil
    )
    let probe = DownloadBoundaryProbe()
    var visibleFailures: [String] = []
    let surface = HarnessWebViewController(
        dataStore: .nonPersistent(),
        preferences: .shared,
        interactions: testInteractions(failure: { presentation, _ in visibleFailures.append(presentation.message) }),
        operations: nil,
        downloadOperations: testDownloadOperations(probe: probe)
    )
    let delegate = WebBoundaryDelegateProbe()
    surface.delegate = delegate
    let operationID = UUID()
    let destinations = [
        surface.beginDownloadTransfer(
            operationID: operationID,
            response: response,
            suggestedFilename: "report.pdf"
        ),
        surface.beginDownloadTransfer(
            operationID: operationID,
            response: response,
            suggestedFilename: "duplicate.pdf"
        )
    ]
    surface.failDownloadTransfer(operationID: operationID, error: HostileWebBoundaryError())

    #expect(destinations.count == 2)
    #expect(destinations[0] == testPendingDownload().incomingURL)
    #expect(destinations[1] == nil)
    #expect(probe.count("prepare") == 1)
    #expect(probe.count("discard-pending") == 1)
    #expect(delegate.failures == [
        HarnessWebSurfaceFailure.downloadRejected.message,
        HarnessWebSurfaceFailure.downloadTransferFailed.message
    ])
    #expect(visibleFailures == delegate.failures)

    var unavailableFailures: [String] = []
    let unavailable = HarnessWebViewController(
        dataStore: .nonPersistent(),
        preferences: .shared,
        interactions: testInteractions(failure: { presentation, _ in unavailableFailures.append(presentation.message) }),
        operations: nil,
        downloadOperations: nil
    )
    let unavailableDestination = unavailable.beginDownloadTransfer(
        operationID: UUID(),
        response: response,
        suggestedFilename: "x"
    )
    #expect(unavailableDestination == nil)
    #expect(unavailableFailures == [HarnessWebSurfaceFailure.downloadStagingUnavailable.message])

    let rejectedProbe = DownloadBoundaryProbe()
    var rejectedFailures: [String] = []
    let rejected = HarnessWebViewController(
        dataStore: .nonPersistent(),
        preferences: .shared,
        interactions: testInteractions(failure: { presentation, _ in rejectedFailures.append(presentation.message) }),
        operations: nil,
        downloadOperations: testDownloadOperations(
            probe: rejectedProbe,
            prepare: { _, _, _, _ in throw HostileWebBoundaryError() }
        )
    )
    _ = rejected.beginDownloadTransfer(
        operationID: UUID(),
        response: response,
        suggestedFilename: "x"
    )
    #expect(rejectedFailures == [HarnessWebSurfaceFailure.downloadStagingUnavailable.message])
}

@Test @MainActor
func downloadFinalizationFailureIsAsynchronousBoundedAndDiscardsPending() async throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let response = URLResponse(
        url: URL(string: "http://127.0.0.1:3080/download")!,
        mimeType: "application/pdf",
        expectedContentLength: 1_024,
        textEncodingName: nil
    )
    let probe = DownloadBoundaryProbe()
    var visibleFailures: [String] = []
    let operations = testDownloadOperations(
        probe: probe,
        finalize: { _ in
            probe.increment("finalize")
            throw HostileWebBoundaryError()
        }
    )
    let surface = HarnessWebViewController(
        dataStore: .nonPersistent(),
        preferences: .shared,
        interactions: testInteractions(failure: { presentation, _ in visibleFailures.append(presentation.message) }),
        operations: nil,
        downloadOperations: operations
    )
    let delegate = WebBoundaryDelegateProbe()
    surface.delegate = delegate
    let operationID = UUID()
    _ = surface.beginDownloadTransfer(
        operationID: operationID,
        response: response,
        suggestedFilename: "report.pdf"
    )
    surface.finishDownloadTransfer(operationID: operationID)

    #expect(await eventually { delegate.failures.count == 1 })
    #expect(delegate.failures == [HarnessWebSurfaceFailure.downloadFinalizationFailed.message])
    #expect(visibleFailures == delegate.failures)
    #expect(probe.count("finalize") == 1)
    #expect(probe.count("discard-pending") == 1)
}

@Test @MainActor
func stagedDownloadReviewIsBoundedDuplicateSafeAndNeverDisplaysFilesystemMetadata() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let probe = DownloadBoundaryProbe()
    let artifact = testArtifact(
        filename: "\u{202E}../../Users/alice/private\nreport.pdf",
        sha256: "not-a-digest-/Users/alice",
        mimeType: "text/plain\u{202E}secret",
        warnings: [HostileWebBoundaryError().localizedDescription]
    )
    let operations = testDownloadOperations(probe: probe, artifact: artifact)
    var presentations: [HarnessDownloadReviewPresentation] = []
    var surface: HarnessWebViewController!
    let interactions = testInteractions(review: { presentation in
        presentations.append(presentation)
        surface.reviewStagedDownload(artifact, operations: operations)
        return .discard
    })
    surface = HarnessWebViewController(
        dataStore: .nonPersistent(),
        preferences: .shared,
        interactions: interactions,
        operations: nil,
        downloadOperations: operations
    )

    surface.reviewStagedDownload(artifact, operations: operations)
    let presentation = try #require(presentations.first)
    #expect(presentations.count == 1)
    #expect(!presentation.filename.contains("\u{202E}"))
    #expect(!presentation.filename.contains("/Users"))
    #expect(presentation.detectedContent == nil)
    #expect(presentation.sha256 == "Unavailable")
    #expect(presentation.warningCount == 1)
    #expect(!String(describing: presentation).contains("fulmar-secret-staging"))
    #expect(!String(describing: presentation).contains("super-secret"))
    #expect(probe.count("discard-artifact") == 1)
}

@Test @MainActor
func previewFailureAndSuccessUseInjectedOperationsWithoutRawErrors() async {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let failingProbe = DownloadBoundaryProbe()
    let artifact = testArtifact()
    let failingOperations = testDownloadOperations(
        probe: failingProbe,
        artifact: artifact,
        validate: { _ in
            failingProbe.increment("validate")
            throw HostileWebBoundaryError()
        }
    )
    var visibleFailures: [String] = []
    let failingSurface = HarnessWebViewController(
        dataStore: .nonPersistent(),
        preferences: .shared,
        interactions: testInteractions(
            review: { _ in .preview },
            failure: { presentation, _ in visibleFailures.append(presentation.message) }
        ),
        operations: nil,
        downloadOperations: failingOperations
    )
    let failingDelegate = WebBoundaryDelegateProbe()
    failingSurface.delegate = failingDelegate
    failingSurface.reviewStagedDownload(artifact, operations: failingOperations)
    #expect(await eventually { failingDelegate.failures.count == 1 })
    #expect(failingDelegate.failures == [HarnessWebSurfaceFailure.downloadPreviewBlocked.message])
    #expect(visibleFailures == failingDelegate.failures)
    #expect(failingProbe.count("discard-artifact") == 1)

    let successProbe = DownloadBoundaryProbe()
    let successOperations = testDownloadOperations(probe: successProbe, artifact: artifact)
    let successSurface = HarnessWebViewController(
        dataStore: .nonPersistent(),
        preferences: .shared,
        interactions: testInteractions(review: { _ in .preview }),
        operations: nil,
        downloadOperations: successOperations
    )
    let successDelegate = WebBoundaryDelegateProbe()
    successSurface.delegate = successDelegate
    successSurface.reviewStagedDownload(artifact, operations: successOperations)
    #expect(await eventually { successDelegate.downloads.count == 1 })
    #expect(successDelegate.downloads.first?.1 == .previewRequested)
    #expect(successDelegate.failures.isEmpty)
    #expect(successProbe.count("validate") == 1)
}

@Test @MainActor
func saveCancelFailureSuccessAndInvalidDestinationAreDeterministic() async throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let artifact = testArtifact()

    let cancelProbe = DownloadBoundaryProbe()
    let cancelOperations = testDownloadOperations(probe: cancelProbe, artifact: artifact)
    let cancelSurface = HarnessWebViewController(
        dataStore: .nonPersistent(),
        preferences: .shared,
        interactions: testInteractions(review: { _ in .save }, save: { _ in nil }),
        operations: nil,
        downloadOperations: cancelOperations
    )
    cancelSurface.reviewStagedDownload(artifact, operations: cancelOperations)
    #expect(cancelProbe.count("discard-artifact") == 1)
    #expect(cancelProbe.count("export") == 0)

    let invalidProbe = DownloadBoundaryProbe()
    var invalidFailures: [String] = []
    let invalidOperations = testDownloadOperations(probe: invalidProbe, artifact: artifact)
    let invalidSurface = HarnessWebViewController(
        dataStore: .nonPersistent(),
        preferences: .shared,
        interactions: testInteractions(
            review: { _ in .save },
            save: { _ in URL(string: "https://evil.example/output") },
            failure: { presentation, _ in invalidFailures.append(presentation.message) }
        ),
        operations: nil,
        downloadOperations: invalidOperations
    )
    invalidSurface.reviewStagedDownload(artifact, operations: invalidOperations)
    #expect(invalidFailures == [HarnessWebSurfaceFailure.downloadSaveFailed.message])
    #expect(invalidProbe.count("discard-artifact") == 1)

    let failureProbe = DownloadBoundaryProbe()
    var saveFailures: [String] = []
    let failureOperations = testDownloadOperations(
        probe: failureProbe,
        artifact: artifact,
        export: { _, _ in
            failureProbe.increment("export")
            throw HostileWebBoundaryError()
        }
    )
    let failureSurface = HarnessWebViewController(
        dataStore: .nonPersistent(),
        preferences: .shared,
        interactions: testInteractions(
            review: { _ in .save },
            save: { _ in URL(fileURLWithPath: "/private/tmp/explicit.pdf") },
            failure: { presentation, _ in saveFailures.append(presentation.message) }
        ),
        operations: nil,
        downloadOperations: failureOperations
    )
    let failureDelegate = WebBoundaryDelegateProbe()
    failureSurface.delegate = failureDelegate
    failureSurface.reviewStagedDownload(artifact, operations: failureOperations)
    #expect(await eventually { failureDelegate.failures.count == 1 })
    #expect(saveFailures == [HarnessWebSurfaceFailure.downloadSaveFailed.message])
    #expect(failureProbe.count("discard-artifact") == 1)

    let successProbe = DownloadBoundaryProbe()
    let successOperations = testDownloadOperations(probe: successProbe, artifact: artifact)
    let successSurface = HarnessWebViewController(
        dataStore: .nonPersistent(),
        preferences: .shared,
        interactions: testInteractions(
            review: { _ in .save },
            save: { _ in URL(fileURLWithPath: "/private/tmp/explicit.pdf") }
        ),
        operations: nil,
        downloadOperations: successOperations
    )
    let successDelegate = WebBoundaryDelegateProbe()
    successSurface.delegate = successDelegate
    successSurface.reviewStagedDownload(artifact, operations: successOperations)
    #expect(await eventually { successDelegate.downloads.count == 1 })
    #expect(successDelegate.downloads.first?.1 == .saved)
    #expect(successDelegate.downloads.first?.0.fileURL.path == "/private/tmp/explicit.pdf")
    #expect(successDelegate.failures.isEmpty)
}

@Test @MainActor
func boundaryChangeMakesInFlightPreviewCompletionStaleAndFailClosed() async {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let probe = DownloadBoundaryProbe()
    let artifact = testArtifact()
    let release = DispatchSemaphore(value: 0)
    let operations = testDownloadOperations(
        probe: probe,
        artifact: artifact,
        validate: { _ in
            probe.markValidationStarted()
            _ = release.wait(timeout: .now() + 3)
        }
    )
    let surface = HarnessWebViewController(
        dataStore: .nonPersistent(),
        preferences: .shared,
        interactions: testInteractions(review: { _ in .preview }),
        operations: nil,
        downloadOperations: operations
    )
    let delegate = WebBoundaryDelegateProbe()
    surface.delegate = delegate
    surface.configure(endpoint: HarnessEndpoint(
        baseURL: URL(string: "http://127.0.0.1:3080/")!,
        token: "one",
        nonce: "one",
        processIdentifier: 1
    ))
    surface.reviewStagedDownload(artifact, operations: operations)
    #expect(await eventually { probe.validationStarted })
    surface.configure(endpoint: HarnessEndpoint(
        baseURL: URL(string: "http://127.0.0.1:3081/")!,
        token: "two",
        nonce: "two",
        processIdentifier: 2
    ))
    release.signal()
    #expect(await eventually { probe.count("discard-artifact") >= 1 })
    #expect(delegate.downloads.isEmpty)
    #expect(delegate.failures.isEmpty)
}

@Test @MainActor
func hostileOverlayTextFitsMinimumLightAndDarkLayoutWithoutLeaking() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let surface = HarnessWebViewController(
        dataStore: .nonPersistent(),
        preferences: .shared,
        interactions: testInteractions(),
        operations: nil,
        downloadOperations: nil
    )
    surface.loadViewIfNeeded()
    surface.view.frame = NSRect(x: 0, y: 0, width: 640, height: 420)
    for appearance in [NSAppearance.Name.aqua, .darkAqua] {
        surface.view.appearance = NSAppearance(named: appearance)
        surface.showFailure(HostileWebBoundaryError().localizedDescription)
        surface.view.layoutSubtreeIfNeeded()
        #expect(!surface.view.hasAmbiguousLayout)
        let labels = descendants(of: surface.view).compactMap { $0 as? NSTextField }
        let message = try #require(labels.first { !$0.stringValue.isEmpty })
        #expect(surface.view.bounds.contains(message.convert(message.bounds, to: surface.view)))
        #expect(!message.stringValue.contains("secret"))
        #expect(!message.stringValue.contains("evil.example"))
        #expect(!message.stringValue.contains("/Users"))
        #expect(message.accessibilityRole() == .staticText)
    }
}

private func descendants(of view: NSView) -> [NSView] {
    view.subviews.flatMap { [$0] + descendants(of: $0) }
}
