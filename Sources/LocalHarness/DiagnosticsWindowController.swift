import AppKit
import Darwin

struct DiagnosticsOperations: @unchecked Sendable {
    var prepareDirectory: @Sendable (URL) throws -> URL

    static let live = Self(prepareDirectory: { directory in
        let standardized = directory.standardizedFileURL
        var metadata = stat()
        if Darwin.lstat(standardized.path, &metadata) != 0 {
            guard errno == ENOENT else { throw CocoaError(.fileReadUnknown) }
            try FileManager.default.createDirectory(
                at: standardized,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            guard Darwin.lstat(standardized.path, &metadata) == 0 else {
                throw CocoaError(.fileReadUnknown)
            }
        }
        guard metadata.st_mode & S_IFMT == S_IFDIR,
              metadata.st_uid == geteuid(),
              metadata.st_mode & (S_IRWXG | S_IRWXO | S_ISUID | S_ISGID) == 0,
              standardized.resolvingSymlinksInPath().standardizedFileURL.path == standardized.path
        else {
            throw CocoaError(.fileReadNoPermission)
        }
        return standardized
    })
}

@MainActor
struct DiagnosticsInteractions {
    var copyText: (String) -> Bool
    var openDirectory: (URL) -> Bool
    var presentNotice: (_ title: String, _ message: String) -> Void

    static var live: Self {
        Self(
            copyText: { value in
                NSPasteboard.general.clearContents()
                return NSPasteboard.general.setString(value, forType: .string)
            },
            openDirectory: { NSWorkspace.shared.open($0) },
            presentNotice: { title, message in
                let alert = NSAlert()
                alert.alertStyle = .informational
                alert.messageText = title
                alert.informativeText = message
                alert.addButton(withTitle: "OK")
                alert.runModal()
            }
        )
    }
}

final class DiagnosticsWindowController: NSWindowController, NSWindowDelegate {
    static let maximumSettingsBytes = 256 * 1_024
    static let maximumReportCharacters = 48_000
    var onRestart: (() -> Void)?
    private let controller: HarnessController
    private let textView = NSTextView()
    private let modelSettingsStore = ModelProviderSettingsStore()
    private let providerConsentStore = ProviderConsentStore()
    private let operations: DiagnosticsOperations
    private let interactions: DiagnosticsInteractions
    private let globalHotKeyStatus: () -> String
    private let copyButton = NSButton(title: "Copy Support Report", target: nil, action: nil)
    private let openButton = NSButton(title: "Open Diagnostics Folder", target: nil, action: nil)
    private let restartButton = NSButton(title: "Restart Services", target: nil, action: nil)
    private var openTask: Task<Void, Never>?
    private var presentationGeneration: UInt64 = 0
    private var copyPending = false
    private var restartPending = false

    init(
        controller: HarnessController,
        operations: DiagnosticsOperations = .live,
        interactions: DiagnosticsInteractions? = nil,
        globalHotKeyStatus: @escaping () -> String = { "Not reported" }
    ) {
        self.controller = controller
        self.operations = operations
        self.interactions = interactions ?? .live
        self.globalHotKeyStatus = globalHotKeyStatus
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 780, height: 580),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "\(ProductBrand.displayName) Diagnostics"
        window.minSize = NSSize(width: 620, height: 420)
        window.isReleasedWhenClosed = false
        window.setFrameAutosaveName("LocalHarness.Diagnostics")
        super.init(window: window)
        window.delegate = self
        buildContent()
        if !window.setFrameUsingName("LocalHarness.Diagnostics") { window.center() }
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func showWindow(_ sender: Any?) {
        presentationGeneration &+= 1
        setOpenPending(false)
        setCopyPending(false)
        setRestartPending(false)
        refresh()
        super.showWindow(sender)
    }

    func windowWillClose(_ notification: Notification) {
        presentationGeneration &+= 1
        openTask?.cancel()
        openTask = nil
        setOpenPending(false)
        setCopyPending(false)
        setRestartPending(false)
    }

    func refresh() {
        let runtime = controller.runtimeInfo()
        let appVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "Development"
        let appBuild = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "Development"
        let system = ProcessInfo.processInfo.operatingSystemVersionString
        let model = readConfiguredModel()
        let runtimeKind = runtime?.bundled == true ? "Bundled and pinned" : "External fallback"
        let reviewedVersion = Bundle.main.resourceURL.flatMap { try? ProductBrand.reviewedDSHVersion(resources: $0) }
        let runtimeContract: String
        if let runtime, let reviewedVersion {
            runtimeContract = runtime.bundled && runtime.dshVersion == reviewedVersion
                ? "Matches reviewed DSH \(reviewedVersion)"
                : "Mismatch — execution should remain blocked"
        } else {
            runtimeContract = "Unavailable"
        }
        let integrity = runtime?.bundled == true && BundleIntegrityVerifier.verify()
            ? "Verified"
            : "Not verified"
        let route = selectedRouteSummary()
        let report = """
        \(ProductBrand.displayName.uppercased()) SUPPORT REPORT

        App version: \(appVersion) (\(appBuild))
        macOS: \(system)
        App bundle integrity: \(integrity)
        Menu-bar API: \(StatusItemIcon.activePlacementPath.rawValue)
        Menu-bar placement: \(StatusItemIcon.lastPlacementVerification.diagnosticSummary)
        Global Chat shortcut: \(globalHotKeyStatus())
        Service state: \(controller.currentState.summary)
        Private service endpoint: \(controller.harnessURL == nil ? "Not running" : "Authenticated loopback active")
        Agent service: \(controller.ownsHarness ? "Managed securely by this app" : "Stopped")
        Local model service: \(controller.ownsOllama ? "Managed by this app" : "External or stopped")
        Selected route: \(route)
        Configured model: \(model)

        DeepSeek Harness version: \(runtime?.dshVersion ?? "Unavailable")
        Runtime compatibility: \(runtimeContract)
        Runtime source: \(runtimeKind)
        Node: \(runtime == nil ? "Unavailable" : "Bundled pinned runtime")
        Harness entry point: \(runtime == nil ? "Unavailable" : "Bundled pinned entry point")
        Private Harness data: Private app storage
        Workspace: Private app workspace storage
        Diagnostics: Private app diagnostics storage

        RECENT SERVICE LOG (KNOWN CREDENTIAL PATTERNS REDACTED)
        Known credential patterns and private paths are redacted again before display or copy. Review this section before sharing.
        \(controller.recentLogs())
        """
        textView.string = Self.shareableSupportReport(
            report,
            homeDirectory: FileManager.default.homeDirectoryForCurrentUser,
            runtimeExecutablePaths: [runtime?.node, runtime?.script].compactMap { $0 }
        )
        textView.setAccessibilityValue("Sanitized support report ready")
    }

    private func buildContent() {
        guard let window else { return }
        let root = NSView()
        root.translatesAutoresizingMaskIntoConstraints = false
        window.contentView = root

        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        scroll.translatesAutoresizingMaskIntoConstraints = false
        textView.isEditable = false
        textView.isSelectable = true
        textView.font = .monospacedSystemFont(ofSize: 11.5, weight: .regular)
        textView.textContainerInset = NSSize(width: 12, height: 12)
        textView.setAccessibilityLabel("Fulmar support report")
        scroll.documentView = textView
        root.addSubview(scroll)

        let refreshButton = NSButton(title: "Refresh", target: self, action: #selector(refreshAction(_:)))
        copyButton.target = self
        copyButton.action = #selector(copyReport(_:))
        openButton.target = self
        openButton.action = #selector(openFolder(_:))
        restartButton.target = self
        restartButton.action = #selector(restart(_:))
        copyButton.setAccessibilityLabel("Copy sanitized support report")
        openButton.setAccessibilityLabel("Open private diagnostics folder")
        restartButton.setAccessibilityLabel("Restart local services")
        let buttons = NSStackView(views: [refreshButton, copyButton, openButton, restartButton])
        buttons.orientation = .horizontal
        buttons.spacing = 8
        buttons.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(buttons)

        NSLayoutConstraint.activate([
            scroll.topAnchor.constraint(equalTo: root.topAnchor, constant: 16),
            scroll.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 16),
            scroll.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -16),
            buttons.topAnchor.constraint(equalTo: scroll.bottomAnchor, constant: 12),
            buttons.leadingAnchor.constraint(equalTo: scroll.leadingAnchor),
            buttons.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -16)
        ])
        textView.string = "Diagnostics load when this window is shown."
    }

    private func readConfiguredModel() -> String {
        let settings = controller.harnessHomeDirectory().appendingPathComponent("settings.yaml")
        return Self.configuredModel(at: settings)
    }

    private func selectedRouteSummary() -> String {
        do {
            let selection = try modelSettingsStore.load()?.defaultSelection ?? .defaultLocal
            let boundary: String
            if selection.route.provider == BuiltInProviderDescriptors.ollama.id {
                boundary = DataBoundary.onDevice.displayName
            } else if let grant = try providerConsentStore.load().activeGrant(for: selection.route.provider) {
                boundary = grant.boundary.displayName
            } else {
                boundary = "Blocked — endpoint consent is missing"
            }
            return "\(selection.route.provider.rawValue) / \(selection.route.model.rawValue) · \(boundary)"
        } catch {
            return "Unavailable — provider settings need recovery"
        }
    }

    static func configuredModel(at settings: URL) -> String {
        guard let data = try? SecureAttachmentReader.readRegularFile(
            at: settings,
            maximumBytes: maximumSettingsBytes
        ), let text = String(data: data, encoding: .utf8) else { return "Unknown" }
        for line in text.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("model:") {
                let value = trimmed.dropFirst("model:".count)
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                guard !value.isEmpty,
                      value.utf8.count <= 512,
                      !value.unicodeScalars.contains(where: {
                          CharacterSet.controlCharacters.contains($0) || $0.properties.generalCategory == .format
                      }) else {
                    return "Unknown"
                }
                return value
            }
        }
        return "Unknown"
    }

    /// The persisted service log already removes known credential patterns,
    /// but it can still contain process diagnostics supplied by third-party
    /// runtimes or historical entries written by an older build. Apply the same
    /// bounded secret redactor again at the sharing boundary, then remove private
    /// absolute paths. No heuristic can recognize every possible secret, so the
    /// report continues to tell the user to review it before sharing.
    static func shareableSupportReport(
        _ report: String,
        homeDirectory: URL,
        runtimeExecutablePaths: [URL]
    ) -> String {
        var value = AuxiliaryDisplayPolicy.multiline(
            report,
            maximumCharacters: maximumReportCharacters,
            fallback: "Support report is unavailable."
        )
        let runtimePaths = Set(runtimeExecutablePaths.map(\.standardizedFileURL.path))
            .filter { $0.hasPrefix("/") && $0.utf8.count <= 16_384 }
            .sorted { $0.utf8.count > $1.utf8.count }
        for path in runtimePaths {
            value = value.replacingOccurrences(of: path, with: "<runtime path removed>")
        }
        let home = homeDirectory.standardizedFileURL.path
        if home.hasPrefix("/"), home.utf8.count <= 16_384 {
            value = value.replacingOccurrences(of: home, with: "<private home>")
        }
        return AuxiliaryDisplayPolicy.multiline(
            ServiceLogStore.redactedDiagnosticText(value),
            maximumCharacters: maximumReportCharacters,
            fallback: "Support report is unavailable."
        )
    }

    @objc private func refreshAction(_ sender: Any?) { refresh() }
    @objc private func copyReport(_ sender: Any?) {
        guard !copyPending else { return }
        setCopyPending(true)
        defer { setCopyPending(false) }
        let runtime = controller.runtimeInfo()
        let report = Self.shareableSupportReport(
            textView.string,
            homeDirectory: FileManager.default.homeDirectoryForCurrentUser,
            runtimeExecutablePaths: [runtime?.node, runtime?.script].compactMap { $0 }
        )
        guard interactions.copyText(report) else {
            interactions.presentNotice(
                "Support report was not copied",
                "The clipboard did not accept the sanitized report. Nothing was changed; try again."
            )
            return
        }
    }
    @objc private func openFolder(_ sender: Any?) {
        guard openTask == nil else { return }
        let directory = controller.diagnosticsDirectory()
        let prepare = operations.prepareDirectory
        presentationGeneration &+= 1
        let generation = presentationGeneration
        setOpenPending(true)
        openTask = Task { @MainActor [weak self] in
            let result = await Task.detached(priority: .utility) {
                Result { try prepare(directory) }
            }.value
            guard let self,
                  !Task.isCancelled,
                  self.presentationGeneration == generation else { return }
            self.openTask = nil
            self.setOpenPending(false)
            switch result {
            case .success(let verifiedDirectory):
                guard self.interactions.openDirectory(verifiedDirectory) else {
                    self.interactions.presentNotice(
                        "Diagnostics folder did not open",
                        "The private diagnostics folder is safe, but Finder did not open it. Try again."
                    )
                    return
                }
            case .failure:
                self.interactions.presentNotice(
                    "Diagnostics folder is unavailable",
                    "The private diagnostics folder could not be verified safely, so it was not opened."
                )
            }
        }
    }
    @objc private func restart(_ sender: Any?) {
        guard !restartPending else { return }
        guard let onRestart else {
            interactions.presentNotice(
                "Restart is unavailable",
                "Local service controls are not ready yet. Close this window, reopen it, and try again."
            )
            return
        }
        setRestartPending(true)
        onRestart()
        setRestartPending(false)
    }

    private func setCopyPending(_ pending: Bool) {
        copyPending = pending
        copyButton.title = pending ? "Copying…" : "Copy Support Report"
        copyButton.isEnabled = !pending
        copyButton.setAccessibilityValue(pending ? "Copying" : "Ready")
    }

    private func setOpenPending(_ pending: Bool) {
        openButton.title = pending ? "Opening…" : "Open Diagnostics Folder"
        openButton.isEnabled = !pending
        openButton.setAccessibilityValue(pending ? "Opening" : "Ready")
    }

    private func setRestartPending(_ pending: Bool) {
        restartPending = pending
        restartButton.title = pending ? "Restarting…" : "Restart Services"
        restartButton.isEnabled = !pending
        restartButton.setAccessibilityValue(pending ? "Restarting" : "Ready")
    }
}
