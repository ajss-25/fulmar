import AppKit
import Testing
@testable import LocalHarness

@MainActor
@Test func statusItemArtworkIsVisibleAndAccessible() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let image = StatusItemIcon.make()

    #expect(image.size == NSSize(width: 18, height: 18))
    #expect(image.isTemplate)
    #expect(image.accessibilityDescription == "Fulmar")

    guard let bitmap = NSBitmapImageRep(
        bitmapDataPlanes: nil,
        pixelsWide: 18,
        pixelsHigh: 18,
        bitsPerSample: 8,
        samplesPerPixel: 4,
        hasAlpha: true,
        isPlanar: false,
        colorSpaceName: .deviceRGB,
        bytesPerRow: 0,
        bitsPerPixel: 0
    ) else {
        Issue.record("Could not allocate a bitmap for the status-item icon")
        return
    }

    NSGraphicsContext.saveGraphicsState()
    defer { NSGraphicsContext.restoreGraphicsState() }
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)
    image.draw(in: NSRect(origin: .zero, size: image.size))

    let visiblePixelCount = (0..<18).reduce(into: 0) { count, x in
        for y in 0..<18 where (bitmap.colorAt(x: x, y: y)?.alphaComponent ?? 0) > 0.05 {
            count += 1
        }
    }

    #expect(visiblePixelCount > 30)
    #expect(visiblePixelCount < 250)
}

@MainActor
@Test func statusItemPresentationHasStableCompactIdentity() {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    #expect(StatusItemIcon.statusItemLength == 18)
    #expect(StatusItemIcon.initialCreationDelay == 1.0)
    #expect(StatusItemIcon.autosaveName == "Fulmar.MenuBar.v2")
    #expect(StatusItemIcon.visibilityInitializationKey == "Fulmar.MenuBar.v2.VisibilityInitialized")
    #expect(StatusItemIcon.placementRecoveryDelay == 2.0)
    #expect(StatusItemIcon.maximumPlacementRecoveryAttempts == 2)

    let button = NSStatusBarButton(frame: NSRect(x: 0, y: 0, width: 18, height: 24))
    StatusItemIcon.configure(button: button)
    #expect(button.image?.isTemplate == true)
    #expect(button.imagePosition == .imageOnly)
    #expect(button.imageScaling == .scaleProportionallyDown)
    #expect(button.toolTip == "Open Fulmar")
    #expect(button.accessibilityLabel() == "Fulmar menu")
}

@MainActor
@Test func statusItemVisibilityIsInitializedExactlyOncePerPersistentIdentity() {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let suiteName = "FulmarStatusVisibilityTests.\(UUID().uuidString)"
    let defaults = UserDefaults(suiteName: suiteName)!
    defer { defaults.removePersistentDomain(forName: suiteName) }
    var showCount = 0

    StatusItemIcon.initializeVisibilityIfNeeded(defaults: defaults) {
        showCount += 1
    }
    #expect(showCount == 1)
    #expect(defaults.object(forKey: StatusItemIcon.visibilityInitializationKey) as? Bool == true)

    StatusItemIcon.initializeVisibilityIfNeeded(defaults: defaults) {
        showCount += 1
    }
    #expect(showCount == 1)
}

@MainActor
@Test func statusItemAppKitGeometryDistinguishesTopPlacementFromParking() {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let primary = CGRect(x: 0, y: 0, width: 1512, height: 982)
    let above = CGRect(x: 200, y: 982, width: 1920, height: 1080)

    #expect(StatusItemIcon.isTopVisible(
        CGRect(x: 1485, y: 959, width: 20, height: 24),
        screenFrames: [primary, above],
        menuBarHeight: 40
    ))
    #expect(StatusItemIcon.isTopVisible(
        CGRect(x: 2080, y: 2038, width: 20, height: 24),
        screenFrames: [primary, above],
        menuBarHeight: 40
    ))
    #expect(!StatusItemIcon.isTopVisible(
        CGRect(x: 7, y: -7, width: 20, height: 24),
        screenFrames: [primary],
        menuBarHeight: 40
    ))
    #expect(!StatusItemIcon.isTopVisible(
        CGRect(x: 7, y: 958, width: 20, height: 24),
        screenFrames: [primary],
        menuBarHeight: 40
    ))
    #expect(!StatusItemIcon.isTopVisible(
        CGRect(x: 1498, y: 959, width: 20, height: 24),
        screenFrames: [primary],
        menuBarHeight: 40
    ))
}

@Test func statusItemGeometryUsesEachQuartzDisplayTopEdge() {
    let primary = MenuBarDisplayGeometry(
        displayID: 1,
        bounds: CGRect(x: 0, y: 0, width: 5120, height: 1440),
        menuBarHeight: 40
    )
    let left = MenuBarDisplayGeometry(
        displayID: 2,
        bounds: CGRect(x: -1920, y: 120, width: 1920, height: 1080),
        menuBarHeight: 32
    )
    let above = MenuBarDisplayGeometry(
        displayID: 3,
        bounds: CGRect(x: 700, y: -1200, width: 1920, height: 1200),
        menuBarHeight: 32
    )
    let below = MenuBarDisplayGeometry(
        displayID: 4,
        bounds: CGRect(x: 400, y: 1440, width: 2560, height: 1440),
        menuBarHeight: 32
    )
    let displays = [primary, left, above, below]

    #expect(StatusItemVisibilityGeometry.topDisplay(
        containing: CGRect(x: 5093, y: -1, width: 20, height: 24),
        displays: displays
    )?.displayID == 1)
    #expect(StatusItemVisibilityGeometry.topDisplay(
        containing: CGRect(x: -30, y: 119, width: 20, height: 24),
        displays: displays
    )?.displayID == 2)
    #expect(StatusItemVisibilityGeometry.topDisplay(
        containing: CGRect(x: 2500, y: -1201, width: 20, height: 24),
        displays: displays
    )?.displayID == 3)
    #expect(StatusItemVisibilityGeometry.topDisplay(
        containing: CGRect(x: 2900, y: 1439, width: 20, height: 24),
        displays: displays
    )?.displayID == 4)
}

@Test func statusItemGeometryRejectsParkedPartialAndInvalidFrames() {
    let display = MenuBarDisplayGeometry(
        displayID: 7,
        bounds: CGRect(x: 0, y: 0, width: 5120, height: 1440),
        menuBarHeight: 40
    )

    #expect(!StatusItemVisibilityGeometry.isTopVisible(
        CGRect(x: 7, y: 1435, width: 20, height: 24),
        displays: [display]
    ))
    let directlyBelow = MenuBarDisplayGeometry(
        displayID: 8,
        bounds: CGRect(x: 0, y: 1440, width: 2560, height: 1440),
        menuBarHeight: 40
    )
    #expect(!StatusItemVisibilityGeometry.isTopVisible(
        CGRect(x: 8, y: 1444, width: 20, height: 24),
        displays: [display, directlyBelow]
    ))
    #expect(!StatusItemVisibilityGeometry.isTopVisible(
        CGRect(x: -2, y: 0, width: 20, height: 24),
        displays: [display]
    ))
    #expect(!StatusItemVisibilityGeometry.isTopVisible(
        CGRect(x: 5110, y: 0, width: 20, height: 24),
        displays: [display]
    ))
    #expect(!StatusItemVisibilityGeometry.isTopVisible(
        CGRect(x: 10, y: 0, width: 0, height: 24),
        displays: [display]
    ))
    #expect(!StatusItemVisibilityGeometry.isTopVisible(
        CGRect(x: CGFloat.nan, y: 0, width: 20, height: 24),
        displays: [display]
    ))
}

@Test func statusItemGeometryAcceptsMirroredDisplaysAndOnePixelTolerance() {
    let first = MenuBarDisplayGeometry(
        displayID: 10,
        bounds: CGRect(x: 0, y: 0, width: 1920, height: 1080),
        menuBarHeight: 32
    )
    let mirror = MenuBarDisplayGeometry(
        displayID: 11,
        bounds: first.bounds,
        menuBarHeight: 32
    )

    #expect(StatusItemVisibilityGeometry.topDisplay(
        containing: CGRect(x: 1901, y: -1, width: 20, height: 24),
        displays: [first, mirror]
    )?.displayID == 10)
    #expect(!StatusItemVisibilityGeometry.isTopVisible(
        CGRect(x: 1901, y: -1, width: 20, height: 24),
        displays: [first, mirror],
        tolerance: 0
    ))
}

@MainActor
@Test func statusItemPlacementDecisionRespectsIdentityUserChoiceAndBoundedRecovery() {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let screen = CGRect(x: 0, y: 0, width: 1512, height: 982)
    let visible = CGRect(x: 1400, y: 958, width: 18, height: 24)
    let parked = CGRect(x: 7, y: 958, width: 18, height: 24)

    #expect(StatusItemIcon.placementDecision(
        isCurrentItem: false,
        isVisible: true,
        frame: parked,
        screenFrames: [screen],
        menuBarHeight: 40,
        attempt: 0
    ) == .ignoreStaleCallback)
    #expect(StatusItemIcon.placementDecision(
        isCurrentItem: true,
        isVisible: false,
        frame: parked,
        screenFrames: [screen],
        menuBarHeight: 40,
        attempt: 0
    ) == .respectPersistedHidden)
    #expect(StatusItemIcon.placementDecision(
        isCurrentItem: true,
        isVisible: true,
        frame: visible,
        screenFrames: [screen],
        menuBarHeight: 40,
        attempt: 0
    ) == .acceptVisiblePlacement)

    #expect(StatusItemIcon.placementDecision(
        isCurrentItem: true,
        isVisible: true,
        frame: parked,
        screenFrames: [screen],
        menuBarHeight: 40,
        attempt: 0
    ) == .recreate(nextAttempt: 1))
    #expect(StatusItemIcon.placementDecision(
        isCurrentItem: true,
        isVisible: true,
        frame: nil,
        screenFrames: [screen],
        menuBarHeight: 40,
        attempt: 1
    ) == .recreate(nextAttempt: 2))
    #expect(StatusItemIcon.placementDecision(
        isCurrentItem: true,
        isVisible: true,
        frame: parked,
        screenFrames: [screen],
        menuBarHeight: 40,
        attempt: 2
    ) == .giveUpAfterBoundedAttempts)
    #expect(StatusItemIcon.placementDecision(
        isCurrentItem: true,
        isVisible: true,
        frame: parked,
        screenFrames: [screen],
        menuBarHeight: 40,
        attempt: -1
    ) == .giveUpAfterBoundedAttempts)
}

@MainActor
@Test func statusItemPlacementDiagnosticsRecordObservedOutcomeNotOnlyCreationAPI() {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    StatusItemIcon.beginPlacementVerification(recoveryAttempt: 0)
    #expect(StatusItemIcon.lastPlacementVerification == .pending(recoveryAttempt: 0))

    StatusItemIcon.recordPlacementDecision(.recreate(nextAttempt: 1), recoveryAttempt: 0)
    #expect(StatusItemIcon.lastPlacementVerification == .pending(recoveryAttempt: 1))

    StatusItemIcon.recordPlacementDecision(.ignoreStaleCallback, recoveryAttempt: 0)
    #expect(StatusItemIcon.lastPlacementVerification == .pending(recoveryAttempt: 1))

    StatusItemIcon.recordPlacementDecision(.respectPersistedHidden, recoveryAttempt: 0)
    #expect(StatusItemIcon.lastPlacementVerification == .hiddenByUser(recoveryAttempt: 0))
    #expect(StatusItemIcon.lastPlacementVerification.diagnosticSummary.contains("saved macOS user choice"))

    StatusItemIcon.recordPlacementDecision(.acceptVisiblePlacement, recoveryAttempt: 1)
    #expect(StatusItemIcon.lastPlacementVerification == .visible(recoveryAttempt: 1))
    #expect(StatusItemIcon.lastPlacementVerification.diagnosticSummary.contains("Visible in a display menu bar"))

    StatusItemIcon.recordPlacementDecision(.giveUpAfterBoundedAttempts, recoveryAttempt: 2)
    #expect(StatusItemIcon.lastPlacementVerification == .failed(recoveryAttempt: 2))
    #expect(StatusItemIcon.lastPlacementVerification.diagnosticSummary.contains("bounded recovery"))
}

@MainActor
@Test func launchPolicyIsEstablishedBeforeTheAppKitEventLoop() {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    #expect(ApplicationLaunchPolicy.activationPolicy(arguments: ["Fulmar"]) == .regular)
    #expect(ApplicationLaunchPolicy.activationPolicy(
        arguments: ["Fulmar", "--background-schedule"]
    ) == .accessory)
    #expect(ApplicationLaunchPolicy.activationPolicy(
        arguments: ["Fulmar", "--status-item-acceptance"]
    ) == .regular)
    #expect(ApplicationLaunchPolicy.activationPolicy(
        arguments: ["Fulmar", "--headless-handoff-acceptance"]
    ) == .accessory)
    #expect(ApplicationLaunchPolicy.activationPolicy(
        arguments: ["Fulmar", PhysicalHandoffAcceptanceEnvironment.foregroundArgument]
    ) == .regular)
}

private func makePhysicalHandoffAcceptanceRoot() throws -> URL {
    let root = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
        .appendingPathComponent(
            PhysicalHandoffAcceptanceEnvironment.rootLeafPrefix + UUID().uuidString,
            isDirectory: true
        )
    let home = root.appendingPathComponent("home", isDirectory: true)
    let temporary = root.appendingPathComponent("temp", isDirectory: true)
    let library = home.appendingPathComponent("Library", isDirectory: true)
    let supportParent = library.appendingPathComponent("Application Support", isDirectory: true)
    let applicationSupport = supportParent.appendingPathComponent("Local Harness", isDirectory: true)
    let modelStore = home
        .appendingPathComponent(".ollama", isDirectory: true)
        .appendingPathComponent("models", isDirectory: true)
    try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: modelStore, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: applicationSupport, withIntermediateDirectories: true)
    for directory in [
        root, home, temporary, library, supportParent, applicationSupport,
        modelStore.deletingLastPathComponent(), modelStore
    ] {
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
    }
    return root
}

private func physicalHandoffRuntimeDirectories(
    root: URL
) -> PhysicalHandoffAcceptanceEnvironment.RuntimeDirectories {
    let home = root.appendingPathComponent("home", isDirectory: true)
    return .init(
        fileManagerHome: home,
        foundationHome: home,
        applicationSupport: home.appendingPathComponent("Library/Application Support", isDirectory: true),
        temporaryDirectory: root.appendingPathComponent("temp", isDirectory: true)
    )
}

private func physicalHandoffEnvironment(root: URL) -> [String: String] {
    [
        PhysicalHandoffAcceptanceEnvironment.rootEnvironmentKey: root.path,
        PhysicalHandoffAcceptanceEnvironment.modelStoreEnvironmentKey: root
            .appendingPathComponent("home/.ollama/models", isDirectory: true).path,
        "HOME": root.appendingPathComponent("home", isDirectory: true).path,
        "CFFIXED_USER_HOME": root.appendingPathComponent("home", isDirectory: true).path,
        "TMPDIR": root.appendingPathComponent("temp", isDirectory: true).path,
        "DEEPSEEK_API_KEY": "must-not-propagate",
        "SSH_AUTH_SOCK": "/private/tmp/must-not-propagate"
    ]
}

@Test func physicalHandoffAcceptanceRequiresExactPrivateDisposableBoundary() throws {
    let root = try makePhysicalHandoffAcceptanceRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let environment = physicalHandoffEnvironment(root: root)

    let resolvedBackground = try PhysicalHandoffAcceptanceEnvironment.resolveIfRequested(
        arguments: [
            "Fulmar", "--background-schedule",
            PhysicalHandoffAcceptanceEnvironment.backgroundArgument
        ],
        environment: environment,
        runtimeDirectories: physicalHandoffRuntimeDirectories(root: root)
    )
    let background = try #require(resolvedBackground)
    #expect(background.mode == .background)
    #expect(background.root == root)
    #expect(background.modelStore == root.appendingPathComponent("home/.ollama/models", isDirectory: true))
    #expect(background.foregroundArguments == [
        PhysicalHandoffAcceptanceEnvironment.foregroundArgument
    ])
    #expect(background.foregroundEnvironment == [
        PhysicalHandoffAcceptanceEnvironment.rootEnvironmentKey: root.path,
        PhysicalHandoffAcceptanceEnvironment.modelStoreEnvironmentKey: root
            .appendingPathComponent("home/.ollama/models", isDirectory: true).path,
        "HOME": root.appendingPathComponent("home", isDirectory: true).path,
        "CFFIXED_USER_HOME": root.appendingPathComponent("home", isDirectory: true).path,
        "TMPDIR": root.appendingPathComponent("temp", isDirectory: true).path
    ])
    #expect(background.foregroundEnvironment["DEEPSEEK_API_KEY"] == nil)
    #expect(background.foregroundEnvironment["SSH_AUTH_SOCK"] == nil)

    let resolvedForeground = try PhysicalHandoffAcceptanceEnvironment.resolveIfRequested(
        arguments: ["Fulmar", PhysicalHandoffAcceptanceEnvironment.foregroundArgument],
        environment: background.foregroundEnvironment,
        runtimeDirectories: physicalHandoffRuntimeDirectories(root: root)
    )
    let foreground = try #require(resolvedForeground)
    #expect(foreground.mode == .foreground)
    #expect(foreground.root == root)
    #expect(foreground.applicationSupport == root.appendingPathComponent(
        "home/Library/Application Support/Local Harness",
        isDirectory: true
    ))
}

@Test func ordinaryLaunchNeverValidatesOrPropagatesAcceptanceEnvironment() throws {
    let result = try PhysicalHandoffAcceptanceEnvironment.resolveIfRequested(
        arguments: ["Fulmar"],
        environment: [
            PhysicalHandoffAcceptanceEnvironment.rootEnvironmentKey: "/unsafe",
            "DEEPSEEK_API_KEY": "ordinary-launch-value"
        ]
    )
    #expect(result == nil)
}

@Test func physicalHandoffAcceptanceRejectsArgumentConfusionAndEnvironmentDrift() throws {
    let root = try makePhysicalHandoffAcceptanceRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let environment = physicalHandoffEnvironment(root: root)

    #expect(throws: PhysicalHandoffAcceptanceEnvironment.ValidationError.invalidArguments) {
        _ = try PhysicalHandoffAcceptanceEnvironment.resolveIfRequested(
            arguments: ["Fulmar", PhysicalHandoffAcceptanceEnvironment.backgroundArgument],
            environment: environment
        )
    }
    #expect(throws: PhysicalHandoffAcceptanceEnvironment.ValidationError.invalidArguments) {
        _ = try PhysicalHandoffAcceptanceEnvironment.resolveIfRequested(
            arguments: [
                "Fulmar", "--background-schedule",
                PhysicalHandoffAcceptanceEnvironment.backgroundArgument,
                PhysicalHandoffAcceptanceEnvironment.foregroundArgument
            ],
            environment: environment
        )
    }
    #expect(throws: PhysicalHandoffAcceptanceEnvironment.ValidationError.invalidArguments) {
        _ = try PhysicalHandoffAcceptanceEnvironment.resolveIfRequested(
            arguments: [
                "Fulmar", "--background-schedule",
                PhysicalHandoffAcceptanceEnvironment.backgroundArgument,
                "--qualify-app-owned-ollama-generation"
            ],
            environment: environment
        )
    }
    #expect(throws: PhysicalHandoffAcceptanceEnvironment.ValidationError.invalidArguments) {
        _ = try PhysicalHandoffAcceptanceEnvironment.resolveIfRequested(
            arguments: [
                "Fulmar",
                PhysicalHandoffAcceptanceEnvironment.foregroundArgument,
                PhysicalHandoffAcceptanceEnvironment.foregroundArgument
            ],
            environment: environment
        )
    }
    var drifted = environment
    drifted["HOME"] = "/private/tmp/wrong-home"
    #expect(throws: PhysicalHandoffAcceptanceEnvironment.ValidationError.invalidEnvironment) {
        _ = try PhysicalHandoffAcceptanceEnvironment.resolveIfRequested(
            arguments: [
                "Fulmar", "--background-schedule",
                PhysicalHandoffAcceptanceEnvironment.backgroundArgument
            ],
            environment: drifted
        )
    }
    drifted = environment
    drifted[PhysicalHandoffAcceptanceEnvironment.modelStoreEnvironmentKey] = "/private/tmp/wrong-model-store"
    #expect(throws: PhysicalHandoffAcceptanceEnvironment.ValidationError.unsafeRoot) {
        _ = try PhysicalHandoffAcceptanceEnvironment.resolveIfRequested(
            arguments: [
                "Fulmar", "--background-schedule",
                PhysicalHandoffAcceptanceEnvironment.backgroundArgument
            ],
            environment: drifted
        )
    }
}

@Test func physicalHandoffAcceptanceRejectsActualAndIndividuallyDriftedRuntimeDirectories() throws {
    let root = try makePhysicalHandoffAcceptanceRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let arguments = [
        "Fulmar", "--background-schedule",
        PhysicalHandoffAcceptanceEnvironment.backgroundArgument
    ]
    let environment = physicalHandoffEnvironment(root: root)

    // The test process is not running inside this freshly-created HOME. This
    // exercises the real Foundation/FileManager/NSTemporaryDirectory values,
    // not merely a caller-supplied mismatch fixture.
    #expect(throws: PhysicalHandoffAcceptanceEnvironment.ValidationError.invalidEnvironment) {
        _ = try PhysicalHandoffAcceptanceEnvironment.resolveIfRequested(
            arguments: arguments,
            environment: environment
        )
    }

    let expected = physicalHandoffRuntimeDirectories(root: root)
    let wrong = root
    let individuallyDrifted: [PhysicalHandoffAcceptanceEnvironment.RuntimeDirectories] = [
        .init(
            fileManagerHome: wrong,
            foundationHome: expected.foundationHome,
            applicationSupport: expected.applicationSupport,
            temporaryDirectory: expected.temporaryDirectory
        ),
        .init(
            fileManagerHome: expected.fileManagerHome,
            foundationHome: wrong,
            applicationSupport: expected.applicationSupport,
            temporaryDirectory: expected.temporaryDirectory
        ),
        .init(
            fileManagerHome: expected.fileManagerHome,
            foundationHome: expected.foundationHome,
            applicationSupport: wrong,
            temporaryDirectory: expected.temporaryDirectory
        ),
        .init(
            fileManagerHome: expected.fileManagerHome,
            foundationHome: expected.foundationHome,
            applicationSupport: expected.applicationSupport,
            temporaryDirectory: wrong
        )
    ]
    for runtimeDirectories in individuallyDrifted {
        #expect(throws: PhysicalHandoffAcceptanceEnvironment.ValidationError.invalidEnvironment) {
            _ = try PhysicalHandoffAcceptanceEnvironment.resolveIfRequested(
                arguments: arguments,
                environment: environment,
                runtimeDirectories: runtimeDirectories
            )
        }
    }
}

@Test func physicalHandoffAcceptanceRejectsHomeAndTemporaryDirectorySymlinkReplacement() throws {
    do {
        let root = try makePhysicalHandoffAcceptanceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let home = root.appendingPathComponent("home", isDirectory: true)
        let replacement = root.appendingPathComponent("replacement-home", isDirectory: true)
        let replacementSupport = replacement.appendingPathComponent(
            "Library/Application Support/Local Harness",
            isDirectory: true
        )
        let replacementModels = replacement.appendingPathComponent(
            ".ollama/models",
            isDirectory: true
        )
        try FileManager.default.createDirectory(
            at: replacementSupport,
            withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            at: replacementModels,
            withIntermediateDirectories: true
        )
        for directory in [
            replacement,
            replacement.appendingPathComponent("Library", isDirectory: true),
            replacement.appendingPathComponent("Library/Application Support", isDirectory: true),
            replacementSupport,
            replacement.appendingPathComponent(".ollama", isDirectory: true),
            replacementModels
        ] {
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: directory.path
            )
        }
        try FileManager.default.removeItem(at: home)
        try FileManager.default.createSymbolicLink(at: home, withDestinationURL: replacement)

        #expect(throws: PhysicalHandoffAcceptanceEnvironment.ValidationError.unsafeRoot) {
            _ = try PhysicalHandoffAcceptanceEnvironment.resolveIfRequested(
                arguments: [
                    "Fulmar", "--background-schedule",
                    PhysicalHandoffAcceptanceEnvironment.backgroundArgument
                ],
                environment: physicalHandoffEnvironment(root: root),
                runtimeDirectories: physicalHandoffRuntimeDirectories(root: root)
            )
        }
    }

    do {
        let root = try makePhysicalHandoffAcceptanceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let temporary = root.appendingPathComponent("temp", isDirectory: true)
        let replacement = root.appendingPathComponent("replacement-temp", isDirectory: true)
        try FileManager.default.createDirectory(at: replacement, withIntermediateDirectories: false)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: replacement.path
        )
        try FileManager.default.removeItem(at: temporary)
        try FileManager.default.createSymbolicLink(at: temporary, withDestinationURL: replacement)

        #expect(throws: PhysicalHandoffAcceptanceEnvironment.ValidationError.unsafeRoot) {
            _ = try PhysicalHandoffAcceptanceEnvironment.resolveIfRequested(
                arguments: [
                    "Fulmar", "--background-schedule",
                    PhysicalHandoffAcceptanceEnvironment.backgroundArgument
                ],
                environment: physicalHandoffEnvironment(root: root),
                runtimeDirectories: physicalHandoffRuntimeDirectories(root: root)
            )
        }
    }
}

@Test func foregroundHandoffReadyEvidenceIsExactPrivateAndNeverOverwritten() throws {
    let root = try makePhysicalHandoffAcceptanceRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let resolved = try PhysicalHandoffAcceptanceEnvironment.resolveIfRequested(
        arguments: ["Fulmar", PhysicalHandoffAcceptanceEnvironment.foregroundArgument],
        environment: physicalHandoffEnvironment(root: root),
        runtimeDirectories: physicalHandoffRuntimeDirectories(root: root)
    )
    let foreground = try #require(resolved)
    #expect(foreground.mode == .foreground)

    try foreground.publishForegroundReady(selection: .defaultLocal, boundary: .onDevice)
    let firstBytes = try Data(contentsOf: foreground.foregroundReadyFile)
    let value = try #require(
        JSONSerialization.jsonObject(with: firstBytes) as? [String: Any]
    )
    #expect(Set(value.keys) == Set([
        "schemaVersion", "state", "provider", "model", "boundary"
    ]))
    #expect((value["schemaVersion"] as? NSNumber)?.intValue == 1)
    #expect(value["state"] as? String == "ready")
    #expect(value["provider"] as? String == ModelSelection.defaultLocal.route.provider.rawValue)
    #expect(value["model"] as? String == ModelSelection.defaultLocal.route.model.rawValue)
    #expect(value["boundary"] as? String == DataBoundary.onDevice.rawValue)

    var metadata = stat()
    #expect(Darwin.lstat(foreground.foregroundReadyFile.path, &metadata) == 0)
    #expect(metadata.st_mode & S_IFMT == S_IFREG)
    #expect(metadata.st_uid == geteuid())
    #expect(metadata.st_nlink == 1)
    #expect(metadata.st_mode & 0o777 == 0o600)

    #expect(throws: PhysicalHandoffAcceptanceEnvironment.ValidationError.publicationFailed) {
        try foreground.publishForegroundReady(selection: .defaultLocal, boundary: .onDevice)
    }
    #expect(try Data(contentsOf: foreground.foregroundReadyFile) == firstBytes)
}

@Test func physicalHandoffAcceptanceRejectsLinkedOrNonPrivateRoots() throws {
    let root = try makePhysicalHandoffAcceptanceRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let arguments = [
        "Fulmar", "--background-schedule",
        PhysicalHandoffAcceptanceEnvironment.backgroundArgument
    ]

    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: root.path)
    #expect(throws: PhysicalHandoffAcceptanceEnvironment.ValidationError.unsafeRoot) {
        _ = try PhysicalHandoffAcceptanceEnvironment.resolveIfRequested(
            arguments: arguments,
            environment: physicalHandoffEnvironment(root: root)
        )
    }
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)

    let linkedHome = root.appendingPathComponent("linked-home", isDirectory: true)
    try FileManager.default.createSymbolicLink(
        at: linkedHome,
        withDestinationURL: root.appendingPathComponent("home", isDirectory: true)
    )
    var linked = physicalHandoffEnvironment(root: root)
    linked["HOME"] = linkedHome.path
    linked["CFFIXED_USER_HOME"] = linkedHome.path
    #expect(throws: PhysicalHandoffAcceptanceEnvironment.ValidationError.invalidEnvironment) {
        _ = try PhysicalHandoffAcceptanceEnvironment.resolveIfRequested(
            arguments: arguments,
            environment: linked
        )
    }

    let linkedRoot = root.deletingLastPathComponent()
        .appendingPathComponent("\(PhysicalHandoffAcceptanceEnvironment.rootLeafPrefix)linked-root")
    try FileManager.default.createSymbolicLink(at: linkedRoot, withDestinationURL: root)
    defer { try? FileManager.default.removeItem(at: linkedRoot) }
    #expect(throws: PhysicalHandoffAcceptanceEnvironment.ValidationError.unsafeRoot) {
        _ = try PhysicalHandoffAcceptanceEnvironment.resolveIfRequested(
            arguments: arguments,
            environment: physicalHandoffEnvironment(root: linkedRoot)
        )
    }

    let modelStore = root.appendingPathComponent("home/.ollama/models", isDirectory: true)
    let replacement = root.appendingPathComponent("replacement-models", isDirectory: true)
    try FileManager.default.removeItem(at: modelStore)
    try FileManager.default.createDirectory(at: replacement, withIntermediateDirectories: false)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: replacement.path)
    try FileManager.default.createSymbolicLink(at: modelStore, withDestinationURL: replacement)
    #expect(throws: PhysicalHandoffAcceptanceEnvironment.ValidationError.unsafeRoot) {
        _ = try PhysicalHandoffAcceptanceEnvironment.resolveIfRequested(
            arguments: arguments,
            environment: physicalHandoffEnvironment(root: root)
        )
    }
}

@Test func headlessForegroundHandoffStopsBeforeLaunchingAndCoalescesDuplicateRequests() {
    var handoff = HeadlessForegroundHandoff()

    #expect(handoff.phase == .idle)
    #expect(handoff.requestForeground() == .beginProtectedTermination)
    #expect(handoff.phase == .stoppingOwnedWork)
    #expect(handoff.requestForeground() == .none)
    #expect(handoff.protectedStopSucceeded() == .relaunchBeforeTerminationReply)
    #expect(handoff.phase == .relaunchingAfterStop(deferredTerminationReply: true))
    #expect(handoff.requestForeground() == .none)
    #expect(handoff.relaunchCompleted(succeeded: true) == .finishDeferredTermination)
    #expect(handoff.phase == .idle)
}

@Test func headlessForegroundHandoffRetriesOnlyAfterAStoppedRelaunchFailure() {
    var handoff = HeadlessForegroundHandoff()

    #expect(handoff.requestForeground() == .beginProtectedTermination)
    #expect(handoff.protectedStopSucceeded() == .relaunchBeforeTerminationReply)
    #expect(handoff.relaunchCompleted(succeeded: false) == .remainStoppedForRetry)
    #expect(handoff.phase == .stoppedAwaitingRetry)

    #expect(handoff.requestForeground() == .relaunchStoppedProcess)
    #expect(handoff.phase == .relaunchingAfterStop(deferredTerminationReply: false))
    #expect(handoff.relaunchCompleted(succeeded: true) == .terminatePreparedProcess)
    #expect(handoff.phase == .idle)
}

@Test func headlessForegroundHandoffCanRetryAProtectedStopFailure() {
    var handoff = HeadlessForegroundHandoff()

    #expect(handoff.requestForeground() == .beginProtectedTermination)
    let firstFailure = handoff.protectedStopFailed()
    #expect(firstFailure)
    #expect(handoff.phase == .idle)
    let duplicateFailure = handoff.protectedStopFailed()
    #expect(!duplicateFailure)
    #expect(handoff.requestForeground() == .beginProtectedTermination)
}

@Test func headlessForegroundHandoffAcceptsOneLateExactLaunchAfterTimeout() {
    var handoff = HeadlessForegroundHandoff()

    #expect(handoff.requestForeground() == .beginProtectedTermination)
    #expect(handoff.protectedStopSucceeded() == .relaunchBeforeTerminationReply)
    #expect(handoff.relaunchCompleted(succeeded: false) == .remainStoppedForRetry)
    #expect(handoff.phase == .stoppedAwaitingRetry)
    #expect(handoff.lateRelaunchSucceeded() == .terminatePreparedProcess)
    #expect(handoff.phase == .idle)
    #expect(handoff.lateRelaunchSucceeded() == .none)
}
