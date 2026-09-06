import AppKit

/// Builds the menu-bar artwork in code so the status item never depends on an
/// SF Symbol that may be absent on a supported macOS release.
@MainActor
enum StatusItemIcon {
    enum PlacementPath: String {
        case notCreated = "Not created"
        case publicAppKit = "Supported public AppKit"
    }

    /// Pure result for the delayed placement callback. Keeping this decision
    /// separate from AppKit makes the user-hidden, stale-callback, and bounded
    /// Control Center recovery cases deterministic without weakening the live
    /// release gate that observes the real status-item window.
    enum PlacementDecision: Equatable {
        case ignoreStaleCallback
        case respectPersistedHidden
        case acceptVisiblePlacement
        case recreate(nextAttempt: Int)
        case giveUpAfterBoundedAttempts
    }

    /// Last observed placement truth, kept separately from `PlacementPath`.
    /// Creating an item through supported AppKit proves how it was requested;
    /// only delayed button-window geometry can prove where macOS displayed it.
    enum PlacementVerification: Equatable {
        case notChecked
        case pending(recoveryAttempt: Int)
        case hiddenByUser(recoveryAttempt: Int)
        case visible(recoveryAttempt: Int)
        case failed(recoveryAttempt: Int)

        var diagnosticSummary: String {
            switch self {
            case .notChecked:
                return "Not checked"
            case .pending(let attempt):
                return "Pending (recovery attempt \(attempt))"
            case .hiddenByUser(let attempt):
                return "Hidden by the saved macOS user choice (recovery attempt \(attempt))"
            case .visible(let attempt):
                return "Visible in a display menu bar (recovery attempt \(attempt))"
            case .failed(let attempt):
                return "Not visible after bounded recovery (recovery attempt \(attempt))"
            }
        }
    }

    static let size = NSSize(width: 18, height: 18)
    // Keep the allocation equal to the artwork. Control Center adds its own
    // scene padding, so a wider fixed allocation needlessly increases the
    // chance that macOS clips the item on a notched display.
    static let statusItemLength: CGFloat = 18
    static let initialCreationDelay: TimeInterval = 1.0
    // Apple's public visibility persistence is keyed by autosaveName. Never
    // fall back to the generic Item-0 identity, which can collide with stale
    // macOS 26 Control Center tracking records across development launches.
    // v2 deliberately abandons the v1 record after the release soak observed
    // Control Center restore a programmatically removed item at its off-screen
    // parking coordinate. Normal teardown detaches this identity before asking
    // AppKit to remove the retained item, so only a user's visibility choice
    // made while the app is running can be persisted under v2.
    static let autosaveName = "Fulmar.MenuBar.v2"
    static let visibilityInitializationKey = "Fulmar.MenuBar.v2.VisibilityInitialized"
    static let placementRecoveryDelay: TimeInterval = 2.0
    static let maximumPlacementRecoveryAttempts = 2
    static private(set) var activePlacementPath: PlacementPath = .notCreated
    static private(set) var lastPlacementVerification: PlacementVerification = .notChecked

    static func makeStatusItem(in statusBar: NSStatusBar = .system) -> NSStatusItem {
        // Use only AppKit's documented factory. The former private priority
        // selector neither made Control Center's host non-clippable nor offered
        // a stable ABI suitable for a public download.
        activePlacementPath = .publicAppKit
        return statusBar.statusItem(withLength: statusItemLength)
    }

    static func beginPlacementVerification(recoveryAttempt: Int) {
        lastPlacementVerification = .pending(recoveryAttempt: recoveryAttempt)
    }

    static func recordPlacementDecision(_ decision: PlacementDecision, recoveryAttempt: Int) {
        switch decision {
        case .ignoreStaleCallback:
            return
        case .respectPersistedHidden:
            lastPlacementVerification = .hiddenByUser(recoveryAttempt: recoveryAttempt)
        case .acceptVisiblePlacement:
            lastPlacementVerification = .visible(recoveryAttempt: recoveryAttempt)
        case .recreate(let nextAttempt):
            lastPlacementVerification = .pending(recoveryAttempt: nextAttempt)
        case .giveUpAfterBoundedAttempts:
            lastPlacementVerification = .failed(recoveryAttempt: recoveryAttempt)
        }
    }

    /// A new autosave identity can initially be parked by Control Center even
    /// though NSStatusItem defaults to visible. Use AppKit's documented setter
    /// exactly once for this identity, then let the autosaved user choice win
    /// on every later launch. The marker is written only after the show action
    /// so an interrupted first launch safely retries initialization.
    static func initializeVisibilityIfNeeded(
        defaults: UserDefaults = .standard,
        show: () -> Void
    ) {
        guard defaults.object(forKey: visibilityInitializationKey) == nil else { return }
        show()
        defaults.set(true, forKey: visibilityInitializationKey)
    }

    /// NSStatusItem.isVisible remains true when Control Center temporarily
    /// parks an item off-screen, so the app's own button-window geometry is the
    /// only public, permission-free launch-time distinction. AppKit global
    /// coordinates place the menu bar at each screen's maximum Y edge.
    static func isTopVisible(
        _ frame: CGRect,
        screenFrames: [CGRect],
        menuBarHeight: CGFloat,
        tolerance: CGFloat = 1
    ) -> Bool {
        guard frame.origin.x.isFinite,
              frame.origin.y.isFinite,
              frame.width.isFinite,
              frame.height.isFinite,
              frame.width > 0,
              frame.height > 0,
              menuBarHeight.isFinite,
              menuBarHeight > 0,
              tolerance.isFinite,
              tolerance >= 0 else { return false }

        return screenFrames.contains { screen in
            guard screen.origin.x.isFinite,
                  screen.origin.y.isFinite,
                  screen.width.isFinite,
                  screen.height.isFinite,
                  screen.width > 0,
                  screen.height > 0 else { return false }
            let compactLeftParking = frame.width <= 32
                && frame.minX >= screen.minX - tolerance
                && frame.minX <= screen.minX + 12
            guard !compactLeftParking else { return false }
            let horizontal = frame.minX >= screen.minX - tolerance
                && frame.maxX <= screen.maxX + tolerance
            let bandBottom = screen.maxY - min(menuBarHeight, screen.height) - tolerance
            let vertical = frame.minY >= bandBottom
                && frame.maxY <= screen.maxY + tolerance
            return horizontal && vertical
        }
    }

    static func placementDecision(
        isCurrentItem: Bool,
        isVisible: Bool,
        frame: CGRect?,
        screenFrames: [CGRect],
        menuBarHeight: CGFloat,
        attempt: Int,
        maximumAttempts: Int = 2
    ) -> PlacementDecision {
        guard isCurrentItem else { return .ignoreStaleCallback }
        guard isVisible else { return .respectPersistedHidden }
        if let frame,
           isTopVisible(frame, screenFrames: screenFrames, menuBarHeight: menuBarHeight) {
            return .acceptVisiblePlacement
        }
        guard attempt >= 0, maximumAttempts >= 0, attempt < maximumAttempts else {
            return .giveUpAfterBoundedAttempts
        }
        return .recreate(nextAttempt: attempt + 1)
    }

    static func make(accessibilityDescription: String = ProductBrand.displayName) -> NSImage {
        let image = NSImage(size: size, flipped: false) { _ in
            NSColor.black.setFill()

            // A deliberately simple Fulmar silhouette: two routed wings meet
            // at one body and remain legible in the 18-point menu-bar slot.
            let bird = NSBezierPath()
            bird.move(to: NSPoint(x: 15.8, y: 2.4))
            bird.curve(to: NSPoint(x: 9.7, y: 8.9),
                       controlPoint1: NSPoint(x: 13.7, y: 4.0),
                       controlPoint2: NSPoint(x: 11.4, y: 6.6))
            bird.curve(to: NSPoint(x: 2.0, y: 15.7),
                       controlPoint1: NSPoint(x: 7.5, y: 10.8),
                       controlPoint2: NSPoint(x: 4.5, y: 13.7))
            bird.curve(to: NSPoint(x: 8.2, y: 10.0),
                       controlPoint1: NSPoint(x: 4.8, y: 14.7),
                       controlPoint2: NSPoint(x: 6.9, y: 12.6))
            bird.curve(to: NSPoint(x: 2.8, y: 4.0),
                       controlPoint1: NSPoint(x: 6.3, y: 8.0),
                       controlPoint2: NSPoint(x: 4.7, y: 5.7))
            bird.curve(to: NSPoint(x: 9.1, y: 8.2),
                       controlPoint1: NSPoint(x: 5.2, y: 4.6),
                       controlPoint2: NSPoint(x: 7.1, y: 6.1))
            bird.curve(to: NSPoint(x: 15.8, y: 2.4),
                       controlPoint1: NSPoint(x: 11.7, y: 6.1),
                       controlPoint2: NSPoint(x: 14.3, y: 3.8))
            bird.close()
            bird.fill()

            for center in [NSPoint(x: 8.7, y: 8.8), NSPoint(x: 12.1, y: 5.7)] {
                NSBezierPath(ovalIn: NSRect(x: center.x - 0.85, y: center.y - 0.85,
                                            width: 1.7, height: 1.7)).fill()
            }

            return true
        }
        image.isTemplate = true
        image.accessibilityDescription = accessibilityDescription
        return image
    }

    static func configure(button: NSStatusBarButton) {
        button.image = make()
        button.imagePosition = .imageOnly
        button.imageScaling = .scaleProportionallyDown
        button.toolTip = "Open \(ProductBrand.displayName)"
        button.setAccessibilityLabel("\(ProductBrand.displayName) menu")
    }

}
