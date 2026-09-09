import AppKit

/// A small, injectable view of the macOS accessibility display preferences
/// used by native Fulmar surfaces. Production evaluates the system values for
/// every presentation and again when macOS posts its display-options change
/// notification; tests use `fixed` to make every branch deterministic.
struct NativeAccessibilityDisplayPolicy {
    private let reduceMotionValue: () -> Bool
    private let reduceTransparencyValue: () -> Bool

    init(
        reduceMotion: @escaping () -> Bool,
        reduceTransparency: @escaping () -> Bool
    ) {
        reduceMotionValue = reduceMotion
        reduceTransparencyValue = reduceTransparency
    }

    var reducesMotion: Bool { reduceMotionValue() }
    var reducesTransparency: Bool { reduceTransparencyValue() }

    static let live = NativeAccessibilityDisplayPolicy(
        reduceMotion: { NSWorkspace.shared.accessibilityDisplayShouldReduceMotion },
        reduceTransparency: { NSWorkspace.shared.accessibilityDisplayShouldReduceTransparency }
    )

    static func fixed(
        reduceMotion: Bool = false,
        reduceTransparency: Bool = false
    ) -> NativeAccessibilityDisplayPolicy {
        NativeAccessibilityDisplayPolicy(
            reduceMotion: { reduceMotion },
            reduceTransparency: { reduceTransparency }
        )
    }

    /// Sidebars normally use the native vibrancy material. Reduce Transparency
    /// replaces that material with a fully opaque semantic AppKit colour while
    /// preserving the same layout and accessibility hierarchy.
    func makeSidebarContainer() -> NativeAccessibilitySidebarView {
        NativeAccessibilitySidebarView(displayPolicy: self)
    }

    /// Resolves an indeterminate progress indicator into an explicit visual
    /// and motion state. Busy text remains available when Reduce Motion is on,
    /// while the non-informative animation is removed entirely.
    func progressIndicatorPresentation(isBusy: Bool) -> NativeProgressIndicatorPresentation {
        let shouldAnimate = isBusy && !reducesMotion
        return NativeProgressIndicatorPresentation(
            isHidden: !shouldAnimate,
            shouldAnimate: shouldAnimate
        )
    }
}

/// Stable sidebar container whose content hierarchy never needs to be moved
/// when Reduce Transparency changes. Only the two background layers switch,
/// avoiding first-responder loss and split-view reconstruction while a person
/// is using the window.
final class NativeAccessibilitySidebarView: NSView {
    private let displayPolicy: NativeAccessibilityDisplayPolicy
    private let vibrancy = NSVisualEffectView()
    private let opaqueBackground = AppearanceAwareLayerView()
    private(set) var isUsingOpaqueBackground = false

    init(displayPolicy: NativeAccessibilityDisplayPolicy) {
        self.displayPolicy = displayPolicy
        super.init(frame: .zero)

        vibrancy.material = .sidebar
        vibrancy.blendingMode = .withinWindow
        vibrancy.state = .active
        vibrancy.translatesAutoresizingMaskIntoConstraints = false
        addSubview(vibrancy)

        opaqueBackground.semanticBackgroundColor = .windowBackgroundColor
        opaqueBackground.backgroundAlpha = 1
        opaqueBackground.translatesAutoresizingMaskIntoConstraints = false
        addSubview(opaqueBackground)

        NSLayoutConstraint.activate([
            vibrancy.topAnchor.constraint(equalTo: topAnchor),
            vibrancy.leadingAnchor.constraint(equalTo: leadingAnchor),
            vibrancy.trailingAnchor.constraint(equalTo: trailingAnchor),
            vibrancy.bottomAnchor.constraint(equalTo: bottomAnchor),
            opaqueBackground.topAnchor.constraint(equalTo: topAnchor),
            opaqueBackground.leadingAnchor.constraint(equalTo: leadingAnchor),
            opaqueBackground.trailingAnchor.constraint(equalTo: trailingAnchor),
            opaqueBackground.bottomAnchor.constraint(equalTo: bottomAnchor)
        ])
        refreshAccessibilityAppearance()
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func refreshAccessibilityAppearance() {
        isUsingOpaqueBackground = displayPolicy.reducesTransparency
        opaqueBackground.isHidden = !isUsingOpaqueBackground
        vibrancy.isHidden = isUsingOpaqueBackground
    }
}

/// Owns one workspace-notification registration and removes it with the
/// observing controller. The callback is delivered on the main queue so every
/// AppKit refresh remains main-actor isolated.
@MainActor
final class NativeAccessibilityDisplayObserver {
    private let notificationCenter: NotificationCenter
    private var token: NSObjectProtocol?

    init(
        notificationCenter: NotificationCenter = NSWorkspace.shared.notificationCenter,
        onChange: @escaping @MainActor () -> Void
    ) {
        self.notificationCenter = notificationCenter
        token = notificationCenter.addObserver(
            forName: NSWorkspace.accessibilityDisplayOptionsDidChangeNotification,
            object: nil,
            queue: .main
        ) { _ in
            MainActor.assumeIsolated { onChange() }
        }
    }

    deinit {
        if let token { notificationCenter.removeObserver(token) }
    }
}

struct NativeProgressIndicatorPresentation: Equatable {
    let isHidden: Bool
    let shouldAnimate: Bool

    func apply(to indicator: NSProgressIndicator) {
        indicator.isHidden = isHidden
        if shouldAnimate {
            indicator.startAnimation(nil)
        } else {
            indicator.stopAnimation(nil)
        }
    }
}

/// Semantic type roles for the release-critical native surfaces. macOS does
/// not expose iOS-style Dynamic Type categories to AppKit, so the policy keeps
/// the intended hierarchy explicit and provides a bounded scale seam for
/// accessibility qualification and deterministic 100/125/150% layout tests.
enum NativeTypographyRole {
    case toolbarStatus
    case settingsHeading
    case settingsSubtitle
    case settingsNote
    case workspaceStatus
    case workspaceDetail
}

struct NativeTypographyPolicy {
    static let minimumScale: CGFloat = 1
    static let maximumScale: CGFloat = 1.5
    static let standard = NativeTypographyPolicy(scale: 1)

    let scale: CGFloat

    init(scale: CGFloat) {
        self.scale = min(Self.maximumScale, max(Self.minimumScale, scale))
    }

    func font(for role: NativeTypographyRole) -> NSFont {
        let metrics: (size: CGFloat, weight: NSFont.Weight) = switch role {
        case .toolbarStatus: (11, .medium)
        case .settingsHeading: (22, .semibold)
        case .settingsSubtitle: (13, .regular)
        case .settingsNote: (11.5, .regular)
        case .workspaceStatus: (15, .medium)
        case .workspaceDetail: (13, .regular)
        }
        return .systemFont(ofSize: metrics.size * scale, weight: metrics.weight)
    }

    /// Keeps the model popup and status container on one shared metric. The
    /// release baseline stays exactly 26 points; larger text adds only the
    /// vertical room required by the scaled toolbar font.
    var toolbarControlHeight: CGFloat {
        max(26, ceil(font(for: .toolbarStatus).boundingRectForFont.height + 8))
    }
}
