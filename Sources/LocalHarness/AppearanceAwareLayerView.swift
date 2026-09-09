import AppKit

/// Resolves semantic AppKit colours again whenever a window changes appearance.
/// Storing a one-time `CGColor` freezes the Aqua value and produces incorrect
/// borders/backgrounds after a live switch to Dark Aqua.
final class AppearanceAwareLayerView: NSView {
    var semanticBackgroundColor: NSColor? { didSet { refreshSemanticColors() } }
    var backgroundAlpha: CGFloat = 1 { didSet { refreshSemanticColors() } }
    var semanticBorderColor: NSColor? { didSet { refreshSemanticColors() } }
    var borderAlpha: CGFloat = 1 { didSet { refreshSemanticColors() } }

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        wantsLayer = true
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        refreshSemanticColors()
    }

    func refreshSemanticColors() {
        effectiveAppearance.performAsCurrentDrawingAppearance {
            layer?.backgroundColor = semanticBackgroundColor?
                .withAlphaComponent(backgroundAlpha).cgColor
            layer?.borderColor = semanticBorderColor?
                .withAlphaComponent(borderAlpha).cgColor
        }
    }
}

final class AppearanceAwareLayerBox: NSBox {
    var semanticBorderColor: NSColor = .separatorColor { didSet { refreshSemanticColors() } }
    var borderAlpha: CGFloat = 1 { didSet { refreshSemanticColors() } }

    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        refreshSemanticColors()
    }

    func refreshSemanticColors() {
        effectiveAppearance.performAsCurrentDrawingAppearance {
            layer?.borderColor = semanticBorderColor.withAlphaComponent(borderAlpha).cgColor
        }
    }
}
