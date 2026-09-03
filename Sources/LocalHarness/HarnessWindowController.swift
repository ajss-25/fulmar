import AppKit
import WebKit

/// Keeps the dynamic service status visually centred beside the adjacent model
/// picker. An `NSTextField` label stretched to the toolbar's full height draws
/// against its cell's top inset, which made the green Ready text appear several
/// points higher than the popup title on macOS 26.
final class CenteredToolbarStatusView: NSView {
    /// `NSPopUpButtonCell` paints its title a fraction below the geometric
    /// centre of its 26-point control. Matching that optical centre avoids the
    /// status text looking high beside the model title on Retina displays.
    private static let opticalVerticalOffset: CGFloat = -0.5

    let label: NSTextField

    init(label: NSTextField, width: CGFloat, height: CGFloat) {
        self.label = label
        super.init(frame: NSRect(x: 0, y: 0, width: width, height: height))
        addSubview(label)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func layout() {
        super.layout()
        let intrinsicHeight = max(1, label.intrinsicContentSize.height)
        let y = max(0, (bounds.height - intrinsicHeight) / 2 + Self.opticalVerticalOffset)
        label.frame = NSRect(x: 0, y: y, width: bounds.width, height: intrinsicHeight)
    }

    override var intrinsicContentSize: NSSize { frame.size }
}

final class ToolbarModelRouteChoice: NSObject {
    let route: ModelRoute
    let boundary: DataBoundary
    let providerName: String
    let modelName: String
    let descriptor: ProviderDescriptor

    init(route: ModelRoute, boundary: DataBoundary, providerName: String, modelName: String, descriptor: ProviderDescriptor) {
        self.route = route
        self.boundary = boundary
        self.providerName = providerName
        self.modelName = modelName
        self.descriptor = descriptor
    }
}

final class HarnessWindowController: NSWindowController, NSToolbarDelegate {
    private enum Item {
        static let back = NSToolbarItem.Identifier("localHarness.back")
        static let forward = NSToolbarItem.Identifier("localHarness.forward")
        static let newSession = NSToolbarItem.Identifier("localHarness.newSession")
        static let status = NSToolbarItem.Identifier("localHarness.status")
        static let appshot = NSToolbarItem.Identifier("localHarness.appshot")
        static let quickChat = NSToolbarItem.Identifier("localHarness.quickChat")
        static let reload = NSToolbarItem.Identifier("localHarness.reload")
        static let activity = NSToolbarItem.Identifier("localHarness.activity")
        static let models = NSToolbarItem.Identifier("localHarness.models")
        static let route = NSToolbarItem.Identifier("localHarness.route")
        static let commandCenter = NSToolbarItem.Identifier("localHarness.commandCenter")
    }

    let surface: HarnessWebViewController
    private weak var actionTarget: AnyObject?
    private let toolbarControlHeight: CGFloat
    private let statusLabel = NSTextField(labelWithString: "Starting…")
    private let routePicker = NSPopUpButton()
    private lazy var statusView = CenteredToolbarStatusView(
        label: statusLabel,
        width: 210,
        height: toolbarControlHeight
    )
    private lazy var statusViewConstraints: [NSLayoutConstraint] = {
        let width = statusView.widthAnchor.constraint(equalToConstant: 210)
        let height = statusView.heightAnchor.constraint(equalToConstant: toolbarControlHeight)
        width.identifier = "Fulmar.Toolbar.Status.Width"
        height.identifier = "Fulmar.Toolbar.Status.Height"
        return [width, height]
    }()
    private lazy var routePickerConstraints: [NSLayoutConstraint] = {
        let width = routePicker.widthAnchor.constraint(equalToConstant: 218)
        let height = routePicker.heightAnchor.constraint(equalToConstant: toolbarControlHeight)
        width.identifier = "Fulmar.Toolbar.Route.Width"
        height.identifier = "Fulmar.Toolbar.Route.Height"
        return [width, height]
    }()
    private var routeSelection: ModelSelection = .defaultLocal
    private var lastAnnouncedStatus: String?

    init(
        dataStore: WKWebsiteDataStore,
        preferences: PreferencesStore,
        actionTarget: AnyObject,
        displayPolicy: NativeAccessibilityDisplayPolicy = .live,
        typography: NativeTypographyPolicy = .standard
    ) {
        toolbarControlHeight = typography.toolbarControlHeight
        surface = HarnessWebViewController(
            dataStore: dataStore,
            preferences: preferences,
            displayPolicy: displayPolicy,
            typography: typography
        )
        self.actionTarget = actionTarget

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1280, height: 840),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.title = ProductBrand.displayName
        window.subtitle = "Agent Workspace"
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = false
        window.toolbarStyle = .unified
        window.minSize = NSSize(width: 900, height: 600)
        window.isReleasedWhenClosed = false
        window.setFrameAutosaveName("LocalHarness.MainWindow")
        window.contentViewController = surface

        super.init(window: window)

        statusLabel.font = typography.font(for: .toolbarStatus)
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.alignment = .center
        statusLabel.lineBreakMode = .byTruncatingTail
        statusLabel.maximumNumberOfLines = 1
        statusLabel.setAccessibilityLabel("Local service status")
        updateStatus("Starting…", color: .secondaryLabelColor)

        // Configure the control before AppKit asks the toolbar delegate so both
        // custom views use one derived height (exactly 26 points at 100%).
        routePicker.bezelStyle = .texturedRounded
        routePicker.controlSize = .small
        routePicker.font = typography.font(for: .toolbarStatus)
        routePicker.cell?.lineBreakMode = .byTruncatingTail
        routePicker.setAccessibilityLabel("Default model and provider")
        routePicker.toolTip = "Default route for new \(ProductBrand.displayName) tasks"

        // This identifier is deliberately versioned. Earlier builds let AppKit
        // persist a customised layout under LocalHarness.MainToolbar, which
        // could restore an empty or obsolete toolbar after an upgrade.
        let toolbar = NSToolbar(identifier: "Fulmar.MainToolbar.v2")
        toolbar.delegate = self
        // The old icon-only toolbar made important modes look like unexplained
        // gaps when an SF Symbol was unavailable. Labels keep Chat and Agent
        // navigation usable and accessible across supported macOS versions.
        toolbar.displayMode = .iconAndLabel
        toolbar.allowsUserCustomization = false
        toolbar.autosavesConfiguration = false
        window.toolbar = toolbar
        toolbar.isVisible = true
        // `window.toolbar =` completes AppKit's first toolbar-cell adaptation,
        // which may replace a popup's font after the delegate returns.
        routePicker.font = statusLabel.font
        if !window.setFrameUsingName("LocalHarness.MainWindow") {
            window.center()
        }
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func updateStatus(_ text: String, color: NSColor) {
        let visible = "● \(text)"
        let attributed = NSMutableAttributedString(
            string: visible,
            attributes: [
                .font: statusLabel.font ?? NSFont.systemFont(ofSize: 11, weight: .medium),
                .foregroundColor: NSColor.labelColor
            ]
        )
        attributed.addAttribute(.foregroundColor, value: color, range: NSRange(location: 0, length: 1))
        statusLabel.attributedStringValue = attributed
        statusLabel.toolTip = text
        statusLabel.setAccessibilityValue(text)
        if lastAnnouncedStatus != text {
            lastAnnouncedStatus = text
            AccessibilityAnnouncement.post(text, element: statusLabel)
        }
    }

    func toolbarAllowedItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        [.space, .flexibleSpace, Item.back, Item.forward, Item.newSession, Item.status, Item.route,
         Item.activity, Item.models, Item.appshot, Item.quickChat, Item.commandCenter, Item.reload]
    }

    func toolbarDefaultItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        [Item.newSession, Item.commandCenter, .flexibleSpace, Item.status, Item.route, .flexibleSpace, Item.appshot, Item.quickChat]
    }

    func toolbar(_ toolbar: NSToolbar, itemForItemIdentifier identifier: NSToolbarItem.Identifier,
                 willBeInsertedIntoToolbar flag: Bool) -> NSToolbarItem? {
        switch identifier {
        case Item.status:
            let item = NSToolbarItem(itemIdentifier: identifier)
            item.view = statusView
            NSLayoutConstraint.activate(statusViewConstraints)
            item.label = "Local Service Status"
            return item
        case Item.route:
            let item = NSToolbarItem(itemIdentifier: identifier)
            NSLayoutConstraint.activate(routePickerConstraints)
            item.view = routePicker
            // AppKit may replace a popup cell's font when the view first enters
            // an NSToolbar. Reapply the shared semantic toolbar font after
            // insertion so the model title and status label retain one metric.
            routePicker.font = statusLabel.font
            item.label = "Model"
            item.paletteLabel = "Model & Provider"
            rebuildRouteMenu(catalog: nil, selection: routeSelection)
            return item
        case Item.back:
            return toolbarItem(identifier, label: "Back", symbol: "chevron.left", action: #selector(AppDelegate.goBack(_:)))
        case Item.forward:
            return toolbarItem(identifier, label: "Forward", symbol: "chevron.right", action: #selector(AppDelegate.goForward(_:)))
        case Item.newSession:
            return toolbarItem(identifier, label: "New Session", symbol: "square.and.pencil", action: #selector(AppDelegate.newSession(_:)))
        case Item.appshot:
            return toolbarItem(identifier, label: "Appshot", symbol: "viewfinder", action: #selector(AppDelegate.captureAppshot(_:)))
        case Item.quickChat:
            return toolbarItem(identifier, label: "Chat", symbol: "bubble.left.and.bubble.right", action: #selector(AppDelegate.showQuickChat(_:)))
        case Item.commandCenter:
            return toolbarItem(identifier, label: "Explore", symbol: "magnifyingglass", action: #selector(AppDelegate.showCommandCenter(_:)))
        case Item.reload:
            return toolbarItem(identifier, label: "Reload", symbol: "arrow.clockwise", action: #selector(AppDelegate.reloadHarness(_:)))
        case Item.activity:
            return toolbarItem(identifier, label: "Activity", symbol: "list.bullet.rectangle", action: #selector(AppDelegate.showActivityCenter(_:)))
        case Item.models:
            return toolbarItem(identifier, label: "Models & Providers", symbol: "memorychip", action: #selector(AppDelegate.showProviderCenter(_:)))
        default:
            return nil
        }
    }

    func updateRouteMenu(catalog: HarnessModelCatalogSnapshot?, selection: ModelSelection) {
        routeSelection = selection
        rebuildRouteMenu(catalog: catalog, selection: selection)
    }

    private func rebuildRouteMenu(catalog: HarnessModelCatalogSnapshot?, selection: ModelSelection) {
        let menu = NSMenu(title: "Model & Provider")
        // The first item supplies the popup's collapsed title. Leaving that
        // selected item disabled makes AppKit paint an otherwise available
        // route as unavailable. Disable automatic action validation and keep
        // this harmless current-title item enabled so the selector retains the
        // normal label colour in both appearances. It has no represented route
        // choice and therefore cannot initiate a provider change.
        menu.autoenablesItems = false
        let currentProvider = catalog?.provider(selection.route.provider)
        let currentModel = currentProvider?.models.first { $0.id == selection.route.model }
        let currentName = currentModel?.displayName ?? selection.route.model.rawValue
        let boundary = currentProvider?.boundary ?? (selection.route.provider == BuiltInProviderDescriptors.ollama.id ? .onDevice : .cloud)
        let current = NSMenuItem(
            title: "\(boundaryGlyph(boundary))  \(currentName) — \(boundary.displayName)",
            action: nil,
            keyEquivalent: ""
        )
        current.isEnabled = true
        menu.addItem(current)
        menu.addItem(.separator())

        if let catalog {
            for provider in catalog.providers where provider.configurationState == .ready && !provider.models.isEmpty {
                let providerItem = NSMenuItem(
                    title: "\(boundaryGlyph(provider.boundary))  \(provider.displayName) — \(provider.boundary.displayName)",
                    action: nil,
                    keyEquivalent: ""
                )
                let models = NSMenu(title: provider.displayName)
                for model in provider.models {
                    let choice = NSMenuItem(title: model.displayName, action: #selector(AppDelegate.selectToolbarModel(_:)), keyEquivalent: "")
                    choice.target = actionTarget
                    choice.state = provider.id == selection.route.provider && model.id == selection.route.model ? .on : .off
                    choice.representedObject = ToolbarModelRouteChoice(
                        route: ModelRoute(provider: provider.id, model: model.id),
                        boundary: provider.boundary,
                        providerName: provider.displayName,
                        modelName: model.displayName,
                        descriptor: provider.descriptor
                    )
                    models.addItem(choice)
                }
                providerItem.submenu = models
                menu.addItem(providerItem)
            }
            menu.addItem(.separator())
        }

        let choose = NSMenuItem(title: "Models & Providers…", action: #selector(AppDelegate.showProviderCenter(_:)), keyEquivalent: "")
        choose.target = actionTarget
        menu.addItem(choose)
        routePicker.menu = menu
        routePicker.selectItem(at: 0)
        routePicker.toolTip = "\(currentName) · \(boundary.displayName) · default for new tasks"
        routePicker.setAccessibilityValue("\(currentName), \(boundary.displayName)")
        routePicker.setAccessibilityHelp(
            "Choose the default model and data boundary for new \(ProductBrand.displayName) tasks."
        )
        window?.subtitle = "\(currentName) · \(boundary.displayName)"
    }

    private func boundaryGlyph(_ boundary: DataBoundary) -> String {
        switch boundary { case .onDevice: return "●"; case .localNetwork: return "◆"; case .cloud: return "☁" }
    }

    private func toolbarItem(_ identifier: NSToolbarItem.Identifier, label: String, symbol: String,
                             action: Selector) -> NSToolbarItem {
        let item = NSToolbarItem(itemIdentifier: identifier)
        item.label = label
        item.paletteLabel = label
        item.toolTip = label
        item.image = NSImage(systemSymbolName: symbol, accessibilityDescription: label)
        item.target = actionTarget
        item.action = action
        return item
    }
}
