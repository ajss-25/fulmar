import AppKit
import Testing
import WebKit
@testable import LocalHarness

private struct ToolbarPaintBounds {
    var minY = Int.max
    var maxY = Int.min

    mutating func include(y: Int) {
        minY = min(minY, y)
        maxY = max(maxY, y)
    }

    var isEmpty: Bool { minY == Int.max }
}

private enum ToolbarRenderTestError: Error {
    case unavailableBitmap
    case incompatibleBitmap
}

@MainActor
private func toolbarBitmap(of view: NSView) throws -> NSBitmapImageRep {
    view.layoutSubtreeIfNeeded()
    view.needsDisplay = true
    view.displayIfNeeded()
    guard let image = view.bitmapImageRepForCachingDisplay(in: view.bounds) else {
        throw ToolbarRenderTestError.unavailableBitmap
    }
    view.cacheDisplay(in: view.bounds, to: image)
    return image
}

private func changedPaintBounds(
    rendered: NSBitmapImageRep,
    reference: NSBitmapImageRep,
    minimumComponentDifference: CGFloat = 0.025
) throws -> ToolbarPaintBounds {
    var bounds = ToolbarPaintBounds()
    guard rendered.pixelsWide == reference.pixelsWide,
          rendered.pixelsHigh == reference.pixelsHigh,
          rendered.bitsPerSample == 8,
          reference.bitsPerSample == 8,
          !rendered.isPlanar,
          !reference.isPlanar,
          rendered.bitsPerPixel % 8 == 0,
          reference.bitsPerPixel % 8 == 0,
          rendered.bitsPerPixel == reference.bitsPerPixel,
          let renderedData = rendered.bitmapData,
          let referenceData = reference.bitmapData else {
        throw ToolbarRenderTestError.incompatibleBitmap
    }
    let bytesPerPixel = rendered.bitsPerPixel / 8
    guard bytesPerPixel >= 3,
          rendered.bytesPerRow >= rendered.pixelsWide * bytesPerPixel,
          reference.bytesPerRow >= reference.pixelsWide * bytesPerPixel else {
        throw ToolbarRenderTestError.incompatibleBitmap
    }
    let minimumByteDifference = UInt8(
        min(255, max(1, Int(ceil(minimumComponentDifference * 255))))
    )
    for y in 0..<rendered.pixelsHigh {
        let renderedRow = renderedData.advanced(by: y * rendered.bytesPerRow)
        let referenceRow = referenceData.advanced(by: y * reference.bytesPerRow)
        for x in 0..<rendered.pixelsWide {
            let renderedPixel = renderedRow.advanced(by: x * bytesPerPixel)
            let referencePixel = referenceRow.advanced(by: x * bytesPerPixel)
            for component in 0..<bytesPerPixel {
                let actual = renderedPixel[component]
                let baseline = referencePixel[component]
                let difference = actual >= baseline ? actual - baseline : baseline - actual
                if difference >= minimumByteDifference {
                    bounds.include(y: y)
                    break
                }
            }
        }
    }
    return bounds
}

@MainActor
private func renderedStatusTextBounds(
    container: NSView,
    label: NSTextField
) throws -> (bounds: ToolbarPaintBounds, scaleY: CGFloat) {
    let original = label.attributedStringValue
    defer {
        label.attributedStringValue = original
        container.layoutSubtreeIfNeeded()
    }
    let rendered = try toolbarBitmap(of: container)
    let prefixLength = min(2, original.length)
    label.attributedStringValue = original.attributedSubstring(
        from: NSRange(location: 0, length: prefixLength)
    )
    label.needsDisplay = true
    container.needsDisplay = true
    container.layoutSubtreeIfNeeded()
    let reference = try toolbarBitmap(of: container)
    return (
        try changedPaintBounds(rendered: rendered, reference: reference),
        CGFloat(rendered.pixelsHigh) / max(1, container.bounds.height)
    )
}

@MainActor
private func renderedModelTextBounds(
    picker: NSPopUpButton
) throws -> (bounds: ToolbarPaintBounds, scaleY: CGFloat) {
    let item = try #require(picker.selectedItem)
    let originalTitle = item.title
    defer {
        item.title = originalTitle
        picker.synchronizeTitleAndSelectedItem()
    }
    let rendered = try toolbarBitmap(of: picker)
    item.title = ""
    picker.synchronizeTitleAndSelectedItem()
    picker.needsDisplay = true
    let reference = try toolbarBitmap(of: picker)
    return (
        try changedPaintBounds(rendered: rendered, reference: reference),
        CGFloat(rendered.pixelsHigh) / max(1, picker.bounds.height)
    )
}

@MainActor
private func renderedCommonProbeBounds(
    container: NSView,
    label: NSTextField,
    picker: NSPopUpButton
) throws -> (
    status: ToolbarPaintBounds,
    model: ToolbarPaintBounds,
    statusScaleY: CGFloat,
    modelScaleY: CGFloat,
    scaleY: CGFloat
) {
    let item = try #require(picker.selectedItem)
    let originalStatus = label.attributedStringValue
    let originalModelTitle = item.title
    defer {
        label.attributedStringValue = originalStatus
        item.title = originalModelTitle
        picker.synchronizeTitleAndSelectedItem()
        label.needsDisplay = true
        container.needsDisplay = true
        picker.needsDisplay = true
    }

    let probe = "AgjpQy"
    let textAttributeIndex = min(2, max(0, originalStatus.length - 1))
    let textAttributes = originalStatus.length > 0
        ? originalStatus.attributes(at: textAttributeIndex, effectiveRange: nil)
        : [.font: label.font ?? NSFont.systemFont(ofSize: 11, weight: .medium)]
    let dotAttributes = originalStatus.length > 0
        ? originalStatus.attributes(at: 0, effectiveRange: nil)
        : textAttributes
    let statusProbe = NSMutableAttributedString(string: "● ", attributes: dotAttributes)
    statusProbe.append(NSAttributedString(string: probe, attributes: textAttributes))
    label.attributedStringValue = statusProbe
    item.title = probe
    picker.synchronizeTitleAndSelectedItem()
    label.needsDisplay = true
    container.needsDisplay = true
    picker.needsDisplay = true

    let statusPaint = try renderedStatusTextBounds(container: container, label: label)
    let modelPaint = try renderedModelTextBounds(picker: picker)
    return (
        statusPaint.bounds,
        modelPaint.bounds,
        statusPaint.scaleY,
        modelPaint.scaleY,
        max(statusPaint.scaleY, modelPaint.scaleY)
    )
}

@MainActor
@Test func mainToolbarStatusAndModelControlsShareOneVisualCenter() {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    for scale in [CGFloat(1), 1.25, 1.5] {
        let typography = NativeTypographyPolicy(scale: scale)
        let height = typography.toolbarControlHeight
        let picker = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 218, height: height))
        picker.controlSize = .small
        picker.font = typography.font(for: .toolbarStatus)
        picker.addItem(withTitle: "Qwen 3.8 27B MLX (Local)")

        let label = NSTextField(labelWithString: "Ready · On this Mac")
        label.font = typography.font(for: .toolbarStatus)
        let status = CenteredToolbarStatusView(
            label: label,
            width: 148,
            height: height
        )

        status.layoutSubtreeIfNeeded()

        // Both controls grow from the same type metric, and the status label's
        // intrinsic-height frame remains geometrically centred.
        #expect(abs(label.frame.midY - picker.frame.midY) < 0.1)
        #expect(abs(label.frame.height - label.intrinsicContentSize.height) < 0.5)
        #expect(status.frame.height == picker.frame.height)
        #expect(label.frame.minY >= status.bounds.minY)
        #expect(label.frame.maxY <= status.bounds.maxY)
        #expect(label.font?.pointSize == picker.font?.pointSize)
        if scale == 1 { #expect(height == 26) }
    }
}

@MainActor
@Test func toolbarDelegateReusesCustomViewDimensionConstraints() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let suite = "FulmarToolbarConstraintReuse.\(UUID().uuidString)"
    let defaults = try #require(UserDefaults(suiteName: suite))
    defaults.removePersistentDomain(forName: suite)
    defer { defaults.removePersistentDomain(forName: suite) }
    let controller = HarnessWindowController(
        dataStore: .nonPersistent(),
        preferences: PreferencesStore(defaults: defaults),
        actionTarget: NSObject(),
        displayPolicy: .fixed()
    )
    let toolbar = try #require(controller.window?.toolbar)

    for rawIdentifier in ["localHarness.status", "localHarness.route"] {
        let identifier = NSToolbarItem.Identifier(rawIdentifier)
        let first = try #require(controller.toolbar(
            toolbar,
            itemForItemIdentifier: identifier,
            willBeInsertedIntoToolbar: false
        ))
        let firstView = try #require(first.view)
        let firstConstraints = Set(firstView.constraints.filter {
            $0.isActive && $0.identifier?.hasPrefix("Fulmar.Toolbar.") == true
        }.map { ObjectIdentifier($0) })
        #expect(firstConstraints.count == 2)

        let second = try #require(controller.toolbar(
            toolbar,
            itemForItemIdentifier: identifier,
            willBeInsertedIntoToolbar: false
        ))
        let secondView = try #require(second.view)
        let secondConstraints = Set(secondView.constraints.filter {
            $0.isActive && $0.identifier?.hasPrefix("Fulmar.Toolbar.") == true
        }.map { ObjectIdentifier($0) })
        #expect(secondView === firstView)
        #expect(secondConstraints == firstConstraints)
    }
}

@MainActor
@Test func mainWindowKeepsAStableTitleWhileItsSubtitleDisclosesTheSelectedBoundary() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let suite = "FulmarWindowTitle.\(UUID().uuidString)"
    let defaults = try #require(UserDefaults(suiteName: suite))
    defaults.removePersistentDomain(forName: suite)
    defer { defaults.removePersistentDomain(forName: suite) }

    let controller = HarnessWindowController(
        dataStore: WKWebsiteDataStore.nonPersistent(),
        preferences: PreferencesStore(defaults: defaults),
        actionTarget: NSObject()
    )
    let window = try #require(controller.window)
    #expect(window.title == ProductBrand.displayName)
    #expect(window.subtitle == "qwen3.8:27b-mlx · On this Mac")

    controller.updateRouteMenu(
        catalog: nil,
        selection: ModelSelection(
            route: ModelRoute(
                provider: BuiltInProviderDescriptors.deepSeekOfficial.id,
                model: ModelID("deepseek-chat")
            )
        )
    )
    #expect(window.title == ProductBrand.displayName)
    #expect(window.subtitle == "deepseek-chat · Cloud")
}

@MainActor
@Test func mainToolbarSemanticTypeScalesFitTheMinimumWindow() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    for scale in [CGFloat(1), 1.25, 1.5] {
        let suite = "FulmarToolbarTypeScale.\(scale).\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defaults.removePersistentDomain(forName: suite)
        defer { defaults.removePersistentDomain(forName: suite) }
        let typography = NativeTypographyPolicy(scale: scale)
        let controller = HarnessWindowController(
            dataStore: .nonPersistent(),
            preferences: PreferencesStore(defaults: defaults),
            actionTarget: NSObject(),
            displayPolicy: .fixed(),
            typography: typography
        )
        let window = try #require(controller.window)
        window.setFrame(NSRect(origin: .zero, size: window.minSize), display: false)
        window.orderFrontRegardless()
        window.layoutIfNeeded()
        let toolbar = try #require(window.toolbar)
        let status = try #require(
            toolbar.items.first { $0.itemIdentifier.rawValue == "localHarness.status" }?.view
        )
        let label = try #require(status.subviews.compactMap { $0 as? NSTextField }.first)
        let picker = try #require(
            toolbar.items.first { $0.itemIdentifier.rawValue == "localHarness.route" }?.view as? NSPopUpButton
        )
        status.layoutSubtreeIfNeeded()
        picker.layoutSubtreeIfNeeded()

        #expect(abs(status.frame.height - typography.toolbarControlHeight) < 0.1)
        #expect(abs(picker.frame.height - typography.toolbarControlHeight) < 0.1)
        #expect(label.font?.pointSize == picker.font?.pointSize)
        #expect(label.frame.minY >= status.bounds.minY)
        #expect(label.frame.maxY <= status.bounds.maxY)
        #expect(abs(label.frame.midY - status.bounds.midY) < 0.1)
        window.orderOut(nil)
    }
}

@MainActor
@Test(.disabled(
    if: ProcessInfo.processInfo.operatingSystemVersion.majorVersion != 26,
    "The scaled toolbar paint matrix requires an actual macOS 26 AppKit host."
))
func renderedMacOS26ToolbarSemanticTypeScalesRemainVisuallyLevel() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    for scale in [CGFloat(1), 1.25, 1.5] {
        let suite = "FulmarToolbarScaledRender.\(scale).\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defaults.removePersistentDomain(forName: suite)
        let typography = NativeTypographyPolicy(scale: scale)
        let controller = HarnessWindowController(
            dataStore: .nonPersistent(),
            preferences: PreferencesStore(defaults: defaults),
            actionTarget: NSObject(),
            displayPolicy: .fixed(),
            typography: typography
        )
        let window = try #require(controller.window)
        window.setFrame(NSRect(origin: .zero, size: window.minSize), display: false)
        window.orderFrontRegardless()
        let toolbar = try #require(window.toolbar)
        let status = try #require(
            toolbar.items.first { $0.itemIdentifier.rawValue == "localHarness.status" }?.view
        )
        let label = try #require(status.subviews.compactMap { $0 as? NSTextField }.first)
        let picker = try #require(
            toolbar.items.first { $0.itemIdentifier.rawValue == "localHarness.route" }?.view as? NSPopUpButton
        )

        for appearanceName in [NSAppearance.Name.aqua, .darkAqua] {
            window.appearance = NSAppearance(named: appearanceName)
            window.layoutIfNeeded()
            let frameView = try #require(window.contentView?.superview)
            let statusRect = status.convert(status.bounds, to: frameView)
            let pickerRect = picker.convert(picker.bounds, to: frameView)
            let paint = try renderedCommonProbeBounds(
                container: status,
                label: label,
                picker: picker
            )
            #expect(!paint.status.isEmpty)
            #expect(!paint.model.isEmpty)
            let statusCentre = statusRect.minY
                + CGFloat(paint.status.minY + paint.status.maxY) / (2 * paint.statusScaleY)
            let modelCentre = pickerRect.minY
                + CGFloat(paint.model.minY + paint.model.maxY) / (2 * paint.modelScaleY)
            #expect(abs(statusCentre - modelCentre) <= 1)
            #expect(abs(statusRect.height - typography.toolbarControlHeight) < 0.1)
            #expect(abs(pickerRect.height - typography.toolbarControlHeight) < 0.1)
            #expect(label.frame.minY >= status.bounds.minY)
            #expect(label.frame.maxY <= status.bounds.maxY)
        }

        window.orderOut(nil)
        defaults.removePersistentDomain(forName: suite)
    }
}

@MainActor
@Test(.disabled(
    if: ProcessInfo.processInfo.operatingSystemVersion.majorVersion != 26,
    "The release toolbar render matrix requires an actual macOS 26 AppKit host."
))
func renderedMacOS26ToolbarStatusAndModelTextAreVisuallyLevelAcrossReleaseMatrix() throws {

    ensureAppKitTestHostSurvivesAutomaticTermination()
    let suite = "FulmarToolbarRender.\(UUID().uuidString)"
    let defaults = try #require(UserDefaults(suiteName: suite))
    defaults.removePersistentDomain(forName: suite)
    defer { defaults.removePersistentDomain(forName: suite) }

    let controller = HarnessWindowController(
        dataStore: WKWebsiteDataStore.nonPersistent(),
        preferences: PreferencesStore(defaults: defaults),
        actionTarget: NSObject()
    )
    let window = try #require(controller.window)
    window.orderFrontRegardless()
    defer { window.orderOut(nil) }

    let toolbar = try #require(window.toolbar)
    let statusContainer = try #require(
        toolbar.items.first { $0.itemIdentifier.rawValue == "localHarness.status" }?.view
    )
    let statusLabel = try #require(statusContainer.subviews.compactMap { $0 as? NSTextField }.first)
    let routePicker = try #require(
        toolbar.items.first { $0.itemIdentifier.rawValue == "localHarness.route" }?.view as? NSPopUpButton
    )
    #expect(routePicker.cell?.lineBreakMode == .byTruncatingTail)
    #expect(routePicker.menu?.autoenablesItems == false)
    #expect(routePicker.selectedItem?.isEnabled == true)
    #expect(routePicker.selectedItem?.representedObject == nil)
    let requiredToolbarItems = Set([
        "localHarness.newSession",
        "localHarness.commandCenter",
        "localHarness.status",
        "localHarness.route",
        "localHarness.appshot",
        "localHarness.quickChat"
    ])
    let statusColors: [NSColor] = [
        .systemGreen,
        .systemOrange,
        .systemRed,
        .secondaryLabelColor
    ]
    let statusTexts = [
        "Ready · On this Mac",
        "Cooling down · 4 min minimum",
        "Stopped",
        "Provider change blocked · Cancellation unverified"
    ]

    var releaseCaseCount = 0
    for width in [CGFloat(1_280), CGFloat(900)] {
        var frame = window.frame
        frame.size = NSSize(width: width, height: width == 900 ? 600 : 840)
        window.setFrame(frame, display: false)
        for appearanceName in [NSAppearance.Name.aqua, .darkAqua] {
            window.appearance = NSAppearance(named: appearanceName)
            window.layoutIfNeeded()
            window.contentView?.layoutSubtreeIfNeeded()
            window.contentView?.displayIfNeeded()
            window.layoutIfNeeded()

            let visibleToolbarItems = Set(
                (toolbar.visibleItems ?? [])
                    .map(\.itemIdentifier.rawValue)
                    .filter { $0.hasPrefix("localHarness.") }
            )
            #expect(visibleToolbarItems == requiredToolbarItems)

            // The identical common-glyph probe depends on control geometry,
            // width, and appearance—not on the 16 status colour/string cells.
            // Render it once for this geometry while every real release cell
            // below still receives its own frame, paint, tooltip, AX, and colour
            // assertions. Keeping this outside the inner matrix prevents the
            // former 20× duplicate AppKit bitmap workload.
            let frameView = try #require(window.contentView?.superview)
            let commonStatusRect = statusContainer.convert(statusContainer.bounds, to: frameView)
            let commonRouteRect = routePicker.convert(routePicker.bounds, to: frameView)
            let commonPaint = try autoreleasepool {
                try renderedCommonProbeBounds(
                    container: statusContainer,
                    label: statusLabel,
                    picker: routePicker
                )
            }
            #expect(!commonPaint.status.isEmpty)
            #expect(!commonPaint.model.isEmpty)
            let doubledCentreDifference = abs(
                (commonPaint.status.minY + commonPaint.status.maxY)
                    - (commonPaint.model.minY + commonPaint.model.maxY)
            )
            let acceptedDoubledDifference = 2 * Int(ceil(commonPaint.scaleY))
            #expect(doubledCentreDifference <= acceptedDoubledDifference)
            let commonStatusGlobalCentre = commonStatusRect.minY
                + CGFloat(commonPaint.status.minY + commonPaint.status.maxY) / (2 * commonPaint.statusScaleY)
            let commonModelGlobalCentre = commonRouteRect.minY
                + CGFloat(commonPaint.model.minY + commonPaint.model.maxY) / (2 * commonPaint.modelScaleY)
            #expect(abs(commonStatusGlobalCentre - commonModelGlobalCentre) <= 1)

            for color in statusColors {
                for text in statusTexts {
                    releaseCaseCount += 1
                    try autoreleasepool {
                        controller.updateStatus(text, color: color)
                        window.layoutIfNeeded()

                        let statusRect = statusContainer.convert(statusContainer.bounds, to: frameView)
                        let routeRect = routePicker.convert(routePicker.bounds, to: frameView)
                        #expect(statusRect.width > 0 && statusRect.height > 0)
                        #expect(routeRect.width > 0 && routeRect.height > 0)
                        #expect(frameView.bounds.insetBy(dx: -0.5, dy: -0.5).contains(statusRect))
                        #expect(frameView.bounds.insetBy(dx: -0.5, dy: -0.5).contains(routeRect))
                        #expect(statusRect.maxX <= routeRect.minX + 0.5)
                        #expect(abs(statusLabel.frame.midY - statusContainer.bounds.midY) < 0.1)
                        #expect(abs(statusRect.midY - routeRect.midY) < 0.5)
                        #expect(abs(statusRect.height - routeRect.height) < 0.5)
                        #expect(abs(statusRect.height - 26) < 0.5)

                        #expect(statusLabel.toolTip == text)
                        #expect(statusLabel.accessibilityLabel() == "Local service status")
                        #expect(statusLabel.accessibilityValue()?.contains(text) == true)
                        #expect(routePicker.toolTip?.contains("On this Mac") == true)
                        #expect(routePicker.accessibilityLabel() == "Default model and provider")
                        #expect(routePicker.accessibilityValue() as? String == "qwen3.8:27b-mlx, On this Mac")
                        #expect(routePicker.accessibilityHelp()?.contains("data boundary") == true)
                        #expect(routePicker.menu?.items.first?.title.contains("On this Mac") == true)
                        let dotColor = try #require(
                            statusLabel.attributedStringValue.attribute(
                                .foregroundColor,
                                at: 0,
                                effectiveRange: nil
                            ) as? NSColor
                        )
                        #expect(dotColor == color)

                        // Each of the 64 real release cells still proves visible
                        // status and model glyph paint. The raw packed-byte scan
                        // includes alpha coverage without allocating NSColor per
                        // pixel, and this autorelease pool bounds AppKit caches.
                        let actualStatusPaint = try renderedStatusTextBounds(
                            container: statusContainer,
                            label: statusLabel
                        )
                        let actualModelPaint = try renderedModelTextBounds(picker: routePicker)
                        #expect(!actualStatusPaint.bounds.isEmpty)
                        #expect(!actualModelPaint.bounds.isEmpty)
                    }
                }
            }
        }
    }
    #expect(releaseCaseCount == 64)
}

@MainActor
@Test(.disabled(
    if: ProcessInfo.processInfo.operatingSystemVersion.majorVersion != 26,
    "The legacy negative render control requires an actual macOS 26 AppKit host."
))
func renderedMacOS26ToolbarMetricRejectsLegacyFullHeightStatusLabel() throws {

    ensureAppKitTestHostSurvivesAutomaticTermination()
    let picker = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 218, height: 26))
    picker.bezelStyle = .texturedRounded
    picker.controlSize = .small
    picker.addItem(withTitle: "AgjpQy")

    let label = NSTextField(labelWithString: "● AgjpQy")
    label.font = .systemFont(ofSize: 11, weight: .medium)
    label.alignment = .center
    // This reproduces the pre-fix layout: the label cell itself was stretched
    // to the toolbar control's full height instead of laying out its intrinsic
    // glyph height at the popup's optical centre.
    let legacyContainer = NSView(frame: NSRect(x: 0, y: 0, width: 148, height: 26))
    label.frame = legacyContainer.bounds
    legacyContainer.addSubview(label)

    let paint = try renderedCommonProbeBounds(
        container: legacyContainer,
        label: label,
        picker: picker
    )
    #expect(!paint.status.isEmpty)
    #expect(!paint.model.isEmpty)
    let doubledCentreDifference = abs(
        (paint.status.minY + paint.status.maxY)
            - (paint.model.minY + paint.model.maxY)
    )
    let acceptedDoubledDifference = 2 * Int(ceil(paint.scaleY))
    #expect(
        doubledCentreDifference > acceptedDoubledDifference,
        "The render metric must fail the legacy stretched-label geometry that produced the visible toolbar offset."
    )
}
