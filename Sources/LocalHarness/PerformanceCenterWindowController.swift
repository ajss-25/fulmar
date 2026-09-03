import AppKit

/// A passive presentation surface. It has no service/client reference, timers,
/// notifications, or refresh action; all data must be supplied by its owner.
final class PerformanceCenterWindowController: NSWindowController {
    var onClearHistory: (() -> Void)?
    private var snapshot: PerformanceCenterSnapshot
    private(set) var historyClearPending = false
    private var clearDispatching = false

    init(snapshot: PerformanceCenterSnapshot) {
        self.snapshot = snapshot
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 920, height: 700),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Performance Center"
        window.subtitle = "Private runtime health and generation speed"
        window.minSize = NSSize(width: 760, height: 560)
        window.isReleasedWhenClosed = false
        window.setFrameAutosaveName("LocalHarness.PerformanceCenter")
        super.init(window: window)
        render()
        if !window.setFrameUsingName("LocalHarness.PerformanceCenter") { window.center() }
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    /// Replaces the complete presentation state without fetching anything.
    func update(snapshot: PerformanceCenterSnapshot) {
        self.snapshot = snapshot
        render()
    }

    func setHistoryClearPending(_ pending: Bool) {
        guard historyClearPending != pending else { return }
        historyClearPending = pending
        render()
    }

    private func render() {
        guard let window else { return }
        let previousScrollOrigin = Self.performanceScrollView(in: window.contentView)?.contentView.bounds.origin
        let previousResponderIdentifier = (window.firstResponder as? NSView)?.identifier

        window.contentViewController = buildContent(snapshot: snapshot)
        window.contentView?.layoutSubtreeIfNeeded()

        if let previousScrollOrigin,
           let scroll = Self.performanceScrollView(in: window.contentView) {
            let clip = scroll.contentView
            let proposed = NSRect(origin: previousScrollOrigin, size: clip.bounds.size)
            clip.setBoundsOrigin(clip.constrainBoundsRect(proposed).origin)
            scroll.reflectScrolledClipView(clip)
        }
        if let previousResponderIdentifier,
           let restored = Self.view(with: previousResponderIdentifier, in: window.contentView),
           !restored.isHidden {
            window.makeFirstResponder(restored)
        }
    }

    private static func performanceScrollView(in view: NSView?) -> NSScrollView? {
        guard let view else { return nil }
        if let scroll = view as? NSScrollView { return scroll }
        return view.subviews.lazy.compactMap { performanceScrollView(in: $0) }.first
    }

    private static func view(with identifier: NSUserInterfaceItemIdentifier, in view: NSView?) -> NSView? {
        guard let view else { return nil }
        if view.identifier == identifier { return view }
        return view.subviews.lazy.compactMap { self.view(with: identifier, in: $0) }.first
    }

    private func buildContent(snapshot: PerformanceCenterSnapshot) -> NSViewController {
        let controller = NSViewController()
        let root = AppearanceAwareLayerView()
        root.semanticBackgroundColor = .windowBackgroundColor

        let scroll = NSScrollView()
        scroll.drawsBackground = false
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        scroll.setAccessibilityLabel("Performance details")
        scroll.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(scroll)

        let document = NSView()
        document.translatesAutoresizingMaskIntoConstraints = false
        scroll.documentView = document

        let content = NSStackView()
        content.orientation = .vertical
        content.alignment = .leading
        content.spacing = 18
        content.translatesAutoresizingMaskIntoConstraints = false
        document.addSubview(content)

        content.addArrangedSubview(makeHeader(snapshot))
        content.addArrangedSubview(makeSectionTitle("This Mac"))
        content.addArrangedSubview(makeHostCards(snapshot.host))
        content.addArrangedSubview(makeRecommendation(snapshot.recommendation))
        if !snapshot.recommendation.assessments.isEmpty {
            content.addArrangedSubview(makeProfileCards(snapshot.recommendation))
        }
        if snapshot.selection?.route.provider == BuiltInProviderDescriptors.ollama.id {
            content.addArrangedSubview(makeSectionTitle("Local model runtime"))
            content.addArrangedSubview(makeRuntimeCard(snapshot.ollama))
        }
        content.addArrangedSubview(makeTelemetrySectionHeader())
        content.addArrangedSubview(makeTelemetryCard(snapshot.telemetry))
        content.addArrangedSubview(makePrivacyFooter(snapshot.capturedAt))

        for arranged in content.arrangedSubviews {
            arranged.translatesAutoresizingMaskIntoConstraints = false
            arranged.widthAnchor.constraint(equalTo: content.widthAnchor).isActive = true
        }

        NSLayoutConstraint.activate([
            scroll.topAnchor.constraint(equalTo: root.topAnchor),
            scroll.leadingAnchor.constraint(equalTo: root.leadingAnchor),
            scroll.trailingAnchor.constraint(equalTo: root.trailingAnchor),
            scroll.bottomAnchor.constraint(equalTo: root.bottomAnchor),

            document.topAnchor.constraint(equalTo: scroll.contentView.topAnchor),
            document.leadingAnchor.constraint(equalTo: scroll.contentView.leadingAnchor),
            document.trailingAnchor.constraint(equalTo: scroll.contentView.trailingAnchor),
            document.widthAnchor.constraint(equalTo: scroll.contentView.widthAnchor),

            content.topAnchor.constraint(equalTo: document.topAnchor, constant: 24),
            content.leadingAnchor.constraint(equalTo: document.leadingAnchor, constant: 28),
            content.trailingAnchor.constraint(equalTo: document.trailingAnchor, constant: -28),
            content.bottomAnchor.constraint(equalTo: document.bottomAnchor, constant: -24)
        ])

        controller.view = root
        return controller
    }

    private func makeHeader(_ snapshot: PerformanceCenterSnapshot) -> NSView {
        let title = label("Performance Center", size: 26, weight: .bold)
        let subtitle = label(
            headerSubtitle(snapshot),
            size: 13,
            color: .secondaryLabelColor
        )
        let titleStack = NSStackView(views: [title, subtitle])
        titleStack.orientation = .vertical
        titleStack.alignment = .leading
        titleStack.spacing = 4

        let (state, stateColor) = headerState(snapshot)
        let pillLabel = label("  \(state)  ", size: 12, weight: .semibold, color: stateColor)
        pillLabel.alignment = .center
        pillLabel.translatesAutoresizingMaskIntoConstraints = false
        let pill = AppearanceAwareLayerView()
        pill.semanticBackgroundColor = stateColor
        pill.backgroundAlpha = 0.12
        pill.layer?.cornerRadius = 11
        pill.addSubview(pillLabel)
        pill.heightAnchor.constraint(equalToConstant: 24).isActive = true
        NSLayoutConstraint.activate([
            pillLabel.leadingAnchor.constraint(equalTo: pill.leadingAnchor, constant: 6),
            pillLabel.trailingAnchor.constraint(equalTo: pill.trailingAnchor, constant: -6),
            pillLabel.centerYAnchor.constraint(equalTo: pill.centerYAnchor)
        ])

        let spacer = NSView()
        let row = NSStackView(views: [titleStack, spacer, pill])
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 12
        return row
    }

    private func makeHostCards(_ host: HostPerformanceSnapshot) -> NSView {
        let memory = String(format: "%.0f GB", host.physicalMemoryGiB)
        let power = host.lowPowerModeEnabled ? "Low Power" : "Full Power"
        let cards = [
            metricCard(title: "Unified memory", value: memory, caption: host.processorArchitecture.displayName),
            metricCard(title: "Thermals", value: host.thermalCondition.displayName, caption: thermalCaption(host.thermalCondition)),
            metricCard(title: "Power", value: power, caption: host.lowPowerModeEnabled ? "Performance is intentionally limited" : "No power restriction detected"),
            metricCard(title: "Processors", value: "\(host.activeProcessorCount)", caption: "of \(host.logicalProcessorCount) logical cores active")
        ]
        let row = NSStackView(views: cards)
        row.orientation = .horizontal
        row.distribution = .fillEqually
        row.spacing = 12
        return row
    }

    private func makeRecommendation(_ recommendation: AdaptivePerformanceRecommendation) -> NSView {
        let box = cardBox(background: NSColor.controlAccentColor.withAlphaComponent(0.09))
        let profileName = recommendation.recommendedProfile?.displayName ?? "Not applicable"
        let badge = label(profileName, size: 20, weight: .bold, color: .controlAccentColor)
        badge.setAccessibilityLabel(recommendation.recommendedProfile.map {
            "Recommended profile: \($0.displayName)"
        } ?? "Local performance profile not applicable")
        let heading = label(
            recommendation.recommendedProfile == nil ? "Route-aware guidance" : "Recommended now",
            size: 11,
            weight: .semibold,
            color: .secondaryLabelColor
        )
        let badgeStack = NSStackView(views: [heading, badge])
        badgeStack.orientation = .vertical
        badgeStack.alignment = .leading
        badgeStack.spacing = 2
        badgeStack.widthAnchor.constraint(equalToConstant: 150).isActive = true

        let safeReasons = recommendation.reasons.prefix(3).map {
            AuxiliaryDisplayPolicy.singleLine($0, maximumCharacters: 180, fallback: "")
        }.filter { !$0.isEmpty }
        let reasonText = safeReasons.isEmpty
            ? "Performance guidance is not available for this snapshot."
            : safeReasons.map { "• \($0)" }.joined(separator: "\n")
        let reasons = wrappingLabel(reasonText, size: 12.5, color: .labelColor)
        let row = NSStackView(views: [badgeStack, reasons])
        row.orientation = .horizontal
        row.alignment = .top
        row.spacing = 18
        pin(row, inside: box, inset: 16)
        return box
    }

    private func headerSubtitle(_ snapshot: PerformanceCenterSnapshot) -> String {
        guard let selection = snapshot.selection else {
            return "The current provider route is unavailable, so local performance guidance is withheld."
        }
        guard selection.route.provider == BuiltInProviderDescriptors.ollama.id else {
            return "Cloud model limits are provider-managed and independent of this Mac's local thermal state."
        }
        if selection.isLocalCompatibilityRoute {
            return "This alternate local model uses fixed Compatibility limits and route-specific thermal protection."
        }
        guard snapshot.host.physicalMemoryBytes >= QualifiedLocalModelHostAdmissionPolicy.minimumPhysicalMemoryBytes else {
            return "This Mac does not meet the memory floor for Fulmar's release-qualified Qwen profiles."
        }
        return "Tune \(ProductBrand.displayName) from measured local device health—not guesswork."
    }

    private func headerState(_ snapshot: PerformanceCenterSnapshot) -> (String, NSColor) {
        guard let selection = snapshot.selection else { return ("Route unavailable", .systemOrange) }
        guard selection.route.provider == BuiltInProviderDescriptors.ollama.id else {
            return ("Cloud route", .systemBlue)
        }
        if selection.isLocalCompatibilityRoute { return ("Compatibility", .systemBlue) }
        guard snapshot.host.physicalMemoryBytes >= QualifiedLocalModelHostAdmissionPolicy.minimumPhysicalMemoryBytes else {
            return ("Host blocked", .systemOrange)
        }
        return snapshot.host.thermalCondition == .serious || snapshot.host.thermalCondition == .critical
            ? ("Needs headroom", .systemOrange)
            : ("Ready", .systemGreen)
    }

    private func makeProfileCards(_ recommendation: AdaptivePerformanceRecommendation) -> NSView {
        let cards = recommendation.assessments.prefix(4).map { assessment -> NSView in
            let background = assessment.isRecommended
                ? NSColor.controlAccentColor.withAlphaComponent(0.08)
                : NSColor.controlBackgroundColor
            let box = cardBox(background: background)
            let title = label(
                assessment.profile.displayName + (assessment.isRecommended ? "  ✓" : ""),
                size: 15,
                weight: .semibold,
                color: assessment.isRecommended ? .controlAccentColor : .labelColor
            )
            let summary = wrappingLabel(
                AuxiliaryDisplayPolicy.singleLine(
                    assessment.summary,
                    maximumCharacters: 140,
                    fallback: "Profile details unavailable"
                ),
                size: 11.5,
                color: .secondaryLabelColor
            )
            let limits = label(
                "Up to \(formatTokens(assessment.settings.maxOutputTokens)) output",
                size: 10.5,
                color: .tertiaryLabelColor
            )
            let stack = NSStackView(views: [title, summary, limits])
            stack.orientation = .vertical
            stack.alignment = .leading
            stack.spacing = 6
            pin(stack, inside: box, inset: 14)
            return box
        }
        let presentedCards: [NSView] = cards.isEmpty
            ? [wrappingLabel(
                "No performance profiles are available for this snapshot.",
                size: 12,
                color: .secondaryLabelColor
            )]
            : cards
        let row = NSStackView(views: presentedCards)
        row.orientation = .horizontal
        row.distribution = .fillEqually
        row.spacing = 12
        return row
    }

    private func makeRuntimeCard(_ runtime: OllamaRuntimeSnapshot) -> NSView {
        let box = cardBox()
        let dotColor: NSColor = runtime.availability == .online ? .systemGreen : .secondaryLabelColor
        let status = label("●  \(runtime.availability.displayName)", size: 13, weight: .semibold, color: dotColor)
        let boundedRunning = Array(runtime.runningModels.prefix(1_000))
        let boundedInstalled = Array(runtime.installedModels.prefix(1_000))
        let modelMemory = boundedRunning.reduce(Int64(0)) { partial, model in
            let value = max(0, model.sizeVRAMBytes)
            let (sum, overflow) = partial.addingReportingOverflow(value)
            return overflow ? Int64.max : sum
        }
        let counts = label(
            "\(countLabel(boundedInstalled.count, wasTruncated: runtime.installedModels.count > boundedInstalled.count)) installed  ·  \(countLabel(boundedRunning.count, wasTruncated: runtime.runningModels.count > boundedRunning.count)) loaded  ·  \(formatBytes(modelMemory)) model memory",
            size: 12,
            color: .secondaryLabelColor
        )
        let heading = NSStackView(views: [status, NSView(), counts])
        heading.orientation = .horizontal
        heading.alignment = .centerY
        heading.spacing = 10

        let loadedDescription: String
        if boundedRunning.isEmpty {
            loadedDescription = runtime.availability == .online
                ? "No model is loaded. Memory will stay free until a local task needs one."
                : (runtime.issue?.displayMessage ?? "No local Ollama runtime was detected.")
        } else {
            loadedDescription = boundedRunning.prefix(50).map { model in
                "\(Self.displayModelName(model.name)) — \(formatBytes(model.sizeVRAMBytes)) · \(formatTokens(model.contextLength)) context"
            }.joined(separator: "\n")
        }
        let models = wrappingLabel(loadedDescription, size: 12, color: .labelColor)
        let stack = NSStackView(views: [heading, divider(), models])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 10
        pin(stack, inside: box, inset: 15)
        return box
    }

    private func makeTelemetryCard(_ records: [GenerationTelemetryRecord]) -> NSView {
        let box = cardBox()
        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 8

        if records.isEmpty {
            stack.addArrangedSubview(wrappingLabel(
                "No completed generations yet. Timing appears here after you use a model.",
                size: 12.5,
                color: .secondaryLabelColor
            ))
        } else {
            let header = telemetryRow(["Model", "TTFT", "Speed", "Elapsed", "Result"], header: true)
            stack.addArrangedSubview(header)
            stack.addArrangedSubview(divider())
            for record in records.prefix(12) {
                let model = Self.displayModelName(record.route?.model.rawValue)
                let ttft = record.timeToFirstTokenSeconds.map(formatDuration) ?? "—"
                let rate = record.outputTokensPerSecond.flatMap {
                    $0.isFinite && $0 >= 0 ? String(format: "%.1f tok/s", $0) : nil
                } ?? "—"
                let elapsed = formatDuration(record.elapsedSeconds)
                let result = record.outcome.rawValue.capitalized
                stack.addArrangedSubview(telemetryRow([model, ttft, rate, elapsed, result], header: false))
            }
        }
        pin(stack, inside: box, inset: 15)
        return box
    }

    private func telemetryRow(_ values: [String], header: Bool) -> NSView {
        let widths: [CGFloat] = [0, 72, 92, 72, 78]
        let fields = values.enumerated().map { index, value -> NSView in
            let field = label(
                value,
                size: header ? 10.5 : 11.5,
                weight: header ? .semibold : .regular,
                color: header ? .secondaryLabelColor : .labelColor
            )
            field.lineBreakMode = .byTruncatingMiddle
            field.toolTip = value
            if widths[index] > 0 { field.widthAnchor.constraint(equalToConstant: widths[index]).isActive = true }
            return field
        }
        let row = NSStackView(views: fields)
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 12
        row.setAccessibilityLabel(values.joined(separator: ", "))
        return row
    }

    private func makePrivacyFooter(_ capturedAt: Date) -> NSView {
        let icon = label("🔒", size: 13)
        let date = Self.timestampFormatter.string(from: capturedAt)
        let copy = wrappingLabel(
            "Performance history stays on this Mac for at most 24 hours and 100 runs. It contains coarse timing, token counts, outcomes, and route labels—never prompts, responses, errors, session IDs, files, or tool data. Snapshot captured \(date).",
            size: 11,
            color: .secondaryLabelColor
        )
        let row = NSStackView(views: [icon, copy])
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 8
        return row
    }

    private func makeSectionTitle(_ title: String) -> NSView {
        label(title, size: 15, weight: .semibold)
    }

    private func makeTelemetrySectionHeader() -> NSView {
        let title = makeSectionTitle("Recent generation performance")
        let clear = NSButton(
            title: historyClearPending ? "Clearing…" : "Clear Performance History",
            target: self,
            action: #selector(clearHistory(_:))
        )
        clear.bezelStyle = .rounded
        clear.controlSize = .small
        clear.isEnabled = !historyClearPending
        clear.identifier = NSUserInterfaceItemIdentifier("Fulmar.PerformanceCenter.ClearHistory")
        clear.setAccessibilityLabel("Clear private performance history")
        let row = NSStackView(views: [title, NSView(), clear])
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 10
        return row
    }

    @objc private func clearHistory(_ sender: Any?) {
        guard !historyClearPending, !clearDispatching else { return }
        clearDispatching = true
        onClearHistory?()
        clearDispatching = false
    }

    private func metricCard(title: String, value: String, caption: String) -> NSView {
        let box = cardBox()
        let titleLabel = label(title.uppercased(), size: 9.5, weight: .semibold, color: .secondaryLabelColor)
        let valueLabel = label(value, size: 18, weight: .semibold)
        let captionLabel = wrappingLabel(caption, size: 10.5, color: .secondaryLabelColor)
        let stack = NSStackView(views: [titleLabel, valueLabel, captionLabel])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 5
        pin(stack, inside: box, inset: 13)
        return box
    }

    private func cardBox(background: NSColor = .controlBackgroundColor) -> NSBox {
        let box = AppearanceAwareLayerBox()
        box.boxType = .custom
        box.cornerRadius = 11
        box.fillColor = background
        box.contentViewMargins = .zero
        box.wantsLayer = true
        box.semanticBorderColor = .separatorColor
        box.borderAlpha = 0.35
        box.refreshSemanticColors()
        box.layer?.borderWidth = 0.5
        return box
    }

    private func pin(_ view: NSView, inside box: NSBox, inset: CGFloat) {
        guard let container = box.contentView else { return }
        view.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(view)
        NSLayoutConstraint.activate([
            view.topAnchor.constraint(equalTo: container.topAnchor, constant: inset),
            view.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: inset),
            view.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -inset),
            view.bottomAnchor.constraint(equalTo: container.bottomAnchor, constant: -inset)
        ])
    }

    private func divider() -> NSView {
        let view = AppearanceAwareLayerView()
        view.semanticBackgroundColor = .separatorColor
        view.heightAnchor.constraint(equalToConstant: 1).isActive = true
        return view
    }

    private func label(
        _ text: String,
        size: CGFloat,
        weight: NSFont.Weight = .regular,
        color: NSColor = .labelColor
    ) -> NSTextField {
        let field = NSTextField(labelWithString: text)
        field.font = .systemFont(ofSize: size, weight: weight)
        field.textColor = color
        return field
    }

    private func wrappingLabel(_ text: String, size: CGFloat, color: NSColor) -> NSTextField {
        let field = NSTextField(wrappingLabelWithString: text)
        field.font = .systemFont(ofSize: size)
        field.textColor = color
        field.maximumNumberOfLines = 0
        return field
    }

    private func thermalCaption(_ condition: HostThermalCondition) -> String {
        switch condition {
        case .nominal: return "Full sustained performance"
        case .fair: return "Some thermal headroom remains"
        case .serious: return "Prefer shorter local work"
        case .critical: return "Pause heavy local generations"
        case .unknown: return "Thermal reading unavailable"
        }
    }

    private func formatBytes(_ value: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: max(0, value), countStyle: .memory)
    }

    private func formatTokens(_ value: Int) -> String {
        let bounded = max(0, value)
        return bounded >= 1_000 ? String(format: "%.0fK", Double(bounded) / 1_024) : "\(bounded)"
    }

    private func formatDuration(_ interval: TimeInterval) -> String {
        guard interval.isFinite, interval >= 0 else { return "—" }
        return interval < 10 ? String(format: "%.1fs", interval) : String(format: "%.0fs", interval)
    }

    static func displayModelName(_ value: String?) -> String {
        guard let value else { return "Unknown model" }
        return AuxiliaryDisplayPolicy.singleLine(value, maximumCharacters: 80, fallback: "Unknown model")
    }

    private func countLabel(_ count: Int, wasTruncated: Bool) -> String {
        wasTruncated ? "\(max(0, count))+" : "\(max(0, count))"
    }

    private static let timestampFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .none
        formatter.timeStyle = .short
        return formatter
    }()
}
