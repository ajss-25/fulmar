import AppKit

/// Keeps the visible label and the VoiceOver title relationship together for
/// native forms. AppKit does not infer this relationship when controls are
/// nested inside stack or scroll views.
@MainActor
enum AccessibleFormSupport {
    @discardableResult
    static func makeLabel(
        _ title: String,
        for control: NSView,
        font: NSFont? = nil,
        alignment: NSTextAlignment = .natural
    ) -> NSTextField {
        let label = NSTextField(labelWithString: title)
        label.font = font
        label.alignment = alignment
        bind(label: label, to: control)
        return label
    }

    static func bind(label: NSTextField, to control: NSView) {
        bind(label: label, to: accessibilityTargets(in: control))
    }

    static func bind(label: NSTextField, to controls: [NSView]) {
        let targets = controls.flatMap(accessibilityTargets(in:))
        guard !targets.isEmpty else {
            controlFallback(label: label, control: controls.first)
            return
        }
        for target in targets {
            if target.accessibilityLabel()?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty != false {
                target.setAccessibilityLabel(label.stringValue)
            }
            target.setAccessibilityTitleUIElement(label)
        }
        label.setAccessibilityServesAsTitleForUIElements(targets)
    }

    private static func controlFallback(label: NSTextField, control: NSView?) {
        guard let control else { return }
        control.setAccessibilityLabel(label.stringValue)
        control.setAccessibilityTitleUIElement(label)
        label.setAccessibilityServesAsTitleForUIElements([control])
    }

    private static func accessibilityTargets(in view: NSView) -> [NSView] {
        if let scroll = view as? NSScrollView, let document = scroll.documentView {
            return accessibilityTargets(in: document)
        }
        if let stack = view as? NSStackView {
            let targets = stack.arrangedSubviews.flatMap(accessibilityTargets(in:))
            return targets.isEmpty ? [stack] : targets
        }
        if view is NSTextView || view is NSPopUpButton || view is NSDatePicker {
            return [view]
        }
        if let field = view as? NSTextField, field.isEditable || field.isSelectable {
            return [field]
        }
        if view is NSButton { return [view] }
        let nested = view.subviews.flatMap(accessibilityTargets(in:))
        return nested.isEmpty ? [] : nested
    }
}

@MainActor
struct ConversationExportChoiceAccessory {
    let view: NSStackView
    let formatPicker: NSPopUpButton
    let privacyPicker: NSPopUpButton
    let formatLabel: NSTextField
    let privacyLabel: NSTextField

    init() {
        formatPicker = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 360, height: 26))
        formatPicker.addItems(withTitles: ["Markdown (.md)", "JSON (.json)"])
        privacyPicker = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 360, height: 26))
        privacyPicker.addItems(withTitles: [
            "Recommended — redact detected secrets",
            "Structure only — redact all message text",
            "Full transcript — no automatic redaction"
        ])
        formatLabel = AccessibleFormSupport.makeLabel("Export format", for: formatPicker)
        privacyLabel = AccessibleFormSupport.makeLabel("Export privacy", for: privacyPicker)
        formatPicker.setAccessibilityHelp("Choose the file format for the exported conversation.")
        privacyPicker.setAccessibilityHelp("Choose how private conversation content is redacted before export.")

        view = NSStackView(views: [formatLabel, formatPicker, privacyLabel, privacyPicker])
        view.orientation = .vertical
        view.alignment = .leading
        view.spacing = 5
    }
}

@MainActor
enum AgentQuestionAccessibility {
    static func configure(
        question: String,
        title: NSTextField,
        optionButtons: [NSButton],
        optionPicker: NSPopUpButton?,
        customField: NSTextField
    ) {
        let context = concise(question)
        var titledControls: [NSView] = optionButtons
        if let optionPicker {
            optionPicker.setAccessibilityLabel("Answer choice for: \(context)")
            optionPicker.setAccessibilityHelp("Choose one answer, or enter a custom answer below.")
            titledControls.append(optionPicker)
        }
        for button in optionButtons {
            button.setAccessibilityLabel("\(button.title), answer to: \(context)")
            button.setAccessibilityHelp("Select this answer for the agent question.")
        }
        customField.setAccessibilityLabel(
            optionPicker == nil && optionButtons.isEmpty
                ? "Answer to: \(context)"
                : "Custom answer to: \(context)"
        )
        customField.setAccessibilityHelp(
            optionPicker == nil && optionButtons.isEmpty
                ? "Enter your answer to the agent question."
                : "Entering text overrides a single selected choice."
        )
        titledControls.append(customField)
        AccessibleFormSupport.bind(label: title, to: titledControls)
    }

    private static func concise(_ value: String) -> String {
        let normalized = value
            .components(separatedBy: .whitespacesAndNewlines)
            .filter { !$0.isEmpty }
            .joined(separator: " ")
        guard normalized.count > 180 else { return normalized }
        return String(normalized.prefix(179)) + "…"
    }
}

@MainActor
enum MCPReviewAccessibility {
    static func configure(review: NSTextView, title: NSTextField) {
        review.setAccessibilityLabel("Exact MCP server configuration review")
        review.setAccessibilityHelp(
            "Review the exact executable, arguments, project, provider boundaries, disclosures, credentials, and limits before approving this MCP server."
        )
        review.setAccessibilityTitleUIElement(title)
        title.setAccessibilityServesAsTitleForUIElements([review])
    }
}
