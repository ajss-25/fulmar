import AppKit
import Vision

struct AppshotReviewResult {
    let image: NSImage
    let accessibleText: String?
}

final class AppshotTextRecognitionCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var cancellation: (() -> Void)?

    init(_ cancellation: @escaping () -> Void = {}) {
        self.cancellation = cancellation
    }

    func cancel() {
        lock.lock()
        let cancellation = cancellation
        self.cancellation = nil
        lock.unlock()
        cancellation?()
    }
}

private final class AppshotTextRecognitionCompletionGate: @unchecked Sendable {
    private let lock = NSLock()
    private var completion: (@MainActor (Result<String, Error>) -> Void)?

    init(completion: @escaping @MainActor (Result<String, Error>) -> Void) {
        self.completion = completion
    }

    func finish(_ result: Result<String, Error>) {
        lock.lock()
        let completion = completion
        self.completion = nil
        lock.unlock()
        guard let completion else { return }
        DispatchQueue.main.async {
            completion(result)
        }
    }
}

struct AppshotTextRecognitionOperations {
    let recognize: @MainActor (
        _ image: CGImage,
        _ completion: @escaping @MainActor (Result<String, Error>) -> Void
    ) -> AppshotTextRecognitionCancellation

    static let live = AppshotTextRecognitionOperations { image, completion in
        let gate = AppshotTextRecognitionCompletionGate(completion: completion)
        let request = VNRecognizeTextRequest { request, error in
            if let error {
                gate.finish(.failure(error))
                return
            }
            let text = (request.results as? [VNRecognizedTextObservation])?
                .compactMap { $0.topCandidates(1).first?.string }
                .joined(separator: "\n") ?? ""
            gate.finish(.success(text))
        }
        request.recognitionLevel = .accurate
        request.usesLanguageCorrection = true
        let cancellation = AppshotTextRecognitionCancellation {
            request.cancel()
        }
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                try VNImageRequestHandler(cgImage: image).perform([request])
            } catch {
                gate.finish(.failure(error))
            }
        }
        return cancellation
    }
}

struct AppshotReviewModalInteractions {
    let accept: @MainActor () -> Void
    let cancel: @MainActor () -> Void

    static let live = AppshotReviewModalInteractions(
        accept: { NSApp.stopModal() },
        cancel: { NSApp.abortModal() }
    )
}

enum AppshotAccessibleTextPolicy {
    static let maximumCharacterCount = 16_000

    static func normalized(_ text: String?) -> String? {
        guard let text else { return nil }
        let lineNormalized = text
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
        let filtered = lineNormalized.filter { character in
            character == "\n" || character == "\t" || !character.unicodeScalars.contains {
                CharacterSet.controlCharacters.contains($0)
            }
        }
        let trimmed = filtered.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        return String(trimmed.prefix(maximumCharacterCount))
    }
}

final class AppshotReviewWindowController: NSWindowController, NSWindowDelegate {
    private let canvas: AppshotCanvasView
    private let includeText = NSButton(checkboxWithTitle: "Include recognized text for accessibility", target: nil, action: nil)
    private let status = NSTextField(labelWithString: "Drag over the image to select an area.")
    private let recognitionOperations: AppshotTextRecognitionOperations
    private let modalInteractions: AppshotReviewModalInteractions
    private var recognizedText: String?
    private var recognitionGeneration: UInt64 = 0
    private var activeRecognition: AppshotTextRecognitionCancellation?
    private var isRunningModal = false
    private(set) var result: AppshotReviewResult?

    init(
        image: NSImage,
        recognitionOperations: AppshotTextRecognitionOperations = .live,
        modalInteractions: AppshotReviewModalInteractions = .live
    ) {
        canvas = AppshotCanvasView(image: image)
        self.recognitionOperations = recognitionOperations
        self.modalInteractions = modalInteractions
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 900, height: 680),
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Review Appshot"
        window.subtitle = "Nothing is attached until you choose Add to Chat"
        window.minSize = NSSize(width: 680, height: 520)
        super.init(window: window)
        window.delegate = self
        window.isReleasedWhenClosed = false
        window.contentViewController = buildContent()
        window.center()
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func runModal() -> AppshotReviewResult? {
        guard let window else { return nil }
        result = nil
        isRunningModal = true
        NSApp.runModal(for: window)
        isRunningModal = false
        window.orderOut(nil)
        return result
    }

    func windowWillClose(_ notification: Notification) {
        result = nil
        invalidateRecognitionAndText()
        guard isRunningModal else { return }
        modalInteractions.cancel()
    }

    private func buildContent() -> NSViewController {
        let vc = NSViewController(); let root = NSView()
        canvas.translatesAutoresizingMaskIntoConstraints = false; root.addSubview(canvas)
        let crop = NSButton(title: "Crop to Selection", target: self, action: #selector(crop(_:)))
        let redact = NSButton(title: "Redact Selection", target: self, action: #selector(redact(_:)))
        let reset = NSButton(title: "Reset", target: self, action: #selector(reset(_:)))
        let recognize = NSButton(title: "Recognize Text", target: self, action: #selector(recognizeText(_:)))
        includeText.isHidden = true
        let imageTools = NSStackView(views: [crop, redact, reset, recognize, NSView()])
        imageTools.orientation = .horizontal
        imageTools.spacing = 8
        let accessibilityTools = NSStackView(views: [includeText, NSView()])
        accessibilityTools.orientation = .horizontal
        accessibilityTools.spacing = 8
        let tools = NSStackView(views: [imageTools, accessibilityTools])
        tools.orientation = .vertical
        tools.alignment = .width
        tools.spacing = 8
        tools.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(tools)
        status.textColor = .secondaryLabelColor; status.translatesAutoresizingMaskIntoConstraints = false; root.addSubview(status)
        let cancel = NSButton(title: "Cancel", target: self, action: #selector(cancel(_:)))
        cancel.keyEquivalent = "\u{1b}"
        let attach = NSButton(title: "Add to Chat", target: self, action: #selector(attach(_:))); attach.keyEquivalent = "\r"; attach.bezelStyle = .rounded
        let actions = NSStackView(views: [NSView(), cancel, attach]); actions.orientation = .horizontal; actions.spacing = 8; actions.translatesAutoresizingMaskIntoConstraints = false; root.addSubview(actions)
        NSLayoutConstraint.activate([
            canvas.topAnchor.constraint(equalTo: root.topAnchor, constant: 18), canvas.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 18), canvas.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -18),
            tools.topAnchor.constraint(equalTo: canvas.bottomAnchor, constant: 12), tools.leadingAnchor.constraint(equalTo: canvas.leadingAnchor), tools.trailingAnchor.constraint(equalTo: canvas.trailingAnchor),
            status.topAnchor.constraint(equalTo: tools.bottomAnchor, constant: 8), status.leadingAnchor.constraint(equalTo: canvas.leadingAnchor), status.trailingAnchor.constraint(equalTo: canvas.trailingAnchor),
            actions.topAnchor.constraint(equalTo: status.bottomAnchor, constant: 12), actions.leadingAnchor.constraint(equalTo: canvas.leadingAnchor), actions.trailingAnchor.constraint(equalTo: canvas.trailingAnchor), actions.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -16)
        ])
        vc.view = root; return vc
    }

    @objc private func crop(_ sender: Any?) {
        if canvas.cropToSelection() { invalidateRecognitionAndText(); status.stringValue = "Cropped. Select another area to redact or crop again." }
        else { status.stringValue = "Drag over the image first to choose a crop area." }
    }
    @objc private func redact(_ sender: Any?) {
        if canvas.redactSelection() { invalidateRecognitionAndText(); status.stringValue = "Selection permanently redacted in this appshot." }
        else { status.stringValue = "Drag over the image first to choose an area to redact." }
    }
    @objc private func reset(_ sender: Any?) { canvas.reset(); invalidateRecognitionAndText(); status.stringValue = "Reset to the original capture." }
    @objc private func recognizeText(_ sender: Any?) {
        invalidateRecognitionAndText()
        guard let cgImage = canvas.currentCGImage else {
            status.stringValue = "Text recognition could not read this appshot. Try another capture."
            AccessibilityAnnouncement.post(status.stringValue, priority: .high, element: status)
            return
        }
        recognitionGeneration &+= 1
        let expectedGeneration = recognitionGeneration
        status.stringValue = "Recognizing text on this Mac…"
        activeRecognition = recognitionOperations.recognize(cgImage) { [weak self] result in
            guard let self, self.recognitionGeneration == expectedGeneration else { return }
            self.activeRecognition = nil
            switch result {
            case .success(let rawText):
                let text = AppshotAccessibleTextPolicy.normalized(rawText)
                self.recognizedText = text
                self.includeText.isHidden = text == nil
                self.includeText.state = text == nil ? .off : .on
                self.status.stringValue = text.map {
                    "Recognized \($0.count) characters locally. Review the checkbox before attaching."
                } ?? "No readable text found."
                AccessibilityAnnouncement.post(self.status.stringValue, element: self.status)
            case .failure:
                self.recognizedText = nil
                self.includeText.isHidden = true
                self.includeText.state = .off
                self.status.stringValue = "Text recognition could not be completed on this Mac. Try again."
                AccessibilityAnnouncement.post(self.status.stringValue, priority: .high, element: self.status)
            }
        }
    }
    @objc private func cancel(_ sender: Any?) {
        result = nil
        invalidateRecognitionAndText()
        modalInteractions.cancel()
    }
    @objc private func attach(_ sender: Any?) {
        let accessibleText = includeText.state == .on ? recognizedText : nil
        result = AppshotReviewResult(image: canvas.image, accessibleText: accessibleText)
        invalidateRecognitionAndText()
        modalInteractions.accept()
    }

    private func invalidateRecognitionAndText() {
        recognitionGeneration &+= 1
        activeRecognition?.cancel()
        activeRecognition = nil
        recognizedText = nil
        includeText.isHidden = true
        includeText.state = .off
    }
}

final class AppshotCanvasView: NSView {
    private let original: NSImage
    private(set) var image: NSImage
    private var dragStart: NSPoint?
    private(set) var selection: NSRect = .zero

    init(image: NSImage) {
        original = image.copy() as? NSImage ?? image
        self.image = image.copy() as? NSImage ?? image
        super.init(frame: .zero)
        wantsLayer = true
        layer?.backgroundColor = NSColor.black.cgColor
        setAccessibilityLabel("Appshot preview and crop area")
        setAccessibilityRole(.image)
        setAccessibilityHelp("Press Space to create a centred selection. Use arrow keys to move it and Option-arrow keys to resize it. Delete clears the selection.")
    }
    @available(*, unavailable) required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    override var intrinsicContentSize: NSSize { NSSize(width: 760, height: 500) }
    override var acceptsFirstResponder: Bool { true }
    var currentCGImage: CGImage? { image.cgImage(forProposedRect: nil, context: nil, hints: nil) }

    override func accessibilityValue() -> Any? {
        selection.isEmpty
            ? "No crop or redaction area selected"
            : "Selected area x \(Int(selection.minX)), y \(Int(selection.minY)), width \(Int(selection.width)), height \(Int(selection.height))"
    }

    override func accessibilityPerformPress() -> Bool {
        setDefaultKeyboardSelection()
        return true
    }

    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        image.draw(in: imageDrawRect(), from: .zero, operation: .sourceOver, fraction: 1, respectFlipped: false, hints: [.interpolation: NSImageInterpolation.high])
        if !selection.isEmpty {
            NSColor.controlAccentColor.withAlphaComponent(0.18).setFill(); selection.fill()
            NSColor.controlAccentColor.setStroke(); let path = NSBezierPath(rect: selection); path.lineWidth = 2; path.stroke()
        }
    }
    override func mouseDown(with event: NSEvent) { dragStart = convert(event.locationInWindow, from: nil); selection = .zero; selectionDidChange() }
    override func mouseDragged(with event: NSEvent) { guard let start = dragStart else { return }; let end = convert(event.locationInWindow, from: nil); selection = NSRect(x: min(start.x, end.x), y: min(start.y, end.y), width: abs(end.x - start.x), height: abs(end.y - start.y)).intersection(imageDrawRect()); selectionDidChange() }
    override func mouseUp(with event: NSEvent) { mouseDragged(with: event); dragStart = nil }

    override func keyDown(with event: NSEvent) {
        switch event.keyCode {
        case 49, 36:
            setDefaultKeyboardSelection()
        case 51, 117, 53:
            selection = .zero
            selectionDidChange()
        case 123:
            adjustKeyboardSelection(dx: -6, dy: 0, resizing: event.modifierFlags.contains(.option))
        case 124:
            adjustKeyboardSelection(dx: 6, dy: 0, resizing: event.modifierFlags.contains(.option))
        case 125:
            adjustKeyboardSelection(dx: 0, dy: -6, resizing: event.modifierFlags.contains(.option))
        case 126:
            adjustKeyboardSelection(dx: 0, dy: 6, resizing: event.modifierFlags.contains(.option))
        default:
            super.keyDown(with: event)
        }
    }

    func setDefaultKeyboardSelection() {
        let drawable = imageDrawRect()
        guard !drawable.isEmpty else { return }
        selection = NSRect(
            x: drawable.minX + drawable.width * 0.25,
            y: drawable.minY + drawable.height * 0.25,
            width: drawable.width * 0.5,
            height: drawable.height * 0.5
        ).integral
        selectionDidChange()
    }

    func adjustKeyboardSelection(dx: CGFloat, dy: CGFloat, resizing: Bool) {
        if selection.isEmpty { setDefaultKeyboardSelection() }
        let drawable = imageDrawRect()
        guard !selection.isEmpty, !drawable.isEmpty else { return }
        var candidate = selection
        if resizing {
            candidate.size.width = max(6, candidate.width + dx)
            candidate.size.height = max(6, candidate.height + dy)
        } else {
            candidate.origin.x += dx
            candidate.origin.y += dy
        }
        if candidate.width > drawable.width { candidate.size.width = drawable.width }
        if candidate.height > drawable.height { candidate.size.height = drawable.height }
        candidate.origin.x = min(max(candidate.minX, drawable.minX), drawable.maxX - candidate.width)
        candidate.origin.y = min(max(candidate.minY, drawable.minY), drawable.maxY - candidate.height)
        selection = candidate.integral
        selectionDidChange()
    }

    func cropToSelection() -> Bool {
        guard let source = currentCGImage, let pixels = selectedPixelRect(for: source), pixels.width > 2, pixels.height > 2, let cropped = source.cropping(to: pixels) else { return false }
        image = NSImage(cgImage: cropped, size: NSSize(width: cropped.width, height: cropped.height)); selection = .zero; needsDisplay = true; return true
    }
    func redactSelection() -> Bool {
        guard let source = currentCGImage, let pixels = selectedPixelRect(for: source), pixels.width > 2, pixels.height > 2 else { return false }
        guard let context = CGContext(data: nil, width: source.width, height: source.height, bitsPerComponent: 8, bytesPerRow: 0, space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { return false }
        context.draw(source, in: CGRect(x: 0, y: 0, width: source.width, height: source.height)); context.setFillColor(NSColor.black.cgColor)
        context.fill(CGRect(x: pixels.minX, y: CGFloat(source.height) - pixels.maxY, width: pixels.width, height: pixels.height))
        guard let redacted = context.makeImage() else { return false }; image = NSImage(cgImage: redacted, size: NSSize(width: redacted.width, height: redacted.height)); selection = .zero; needsDisplay = true; return true
    }
    func reset() { image = original.copy() as? NSImage ?? original; selection = .zero; selectionDidChange() }
    private func selectionDidChange() {
        needsDisplay = true
        NSAccessibility.post(element: self, notification: .valueChanged)
    }
    private func imageDrawRect() -> NSRect { let size = image.size; guard size.width > 0, size.height > 0 else { return bounds }; let scale = min(bounds.width / size.width, bounds.height / size.height); let fitted = NSSize(width: size.width * scale, height: size.height * scale); return NSRect(x: bounds.midX - fitted.width / 2, y: bounds.midY - fitted.height / 2, width: fitted.width, height: fitted.height) }
    private func selectedPixelRect(for image: CGImage) -> CGRect? { let draw = imageDrawRect(); let selected = selection.intersection(draw); guard !selected.isEmpty else { return nil }; let sx = CGFloat(image.width) / draw.width; let sy = CGFloat(image.height) / draw.height; return CGRect(x: (selected.minX - draw.minX) * sx, y: (draw.maxY - selected.maxY) * sy, width: selected.width * sx, height: selected.height * sy).integral }
}
