import AppKit
import CryptoKit
import Darwin
import Quartz

typealias ArtifactPreviewViewFactory = @MainActor (URL) -> NSView

@MainActor
func makeLiveArtifactPreviewView(for artifact: URL) -> NSView {
    guard let preview = QLPreviewView(frame: .zero, style: .normal) else {
        return NSView()
    }
    preview.previewItem = artifact as NSURL
    preview.autostarts = true
    return preview
}

@MainActor
enum ArtifactPreviewAccessibility {
    enum Position { case primary, left, right }

    static func configure(_ view: NSView, position: Position, fileName: String) {
        let fileName = artifactPreviewSafeText(fileName, fallback: "Artifact", maximumCharacters: 160)
        switch position {
        case .primary:
            view.setAccessibilityLabel("Artifact preview: \(fileName)")
            view.setAccessibilityHelp("Preview of the selected local artifact.")
        case .left:
            view.setAccessibilityLabel("Left artifact preview: \(fileName)")
            view.setAccessibilityHelp("Preview of the original artifact on the left side of the comparison.")
        case .right:
            view.setAccessibilityLabel("Right artifact preview: \(fileName)")
            view.setAccessibilityHelp("Preview of the comparison artifact on the right side of the comparison.")
        }
    }
}

private func artifactPreviewSafeText(
    _ value: String,
    fallback: String,
    maximumCharacters: Int
) -> String {
    let flattened = String(value.unicodeScalars.map { scalar in
        CharacterSet.controlCharacters.contains(scalar) ? " " : Character(scalar)
    })
    let collapsed = flattened
        .split(whereSeparator: { $0.isWhitespace })
        .joined(separator: " ")
    guard !collapsed.isEmpty else { return fallback }
    return String(collapsed.prefix(maximumCharacters))
}

enum ArtifactAnnotationError: Error, Equatable, LocalizedError {
    case unsafeStorage
    case noteTooLarge(maximumBytes: Int)
    case storageLimitExceeded
    case invalidUTF8
    case writeFailed

    var errorDescription: String? {
        switch self {
        case .unsafeStorage: return "Private artifact notes are unavailable because their local storage is not safe."
        case .noteTooLarge(let maximum): return "Artifact notes are limited to \(maximum) UTF-8 bytes."
        case .storageLimitExceeded: return "Private artifact-note storage has reached its safe local limit."
        case .invalidUTF8: return "The saved artifact note is not valid text."
        case .writeFailed: return "The artifact note could not be saved safely."
        }
    }
}

final class ArtifactAnnotationStore {
    struct Limits: Sendable {
        var maximumNoteBytes = 256 * 1_024
        var maximumNotes = 2_000
        var maximumAggregateBytes = 64 * 1_024 * 1_024
        var maximumDirectoryEntries = 2_048
        var scanDuration: TimeInterval = 2

        var isValid: Bool {
            maximumNoteBytes > 0 && maximumNoteBytes <= 4 * 1_024 * 1_024
                && maximumNotes > 0 && maximumNotes <= 10_000
                && maximumAggregateBytes >= maximumNoteBytes
                && maximumAggregateBytes <= 512 * 1_024 * 1_024
                && maximumDirectoryEntries >= maximumNotes
                && maximumDirectoryEntries <= 20_000
                && scanDuration.isFinite && scanDuration > 0 && scanDuration <= 10
        }
    }

    static let maximumNoteBytes = Limits().maximumNoteBytes
    private let fileManager = FileManager.default
    private let directory: URL
    private let limits: Limits

    init(applicationSupport: URL, limits: Limits = Limits()) {
        directory = applicationSupport.appendingPathComponent("Artifact Notes", isDirectory: true)
        self.limits = limits
    }

    func read(for artifact: URL) throws -> String {
        guard limits.isValid else { throw ArtifactAnnotationError.unsafeStorage }
        try ensurePrivateDirectory()
        let url = noteURL(for: artifact)
        var metadata = stat()
        guard Darwin.lstat(url.path, &metadata) == 0 else {
            if errno == ENOENT { return "" }
            throw ArtifactAnnotationError.unsafeStorage
        }
        guard secureRegular(metadata) else { throw ArtifactAnnotationError.unsafeStorage }
        let data: Data
        do {
            data = try SecureAttachmentReader.readRegularFile(at: url, maximumBytes: limits.maximumNoteBytes)
        } catch SecureAttachmentReaderError.tooLarge(_) {
            throw ArtifactAnnotationError.noteTooLarge(maximumBytes: limits.maximumNoteBytes)
        } catch {
            throw ArtifactAnnotationError.unsafeStorage
        }
        guard let text = String(data: data, encoding: .utf8) else {
            throw ArtifactAnnotationError.invalidUTF8
        }
        return text
    }

    func write(_ note: String, for artifact: URL) throws {
        guard limits.isValid else { throw ArtifactAnnotationError.unsafeStorage }
        try ensurePrivateDirectory()
        let url = noteURL(for: artifact)
        if note.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            var metadata = stat()
            if Darwin.lstat(url.path, &metadata) == 0 {
                guard secureRegular(metadata), Darwin.unlink(url.path) == 0 else {
                    throw ArtifactAnnotationError.unsafeStorage
                }
                try synchronizeDirectory()
            } else if errno != ENOENT {
                throw ArtifactAnnotationError.unsafeStorage
            }
            return
        }
        let data = Data(note.utf8)
        guard data.count <= limits.maximumNoteBytes else {
            throw ArtifactAnnotationError.noteTooLarge(maximumBytes: limits.maximumNoteBytes)
        }
        let inventory = try storageInventory(replacing: url.lastPathComponent)
        let replacingBytes = inventory.replacedBytes ?? 0
        let prospectiveCount = inventory.noteCount + (inventory.replacedBytes == nil ? 1 : 0)
        let prospectiveBytes = inventory.aggregateBytes - replacingBytes + data.count
        guard prospectiveCount <= limits.maximumNotes,
              prospectiveBytes <= limits.maximumAggregateBytes else {
            throw ArtifactAnnotationError.storageLimitExceeded
        }
        try writePrivate(data, destinationName: url.lastPathComponent)
    }

    func noteURL(for artifact: URL) -> URL {
        let key = SHA256.hash(data: Data(artifact.standardizedFileURL.path.utf8)).map { String(format: "%02x", $0) }.joined()
        return directory.appendingPathComponent("\(key).txt")
    }

    private func ensurePrivateDirectory() throws {
        if !fileManager.fileExists(atPath: directory.path) {
            do { try fileManager.createDirectory(at: directory, withIntermediateDirectories: true) }
            catch { throw ArtifactAnnotationError.unsafeStorage }
        }
        guard directory.standardizedFileURL == directory.resolvingSymlinksInPath().standardizedFileURL else {
            throw ArtifactAnnotationError.unsafeStorage
        }
        let descriptor = Darwin.open(
            directory.path,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else { throw ArtifactAnnotationError.unsafeStorage }
        defer { Darwin.close(descriptor) }
        var before = stat()
        var after = stat()
        guard Darwin.fstat(descriptor, &before) == 0,
              before.st_mode & S_IFMT == S_IFDIR,
              before.st_uid == geteuid(),
              Darwin.fchmod(descriptor, 0o700) == 0,
              Darwin.fstat(descriptor, &after) == 0,
              after.st_dev == before.st_dev,
              after.st_ino == before.st_ino,
              after.st_mode & S_IFMT == S_IFDIR,
              after.st_uid == geteuid(),
              after.st_mode & (S_IWGRP | S_IWOTH) == 0 else {
            throw ArtifactAnnotationError.unsafeStorage
        }
    }

    private func storageInventory(replacing target: String) throws -> (
        noteCount: Int, aggregateBytes: Int, replacedBytes: Int?
    ) {
        let descriptor = Darwin.open(
            directory.path,
            O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else { throw ArtifactAnnotationError.unsafeStorage }
        guard let stream = fdopendir(descriptor) else {
            Darwin.close(descriptor)
            throw ArtifactAnnotationError.unsafeStorage
        }
        defer { closedir(stream) }
        let started = DispatchTime.now().uptimeNanoseconds
        let duration = UInt64(limits.scanDuration * 1_000_000_000)
        let addition = started.addingReportingOverflow(duration)
        let deadline = addition.overflow ? UInt64.max : addition.partialValue
        var entries = 0
        var noteCount = 0
        var aggregateBytes = 0
        var replacedBytes: Int?
        while true {
            guard DispatchTime.now().uptimeNanoseconds < deadline else {
                throw ArtifactAnnotationError.storageLimitExceeded
            }
            errno = 0
            guard let entry = readdir(stream) else {
                guard errno == 0 else { throw ArtifactAnnotationError.unsafeStorage }
                return (noteCount, aggregateBytes, replacedBytes)
            }
            guard let name = DarwinDirectoryEntry.name(entry) else {
                throw ArtifactAnnotationError.unsafeStorage
            }
            if name == "." || name == ".." { continue }
            entries += 1
            guard entries <= limits.maximumDirectoryEntries,
                  Self.isNoteFilename(name) else { throw ArtifactAnnotationError.storageLimitExceeded }
            var metadata = stat()
            guard fstatat(dirfd(stream), name, &metadata, AT_SYMLINK_NOFOLLOW) == 0,
                  secureRegular(metadata),
                  metadata.st_size >= 0,
                  metadata.st_size <= off_t(limits.maximumNoteBytes) else {
                throw ArtifactAnnotationError.unsafeStorage
            }
            noteCount += 1
            guard noteCount <= limits.maximumNotes,
                  Int(metadata.st_size) <= limits.maximumAggregateBytes - aggregateBytes else {
                throw ArtifactAnnotationError.storageLimitExceeded
            }
            aggregateBytes += Int(metadata.st_size)
            if name == target { replacedBytes = Int(metadata.st_size) }
        }
    }

    private func writePrivate(_ data: Data, destinationName: String) throws {
        let directoryDescriptor = Darwin.open(
            directory.path,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard directoryDescriptor >= 0 else { throw ArtifactAnnotationError.unsafeStorage }
        defer { Darwin.close(directoryDescriptor) }
        let temporaryName = ".artifact-note-\(UUID().uuidString).tmp"
        let temporaryDescriptor = openat(
            directoryDescriptor,
            temporaryName,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            0o600
        )
        guard temporaryDescriptor >= 0 else { throw ArtifactAnnotationError.writeFailed }
        var keepTemporary = true
        defer {
            Darwin.close(temporaryDescriptor)
            if keepTemporary { _ = unlinkat(directoryDescriptor, temporaryName, 0) }
        }
        let wrote = data.withUnsafeBytes { raw -> Bool in
            var offset = 0
            while offset < raw.count {
                let count = Darwin.write(
                    temporaryDescriptor,
                    raw.baseAddress?.advanced(by: offset),
                    raw.count - offset
                )
                if count > 0 { offset += count }
                else if count < 0, errno == EINTR { continue }
                else { return false }
            }
            return true
        }
        guard wrote,
              Darwin.fchmod(temporaryDescriptor, 0o600) == 0,
              Darwin.fsync(temporaryDescriptor) == 0 else {
            throw ArtifactAnnotationError.writeFailed
        }
        guard Darwin.renameat(directoryDescriptor, temporaryName, directoryDescriptor, destinationName) == 0 else {
            throw ArtifactAnnotationError.writeFailed
        }
        keepTemporary = false
        guard Darwin.fsync(directoryDescriptor) == 0 else { throw ArtifactAnnotationError.writeFailed }
    }

    private func synchronizeDirectory() throws {
        let descriptor = Darwin.open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw ArtifactAnnotationError.unsafeStorage }
        defer { Darwin.close(descriptor) }
        guard Darwin.fsync(descriptor) == 0 else { throw ArtifactAnnotationError.writeFailed }
    }

    private func secureRegular(_ metadata: stat) -> Bool {
        metadata.st_mode & S_IFMT == S_IFREG
            && metadata.st_uid == geteuid()
            && metadata.st_nlink == 1
            && metadata.st_mode & (S_IWGRP | S_IWOTH) == 0
    }

    private static func isNoteFilename(_ name: String) -> Bool {
        guard name.count == 68, name.hasSuffix(".txt") else { return false }
        return name.dropLast(4).allSatisfy { $0.isHexDigit && !$0.isUppercase }
    }
}

final class ArtifactPreviewOperationCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false

    func cancel() {
        lock.lock()
        cancelled = true
        lock.unlock()
    }

    var isCancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled
    }
}

enum ArtifactPreviewFailure: Equatable {
    case loadNote
    case saveNote
    case reveal
    case comparison

    var message: String {
        switch self {
        case .loadNote:
            "Private notes could not be loaded safely. The editor remains read-only; retry or close without changing anything."
        case .saveNote:
            "The private note could not be saved and the preview remains open. Your text is still available to retry."
        case .reveal:
            "The artifact could not be shown in Finder. The preview remains available here."
        case .comparison:
            "That comparison could not be opened safely. Choose another local file and try again."
        }
    }
}

struct ArtifactPreviewOperations {
    let read: @MainActor (
        _ artifact: URL,
        _ completion: @escaping @MainActor (Result<String, Error>) -> Void
    ) -> ArtifactPreviewOperationCancellation
    let write: @MainActor (
        _ note: String,
        _ artifact: URL,
        _ completion: @escaping @MainActor (Result<Void, Error>) -> Void
    ) -> ArtifactPreviewOperationCancellation

    init(
        read: @escaping @MainActor (URL, @escaping @MainActor (Result<String, Error>) -> Void) -> ArtifactPreviewOperationCancellation,
        write: @escaping @MainActor (String, URL, @escaping @MainActor (Result<Void, Error>) -> Void) -> ArtifactPreviewOperationCancellation
    ) {
        self.read = read
        self.write = write
    }

    init(annotations: ArtifactAnnotationStore) {
        let queue = DispatchQueue(label: "app.fulmar.artifact-notes", qos: .userInitiated)
        read = { artifact, completion in
            Self.run(on: queue, work: { try annotations.read(for: artifact) }, completion: completion)
        }
        write = { note, artifact, completion in
            Self.run(on: queue, work: { try annotations.write(note, for: artifact) }, completion: completion)
        }
    }

    private static func run<Value>(
        on queue: DispatchQueue,
        work: @escaping () throws -> Value,
        completion: @escaping @MainActor (Result<Value, Error>) -> Void
    ) -> ArtifactPreviewOperationCancellation {
        let cancellation = ArtifactPreviewOperationCancellation()
        queue.async {
            guard !cancellation.isCancelled else { return }
            let result = Result { try work() }
            guard !cancellation.isCancelled else { return }
            DispatchQueue.main.async {
                guard !cancellation.isCancelled else { return }
                completion(result)
            }
        }
        return cancellation
    }
}

struct ArtifactPreviewInteractions {
    let reveal: @MainActor (
        _ artifact: URL,
        _ completion: @escaping @MainActor (Result<Void, Error>) -> Void
    ) -> Void
    let chooseComparison: @MainActor (
        _ parent: NSWindow,
        _ artifactName: String,
        _ completion: @escaping @MainActor (Result<URL?, Error>) -> Void
    ) -> Void
    let presentComparison: @MainActor (_ left: URL, _ right: URL, _ sender: Any?) -> NSWindowController
    let presentFailure: @MainActor (_ failure: ArtifactPreviewFailure, _ parent: NSWindow?) -> Void
    let requestVerifiedClose: @MainActor (_ window: NSWindow) -> Void

    static let live = ArtifactPreviewInteractions(
        reveal: { artifact, completion in
            NSWorkspace.shared.activateFileViewerSelecting([artifact])
            completion(.success(()))
        },
        chooseComparison: { parent, artifactName, completion in
            let panel = NSOpenPanel()
            panel.title = "Compare Artifact"
            panel.message = "Choose another local file to compare with \(artifactName)."
            panel.prompt = "Compare"
            panel.allowsMultipleSelection = false
            panel.canChooseDirectories = false
            panel.canChooseFiles = true
            panel.resolvesAliases = false
            panel.beginSheetModal(for: parent) { response in
                completion(.success(response == .OK ? panel.url : nil))
            }
        },
        presentComparison: { left, right, sender in
            let comparison = ArtifactComparisonWindowController(left: left, right: right)
            comparison.showWindow(sender)
            comparison.window?.makeKeyAndOrderFront(sender)
            return comparison
        },
        presentFailure: { failure, parent in
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = "Artifact preview needs attention"
            alert.informativeText = failure.message
            if let parent { alert.beginSheetModal(for: parent) }
        },
        requestVerifiedClose: { $0.performClose(nil) }
    )
}

final class ArtifactPreviewWindowController: NSWindowController, NSWindowDelegate, NSTextViewDelegate {
    private static let notesPanelWidth: CGFloat = 280

    private let artifact: URL
    private let operations: ArtifactPreviewOperations
    private let interactions: ArtifactPreviewInteractions
    private let preview: NSView
    private let notes = NSTextView()
    private let annotationStatus = NSTextField(wrappingLabelWithString: "")
    private let retryLoadButton = NSButton(title: "Retry Note Load", target: nil, action: nil)
    private let cancelSaveButton = NSButton(title: "Cancel Save", target: nil, action: nil)
    private let revealButton = NSButton(title: "Show in Finder", target: nil, action: nil)
    private let compareButton = NSButton(title: "Compare Version…", target: nil, action: nil)
    private(set) var comparisonWindow: NSWindowController?
    private var activeLoad: ArtifactPreviewOperationCancellation?
    private var activeSave: ArtifactPreviewOperationCancellation?
    private var loadGeneration = 0
    private var saveGeneration = 0
    private var revealGeneration = 0
    private var comparisonGeneration = 0
    private var noteLoaded = false
    private var noteDirty = false
    private var saveInProgress = false
    private var allowingVerifiedClose = false

    convenience init(
        artifact: URL,
        annotations: ArtifactAnnotationStore,
        previewFactory: ArtifactPreviewViewFactory = makeLiveArtifactPreviewView
    ) {
        self.init(
            artifact: artifact,
            operations: ArtifactPreviewOperations(annotations: annotations),
            previewFactory: previewFactory
        )
    }

    init(
        artifact: URL,
        operations: ArtifactPreviewOperations,
        interactions: ArtifactPreviewInteractions = .live,
        previewFactory: ArtifactPreviewViewFactory = makeLiveArtifactPreviewView
    ) {
        self.artifact = artifact
        self.operations = operations
        self.interactions = interactions
        preview = previewFactory(artifact)
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1100, height: 720), styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = Self.safeArtifactName(artifact)
        window.subtitle = "Local artifact preview"
        window.minSize = NSSize(width: 760, height: 520)
        window.setFrameAutosaveName("LocalHarness.ArtifactPreview")
        super.init(window: window)
        window.delegate = self
        window.contentViewController = buildContent()
        if !window.setFrameUsingName("LocalHarness.ArtifactPreview") { window.center() }
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func showWindow(_ sender: Any?) {
        super.showWindow(sender)
        prepareNoteForPresentation()
    }

    private func buildContent() -> NSViewController {
        let vc = NSViewController(); let root = NSView()
        ArtifactPreviewAccessibility.configure(
            preview,
            position: .primary,
            fileName: Self.safeArtifactName(artifact)
        )
        preview.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(preview)

        let notesHeading = NSTextField(labelWithString: "Private notes")
        notesHeading.font = .systemFont(ofSize: 14, weight: .semibold)
        notes.string = ""
        notes.isEditable = false
        annotationStatus.stringValue = "Open the preview to load its private note."
        annotationStatus.textColor = .secondaryLabelColor
        annotationStatus.maximumNumberOfLines = 3
        annotationStatus.setAccessibilityLabel("Artifact note status")
        notes.font = .systemFont(ofSize: 13)
        notes.delegate = self
        notes.textContainerInset = NSSize(width: 10, height: 10)
        notes.setAccessibilityLabel("Artifact notes")
        let notesScroll = AppearanceAwareSeparatorScrollView(); notesScroll.documentView = notes; notesScroll.hasVerticalScroller = true; notesScroll.wantsLayer = true; notesScroll.layer?.borderWidth = 1; notesScroll.refreshSeparatorBorder()
        retryLoadButton.target = self; retryLoadButton.action = #selector(retryNoteLoad(_:)); retryLoadButton.isHidden = true
        cancelSaveButton.target = self; cancelSaveButton.action = #selector(cancelSave(_:)); cancelSaveButton.isHidden = true
        revealButton.target = self; revealButton.action = #selector(reveal(_:))
        compareButton.target = self; compareButton.action = #selector(compare(_:))
        let side = NSStackView(views: [notesHeading, annotationStatus, notesScroll, retryLoadButton, cancelSaveButton, compareButton, revealButton]); side.orientation = .vertical; side.alignment = .leading; side.spacing = 10; side.translatesAutoresizingMaskIntoConstraints = false; root.addSubview(side)
        notesScroll.widthAnchor.constraint(equalTo: side.widthAnchor).isActive = true

        NSLayoutConstraint.activate([
            preview.topAnchor.constraint(equalTo: root.topAnchor), preview.leadingAnchor.constraint(equalTo: root.leadingAnchor), preview.bottomAnchor.constraint(equalTo: root.bottomAnchor),
            side.topAnchor.constraint(equalTo: root.topAnchor, constant: 18), side.leadingAnchor.constraint(equalTo: preview.trailingAnchor, constant: 16), side.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -18), side.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -18),
            side.widthAnchor.constraint(equalToConstant: Self.notesPanelWidth), notesScroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 280)
        ])
        vc.view = root; return vc
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        if allowingVerifiedClose { return true }
        guard noteLoaded, noteDirty else { return true }
        guard !saveInProgress else { return false }
        beginSave(for: sender)
        return false
    }

    func windowWillClose(_ notification: Notification) {
        activeLoad?.cancel()
        activeSave?.cancel()
        activeLoad = nil
        activeSave = nil
        loadGeneration += 1
        saveGeneration += 1
        revealGeneration += 1
        comparisonGeneration += 1
        noteLoaded = false
        saveInProgress = false
        allowingVerifiedClose = false
    }

    func textView(
        _ textView: NSTextView,
        shouldChangeTextIn affectedCharRange: NSRange,
        replacementString: String?
    ) -> Bool {
        let replacement = replacementString ?? ""
        let candidate = (textView.string as NSString).replacingCharacters(
            in: affectedCharRange,
            with: replacement
        )
        guard candidate.utf8.count <= ArtifactAnnotationStore.maximumNoteBytes else {
            annotationStatus.stringValue = "Artifact notes are limited to \(ArtifactAnnotationStore.maximumNoteBytes / 1_024) KB of UTF-8 text."
            annotationStatus.textColor = .systemRed
            NSSound.beep()
            return false
        }
        return true
    }

    func textDidChange(_ notification: Notification) {
        guard notification.object as? NSTextView === notes, noteLoaded, !saveInProgress else { return }
        noteDirty = true
        presentStatus("Unsaved private note · closes only after a verified save", color: .secondaryLabelColor)
    }

    @objc private func retryNoteLoad(_ sender: Any?) { prepareNoteForPresentation() }

    func prepareNoteForPresentation() {
        guard !saveInProgress else { return }
        activeLoad?.cancel()
        loadGeneration += 1
        let generation = loadGeneration
        noteLoaded = false
        noteDirty = false
        notes.isEditable = false
        retryLoadButton.isHidden = true
        presentStatus("Loading the private note…", color: .secondaryLabelColor)
        activeLoad = operations.read(artifact) { [weak self] result in
            guard let self, generation == self.loadGeneration, self.activeLoad != nil else { return }
            self.activeLoad = nil
            switch result {
            case .success(let note):
                guard note.utf8.count <= ArtifactAnnotationStore.maximumNoteBytes else {
                    self.notes.string = ""
                    self.notes.isEditable = false
                    self.noteLoaded = false
                    self.retryLoadButton.isHidden = false
                    self.presentFailure(.loadNote)
                    return
                }
                self.notes.string = note
                self.notes.isEditable = true
                self.noteLoaded = true
                self.noteDirty = false
                self.presentStatus("Stored privately on this Mac · \(ArtifactAnnotationStore.maximumNoteBytes / 1_024) KB maximum", color: .secondaryLabelColor)
            case .failure:
                self.notes.string = ""
                self.notes.isEditable = false
                self.noteLoaded = false
                self.retryLoadButton.isHidden = false
                self.presentFailure(.loadNote)
            }
        }
    }

    private func beginSave(for sender: NSWindow) {
        let byteCount = notes.string.utf8.count
        guard byteCount <= ArtifactAnnotationStore.maximumNoteBytes else {
            presentFailure(.saveNote)
            return
        }
        activeSave?.cancel()
        saveGeneration += 1
        let generation = saveGeneration
        saveInProgress = true
        notes.isEditable = false
        retryLoadButton.isHidden = true
        cancelSaveButton.isHidden = false
        compareButton.isEnabled = false
        revealButton.isEnabled = false
        presentStatus("Saving the private note before closing…", color: .secondaryLabelColor)
        var responded = false
        activeSave = operations.write(notes.string, artifact) { [weak self, weak sender] result in
            guard let self, let sender,
                  !responded,
                  generation == self.saveGeneration,
                  self.saveInProgress,
                  self.activeSave != nil else { return }
            responded = true
            self.activeSave = nil
            self.saveInProgress = false
            self.cancelSaveButton.isHidden = true
            self.compareButton.isEnabled = true
            self.revealButton.isEnabled = true
            switch result {
            case .success:
                self.noteDirty = false
                self.allowingVerifiedClose = true
                self.presentStatus("Private note saved.", color: .systemGreen)
                self.interactions.requestVerifiedClose(sender)
            case .failure:
                self.notes.isEditable = true
                self.presentFailure(.saveNote)
            }
        }
    }

    @objc private func cancelSave(_ sender: Any?) {
        guard saveInProgress else { return }
        activeSave?.cancel()
        activeSave = nil
        saveGeneration += 1
        saveInProgress = false
        notes.isEditable = noteLoaded
        cancelSaveButton.isHidden = true
        compareButton.isEnabled = true
        revealButton.isEnabled = true
        presentStatus("Save cancelled. The preview remains open with your unsaved note.", color: .systemOrange)
    }

    @objc private func reveal(_ sender: Any?) {
        guard revealButton.isEnabled else { return }
        revealGeneration += 1
        let generation = revealGeneration
        revealButton.isEnabled = false
        var responded = false
        interactions.reveal(artifact) { [weak self] result in
            guard let self, !responded, generation == self.revealGeneration else { return }
            responded = true
            self.revealButton.isEnabled = true
            if case .failure = result { self.presentFailure(.reveal) }
        }
    }

    @objc private func compare(_ sender: Any?) {
        guard compareButton.isEnabled, let parent = window else { return }
        comparisonGeneration += 1
        let generation = comparisonGeneration
        compareButton.isEnabled = false
        presentStatus("Choose another local artifact to compare…", color: .secondaryLabelColor)
        var responded = false
        interactions.chooseComparison(parent, Self.safeArtifactName(artifact)) { [weak self] result in
            guard let self, !responded, generation == self.comparisonGeneration else { return }
            responded = true
            self.compareButton.isEnabled = true
            switch result {
            case .success(nil):
                self.restoreNoteStatus()
            case .success(let other?):
                guard other.isFileURL, other.standardizedFileURL != self.artifact.standardizedFileURL else {
                    self.presentFailure(.comparison)
                    return
                }
                self.comparisonWindow = self.interactions.presentComparison(self.artifact, other, sender)
                self.restoreNoteStatus()
            case .failure:
                self.presentFailure(.comparison)
            }
        }
    }

    private func presentFailure(_ failure: ArtifactPreviewFailure) {
        presentStatus(failure.message, color: .systemRed)
        interactions.presentFailure(failure, window)
    }

    private func presentStatus(_ message: String, color: NSColor) {
        annotationStatus.stringValue = message
        annotationStatus.textColor = color
    }

    private func restoreNoteStatus() {
        if noteDirty {
            presentStatus("Unsaved private note · closes only after a verified save", color: .secondaryLabelColor)
        } else if noteLoaded {
            presentStatus("Stored privately on this Mac · \(ArtifactAnnotationStore.maximumNoteBytes / 1_024) KB maximum", color: .secondaryLabelColor)
        }
    }

    private static func safeArtifactName(_ url: URL) -> String {
        artifactPreviewSafeText(url.lastPathComponent, fallback: "Artifact", maximumCharacters: 160)
    }
}

final class ArtifactComparisonWindowController: NSWindowController {
    init(
        left: URL,
        right: URL,
        previewFactory: ArtifactPreviewViewFactory = makeLiveArtifactPreviewView
    ) {
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1200, height: 720), styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        window.title = "Compare Artifacts"
        let leftName = artifactPreviewSafeText(left.lastPathComponent, fallback: "Artifact", maximumCharacters: 160)
        let rightName = artifactPreviewSafeText(right.lastPathComponent, fallback: "Artifact", maximumCharacters: 160)
        window.subtitle = "\(leftName) ↔ \(rightName)"
        window.minSize = NSSize(width: 760, height: 500)
        window.setFrameAutosaveName("LocalHarness.ArtifactComparison")
        super.init(window: window)
        let root = NSView()
        let leftPreview = previewFactory(left)
        let rightPreview = previewFactory(right)
        ArtifactPreviewAccessibility.configure(leftPreview, position: .left, fileName: leftName)
        ArtifactPreviewAccessibility.configure(rightPreview, position: .right, fileName: rightName)
        leftPreview.translatesAutoresizingMaskIntoConstraints = false; rightPreview.translatesAutoresizingMaskIntoConstraints = false; root.addSubview(leftPreview); root.addSubview(rightPreview)
        let divider = NSBox(); divider.boxType = .separator; divider.translatesAutoresizingMaskIntoConstraints = false; root.addSubview(divider)
        NSLayoutConstraint.activate([leftPreview.topAnchor.constraint(equalTo: root.topAnchor), leftPreview.leadingAnchor.constraint(equalTo: root.leadingAnchor), leftPreview.bottomAnchor.constraint(equalTo: root.bottomAnchor), leftPreview.trailingAnchor.constraint(equalTo: divider.leadingAnchor), divider.centerXAnchor.constraint(equalTo: root.centerXAnchor), divider.widthAnchor.constraint(equalToConstant: 1), divider.topAnchor.constraint(equalTo: root.topAnchor), divider.bottomAnchor.constraint(equalTo: root.bottomAnchor), rightPreview.topAnchor.constraint(equalTo: root.topAnchor), rightPreview.leadingAnchor.constraint(equalTo: divider.trailingAnchor), rightPreview.trailingAnchor.constraint(equalTo: root.trailingAnchor), rightPreview.bottomAnchor.constraint(equalTo: root.bottomAnchor), leftPreview.widthAnchor.constraint(equalTo: rightPreview.widthAnchor)])
        let vc = NSViewController(); vc.view = root; window.contentViewController = vc
        if !window.setFrameUsingName("LocalHarness.ArtifactComparison") { window.center() }
    }
    @available(*, unavailable) required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
}
