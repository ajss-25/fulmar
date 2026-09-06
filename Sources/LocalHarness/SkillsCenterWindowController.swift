import AppKit

enum SkillsCenterFailure: Equatable {
    case importSkill
    case removeSkill
    case savePolicy

    var title: String {
        switch self {
        case .importSkill: "Skill was not imported"
        case .removeSkill: "Skill was not removed"
        case .savePolicy: "Skill policy was not saved"
        }
    }

    var message: String {
        switch self {
        case .importSkill:
            "The selected bundle was left unchanged. Review its structure and permissions, then try again."
        case .removeSkill:
            "The quarantined skill and its workspace permissions were preserved. Try again after private storage is available."
        case .savePolicy:
            "The previous fingerprint-bound policy was restored. Review the skill and try again."
        }
    }
}

struct SkillsAuditPresentation: Equatable {
    enum Outcome: Equatable {
        case empty
        case trusted
        case attention
    }

    let outcome: Outcome
    let problemSummaries: [String]
}

@MainActor
struct SkillsCenterInteractions {
    var chooseImportSource: () -> URL?
    var confirmImport: (SkillBundleInspection, Bool) -> Bool
    var confirmRemove: (InstalledSkill) -> Bool
    var confirmExternalDisclosure: (InstalledSkill) -> Bool
    var presentAudit: (SkillsAuditPresentation) -> Void
    var showFailure: (SkillsCenterFailure) -> Void

    static let live = SkillsCenterInteractions(
        chooseImportSource: {
            let panel = NSOpenPanel()
            panel.title = "Choose a skill bundle"
            panel.message = "Select a folder containing SKILL.md, or select SKILL.md itself. Files are copied into quarantine without being executed."
            panel.canChooseDirectories = true
            panel.canChooseFiles = true
            panel.allowsMultipleSelection = false
            panel.resolvesAliases = false
            return panel.runModal() == .OK ? panel.url : nil
        },
        confirmImport: { inspection, alreadyExists in
            let alert = NSAlert()
            alert.alertStyle = inspection.riskFlags.isEmpty ? .informational : .warning
            alert.messageText = alreadyExists
                ? "Replace reviewed skill \(inspection.name)?"
                : "Import reviewed skill \(inspection.name)?"
            let risks = SkillsCenterPresentation.riskDescription(inspection.riskFlags)
            alert.informativeText = "\(SkillsCenterPresentation.safeDescription(inspection.description))\n\n\(inspection.fileCount) files · \(ByteCountFormatter.string(fromByteCount: inspection.totalBytes, countStyle: .file))\nSHA-256: \(inspection.fingerprint)\n\n\(risks)\n\nImporting keeps the bundle disabled. You choose its workspace and cloud policy afterward."
            alert.addButton(withTitle: alreadyExists ? "Replace in Quarantine" : "Import to Quarantine")
            alert.addButton(withTitle: "Cancel")
            return alert.runModal() == .alertFirstButtonReturn
        },
        confirmRemove: { skill in
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = "Remove \(skill.name)?"
            alert.informativeText = "The quarantined copy and its workspace permissions will be removed. The original source folder is not changed."
            alert.addButton(withTitle: "Remove Skill")
            alert.addButton(withTitle: "Cancel")
            return alert.runModal() == .alertFirstButtonReturn
        },
        confirmExternalDisclosure: { _ in
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = "Allow this skill with external models?"
            alert.informativeText = "The instructions and any selected skill resources may be included in prompts sent to a cloud or network provider. Permission remains tied to this exact fingerprint."
            alert.addButton(withTitle: "Allow External Use")
            alert.addButton(withTitle: "Keep Local Only")
            return alert.runModal() == .alertFirstButtonReturn
        },
        presentAudit: { presentation in
            let alert = NSAlert()
            switch presentation.outcome {
            case .empty:
                alert.alertStyle = .informational
                alert.messageText = "No skills to verify"
                alert.informativeText = "There are no imported skills to verify."
            case .trusted:
                alert.alertStyle = .informational
                alert.messageText = "All installed skills match"
                alert.informativeText = "Every quarantined skill matches the exact fingerprint you reviewed."
            case .attention:
                alert.alertStyle = .warning
                alert.messageText = "Some skills need attention"
                alert.informativeText = presentation.problemSummaries.joined(separator: "\n")
            }
            alert.addButton(withTitle: "OK")
            alert.runModal()
        },
        showFailure: { failure in
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = failure.title
            alert.informativeText = failure.message
            alert.addButton(withTitle: "OK")
            alert.runModal()
        }
    )
}

@MainActor
struct SkillsCenterOperations {
    var installedSkills: () -> [InstalledSkill]
    var policy: (String, String) -> SkillProjectPolicy
    var inspect: (URL) throws -> SkillBundleInspection
    var importBundle: (URL, Bool) throws -> InstalledSkill
    var remove: (String) throws -> Void
    var setPolicy: (String, String, Bool, SkillCloudDisclosure) throws -> Void
    var audit: () -> [SkillTrustFinding]

    init(store: SkillsTrustStore) {
        installedSkills = { store.installedSkills() }
        policy = { store.policy(skillID: $0, projectID: $1) }
        inspect = { try store.inspect(at: $0) }
        importBundle = { try store.importBundle(at: $0, replacingExisting: $1) }
        remove = { try store.remove(skillID: $0) }
        setPolicy = { try store.setPolicy(
            skillID: $0,
            projectID: $1,
            enabled: $2,
            cloudDisclosure: $3
        ) }
        audit = { store.audit() }
    }
}

enum SkillsCenterPresentation {
    static func safeDescription(_ value: String) -> String {
        var scalars: [UnicodeScalar] = []
        scalars.reserveCapacity(min(value.unicodeScalars.count, 4_096))
        for scalar in value.unicodeScalars.prefix(4_096) {
            switch scalar.value {
            case 0x09, 0x0A, 0x0D:
                scalars.append(" ")
            case 0x200E, 0x200F, 0x202A...0x202E, 0x2066...0x2069:
                continue
            default:
                if !CharacterSet.controlCharacters.contains(scalar) { scalars.append(scalar) }
            }
        }
        let cleaned = String(String.UnicodeScalarView(scalars))
            .split(whereSeparator: \.isWhitespace)
            .joined(separator: " ")
        return cleaned.isEmpty ? "No safe description was provided." : cleaned
    }

    static func riskDescription(_ flags: [SkillRiskFlag]) -> String {
        guard !flags.isEmpty else {
            return "No executable, script, or binary-resource signals were found. The instructions can still influence agent actions, so review the source before enabling it."
        }
        let labels = flags.map { flag in
            switch flag {
            case .containsExecutableFile: "executable file"
            case .containsScript: "script"
            case .containsBinaryResource: "binary resource"
            }
        }
        return "Review carefully: bundle contains \(labels.joined(separator: ", ")). Import never executes these files."
    }
}

/// A native review surface for inert, fingerprint-pinned skill bundles. Skill
/// files are never executed by this window; the Harness controller exposes only
/// the reviewed Active snapshot after a restart.
final class SkillsCenterWindowController: NSWindowController, NSTableViewDataSource, NSTableViewDelegate {
    var onApplyAndRestart: (@MainActor (SkillExecutionBoundary) async throws -> Void)?

    private let operations: SkillsCenterOperations
    private let interactions: SkillsCenterInteractions
    private let projectID: String
    private let currentBoundary: () -> SkillExecutionBoundary

    private let tableView = NSTableView()
    private let emptyLabel = NSTextField(wrappingLabelWithString: "No skills installed. Import a folder containing SKILL.md to review it safely.")
    private let nameLabel = NSTextField(wrappingLabelWithString: "Select a skill")
    private let descriptionLabel = NSTextField(wrappingLabelWithString: "Imported skills remain quarantined until you explicitly enable them for this workspace.")
    private let fingerprintLabel = NSTextField(wrappingLabelWithString: "")
    private let metadataLabel = NSTextField(wrappingLabelWithString: "")
    private let riskLabel = NSTextField(wrappingLabelWithString: "")
    private let enabledButton = NSButton(checkboxWithTitle: "Enable for this workspace", target: nil, action: nil)
    private let disclosurePicker = NSPopUpButton()
    private let policyExplanation = NSTextField(wrappingLabelWithString: "")
    private let importButton = NSButton(title: "Import & Review…", target: nil, action: nil)
    private let removeButton = NSButton(title: "Remove", target: nil, action: nil)
    private let verifyButton = NSButton(title: "Verify All", target: nil, action: nil)
    private let applyButton = NSButton(title: "Apply & Restart", target: nil, action: nil)
    private let statusLabel = NSTextField(labelWithString: "Changes are fingerprint-bound and apply after a secure runtime restart.")
    private var skills: [InstalledSkill] = []
    private var policyIsDirty = false
    private var isApplying = false
    private var isPerformingOperation = false
    private var applyGeneration = 0

    convenience init(
        store: SkillsTrustStore,
        projectURL: URL,
        currentBoundary: @escaping () -> SkillExecutionBoundary
    ) {
        self.init(
            operations: SkillsCenterOperations(store: store),
            projectURL: projectURL,
            currentBoundary: currentBoundary,
            interactions: .live
        )
    }

    init(
        operations: SkillsCenterOperations,
        projectURL: URL,
        currentBoundary: @escaping () -> SkillExecutionBoundary,
        interactions: SkillsCenterInteractions
    ) {
        self.operations = operations
        self.interactions = interactions
        projectID = SkillsProjectIdentity.identifier(for: projectURL)
        self.currentBoundary = currentBoundary
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 920, height: 620),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Skills"
        window.subtitle = "Reviewed instructions for the Harness agent"
        window.minSize = NSSize(width: 760, height: 500)
        window.isReleasedWhenClosed = false
        window.setFrameAutosaveName("LocalHarness.SkillsCenter")
        super.init(window: window)
        window.contentViewController = buildContent()
        if !window.setFrameUsingName("LocalHarness.SkillsCenter") { window.center() }
        reload()
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func showWindow(_ sender: Any?) {
        if operationIsBusy {
            // Keep the last reviewed snapshot stable while a protected runtime
            // transition or store mutation owns the underlying trust state.
            // This also avoids racing activation if a closed window is reopened.
            presentSelection()
            updateOperationControls()
        } else {
            reload(retaining: selectedSkill?.id)
        }
        super.showWindow(sender)
    }

    func numberOfRows(in tableView: NSTableView) -> Int { skills.count }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard skills.indices.contains(row) else { return nil }
        let identifier = NSUserInterfaceItemIdentifier("SkillRow")
        let field = tableView.makeView(withIdentifier: identifier, owner: self) as? NSTextField
            ?? NSTextField(labelWithString: "")
        field.identifier = identifier
        field.font = .systemFont(ofSize: 13, weight: .medium)
        field.lineBreakMode = .byTruncatingTail
        field.stringValue = skills[row].name
        field.toolTip = SkillsCenterPresentation.safeDescription(skills[row].description)
        return field
    }

    func tableViewSelectionDidChange(_ notification: Notification) { presentSelection() }

    private var selectedSkill: InstalledSkill? {
        let row = tableView.selectedRow
        return skills.indices.contains(row) ? skills[row] : nil
    }

    private func buildContent() -> NSViewController {
        let controller = NSViewController()
        let root = NSView()

        let heading = NSTextField(labelWithString: "Skills")
        heading.font = .systemFont(ofSize: 22, weight: .semibold)
        let subtitle = NSTextField(wrappingLabelWithString: "Import skills as inert data, inspect their fingerprint and risk signals, then decide whether each workspace and provider boundary may see them.")
        subtitle.textColor = .secondaryLabelColor
        subtitle.maximumNumberOfLines = 2
        let titles = NSStackView(views: [heading, subtitle])
        titles.orientation = .vertical
        titles.alignment = .leading
        titles.spacing = 3

        configureButton(importButton, action: #selector(importSkill(_:)))
        configureButton(verifyButton, action: #selector(verifyAll(_:)))
        let header = NSStackView(views: [titles, NSView(), verifyButton, importButton])
        header.orientation = .horizontal
        header.alignment = .centerY
        header.spacing = 8

        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("skill"))
        column.title = "Installed skill"
        column.resizingMask = .autoresizingMask
        tableView.addTableColumn(column)
        tableView.headerView = nil
        tableView.delegate = self
        tableView.dataSource = self
        tableView.rowHeight = 34
        tableView.setAccessibilityLabel("Installed reviewed skills")
        let tableScroll = NSScrollView()
        tableScroll.documentView = tableView
        tableScroll.hasVerticalScroller = true
        tableScroll.drawsBackground = false

        emptyLabel.textColor = .secondaryLabelColor
        emptyLabel.alignment = .center
        emptyLabel.maximumNumberOfLines = 4
        emptyLabel.setAccessibilityLabel("Skills empty state")
        emptyLabel.translatesAutoresizingMaskIntoConstraints = false
        let sidebar = NSView()
        tableScroll.translatesAutoresizingMaskIntoConstraints = false
        sidebar.addSubview(tableScroll)
        sidebar.addSubview(emptyLabel)
        NSLayoutConstraint.activate([
            tableScroll.topAnchor.constraint(equalTo: sidebar.topAnchor),
            tableScroll.leadingAnchor.constraint(equalTo: sidebar.leadingAnchor),
            tableScroll.trailingAnchor.constraint(equalTo: sidebar.trailingAnchor),
            tableScroll.bottomAnchor.constraint(equalTo: sidebar.bottomAnchor),
            emptyLabel.centerYAnchor.constraint(equalTo: sidebar.centerYAnchor),
            emptyLabel.leadingAnchor.constraint(equalTo: sidebar.leadingAnchor, constant: 24),
            emptyLabel.trailingAnchor.constraint(equalTo: sidebar.trailingAnchor, constant: -24)
        ])

        nameLabel.font = .systemFont(ofSize: 20, weight: .semibold)
        nameLabel.maximumNumberOfLines = 2
        descriptionLabel.textColor = .secondaryLabelColor
        descriptionLabel.maximumNumberOfLines = 5
        descriptionLabel.setAccessibilityLabel("Skill description")
        fingerprintLabel.font = .monospacedSystemFont(ofSize: 10, weight: .regular)
        fingerprintLabel.textColor = .tertiaryLabelColor
        fingerprintLabel.maximumNumberOfLines = 3
        metadataLabel.textColor = .secondaryLabelColor
        riskLabel.textColor = .systemOrange
        riskLabel.maximumNumberOfLines = 3

        enabledButton.target = self
        enabledButton.action = #selector(policyChanged(_:))
        disclosurePicker.addItems(withTitles: [
            "Keep local only",
            "Ask before each external session",
            "Allow with external models"
        ])
        disclosurePicker.target = self
        disclosurePicker.action = #selector(policyChanged(_:))
        disclosurePicker.setAccessibilityLabel("External model disclosure")
        policyExplanation.textColor = .secondaryLabelColor
        policyExplanation.maximumNumberOfLines = 4
        policyExplanation.setAccessibilityLabel("Skill policy explanation")

        configureButton(removeButton, action: #selector(removeSkill(_:)))
        removeButton.contentTintColor = .systemRed
        configureButton(applyButton, action: #selector(applyAndRestart(_:)))
        applyButton.keyEquivalent = "\r"

        let policyRow = NSStackView(views: [enabledButton, disclosurePicker])
        policyRow.orientation = .horizontal
        policyRow.alignment = .centerY
        policyRow.spacing = 12
        let actionRow = NSStackView(views: [removeButton, NSView(), applyButton])
        actionRow.orientation = .horizontal
        actionRow.alignment = .centerY
        let detail = NSStackView(views: [
            nameLabel, descriptionLabel, metadataLabel, fingerprintLabel, riskLabel,
            NSBox(), policyRow, policyExplanation, NSView(), actionRow
        ])
        detail.orientation = .vertical
        detail.alignment = .leading
        detail.spacing = 10
        detail.edgeInsets = NSEdgeInsets(top: 16, left: 20, bottom: 16, right: 20)
        policyRow.widthAnchor.constraint(equalTo: detail.widthAnchor, constant: -40).isActive = true
        policyExplanation.widthAnchor.constraint(equalTo: detail.widthAnchor, constant: -40).isActive = true
        actionRow.widthAnchor.constraint(equalTo: detail.widthAnchor, constant: -40).isActive = true

        let split = NSSplitView()
        split.isVertical = true
        split.dividerStyle = .thin
        split.addArrangedSubview(sidebar)
        split.addArrangedSubview(detail)
        sidebar.widthAnchor.constraint(greaterThanOrEqualToConstant: 230).isActive = true
        sidebar.widthAnchor.constraint(lessThanOrEqualToConstant: 330).isActive = true

        statusLabel.textColor = .secondaryLabelColor
        statusLabel.font = .systemFont(ofSize: 11)
        statusLabel.lineBreakMode = .byTruncatingTail
        statusLabel.setAccessibilityLabel("Skills status")
        let layout = NSStackView(views: [header, split, statusLabel])
        layout.orientation = .vertical
        layout.alignment = .leading
        layout.spacing = 12
        layout.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(layout)
        NSLayoutConstraint.activate([
            layout.topAnchor.constraint(equalTo: root.topAnchor, constant: 18),
            layout.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 18),
            layout.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -18),
            layout.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -14),
            header.widthAnchor.constraint(equalTo: layout.widthAnchor),
            split.widthAnchor.constraint(equalTo: layout.widthAnchor),
            statusLabel.widthAnchor.constraint(equalTo: layout.widthAnchor)
        ])
        controller.view = root
        return controller
    }

    private func configureButton(_ button: NSButton, action: Selector) {
        button.target = self
        button.action = action
        button.bezelStyle = .rounded
    }

    private func reload(retaining skillID: String? = nil) {
        skills = operations.installedSkills()
        tableView.reloadData()
        emptyLabel.isHidden = !skills.isEmpty
        tableView.isHidden = skills.isEmpty
        if let skillID, let row = skills.firstIndex(where: { $0.id == skillID }) {
            tableView.selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false)
        } else if !skills.isEmpty {
            tableView.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)
        } else {
            presentSelection()
        }
    }

    private func presentSelection() {
        guard let skill = selectedSkill else {
            nameLabel.stringValue = "No skill selected"
            descriptionLabel.stringValue = "Import a directory containing SKILL.md. Nothing is run during import or review."
            fingerprintLabel.stringValue = ""
            metadataLabel.stringValue = ""
            riskLabel.stringValue = ""
            enabledButton.isEnabled = false
            disclosurePicker.isEnabled = false
            removeButton.isEnabled = false
            applyButton.isEnabled = policyIsDirty && !operationIsBusy
            policyExplanation.stringValue = ""
            return
        }
        let policy = operations.policy(skill.id, projectID)
        nameLabel.stringValue = skill.name
        descriptionLabel.stringValue = SkillsCenterPresentation.safeDescription(skill.description)
        metadataLabel.stringValue = "\(skill.fileCount) files · \(ByteCountFormatter.string(fromByteCount: skill.totalBytes, countStyle: .file)) · imported \(Self.dateFormatter.string(from: skill.importedAt))"
        fingerprintLabel.stringValue = "SHA-256  \(skill.fingerprint)"
        riskLabel.stringValue = riskDescription(skill.riskFlags)
        enabledButton.isEnabled = !operationIsBusy
        enabledButton.state = policy.enabled ? .on : .off
        disclosurePicker.isEnabled = policy.enabled && !operationIsBusy
        disclosurePicker.selectItem(at: Self.index(for: policy.cloudDisclosure))
        removeButton.isEnabled = !operationIsBusy
        applyButton.isEnabled = policyIsDirty && !operationIsBusy
        updatePolicyExplanation()
    }

    @objc private func importSkill(_ sender: Any?) {
        performSynchronousOperation {
            guard let source = interactions.chooseImportSource() else { return }
            do {
                let inspection = try operations.inspect(source)
                let alreadyExists = operations.installedSkills().contains { $0.id == inspection.name }
                guard interactions.confirmImport(inspection, alreadyExists) else { return }
                let installed = try operations.importBundle(source, alreadyExists)
                policyIsDirty = true
                statusLabel.stringValue = "\(installed.name) was imported safely and remains disabled until you enable and apply it."
                reload(retaining: installed.id)
            } catch {
                interactions.showFailure(.importSkill)
            }
        }
    }

    @objc private func removeSkill(_ sender: Any?) {
        guard !operationIsBusy, let skill = selectedSkill else { return }
        performSynchronousOperation {
            guard interactions.confirmRemove(skill) else { return }
            do {
                try operations.remove(skill.id)
                policyIsDirty = true
                statusLabel.stringValue = "\(skill.name) was removed. Restart to refresh the active skill catalog."
                reload()
            } catch {
                interactions.showFailure(.removeSkill)
            }
        }
    }

    @objc private func policyChanged(_ sender: Any?) {
        guard !operationIsBusy, let skill = selectedSkill else { return }
        performSynchronousOperation {
            let disclosure = Self.disclosure(at: disclosurePicker.indexOfSelectedItem)
            if enabledButton.state == .on,
               disclosure == .allowed,
               operations.policy(skill.id, projectID).cloudDisclosure != .allowed,
               !interactions.confirmExternalDisclosure(skill) {
                disclosurePicker.selectItem(at: Self.index(for: .localOnly))
            }
            do {
                try operations.setPolicy(
                    skill.id,
                    projectID,
                    enabledButton.state == .on,
                    Self.disclosure(at: disclosurePicker.indexOfSelectedItem)
                )
                policyIsDirty = true
                statusLabel.stringValue = "Policy saved. Apply & Restart will expose only the permitted fingerprint."
                updatePolicyExplanation()
            } catch {
                interactions.showFailure(.savePolicy)
                reload(retaining: skill.id)
            }
        }
    }

    @objc private func verifyAll(_ sender: Any?) {
        performSynchronousOperation {
            let findings = operations.audit()
            let problems = findings.filter { $0.status != .trusted }
            let outcome: SkillsAuditPresentation.Outcome = findings.isEmpty
                ? .empty
                : (problems.isEmpty ? .trusted : .attention)
            let installedNames = Set(skills.map(\.id))
            let summaries = problems.prefix(20).map { finding in
                let name = installedNames.contains(finding.id) ? finding.id : "Imported skill"
                return "\(name): \(Self.auditStatusMessage(finding.status))"
            }
            interactions.presentAudit(SkillsAuditPresentation(
                outcome: outcome,
                problemSummaries: summaries
            ))
            switch outcome {
            case .empty:
                statusLabel.stringValue = "There are no imported skills to verify."
            case .trusted:
                statusLabel.stringValue = "Skill verification passed."
            case .attention:
                statusLabel.stringValue = "Changed or invalid skills will remain unavailable."
            }
        }
    }

    @objc private func applyAndRestart(_ sender: Any?) {
        guard !operationIsBusy, policyIsDirty else { return }
        isApplying = true
        applyGeneration += 1
        let generation = applyGeneration
        updateOperationControls()
        statusLabel.stringValue = "Stopping the exact old runtime before preparing the reviewed skill catalog…"
        guard let apply = onApplyAndRestart else {
            isApplying = false
            updateOperationControls()
            statusLabel.stringValue = "Skills were not applied because protected runtime coordination is unavailable."
            return
        }
        let boundary = currentBoundary()
        Task { @MainActor [weak self] in
            guard let self else { return }
            do {
                try await apply(boundary)
                guard self.isApplying, generation == self.applyGeneration else { return }
                self.policyIsDirty = false
                self.isApplying = false
                self.updateOperationControls()
                self.statusLabel.stringValue = "Reviewed skills are active in a fresh verified runtime."
            } catch {
                guard self.isApplying, generation == self.applyGeneration else { return }
                self.isApplying = false
                self.updateOperationControls()
                self.statusLabel.stringValue = "Skills were not applied. The protected runtime could not be restarted safely; the previous active catalog remains in use."
            }
        }
    }

    private func updateOperationControls() {
        importButton.isEnabled = !operationIsBusy
        verifyButton.isEnabled = !operationIsBusy
        tableView.isEnabled = !operationIsBusy
        guard let skill = selectedSkill else {
            enabledButton.isEnabled = false
            disclosurePicker.isEnabled = false
            removeButton.isEnabled = false
            applyButton.isEnabled = policyIsDirty && !operationIsBusy
            return
        }
        let policy = operations.policy(skill.id, projectID)
        enabledButton.isEnabled = !operationIsBusy
        disclosurePicker.isEnabled = !operationIsBusy && policy.enabled
        removeButton.isEnabled = !operationIsBusy
        applyButton.isEnabled = !operationIsBusy && policyIsDirty
    }

    private var operationIsBusy: Bool { isApplying || isPerformingOperation }

    private func performSynchronousOperation(_ operation: () -> Void) {
        guard !operationIsBusy else { return }
        isPerformingOperation = true
        updateOperationControls()
        defer {
            isPerformingOperation = false
            updateOperationControls()
        }
        operation()
    }

    private func updatePolicyExplanation() {
        guard selectedSkill != nil else { policyExplanation.stringValue = ""; return }
        if enabledButton.state != .on {
            policyExplanation.stringValue = "Disabled skills remain in quarantine and are invisible to the agent runtime."
            return
        }
        switch Self.disclosure(at: disclosurePicker.indexOfSelectedItem) {
        case .localOnly:
            policyExplanation.stringValue = "Available to local models only. It is automatically withheld from LAN and cloud routes."
        case .askEveryTime:
            policyExplanation.stringValue = "Before each external runtime session, \(ProductBrand.displayName) asks whether this exact reviewed skill may be exposed once."
        case .allowed:
            policyExplanation.stringValue = "Available to local and external models until its files change or you revoke this permission."
        }
    }

    private func riskDescription(_ flags: [SkillRiskFlag]) -> String {
        SkillsCenterPresentation.riskDescription(flags)
    }

    private static func auditStatusMessage(_ status: SkillTrustFinding.Status) -> String {
        switch status {
        case .trusted: "Fingerprint verified."
        case .modified: "Files changed after import."
        case .missing: "The reviewed package is missing."
        case .invalid: "The reviewed package could not be verified safely."
        case .unexpected: "An unreviewed package was found and remains unavailable."
        }
    }

    private static func index(for disclosure: SkillCloudDisclosure) -> Int {
        switch disclosure { case .localOnly: return 0; case .askEveryTime: return 1; case .allowed: return 2 }
    }

    private static func disclosure(at index: Int) -> SkillCloudDisclosure {
        switch index { case 1: return .askEveryTime; case 2: return .allowed; default: return .localOnly }
    }

    private static let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter
    }()
}
