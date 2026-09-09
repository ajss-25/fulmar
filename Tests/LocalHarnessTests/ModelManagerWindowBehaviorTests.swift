import AppKit
import Foundation
import Testing
@testable import LocalHarness

private struct HostileModelManagerError: LocalizedError {
    var errorDescription: String? {
        "MODEL_MANAGER_SECRET_CANARY sk-private /Users/private/provider-ledger"
    }
}

@MainActor
private func modelManagerTemporaryDirectory(_ name: String) throws -> URL {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("FulmarModelManagerBehavior-\(name)-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    return directory
}

@MainActor
private func modelManagerDescendants(of root: NSView) -> [NSView] {
    [root] + root.subviews.flatMap(modelManagerDescendants(of:))
}

@MainActor
private func modelManagerButton(_ title: String, in root: NSView) throws -> NSButton {
    try #require(modelManagerDescendants(of: root).compactMap { $0 as? NSButton }.first { $0.title == title })
}

@MainActor
private func modelManagerStatus(in root: NSView) throws -> NSTextField {
    try #require(modelManagerDescendants(of: root).compactMap { $0 as? NSTextField }.first {
        $0.accessibilityLabel() == "Local model status"
    })
}

@MainActor
private func modelManagerTable(in root: NSView) throws -> NSTableView {
    try #require(modelManagerDescendants(of: root).compactMap { $0 as? NSTableView }.first)
}

private func qualifiedModel(running: Bool = false) -> (OllamaModel, [OllamaRunningModel]) {
    let name = BuiltInProviderDescriptors.qwenLocalModel.id.rawValue
    let model = OllamaModel(
        name: name,
        digest: BuiltInProviderDescriptors.qwenLocalModelManifestDigest,
        size: 18_000_000_000,
        modifiedAt: nil,
        details: nil
    )
    let loaded = OllamaRunningModel(
        name: name,
        size: 18_000_000_000,
        sizeVRAM: 18_000_000_000,
        expiresAt: nil
    )
    return (model, running ? [loaded] : [])
}

private func compatibilityModel() -> OllamaModel {
    OllamaModel(
        name: "community-tools:latest",
        digest: String(repeating: "b", count: 64),
        size: 9_000_000_000,
        modifiedAt: nil,
        details: nil
    )
}

@MainActor
@Test func modelManagerPreparationAndCatalogueRefreshAreSingleFlightAndGenerationBound() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let directory = try modelManagerTemporaryDirectory("Refresh")
    defer { try? FileManager.default.removeItem(at: directory) }

    var ensureCompletions: [(Result<Void, Error>) -> Void] = []
    var modelCompletions: [(Result<[OllamaModel], Error>) -> Void] = []
    var runningCompletions: [(Result<[OllamaRunningModel], Error>) -> Void] = []
    let controller = ModelManagerWindowController(
        client: OllamaClient(baseURLProvider: { nil }),
        activities: ActivityStore(applicationSupport: directory),
        ensureLocalService: { ensureCompletions.append($0) },
        currentSelection: { nil },
        useModelForNewTasks: { _, _ in },
        releaseModelMemory: { _, _ in },
        fetchModels: { modelCompletions.append($0) },
        fetchRunningModels: { runningCompletions.append($0) }
    )
    let root = try #require(controller.window?.contentViewController?.view)
    let refresh = try modelManagerButton("Refresh", in: root)
    let status = try modelManagerStatus(in: root)
    let table = try modelManagerTable(in: root)

    refresh.performClick(nil)
    #expect(ensureCompletions.count == 1)
    #expect(!refresh.isEnabled)
    #expect(!table.isEnabled)
    refresh.performClick(nil)
    #expect(ensureCompletions.count == 1)

    ensureCompletions[0](.failure(HostileModelManagerError()))
    #expect(refresh.isEnabled)
    #expect(table.isEnabled)
    #expect(status.stringValue.contains("Confirm that the supported Ollama app is installed"))
    #expect(!status.stringValue.contains("MODEL_MANAGER_SECRET_CANARY"))

    refresh.performClick(nil)
    #expect(ensureCompletions.count == 2)
    ensureCompletions[0](.success(()))
    #expect(modelCompletions.isEmpty)
    ensureCompletions[1](.success(()))
    #expect(modelCompletions.count == 1)

    let fixture = qualifiedModel()
    modelCompletions[0](.success([fixture.0]))
    #expect(runningCompletions.count == 1)
    modelCompletions[0](.success([]))
    #expect(runningCompletions.count == 1)
    runningCompletions[0](.success([]))
    #expect(refresh.isEnabled)
    #expect(table.isEnabled)
    #expect(status.stringValue.contains("1 installed"))
    runningCompletions[0](.failure(HostileModelManagerError()))
    #expect(status.stringValue.contains("1 installed"))
    #expect(!status.stringValue.contains("MODEL_MANAGER_SECRET_CANARY"))
}

@MainActor
@Test func modelManagerCatalogueFailuresAreBoundedSanitizedAndRecoverable() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let directory = try modelManagerTemporaryDirectory("Failures")
    defer { try? FileManager.default.removeItem(at: directory) }

    var ensureCompletions: [(Result<Void, Error>) -> Void] = []
    var modelCompletions: [(Result<[OllamaModel], Error>) -> Void] = []
    var runningCompletions: [(Result<[OllamaRunningModel], Error>) -> Void] = []
    let controller = ModelManagerWindowController(
        client: OllamaClient(baseURLProvider: { nil }),
        activities: ActivityStore(applicationSupport: directory),
        ensureLocalService: { ensureCompletions.append($0) },
        currentSelection: { nil },
        useModelForNewTasks: { _, _ in },
        releaseModelMemory: { _, _ in },
        fetchModels: { modelCompletions.append($0) },
        fetchRunningModels: { runningCompletions.append($0) }
    )
    let root = try #require(controller.window?.contentViewController?.view)
    let refresh = try modelManagerButton("Refresh", in: root)
    let status = try modelManagerStatus(in: root)

    refresh.performClick(nil)
    ensureCompletions[0](.success(()))
    modelCompletions[0](.failure(HostileModelManagerError()))
    #expect(refresh.isEnabled)
    #expect(status.stringValue == "Installed local models could not be refreshed. Confirm that Ollama is running, then try again.")
    #expect(!status.stringValue.contains("MODEL_MANAGER_SECRET_CANARY"))

    refresh.performClick(nil)
    ensureCompletions[1](.success(()))
    let fixture = qualifiedModel()
    modelCompletions[1](.success([fixture.0]))
    runningCompletions[0](.failure(HostileModelManagerError()))
    #expect(refresh.isEnabled)
    #expect(status.stringValue == "Installed local models could not be refreshed. Confirm that Ollama is running, then try again.")
    #expect(!status.stringValue.contains("MODEL_MANAGER_SECRET_CANARY"))

    refresh.performClick(nil)
    ensureCompletions[2](.success(()))
    modelCompletions[2](.success([fixture.0]))
    runningCompletions[1](.success([]))
    #expect(status.stringValue.contains("1 installed"))
}

@MainActor
@Test func modelManagerSelectionIsSingleFlightIgnoresDuplicateCompletionAndSanitizesFailure() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let directory = try modelManagerTemporaryDirectory("Selection")
    defer { try? FileManager.default.removeItem(at: directory) }

    var selectionCompletions: [(Result<ModelSelection, Error>) -> Void] = []
    var requestedModels: [String] = []
    var authoritativeSelection: ModelSelection?
    let controller = ModelManagerWindowController(
        client: OllamaClient(baseURLProvider: { nil }),
        activities: ActivityStore(applicationSupport: directory),
        ensureLocalService: { _ in },
        currentSelection: { authoritativeSelection },
        useModelForNewTasks: { model, completion in
            requestedModels.append(model)
            selectionCompletions.append(completion)
        },
        releaseModelMemory: { _, _ in }
    )
    let root = try #require(controller.window?.contentViewController?.view)
    let status = try modelManagerStatus(in: root)
    let table = try modelManagerTable(in: root)
    let fixture = qualifiedModel()
    controller.applyCatalogue(models: [fixture.0], running: [])
    table.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)
    controller.tableViewSelectionDidChange(Notification(name: NSTableView.selectionDidChangeNotification, object: table))
    let select = try modelManagerButton("Use for New Tasks", in: root)
    let refresh = try modelManagerButton("Refresh", in: root)

    select.performClick(nil)
    #expect(requestedModels == [fixture.0.name])
    #expect(!select.isEnabled)
    #expect(!refresh.isEnabled)
    #expect(!table.isEnabled)
    select.performClick(nil)
    #expect(requestedModels.count == 1)

    selectionCompletions[0](.failure(HostileModelManagerError()))
    #expect(table.isEnabled)
    #expect(refresh.isEnabled)
    #expect(!status.stringValue.contains("MODEL_MANAGER_SECRET_CANARY"))
    let failureMessage = status.stringValue
    selectionCompletions[0](.success(ModelSelection(route: ModelRoute(
        provider: BuiltInProviderDescriptors.ollama.id,
        model: BuiltInProviderDescriptors.qwenLocalModel.id
    ))))
    #expect(status.stringValue == failureMessage)

    table.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)
    controller.tableViewSelectionDidChange(Notification(name: NSTableView.selectionDidChangeNotification, object: table))
    #expect(select.isEnabled)
    select.performClick(nil)
    #expect(requestedModels.count == 2)
    authoritativeSelection = ModelSelection(route: ModelRoute(
        provider: BuiltInProviderDescriptors.ollama.id,
        model: BuiltInProviderDescriptors.qwenLocalModel.id
    ))
    selectionCompletions[1](.success(try #require(authoritativeSelection)))
    #expect(status.stringValue.contains("verified default"))
    #expect(table.selectedRow == 0)
    #expect(!select.isEnabled)
    let successMessage = status.stringValue
    selectionCompletions[1](.failure(HostileModelManagerError()))
    #expect(status.stringValue == successMessage)
}

@MainActor
@Test func modelManagerCompatibilitySelectionRequiresAnInjectedFreshConfirmation() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let directory = try modelManagerTemporaryDirectory("CompatibilityConsent")
    defer { try? FileManager.default.removeItem(at: directory) }

    var prompts: [String] = []
    var allow = false
    var requestedModels: [String] = []
    var completions: [(Result<ModelSelection, Error>) -> Void] = []
    let controller = ModelManagerWindowController(
        client: OllamaClient(baseURLProvider: { nil }),
        activities: ActivityStore(applicationSupport: directory),
        ensureLocalService: { _ in },
        currentSelection: { nil },
        useModelForNewTasks: { model, completion in
            requestedModels.append(model)
            completions.append(completion)
        },
        releaseModelMemory: { _, _ in },
        interactions: ModelManagerInteractions { model in
            prompts.append(model)
            return allow
        }
    )
    let root = try #require(controller.window?.contentViewController?.view)
    let table = try modelManagerTable(in: root)
    let model = compatibilityModel()
    controller.applyCatalogue(models: [model], running: [])
    table.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)
    controller.tableViewSelectionDidChange(Notification(
        name: NSTableView.selectionDidChangeNotification,
        object: table
    ))
    let select = try modelManagerButton("Use Compatibility Mode", in: root)

    select.performClick(nil)
    #expect(prompts == [model.name])
    #expect(requestedModels.isEmpty)
    #expect(select.isEnabled)

    allow = true
    select.performClick(nil)
    #expect(prompts == [model.name, model.name])
    #expect(requestedModels == [model.name])
    #expect(!select.isEnabled)
    completions[0](.failure(HostileModelManagerError()))
    #expect(select.isEnabled)
}

@MainActor
@Test func modelManagerUnloadIsSingleFlightAndRefreshesOnlyAfterVerifiedSuccess() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let directory = try modelManagerTemporaryDirectory("Unload")
    defer { try? FileManager.default.removeItem(at: directory) }

    var releaseCompletions: [(Result<Void, Error>) -> Void] = []
    var releasedModels: [String] = []
    var modelCompletions: [(Result<[OllamaModel], Error>) -> Void] = []
    var runningCompletions: [(Result<[OllamaRunningModel], Error>) -> Void] = []
    let controller = ModelManagerWindowController(
        client: OllamaClient(baseURLProvider: { nil }),
        activities: ActivityStore(applicationSupport: directory),
        ensureLocalService: { _ in },
        currentSelection: { nil },
        useModelForNewTasks: { _, _ in },
        releaseModelMemory: { model, completion in
            releasedModels.append(model)
            releaseCompletions.append(completion)
        },
        fetchModels: { modelCompletions.append($0) },
        fetchRunningModels: { runningCompletions.append($0) }
    )
    let root = try #require(controller.window?.contentViewController?.view)
    let status = try modelManagerStatus(in: root)
    let table = try modelManagerTable(in: root)
    let fixture = qualifiedModel(running: true)
    controller.applyCatalogue(models: [fixture.0], running: fixture.1)
    table.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)
    controller.tableViewSelectionDidChange(Notification(name: NSTableView.selectionDidChangeNotification, object: table))
    let unload = try modelManagerButton("Unload", in: root)

    unload.performClick(nil)
    #expect(releasedModels == [fixture.0.name])
    #expect(!unload.isEnabled)
    #expect(!table.isEnabled)
    unload.performClick(nil)
    #expect(releasedModels.count == 1)
    releaseCompletions[0](.failure(HostileModelManagerError()))
    #expect(table.isEnabled)
    #expect(unload.isEnabled)
    #expect(status.stringValue == "Model memory could not be released. The model remains available; try again after active local tasks finish.")
    #expect(!status.stringValue.contains("MODEL_MANAGER_SECRET_CANARY"))

    unload.performClick(nil)
    #expect(releasedModels.count == 2)
    releaseCompletions[1](.success(()))
    #expect(modelCompletions.count == 1)
    releaseCompletions[1](.success(()))
    #expect(modelCompletions.count == 1)
    modelCompletions[0](.success([fixture.0]))
    #expect(runningCompletions.count == 1)
    runningCompletions[0](.success([]))
    #expect(status.stringValue.contains("1 installed"))
    #expect(table.isEnabled)
    #expect(table.selectedRow == 0)
}
