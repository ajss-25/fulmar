import AppKit
import Testing
@testable import LocalHarness

@MainActor
@Test func mainMenuShortcutCatalogHasUniqueReservedAwareChordsAndStableSelectors() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    #expect(MainMenuShortcutCatalog.duplicateChords.isEmpty)
    let commands = Dictionary(
        uniqueKeysWithValues: MainMenuShortcutCatalog.fulmarCommands.map { ($0.id, $0) }
    )
    #expect(commands.count == MainMenuShortcutCatalog.fulmarCommands.count)

    let expected: [(String, String, Selector, String, NSEvent.ModifierFlags)] = [
        ("settings", "Settings…", #selector(AppDelegate.showSettings(_:)), ",", [.command]),
        ("new-session", "New Session", #selector(AppDelegate.newSession(_:)), "n", [.command]),
        ("chat", "Chat", #selector(AppDelegate.showQuickChat(_:)), " ", [.command, .option]),
        ("command-center", "Command Center…", #selector(AppDelegate.showCommandCenter(_:)), "k", [.command]),
        ("appshot", "Capture Appshot", #selector(AppDelegate.captureAppshot(_:)), "2", [.command, .shift]),
        ("activity", "Activity Center", #selector(AppDelegate.showActivityCenter(_:)), "0", [.command, .shift]),
        ("history", "Task History", #selector(AppDelegate.showTaskHistory(_:)), "y", [.command, .shift]),
        ("find", "Find…", #selector(AppDelegate.findInPage(_:)), "f", [.command]),
        ("back", "Back", #selector(AppDelegate.goBack(_:)), "[", [.command]),
        ("forward", "Forward", #selector(AppDelegate.goForward(_:)), "]", [.command]),
        ("reload", "Reload Agent Workspace", #selector(AppDelegate.reloadHarness(_:)), "r", [.command]),
        ("actual-size", "Actual Size", #selector(AppDelegate.actualSize(_:)), "0", [.command]),
        ("zoom-in", "Zoom In", #selector(AppDelegate.zoomIn(_:)), "+", [.command]),
        ("zoom-out", "Zoom Out", #selector(AppDelegate.zoomOut(_:)), "-", [.command]),
        ("main-window", ProductBrand.displayName, #selector(AppDelegate.showMainWindow(_:)), "1", [.command])
    ]

    for (id, title, action, key, modifiers) in expected {
        let command = try #require(commands[id])
        #expect(command.title == title)
        #expect(NSStringFromSelector(command.action) == NSStringFromSelector(action))
        #expect(command.shortcut.keyEquivalent == key)
        #expect(command.shortcut.modifiers == modifiers)
    }
}

@Test func shortcutChordNormalizationDetectsCaseInsensitiveDuplicates() {
    let lower = MainMenuShortcutChord(keyEquivalent: "z", modifiers: [.command, .shift])
    let upper = MainMenuShortcutChord(keyEquivalent: "Z", modifiers: [.command, .shift])
    #expect(lower == upper)
    #expect(Set([lower, upper]).count == 1)
}

@MainActor
@Test func builtMenuConsumptionRejectsMissingDuplicateAndMiswiredCommands() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let target = NSObject()
    let root = NSMenu(title: "Test Main Menu")
    let commandsMenu = NSMenu(title: "Commands")
    let commandsItem = NSMenuItem(title: "Commands", action: nil, keyEquivalent: "")
    commandsItem.submenu = commandsMenu
    root.addItem(commandsItem)

    for command in MainMenuShortcutCatalog.fulmarCommands {
        let item = NSMenuItem(
            title: command.title,
            action: command.action,
            keyEquivalent: command.shortcut.keyEquivalent
        )
        item.target = target
        item.keyEquivalentModifierMask = command.shortcut.modifiers
        commandsMenu.addItem(item)
    }
    #expect(MainMenuShortcutCatalog.builtMenuConsumesEveryCommandExactlyOnce(root, target: target))
    #expect(
        MainMenuShortcutCatalog.builtMenuConsumption(in: root, target: target)
            == Dictionary(uniqueKeysWithValues: MainMenuShortcutCatalog.fulmarCommands.map { ($0.id, 1) })
    )

    let removed = try #require(commandsMenu.item(at: 0))
    commandsMenu.removeItem(at: 0)
    #expect(!MainMenuShortcutCatalog.builtMenuConsumesEveryCommandExactlyOnce(root, target: target))
    commandsMenu.insertItem(removed, at: 0)

    let duplicate = NSMenuItem(
        title: MainMenuShortcutCatalog.chat.title,
        action: MainMenuShortcutCatalog.chat.action,
        keyEquivalent: MainMenuShortcutCatalog.chat.shortcut.keyEquivalent
    )
    duplicate.target = target
    duplicate.keyEquivalentModifierMask = MainMenuShortcutCatalog.chat.shortcut.modifiers
    commandsMenu.addItem(duplicate)
    #expect(!MainMenuShortcutCatalog.builtMenuConsumesEveryCommandExactlyOnce(root, target: target))
    commandsMenu.removeItem(duplicate)

    let settings = try #require(commandsMenu.items.first {
        $0.title == MainMenuShortcutCatalog.settings.title
    })
    settings.keyEquivalent = "x"
    #expect(!MainMenuShortcutCatalog.builtMenuConsumesEveryCommandExactlyOnce(root, target: target))
    settings.keyEquivalent = MainMenuShortcutCatalog.settings.shortcut.keyEquivalent
    let wrongTarget = NSObject()
    settings.target = wrongTarget
    withExtendedLifetime(wrongTarget) {
        #expect(!MainMenuShortcutCatalog.builtMenuConsumesEveryCommandExactlyOnce(root, target: target))
    }
}
