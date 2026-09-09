import AppKit

struct MainMenuShortcutChord: Hashable {
    let keyEquivalent: String
    let modifiers: NSEvent.ModifierFlags

    var normalizedKey: String { keyEquivalent.lowercased() }

    static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.normalizedKey == rhs.normalizedKey
            && lhs.modifiers.rawValue == rhs.modifiers.rawValue
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(normalizedKey)
        hasher.combine(modifiers.rawValue)
    }
}

struct MainMenuCommandDescriptor {
    let id: String
    let title: String
    let action: Selector
    let shortcut: MainMenuShortcutChord
}

/// One source of truth for Fulmar-owned main-menu shortcuts. Framework-owned
/// editing/window chords are listed as reservations so new commands cannot
/// silently steal a standard macOS shortcut.
@MainActor
enum MainMenuShortcutCatalog {
    static let settings = command("settings", "Settings…", #selector(AppDelegate.showSettings(_:)), ",")
    static let newSession = command("new-session", "New Session", #selector(AppDelegate.newSession(_:)), "n")
    static let chat = command("chat", "Chat", #selector(AppDelegate.showQuickChat(_:)), " ", [.command, .option])
    static let commandCenter = command("command-center", "Command Center…", #selector(AppDelegate.showCommandCenter(_:)), "k")
    static let appshot = command("appshot", "Capture Appshot", #selector(AppDelegate.captureAppshot(_:)), "2", [.command, .shift])
    static let activity = command("activity", "Activity Center", #selector(AppDelegate.showActivityCenter(_:)), "0", [.command, .shift])
    static let history = command("history", "Task History", #selector(AppDelegate.showTaskHistory(_:)), "y", [.command, .shift])
    static let find = command("find", "Find…", #selector(AppDelegate.findInPage(_:)), "f")
    static let back = command("back", "Back", #selector(AppDelegate.goBack(_:)), "[")
    static let forward = command("forward", "Forward", #selector(AppDelegate.goForward(_:)), "]")
    static let reload = command("reload", "Reload Agent Workspace", #selector(AppDelegate.reloadHarness(_:)), "r")
    static let actualSize = command("actual-size", "Actual Size", #selector(AppDelegate.actualSize(_:)), "0")
    static let zoomIn = command("zoom-in", "Zoom In", #selector(AppDelegate.zoomIn(_:)), "+")
    static let zoomOut = command("zoom-out", "Zoom Out", #selector(AppDelegate.zoomOut(_:)), "-")
    static let mainWindow = command("main-window", ProductBrand.displayName, #selector(AppDelegate.showMainWindow(_:)), "1")

    static let fulmarCommands: [MainMenuCommandDescriptor] = [
        settings, newSession, chat, commandCenter, appshot, activity, history,
        find, back, forward, reload, actualSize, zoomIn, zoomOut, mainWindow
    ]

    static let reservedSystemChords: [MainMenuShortcutChord] = [
        chord("h"), chord("h", [.command, .option]), chord("q"), chord("w"),
        chord("z"), chord("z", [.command, .shift]), chord("x"), chord("c"),
        chord("v"), chord("a"), chord(" ", [.command, .control]),
        chord("f", [.command, .control]), chord("m")
    ]

    static var duplicateChords: Set<MainMenuShortcutChord> {
        var seen = Set<MainMenuShortcutChord>()
        var duplicates = Set<MainMenuShortcutChord>()
        for shortcut in fulmarCommands.map(\.shortcut) + reservedSystemChords {
            if !seen.insert(shortcut).inserted { duplicates.insert(shortcut) }
        }
        return duplicates
    }

    /// Validates the menu AppKit will actually route, rather than only the
    /// descriptor catalogue. A command counts only when title, selector, key,
    /// and modifiers all match, so a similarly named responder-chain item cannot
    /// mask a missing or miswired Fulmar command.
    static func builtMenuConsumption(in root: NSMenu, target: AnyObject? = nil) -> [String: Int] {
        var counts = Dictionary(uniqueKeysWithValues: fulmarCommands.map { ($0.id, 0) })

        func visit(_ menu: NSMenu) {
            for item in menu.items {
                for command in fulmarCommands where itemMatches(item, command: command, target: target) {
                    counts[command.id, default: 0] += 1
                }
                if let submenu = item.submenu { visit(submenu) }
            }
        }
        visit(root)
        return counts
    }

    static func builtMenuConsumesEveryCommandExactlyOnce(
        _ root: NSMenu,
        target: AnyObject? = nil
    ) -> Bool {
        let counts = builtMenuConsumption(in: root, target: target)
        return counts.count == fulmarCommands.count && counts.values.allSatisfy { $0 == 1 }
    }

    private static func itemMatches(
        _ item: NSMenuItem,
        command: MainMenuCommandDescriptor,
        target: AnyObject?
    ) -> Bool {
        item.title == command.title
            && item.action == command.action
            && item.keyEquivalent.lowercased() == command.shortcut.normalizedKey
            && item.keyEquivalentModifierMask == command.shortcut.modifiers
            && (target == nil || item.target === target)
    }

    private static func command(
        _ id: String,
        _ title: String,
        _ action: Selector,
        _ key: String,
        _ modifiers: NSEvent.ModifierFlags = [.command]
    ) -> MainMenuCommandDescriptor {
        MainMenuCommandDescriptor(
            id: id,
            title: title,
            action: action,
            shortcut: chord(key, modifiers)
        )
    }

    private static func chord(
        _ key: String,
        _ modifiers: NSEvent.ModifierFlags = [.command]
    ) -> MainMenuShortcutChord {
        MainMenuShortcutChord(keyEquivalent: key, modifiers: modifiers)
    }
}
