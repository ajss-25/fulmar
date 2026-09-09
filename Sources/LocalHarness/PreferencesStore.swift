import Foundation

final class PreferencesStore {
    static let shared = PreferencesStore()

    private enum Key {
        static let confirmExternalLinks = "confirmExternalLinks"
        static let notificationsEnabled = "notificationsEnabled"
        static let autoRestartHarness = "autoRestartHarness"
        static let strictLocalMode = "strictLocalMode"
        static let allowCommunityPlugins = "allowCommunityPlugins"
        static let appshotRetentionDays = "appshotRetentionDays"
        static let attachmentRetentionDays = "attachmentRetentionDays"
        static let unloadModelWhenIdle = "unloadModelWhenIdle"
        static let selectedLocalModel = "selectedLocalModel"
        static let excludedCaptureBundleIdentifiers = "excludedCaptureBundleIdentifiers"
        static let allowSSHAgent = "allowSSHAgent"
        static let thermalSafetyCooldownUntil = "thermalSafetyCooldownUntil"
        static let thermalSafetyTrigger = "thermalSafetyTrigger"
    }

    private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        defaults.register(defaults: [
            Key.confirmExternalLinks: true,
            // Permission-bearing features are opt-in. Registering `true` here
            // made a clean install ask for notification access at launch even
            // though the product and privacy documentation promise otherwise.
            Key.notificationsEnabled: false,
            Key.autoRestartHarness: true,
            Key.strictLocalMode: true,
            Key.allowCommunityPlugins: false,
            Key.appshotRetentionDays: 7,
            Key.attachmentRetentionDays: 30,
            Key.unloadModelWhenIdle: true,
            Key.allowSSHAgent: false,
            Key.selectedLocalModel: "qwen3.8:27b-mlx",
            Key.excludedCaptureBundleIdentifiers: [
                "com.1password.1password", "com.apple.keychainaccess", "com.bitwarden.desktop", "com.lastpass.LastPass"
            ]
        ])
    }

    var confirmExternalLinks: Bool {
        get { defaults.bool(forKey: Key.confirmExternalLinks) }
        set { defaults.set(newValue, forKey: Key.confirmExternalLinks) }
    }

    var notificationsEnabled: Bool {
        get { defaults.bool(forKey: Key.notificationsEnabled) }
        set { defaults.set(newValue, forKey: Key.notificationsEnabled) }
    }

    var autoRestartHarness: Bool {
        get { defaults.bool(forKey: Key.autoRestartHarness) }
        set { defaults.set(newValue, forKey: Key.autoRestartHarness) }
    }

    var strictLocalMode: Bool {
        get { defaults.bool(forKey: Key.strictLocalMode) }
        set { defaults.set(newValue, forKey: Key.strictLocalMode) }
    }

    var allowCommunityPlugins: Bool {
        get { defaults.bool(forKey: Key.allowCommunityPlugins) }
        set { defaults.set(newValue, forKey: Key.allowCommunityPlugins) }
    }

    var appshotRetentionDays: Int {
        get { max(1, defaults.integer(forKey: Key.appshotRetentionDays)) }
        set { defaults.set(max(1, newValue), forKey: Key.appshotRetentionDays) }
    }

    var attachmentRetentionDays: Int {
        get { max(1, defaults.integer(forKey: Key.attachmentRetentionDays)) }
        set { defaults.set(max(1, newValue), forKey: Key.attachmentRetentionDays) }
    }

    var unloadModelWhenIdle: Bool {
        get { defaults.bool(forKey: Key.unloadModelWhenIdle) }
        set { defaults.set(newValue, forKey: Key.unloadModelWhenIdle) }
    }

    var selectedLocalModel: String {
        get { defaults.string(forKey: Key.selectedLocalModel) ?? "qwen3.8:27b-mlx" }
        set { defaults.set(newValue, forKey: Key.selectedLocalModel) }
    }

    var excludedCaptureBundleIdentifiers: [String] {
        get { defaults.stringArray(forKey: Key.excludedCaptureBundleIdentifiers) ?? [] }
        set { defaults.set(Array(Set(newValue)).sorted(), forKey: Key.excludedCaptureBundleIdentifiers) }
    }

    var allowSSHAgent: Bool {
        get { defaults.bool(forKey: Key.allowSSHAgent) }
        set { defaults.set(newValue, forKey: Key.allowSSHAgent) }
    }

    func thermalSafetyCooldown(now: Date = Date()) -> (trigger: ThermalSafetyTrigger, until: Date)? {
        let rawDate = defaults.double(forKey: Key.thermalSafetyCooldownUntil)
        guard rawDate.isFinite,
              rawDate > 0,
              let rawTrigger = defaults.string(forKey: Key.thermalSafetyTrigger),
              let trigger = ThermalSafetyTrigger(rawValue: rawTrigger) else {
            clearThermalSafetyCooldown()
            return nil
        }
        let until = Date(timeIntervalSince1970: rawDate)
        // Production cooldowns are at most ten minutes. A malformed, stale,
        // or externally extended value must not lock the app indefinitely.
        guard until > now, until.timeIntervalSince(now) <= 3_600 else {
            clearThermalSafetyCooldown()
            return nil
        }
        return (trigger, until)
    }

    func recordThermalSafetyCooldown(trigger: ThermalSafetyTrigger, until: Date) {
        defaults.set(until.timeIntervalSince1970, forKey: Key.thermalSafetyCooldownUntil)
        defaults.set(trigger.rawValue, forKey: Key.thermalSafetyTrigger)
        defaults.synchronize()
    }

    func clearThermalSafetyCooldown() {
        defaults.removeObject(forKey: Key.thermalSafetyCooldownUntil)
        defaults.removeObject(forKey: Key.thermalSafetyTrigger)
        defaults.synchronize()
    }
}
