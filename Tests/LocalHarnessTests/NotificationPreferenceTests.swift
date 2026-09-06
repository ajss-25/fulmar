import Foundation
import Testing
import UserNotifications
@testable import LocalHarness

@Test func notificationsAreOptInOnACleanInstall() throws {
    let suite = "FulmarNotificationDefaults.\(UUID().uuidString)"
    let defaults = try #require(UserDefaults(suiteName: suite))
    defaults.removePersistentDomain(forName: suite)
    defer { defaults.removePersistentDomain(forName: suite) }

    let preferences = PreferencesStore(defaults: defaults)
    var authorizationRequests = 0
    var deliveredRequests = 0
    let manager = NotificationManager(
        preferences: preferences,
        requestAuthorization: { authorizationRequests += 1 },
        deliver: { _ in deliveredRequests += 1 }
    )

    manager.prepare()
    manager.send(title: "Private task", body: "Finished")

    #expect(preferences.notificationsEnabled == false)
    #expect(authorizationRequests == 0)
    #expect(deliveredRequests == 0)
}
@Test func explicitNotificationOptInRequestsAuthorizationAndAllowsDelivery() throws {
    let suite = "FulmarNotificationOptIn.\(UUID().uuidString)"
    let defaults = try #require(UserDefaults(suiteName: suite))
    defaults.removePersistentDomain(forName: suite)
    defer { defaults.removePersistentDomain(forName: suite) }

    let preferences = PreferencesStore(defaults: defaults)
    preferences.notificationsEnabled = true
    var authorizationRequests = 0
    var deliveredRequests = 0
    let manager = NotificationManager(
        preferences: preferences,
        requestAuthorization: { authorizationRequests += 1 },
        deliver: { _ in deliveredRequests += 1 }
    )

    manager.prepare()
    manager.send(title: "Task", body: "Finished")

    #expect(authorizationRequests == 1)
    #expect(deliveredRequests == 1)
}
