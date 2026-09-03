import Foundation
import UserNotifications

final class NotificationManager {
    typealias AuthorizationRequester = () -> Void
    typealias RequestDeliverer = (UNNotificationRequest) -> Void

    private let preferences: PreferencesStore
    private let requestAuthorization: AuthorizationRequester
    private let deliver: RequestDeliverer

    init(
        preferences: PreferencesStore,
        requestAuthorization: AuthorizationRequester? = nil,
        deliver: RequestDeliverer? = nil
    ) {
        self.preferences = preferences
        self.requestAuthorization = requestAuthorization ?? {
            UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
        }
        self.deliver = deliver ?? { request in
            UNUserNotificationCenter.current().add(request)
        }
    }

    func prepare() {
        guard preferences.notificationsEnabled else { return }
        requestAuthorization()
    }

    func send(title: String, body: String, identifier: String = UUID().uuidString) {
        guard preferences.notificationsEnabled else { return }
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        let request = UNNotificationRequest(identifier: identifier, content: content, trigger: nil)
        deliver(request)
    }
}
