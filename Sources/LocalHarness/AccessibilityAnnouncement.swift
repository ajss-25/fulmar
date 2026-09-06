import AppKit

/// Announces only meaningful, bounded native state transitions. Streaming
/// tokens and rapidly changing metrics deliberately do not use this path.
@MainActor
enum AccessibilityAnnouncement {
    static func post(
        _ message: String,
        priority: NSAccessibilityPriorityLevel = .medium,
        element: Any? = nil
    ) {
        let bounded = String(message.trimmingCharacters(in: .whitespacesAndNewlines).prefix(1_000))
        guard !bounded.isEmpty else { return }
        NSAccessibility.post(
            element: element ?? NSApp as Any,
            notification: .announcementRequested,
            userInfo: [
                .announcement: bounded,
                .priority: priority.rawValue
            ]
        )
    }
}
