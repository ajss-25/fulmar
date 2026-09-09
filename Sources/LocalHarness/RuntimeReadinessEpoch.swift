import Foundation

/// Main-actor generation gate for every asynchronous runtime-readiness path.
///
/// A protected transition rotates the epoch synchronously before it awaits
/// cancellation or process shutdown. Completion work captured by the previous
/// runtime can therefore never reopen Web, native, or schedule admissions.
@MainActor
final class RuntimeReadinessEpoch {
    private(set) var current: UUID

    init(current: UUID = UUID()) {
        self.current = current
    }

    @discardableResult
    func rotate() -> UUID {
        let replacement = UUID()
        current = replacement
        return replacement
    }

    /// Runs a readiness publication atomically with respect to every other
    /// main-actor lifecycle transition.
    @discardableResult
    func performIfCurrent(_ captured: UUID, _ action: () -> Void) -> Bool {
        guard captured == current else { return false }
        action()
        return true
    }
}
