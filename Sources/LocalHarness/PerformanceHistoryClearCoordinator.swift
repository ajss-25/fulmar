import Foundation

enum PerformanceHistoryClearOutcome: Equatable, Sendable {
    case success
    /// Deliberately content-free. Storage errors can contain private paths,
    /// hostile control characters, or implementation details supplied by a
    /// lower layer. The UI owns the bounded recovery message.
    case failure
}

/// Keeps the bounded cross-process lock wait and durability work off AppKit's
/// main thread while exposing one small, duplicate-safe UI operation.
@MainActor
final class PerformanceHistoryClearCoordinator {
    enum State: Equatable, Sendable {
        case idle
        case clearing
    }

    typealias StorageClear = @Sendable (URL) throws -> Void

    private let applicationSupport: URL
    private let storageClear: StorageClear
    private(set) var state: State = .idle

    nonisolated init(
        applicationSupport: URL,
        storageClear: @escaping StorageClear = { applicationSupport in
            _ = try GenerationTelemetrySpool.clear(applicationSupport: applicationSupport)
        }
    ) {
        self.applicationSupport = applicationSupport
        self.storageClear = storageClear
    }

    @discardableResult
    func clear(
        completion: @escaping @MainActor (PerformanceHistoryClearOutcome) -> Void
    ) -> Bool {
        guard state == .idle else { return false }
        state = .clearing
        let applicationSupport = applicationSupport
        let storageClear = storageClear
        Task { @MainActor [weak self] in
            let outcome = await Task.detached(priority: .utility) {
                do {
                    try storageClear(applicationSupport)
                    return PerformanceHistoryClearOutcome.success
                } catch {
                    return PerformanceHistoryClearOutcome.failure
                }
            }.value
            guard let self else { return }
            self.state = .idle
            completion(outcome)
        }
        return true
    }
}
