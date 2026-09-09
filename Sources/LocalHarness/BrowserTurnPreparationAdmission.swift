import Foundation

enum BrowserTurnPreparationAdmission: Equatable, Sendable {
    case accepted
    case duplicateOperation
    case atCapacity
}

/// A main-actor admission boundary for browser-triggered recovery work.
///
/// Web content can issue requests faster than the filesystem and RPC recovery
/// path can complete them. Keeping the identities in a bounded, actor-isolated
/// set makes the capacity decision atomic before AppDelegate creates a task or
/// adds an entry to `activeBrowserTurnPreparations`.
@MainActor
final class BrowserTurnPreparationAdmissionGate {
    nonisolated static let productionMaximumConcurrent = 8
    nonisolated static let productionCompletedReplayCapacity = 4_096

    private let maximumConcurrent: Int
    private let completedReplayCapacity: Int
    private var admittedOperationIDs: Set<UUID> = []
    private var completedReplaySet: Set<UUID> = []
    private var completedReplayOrder: [UUID] = []
    private var completedReplayCursor = 0

    init(
        maximumConcurrent: Int = productionMaximumConcurrent,
        completedReplayCapacity: Int = productionCompletedReplayCapacity
    ) {
        precondition(maximumConcurrent > 0)
        precondition(completedReplayCapacity > 0)
        self.maximumConcurrent = maximumConcurrent
        self.completedReplayCapacity = completedReplayCapacity
    }

    var count: Int { admittedOperationIDs.count }
    var completedReplayCount: Int { completedReplaySet.count }

    func admit(_ operationID: UUID) -> BrowserTurnPreparationAdmission {
        guard !admittedOperationIDs.contains(operationID),
              !completedReplaySet.contains(operationID) else {
            return .duplicateOperation
        }
        guard admittedOperationIDs.count < maximumConcurrent else {
            return .atCapacity
        }
        admittedOperationIDs.insert(operationID)
        return .accepted
    }

    @discardableResult
    func release(_ operationID: UUID) -> Bool {
        guard admittedOperationIDs.remove(operationID) != nil else { return false }
        if completedReplayOrder.count < completedReplayCapacity {
            completedReplayOrder.append(operationID)
        } else {
            let evicted = completedReplayOrder[completedReplayCursor]
            completedReplaySet.remove(evicted)
            completedReplayOrder[completedReplayCursor] = operationID
            completedReplayCursor = (completedReplayCursor + 1) % completedReplayCapacity
        }
        completedReplaySet.insert(operationID)
        return true
    }
}
