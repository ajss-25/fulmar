import Foundation

/// The irreversible privacy boundary for provider-owned conversation state.
///
/// A Harness home is current only when both the receipt schema and this epoch
/// match. Older receipts are deliberately treated as historical data: their
/// whole home is moved, without inspecting its child namespace, into the
/// authenticated recovery area before a new runtime is admitted.
enum ProviderHistoryPrivacyEpoch {
    static let current = 1
    static let currentHarnessHomeReceiptVersion = 3
    static let ownershipReceiptName = ".local-harness-home.json"

    /// These are the only historical-home leaves that may be opened. Everything
    /// else, including sessions, storage, attachments, profiles, Skills, and
    /// unknown future provider state, remains opaque in the preserved home.
    static let settingsFileNames: Set<String> = ["settings.json", "settings.yaml"]

    static func isCurrent(receiptVersion: Int, epoch: Int?) -> Bool {
        receiptVersion == currentHarnessHomeReceiptVersion && epoch == current
    }
}

/// An explicit foreground decision made before historical provider state is
/// moved or any recovery credential is accessed.
enum ProviderHistoryRecoveryChoice: String, Codable, Equatable, Sendable {
    case settingsOnly
    case startClean
}
