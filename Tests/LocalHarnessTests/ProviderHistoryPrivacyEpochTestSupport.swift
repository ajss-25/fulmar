import Foundation
@testable import LocalHarness

/// Writes the exact clean Harness-home receipt admitted by backup and runtime
/// migration tests. Production never calls this helper.
func writeCurrentProviderHistoryPrivacyReceipt(at home: URL) throws {
    let receipt: [String: Any] = [
        "version": ProviderHistoryPrivacyEpoch.currentHarnessHomeReceiptVersion,
        "migratedAt": 0.0,
        "copiedEntries": [String](),
        "providerHistoryPrivacyEpoch": ProviderHistoryPrivacyEpoch.current
    ]
    let data = try JSONSerialization.data(withJSONObject: receipt, options: [.sortedKeys])
    let url = home.appendingPathComponent(".local-harness-home.json", isDirectory: false)
    try data.write(to: url, options: .withoutOverwriting)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
}
