import Foundation
import LocalHarnessDeviceAttestation
import Security

final class LocalHarnessTestDeviceAttestationKeyStore: DeviceAttestationRecoverableKeyStore, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String: Data] = [:]
    private var reads: [String] = []
    private var inserts: [String] = []
    private var deletes: [String] = []
    var deleteFailureAccount: String?

    func read(account: String) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        reads.append(account)
        return values[account]
    }

    func insert(_ data: Data, account: String) throws {
        lock.lock()
        defer { lock.unlock() }
        guard values[account] == nil else {
            throw DeviceAttestationError.invalidConfiguration
        }
        values[account] = data
        inserts.append(account)
    }

    func delete(account: String) throws {
        lock.lock()
        defer { lock.unlock() }
        if deleteFailureAccount == account {
            throw DeviceAttestationError.keychainFailure(errSecIO)
        }
        values.removeValue(forKey: account)
        deletes.append(account)
    }

    func removeForTest(account: String) {
        lock.lock()
        values.removeValue(forKey: account)
        lock.unlock()
    }

    func resetObservations() {
        lock.lock()
        reads.removeAll()
        inserts.removeAll()
        deletes.removeAll()
        lock.unlock()
    }

    func observations() -> (reads: [String], inserts: [String], deletes: [String]) {
        lock.lock()
        defer { lock.unlock() }
        return (reads, inserts, deletes)
    }
}
