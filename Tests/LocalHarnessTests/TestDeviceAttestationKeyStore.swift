import Foundation
import LocalHarnessDeviceAttestation
import Security

/// Holds a background key-store read open until the test releases it, standing
/// in for the native Keychain panel being on screen while the app keeps
/// running its main loop. The wait happens outside the store's own lock so the
/// main thread can still observe and mutate the controller meanwhile, and it is
/// hard-bounded so a test that forgets to open it fails rather than hangs.
final class LocalHarnessTestDeviceAttestationReadGate: @unchecked Sendable {
    private let condition = NSCondition()
    private var isOpen = false
    private var arrivedReads = 0

    /// Number of background reads that have reached the gate.
    var arrivals: Int {
        condition.lock()
        defer { condition.unlock() }
        return arrivedReads
    }

    func open() {
        condition.lock()
        isOpen = true
        condition.broadcast()
        condition.unlock()
    }

    func waitUntilOpen(bound: TimeInterval = 10) {
        condition.lock()
        arrivedReads += 1
        condition.broadcast()
        let deadline = Date().addingTimeInterval(bound)
        while !isOpen, Date() < deadline {
            _ = condition.wait(until: deadline)
        }
        condition.unlock()
    }
}

final class LocalHarnessTestDeviceAttestationKeyStore: DeviceAttestationRecoverableKeyStore, @unchecked Sendable {
    private let lock = NSLock()
    private let gateLock = NSLock()
    private var readGate: LocalHarnessTestDeviceAttestationReadGate?
    private var values: [String: Data] = [:]
    private var reads: [String] = []
    private var inserts: [String] = []
    private var deletes: [String] = []
    var deleteFailureAccount: String?
    private var readFailure: DeviceAttestationError?
    private var backing: LocalHarnessTestDeviceAttestationKeyStore?

    init() {}

    /// A view over another store's values that can be made to refuse reads,
    /// standing in for the production noninteractive Keychain store whose
    /// read is refused (`errSecInteractionNotAllowed`) or cancelled while the
    /// interactive store sees the same items.
    init(sharing backing: LocalHarnessTestDeviceAttestationKeyStore, readFailure: DeviceAttestationError?) {
        self.backing = backing
        self.readFailure = readFailure
    }

    func setReadFailure(_ failure: DeviceAttestationError?) {
        lock.lock()
        readFailure = failure
        lock.unlock()
    }

    /// Suspends every subsequent read at `gate` until the test opens it.
    func setReadGate(_ gate: LocalHarnessTestDeviceAttestationReadGate?) {
        gateLock.lock()
        readGate = gate
        gateLock.unlock()
    }

    private var currentReadGate: LocalHarnessTestDeviceAttestationReadGate? {
        gateLock.lock()
        defer { gateLock.unlock() }
        return readGate
    }

    func read(account: String) throws -> Data? {
        // Deliberately outside `lock`: the main thread must stay able to
        // observe and drive the controller while this read is held open.
        currentReadGate?.waitUntilOpen()
        lock.lock()
        defer { lock.unlock() }
        reads.append(account)
        if let readFailure { throw readFailure }
        if let backing { return try backing.read(account: account) }
        return values[account]
    }

    func insert(_ data: Data, account: String) throws {
        lock.lock()
        defer { lock.unlock() }
        if let backing {
            try backing.insert(data, account: account)
            inserts.append(account)
            return
        }
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
        deletes.append(account)
        if let backing { try backing.delete(account: account); return }
        values.removeValue(forKey: account)
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
