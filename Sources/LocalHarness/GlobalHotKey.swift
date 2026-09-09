import Carbon
import Foundation

enum GlobalHotKeyRegistrationFailure: Error, Equatable, LocalizedError {
    case eventHandlerRegistrationFailed(OSStatus)
    case shortcutRegistrationFailed(OSStatus)

    var errorDescription: String? {
        switch self {
        case .eventHandlerRegistrationFailed(let status):
            return "The macOS hot-key event handler could not be installed (status \(status))."
        case .shortcutRegistrationFailed(let status):
            return "Option-Space is unavailable, usually because another app already uses it (status \(status))."
        }
    }
}

protocol GlobalHotKeyRegistrationToken: AnyObject {
    func invalidate()
}

protocol GlobalHotKeyRegistering: AnyObject {
    func register(
        keyCode: UInt32,
        modifiers: UInt32,
        action: @escaping () -> Void
    ) -> Result<GlobalHotKeyRegistrationToken, GlobalHotKeyRegistrationFailure>
}

/// User-facing state is independent of Carbon so a shortcut conflict always
/// leaves an explicit, testable menu and diagnostics fallback.
enum GlobalHotKeyAvailability: Equatable {
    case notAttempted
    case available
    case disabledForShutdown
    case unavailable(GlobalHotKeyRegistrationFailure)

    var statusMenuDetail: String? {
        switch self {
        case .disabledForShutdown:
            return "Option-Space disabled while shutdown is pending"
        case .unavailable:
            return "Option-Space unavailable — use Chat or ⌘⌥Space"
        case .notAttempted, .available:
            return nil
        }
    }

    var diagnosticSummary: String {
        switch self {
        case .notAttempted:
            return "Not attempted"
        case .available:
            return "Option-Space registered"
        case .disabledForShutdown:
            return "Disabled while shutdown is pending"
        case .unavailable(let failure):
            return failure.localizedDescription
        }
    }
}

final class GlobalHotKey {
    /// Registrars retain their callback while the platform registration exists.
    /// A callback may already be queued when registration teardown begins, so
    /// lifetime alone cannot suppress delivery. Close this independent gate
    /// before unregistering and every captured callback becomes a deterministic
    /// no-op after `invalidate()`.
    private final class ActionGate {
        private let lock = NSLock()
        private var action: (() -> Void)?

        init(action: @escaping () -> Void) {
            self.action = action
        }

        func invokeIfActive() {
            lock.lock()
            let action = self.action
            lock.unlock()
            action?()
        }

        func invalidate() {
            lock.lock()
            action = nil
            lock.unlock()
        }
    }

    private let lifecycleLock = NSLock()
    private let actionGate: ActionGate
    private var registration: GlobalHotKeyRegistrationToken?

    private init(registration: GlobalHotKeyRegistrationToken, actionGate: ActionGate) {
        self.registration = registration
        self.actionGate = actionGate
    }

    static func register(
        keyCode: UInt32,
        modifiers: UInt32,
        registrar: GlobalHotKeyRegistering = CarbonGlobalHotKeyRegistrar.shared,
        action: @escaping () -> Void
    ) -> Result<GlobalHotKey, GlobalHotKeyRegistrationFailure> {
        let actionGate = ActionGate(action: action)
        switch registrar.register(
            keyCode: keyCode,
            modifiers: modifiers,
            action: { actionGate.invokeIfActive() }
        ) {
        case .success(let registration):
            return .success(GlobalHotKey(registration: registration, actionGate: actionGate))
        case .failure(let failure):
            actionGate.invalidate()
            return .failure(failure)
        }
    }

    func invalidate() {
        // Close delivery first. Platform teardown cannot recall a callback that
        // has already been queued onto the main dispatch queue.
        actionGate.invalidate()
        lifecycleLock.lock()
        let registration = self.registration
        self.registration = nil
        lifecycleLock.unlock()
        registration?.invalidate()
    }

    deinit { invalidate() }
}

final class CarbonGlobalHotKeyRegistrar: GlobalHotKeyRegistering {
    static let shared = CarbonGlobalHotKeyRegistrar()

    private final class Token: GlobalHotKeyRegistrationToken {
        let action: () -> Void
        private let lifecycleLock = NSLock()
        var hotKeyRef: EventHotKeyRef?
        var eventHandlerRef: EventHandlerRef?
        private var invalidated = false

        init(action: @escaping () -> Void) {
            self.action = action
        }

        func invalidate() {
            lifecycleLock.lock()
            guard !invalidated else {
                lifecycleLock.unlock()
                return
            }
            invalidated = true
            let hotKeyRef = self.hotKeyRef
            let eventHandlerRef = self.eventHandlerRef
            self.hotKeyRef = nil
            self.eventHandlerRef = nil
            lifecycleLock.unlock()
            if let hotKeyRef {
                UnregisterEventHotKey(hotKeyRef)
            }
            if let eventHandlerRef {
                RemoveEventHandler(eventHandlerRef)
            }
        }

        deinit { invalidate() }
    }

    private init() {}

    func register(
        keyCode: UInt32,
        modifiers: UInt32,
        action: @escaping () -> Void
    ) -> Result<GlobalHotKeyRegistrationToken, GlobalHotKeyRegistrationFailure> {
        let token = Token(action: action)
        var eventType = EventTypeSpec(
            eventClass: OSType(kEventClassKeyboard),
            eventKind: UInt32(kEventHotKeyPressed)
        )
        let handlerStatus = InstallEventHandler(
            GetApplicationEventTarget(),
            { _, _, userData in
                guard let userData else { return noErr }
                let token = Unmanaged<Token>.fromOpaque(userData).takeUnretainedValue()
                DispatchQueue.main.async { token.action() }
                return noErr
            },
            1,
            &eventType,
            Unmanaged.passUnretained(token).toOpaque(),
            &token.eventHandlerRef
        )
        guard handlerStatus == noErr, token.eventHandlerRef != nil else {
            token.invalidate()
            return .failure(.eventHandlerRegistrationFailed(handlerStatus))
        }

        let hotKeyID = EventHotKeyID(signature: OSType(0x46554C4D), id: 1) // FULM
        let registrationStatus = RegisterEventHotKey(
            keyCode,
            modifiers,
            hotKeyID,
            GetApplicationEventTarget(),
            0,
            &token.hotKeyRef
        )
        guard registrationStatus == noErr, token.hotKeyRef != nil else {
            token.invalidate()
            return .failure(.shortcutRegistrationFailed(registrationStatus))
        }
        return .success(token)
    }
}
