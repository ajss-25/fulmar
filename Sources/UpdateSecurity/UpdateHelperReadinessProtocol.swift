import Foundation

/// The update helper's one-way, pre-parent-wait readiness protocol.
///
/// The parent maps a newly-created anonymous pipe to this otherwise-unused
/// descriptor with `posix_spawn` file actions. `POSIX_SPAWN_CLOEXEC_DEFAULT`
/// prevents any ambient descriptor from becoming an alternate writer. The
/// helper accepts the protocol only when the exact version argument is also
/// present, writes the one fixed frame, and closes the descriptor.
public enum UpdateHelperReadinessProtocol {
    public static let argument = "--local-harness-update-helper-readiness-v1"
    public static let childDescriptor: Int32 = 3
    public static let frame = Data("LOCAL_HARNESS_UPDATE_HELPER_READY_V1\n".utf8)

    /// The app's terminal shutdown barrier can legitimately spend up to 52
    /// seconds forcing an exact-process stop after a quiescence timeout. Keep
    /// the already-attested helper alive beyond that complete bound so a slow
    /// but successful protected Quit cannot close the app without installing
    /// the update. This remains finite so a cancelled Quit never leaves an
    /// orphaned installer waiting forever.
    public static let parentExitMaximumPolls = 1_200
    public static let parentExitPollMicroseconds: UInt32 = 100_000
}
