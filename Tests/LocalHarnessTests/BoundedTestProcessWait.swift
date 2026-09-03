import Darwin
import Foundation

/// Test processes must never be able to hang the qualification runner. The
/// normal path only observes Foundation's exact `Process`; timeout cleanup
/// signals that exact PID and remains bounded as well.
@discardableResult
func boundedTestWaitForExit(
    _ process: Process,
    timeout: TimeInterval = 20,
    terminateOnTimeout: Bool = true
) -> Bool {
    guard timeout.isFinite, timeout >= 0 else { return false }
    let start = DispatchTime.now().uptimeNanoseconds
    let duration = UInt64(min(timeout, 120) * 1_000_000_000)
    let (candidate, overflow) = start.addingReportingOverflow(duration)
    let deadline = overflow ? UInt64.max : candidate
    while process.isRunning, DispatchTime.now().uptimeNanoseconds < deadline {
        Darwin.usleep(10_000)
    }
    guard process.isRunning else { return true }
    guard terminateOnTimeout else { return false }

    process.terminate()
    let graceful = DispatchTime.now().uptimeNanoseconds &+ 250_000_000
    while process.isRunning, DispatchTime.now().uptimeNanoseconds < graceful {
        Darwin.usleep(10_000)
    }
    if process.isRunning {
        _ = Darwin.kill(process.processIdentifier, SIGKILL)
    }
    let forced = DispatchTime.now().uptimeNanoseconds &+ 2_000_000_000
    while process.isRunning, DispatchTime.now().uptimeNanoseconds < forced {
        Darwin.usleep(10_000)
    }
    return !process.isRunning
}
