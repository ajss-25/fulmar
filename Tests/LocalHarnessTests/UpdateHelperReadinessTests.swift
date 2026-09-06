import Darwin
import Foundation
import LocalHarnessUpdateSecurity
import Testing
@testable import LocalHarness

private let readinessWrite = "printf 'LOCAL_HARNESS_UPDATE_HELPER_READY_V1\\n' >&3"

private func helperEnvironment() -> [String: String] {
    [
        "HOME": FileManager.default.homeDirectoryForCurrentUser.path,
        "PATH": "/usr/bin:/bin"
    ]
}

private func failedHelperLaunch(
    script: String,
    maximumStderrBytes: Int = 64 * 1_024,
    deadline: TimeInterval = 0.35,
    terminationGrace: TimeInterval = 0.05
) -> (error: UpdateHelperReadinessError?, pid: pid_t, elapsed: TimeInterval) {
    var spawnedPID: pid_t = 0
    let started = DispatchTime.now().uptimeNanoseconds
    do {
        let handle = try UpdateHelperReadinessSupervisor.launch(
            executable: URL(fileURLWithPath: "/bin/sh"),
            arguments: ["-c", script],
            environment: helperEnvironment(),
            maximumStderrBytes: maximumStderrBytes,
            deadline: deadline,
            terminationGrace: terminationGrace,
            onSpawn: { spawnedPID = $0 }
        )
        _ = UpdateHelperReadinessSupervisor.terminateReadyProcess(handle)
        return (
            nil,
            spawnedPID,
            Double(DispatchTime.now().uptimeNanoseconds - started) / 1_000_000_000
        )
    } catch let error as UpdateHelperReadinessError {
        return (
            error,
            spawnedPID,
            Double(DispatchTime.now().uptimeNanoseconds - started) / 1_000_000_000
        )
    } catch {
        return (
            nil,
            spawnedPID,
            Double(DispatchTime.now().uptimeNanoseconds - started) / 1_000_000_000
        )
    }
}

private func processAndGroupAreGone(_ pid: pid_t) -> Bool {
    guard pid > 1 else { return false }
    errno = 0
    let processGone = Darwin.kill(pid, 0) != 0 && errno == ESRCH
    errno = 0
    let groupGone = Darwin.kill(-pid, 0) != 0 && errno == ESRCH
    return processGone && groupGone
}

@Test func updateHelperReadinessWaitsForDelayedExactFrameAndKeepsValidatedHelperAlive() throws {
    var spawnedPID: pid_t = 0
    let started = DispatchTime.now().uptimeNanoseconds
    let handle = try UpdateHelperReadinessSupervisor.launch(
        executable: URL(fileURLWithPath: "/bin/sh"),
        arguments: [
            "-c",
            "sleep 0.08; \(readinessWrite); exec 3>&-; exec 2>&-; sleep 30"
        ],
        environment: helperEnvironment(),
        deadline: 1,
        terminationGrace: 0.05,
        onSpawn: { spawnedPID = $0 }
    )
    let elapsed = Double(DispatchTime.now().uptimeNanoseconds - started) / 1_000_000_000
    #expect(elapsed >= 0.05)
    #expect(handle.processIdentifier == spawnedPID)
    #expect(Darwin.kill(spawnedPID, 0) == 0)
    #expect(UpdateHelperReadinessSupervisor.terminateReadyProcess(handle))
    #expect(processAndGroupAreGone(spawnedPID))
}

@Test func updateHelperReadinessRejectsValidationFailureAfterOldTenMillisecondWindow() {
    let result = failedHelperLaunch(
        script: "sleep 0.08; printf 'validation failed\\n' >&2; exit 7",
        deadline: 1
    )
    #expect(result.elapsed >= 0.05)
    #expect(result.error == .protocolViolation || result.error == .exitedBeforeReady)
    #expect(processAndGroupAreGone(result.pid))
}

@Test func updateHelperReadinessRejectsMalformedFrameAndReapsExactGroup() {
    let result = failedHelperLaunch(
        script: "printf 'WRONG' >&3; exec 3>&-; exec 2>&-; sleep 30"
    )
    #expect(result.error == .protocolViolation)
    #expect(processAndGroupAreGone(result.pid))
}

@Test func updateHelperReadinessRejectsNoiseAfterOtherwiseValidFrame() {
    let result = failedHelperLaunch(
        script: "\(readinessWrite); printf 'NOISE' >&3; exec 3>&-; exec 2>&-; sleep 30"
    )
    #expect(result.error == .protocolViolation)
    #expect(processAndGroupAreGone(result.pid))
}

@Test func updateHelperReadinessRejectsPipeEOFWithoutFrame() {
    let result = failedHelperLaunch(
        script: "exec 3>&-; exec 2>&-; sleep 30"
    )
    #expect(result.error == .protocolViolation)
    #expect(processAndGroupAreGone(result.pid))
}

@Test func updateHelperReadinessCapsContinuousStderrAndReapsWriterGroup() {
    let result = failedHelperLaunch(
        script: "while :; do printf '0123456789abcdef0123456789abcdef' >&2; done",
        maximumStderrBytes: 1_024,
        deadline: 1
    )
    #expect(result.error == .stderrLimitExceeded || result.error == .protocolViolation)
    #expect(result.elapsed < 2)
    #expect(processAndGroupAreGone(result.pid))
}

@Test func updateHelperReadinessDeadlineKillsTermResistantGroupWithoutKillingSibling() throws {
    let sibling = Process()
    sibling.executableURL = URL(fileURLWithPath: "/bin/sleep")
    sibling.arguments = ["30"]
    try sibling.run()
    defer {
        if sibling.isRunning { sibling.terminate() }
        #expect(boundedTestWaitForExit(sibling, timeout: 3))
    }

    let result = failedHelperLaunch(
        script: "trap '' TERM; while :; do sleep 1; done",
        deadline: 0.12,
        terminationGrace: 0.05
    )
    #expect(result.error == .deadlineExceeded)
    #expect(result.elapsed < 2)
    #expect(processAndGroupAreGone(result.pid))
    #expect(sibling.isRunning)
    #expect(Darwin.kill(sibling.processIdentifier, 0) == 0)
}
