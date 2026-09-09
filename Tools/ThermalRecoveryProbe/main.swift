import Darwin
import Foundation

private let sampleSchema = "fulmar-thermal-sample-v1"
private let clockSchema = "fulmar-thermal-clock-v1"
private let supervisorModes: Set<String> = [
    "--supervise-monotonic",
    "--supervise-sample",
    "--test-supervise-monotonic",
    "--test-supervise-sample",
]
private let testScenarios: Set<String> = [
    "hang",
    "hung-once",
    "invalid",
    "monotonic-backward",
    "nominal",
    "reset",
    "stopped-once",
    "timeout",
    "wall-backward",
    "wall-forward",
]

private enum ProbeFailure: Error {
    case invalidArguments
    case monotonicClockUnavailable
    case arithmeticOverflow
}

@_silgen_name("fulmar_run_supervisor")
private func runNativeSupervisor(
    _ argumentCount: Int32,
    _ arguments: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Int32

private func monotonicMilliseconds() throws -> UInt64 {
    var timebase = mach_timebase_info_data_t()
    guard mach_timebase_info(&timebase) == KERN_SUCCESS, timebase.denom != 0 else {
        throw ProbeFailure.monotonicClockUnavailable
    }
    let ticks = mach_continuous_time()
    let denominator = UInt64(timebase.denom)
    let numerator = UInt64(timebase.numer)
    let quotient = ticks / denominator
    let remainder = ticks % denominator
    let (wholeNanoseconds, wholeOverflow) = quotient.multipliedReportingOverflow(by: numerator)
    let (remainderProduct, remainderOverflow) = remainder.multipliedReportingOverflow(by: numerator)
    let (nanoseconds, sumOverflow) = wholeNanoseconds.addingReportingOverflow(
        remainderProduct / denominator
    )
    guard !wholeOverflow, !remainderOverflow, !sumOverflow else {
        throw ProbeFailure.arithmeticOverflow
    }
    return nanoseconds / 1_000_000
}

private func wallMilliseconds() -> Int64 {
    let value = Date().timeIntervalSince1970 * 1_000
    guard value.isFinite, value >= Double(Int64.min), value <= Double(Int64.max) else {
        return 0
    }
    return Int64(value.rounded(.towardZero))
}

private func thermalStateCode() -> String {
    switch ProcessInfo.processInfo.thermalState {
    case .nominal: return "0"
    case .fair: return "1"
    case .serious: return "2"
    case .critical: return "3"
    @unknown default: return "invalid"
    }
}

private func checkedTestMilliseconds(index: UInt64) throws -> UInt64 {
    let (offset, overflow) = index.multipliedReportingOverflow(by: 2_000)
    let (value, sumOverflow) = UInt64(1_000_000).addingReportingOverflow(offset)
    guard !overflow, !sumOverflow else { throw ProbeFailure.arithmeticOverflow }
    return value
}

private func testMonotonicMilliseconds(scenario: String, index: UInt64) throws -> UInt64 {
    if scenario == "timeout", index >= 1 { return 1_600_000 }
    if scenario == "monotonic-backward", index == 1 { return 999_000 }
    return try checkedTestMilliseconds(index: index)
}

private func testWallMilliseconds(scenario: String, index: UInt64) throws -> Int64 {
    let normal = Int64(2_000_000_000_000) + Int64(try checkedTestMilliseconds(index: index))
    if scenario == "wall-forward", index == 30 { return normal + 1_000_000_000 }
    if scenario == "wall-backward", index == 30 { return normal - 1_000_000_000 }
    return normal
}

private func testThermalState(scenario: String, index: UInt64) -> String {
    if scenario == "reset", index == 60 { return "1" }
    if scenario == "invalid", index == 60 { return "not-a-thermal-state" }
    if scenario == "timeout" { return "1" }
    return "0"
}

private func hangForever() -> Never {
    while true { sleep(60) }
}

private func stopForever() -> Never {
    _ = raise(SIGSTOP)
    hangForever()
}

@main
private struct ThermalRecoveryProbe {
    static func main() {
        if let mode = CommandLine.arguments.dropFirst().first,
           supervisorModes.contains(mode) {
            exit(runNativeSupervisor(CommandLine.argc, CommandLine.unsafeArgv))
        }
        do {
            try run()
        } catch {
            exit(1)
        }
    }

    private static func run() throws {
        let arguments = Array(CommandLine.arguments.dropFirst())
        if arguments == ["--sample"] {
            print("\(sampleSchema) \(try monotonicMilliseconds()) \(thermalStateCode()) \(wallMilliseconds())")
            return
        }
        if arguments == ["--monotonic"] {
            print("\(clockSchema) \(try monotonicMilliseconds())")
            return
        }
        guard arguments.count == 3,
              arguments[0] == "--test-sample" || arguments[0] == "--test-monotonic",
              testScenarios.contains(arguments[1]),
              let index = UInt64(arguments[2]) else {
            throw ProbeFailure.invalidArguments
        }
        let scenario = arguments[1]
        if arguments[0] == "--test-sample" {
            if scenario == "hang", index >= 1 { hangForever() }
            if scenario == "hung-once", index == 1 { hangForever() }
            if scenario == "stopped-once", index == 1 { stopForever() }
            print("\(sampleSchema) \(try testMonotonicMilliseconds(scenario: scenario, index: index)) "
                  + "\(testThermalState(scenario: scenario, index: index)) "
                  + "\(try testWallMilliseconds(scenario: scenario, index: index))")
        } else {
            print("\(clockSchema) \(try testMonotonicMilliseconds(scenario: scenario, index: index))")
        }
    }
}
