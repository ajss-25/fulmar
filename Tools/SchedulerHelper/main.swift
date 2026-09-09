import Foundation
import LocalHarnessSchedulerWake

let home = FileManager.default.homeDirectoryForCurrentUser
let schedules = home.appendingPathComponent("Library/Application Support/Local Harness/Schedules/schedules.json")
guard SchedulerWakePolicy.shouldWake(schedulesURL: schedules) else { exit(0) }

guard let helperExecutable = SchedulerWakePolicy.currentExecutableURL() else { exit(1) }
let launchPlan: SchedulerHelperLaunchPlan
do {
    launchPlan = try SchedulerWakePolicy.validatedLaunchPlan(helperExecutable: helperExecutable)
} catch {
    exit(1)
}

do {
    // Close the validation/use interval as far as a path-based Launch Services
    // API permits: the exact same topology and nested signature are checked
    // again immediately before `/usr/bin/open` resolves the absolute app URL.
    try SchedulerWakePolicy.revalidate(
        launchPlan,
        helperExecutable: helperExecutable
    )
} catch {
    exit(1)
}
exit(SchedulerWakePolicy.runLaunchProcess(
    arguments: launchPlan.openArguments,
    environment: ["HOME": home.path, "PATH": "/usr/bin:/bin"]
))
