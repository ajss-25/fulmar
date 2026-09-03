import Darwin
import Foundation

@main
struct SwiftTestingHost {
    private static func fail() -> Never {
        let message = Data("The private Swift Testing host could not start.\n".utf8)
        try? FileHandle.standardError.write(contentsOf: message)
        Darwin.exit(126)
    }

    static func main() {
        let arguments = CommandLine.arguments
        guard arguments.count >= 3,
              arguments[1] == "--test-bundle-path" else {
            fail()
        }

        // The private app declares NSSupportsAutomaticTermination. This is a
        // single-purpose process whose only successful return path is Darwin
        // exit, so hold both process counters directly for its whole lifetime.
        // A temporary activity token can be released by runtime teardown while
        // QuickLook drains hidden windows, which previously let macOS auto-quit
        // this host with status zero in the middle of an otherwise green run.
        // Disable before loading the test image, and never re-enable before the
        // authoritative process exit.
        let processInfo = ProcessInfo.processInfo
        processInfo.disableAutomaticTermination(
            "Fulmar is executing its native qualification suite."
        )
        processInfo.disableSuddenTermination()

        guard let image = dlopen(arguments[2], RTLD_LAZY | RTLD_FIRST) else {
            fail()
        }
        defer { dlclose(image) }

        typealias TestingMain = @convention(c) (
            CInt,
            UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
        ) -> CInt
        guard let symbol = dlsym(image, "main") else {
            fail()
        }
        let testingMain = unsafeBitCast(symbol, to: TestingMain.self)
        let status = testingMain(CommandLine.argc, CommandLine.unsafeArgv)
        Darwin.exit(status)
    }
}
