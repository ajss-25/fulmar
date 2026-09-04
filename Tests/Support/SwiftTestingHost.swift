import Darwin
import Foundation

@main
struct SwiftTestingHost {
    private enum StartupFailure: String {
        case invalidInvocation = "invalid invocation"
        case testBundleLoad = "test bundle load failed"
        case testEntryPoint = "test entry point missing"
    }

    private static func currentLoaderError() -> String? {
        guard let pointer = dlerror() else { return nil }
        let length = strnlen(pointer, 2_048)
        let bytes = UnsafeRawPointer(pointer).assumingMemoryBound(to: UInt8.self)
        let bounded = UnsafeBufferPointer(start: bytes, count: length)
        let printableASCII = bounded.map { byte in
            (0x20...0x7E).contains(byte) ? byte : 0x3F
        }
        return String(decoding: printableASCII, as: UTF8.self)
    }

    private static func fail(_ failure: StartupFailure, loaderDetail: String? = nil) -> Never {
        var text = "The private Swift Testing host could not start: \(failure.rawValue)."
        if let loaderDetail, !loaderDetail.isEmpty {
            text += " Loader detail: \(loaderDetail)"
        }
        let message = Data("\(text)\n".utf8)
        try? FileHandle.standardError.write(contentsOf: message)
        Darwin.exit(126)
    }

    static func main() {
        let arguments = CommandLine.arguments
        guard arguments.count >= 3,
              arguments[1] == "--test-bundle-path" else {
            fail(.invalidInvocation)
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

        _ = dlerror()
        guard let image = dlopen(arguments[2], RTLD_LAZY | RTLD_FIRST) else {
            fail(.testBundleLoad, loaderDetail: currentLoaderError())
        }
        defer { dlclose(image) }

        typealias TestingMain = @convention(c) (
            CInt,
            UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
        ) -> CInt
        _ = dlerror()
        guard let symbol = dlsym(image, "main") else {
            fail(.testEntryPoint, loaderDetail: currentLoaderError())
        }
        let testingMain = unsafeBitCast(symbol, to: TestingMain.self)
        let status = testingMain(CommandLine.argc, CommandLine.unsafeArgv)
        Darwin.exit(status)
    }
}
