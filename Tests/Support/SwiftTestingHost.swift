import CoreFoundation
import Darwin
import Foundation

@main
struct SwiftTestingHost {
    private enum StartupFailure: String {
        case invalidInvocation = "invalid invocation"
        case testBundleLoad = "test bundle load failed"
        case testEntryPoint = "test entry point missing"
        case testRunLoop = "test run loop unavailable"
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

        // Hold both counters before loading the test image. The private app
        // also opts out of automatic termination in its property list.
        let processInfo = ProcessInfo.processInfo
        processInfo.disableAutomaticTermination(
            "Fulmar is executing its native qualification suite."
        )
        processInfo.disableSuddenTermination()

        _ = dlerror()
        guard let image = dlopen(arguments[2], RTLD_LAZY | RTLD_FIRST) else {
            fail(.testBundleLoad, loaderDetail: currentLoaderError())
        }
        typealias TestingStart = @convention(c) () -> Void
        _ = dlerror()
        guard let symbol = dlsym(image, "fulmar_swift_testing_start") else {
            fail(.testEntryPoint, loaderDetail: currentLoaderError())
        }
        // Swift's generated async main exits zero if AppKit stops its main-loop
        // drain while a test is suspended. Own the synchronous loop instead;
        // the test bundle's starter exits only after Testing returns its result.
        // A permanent source keeps an idle loop asleep, and a stop simply makes
        // us enter it again. The outer watchdog remains the bound on a hung test.
        var context = CFRunLoopSourceContext(
            version: 0, info: nil, retain: nil, release: nil,
            copyDescription: nil, equal: nil, hash: nil,
            schedule: nil, cancel: nil, perform: { _ in }
        )
        guard let keepAlive = CFRunLoopSourceCreate(kCFAllocatorDefault, 0, &context) else {
            fail(.testRunLoop)
        }
        CFRunLoopAddSource(CFRunLoopGetMain(), keepAlive, .commonModes)
        let startTesting = unsafeBitCast(symbol, to: TestingStart.self)
        startTesting()
        withExtendedLifetime(keepAlive) {
            while true { CFRunLoopRun() }
        }
    }
}
