import Darwin
import Foundation
import LocalHarnessPrivateInstallCoordinator

private func writeAll(_ message: String, descriptor: Int32) {
    let bytes = Array(message.utf8)
    bytes.withUnsafeBytes { buffer in
        var offset = 0
        while offset < buffer.count {
            let count = Darwin.write(
                descriptor,
                buffer.baseAddress?.advanced(by: offset),
                buffer.count - offset
            )
            if count > 0 {
                offset += count
            } else if count < 0, errno == EINTR {
                continue
            } else {
                return
            }
        }
    }
}

private func parseNonce() throws -> String {
    let arguments = Array(CommandLine.arguments.dropFirst())
    guard arguments.count == 2,
          arguments[0] == "--nonce" else {
        throw PrivateInstallCoordinatorError.invalidInvocation
    }
    return arguments[1]
}

do {
    let nonce = try parseNonce()
    _ = try PrivateInstallCoordinator.performProduction(nonce: nonce)
    writeAll(
        "Fulmar private installation committed; the prior bundle is retained for rollback.\n",
        descriptor: STDOUT_FILENO
    )
    exit(0)
} catch let error as PrivateInstallCoordinatorError {
    writeAll("Fulmar private installer: \(error.localizedDescription)\n", descriptor: STDERR_FILENO)
    exit(2)
} catch {
    writeAll(
        "Fulmar private installer: The private installation failed closed.\n",
        descriptor: STDERR_FILENO
    )
    exit(2)
}
