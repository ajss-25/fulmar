import Darwin
import Foundation
import LocalHarnessAtomicInstallSwap

private enum InvocationFailure: Error {
    case invalid
}

private func writeAll(_ message: String, descriptor: Int32) {
    let bytes = Array(message.utf8)
    bytes.withUnsafeBytes { buffer in
        var offset = 0
        while offset < buffer.count {
            let written = Darwin.write(
                descriptor,
                buffer.baseAddress?.advanced(by: offset),
                buffer.count - offset
            )
            if written > 0 {
                offset += written
            } else if written < 0, errno == EINTR {
                continue
            } else {
                return
            }
        }
    }
}

private func canonicalUnsignedInteger(_ raw: String) throws -> UInt64 {
    guard !raw.isEmpty,
          raw.utf8.allSatisfy({ $0 >= UInt8(ascii: "0") && $0 <= UInt8(ascii: "9") }),
          let value = UInt64(raw),
          String(value) == raw else {
        throw InvocationFailure.invalid
    }
    return value
}

private func parseArguments() throws -> (
    nonce: String,
    currentDevice: UInt64,
    currentInode: UInt64,
    stageDevice: UInt64,
    stageInode: UInt64,
    candidate: PrivateStableApplicationAttestation
) {
    let arguments = Array(CommandLine.arguments.dropFirst())
    let allowed = Set([
        "--nonce",
        "--current-device",
        "--current-inode",
        "--stage-device",
        "--stage-inode",
        "--candidate-attestation"
    ])
    guard arguments.count == allowed.count * 2 else {
        throw InvocationFailure.invalid
    }
    var values: [String: String] = [:]
    var index = 0
    while index < arguments.count {
        let flag = arguments[index]
        guard allowed.contains(flag), values[flag] == nil else {
            throw InvocationFailure.invalid
        }
        values[flag] = arguments[index + 1]
        index += 2
    }
    guard let nonce = values["--nonce"],
          let currentDeviceRaw = values["--current-device"],
          let currentInodeRaw = values["--current-inode"],
          let stageDeviceRaw = values["--stage-device"],
          let stageInodeRaw = values["--stage-inode"],
          let candidateRaw = values["--candidate-attestation"] else {
        throw InvocationFailure.invalid
    }
    _ = try AtomicInstallSwap.stageLeaf(nonce: nonce)
    return (
        nonce,
        try canonicalUnsignedInteger(currentDeviceRaw),
        try canonicalUnsignedInteger(currentInodeRaw),
        try canonicalUnsignedInteger(stageDeviceRaw),
        try canonicalUnsignedInteger(stageInodeRaw),
        try PrivateStableApplicationAttestation.decodeArgument(candidateRaw)
    )
}

do {
    let invocation = try parseArguments()
    let owner = UInt32(geteuid())
    _ = try AtomicInstallSwap.performProduction(
        nonce: invocation.nonce,
        expectedCurrent: AtomicInstallIdentity(
            device: invocation.currentDevice,
            inode: invocation.currentInode,
            owner: owner
        ),
        expectedStage: AtomicInstallIdentity(
            device: invocation.stageDevice,
            inode: invocation.stageInode,
            owner: owner
        ),
        expectedCandidate: invocation.candidate
    )
    writeAll("Fulmar installation swap committed.\n", descriptor: STDOUT_FILENO)
    exit(0)
} catch let error as AtomicInstallSwapError {
    writeAll("Atomic installer: \(error.localizedDescription)\n", descriptor: STDERR_FILENO)
    exit(2)
} catch {
    writeAll("Atomic installer: The invocation is invalid.\n", descriptor: STDERR_FILENO)
    exit(64)
}
