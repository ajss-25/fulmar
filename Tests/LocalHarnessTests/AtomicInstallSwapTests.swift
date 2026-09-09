import Darwin
import Foundation
@testable import LocalHarnessAtomicInstallSwap
import Testing

private let atomicInstallTestNonce = String(repeating: "a", count: 64)

private struct AtomicInstallFixture {
    let root: URL
    let current: URL
    let stage: URL
    let currentIdentity: AtomicInstallIdentity
    let stageIdentity: AtomicInstallIdentity
}

private enum AtomicInstallTestFailure: Error {
    case aclSetupFailed
    case fixtureCopyFailed
}

private func makeAtomicInstallFixture() throws -> AtomicInstallFixture {
    let fileManager = FileManager.default
    let root = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
        .appendingPathComponent("FulmarAtomicInstallTests.\(UUID().uuidString)", isDirectory: true)
    try fileManager.createDirectory(at: root, withIntermediateDirectories: false)
    try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
    let current = root.appendingPathComponent("Fulmar.app", isDirectory: true)
    let stage = root.appendingPathComponent(
        try AtomicInstallSwap.stageLeaf(nonce: atomicInstallTestNonce),
        isDirectory: true
    )
    try fileManager.createDirectory(at: current, withIntermediateDirectories: false)
    try fileManager.createDirectory(at: stage, withIntermediateDirectories: false)
    try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: current.path)
    try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: stage.path)
    try Data("old".utf8).write(to: current.appendingPathComponent("identity"))
    try Data("candidate".utf8).write(to: stage.appendingPathComponent("identity"))
    return AtomicInstallFixture(
        root: root,
        current: current,
        stage: stage,
        currentIdentity: try AtomicInstallSwap.identityForTesting(
            parentDirectory: root,
            leaf: current.lastPathComponent
        ),
        stageIdentity: try AtomicInstallSwap.identityForTesting(
            parentDirectory: root,
            leaf: stage.lastPathComponent
        )
    )
}

private func removeAtomicInstallFixture(_ fixture: AtomicInstallFixture) {
    try? FileManager.default.removeItem(at: fixture.root)
}

private func identityAt(_ fixture: AtomicInstallFixture, leaf: String) throws -> AtomicInstallIdentity {
    try AtomicInstallSwap.identityForTesting(parentDirectory: fixture.root, leaf: leaf)
}

private func addReadACL(to url: URL) throws {
    guard let passwordEntry = getpwuid(geteuid()) else {
        throw AtomicInstallTestFailure.aclSetupFailed
    }
    let userName = String(cString: passwordEntry.pointee.pw_name)
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/chmod")
    process.arguments = ["+a", "\(userName) allow read", url.path]
    process.environment = ["PATH": "/usr/bin:/bin"]
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
    guard boundedTestWaitForExit(process, timeout: 5),
          process.terminationReason == .exit,
          process.terminationStatus == 0 else {
        throw AtomicInstallTestFailure.aclSetupFailed
    }
}

private func readIdentityMarker(stageDescriptor: Int32) throws -> String {
    let descriptor = "identity".withCString {
        openat(stageDescriptor, $0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    }
    guard descriptor >= 0 else { throw AtomicInstallSwapError.identityMismatch }
    defer { _ = Darwin.close(descriptor) }
    var metadata = stat()
    guard fstat(descriptor, &metadata) == 0,
          metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
          metadata.st_uid == geteuid(),
          metadata.st_size >= 0,
          metadata.st_size <= 64 else {
        throw AtomicInstallSwapError.identityMismatch
    }
    var bytes = [UInt8](repeating: 0, count: Int(metadata.st_size))
    var offset = 0
    while offset < bytes.count {
        let count = bytes.withUnsafeMutableBytes { buffer in
            Darwin.read(
                descriptor,
                buffer.baseAddress?.advanced(by: offset),
                buffer.count - offset
            )
        }
        if count > 0 {
            offset += count
        } else if count < 0, errno == EINTR {
            continue
        } else {
            throw AtomicInstallSwapError.identityMismatch
        }
    }
    guard let value = String(bytes: bytes, encoding: .utf8) else {
        throw AtomicInstallSwapError.identityMismatch
    }
    return value
}

private func cloneApplicationFixture(from source: URL, to destination: URL) throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/cp")
    process.arguments = ["-cR", source.path, destination.path]
    process.environment = ["PATH": "/usr/bin:/bin"]
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
    guard boundedTestWaitForExit(process, timeout: 10),
          process.terminationReason == .exit,
          process.terminationStatus == 0 else {
        throw AtomicInstallTestFailure.fixtureCopyFailed
    }
}

private func expectAtomicInstallError(
    _ expected: AtomicInstallSwapError,
    operation: () throws -> Void
) {
    do {
        try operation()
        Issue.record("Expected \(expected) but the operation succeeded")
    } catch let error as AtomicInstallSwapError {
        #expect(error == expected)
    } catch {
        Issue.record("Unexpected error type")
    }
}

@Test func atomicInstallSwapCommitsExactPredeclaredIdentities() throws {
    let fixture = try makeAtomicInstallFixture()
    defer { removeAtomicInstallFixture(fixture) }

    let receipt = try AtomicInstallSwap.performForTesting(
        parentDirectory: fixture.root,
        nonce: atomicInstallTestNonce,
        expectedCurrent: fixture.currentIdentity,
        expectedStage: fixture.stageIdentity
    )

    #expect(receipt.installed == fixture.stageIdentity)
    #expect(receipt.retainedRollback == fixture.currentIdentity)
    #expect(try identityAt(fixture, leaf: fixture.current.lastPathComponent) == fixture.stageIdentity)
    #expect(try identityAt(fixture, leaf: fixture.stage.lastPathComponent) == fixture.currentIdentity)
    #expect(try String(contentsOf: fixture.current.appendingPathComponent("identity"), encoding: .utf8) == "candidate")
    #expect(try String(contentsOf: fixture.stage.appendingPathComponent("identity"), encoding: .utf8) == "old")
}

@Test func atomicInstallProductionParentPolicyAcceptsStockApplicationsMetadata() {
    #expect(AtomicInstallSwap.productionParentMetadataIsSafe(
        AtomicInstallParentMetadata(
            owner: 0,
            group: 80,
            permissions: 0o775,
            isDirectory: true,
            hasExtendedACL: false
        ),
        adminGroup: 80,
        wheelGroup: 0
    ))
    #expect(AtomicInstallSwap.productionParentMetadataIsSafe(
        AtomicInstallParentMetadata(
            owner: 0,
            group: 0,
            permissions: 0o755,
            isDirectory: true,
            hasExtendedACL: false
        ),
        adminGroup: 80,
        wheelGroup: 0
    ))
}

@Test func atomicInstallProductionParentPolicyRejectsUnsafeMetadataForms() {
    let unsafeMetadata = [
        AtomicInstallParentMetadata(owner: 501, group: 80, permissions: 0o775, isDirectory: true, hasExtendedACL: false),
        AtomicInstallParentMetadata(owner: 0, group: 20, permissions: 0o775, isDirectory: true, hasExtendedACL: false),
        AtomicInstallParentMetadata(owner: 0, group: 80, permissions: 0o777, isDirectory: true, hasExtendedACL: false),
        AtomicInstallParentMetadata(owner: 0, group: 80, permissions: 0o755, isDirectory: true, hasExtendedACL: true),
        AtomicInstallParentMetadata(owner: 0, group: 80, permissions: 0o755, isDirectory: false, hasExtendedACL: false),
        AtomicInstallParentMetadata(owner: 0, group: 80, permissions: 0o2775, isDirectory: true, hasExtendedACL: false)
    ]
    for metadata in unsafeMetadata {
        #expect(!AtomicInstallSwap.productionParentMetadataIsSafe(
            metadata,
            adminGroup: 80,
            wheelGroup: 0
        ))
    }
}

@Test func atomicInstallPrivateStableAttestationShapeRoundTripsAndRejectsDeveloperModeConfusion() throws {
    let requirement = Data([0x00, 0x01, 0x02, 0x03])
    let malformed = PrivateStableApplicationAttestation(
        identifier: "com.angadjairath.localharness",
        version: "1.2.3",
        build: 123,
        cdHashHex: String(repeating: "a", count: 40),
        leafCertificateSHA256Hex: String(repeating: "b", count: 64),
        designatedRequirement: requirement
    )
    expectAtomicInstallError(.privateAttestationInvalid) {
        _ = try malformed.encodedArgument()
    }
    #expect(PrivateStableApplicationAttestation.signingMode == "private-self-signed-v1")
}

@Test(.disabled(
    if: ProcessInfo.processInfo.environment["LOCAL_HARNESS_TEST_APP_PATH"] == nil,
    "Requires the release runner's exact extracted application fixture."
))
func atomicInstallValidatesRealPrivateStableFixtureAndRejectsCertMismatchAndTamper() throws {
    let fixturePath = try #require(
        ProcessInfo.processInfo.environment["LOCAL_HARNESS_TEST_APP_PATH"]
    )
    let fixtureURL = URL(fileURLWithPath: fixturePath, isDirectory: true)
    let expected = try AtomicInstallSwap.privateStableAttestationForTesting(at: fixtureURL)
    try expected.validateShape()
    let roundTripped = try PrivateStableApplicationAttestation.decodeArgument(
        try expected.encodedArgument()
    )
    #expect(roundTripped == expected)
    #expect(expected.identifier == "com.angadjairath.localharness")
    #expect(expected.leafCertificateSHA256Hex.count == 64)
    #expect(!expected.designatedRequirement.isEmpty)
    try AtomicInstallSwap.validatePrivateStableApplicationForTesting(
        at: fixtureURL,
        expected: expected
    )

    let differentCertificate = PrivateStableApplicationAttestation(
        identifier: expected.identifier,
        version: expected.version,
        build: expected.build,
        cdHashHex: expected.cdHashHex,
        leafCertificateSHA256Hex: String(repeating: "0", count: 64),
        designatedRequirement: expected.designatedRequirement
    )
    expectAtomicInstallError(.privateAttestationInvalid) {
        try AtomicInstallSwap.validatePrivateStableApplicationForTesting(
            at: fixtureURL,
            expected: differentCertificate
        )
    }

    let installedURL = URL(fileURLWithPath: "/Applications/Fulmar.app", isDirectory: true)
    if FileManager.default.fileExists(atPath: installedURL.path) {
        let installed = try AtomicInstallSwap.privateStableAttestationForTesting(at: installedURL)
        #expect(installed.leafCertificateSHA256Hex == expected.leafCertificateSHA256Hex)
        #expect(installed.designatedRequirement == expected.designatedRequirement)
    }

    let trustedSystemApplication = URL(
        fileURLWithPath: "/System/Applications/Calculator.app",
        isDirectory: true
    )
    if FileManager.default.fileExists(atPath: trustedSystemApplication.path) {
        expectAtomicInstallError(.privateAttestationInvalid) {
            _ = try AtomicInstallSwap.privateStableAttestationForTesting(
                at: trustedSystemApplication
            )
        }
    }

    let root = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
        .appendingPathComponent("FulmarAtomicInstallTests.\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
    defer { try? FileManager.default.removeItem(at: root) }
    let tampered = root.appendingPathComponent("Tampered.app", isDirectory: true)
    try cloneApplicationFixture(from: fixtureURL, to: tampered)
    let informationURL = tampered.appendingPathComponent("Contents/Info.plist")
    let originalInformation = try Data(contentsOf: informationURL)
    guard var information = try PropertyListSerialization.propertyList(
        from: originalInformation,
        options: [],
        format: nil
    ) as? [String: Any] else {
        throw AtomicInstallTestFailure.fixtureCopyFailed
    }
    information["CFBundleDisplayName"] = "Tampered Fulmar"
    try PropertyListSerialization.data(
        fromPropertyList: information,
        format: .xml,
        options: 0
    ).write(to: informationURL, options: .atomic)
    expectAtomicInstallError(.privateAttestationInvalid) {
        try AtomicInstallSwap.validatePrivateStableApplicationForTesting(
            at: tampered,
            expected: expected
        )
    }
}

@Test func atomicInstallSwapRejectsWrongInodeWithoutMutation() throws {
    let fixture = try makeAtomicInstallFixture()
    defer { removeAtomicInstallFixture(fixture) }
    let wrong = AtomicInstallIdentity(
        device: fixture.stageIdentity.device,
        inode: fixture.stageIdentity.inode &+ 1,
        owner: fixture.stageIdentity.owner
    )

    expectAtomicInstallError(.identityMismatch) {
        _ = try AtomicInstallSwap.performForTesting(
            parentDirectory: fixture.root,
            nonce: atomicInstallTestNonce,
            expectedCurrent: fixture.currentIdentity,
            expectedStage: wrong
        )
    }
    #expect(try identityAt(fixture, leaf: fixture.current.lastPathComponent) == fixture.currentIdentity)
    #expect(try identityAt(fixture, leaf: fixture.stage.lastPathComponent) == fixture.stageIdentity)
}

@Test func atomicInstallSwapRejectsWrongDeviceWithoutMutation() throws {
    let fixture = try makeAtomicInstallFixture()
    defer { removeAtomicInstallFixture(fixture) }
    let wrong = AtomicInstallIdentity(
        device: fixture.stageIdentity.device &+ 1,
        inode: fixture.stageIdentity.inode,
        owner: fixture.stageIdentity.owner
    )

    expectAtomicInstallError(.identityMismatch) {
        _ = try AtomicInstallSwap.performForTesting(
            parentDirectory: fixture.root,
            nonce: atomicInstallTestNonce,
            expectedCurrent: fixture.currentIdentity,
            expectedStage: wrong
        )
    }
    #expect(try identityAt(fixture, leaf: fixture.current.lastPathComponent) == fixture.currentIdentity)
}

@Test func atomicInstallSwapRejectsSymlinkStageWithoutFollowingIt() throws {
    let fixture = try makeAtomicInstallFixture()
    defer { removeAtomicInstallFixture(fixture) }
    let fileManager = FileManager.default
    try fileManager.removeItem(at: fixture.stage)
    try fileManager.createSymbolicLink(at: fixture.stage, withDestinationURL: fixture.current)

    expectAtomicInstallError(.unsafeLeaf) {
        _ = try AtomicInstallSwap.performForTesting(
            parentDirectory: fixture.root,
            nonce: atomicInstallTestNonce,
            expectedCurrent: fixture.currentIdentity,
            expectedStage: fixture.stageIdentity
        )
    }
    #expect(try identityAt(fixture, leaf: fixture.current.lastPathComponent) == fixture.currentIdentity)
}

@Test func atomicInstallSwapRejectsRenamedAndReplacedStageAtFinalBoundary() throws {
    let fixture = try makeAtomicInstallFixture()
    defer { removeAtomicInstallFixture(fixture) }
    let replacement = fixture.root.appendingPathComponent("replacement", isDirectory: true)
    let quarantined = fixture.root.appendingPathComponent("original-stage", isDirectory: true)
    try FileManager.default.createDirectory(at: replacement, withIntermediateDirectories: false)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: replacement.path)

    let hooks = AtomicInstallSwapTestHooks(afterOpenBeforeFinalValidation: {
        try FileManager.default.moveItem(at: fixture.stage, to: quarantined)
        try FileManager.default.moveItem(at: replacement, to: fixture.stage)
    })
    expectAtomicInstallError(.identityMismatch) {
        _ = try AtomicInstallSwap.performForTesting(
            parentDirectory: fixture.root,
            nonce: atomicInstallTestNonce,
            expectedCurrent: fixture.currentIdentity,
            expectedStage: fixture.stageIdentity,
            hooks: hooks
        )
    }
    #expect(try identityAt(fixture, leaf: fixture.current.lastPathComponent) == fixture.currentIdentity)
    #expect(try identityAt(fixture, leaf: quarantined.lastPathComponent) == fixture.stageIdentity)
}

@Test func atomicInstallSwapRejectsNestedStageMutationAfterOpenWithoutSwapping() throws {
    let fixture = try makeAtomicInstallFixture()
    defer { removeAtomicInstallFixture(fixture) }
    var exchanges = 0
    let hooks = AtomicInstallSwapTestHooks(
        afterOpenBeforeFinalValidation: {
            try Data("tampered".utf8).write(
                to: fixture.stage.appendingPathComponent("identity"),
                options: .atomic
            )
        },
        validateStageContent: { stageDescriptor in
            guard try readIdentityMarker(stageDescriptor: stageDescriptor) == "candidate" else {
                throw AtomicInstallSwapError.identityMismatch
            }
        },
        exchange: { descriptor, first, second in
            exchanges += 1
            return AtomicInstallSwap.liveExchange(
                parentDescriptor: descriptor,
                first: first,
                second: second
            )
        }
    )

    expectAtomicInstallError(.identityMismatch) {
        _ = try AtomicInstallSwap.performForTesting(
            parentDirectory: fixture.root,
            nonce: atomicInstallTestNonce,
            expectedCurrent: fixture.currentIdentity,
            expectedStage: fixture.stageIdentity,
            hooks: hooks
        )
    }
    #expect(exchanges == 0)
    #expect(try identityAt(fixture, leaf: fixture.current.lastPathComponent) == fixture.currentIdentity)
    #expect(try identityAt(fixture, leaf: fixture.stage.lastPathComponent) == fixture.stageIdentity)
}

@Test func atomicInstallSwapRejectsInvalidNonceAndLeafForms() throws {
    #expect(try AtomicInstallSwap.stageLeaf(nonce: atomicInstallTestNonce)
        == ".Fulmar.install-stage.\(atomicInstallTestNonce).app")
    #expect(AtomicInstallSwap.productionCurrentApplicationPath == "/Applications/Fulmar.app")
    for nonce in [
        "",
        String(repeating: "a", count: 63),
        String(repeating: "a", count: 65),
        String(repeating: "A", count: 64),
        String(repeating: "g", count: 64),
        String(repeating: "0", count: 63) + "/"
    ] {
        expectAtomicInstallError(.invalidNonce) {
            _ = try AtomicInstallSwap.stageLeaf(nonce: nonce)
        }
    }
    for leaf in ["", ".", "..", "../Fulmar.app", "nested/Fulmar.app", "bad\0leaf", "fú.app"] {
        expectAtomicInstallError(.unsafeLeaf) {
            try AtomicInstallSwap.validateLeafForTesting(leaf)
        }
    }
}

@Test func atomicInstallSwapRejectsExtendedACLOnParentAndLeaf() throws {
    do {
        let fixture = try makeAtomicInstallFixture()
        defer { removeAtomicInstallFixture(fixture) }
        try addReadACL(to: fixture.root)
        expectAtomicInstallError(.unsafeParent) {
            _ = try AtomicInstallSwap.performForTesting(
                parentDirectory: fixture.root,
                nonce: atomicInstallTestNonce,
                expectedCurrent: fixture.currentIdentity,
                expectedStage: fixture.stageIdentity
            )
        }
    }

    do {
        let fixture = try makeAtomicInstallFixture()
        defer { removeAtomicInstallFixture(fixture) }
        try addReadACL(to: fixture.stage)
        expectAtomicInstallError(.unsafeLeaf) {
            _ = try AtomicInstallSwap.performForTesting(
                parentDirectory: fixture.root,
                nonce: atomicInstallTestNonce,
                expectedCurrent: fixture.currentIdentity,
                expectedStage: fixture.stageIdentity
            )
        }
        #expect(try identityAt(fixture, leaf: fixture.current.lastPathComponent) == fixture.currentIdentity)
    }
}

@Test func atomicInstallSwapDoesNotFallbackWhenAtomicExchangeIsUnsupported() throws {
    let fixture = try makeAtomicInstallFixture()
    defer { removeAtomicInstallFixture(fixture) }
    var exchanges = 0
    let hooks = AtomicInstallSwapTestHooks(exchange: { _, _, _ in
        exchanges += 1
        return ENOTSUP
    })

    expectAtomicInstallError(.atomicSwapUnsupported) {
        _ = try AtomicInstallSwap.performForTesting(
            parentDirectory: fixture.root,
            nonce: atomicInstallTestNonce,
            expectedCurrent: fixture.currentIdentity,
            expectedStage: fixture.stageIdentity,
            hooks: hooks
        )
    }
    #expect(exchanges == 1)
    #expect(try identityAt(fixture, leaf: fixture.current.lastPathComponent) == fixture.currentIdentity)
    #expect(try identityAt(fixture, leaf: fixture.stage.lastPathComponent) == fixture.stageIdentity)
}

@Test func atomicInstallSwapDoesNotFallbackAcrossDevices() throws {
    let fixture = try makeAtomicInstallFixture()
    defer { removeAtomicInstallFixture(fixture) }
    var exchanges = 0
    let hooks = AtomicInstallSwapTestHooks(exchange: { _, _, _ in
        exchanges += 1
        return EXDEV
    })

    expectAtomicInstallError(.crossDevice) {
        _ = try AtomicInstallSwap.performForTesting(
            parentDirectory: fixture.root,
            nonce: atomicInstallTestNonce,
            expectedCurrent: fixture.currentIdentity,
            expectedStage: fixture.stageIdentity,
            hooks: hooks
        )
    }
    #expect(exchanges == 1)
    #expect(try identityAt(fixture, leaf: fixture.current.lastPathComponent) == fixture.currentIdentity)
}

@Test func atomicInstallSwapBeforeBoundaryFaultMakesNoChange() throws {
    let fixture = try makeAtomicInstallFixture()
    defer { removeAtomicInstallFixture(fixture) }
    var exchanges = 0
    let hooks = AtomicInstallSwapTestHooks(
        afterOpenBeforeFinalValidation: {
            throw AtomicInstallSwapError.injectedBeforeSwap
        },
        exchange: { descriptor, first, second in
            exchanges += 1
            return AtomicInstallSwap.liveExchange(
                parentDescriptor: descriptor,
                first: first,
                second: second
            )
        }
    )

    expectAtomicInstallError(.injectedBeforeSwap) {
        _ = try AtomicInstallSwap.performForTesting(
            parentDirectory: fixture.root,
            nonce: atomicInstallTestNonce,
            expectedCurrent: fixture.currentIdentity,
            expectedStage: fixture.stageIdentity,
            hooks: hooks
        )
    }
    #expect(exchanges == 0)
    #expect(try identityAt(fixture, leaf: fixture.current.lastPathComponent) == fixture.currentIdentity)
    #expect(try identityAt(fixture, leaf: fixture.stage.lastPathComponent) == fixture.stageIdentity)
}

@Test func atomicInstallSwapAfterBoundaryFaultImmediatelySwapsBack() throws {
    let fixture = try makeAtomicInstallFixture()
    defer { removeAtomicInstallFixture(fixture) }
    var exchanges = 0
    let hooks = AtomicInstallSwapTestHooks(
        afterExchangeBeforeProof: {
            throw AtomicInstallSwapError.injectedAfterSwap
        },
        exchange: { descriptor, first, second in
            exchanges += 1
            return AtomicInstallSwap.liveExchange(
                parentDescriptor: descriptor,
                first: first,
                second: second
            )
        }
    )

    expectAtomicInstallError(.injectedAfterSwap) {
        _ = try AtomicInstallSwap.performForTesting(
            parentDirectory: fixture.root,
            nonce: atomicInstallTestNonce,
            expectedCurrent: fixture.currentIdentity,
            expectedStage: fixture.stageIdentity,
            hooks: hooks
        )
    }
    #expect(exchanges == 2)
    #expect(try identityAt(fixture, leaf: fixture.current.lastPathComponent) == fixture.currentIdentity)
    #expect(try identityAt(fixture, leaf: fixture.stage.lastPathComponent) == fixture.stageIdentity)
}

@Test func atomicInstallSwapPostProofRejectsUnexpectedNameOrientation() throws {
    let fixture = try makeAtomicInstallFixture()
    defer { removeAtomicInstallFixture(fixture) }
    let hooks = AtomicInstallSwapTestHooks(afterExchangeBeforeProof: {
        let status = fixture.current.path.withCString { currentPointer in
            fixture.stage.path.withCString { stagePointer in
                renameatx_np(
                    AT_FDCWD,
                    currentPointer,
                    AT_FDCWD,
                    stagePointer,
                    UInt32(RENAME_SWAP)
                )
            }
        }
        guard status == 0 else { throw AtomicInstallSwapError.atomicSwapFailed }
    })

    expectAtomicInstallError(.postSwapProofFailed) {
        _ = try AtomicInstallSwap.performForTesting(
            parentDirectory: fixture.root,
            nonce: atomicInstallTestNonce,
            expectedCurrent: fixture.currentIdentity,
            expectedStage: fixture.stageIdentity,
            hooks: hooks
        )
    }
    #expect(try identityAt(fixture, leaf: fixture.current.lastPathComponent) == fixture.currentIdentity)
    #expect(try identityAt(fixture, leaf: fixture.stage.lastPathComponent) == fixture.stageIdentity)
}

@Test func atomicInstallSwapRejectsRunningApplicationBeforeOpeningBundles() throws {
    let fixture = try makeAtomicInstallFixture()
    defer { removeAtomicInstallFixture(fixture) }
    let hooks = AtomicInstallSwapTestHooks(applicationIsRunning: { true })

    expectAtomicInstallError(.applicationRunning) {
        _ = try AtomicInstallSwap.performForTesting(
            parentDirectory: fixture.root,
            nonce: atomicInstallTestNonce,
            expectedCurrent: fixture.currentIdentity,
            expectedStage: fixture.stageIdentity,
            hooks: hooks
        )
    }
    #expect(try identityAt(fixture, leaf: fixture.current.lastPathComponent) == fixture.currentIdentity)
}

@Test func atomicInstallSwapRejectsRunningApplicationAtFinalPreSwapBoundary() throws {
    let fixture = try makeAtomicInstallFixture()
    defer { removeAtomicInstallFixture(fixture) }
    var checks = 0
    var exchanges = 0
    let hooks = AtomicInstallSwapTestHooks(
        applicationIsRunning: {
            checks += 1
            return checks == 2
        },
        exchange: { descriptor, first, second in
            exchanges += 1
            return AtomicInstallSwap.liveExchange(
                parentDescriptor: descriptor,
                first: first,
                second: second
            )
        }
    )

    expectAtomicInstallError(.applicationRunning) {
        _ = try AtomicInstallSwap.performForTesting(
            parentDirectory: fixture.root,
            nonce: atomicInstallTestNonce,
            expectedCurrent: fixture.currentIdentity,
            expectedStage: fixture.stageIdentity,
            hooks: hooks
        )
    }
    #expect(checks == 2)
    #expect(exchanges == 0)
    #expect(try identityAt(fixture, leaf: fixture.current.lastPathComponent) == fixture.currentIdentity)
}

@Test func atomicInstallSwapRecoversIfApplicationAppearsAfterExchange() throws {
    let fixture = try makeAtomicInstallFixture()
    defer { removeAtomicInstallFixture(fixture) }
    var checks = 0
    var exchanges = 0
    let hooks = AtomicInstallSwapTestHooks(
        applicationIsRunning: {
            checks += 1
            return checks == 3
        },
        exchange: { descriptor, first, second in
            exchanges += 1
            return AtomicInstallSwap.liveExchange(
                parentDescriptor: descriptor,
                first: first,
                second: second
            )
        }
    )

    expectAtomicInstallError(.applicationRunning) {
        _ = try AtomicInstallSwap.performForTesting(
            parentDirectory: fixture.root,
            nonce: atomicInstallTestNonce,
            expectedCurrent: fixture.currentIdentity,
            expectedStage: fixture.stageIdentity,
            hooks: hooks
        )
    }
    #expect(checks == 3)
    #expect(exchanges == 2)
    #expect(try identityAt(fixture, leaf: fixture.current.lastPathComponent) == fixture.currentIdentity)
    #expect(try identityAt(fixture, leaf: fixture.stage.lastPathComponent) == fixture.stageIdentity)
}

@Test func atomicInstallSwapTestAPIRejectsNonPrivateOrUnscopedParents() throws {
    let fixture = try makeAtomicInstallFixture()
    defer { removeAtomicInstallFixture(fixture) }
    let unsafe = URL(fileURLWithPath: "/private/tmp", isDirectory: true)

    expectAtomicInstallError(.unsafeParent) {
        _ = try AtomicInstallSwap.performForTesting(
            parentDirectory: unsafe,
            nonce: atomicInstallTestNonce,
            expectedCurrent: fixture.currentIdentity,
            expectedStage: fixture.stageIdentity
        )
    }
}
