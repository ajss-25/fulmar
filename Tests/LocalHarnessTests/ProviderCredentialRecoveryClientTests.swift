import Darwin
import Foundation
import Testing
@testable import LocalHarness

private struct CredentialRecoveryInvocation: Equatable, Sendable {
    let executable: URL
    let arguments: [String]
    let environment: [String: String]
    let input: Data?
    let outputLimit: Int
    let errorLimit: Int
    let deadline: TimeInterval
}

private final class CredentialRecoveryProcessProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var storedInvocations: [CredentialRecoveryInvocation] = []
    var result = CredentialMigrationProcessResult(
        exitStatus: 0,
        terminationSignal: nil,
        standardOutput: Data("OK\n".utf8),
        standardError: Data(),
        limit: nil
    )
    var thrownError: Error?
    private var queuedResults: [CredentialMigrationProcessResult] = []

    func enqueue(_ results: [CredentialMigrationProcessResult]) {
        lock.lock()
        queuedResults.append(contentsOf: results)
        lock.unlock()
    }

    func run(
        executable: URL,
        arguments: [String],
        environment: [String: String],
        input: Data?,
        outputLimit: Int,
        errorLimit: Int,
        deadline: TimeInterval
    ) throws -> CredentialMigrationProcessResult {
        lock.lock()
        storedInvocations.append(CredentialRecoveryInvocation(
            executable: executable,
            arguments: arguments,
            environment: environment,
            input: input,
            outputLimit: outputLimit,
            errorLimit: errorLimit,
            deadline: deadline
        ))
        var result = queuedResults.isEmpty ? self.result : queuedResults.removeFirst()
        if queuedResults.isEmpty,
           arguments.first == "describe" || arguments.first == "describe-record",
           result.exitStatus == 0,
           result.standardOutput == Data("OK\n".utf8) {
            let precedingCommand = storedInvocations.dropLast().last?.arguments.first
            result = CredentialMigrationProcessResult(
                exitStatus: 0,
                terminationSignal: nil,
                standardOutput: Data((precedingCommand == "repair-remove" || precedingCommand == "repair-remove-record" ? "0" : "1").utf8),
                standardError: Data(),
                limit: nil
            )
        }
        let thrownError = self.thrownError
        lock.unlock()
        if let thrownError { throw thrownError }
        return result
    }

    var invocations: [CredentialRecoveryInvocation] {
        lock.lock()
        defer { lock.unlock() }
        return storedInvocations
    }
}

private struct SecretDiagnosticError: LocalizedError, Sendable {
    let secret: String
    var errorDescription: String? { "runner leaked \(secret)" }
}

private func credentialRecoveryClient(
    probe: CredentialRecoveryProcessProbe,
    helper: URL = URL(fileURLWithPath: "/private/tmp/Fulmar Credential Helper")
) -> ProviderCredentialRecoveryClient {
    ProviderCredentialRecoveryClient(
        componentLocator: { .init(helper: helper) },
        processRunner: { executable, arguments, environment, input, output, error, deadline in
            try probe.run(
                executable: executable,
                arguments: arguments,
                environment: environment,
                input: input,
                outputLimit: output,
                errorLimit: error,
                deadline: deadline
            )
        }
    )
}

@Suite(.serialized)
struct ProviderCredentialRecoveryClientTests {
    @Test func pinnedHelperReplacementBetweenRepairAndVerificationFailsClosed() async throws {
        let root = URL(fileURLWithPath: "/tmp", isDirectory: true)
            .appendingPathComponent("fulmar-helper-pin-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        defer { try? FileManager.default.removeItem(at: root) }
        let helper = root.appendingPathComponent("LocalHarnessCredentialHelper")
        try Data("first".utf8).write(to: helper)
        #expect(chmod(helper.path, 0o700) == 0)
        let client = ProviderCredentialRecoveryClient(
            componentLocator: { .init(helper: helper, enforceIdentity: true) },
            processRunner: { _, _, _, _, _, _, _ in
                try FileManager.default.removeItem(at: helper)
                try Data("replacement".utf8).write(to: helper)
                _ = chmod(helper.path, 0o700)
                return CredentialMigrationProcessResult(
                    exitStatus: 0, terminationSignal: nil,
                    standardOutput: Data("OK\n".utf8), standardError: Data(), limit: nil
                )
            }
        )
        await #expect(throws: ProviderCredentialRecoveryFailure.unavailable) {
            try await client.authorizeExisting(CredentialReference("DEEPSEEK_API_KEY"))
        }
    }

    @Test func recordAttentionAndRepairsAreValueFreeBoundedAndFreshlyVerified() async throws {
        let probe = CredentialRecoveryProcessProbe()
        probe.enqueue([
            CredentialMigrationProcessResult(
                exitStatus: 0, terminationSignal: nil,
                standardOutput: Data(#"[{"key":"provider/account","kind":"api-key","reason":"authorization","token":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"key":"grant/session","kind":"grant","reason":"ambiguous","token":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},{"key":"broken/item","kind":"api-key","reason":"invalid","token":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},{"key":"unknown/item","kind":"unknown","reason":"invalid","token":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}]"#.utf8),
                standardError: Data(), limit: nil
            )
        ])
        let client = credentialRecoveryClient(probe: probe)
        let attention = try await client.listRecordAttention()
        #expect(attention.map(\.key) == ["broken/item", "grant/session", "provider/account", "unknown/item"])
        #expect(attention.map(\.reason) == [.invalid, .ambiguous, .authorization, .invalid])

        try await client.authorizeRecord("provider/account")
        try await client.adoptCurrentRecord("grant/session")
        try await client.removeCurrentRecord("broken/item")
        #expect(probe.invocations.map(\.arguments) == [
            ["list-record-attention"],
            ["authorize-record", "provider/account"],
            ["describe-record", "provider/account"],
            ["repair-adopt-record", "grant/session"],
            ["describe-record", "grant/session"],
            ["repair-remove-record", "broken/item"],
            ["describe-record", "broken/item"],
        ])
        #expect(probe.invocations.first?.outputLimit == 3 * 1_024 * 1_024)
        #expect(probe.invocations[5].input == Data(String(repeating: "c", count: 64).utf8))
    }

    @Test func recordAttentionRejectsDuplicateInvalidOrSecretBearingResponses() async {
        for payload in [
            #"[{"key":"same/key","kind":"api-key","reason":"authorization","token":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"key":"same/key","kind":"api-key","reason":"ambiguous","token":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]"#,
            #"[{"key":"no-slash","kind":"api-key","reason":"invalid","token":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]"#,
            #"[{"key":"safe/key","kind":"api-key","reason":"authorization","token":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","value":"secret"}]"#,
            #"[{"key":"unknown/ambiguous","kind":"unknown","reason":"ambiguous","token":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]"#,
            #"[{"key":"unknown/authorization","kind":"unknown","reason":"authorization","token":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]"#,
        ] {
            let probe = CredentialRecoveryProcessProbe()
            probe.result = CredentialMigrationProcessResult(
                exitStatus: 0, terminationSignal: nil,
                standardOutput: Data(payload.utf8), standardError: Data(), limit: nil
            )
            do {
                _ = try await credentialRecoveryClient(probe: probe).listRecordAttention()
                Issue.record("Unsafe record attention payload was accepted")
            } catch let error as ProviderCredentialRecoveryFailure {
                #expect(error == .invalidResponse)
            } catch { Issue.record("Unexpected error: \(error)") }
        }
    }

    @Test func usesExactHelperCommandsEnvironmentBoundsAndReplacementStdin() async throws {
        let helper = URL(fileURLWithPath: "/private/tmp/Fulmar Credential Helper")
        let probe = CredentialRecoveryProcessProbe()
        let client = credentialRecoveryClient(probe: probe, helper: helper)
        let reference = CredentialReference("DEEPSEEK_API_KEY")
        let replacement = "sk-replacement-å"

        try await client.authorizeExisting(reference)
        try await client.adoptCurrent(reference)
        try await client.replaceCurrent(reference, value: replacement)
        try await client.removeCurrent(reference)

        let expectedEnvironment = ChildProcessEnvironment.make(nodeBin: nil)
        #expect(probe.invocations == [
            CredentialRecoveryInvocation(
                executable: helper,
                arguments: ["authorize", "DEEPSEEK_API_KEY"],
                environment: expectedEnvironment,
                input: nil,
                outputLimit: 16,
                errorLimit: 4 * 1_024,
                deadline: 120
            ),
            CredentialRecoveryInvocation(
                executable: helper,
                arguments: ["describe", "DEEPSEEK_API_KEY"],
                environment: expectedEnvironment,
                input: nil,
                outputLimit: 16,
                errorLimit: 4 * 1_024,
                deadline: 120
            ),
            CredentialRecoveryInvocation(
                executable: helper,
                arguments: ["repair-adopt", "DEEPSEEK_API_KEY"],
                environment: expectedEnvironment,
                input: nil,
                outputLimit: 16,
                errorLimit: 4 * 1_024,
                deadline: 120
            ),
            CredentialRecoveryInvocation(
                executable: helper,
                arguments: ["describe", "DEEPSEEK_API_KEY"],
                environment: expectedEnvironment,
                input: nil,
                outputLimit: 16,
                errorLimit: 4 * 1_024,
                deadline: 120
            ),
            CredentialRecoveryInvocation(
                executable: helper,
                arguments: ["repair-replace", "DEEPSEEK_API_KEY"],
                environment: expectedEnvironment,
                input: Data(replacement.utf8),
                outputLimit: 16,
                errorLimit: 4 * 1_024,
                deadline: 120
            ),
            CredentialRecoveryInvocation(
                executable: helper,
                arguments: ["describe", "DEEPSEEK_API_KEY"],
                environment: expectedEnvironment,
                input: nil,
                outputLimit: 16,
                errorLimit: 4 * 1_024,
                deadline: 120
            ),
            CredentialRecoveryInvocation(
                executable: helper,
                arguments: ["repair-remove", "DEEPSEEK_API_KEY"],
                environment: expectedEnvironment,
                input: nil,
                outputLimit: 16,
                errorLimit: 4 * 1_024,
                deadline: 120
            ),
            CredentialRecoveryInvocation(
                executable: helper,
                arguments: ["describe", "DEEPSEEK_API_KEY"],
                environment: expectedEnvironment,
                input: nil,
                outputLimit: 16,
                errorLimit: 4 * 1_024,
                deadline: 120
            )
        ])
    }

    @Test func foregroundSuccessRequiresAFreshNoninteractiveAccessProof() async {
        let probe = CredentialRecoveryProcessProbe()
        probe.enqueue([
            CredentialMigrationProcessResult(
                exitStatus: 0,
                terminationSignal: nil,
                standardOutput: Data("OK\n".utf8),
                standardError: Data(),
                limit: nil
            ),
            CredentialMigrationProcessResult(
                exitStatus: 5,
                terminationSignal: nil,
                standardOutput: Data(),
                standardError: Data("SECRET_MUST_NOT_ESCAPE".utf8),
                limit: nil
            ),
        ])
        let client = credentialRecoveryClient(probe: probe)
        do {
            try await client.authorizeExisting(CredentialReference("TEST_KEY"))
            Issue.record("One-process foreground authorization was incorrectly accepted")
        } catch let error as ProviderCredentialRecoveryFailure {
            #expect(error == .persistentAuthorizationRequired)
            #expect(!error.localizedDescription.contains("SECRET_MUST_NOT_ESCAPE"))
        } catch {
            Issue.record("Expected ProviderCredentialRecoveryFailure, got \(error)")
        }
        #expect(probe.invocations.map(\.arguments) == [
            ["authorize", "TEST_KEY"],
            ["describe", "TEST_KEY"],
        ])
    }

    @Test func mapsEveryStableHelperExitWithoutReadingDiagnosticText() async {
        let cases: [(Int32, ProviderCredentialRecoveryFailure)] = [
            (5, .authorizationRequired),
            (6, .recoveryRequired),
            (7, .busy),
            (8, .unsafeState),
            (9, .persistenceUnavailable),
            (10, .verificationFailed)
        ]
        for (status, expected) in cases {
            let probe = CredentialRecoveryProcessProbe()
            probe.result = CredentialMigrationProcessResult(
                exitStatus: status,
                terminationSignal: nil,
                standardOutput: Data(),
                standardError: Data("DIAGNOSTIC_SECRET_\(status)".utf8),
                limit: nil
            )
            let client = credentialRecoveryClient(probe: probe)
            do {
                try await client.authorizeExisting(CredentialReference("TEST_KEY"))
                Issue.record("Helper exit \(status) was unexpectedly accepted")
            } catch let error as ProviderCredentialRecoveryFailure {
                #expect(error == expected)
                #expect(!(error.localizedDescription.contains("DIAGNOSTIC_SECRET")))
            } catch {
                Issue.record("Expected ProviderCredentialRecoveryFailure, got \(error)")
            }
        }
    }

    @Test func rejectsMalformedSuccessAndMapsDeadlineAndSignal() async {
        let cases: [(CredentialMigrationProcessResult, ProviderCredentialRecoveryFailure)] = [
            (
                CredentialMigrationProcessResult(
                    exitStatus: 0,
                    terminationSignal: nil,
                    standardOutput: Data("OK".utf8),
                    standardError: Data(),
                    limit: nil
                ),
                .invalidResponse
            ),
            (
                CredentialMigrationProcessResult(
                    exitStatus: nil,
                    terminationSignal: nil,
                    standardOutput: Data(),
                    standardError: Data(),
                    limit: .deadline(120)
                ),
                .timedOut
            ),
            (
                CredentialMigrationProcessResult(
                    exitStatus: nil,
                    terminationSignal: SIGKILL,
                    standardOutput: Data(),
                    standardError: Data("SIGNAL_SECRET".utf8),
                    limit: nil
                ),
                .unavailable
            )
        ]
        for (result, expected) in cases {
            let probe = CredentialRecoveryProcessProbe()
            probe.result = result
            let client = credentialRecoveryClient(probe: probe)
            do {
                try await client.adoptCurrent(CredentialReference("TEST_KEY"))
                Issue.record("Malformed helper result was unexpectedly accepted")
            } catch let error as ProviderCredentialRecoveryFailure {
                #expect(error == expected)
                #expect(!(error.localizedDescription.contains("SECRET")))
            } catch {
                Issue.record("Expected ProviderCredentialRecoveryFailure, got \(error)")
            }
        }
    }

    @Test func runnerDiagnosticsAndThrownSecretsNeverSurface() async {
        let secret = "SUPER_SECRET_DIAGNOSTIC_VALUE"
        let probe = CredentialRecoveryProcessProbe()
        probe.thrownError = SecretDiagnosticError(secret: secret)
        let client = credentialRecoveryClient(probe: probe)

        do {
            try await client.removeCurrent(CredentialReference("TEST_KEY"))
            Issue.record("A thrown runner failure was unexpectedly accepted")
        } catch let error as ProviderCredentialRecoveryFailure {
            #expect(error == .unavailable)
            #expect(!(error.localizedDescription.contains(secret)))
            #expect(!(String(describing: error).contains(secret)))
        } catch {
            Issue.record("Expected ProviderCredentialRecoveryFailure, got \(error)")
        }
    }

    @Test func replacementValidationRejectsEmptyNewlineAndOversizedValuesBeforeSpawn() async {
        let probe = CredentialRecoveryProcessProbe()
        let client = credentialRecoveryClient(probe: probe)
        let invalidValues = ["", "line\nbreak", String(repeating: "x", count: 32 * 1_024 + 1)]

        for value in invalidValues {
            do {
                try await client.replaceCurrent(CredentialReference("TEST_KEY"), value: value)
                Issue.record("Invalid replacement input was unexpectedly admitted")
            } catch let error as ProviderCredentialRecoveryFailure {
                #expect(error == .invalidResponse)
            } catch {
                Issue.record("Expected ProviderCredentialRecoveryFailure, got \(error)")
            }
        }
        #expect(probe.invocations.isEmpty)
    }
}
