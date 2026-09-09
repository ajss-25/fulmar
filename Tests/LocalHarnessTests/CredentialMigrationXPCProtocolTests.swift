import Foundation
import LocalHarnessCredentialMigrationXPCProtocol
import Testing

struct CredentialMigrationXPCProtocolTests {
    private func identity() -> CredentialMigrationXPCFileIdentity {
        CredentialMigrationXPCFileIdentity(
            device: 1,
            inode: 2,
            mode: 0o100600,
            owner: 501,
            linkCount: 1,
            size: 42,
            modifiedSeconds: 3,
            modifiedNanoseconds: 4,
            changedSeconds: 5,
            changedNanoseconds: 6
        )
    }

    private func request() -> CredentialMigrationXPCRequest {
        let identity = identity()
        return CredentialMigrationXPCRequest(
            sourceName: ".credentials.yaml",
            source: identity,
            sourceParent: identity,
            lease: identity,
            deadlineNanoseconds: 60_000_000_000
        )
    }

    @Test func requestAndResponseSchemasRoundTripWithoutUnboundedFields() throws {
        let request = request()
        let encoded = try CredentialMigrationXPCSchema.encode(request)
        #expect(encoded.count <= CredentialMigrationXPCConstants.maximumRequestBytes)
        #expect(CredentialMigrationXPCSchema.decodeRequest(encoded) == request)

        for status in [
            CredentialMigrationXPCStatus.success,
            .busy,
            .invalidRequest,
            .identityMismatch,
            .sourceChanged,
            .invalidYAML,
            .keychainFailure,
            .timedOut,
            .interrupted,
            .recoveryRequired,
            .internalFailure,
        ] {
            let response = CredentialMigrationXPCResponse(
                status: status,
                references: status == .success ? 2 : 0,
                records: status == .success ? 3 : 0
            )
            let bytes = try CredentialMigrationXPCSchema.encode(response)
            #expect(bytes.count <= CredentialMigrationXPCConstants.maximumResponseBytes)
            #expect(CredentialMigrationXPCSchema.decodeResponse(bytes) == response)
        }
    }

    @Test func acceptanceRequestHasTheSameExactBoundedSchema() throws {
        let identity = identity()
        let nonce = "123e4567-e89b-12d3-a456-426614174000"
        let request = CredentialMigrationXPCRequest(
            operation: .acceptance,
            acceptanceNonce: nonce,
            sourceName: CredentialMigrationXPCConstants.acceptanceSourceName,
            source: identity,
            sourceParent: identity,
            lease: identity,
            deadlineNanoseconds: 5_000_000_000
        )
        let encoded = try CredentialMigrationXPCSchema.encode(request)
        #expect(CredentialMigrationXPCSchema.decodeRequest(encoded) == request)
        let text = try #require(String(data: encoded, encoding: .utf8))
        let unknownOperation = Data(
            text.replacingOccurrences(
                of: #""operation":"acceptance""#,
                with: #""operation":"diagnostic""#
            ).utf8
        )
        #expect(CredentialMigrationXPCSchema.decodeRequest(unknownOperation) == nil)
    }

    @Test func requestSchemaRejectsUnknownKeysWrongTypesDuplicatesAndNoncanonicalBytes() throws {
        let canonical = try CredentialMigrationXPCSchema.encode(request())
        let canonicalText = try #require(String(data: canonical, encoding: .utf8))

        var unknownRoot = try #require(
            JSONSerialization.jsonObject(with: canonical) as? [String: Any]
        )
        unknownRoot["unexpected"] = 1
        let unknownRootBytes = try JSONSerialization.data(
            withJSONObject: unknownRoot,
            options: [.sortedKeys]
        )
        #expect(CredentialMigrationXPCSchema.decodeRequest(unknownRootBytes) == nil)

        var unknownNested = try #require(
            JSONSerialization.jsonObject(with: canonical) as? [String: Any]
        )
        var source = try #require(unknownNested["source"] as? [String: Any])
        source["unexpected"] = 1
        unknownNested["source"] = source
        let unknownNestedBytes = try JSONSerialization.data(
            withJSONObject: unknownNested,
            options: [.sortedKeys]
        )
        #expect(CredentialMigrationXPCSchema.decodeRequest(unknownNestedBytes) == nil)

        var booleanNested = try #require(
            JSONSerialization.jsonObject(with: canonical) as? [String: Any]
        )
        var booleanSource = try #require(booleanNested["source"] as? [String: Any])
        booleanSource["mode"] = true
        booleanNested["source"] = booleanSource
        let booleanNestedBytes = try JSONSerialization.data(
            withJSONObject: booleanNested,
            options: [.sortedKeys]
        )
        #expect(CredentialMigrationXPCSchema.decodeRequest(booleanNestedBytes) == nil)

        var wrongSourceName = try #require(
            JSONSerialization.jsonObject(with: canonical) as? [String: Any]
        )
        wrongSourceName["sourceName"] = 1
        let wrongSourceNameBytes = try JSONSerialization.data(
            withJSONObject: wrongSourceName,
            options: [.sortedKeys]
        )
        #expect(CredentialMigrationXPCSchema.decodeRequest(wrongSourceNameBytes) == nil)

        let booleanVersion = Data(
            canonicalText.replacingOccurrences(of: #""version":1"#, with: #""version":true"#).utf8
        )
        #expect(CredentialMigrationXPCSchema.decodeRequest(booleanVersion) == nil)

        let floatingVersion = Data(
            canonicalText.replacingOccurrences(of: #""version":1"#, with: #""version":1.0"#).utf8
        )
        #expect(CredentialMigrationXPCSchema.decodeRequest(floatingVersion) == nil)

        let duplicateVersion = Data(
            canonicalText.replacingOccurrences(
                of: #""version":1"#,
                with: #""version":1,"version":1"#
            ).utf8
        )
        #expect(CredentialMigrationXPCSchema.decodeRequest(duplicateVersion) == nil)
        #expect(CredentialMigrationXPCSchema.decodeRequest(Data((" " + canonicalText).utf8)) == nil)
        #expect(CredentialMigrationXPCSchema.decodeRequest(Data()) == nil)
        #expect(CredentialMigrationXPCSchema.decodeRequest(
            Data(repeating: 0x20, count: CredentialMigrationXPCConstants.maximumRequestBytes + 1)
        ) == nil)
    }

    @Test func responseSchemaRejectsUnknownKeysWrongTypesDuplicatesAndNoncanonicalBytes() throws {
        let response = CredentialMigrationXPCResponse(status: .success, references: 2, records: 3)
        let canonical = try CredentialMigrationXPCSchema.encode(response)
        let canonicalText = try #require(String(data: canonical, encoding: .utf8))

        var unknown = try #require(
            JSONSerialization.jsonObject(with: canonical) as? [String: Any]
        )
        unknown["unexpected"] = 0
        let unknownBytes = try JSONSerialization.data(withJSONObject: unknown, options: [.sortedKeys])
        #expect(CredentialMigrationXPCSchema.decodeResponse(unknownBytes) == nil)

        let booleanCount = Data(
            canonicalText.replacingOccurrences(of: #""records":3"#, with: #""records":true"#).utf8
        )
        #expect(CredentialMigrationXPCSchema.decodeResponse(booleanCount) == nil)

        let floatingCount = Data(
            canonicalText.replacingOccurrences(of: #""references":2"#, with: #""references":2.0"#).utf8
        )
        #expect(CredentialMigrationXPCSchema.decodeResponse(floatingCount) == nil)

        let duplicateStatus = Data(
            canonicalText.replacingOccurrences(
                of: #""status":"success""#,
                with: #""status":"success","status":"success""#
            ).utf8
        )
        #expect(CredentialMigrationXPCSchema.decodeResponse(duplicateStatus) == nil)
        #expect(CredentialMigrationXPCSchema.decodeResponse(Data((canonicalText + "\n").utf8)) == nil)
        #expect(CredentialMigrationXPCSchema.decodeResponse(
            Data(repeating: 0x20, count: CredentialMigrationXPCConstants.maximumResponseBytes + 1)
        ) == nil)
    }

    @Test func productionBoundsAreFiniteAndMutuallyConsistent() {
        #expect(CredentialMigrationXPCConstants.protocolVersion == 1)
        #expect(CredentialMigrationXPCConstants.exactYAMLModuleCount == 74)
        #expect(CredentialMigrationXPCConstants.maximumRequestBytes == 16 * 1_024)
        #expect(CredentialMigrationXPCConstants.maximumResponseBytes == 1_024)
        #expect(CredentialMigrationXPCConstants.maximumGraphBytes == 8 * 1_024 * 1_024)
        #expect(CredentialMigrationXPCConstants.maximumSourceBytes == 4 * 1_024 * 1_024)
        #expect(CredentialMigrationXPCConstants.maximumCredentialBytes == 1 * 1_024 * 1_024)
        #expect(CredentialMigrationXPCConstants.maximumEntryCount == 4_096)
        #expect(CredentialMigrationXPCConstants.minimumDeadlineNanoseconds > 0)
        #expect(CredentialMigrationXPCConstants.maximumDeadlineNanoseconds
            > CredentialMigrationXPCConstants.minimumDeadlineNanoseconds)
        #expect(CredentialMigrationXPCConstants.serviceName
            == "com.angadjairath.localharness.credential-helper")
        #expect(CredentialMigrationXPCConstants.leaseFileName
            == ".fulmar-credential-migration.lock")
        #expect(CredentialMigrationXPCConstants.acceptanceSourceName
            == ".fulmar-credential-xpc-acceptance")
    }
}
