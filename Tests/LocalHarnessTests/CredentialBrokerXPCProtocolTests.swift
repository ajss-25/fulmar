import CoreFoundation
import Foundation
import LocalHarnessCredentialBrokerXPCProtocol
import Testing

struct CredentialBrokerXPCProtocolTests {
    private func request(
        operation: CredentialBrokerXPCOperation = .get,
        subject: String = "DEEPSEEK_API_KEY",
        acceptanceNonce: String = ""
    ) -> CredentialBrokerXPCRequest {
        CredentialBrokerXPCRequest(
            operation: operation,
            subject: subject,
            acceptanceNonce: acceptanceNonce,
            deadlineNanoseconds: 5_000_000_000
        )
    }

    @Test func everyOperationAndStatusRoundTripsThroughTheExactCanonicalSchema() throws {
        let operations: [CredentialBrokerXPCOperation] = [
            .get, .getRecord, .describe, .describeRecord, .set, .setRecord,
            .unset, .unsetRecord, .listRecords, .listRecordAttention,
            .modifyRecordLocked, .backupLoadOrCreate, .acceptance,
        ]
        for operation in operations {
            let needsSubject = ![.listRecords, .listRecordAttention, .backupLoadOrCreate, .acceptance]
                .contains(operation)
            let value = request(
                operation: operation,
                subject: needsSubject ? "provider/key" : "",
                acceptanceNonce: operation == .acceptance
                    ? "123e4567-e89b-12d3-a456-426614174000"
                    : ""
            )
            let data = try CredentialBrokerXPCSchema.encode(value)
            #expect(data.count <= CredentialBrokerXPCConstants.maximumRequestBytes)
            #expect(CredentialBrokerXPCSchema.decodeRequest(data) == value)
        }

        let statuses: [CredentialBrokerXPCStatus] = [
            .success, .notFound, .busy, .invalidRequest, .identityMismatch,
            .authorizationRequired, .recoveryRequired, .unsafeState,
            .persistenceFailure, .verificationFailure, .conflict, .timedOut,
            .interrupted, .internalFailure,
        ]
        for status in statuses {
            let value = CredentialBrokerXPCResponse(
                status: status,
                configured: status == .success
            )
            let data = try CredentialBrokerXPCSchema.encode(value)
            #expect(data.count <= CredentialBrokerXPCConstants.maximumResponseBytes)
            #expect(CredentialBrokerXPCSchema.decodeResponse(data) == value)
        }
    }

    @Test func requestRejectsMissingUnknownDuplicateWrongTypeAndNoncanonicalFields() throws {
        let canonical = try CredentialBrokerXPCSchema.encode(request())
        let text = try #require(String(data: canonical, encoding: .utf8))

        var unknown = try #require(JSONSerialization.jsonObject(with: canonical) as? [String: Any])
        unknown["unexpected"] = 1
        #expect(CredentialBrokerXPCSchema.decodeRequest(
            try JSONSerialization.data(withJSONObject: unknown, options: [.sortedKeys])
        ) == nil)

        var missing = try #require(JSONSerialization.jsonObject(with: canonical) as? [String: Any])
        missing.removeValue(forKey: "subject")
        #expect(CredentialBrokerXPCSchema.decodeRequest(
            try JSONSerialization.data(withJSONObject: missing, options: [.sortedKeys])
        ) == nil)

        let booleanVersion = Data(
            text.replacingOccurrences(of: #""version":1"#, with: #""version":true"#).utf8
        )
        let floatingDeadline = Data(
            text.replacingOccurrences(
                of: #""deadlineNanoseconds":5000000000"#,
                with: #""deadlineNanoseconds":5000000000.0"#
            ).utf8
        )
        let duplicateOperation = Data(
            text.replacingOccurrences(
                of: #""operation":"get""#,
                with: #""operation":"get","operation":"get""#
            ).utf8
        )
        #expect(CredentialBrokerXPCSchema.decodeRequest(booleanVersion) == nil)
        #expect(CredentialBrokerXPCSchema.decodeRequest(floatingDeadline) == nil)
        #expect(CredentialBrokerXPCSchema.decodeRequest(duplicateOperation) == nil)
        #expect(CredentialBrokerXPCSchema.decodeRequest(Data((text + "\n").utf8)) == nil)
        #expect(CredentialBrokerXPCSchema.decodeRequest(Data()) == nil)
        #expect(CredentialBrokerXPCSchema.decodeRequest(
            Data(repeating: 0x20, count: CredentialBrokerXPCConstants.maximumRequestBytes + 1)
        ) == nil)
    }

    @Test func responseRejectsUnavailableOrAmbiguousWireStates() throws {
        let canonical = try CredentialBrokerXPCSchema.encode(
            CredentialBrokerXPCResponse(status: .internalFailure)
        )
        let text = try #require(String(data: canonical, encoding: .utf8))

        var unknown = try #require(JSONSerialization.jsonObject(with: canonical) as? [String: Any])
        unknown["detail"] = "unavailable"
        #expect(CredentialBrokerXPCSchema.decodeResponse(
            try JSONSerialization.data(withJSONObject: unknown, options: [.sortedKeys])
        ) == nil)

        let missingConfigured = Data(
            text.replacingOccurrences(of: #""configured":false,"#, with: "").utf8
        )
        let numericConfigured = Data(
            text.replacingOccurrences(of: #""configured":false"#, with: #""configured":0"#).utf8
        )
        let duplicateStatus = Data(
            text.replacingOccurrences(
                of: #""status":"internalFailure""#,
                with: #""status":"internalFailure","status":"success""#
            ).utf8
        )
        #expect(CredentialBrokerXPCSchema.decodeResponse(missingConfigured) == nil)
        #expect(CredentialBrokerXPCSchema.decodeResponse(numericConfigured) == nil)
        #expect(CredentialBrokerXPCSchema.decodeResponse(duplicateStatus) == nil)
        #expect(CredentialBrokerXPCSchema.decodeResponse(Data((" " + text).utf8)) == nil)
    }

    @Test func productionBoundsAreFiniteAndOrdered() {
        #expect(CredentialBrokerXPCConstants.protocolVersion == 1)
        #expect(CredentialBrokerXPCConstants.minimumDeadlineNanoseconds > 0)
        #expect(
            CredentialBrokerXPCConstants.minimumDeadlineNanoseconds
                < CredentialBrokerXPCConstants.maximumDeadlineNanoseconds
        )
        #expect(CredentialBrokerXPCConstants.maximumRequestBytes <= 16 * 1_024)
        #expect(CredentialBrokerXPCConstants.maximumResponseBytes <= 1 * 1_024)
        #expect(
            CredentialBrokerXPCConstants.maximumCredentialBytes
                <= CredentialBrokerXPCConstants.maximumResponsePayloadBytes
        )
    }
}
