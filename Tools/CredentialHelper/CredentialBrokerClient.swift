import Darwin
import Foundation
import LocalHarnessCredentialBrokerXPCProtocol
import Security

private enum BrokerClientError: Error {
    case invalidCommand
    case invalidBundle
    case unavailable
    case timedOut
    case invalidResponse
    case service(CredentialBrokerXPCStatus)
}

private func brokerHasCanonicalFileURL(_ url: URL) -> Bool {
    // Do not normalize away /private: existing canonical temporary candidates
    // are rewritten to /tmp by Foundation. Only realpath equality admits the
    // caller's exact spelling, with real symlinks and aliases still rejected.
    guard url.isFileURL,
          url.path.hasPrefix("/"),
          !url.path.contains("\0"),
          let resolved = url.path.withCString({ Darwin.realpath($0, nil) }) else {
        return false
    }
    defer { free(resolved) }
    return String(cString: resolved) == url.path
}

private struct BrokerCodeIdentity {
    let identifier: String
    let designatedRequirement: Data
    let exactRequirement: String

    static func inspect(_ url: URL) throws -> BrokerCodeIdentity {
        guard brokerHasCanonicalFileURL(url) else {
            throw BrokerClientError.invalidBundle
        }
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess,
              let code,
              SecStaticCodeCheckValidity(
                  code,
                  SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate),
                  nil
              ) == errSecSuccess else { throw BrokerClientError.invalidBundle }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(
            code,
            SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSRequirementInformation),
            &information
        ) == errSecSuccess,
              let values = information as? [String: Any],
              let identifier = values[kSecCodeInfoIdentifier as String] as? String,
              let cdHash = values[kSecCodeInfoUnique as String] as? Data,
              !cdHash.isEmpty,
              cdHash.count <= 64,
              let rawRequirement = values[kSecCodeInfoDesignatedRequirement as String],
              CFGetTypeID(rawRequirement as CFTypeRef) == SecRequirementGetTypeID() else {
            throw BrokerClientError.invalidBundle
        }
        let requirement = unsafeBitCast(rawRequirement as AnyObject, to: SecRequirement.self)
        var requirementData: CFData?
        var requirementString: CFString?
        guard SecRequirementCopyData(requirement, [], &requirementData) == errSecSuccess,
              let requirementData,
              SecRequirementCopyString(requirement, [], &requirementString) == errSecSuccess,
              let requirementString else { throw BrokerClientError.invalidBundle }
        let digest = cdHash.map { String(format: "%02x", $0) }.joined()
        return BrokerCodeIdentity(
            identifier: identifier,
            designatedRequirement: requirementData as Data,
            exactRequirement: "(\(requirementString as String)) and cdhash H\"\(digest)\""
        )
    }
}

private final class BrokerReplyGate: @unchecked Sendable {
    private let lock = NSLock()
    private var result: Result<(CredentialBrokerXPCResponse, Data), BrokerClientError>?
    let semaphore = DispatchSemaphore(value: 0)

    func resolve(_ value: Result<(CredentialBrokerXPCResponse, Data), BrokerClientError>) {
        let signal = lock.withLock { () -> Bool in
            guard result == nil else { return false }
            result = value
            return true
        }
        if signal { semaphore.signal() }
    }

    func take() -> Result<(CredentialBrokerXPCResponse, Data), BrokerClientError>? {
        lock.withLock { result }
    }
}

private func brokerInput(maximumBytes: Int) -> Data {
    var data = Data()
    var buffer = [UInt8](repeating: 0, count: 64 * 1_024)
    while data.count <= maximumBytes {
        let requested = min(buffer.count, maximumBytes + 1 - data.count)
        let count = buffer.withUnsafeMutableBytes { storage -> Int in
            guard let baseAddress = storage.baseAddress else { return -1 }
            return Darwin.read(STDIN_FILENO, baseAddress, requested)
        }
        if count == 0 { break }
        if count < 0, errno == EINTR { continue }
        guard count > 0 else { brokerClientFail(.unavailable) }
        data.append(contentsOf: buffer.prefix(count))
    }
    guard data.count <= maximumBytes else { brokerClientFail(.invalidCommand) }
    return data
}

private func brokerClientFail(_ error: BrokerClientError) -> Never {
    let status: Int32
    let message: String
    switch error {
    case .service(.notFound): status = 3; message = "credential was not found"
    case .service(.authorizationRequired): status = 5; message = "Keychain authorization is required"
    case .service(.recoveryRequired): status = 6; message = "credential recovery is required"
    case .service(.busy): status = 7; message = "credential broker is busy"
    case .service(.unsafeState): status = 8; message = "credential state is unsafe"
    case .service(.persistenceFailure): status = 9; message = "credential state is unavailable"
    case .service(.verificationFailure): status = 10; message = "credential verification failed"
    case .service(.conflict): status = 11; message = "credential changed before commit"
    case .timedOut, .service(.timedOut): status = 12; message = "credential broker timed out"
    case .invalidCommand, .service(.invalidRequest): status = 2; message = "credential request is invalid"
    case .invalidBundle, .service(.identityMismatch): status = 2; message = "credential broker identity is invalid"
    case .unavailable, .service(.interrupted), .service(.internalFailure), .invalidResponse:
        status = 2; message = "credential broker is unavailable"
    case .service(.success): status = 2; message = "credential broker response is invalid"
    }
    FileHandle.standardError.write(Data("Credential helper: \(message)\n".utf8))
    exit(status)
}

private func brokerOperation(_ command: String) -> CredentialBrokerXPCOperation? {
    switch command {
    case "get": .get
    case "get-record": .getRecord
    case "describe": .describe
    case "describe-record": .describeRecord
    case "set": .set
    case "set-record": .setRecord
    case "unset": .unset
    case "unset-record": .unsetRecord
    case "list-records": .listRecords
    case "list-record-attention": .listRecordAttention
    case "modify-record-locked": .modifyRecordLocked
    case "backup-load-or-create": .backupLoadOrCreate
    case "broker-acceptance": .acceptance
    default: nil
    }
}

func dispatchCredentialBrokerCommandIfNeeded(
    command: String,
    arguments: [String]
) {
    guard let operation = brokerOperation(command) else { return }
    guard brokerIsPackagedHelper() else {
        #if DEBUG
        // Source-tree recovery tests exercise the transaction library through
        // the historical helper seam. A release helper has no such fallback:
        // outside its signed app/XPC layout it fails before credential input is
        // read or any Keychain/metadata API is reached.
        return
        #else
        brokerClientFail(.invalidBundle)
        #endif
    }
    let subjectOperations: Set<CredentialBrokerXPCOperation> = [
        .get, .getRecord, .describe, .describeRecord, .set, .setRecord,
        .unset, .unsetRecord, .modifyRecordLocked,
    ]
    let subject: String
    if subjectOperations.contains(operation) {
        guard arguments.count == 3 else { brokerClientFail(.invalidCommand) }
        subject = arguments[2]
    } else {
        guard arguments.count == 2 else { brokerClientFail(.invalidCommand) }
        subject = ""
    }
    let payload = operation == .set || operation == .setRecord
        ? brokerInput(maximumBytes: CredentialBrokerXPCConstants.maximumCredentialBytes)
        : Data()
    let acceptanceNonce = operation == .acceptance ? UUID().uuidString.lowercased() : ""
    let deadline: TimeInterval = operation == .modifyRecordLocked ? 35 : 10
    let response: (CredentialBrokerXPCResponse, Data)
    do {
        response = try invokeBroker(
            operation: operation,
            subject: subject,
            acceptanceNonce: acceptanceNonce,
            payload: payload,
            deadline: deadline
        )
    } catch let error as BrokerClientError {
        brokerClientFail(error)
    } catch {
        brokerClientFail(.unavailable)
    }
    guard response.0.status == .success else { brokerClientFail(.service(response.0.status)) }
    switch operation {
    case .get, .getRecord, .listRecords, .listRecordAttention, .backupLoadOrCreate:
        FileHandle.standardOutput.write(response.1)
    case .describe, .describeRecord:
        FileHandle.standardOutput.write(Data(response.0.configured ? "1".utf8 : "0".utf8))
    case .acceptance:
        guard response.1.isEmpty else { brokerClientFail(.invalidResponse) }
        FileHandle.standardOutput.write(Data("FULMAR_CREDENTIAL_BROKER_ACCEPTANCE_OK\n".utf8))
    case .set, .setRecord, .unset, .unsetRecord, .modifyRecordLocked:
        guard response.1.isEmpty else { brokerClientFail(.invalidResponse) }
    }
    exit(0)
}

private func brokerIsPackagedHelper() -> Bool {
    let executable = URL(fileURLWithPath: CommandLine.arguments[0], isDirectory: false)
    let macOSDirectory = executable.deletingLastPathComponent()
    let contents = macOSDirectory.deletingLastPathComponent()
    let application = contents.deletingLastPathComponent()
    return brokerHasCanonicalFileURL(executable)
        && executable.lastPathComponent == "LocalHarnessCredentialHelper"
        && macOSDirectory.lastPathComponent == "MacOS"
        && contents.lastPathComponent == "Contents"
        && application.pathExtension == "app"
        && Bundle(url: application)?.bundleIdentifier == "com.angadjairath.localharness"
}

private func invokeBroker(
    operation: CredentialBrokerXPCOperation,
    subject: String,
    acceptanceNonce: String,
    payload: Data,
    deadline: TimeInterval
) throws -> (CredentialBrokerXPCResponse, Data) {
    guard deadline.isFinite, deadline >= 0.05, deadline <= 35 else {
        throw BrokerClientError.invalidCommand
    }
    let executable = URL(fileURLWithPath: CommandLine.arguments[0], isDirectory: false)
    let macOSDirectory = executable.deletingLastPathComponent()
    let contents = macOSDirectory.deletingLastPathComponent()
    let application = contents.deletingLastPathComponent()
    let serviceBundle = contents.appendingPathComponent("XPCServices", isDirectory: true)
        .appendingPathComponent(CredentialBrokerXPCConstants.serviceBundleName, isDirectory: true)
    guard brokerHasCanonicalFileURL(executable),
          executable.lastPathComponent == "LocalHarnessCredentialHelper",
          macOSDirectory.lastPathComponent == "MacOS",
          contents.lastPathComponent == "Contents",
          application.pathExtension == "app",
          Bundle(url: application)?.bundleIdentifier == "com.angadjairath.localharness",
          Bundle(url: serviceBundle)?.bundleIdentifier == CredentialBrokerXPCConstants.serviceName else {
        throw BrokerClientError.invalidBundle
    }
    let helperIdentity = try BrokerCodeIdentity.inspect(executable)
    let serviceIdentity = try BrokerCodeIdentity.inspect(serviceBundle)
    guard helperIdentity.identifier == CredentialBrokerXPCConstants.codeIdentifier,
          serviceIdentity.identifier == CredentialBrokerXPCConstants.codeIdentifier,
          helperIdentity.designatedRequirement == serviceIdentity.designatedRequirement else {
        throw BrokerClientError.invalidBundle
    }
    let duration = UInt64((deadline * 1_000_000_000).rounded(.down))
    let request = CredentialBrokerXPCRequest(
        operation: operation,
        subject: subject,
        acceptanceNonce: acceptanceNonce,
        deadlineNanoseconds: duration
    )
    let requestData = try CredentialBrokerXPCSchema.encode(request)
    guard requestData.count <= CredentialBrokerXPCConstants.maximumRequestBytes else {
        throw BrokerClientError.invalidCommand
    }
    let gate = BrokerReplyGate()
    let connection = NSXPCConnection(serviceName: CredentialBrokerXPCConstants.serviceName)
    connection.setCodeSigningRequirement(serviceIdentity.exactRequirement)
    connection.remoteObjectInterface = NSXPCInterface(
        with: LocalHarnessCredentialBrokerXPCProtocol.self
    )
    connection.interruptionHandler = { gate.resolve(.failure(.unavailable)) }
    connection.invalidationHandler = { gate.resolve(.failure(.unavailable)) }
    connection.resume()
    guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in
        gate.resolve(.failure(.unavailable))
    }) as? LocalHarnessCredentialBrokerXPCProtocol else {
        connection.invalidate()
        throw BrokerClientError.unavailable
    }
    proxy.perform(
        request: requestData as NSData,
        payload: payload as NSData,
        input: FileHandle.standardInput,
        output: FileHandle.standardOutput
    ) { responseData, responsePayload in
        guard responsePayload.length <= CredentialBrokerXPCConstants.maximumResponsePayloadBytes,
              let response = CredentialBrokerXPCSchema.decodeResponse(responseData as Data),
              response.version == CredentialBrokerXPCConstants.protocolVersion,
              response.status == .success || responsePayload.length == 0,
              response.status == .success || !response.configured else {
            gate.resolve(.failure(.invalidResponse))
            return
        }
        gate.resolve(.success((response, responsePayload as Data)))
    }
    let wait = gate.semaphore.wait(timeout: .now() + deadline + 1)
    connection.invalidate()
    guard wait == .success, let result = gate.take() else { throw BrokerClientError.timedOut }
    let response = try result.get()
    let helperAfter = try BrokerCodeIdentity.inspect(executable)
    let serviceAfter = try BrokerCodeIdentity.inspect(serviceBundle)
    guard helperAfter.identifier == helperIdentity.identifier,
          helperAfter.designatedRequirement == helperIdentity.designatedRequirement,
          helperAfter.exactRequirement == helperIdentity.exactRequirement,
          serviceAfter.identifier == serviceIdentity.identifier,
          serviceAfter.designatedRequirement == serviceIdentity.designatedRequirement,
          serviceAfter.exactRequirement == serviceIdentity.exactRequirement else {
        throw BrokerClientError.invalidBundle
    }
    return response
}
