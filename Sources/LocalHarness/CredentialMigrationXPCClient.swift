import Darwin
import Foundation
import LocalHarnessCredentialMigrationXPCProtocol
import Security

enum CredentialMigrationXPCClientError: Error, Equatable, Sendable {
    case serviceMissing
    case serviceIdentityMismatch
    case invalidCapabilities
    case unavailable
    case interrupted
    case timedOut
    case sourceChanged
    case invalidResponse
    case service(CredentialMigrationXPCStatus)
}

private struct CredentialMigrationXPCCodeIdentity {
    let identifier: String
    let designatedRequirement: Data
    let exactRequirement: String

    static func inspect(_ url: URL, nested: Bool) throws -> CredentialMigrationXPCCodeIdentity {
        guard url.isFileURL,
              url.path.hasPrefix("/"),
              !url.path.contains("\0"),
              url.path == url.standardizedFileURL.path,
              url.path == url.resolvingSymlinksInPath().standardizedFileURL.path else {
            throw CredentialMigrationXPCClientError.serviceIdentityMismatch
        }
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess,
              let code else {
            throw CredentialMigrationXPCClientError.serviceIdentityMismatch
        }
        var rawFlags = kSecCSCheckAllArchitectures | kSecCSStrictValidate
        if nested { rawFlags |= kSecCSCheckNestedCode }
        let flags = SecCSFlags(rawValue: rawFlags)
        guard SecStaticCodeCheckValidity(code, flags, nil) == errSecSuccess else {
            throw CredentialMigrationXPCClientError.serviceIdentityMismatch
        }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(
            code,
            SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSRequirementInformation),
            &information
        ) == errSecSuccess,
              let values = information as? [String: Any],
              let identifier = values[kSecCodeInfoIdentifier as String] as? String,
              !identifier.isEmpty,
              identifier.utf8.count <= 256,
              let cdHash = values[kSecCodeInfoUnique as String] as? Data,
              !cdHash.isEmpty,
              cdHash.count <= 64,
              let rawRequirement = values[kSecCodeInfoDesignatedRequirement as String],
              CFGetTypeID(rawRequirement as CFTypeRef) == SecRequirementGetTypeID() else {
            throw CredentialMigrationXPCClientError.serviceIdentityMismatch
        }
        let requirement = unsafeBitCast(rawRequirement as AnyObject, to: SecRequirement.self)
        var requirementData: CFData?
        var requirementString: CFString?
        guard SecRequirementCopyData(requirement, [], &requirementData) == errSecSuccess,
              let requirementData,
              (requirementData as Data).count <= 16 * 1_024,
              SecRequirementCopyString(requirement, [], &requirementString) == errSecSuccess,
              let requirementString,
              (requirementString as String).utf8.count <= 16 * 1_024,
              SecStaticCodeCheckValidity(code, flags, requirement) == errSecSuccess else {
            throw CredentialMigrationXPCClientError.serviceIdentityMismatch
        }
        let digest = cdHash.map { String(format: "%02x", $0) }.joined()
        return CredentialMigrationXPCCodeIdentity(
            identifier: identifier,
            designatedRequirement: requirementData as Data,
            exactRequirement: "(\(requirementString as String)) and cdhash H\"\(digest)\""
        )
    }
}

private final class CredentialMigrationXPCReplyGate: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Result<CredentialMigrationXPCResponse, CredentialMigrationXPCClientError>?
    let semaphore = DispatchSemaphore(value: 0)

    func resolve(
        _ result: Result<CredentialMigrationXPCResponse, CredentialMigrationXPCClientError>
    ) {
        lock.lock()
        let shouldSignal = value == nil
        if shouldSignal { value = result }
        lock.unlock()
        if shouldSignal { semaphore.signal() }
    }

    func result() -> Result<CredentialMigrationXPCResponse, CredentialMigrationXPCClientError>? {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

enum CredentialMigrationXPCClient {
    static func run(
        serviceBundleURL: URL,
        helperURL: URL,
        sourceURL: URL,
        leaseDescriptor: CredentialMigrationInheritedDescriptor,
        yamlGraph: Data,
        deadline: TimeInterval
    ) throws -> CredentialMigrationXPCResponse {
        try run(
            serviceBundleURL: serviceBundleURL,
            helperURL: helperURL,
            sourceURL: sourceURL,
            leaseDescriptor: leaseDescriptor,
            yamlGraph: yamlGraph,
            deadline: deadline,
            operation: .migration,
            acceptanceNonce: ""
        )
    }

    static func runAcceptance(
        serviceBundleURL: URL,
        helperURL: URL,
        sourceURL: URL,
        leaseDescriptor: CredentialMigrationInheritedDescriptor,
        acceptanceNonce: String,
        deadline: TimeInterval = 5
    ) throws -> CredentialMigrationXPCResponse {
        try run(
            serviceBundleURL: serviceBundleURL,
            helperURL: helperURL,
            sourceURL: sourceURL,
            leaseDescriptor: leaseDescriptor,
            yamlGraph: Data(),
            deadline: deadline,
            operation: .acceptance,
            acceptanceNonce: acceptanceNonce
        )
    }

    private static func run(
        serviceBundleURL: URL,
        helperURL: URL,
        sourceURL: URL,
        leaseDescriptor: CredentialMigrationInheritedDescriptor,
        yamlGraph: Data,
        deadline: TimeInterval,
        operation: CredentialMigrationXPCOperation,
        acceptanceNonce: String
    ) throws -> CredentialMigrationXPCResponse {
        let inputIsValid: Bool
        switch operation {
        case .migration:
            inputIsValid = acceptanceNonce.isEmpty
                && sourceURL.lastPathComponent == ".credentials.yaml"
                && !yamlGraph.isEmpty
                && yamlGraph.count <= CredentialMigrationXPCConstants.maximumGraphBytes
        case .acceptance:
            inputIsValid = validAcceptanceNonce(acceptanceNonce)
                && sourceURL.lastPathComponent
                    == CredentialMigrationXPCConstants.acceptanceSourceName
                && yamlGraph.isEmpty
        }
        guard Bundle.main.bundleURL.pathExtension == "app",
              Bundle.main.bundleIdentifier == "com.angadjairath.localharness",
              serviceBundleURL.lastPathComponent
                == CredentialMigrationXPCConstants.serviceBundleName,
              Bundle(url: serviceBundleURL)?.bundleIdentifier
                == CredentialMigrationXPCConstants.serviceName,
              inputIsValid,
              deadline.isFinite,
              deadline >= 0.05,
              deadline <= 3_600 else {
            throw CredentialMigrationXPCClientError.serviceMissing
        }
        let serviceIdentity = try CredentialMigrationXPCCodeIdentity.inspect(
            serviceBundleURL,
            nested: false
        )
        let helperIdentity = try CredentialMigrationXPCCodeIdentity.inspect(
            helperURL,
            nested: false
        )
        guard serviceIdentity.identifier == CredentialMigrationXPCConstants.serviceName,
              helperIdentity.identifier == CredentialMigrationXPCConstants.serviceName,
              serviceIdentity.designatedRequirement == helperIdentity.designatedRequirement else {
            throw CredentialMigrationXPCClientError.serviceIdentityMismatch
        }

        let capabilities = try makeCapabilities(
            sourceURL: sourceURL,
            leaseDescriptor: leaseDescriptor,
            deadline: deadline,
            operation: operation,
            acceptanceNonce: acceptanceNonce
        )
        defer {
            try? capabilities.source.close()
            try? capabilities.parent.close()
            try? capabilities.lease.close()
        }
        let requestData = try CredentialMigrationXPCSchema.encode(capabilities.request)
        guard requestData.count <= CredentialMigrationXPCConstants.maximumRequestBytes else {
            throw CredentialMigrationXPCClientError.invalidCapabilities
        }

        let gate = CredentialMigrationXPCReplyGate()
        let (clientDeadline, deadlineOverflow) = DispatchTime.now().uptimeNanoseconds
            .addingReportingOverflow(capabilities.request.deadlineNanoseconds)
        guard !deadlineOverflow else {
            throw CredentialMigrationXPCClientError.invalidCapabilities
        }
        let connectionLoss: @Sendable () -> CredentialMigrationXPCClientError = {
            DispatchTime.now().uptimeNanoseconds >= clientDeadline ? .timedOut : .interrupted
        }
        let connection = NSXPCConnection(
            serviceName: CredentialMigrationXPCConstants.serviceName
        )
        connection.setCodeSigningRequirement(serviceIdentity.exactRequirement)
        connection.remoteObjectInterface = NSXPCInterface(
            with: LocalHarnessCredentialMigrationXPCProtocol.self
        )
        connection.interruptionHandler = { gate.resolve(.failure(connectionLoss())) }
        connection.invalidationHandler = { gate.resolve(.failure(connectionLoss())) }
        connection.resume()
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in
            let error = DispatchTime.now().uptimeNanoseconds >= clientDeadline
                ? CredentialMigrationXPCClientError.timedOut
                : .unavailable
            gate.resolve(.failure(error))
        }) as? LocalHarnessCredentialMigrationXPCProtocol else {
            connection.invalidate()
            throw CredentialMigrationXPCClientError.unavailable
        }
        proxy.migrate(
            source: capabilities.source,
            sourceParent: capabilities.parent,
            lease: capabilities.lease,
            request: requestData as NSData,
            yamlGraph: yamlGraph as NSData
        ) { responseData in
            guard responseData.length > 0,
                  responseData.length <= CredentialMigrationXPCConstants.maximumResponseBytes,
                  let response = CredentialMigrationXPCSchema.decodeResponse(
                    responseData as Data
                  ),
                  response.version == CredentialMigrationXPCConstants.protocolVersion,
                  response.references >= 0,
                  response.records >= 0,
                  response.references <= CredentialMigrationXPCConstants.maximumEntryCount,
                  response.records <= CredentialMigrationXPCConstants.maximumEntryCount,
                  response.references + response.records
                    <= CredentialMigrationXPCConstants.maximumEntryCount,
                  response.status == .success
                    || (response.references == 0 && response.records == 0) else {
                gate.resolve(.failure(.invalidResponse))
                return
            }
            gate.resolve(.success(response))
        }

        let waitNanoseconds = min(
            UInt64((deadline * 1_000_000_000).rounded(.up)) + 1_000_000_000,
            CredentialMigrationXPCConstants.maximumDeadlineNanoseconds + 1_000_000_000
        )
        let waitResult = gate.semaphore.wait(
            timeout: .now() + .nanoseconds(Int(waitNanoseconds))
        )
        if waitResult == .timedOut {
            connection.invalidate()
            throw CredentialMigrationXPCClientError.timedOut
        }
        connection.invalidate()
        guard let result = gate.result() else {
            throw CredentialMigrationXPCClientError.invalidResponse
        }
        let response = try result.get()
        guard response.status == .success else {
            throw CredentialMigrationXPCClientError.service(response.status)
        }
        guard validateCommittedPaths(
            sourceURL: sourceURL,
            leaseDescriptor: leaseDescriptor,
            expectedSourceDevice: capabilities.request.source.device,
            expectedSourceInode: capabilities.request.source.inode,
            expectedParent: capabilities.request.sourceParent,
            expectedLease: capabilities.request.lease,
            expectedSourceName: capabilities.request.sourceName
        ) else {
            throw CredentialMigrationXPCClientError.sourceChanged
        }
        return response
    }

    private struct Capabilities {
        let source: FileHandle
        let parent: FileHandle
        let lease: FileHandle
        let request: CredentialMigrationXPCRequest
    }

    private static func makeCapabilities(
        sourceURL: URL,
        leaseDescriptor: CredentialMigrationInheritedDescriptor,
        deadline: TimeInterval,
        operation: CredentialMigrationXPCOperation,
        acceptanceNonce: String
    ) throws -> Capabilities {
        let parentURL = sourceURL.deletingLastPathComponent()
        let expectedSourceName = operation == .migration
            ? ".credentials.yaml"
            : CredentialMigrationXPCConstants.acceptanceSourceName
        let expectedAcceptanceParent = "/private/tmp/"
            + CredentialMigrationXPCConstants.acceptanceDirectoryPrefix
            + acceptanceNonce
        let parentMatchesOperation = operation == .migration
            ? acceptanceNonce.isEmpty
            : parentURL.path == expectedAcceptanceParent
        guard sourceURL.isFileURL,
              sourceURL.lastPathComponent == expectedSourceName,
              parentMatchesOperation,
              sourceURL.path == sourceURL.standardizedFileURL.path,
              parentURL.path == parentURL.standardizedFileURL.path,
              parentURL.path == parentURL.resolvingSymlinksInPath().standardizedFileURL.path else {
            throw CredentialMigrationXPCClientError.invalidCapabilities
        }
        let sourceDescriptor = Darwin.open(
            sourceURL.path,
            O_RDWR | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard sourceDescriptor >= 0 else {
            throw CredentialMigrationXPCClientError.invalidCapabilities
        }
        var sourceOwned = true
        defer { if sourceOwned { _ = Darwin.close(sourceDescriptor) } }
        let parentDescriptor = Darwin.open(
            parentURL.path,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard parentDescriptor >= 0 else {
            throw CredentialMigrationXPCClientError.invalidCapabilities
        }
        var parentOwned = true
        defer { if parentOwned { _ = Darwin.close(parentDescriptor) } }
        let duplicatedLease = Darwin.fcntl(
            leaseDescriptor.sourceDescriptor,
            F_DUPFD_CLOEXEC,
            3
        )
        guard duplicatedLease >= 0 else {
            throw CredentialMigrationXPCClientError.invalidCapabilities
        }
        var leaseOwned = true
        defer { if leaseOwned { _ = Darwin.close(duplicatedLease) } }

        var sourceMetadata = stat()
        var namedSource = stat()
        var namedLease = stat()
        var parentMetadata = stat()
        var leaseMetadata = stat()
        guard Darwin.fstat(sourceDescriptor, &sourceMetadata) == 0,
              Darwin.fstat(parentDescriptor, &parentMetadata) == 0,
              Darwin.fstat(duplicatedLease, &leaseMetadata) == 0,
              sourceURL.lastPathComponent.withCString({
                Darwin.fstatat(
                    parentDescriptor,
                    $0,
                    &namedSource,
                    AT_SYMLINK_NOFOLLOW
                )
              }) == 0,
              CredentialMigrationXPCConstants.leaseFileName.withCString({
                  Darwin.fstatat(
                      parentDescriptor,
                      $0,
                      &namedLease,
                      AT_SYMLINK_NOFOLLOW
                  )
              }) == 0,
              sourceMetadata.st_dev == namedSource.st_dev,
              sourceMetadata.st_ino == namedSource.st_ino,
              sourceMetadata.st_mode & S_IFMT == S_IFREG,
              sourceMetadata.st_uid == geteuid(),
              sourceMetadata.st_nlink == 1,
              sourceMetadata.st_mode & 0o777 == 0o600,
              sourceMetadata.st_size >= 0,
              sourceMetadata.st_size <= CredentialMigrationXPCConstants.maximumSourceBytes,
              operation == .migration || sourceMetadata.st_size == 0,
              parentMetadata.st_mode & S_IFMT == S_IFDIR,
              parentMetadata.st_uid == geteuid(),
              parentMetadata.st_mode & 0o022 == 0,
              operation == .migration || parentMetadata.st_mode & 0o777 == 0o700,
              leaseMetadata.st_mode & S_IFMT == S_IFREG,
              leaseMetadata.st_uid == geteuid(),
              leaseMetadata.st_nlink == 1,
              leaseMetadata.st_mode & 0o777 == 0o600,
              leaseMetadata.st_size == 0,
              leaseMetadata.st_dev == namedLease.st_dev,
              leaseMetadata.st_ino == namedLease.st_ino,
              UInt64(truncatingIfNeeded: leaseMetadata.st_dev)
                == leaseDescriptor.expectedDevice,
              UInt64(leaseMetadata.st_ino) == leaseDescriptor.expectedInode,
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(sourceDescriptor),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(parentDescriptor),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(duplicatedLease) else {
            throw CredentialMigrationXPCClientError.invalidCapabilities
        }
        let duration = UInt64((deadline * 1_000_000_000).rounded(.down))
        guard duration >= CredentialMigrationXPCConstants.minimumDeadlineNanoseconds,
              duration <= CredentialMigrationXPCConstants.maximumDeadlineNanoseconds else {
            throw CredentialMigrationXPCClientError.invalidCapabilities
        }

        let request = CredentialMigrationXPCRequest(
            operation: operation,
            acceptanceNonce: acceptanceNonce,
            sourceName: sourceURL.lastPathComponent,
            source: fileIdentity(sourceMetadata),
            sourceParent: fileIdentity(parentMetadata),
            lease: fileIdentity(leaseMetadata),
            deadlineNanoseconds: duration
        )
        let source = FileHandle(fileDescriptor: sourceDescriptor, closeOnDealloc: true)
        let parent = FileHandle(fileDescriptor: parentDescriptor, closeOnDealloc: true)
        let lease = FileHandle(fileDescriptor: duplicatedLease, closeOnDealloc: true)
        sourceOwned = false
        parentOwned = false
        leaseOwned = false
        return Capabilities(source: source, parent: parent, lease: lease, request: request)
    }

    private static func fileIdentity(_ value: stat) -> CredentialMigrationXPCFileIdentity {
        CredentialMigrationXPCFileIdentity(
            device: UInt64(truncatingIfNeeded: value.st_dev),
            inode: UInt64(value.st_ino),
            mode: UInt32(value.st_mode),
            owner: UInt32(value.st_uid),
            linkCount: UInt64(value.st_nlink),
            size: Int64(value.st_size),
            modifiedSeconds: Int64(value.st_mtimespec.tv_sec),
            modifiedNanoseconds: Int64(value.st_mtimespec.tv_nsec),
            changedSeconds: Int64(value.st_ctimespec.tv_sec),
            changedNanoseconds: Int64(value.st_ctimespec.tv_nsec)
        )
    }

    static func validateCommittedPaths(
        sourceURL: URL,
        leaseDescriptor: CredentialMigrationInheritedDescriptor,
        expectedSourceDevice: UInt64? = nil,
        expectedSourceInode: UInt64? = nil,
        expectedParent: CredentialMigrationXPCFileIdentity? = nil,
        expectedLease: CredentialMigrationXPCFileIdentity? = nil,
        expectedSourceName: String = ".credentials.yaml"
    ) -> Bool {
        let parentURL = sourceURL.deletingLastPathComponent()
        let leaseURL = parentURL.appendingPathComponent(
            CredentialMigrationXPCConstants.leaseFileName,
            isDirectory: false
        )
        guard sourceURL.isFileURL,
              sourceURL.lastPathComponent == expectedSourceName,
              sourceURL.path == sourceURL.standardizedFileURL.path,
              parentURL.path == parentURL.standardizedFileURL.path,
              parentURL.path == parentURL.resolvingSymlinksInPath().standardizedFileURL.path else {
            return false
        }
        let source = Darwin.open(sourceURL.path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        guard source >= 0 else { return false }
        defer { _ = Darwin.close(source) }
        let parent = Darwin.open(parentURL.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { return false }
        defer { _ = Darwin.close(parent) }
        let lease = Darwin.fcntl(leaseDescriptor.sourceDescriptor, F_DUPFD_CLOEXEC, 3)
        guard lease >= 0 else { return false }
        defer { _ = Darwin.close(lease) }

        var sourceMetadata = stat()
        var namedSource = stat()
        var parentMetadata = stat()
        var namedParent = stat()
        var leaseMetadata = stat()
        var namedLease = stat()
        guard Darwin.fstat(source, &sourceMetadata) == 0,
              Darwin.fstat(parent, &parentMetadata) == 0,
              Darwin.lstat(parentURL.path, &namedParent) == 0,
              Darwin.fstat(lease, &leaseMetadata) == 0,
              sourceURL.lastPathComponent.withCString({
                  Darwin.fstatat(parent, $0, &namedSource, AT_SYMLINK_NOFOLLOW)
              }) == 0,
              leaseURL.lastPathComponent.withCString({
                  Darwin.fstatat(parent, $0, &namedLease, AT_SYMLINK_NOFOLLOW)
              }) == 0,
              sourceMetadata.st_dev == namedSource.st_dev,
              sourceMetadata.st_ino == namedSource.st_ino,
              sourceMetadata.st_mode & S_IFMT == S_IFREG,
              sourceMetadata.st_uid == geteuid(),
              sourceMetadata.st_nlink == 1,
              sourceMetadata.st_mode & 0o777 == 0o600,
              sourceMetadata.st_size == 0,
              expectedSourceDevice.map({
                  UInt64(truncatingIfNeeded: sourceMetadata.st_dev) == $0
              }) ?? true,
              expectedSourceInode.map({ UInt64(sourceMetadata.st_ino) == $0 }) ?? true,
              parentMetadata.st_dev == namedParent.st_dev,
              parentMetadata.st_ino == namedParent.st_ino,
              parentMetadata.st_mode & S_IFMT == S_IFDIR,
              parentMetadata.st_uid == geteuid(),
              parentMetadata.st_mode & 0o022 == 0,
              expectedParent.map({
                  UInt64(truncatingIfNeeded: parentMetadata.st_dev) == $0.device
                      && UInt64(parentMetadata.st_ino) == $0.inode
              }) ?? true,
              leaseMetadata.st_dev == namedLease.st_dev,
              leaseMetadata.st_ino == namedLease.st_ino,
              leaseMetadata.st_mode & S_IFMT == S_IFREG,
              leaseMetadata.st_uid == geteuid(),
              leaseMetadata.st_nlink == 1,
              leaseMetadata.st_mode & 0o777 == 0o600,
              leaseMetadata.st_size == 0,
              UInt64(truncatingIfNeeded: leaseMetadata.st_dev)
                == leaseDescriptor.expectedDevice,
              UInt64(leaseMetadata.st_ino) == leaseDescriptor.expectedInode,
              expectedLease.map({ fileIdentity(leaseMetadata) == $0 }) ?? true,
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(source),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(parent),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(lease) else {
            return false
        }
        return true
    }

    private static func validAcceptanceNonce(_ value: String) -> Bool {
        guard value.utf8.count == 36,
              let nonce = UUID(uuidString: value) else { return false }
        return nonce.uuidString.lowercased() == value
    }
}
