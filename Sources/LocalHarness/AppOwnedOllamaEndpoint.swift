import Darwin
import Foundation

/// The only Ollama endpoint the product may classify as on-device. The port is
/// selected for each owned Ollama process; a conventional system-wide port is
/// never discovered or adopted.
struct AppOwnedOllamaEndpoint: Equatable, Sendable {
    static let host = "127.0.0.1"

    let port: Int

    init?(port: Int) {
        guard (1...65_535).contains(port) else { return nil }
        self.port = port
    }

    var baseURL: URL { URL(string: "http://\(Self.host):\(port)/")! }
    var versionURL: URL { baseURL.appendingPathComponent("api/version") }
    var tagsURL: URL { baseURL.appendingPathComponent("api/tags") }
    var providerBaseURL: URL { baseURL.appendingPathComponent("v1") }
    var networkOrigin: ProviderNetworkOrigin { ProviderNetworkOrigin(url: baseURL)! }

    static func validatingProviderBaseURL(_ url: URL) -> AppOwnedOllamaEndpoint? {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.scheme?.lowercased() == "http",
              components.host?.lowercased() == host,
              components.user == nil,
              components.password == nil,
              components.query == nil,
              components.fragment == nil,
              let port = components.port,
              components.path == "/v1" || components.path == "/v1/" else { return nil }
        return AppOwnedOllamaEndpoint(port: port)
    }
}

enum OllamaModelNamePolicy {
    /// Ollama model identifiers are data, never command arguments, but keeping
    /// them to the documented registry-like alphabet avoids ambiguous DSH
    /// routes, log control characters, and invisible look-alikes.
    static func isSafe(_ value: String) -> Bool {
        guard !value.isEmpty,
              value.utf8.count <= 512,
              value.first?.isASCII == true,
              (value.first?.isLetter == true || value.first?.isNumber == true),
              value.unicodeScalars.allSatisfy({ scalar in
                  scalar.isASCII && (
                      CharacterSet.alphanumerics.contains(scalar)
                        || scalar == "." || scalar == "_" || scalar == "-"
                        || scalar == "/" || scalar == ":"
                  )
              }),
              !value.contains("//") else { return false }
        return value.split(separator: "/", omittingEmptySubsequences: false).allSatisfy {
            !$0.isEmpty && $0 != "." && $0 != ".."
        }
    }
}

enum AppOwnedOllamaEndpointError: Error, LocalizedError {
    case portReservationFailed(Int32)

    var errorDescription: String? {
        switch self {
        case .portReservationFailed(let code):
            return "A private Ollama port could not be reserved (system error \(code))."
        }
    }
}

/// Holds an exclusive loopback listener until immediately before Ollama is
/// spawned. The later PID/socket verification closes the unavoidable handoff
/// interval without trusting whichever process happens to answer HTTP.
final class LoopbackPortReservation {
    let endpoint: AppOwnedOllamaEndpoint
    private var descriptor: Int32

    private init(endpoint: AppOwnedOllamaEndpoint, descriptor: Int32) {
        self.endpoint = endpoint
        self.descriptor = descriptor
    }

    deinit { release() }

    static func reserve() throws -> LoopbackPortReservation {
        let descriptor = socket(AF_INET, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw AppOwnedOllamaEndpointError.portReservationFailed(errno) }

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = 0
        let parsed = AppOwnedOllamaEndpoint.host.withCString {
            inet_pton(AF_INET, $0, &address.sin_addr)
        }
        guard parsed == 1 else {
            Darwin.close(descriptor)
            throw AppOwnedOllamaEndpointError.portReservationFailed(EINVAL)
        }

        let bindResult = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0, Darwin.listen(descriptor, 1) == 0 else {
            let code = errno
            Darwin.close(descriptor)
            throw AppOwnedOllamaEndpointError.portReservationFailed(code)
        }

        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let nameResult = withUnsafeMutablePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(descriptor, $0, &length)
            }
        }
        let port = Int(UInt16(bigEndian: address.sin_port))
        guard nameResult == 0, let endpoint = AppOwnedOllamaEndpoint(port: port) else {
            let code = errno == 0 ? EINVAL : errno
            Darwin.close(descriptor)
            throw AppOwnedOllamaEndpointError.portReservationFailed(code)
        }
        return LoopbackPortReservation(endpoint: endpoint, descriptor: descriptor)
    }

    /// Releases the reservation exactly once. Call immediately before
    /// `Process.run()`; readiness remains denied until the new PID is proven to
    /// own this exact listener.
    func releaseForLaunch() {
        release()
    }

    private func release() {
        guard descriptor >= 0 else { return }
        Darwin.close(descriptor)
        descriptor = -1
    }
}

/// Uses macOS process metadata to prove the exact child PID owns the expected
/// listening socket. A valid-looking reply from an unrelated local process is
/// insufficient.
enum OwnedLoopbackListenerVerifier {
    static func descriptorBufferPlan(
        requiredBytes: Int32,
        stride: Int
    ) -> (capacity: Int, byteCount: Int32)? {
        guard requiredBytes > 0, stride > 0 else { return nil }
        let required = Int(requiredBytes)
        let wholeRecords = required / stride
        let roundedRecords = wholeRecords + (required.isMultiple(of: stride) ? 0 : 1)
        let (capacity, capacityOverflow) = roundedRecords.addingReportingOverflow(8)
        guard !capacityOverflow, capacity > 0 else { return nil }
        let (byteCount, byteCountOverflow) = capacity.multipliedReportingOverflow(by: stride)
        guard !byteCountOverflow, let narrowedByteCount = Int32(exactly: byteCount) else {
            return nil
        }
        return (capacity, narrowedByteCount)
    }

    static func process(_ processIdentifier: Int32, owns endpoint: AppOwnedOllamaEndpoint) -> Bool {
        guard processIdentifier > 0 else { return false }
        let requiredBytes = proc_pidinfo(processIdentifier, PROC_PIDLISTFDS, 0, nil, 0)
        guard requiredBytes > 0 else { return false }

        let stride = MemoryLayout<proc_fdinfo>.stride
        guard let plan = descriptorBufferPlan(requiredBytes: requiredBytes, stride: stride) else {
            return false
        }
        var descriptors = [proc_fdinfo](repeating: proc_fdinfo(), count: plan.capacity)
        let returnedBytes = proc_pidinfo(
            processIdentifier,
            PROC_PIDLISTFDS,
            0,
            &descriptors,
            plan.byteCount
        )
        guard returnedBytes > 0,
              returnedBytes <= plan.byteCount,
              Int(returnedBytes).isMultiple(of: stride) else { return false }

        for descriptor in descriptors.prefix(Int(returnedBytes) / stride)
        where descriptor.proc_fdtype == PROX_FDTYPE_SOCKET {
            var information = socket_fdinfo()
            let size = proc_pidfdinfo(
                processIdentifier,
                descriptor.proc_fd,
                PROC_PIDFDSOCKETINFO,
                &information,
                Int32(MemoryLayout<socket_fdinfo>.stride)
            )
            guard size == MemoryLayout<socket_fdinfo>.stride,
                  information.psi.soi_kind == SOCKINFO_TCP else { continue }

            let tcp = information.psi.soi_proto.pri_tcp
            let localPort = Int(UInt16(bigEndian: UInt16(truncatingIfNeeded: tcp.tcpsi_ini.insi_lport)))
            guard tcp.tcpsi_state == TSI_S_LISTEN, localPort == endpoint.port else { continue }

            // OLLAMA_HOST is a literal IPv4 loopback address. Verify the
            // kernel-reported listener address as well as its port and PID.
            var rawAddress = tcp.tcpsi_ini.insi_laddr.ina_46.i46a_addr4
            let bytes = withUnsafeBytes(of: &rawAddress) { Array($0) }
            if bytes == [127, 0, 0, 1] { return true }
        }
        return false
    }
}
