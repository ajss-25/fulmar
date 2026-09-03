import Darwin
import Foundation

struct ProviderNetworkOrigin: Codable, Hashable, Sendable {
    let scheme: String
    let host: String
    let port: Int

    init?(url: URL) {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.user == nil, components.password == nil,
              let rawScheme = components.scheme?.lowercased(),
              let rawHost = components.host?.lowercased(), !rawHost.isEmpty,
              components.fragment == nil else { return nil }
        let normalizedHost = Self.normalizedHost(rawHost)
        guard Self.isValidHost(normalizedHost),
              rawScheme == "https" || (rawScheme == "http" && Self.isLocalAddress(normalizedHost))
        else { return nil }
        let candidatePort = components.port ?? (rawScheme == "https" ? 443 : 80)
        guard (1...65_535).contains(candidatePort), !Self.isForbiddenAddress(normalizedHost) else { return nil }
        scheme = rawScheme
        host = normalizedHost
        port = candidatePort
    }

    static func isValidHost(_ host: String) -> Bool {
        let value = normalizedHost(host)
        guard !value.isEmpty, value.utf8.count <= 253,
              value.unicodeScalars.allSatisfy({ $0.isASCII }) else { return false }
        if value == "localhost" || ipv6Bytes(value) != nil { return true }
        // Reject legacy numeric IPv4 spellings (for example 127.1, octal, or a
        // single 32-bit integer) instead of allowing the system resolver to
        // reinterpret them after the boundary decision.
        if value.allSatisfy({ $0.isNumber || $0 == "." }) {
            guard let bytes = ipv4Bytes(value) else { return false }
            return bytes.map(String.init).joined(separator: ".") == value
        }
        if value.hasPrefix("0x") { return false }
        let labels = value.split(separator: ".", omittingEmptySubsequences: false)
        guard !labels.isEmpty else { return false }
        return labels.allSatisfy { label in
            guard !label.isEmpty, label.utf8.count <= 63,
                  let first = label.utf8.first, let last = label.utf8.last,
                  Self.isASCIILetterOrDigit(first), Self.isASCIILetterOrDigit(last) else { return false }
            return label.utf8.allSatisfy { byte in
                Self.isASCIILetterOrDigit(byte) || byte == 45
            }
        }
    }

    static func isLocalAddress(_ host: String) -> Bool {
        let value = normalizedHost(host)
        if value == "localhost" { return true }
        if let bytes = ipv4Bytes(value) {
            return bytes[0] == 127
                || bytes[0] == 10
                || (bytes[0] == 192 && bytes[1] == 168)
                || (bytes[0] == 172 && (16...31).contains(Int(bytes[1])))
        }
        guard let bytes = ipv6Bytes(value) else { return false }
        if bytes.dropLast().allSatisfy({ $0 == 0 }), bytes.last == 1 { return true }
        if (bytes[0] & 0xfe) == 0xfc { return true }
        if isIPv4Mapped(bytes) {
            return isLocalAddress(bytes.suffix(4).map(String.init).joined(separator: "."))
        }
        return false
    }

    /// Returns true only for a DNS-free literal loopback, RFC1918, or IPv6 ULA
    /// origin. Hostnames (including `localhost`) and IPv4-mapped IPv6 spellings
    /// are deliberately excluded from the explicit no-auth trust boundary.
    static func isLiteralPrivateOrLoopback(_ url: URL) -> Bool {
        guard let origin = ProviderNetworkOrigin(url: url),
              isLocalAddress(origin.host),
              origin.host != "localhost" else { return false }
        if origin.host.contains(":") {
            guard let bytes = ipv6Bytes(origin.host), !isIPv4Mapped(bytes) else { return false }
            if bytes.dropLast().allSatisfy({ $0 == 0 }), bytes.last == 1 { return true }
            return (bytes[0] & 0xfe) == 0xfc
        }
        return ipv4Bytes(origin.host) != nil
    }

    static func isForbiddenAddress(_ host: String) -> Bool {
        let value = normalizedHost(host)
        if value == "metadata.google.internal" { return true }
        if let bytes = ipv4Bytes(value) {
            return isRuntimeForbiddenIPv4(bytes)
        }
        if let bytes = ipv6Bytes(value) {
            if isIPv4Mapped(bytes) {
                return isForbiddenAddress(bytes.suffix(4).map(String.init).joined(separator: "."))
            }
            // The runtime admits only loopback/ULA at the local boundary and
            // ordinary global-unicast IPv6 at the cloud boundary. Mirror that
            // union here so the native editor cannot accept an origin that the
            // fresh security preload will reject after consent.
            if isLocalAddress(value) { return false }
            return !isRuntimePublicIPv6(bytes)
        }
        return false
    }

    /// Keep this literal policy byte-for-byte equivalent in meaning to
    /// RuntimeSecurityPreload.mjs `isPublicIPv4`, while preserving the RFC1918
    /// and loopback ranges admitted by `isLocalAddress`.
    private static func isRuntimeForbiddenIPv4(_ bytes: [UInt8]) -> Bool {
        guard bytes.count == 4 else { return true }
        let a = bytes[0]
        let b = bytes[1]
        let c = bytes[2]
        return a == 0
            || (a == 100 && (64...127).contains(Int(b)))
            || (a == 169 && b == 254)
            || (a == 192 && (b == 0 || (b == 88 && c == 99)))
            || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
            || (a == 203 && b == 0 && c == 113)
            || a >= 224
    }

    /// Mirrors the runtime's cloud IPv6 allowlist. Local loopback/ULA values
    /// are handled before this helper; transition, documentation, benchmark,
    /// ORCHID, and deprecated global prefixes remain rejected.
    private static func isRuntimePublicIPv6(_ bytes: [UInt8]) -> Bool {
        guard bytes.count == 16, (bytes[0] & 0xe0) == 0x20 else { return false }
        let first32 = UInt32(bytes[0]) << 24
            | UInt32(bytes[1]) << 16
            | UInt32(bytes[2]) << 8
            | UInt32(bytes[3])
        if first32 == 0x2001_0db8 || first32 == 0x2001_0000
            || (bytes[0] == 0x20 && bytes[1] == 0x02) {
            return false
        }
        if bytes[0] == 0x20, bytes[1] == 0x01 {
            let secondHextet = UInt16(bytes[2]) << 8 | UInt16(bytes[3])
            let thirdHextet = UInt16(bytes[4]) << 8 | UInt16(bytes[5])
            if (secondHextet == 0x0002 && thirdHextet == 0x0000)
                || (0x0010...0x002f).contains(secondHextet) {
                return false
            }
        }
        if (bytes[0] == 0x3f && bytes[1] == 0xfe)
            || (bytes[0] == 0x3f && bytes[1] == 0xff && (bytes[2] & 0xf0) == 0x00) {
            return false
        }
        return true
    }

    private static func normalizedHost(_ host: String) -> String {
        var value = host.lowercased()
        if value.hasPrefix("[") || value.hasSuffix("]") {
            guard value.hasPrefix("["), value.hasSuffix("]"), value.count > 2 else { return "" }
            value.removeFirst()
            value.removeLast()
            guard !value.contains("["), !value.contains("]") else { return "" }
        }
        guard !value.hasPrefix(".") else { return "" }
        if value.hasSuffix(".") {
            value.removeLast()
            guard !value.hasSuffix(".") else { return "" }
        }
        return value
    }

    private static func isASCIILetterOrDigit(_ byte: UInt8) -> Bool {
        (48...57).contains(byte) || (97...122).contains(byte) || (65...90).contains(byte)
    }

    private static func ipv4Bytes(_ value: String) -> [UInt8]? {
        var address = in_addr()
        guard value.withCString({ inet_pton(AF_INET, $0, &address) }) == 1 else { return nil }
        return withUnsafeBytes(of: &address) { Array($0) }
    }

    private static func ipv6Bytes(_ value: String) -> [UInt8]? {
        var address = in6_addr()
        guard value.withCString({ inet_pton(AF_INET6, $0, &address) }) == 1 else { return nil }
        return withUnsafeBytes(of: &address) { Array($0) }
    }

    private static func isIPv4Mapped(_ bytes: [UInt8]) -> Bool {
        bytes.count == 16
            && bytes.prefix(10).allSatisfy { $0 == 0 }
            && bytes[10] == 0xff
            && bytes[11] == 0xff
    }
}

/// The exact wire capability passed to the JavaScript security preload.
///
/// `ProviderNetworkOrigin` deliberately remains an origin-only value because
/// it is also used by native endpoint validation. The runtime, however, must
/// never infer a trust boundary from an address. Carrying the reviewed
/// boundary beside every serialized origin makes a missing or downgraded
/// boundary fail closed in the preload.
struct ProviderRuntimeNetworkOrigin: Codable, Hashable, Sendable {
    let scheme: String
    let host: String
    let port: Int
    let boundary: DataBoundary

    init(origin: ProviderNetworkOrigin, boundary: DataBoundary) {
        scheme = origin.scheme
        host = origin.host
        port = origin.port
        self.boundary = boundary
    }
}

enum ProviderEgressPolicy {
    /// Produces the one exact external origin available to the provider
    /// transport. Built-in providers are not implicitly trusted: the selected
    /// route must match the active, endpoint-bound consent record.
    static func allowedOrigins(
        selection: ModelSelection,
        consent: ProviderConsentState
    ) -> Set<ProviderNetworkOrigin> {
        guard consent.activeProvider == selection.route.provider,
              let grant = consent.activeGrant(for: selection.route.provider),
              grant.boundary.requiresExplicitConsent,
              let endpoint = grant.origin else { return [] }

        var components = URLComponents()
        components.scheme = endpoint.scheme
        components.host = endpoint.host
        components.port = endpoint.port
        guard let url = components.url,
              let origin = ProviderNetworkOrigin(url: url) else { return [] }

        switch grant.boundary {
        case .onDevice:
            return []
        case .localNetwork:
            guard ProviderNetworkOrigin.isLocalAddress(origin.host) else { return [] }
        case .cloud:
            guard origin.scheme == "https", !ProviderNetworkOrigin.isLocalAddress(origin.host) else { return [] }
        }
        return [origin]
    }

    static func serializedAllowlist(
        selection: ModelSelection,
        consent: ProviderConsentState
    ) -> String {
        guard let grant = consent.activeGrant(for: selection.route.provider) else { return "[]" }
        return serializedAllowlist(
            origins: allowedOrigins(selection: selection, consent: consent),
            boundary: grant.boundary
        )
    }

    /// Serializes an already-authorized origin set. The controller uses this
    /// only to add the freshly created, PID-owned Ollama origin to Strict Local;
    /// external origins must still come from `allowedOrigins` above.
    static func serializedAllowlist(
        origins: Set<ProviderNetworkOrigin>,
        boundary: DataBoundary
    ) -> String {
        let values = origins
            .sorted { ($0.scheme, $0.host, $0.port) < ($1.scheme, $1.host, $1.port) }
            .map { ProviderRuntimeNetworkOrigin(origin: $0, boundary: boundary) }
        guard let data = try? JSONEncoder().encode(values) else { return "[]" }
        return String(decoding: data, as: UTF8.self)
    }
}
