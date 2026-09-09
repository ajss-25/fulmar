import Foundation

/// A stable semantic version returned by Ollama's official local
/// `GET /api/version` endpoint. Prerelease identifiers are deliberately not
/// admitted for the qualified agent route; build metadata is retained in
/// evidence but does not affect precedence.
struct OllamaStableVersion: Equatable, Sendable, CustomStringConvertible {
    let major: Int
    let minor: Int
    let patch: Int
    let buildMetadata: String?
    let rawValue: String

    var description: String { rawValue }

    func isAtLeast(_ other: OllamaStableVersion) -> Bool {
        if major != other.major { return major > other.major }
        if minor != other.minor { return minor > other.minor }
        return patch >= other.patch
    }
}

enum OllamaVersionCompatibilityError: Error, Equatable, LocalizedError, Sendable {
    case unavailable
    case malformedResponse
    case unsupported(actual: String, minimum: String)
    case newerUnqualified(actual: String, qualifiedSeries: String)

    var errorDescription: String? {
        switch self {
        case .unavailable:
            return "Fulmar could not verify Ollama's local version endpoint. Update or reinstall the official Ollama app, restart it, then restart Fulmar."
        case .malformedResponse:
            return "Ollama returned an invalid version response. Update or reinstall the official Ollama app, then restart Fulmar."
        case .unsupported(let actual, let minimum):
            return "Ollama \(actual) is too old for Fulmar's local agent route. Update the official Ollama app to version \(minimum) or later, then restart Fulmar."
        case .newerUnqualified(let actual, let qualifiedSeries):
            return "Ollama \(actual) is newer than Fulmar's release-qualified \(qualifiedSeries) range. Install a Fulmar update that qualifies this Ollama release, or restore Ollama \(qualifiedSeries) (version \(OllamaVersionCompatibilityPolicy.minimum.rawValue) or later), then restart Fulmar."
        }
    }
}

enum OllamaVersionCompatibilityPolicy {
    static let maximumResponseBytes = 256
    static let qualifiedSeries = "0.33.x"
    static let minimum = OllamaStableVersion(
        major: 0,
        minor: 33,
        patch: 2,
        buildMetadata: nil,
        rawValue: "0.33.2"
    )
    static let tested = OllamaStableVersion(
        major: 0,
        minor: 33,
        patch: 2,
        buildMetadata: nil,
        rawValue: "0.33.2"
    )

    /// Accept only one small JSON object containing one literal, unescaped
    /// `version` string. This rejects duplicate/extra fields, JSON coercion,
    /// prereleases, leading-zero components, and unbounded integers before a
    /// version can affect admission.
    static func parseResponse(_ data: Data) throws -> OllamaStableVersion {
        guard !data.isEmpty,
              data.count <= maximumResponseBytes,
              let text = String(data: data, encoding: .utf8),
              text.utf8.count == data.count else {
            throw OllamaVersionCompatibilityError.malformedResponse
        }
        let envelope = try NSRegularExpression(
            pattern: #"^[ \t\r\n]*\{[ \t\r\n]*\"version\"[ \t\r\n]*:[ \t\r\n]*\"([^\"\\]{1,64})\"[ \t\r\n]*\}[ \t\r\n]*$"#
        )
        let wholeRange = NSRange(text.startIndex..<text.endIndex, in: text)
        guard let match = envelope.firstMatch(in: text, range: wholeRange),
              match.range == wholeRange,
              let valueRange = Range(match.range(at: 1), in: text) else {
            throw OllamaVersionCompatibilityError.malformedResponse
        }
        let version = try parseStableVersion(String(text[valueRange]))
        guard version.isAtLeast(minimum) else {
            throw OllamaVersionCompatibilityError.unsupported(
                actual: version.rawValue,
                minimum: minimum.rawValue
            )
        }
        guard version.major == minimum.major,
              version.minor == minimum.minor else {
            throw OllamaVersionCompatibilityError.newerUnqualified(
                actual: version.rawValue,
                qualifiedSeries: qualifiedSeries
            )
        }
        return version
    }

    static func parseStableVersion(_ rawValue: String) throws -> OllamaStableVersion {
        guard !rawValue.isEmpty, rawValue.utf8.count <= 64 else {
            throw OllamaVersionCompatibilityError.malformedResponse
        }
        let expression = try NSRegularExpression(
            pattern: #"^(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"#
        )
        let wholeRange = NSRange(rawValue.startIndex..<rawValue.endIndex, in: rawValue)
        guard let match = expression.firstMatch(in: rawValue, range: wholeRange),
              match.range == wholeRange else {
            throw OllamaVersionCompatibilityError.malformedResponse
        }

        func component(at index: Int) -> Int? {
            guard let range = Range(match.range(at: index), in: rawValue),
                  let value = Int(rawValue[range]),
                  value <= Int(Int32.max) else { return nil }
            return value
        }
        guard let major = component(at: 1),
              let minor = component(at: 2),
              let patch = component(at: 3) else {
            throw OllamaVersionCompatibilityError.malformedResponse
        }
        let metadata = Range(match.range(at: 4), in: rawValue).map { String(rawValue[$0]) }
        return OllamaStableVersion(
            major: major,
            minor: minor,
            patch: patch,
            buildMetadata: metadata,
            rawValue: rawValue
        )
    }
}
