import Foundation

/// Bounds the provider catalog before it reaches any native menu, table, or
/// accessibility surface. The authenticated Harness process remains an
/// external parser boundary: a malformed plugin/provider response must not be
/// able to create unbounded AppKit objects or inject invisible display control
/// characters.
enum HarnessCatalogWirePolicy {
    static let maximumProviders = 64
    static let maximumProviderGroups = 64
    static let maximumModelsPerGroup = 256
    static let maximumModelsTotal = 1_024
    static let maximumFailures = 64
    static let maximumReasoningEfforts = 16
    static let maximumSettingsPathComponents = 16
    static let maximumIdentifierScalars = 256
    static let maximumIdentifierUTF8Bytes = 1_024
    static let maximumSettingsNamespaceScalars = 128
    // Custom-provider validation already permits names up to 256 UTF-8 bytes.
    // A matching scalar ceiling keeps the wire boundary bounded without
    // changing a legitimate configured name before exact-provider verification.
    static let maximumNameScalars = 256
    static let maximumDetailScalars = 1_000

    static func displayName(
        _ rawValue: String,
        fallback: String,
        genericFallback: String
    ) -> String {
        normalized(rawValue, maximumScalars: maximumNameScalars, preserveOrdinarySpaces: true)
            ?? normalized(fallback, maximumScalars: maximumNameScalars, preserveOrdinarySpaces: true)
            ?? genericFallback
    }

    static func detail(_ rawValue: String?) -> String? {
        rawValue.flatMap { normalized($0, maximumScalars: maximumDetailScalars) }
    }

    static func failureMessage(_ rawValue: String) -> String {
        // Adapter/provider failure bodies may echo credentials, request content,
        // or private endpoints. The catalog is a UI routing surface, not a
        // diagnostics channel, so never project that body into native controls.
        _ = rawValue
        return "Provider unavailable"
    }

    /// Validates but never rewrites opaque route identifiers. DSH providers
    /// legitimately use punctuation such as `/`, `:`, `@`, and `+`; changing
    /// those values could silently select a different model. Unsafe/invisible
    /// controls and unbounded values therefore fail the whole authenticated
    /// response instead of being projected into dictionaries or UI fallbacks.
    static func opaqueIdentifier(
        _ value: String,
        codingPath: [any CodingKey],
        label: String,
        maximumScalars: Int = maximumIdentifierScalars,
        maximumUTF8Bytes: Int = maximumIdentifierUTF8Bytes
    ) throws -> String {
        guard !value.isEmpty,
              value.unicodeScalars.count <= maximumScalars,
              value.utf8.count <= maximumUTF8Bytes,
              value.unicodeScalars.contains(where: { !CharacterSet.whitespacesAndNewlines.contains($0) }),
              !value.unicodeScalars.contains(where: isUnsafeScalar) else {
            throw invalidWireStringError(codingPath: codingPath, label: label)
        }
        return value
    }

    static func optionalOpaqueIdentifier(
        _ value: String?,
        codingPath: [any CodingKey],
        label: String
    ) throws -> String? {
        guard let value else { return nil }
        return try opaqueIdentifier(value, codingPath: codingPath, label: label)
    }

    static func settingsNamespace(
        _ value: String,
        codingPath: [any CodingKey]
    ) throws -> String {
        try opaqueIdentifier(
            value,
            codingPath: codingPath,
            label: "settings namespace",
            maximumScalars: maximumSettingsNamespaceScalars,
            maximumUTF8Bytes: maximumSettingsNamespaceScalars * 4
        )
    }

    static func decodeSettingsPath(
        from container: inout UnkeyedDecodingContainer
    ) throws -> [String] {
        if let count = container.count, count > maximumSettingsPathComponents {
            throw countLimitError(
                codingPath: container.codingPath,
                label: "settings-path components",
                maximumCount: maximumSettingsPathComponents
            )
        }
        var components: [String] = []
        components.reserveCapacity(min(container.count ?? 0, maximumSettingsPathComponents))
        while !container.isAtEnd {
            guard components.count < maximumSettingsPathComponents else {
                throw countLimitError(
                    codingPath: container.codingPath,
                    label: "settings-path components",
                    maximumCount: maximumSettingsPathComponents
                )
            }
            let path = container.codingPath
            let component = try container.decode(String.self)
            components.append(try opaqueIdentifier(
                component,
                codingPath: path,
                label: "settings-path component"
            ))
        }
        return components
    }

    static func decodeBoundedArray<Element: Decodable>(
        _ type: Element.Type,
        from container: inout UnkeyedDecodingContainer,
        maximumCount: Int,
        label: String
    ) throws -> [Element] {
        if let declaredCount = container.count, declaredCount > maximumCount {
            throw decodingLimitError(
                codingPath: container.codingPath,
                label: label,
                maximumCount: maximumCount
            )
        }
        var values: [Element] = []
        values.reserveCapacity(min(container.count ?? 0, maximumCount))
        while !container.isAtEnd {
            guard values.count < maximumCount else {
                throw decodingLimitError(
                    codingPath: container.codingPath,
                    label: label,
                    maximumCount: maximumCount
                )
            }
            values.append(try container.decode(Element.self))
        }
        return values
    }

    static func decodeProviderGroups(
        from container: inout UnkeyedDecodingContainer
    ) throws -> [HarnessModelProviderGroup] {
        if let count = container.count, count > maximumProviderGroups {
            throw countLimitError(
                codingPath: container.codingPath,
                label: "model-provider groups",
                maximumCount: maximumProviderGroups
            )
        }
        var groups: [HarnessModelProviderGroup] = []
        groups.reserveCapacity(min(container.count ?? 0, maximumProviderGroups))
        var totalModels = 0
        while !container.isAtEnd {
            guard groups.count < maximumProviderGroups else {
                throw countLimitError(
                    codingPath: container.codingPath,
                    label: "model-provider groups",
                    maximumCount: maximumProviderGroups
                )
            }
            let group = try container.decode(HarnessModelProviderGroup.self)
            totalModels += group.models.count
            guard totalModels <= maximumModelsTotal else {
                throw countLimitError(
                    codingPath: container.codingPath,
                    label: "total model catalog",
                    maximumCount: maximumModelsTotal
                )
            }
            groups.append(group)
        }
        return groups
    }

    static func countLimitError(
        codingPath: [any CodingKey],
        label: String,
        maximumCount: Int
    ) -> DecodingError {
        decodingLimitError(
            codingPath: codingPath,
            label: label,
            maximumCount: maximumCount
        )
    }

    private static func normalized(
        _ value: String,
        maximumScalars: Int,
        preserveOrdinarySpaces: Bool = false
    ) -> String? {
        var result = String.UnicodeScalarView()
        result.reserveCapacity(min(value.unicodeScalars.count, maximumScalars))
        var pendingSpace = false

        for scalar in value.unicodeScalars {
            // Preserve ordinary spaces exactly: provider verification compares
            // the decoded catalog name with the user's validated configuration.
            // Other whitespace and unsafe format controls collapse to one
            // visible separator so they cannot forge menu/accessibility text.
            if scalar.value == 0x20, preserveOrdinarySpaces {
                if pendingSpace, result.count < maximumScalars {
                    result.append(" ")
                }
                pendingSpace = false
                guard result.count < maximumScalars else { break }
                result.append(scalar)
                continue
            }
            if CharacterSet.whitespacesAndNewlines.contains(scalar)
                || CharacterSet.controlCharacters.contains(scalar)
                || CharacterSet.illegalCharacters.contains(scalar)
                || isInvisibleFormatControl(scalar.value) {
                pendingSpace = !result.isEmpty
                continue
            }
            if pendingSpace, result.count < maximumScalars {
                result.append(" ")
            }
            pendingSpace = false
            guard result.count < maximumScalars else { break }
            result.append(scalar)
        }

        let normalized = String(result).trimmingCharacters(in: .whitespaces)
        return normalized.isEmpty ? nil : normalized
    }

    private static func isInvisibleFormatControl(_ value: UInt32) -> Bool {
        value == 0x061C
            || value == 0x200B
            || (0x200E...0x200F).contains(value)
            || (0x202A...0x202E).contains(value)
            || (0x2066...0x2069).contains(value)
            || value == 0x2060
            || value == 0xFEFF
    }

    private static func isUnsafeScalar(_ scalar: UnicodeScalar) -> Bool {
        CharacterSet.controlCharacters.contains(scalar)
            || CharacterSet.illegalCharacters.contains(scalar)
            || isInvisibleFormatControl(scalar.value)
    }

    private static func invalidWireStringError(
        codingPath: [any CodingKey],
        label: String
    ) -> DecodingError {
        .dataCorrupted(.init(
            codingPath: codingPath,
            debugDescription: "Harness returned an invalid or oversized \(label)."
        ))
    }

    private static func decodingLimitError(
        codingPath: [any CodingKey],
        label: String,
        maximumCount: Int
    ) -> DecodingError {
        .dataCorrupted(.init(
            codingPath: codingPath,
            debugDescription: "Harness \(label) exceeds the supported maximum of \(maximumCount)."
        ))
    }
}
