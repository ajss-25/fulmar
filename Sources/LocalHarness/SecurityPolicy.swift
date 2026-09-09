import Foundation

struct NavigationSecurityPolicy {
    let port: Int

    func permitsEmbeddedNavigation(to url: URL) -> Bool {
        if url.absoluteString == "about:blank" { return true }
        if url.scheme == "blob" {
            return url.absoluteString.hasPrefix("blob:http://127.0.0.1:\(port)/") || url.absoluteString.hasPrefix("blob:http://localhost:\(port)/")
        }
        guard url.scheme == "http", url.port == port else { return false }
        return url.host == "127.0.0.1" || url.host == "localhost"
    }

    func normalizedExternalHTTPSURL(_ url: URL) -> URL? {
        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.scheme?.caseInsensitiveCompare("https") == .orderedSame,
              let host = components.host,
              !host.isEmpty,
              components.user == nil,
              components.password == nil else {
            return nil
        }
        components.scheme = "https"
        components.host = host.lowercased()
        if components.port == 443 { components.port = nil }
        return components.url?.standardized
    }

    func isExternalWebURL(_ url: URL) -> Bool {
        normalizedExternalHTTPSURL(url) != nil
    }
}

enum DownloadPath {
    private static let maximumFilenameBytes = 200

    static func safeFilename(_ suggestedFilename: String, fallback: String = "Download") -> String {
        let normalized = suggestedFilename.precomposedStringWithCompatibilityMapping
        var scalars = String.UnicodeScalarView()
        var previousWasWhitespace = false

        for scalar in normalized.unicodeScalars {
            let value = scalar.value
            let isDirectionControl = (0x202A...0x202E).contains(value)
                || (0x2066...0x2069).contains(value)
                || value == 0x200E || value == 0x200F || value == 0x061C
            let isInvisibleFormat = scalar.properties.generalCategory == .format
            if CharacterSet.controlCharacters.contains(scalar) || isDirectionControl || isInvisibleFormat {
                continue
            }

            if CharacterSet.whitespacesAndNewlines.contains(scalar) {
                if !previousWasWhitespace { scalars.append(" ") }
                previousWasWhitespace = true
                continue
            }
            previousWasWhitespace = false

            switch value {
            case 0x2F, 0x5C, 0x3A, 0x2215, 0x2044:
                scalars.append("-")
            default:
                scalars.append(scalar)
            }
        }

        let unsafeEdges = CharacterSet.whitespacesAndNewlines.union(CharacterSet(charactersIn: ".-"))
        var safeName = String(scalars).trimmingCharacters(in: unsafeEdges)
        if safeName.isEmpty { safeName = sanitizedFallback(fallback) }
        safeName = truncatePreservingExtension(safeName, maximumUTF8Bytes: maximumFilenameBytes)
        if safeName.isEmpty || safeName == "." || safeName == ".." { return "Download" }
        return safeName
    }

    static func uniqueURL(in directory: URL, suggestedFilename: String) -> URL {
        let fileManager = FileManager.default
        let safeName = safeFilename(suggestedFilename)
        let base = (safeName as NSString).deletingPathExtension
        let ext = (safeName as NSString).pathExtension
        var candidate = directory.appendingPathComponent(safeName)
        var index = 2

        while fileManager.fileExists(atPath: candidate.path) {
            let filename = ext.isEmpty ? "\(base) \(index)" : "\(base) \(index).\(ext)"
            candidate = directory.appendingPathComponent(filename)
            index += 1
        }
        return candidate
    }

    private static func sanitizedFallback(_ fallback: String) -> String {
        let normalized = fallback.precomposedStringWithCompatibilityMapping
        let candidate = String(normalized.unicodeScalars.compactMap { scalar -> Character? in
            if CharacterSet.controlCharacters.contains(scalar) || scalar.properties.generalCategory == .format { return nil }
            switch scalar.value {
            case 0x2F, 0x5C, 0x3A, 0x2215, 0x2044: return "-"
            default: return Character(String(scalar))
            }
        }).trimmingCharacters(in: CharacterSet.whitespacesAndNewlines.union(CharacterSet(charactersIn: ".-")))
        return candidate.isEmpty ? "Download" : candidate
    }

    private static func truncatePreservingExtension(_ filename: String, maximumUTF8Bytes: Int) -> String {
        guard filename.utf8.count > maximumUTF8Bytes else { return filename }
        let nsName = filename as NSString
        let pathExtension = nsName.pathExtension
        let extensionSuffix = pathExtension.isEmpty ? "" : ".\(pathExtension)"
        let extensionBytes = min(extensionSuffix.utf8.count, maximumUTF8Bytes / 2)
        let suffix = utf8Prefix(extensionSuffix, maximumBytes: extensionBytes)
        let baseBudget = maximumUTF8Bytes - suffix.utf8.count
        let base = utf8Prefix(nsName.deletingPathExtension, maximumBytes: baseBudget)
            .trimmingCharacters(in: CharacterSet.whitespacesAndNewlines.union(CharacterSet(charactersIn: ".")))
        return (base.isEmpty ? "Download" : base) + suffix
    }

    private static func utf8Prefix(_ value: String, maximumBytes: Int) -> String {
        var result = ""
        var count = 0
        for character in value {
            let bytes = String(character).utf8.count
            guard count + bytes <= maximumBytes else { break }
            result.append(character)
            count += bytes
        }
        return result
    }
}
