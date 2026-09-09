import CryptoKit
import Foundation

/// Supplies capability facts which DSH's current `llm.models` response omits.
/// Only exact, bundled pi-ai provider registries are trusted here. A missing,
/// malformed, or ambiguous record deliberately returns no answer so callers can
/// fall back to text-only behavior.
protocol ModelCapabilityCatalogProviding: Sendable {
    func inputModalities(provider: ProviderID, model: ModelID) -> [ModelInputModality]?
}

struct BundledModelCapabilityCatalog: ModelCapabilityCatalogProviding, Sendable {
    private struct RouteKey: Hashable, Sendable {
        let provider: ProviderID
        let model: ModelID
    }

    private static let manifestName = ".manifest.json"
    private static let maximumManifestBytes = 64 * 1_024
    private static let maximumRegistryBytes = 8 * 1_024 * 1_024
    private static let maximumRegistryFiles = 128
    private static let maximumAPIGroups = 16
    private static let maximumModelsPerRegistry = 4_096
    private static let maximumModelsTotal = 16_384
    private static let maximumIdentifierBytes = 512
    /// Exact defaults from the pinned `@deepseek-ai/dsh-llm-deepseek` adapter.
    /// The source qualification test reads that vendored adapter so an upstream
    /// catalog change cannot silently drift away from this native presentation.
    private static let pinnedAdapterEntries: [RouteKey: [ModelInputModality]] = [
        RouteKey(provider: ProviderID("deepseek-official"), model: ModelID("deepseek-v4-flash")): [.text],
        RouteKey(provider: ProviderID("deepseek-official"), model: ModelID("deepseek-v4-pro")): [.text],
        RouteKey(provider: ProviderID("deepseek-official"), model: ModelID("deepseek-v4-flash-vision-exp")): [.text, .image]
    ]

    private let entries: [RouteKey: [ModelInputModality]]

    init() {
        let dataDirectory = Bundle.main.resourceURL?
            .appendingPathComponent("Runtime/dsh/node_modules/@earendil-works/pi-ai/dist/providers/data", isDirectory: true)
        self.init(providerDataDirectory: dataDirectory)
    }

    /// Internal injection point used by qualification tests against both the
    /// checked-in runtime and deliberately malformed fixture registries.
    init(providerDataDirectory: URL?) {
        guard let providerDataDirectory else {
            entries = Self.pinnedAdapterEntries
            return
        }
        var loaded = Self.pinnedAdapterEntries
        if let parsed = Self.parseManifestedRegistries(providerDataDirectory) {
            loaded.merge(parsed) { _, reviewed in reviewed }
        }
        entries = loaded
    }

    func inputModalities(provider: ProviderID, model: ModelID) -> [ModelInputModality]? {
        entries[RouteKey(provider: provider, model: model)]
    }

    /// Parses only filenames declared by pi-ai's signed, hash-bearing manifest.
    /// One mismatch rejects the whole pi-ai capability set rather than exposing
    /// a partially trusted or attacker-added registry.
    private static func parseManifestedRegistries(
        _ directory: URL
    ) -> [RouteKey: [ModelInputModality]]? {
        guard directory.standardizedFileURL.path == directory.resolvingSymlinksInPath().standardizedFileURL.path,
              let manifestData = try? SecureAttachmentReader.readRegularFile(
                at: directory.appendingPathComponent(manifestName, isDirectory: false),
                maximumBytes: maximumManifestBytes
              ),
              let rawManifest = try? JSONSerialization.jsonObject(with: manifestData),
              let manifest = rawManifest as? [String: Any],
              Set(manifest.keys) == ["schemaVersion", "generatedAt", "structureHash", "files"],
              manifest["schemaVersion"] as? Int == 3,
              let generatedAt = manifest["generatedAt"] as? String,
              !generatedAt.isEmpty,
              generatedAt.utf8.count <= 128,
              let structureHash = manifest["structureHash"] as? String,
              validDigest(structureHash),
              let files = manifest["files"] as? [String: String],
              !files.isEmpty,
              files.count <= maximumRegistryFiles,
              files.allSatisfy({ safeRegistryFilename($0.key) && validDigest($0.value) }),
              let actualNames = BundleSecurityIO.directoryEntryNames(
                  at: directory,
                  inside: directory,
                  maximumEntries: files.count + 2
              ),
              actualNames.count == files.count + 1,
              Set(actualNames) == Set(files.keys).union([manifestName]) else {
            return nil
        }

        var result: [RouteKey: [ModelInputModality]] = [:]
        var totalModels = 0
        for filename in files.keys.sorted() {
            let file = directory.appendingPathComponent(filename, isDirectory: false)
            guard let data = try? SecureAttachmentReader.readRegularFile(
            at: file,
            maximumBytes: maximumRegistryBytes
            ), sha256(data) == files[filename],
                  let providerName = filename.split(separator: ".", omittingEmptySubsequences: false).first.map(String.init),
                  safeIdentifier(providerName),
                  let parsed = parseRegistry(data, provider: ProviderID(providerName)) else {
                return nil
            }
            totalModels += parsed.count
            guard totalModels <= maximumModelsTotal else { return nil }
            for (key, modalities) in parsed {
                guard result[key] == nil else { return nil }
                result[key] = modalities
            }
        }
        return result
    }

    private static func parseRegistry(
        _ data: Data,
        provider: ProviderID
    ) -> [RouteKey: [ModelInputModality]]? {
        guard let root = try? JSONSerialization.jsonObject(with: data, options: []),
              let groups = root as? [String: Any],
              !groups.isEmpty,
              groups.count <= maximumAPIGroups else {
            return nil
        }
        var result: [RouteKey: [ModelInputModality]] = [:]
        var modelCount = 0
        for (api, rawGroup) in groups {
            guard safeIdentifier(api),
                  let models = rawGroup as? [String: Any],
                  !models.isEmpty,
                  models.count <= maximumModelsPerRegistry else {
                return nil
            }
            modelCount += models.count
            guard modelCount <= maximumModelsPerRegistry else { return nil }
            for (identifier, rawModel) in models {
                let key = RouteKey(provider: provider, model: ModelID(identifier))
                guard safeIdentifier(identifier),
                      let model = rawModel as? [String: Any],
                      model["id"] as? String == identifier,
                      model["provider"] as? String == provider.rawValue,
                      model["api"] as? String == api,
                      let rawInput = model["input"] as? [Any],
                      let modalities = parsedModalities(rawInput),
                      result[key] == nil else {
                    return nil
                }
                result[key] = modalities
            }
        }
        return result
    }

    private static func safeRegistryFilename(_ value: String) -> Bool {
        value.range(
            of: #"^[a-z0-9][a-z0-9-]{0,126}\.json$"#,
            options: .regularExpression
        ) != nil
    }

    private static func validDigest(_ value: String) -> Bool {
        value.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil
    }

    private static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func parsedModalities(_ values: [Any]) -> [ModelInputModality]? {
        guard !values.isEmpty, values.count <= ModelInputModality.allCases.count else { return nil }
        var seen = Set<ModelInputModality>()
        var result: [ModelInputModality] = []
        for value in values {
            guard let raw = value as? String,
                  let modality = ModelInputModality(rawValue: raw),
                  seen.insert(modality).inserted else {
                return nil
            }
            result.append(modality)
        }
        // Quick Chat always sends a textual prompt envelope, so an entry which
        // does not accept text cannot safely be exposed through this surface.
        return seen.contains(.text) ? result : nil
    }

    private static func safeIdentifier(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= maximumIdentifierBytes && !value.unicodeScalars.contains {
            CharacterSet.controlCharacters.contains($0)
        }
    }
}
