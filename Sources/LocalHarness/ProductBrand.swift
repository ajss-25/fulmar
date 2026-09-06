import Foundation

/// User-facing product identity. The bundle metadata is authoritative in a
/// shipped app; the fallback keeps previews and unit tests deterministic.
///
/// Technical identifiers intentionally remain under the LocalHarness name.
/// They are persistence and security boundaries, not branding, and changing
/// them would strand existing settings, Keychain items, backups, and updates.
enum ProductBrand {
    private struct ReleaseIdentity: Decodable {
        struct Runtime: Decodable { let deepseekHarnessVersion: String }
        let productDisplayName: String
        let bundleIdentifier: String
        let runtime: Runtime
    }

    static var displayName: String {
        let configured = Bundle.main.bundleIdentifier == bundleIdentifier
            ? Bundle.main.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String
            : nil
        return configured?.trimmingCharacters(in: .whitespacesAndNewlines).nonEmpty ?? "Fulmar"
    }

    static let legacyStorageName = "Local Harness"
    static let bundleIdentifier = "com.angadjairath.localharness"
    static let upstreamRuntimeName = "DeepSeek Harness"

    static func reviewedDSHVersion(resources: URL) throws -> String {
        let identityURL = resources.appendingPathComponent("ReleaseIdentity.json")
        let data = try SecureAttachmentReader.readRegularFile(at: identityURL, maximumBytes: 64 * 1_024)
        let identity = try JSONDecoder().decode(ReleaseIdentity.self, from: data)
        let version = identity.runtime.deepseekHarnessVersion
        guard identity.productDisplayName == displayName,
              identity.bundleIdentifier == bundleIdentifier,
              !version.isEmpty,
              version.utf8.count <= 128 else {
            throw LocalHarnessError.harnessNotFound
        }
        return version
    }
}

private extension String {
    var nonEmpty: String? { isEmpty ? nil : self }
}
