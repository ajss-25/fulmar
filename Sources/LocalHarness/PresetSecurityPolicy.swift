import Foundation
import CryptoKit

enum PresetSecurityPolicy {
    static let maximumCompositionBytes = 512 * 1_024
    static let maximumMetadataBytes = 64 * 1_024
    static let maximumManifestBytes = 64 * 1_024

    private struct Manifest: Decodable {
        let version: Int
        let allowedPresetIDs: [String]
        let removedRowIDs: [String]
        let compositionSHA256: String
    }

    static let allowedShippedPresetIDs: Set<String> = ["standard"]
    static let forbiddenCompositionMarkers = [
        "@deepseek-ai/dsh-fs-local",
        "@deepseek-ai/dsh-tool-cordis",
        "@deepseek-ai/dsh-tool-cordis-mount",
        "@deepseek-ai/dsh-cordis-mount",
        "@deepseek-ai/dsh-workflow-worker-thread",
        "@deepseek-ai/dsh-tool-workflow",
        "@deepseek-ai/dsh-tool-ralph",
        "@deepseek-ai/dsh-code-runtime-worker-thread",
        "@deepseek-ai/dsh-tool-code"
    ]
    static let requiredSkillIsolationMarkers = [
        "- id: skill-filesystem",
        "includeDefaultRoots: false",
        "bundledSkillDir:",
        "process.env.DSH_HOME, 'skills', 'Active'",
        "watchFollowSymlinks: false"
    ]
    static let requiredApprovedWebMarkers = [
        "- id: tool-web",
        "name: '@deepseek-ai/dsh-tool-web'",
        "search: false",
        "fetch: true",
        "fetchTimeoutMs: 30000",
        "fetchMaxOutputChars: 200000"
    ]

    static func validatePresetRoot(_ root: URL, fileManager: FileManager = .default) -> Bool {
        guard isDirectoryWithoutSymlink(root, containedIn: root) else { return false }
        _ = fileManager
        let expectedRootEntries = allowedShippedPresetIDs.union(["local-harness-policy.json"])
        guard let entryNames = BundleSecurityIO.directoryEntryNames(
            at: root,
            inside: root,
            maximumEntries: expectedRootEntries.count + 1
        ), Set(entryNames) == expectedRootEntries, entryNames.count == expectedRootEntries.count else {
            return false
        }

        var discovered = Set<String>()
        var compositionByIdentifier: [String: Data] = [:]
        for identifier in allowedShippedPresetIDs.sorted() {
            let entry = root.appendingPathComponent(identifier, isDirectory: true)
            guard isDirectoryWithoutSymlink(entry, containedIn: root) else { return false }
            let expectedPresetEntries: Set<String> = ["agent.cordis.yml", "preset.yml"]
            guard let presetEntries = BundleSecurityIO.directoryEntryNames(
                at: entry,
                inside: root,
                maximumEntries: expectedPresetEntries.count + 1
            ), Set(presetEntries) == expectedPresetEntries,
               presetEntries.count == expectedPresetEntries.count else { return false }
            let composition = entry.appendingPathComponent("agent.cordis.yml")
            let metadata = entry.appendingPathComponent("preset.yml")
            guard let compositionData = BundleSecurityIO.readRegularFile(
                      at: composition, inside: root, maximumBytes: maximumCompositionBytes
                  ), BundleSecurityIO.isRegularFile(
                      metadata, inside: root, maximumBytes: maximumMetadataBytes
                  ), let text = String(data: compositionData, encoding: .utf8) else { return false }
            guard allowedShippedPresetIDs.contains(identifier),
                  !forbiddenCompositionMarkers.contains(where: text.contains),
                  requiredSkillIsolationMarkers.allSatisfy(text.contains),
                  requiredApprovedWebMarkers.allSatisfy(text.contains),
                  text.components(separatedBy: "- id: skill-filesystem").count == 2,
                  text.components(separatedBy: "- id: tool-web").count == 2 else { return false }
            discovered.insert(identifier)
            compositionByIdentifier[identifier] = compositionData
        }
        guard discovered == allowedShippedPresetIDs,
              let data = BundleSecurityIO.readRegularFile(
                  at: root.appendingPathComponent("local-harness-policy.json"),
                  inside: root,
                  maximumBytes: maximumManifestBytes
              ),
              let manifest = try? JSONDecoder().decode(Manifest.self, from: data),
              manifest.version == 1,
              Set(manifest.allowedPresetIDs) == allowedShippedPresetIDs,
              Set(manifest.removedRowIDs) == Set(["tool-ralph", "tool-workflow", "workflow-worker-thread"]),
              let composition = compositionByIdentifier["standard"] else { return false }
        let digest = SHA256.hash(data: composition).map { String(format: "%02x", $0) }.joined()
        return digest == manifest.compositionSHA256
    }

    private static func isDirectoryWithoutSymlink(_ candidate: URL, containedIn root: URL) -> Bool {
        guard isContained(candidate, in: root),
              let values = try? candidate.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey]),
              values.isDirectory == true, values.isSymbolicLink != true else { return false }
        return true
    }

    private static func isRegularFileWithoutSymlink(_ candidate: URL, containedIn root: URL) -> Bool {
        guard isContained(candidate, in: root),
              let values = try? candidate.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey]),
              values.isRegularFile == true, values.isSymbolicLink != true else { return false }
        return true
    }

    private static func isContained(_ candidate: URL, in root: URL) -> Bool {
        let resolvedRoot = root.resolvingSymlinksInPath().standardizedFileURL.path
        let resolvedCandidate = candidate.resolvingSymlinksInPath().standardizedFileURL.path
        return resolvedCandidate == resolvedRoot || resolvedCandidate.hasPrefix(resolvedRoot + "/")
    }

    static func verifyBundledRuntime(bundle: Bundle = .main) -> Bool {
        guard bundle.bundleURL.pathExtension == "app", let resources = bundle.resourceURL else { return true }
        return validatePresetRoot(resources.appendingPathComponent("Runtime/dsh/config/agent-presets", isDirectory: true))
    }
}
