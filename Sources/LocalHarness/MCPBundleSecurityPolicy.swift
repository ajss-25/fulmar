import Darwin
import Foundation

/// Structural checks for the signed MCP bridge. Code signing authenticates the
/// bytes; these checks make the security-relevant package shape, pinned upstream
/// dependency, and activation patch part of the native launch invariant.
enum MCPBundleSecurityPolicy {
    static let maximumPackageJSONBytes = 256 * 1_024
    static let maximumPatchBytes = 1 * 1_024 * 1_024
    static let maximumPackageFileBytes = 8 * 1_024 * 1_024
    static let reviewedClientBridgeVersion = "1.2.1"

    static let guardedPackageFiles: Set<String> = [
        "package.json", "index.mjs", "catalog-core.mjs", "guarded-runtime.mjs",
        "wire-guard.mjs", "stdio-guard-runner.mjs"
    ]
    static let clientBridgePackageFiles: Set<String> = [
        "package.json", "index.mjs", "client.js"
    ]

    private struct Package: Decodable {
        let name: String
        let version: String
        let type: String?
        let main: String?
        let exports: String?
        let dependencies: [String: String]?
        let peerDependencies: [String: String]?
    }

    private struct PackageIdentity: Decodable {
        let name: String
        let version: String
    }

    private struct ClientBridgePackage: Decodable {
        struct DSH: Decodable {
            struct Client: Decodable {
                let inject: [String]
                let platform: String
            }

            let client: Client
        }

        let name: String
        let version: String
        let `private`: Bool
        let type: String
        let main: String
        let exports: [String: String]
        let peerDependencies: [String: String]
        let dsh: DSH
    }

    static func verifyBundledRuntime(bundle: Bundle = .main) -> Bool {
        guard bundle.bundleURL.pathExtension == "app", let resources = bundle.resourceURL else { return true }
        return validate(resources: resources)
    }

    static func validate(resources: URL, fileManager: FileManager = .default) -> Bool {
        _ = fileManager
        let runtime = resources.appendingPathComponent("Runtime/dsh", isDirectory: true)
        let guarded = runtime.appendingPathComponent(
            "node_modules/@local-harness/dsh-mcp-guarded",
            isDirectory: true
        )
        let clientBridge = runtime.appendingPathComponent(
            "node_modules/@local-harness/dsh-client-security-bridge",
            isDirectory: true
        )
        let upstream = runtime.appendingPathComponent(
            "node_modules/@deepseek-ai/dsh-mcp-client/package.json",
            isDirectory: false
        )
        let upstreamCredentials = runtime.appendingPathComponent(
            "node_modules/@deepseek-ai/dsh-credentials/package.json",
            isDirectory: false
        )
        let upstreamSchemastery = runtime.appendingPathComponent(
            "node_modules/@deepseek-ai/schemastery/package.json",
            isDirectory: false
        )
        let runtimeManifest = runtime.appendingPathComponent("package.json", isDirectory: false)
        let patch = resources.appendingPathComponent("LocalHarness.patch.yml", isDirectory: false)

        guard secureDirectory(runtime, inside: runtime),
              secureDirectory(guarded, inside: runtime),
              secureDirectory(clientBridge, inside: runtime),
              secureFile(upstream, inside: runtime, maximumBytes: maximumPackageJSONBytes),
              secureFile(upstreamCredentials, inside: runtime, maximumBytes: maximumPackageJSONBytes),
              secureFile(upstreamSchemastery, inside: runtime, maximumBytes: maximumPackageJSONBytes),
              secureFile(runtimeManifest, inside: runtime, maximumBytes: maximumPackageJSONBytes),
              secureFile(patch, inside: resources, maximumBytes: maximumPatchBytes),
              let entryNames = BundleSecurityIO.directoryEntryNames(
                  at: guarded, inside: runtime, maximumEntries: guardedPackageFiles.count + 1
              ),
              Set(entryNames) == guardedPackageFiles,
              entryNames.count == guardedPackageFiles.count,
              entryNames.allSatisfy({
                  secureFile(
                      guarded.appendingPathComponent($0),
                      inside: guarded,
                      maximumBytes: maximumPackageFileBytes
                  )
              }),
              let clientEntryNames = BundleSecurityIO.directoryEntryNames(
                  at: clientBridge, inside: runtime, maximumEntries: clientBridgePackageFiles.count + 1
              ),
              Set(clientEntryNames) == clientBridgePackageFiles,
              clientEntryNames.count == clientBridgePackageFiles.count,
              clientEntryNames.allSatisfy({
                  secureFile(
                      clientBridge.appendingPathComponent($0),
                      inside: clientBridge,
                      maximumBytes: maximumPackageFileBytes
                  )
              }),
              let localPackage = decodePackage(guarded.appendingPathComponent("package.json")),
              localPackage.name == "@local-harness/dsh-mcp-guarded",
              localPackage.version == "1.0.0",
              localPackage.type == "module",
              localPackage.main == "./index.mjs",
              localPackage.exports == "./index.mjs",
              let bridgePackage = decodeClientBridgePackage(
                  clientBridge.appendingPathComponent("package.json")
              ),
              bridgePackage.name == "@local-harness/dsh-client-security-bridge",
              bridgePackage.version == reviewedClientBridgeVersion,
              bridgePackage.private,
              bridgePackage.type == "module",
              bridgePackage.main == "./index.mjs",
              bridgePackage.exports == [
                  ".": "./index.mjs",
                  "./client": "./client.js",
                  "./package.json": "./package.json"
              ],
              bridgePackage.peerDependencies == [
                  "@deepseek-ai/dsh-host-apiproxy": "0.1.1-rc.1",
                  "@deepseek-ai/dsh-llm": "0.1.1-rc.1"
              ],
              bridgePackage.dsh.client.inject == [
                  "@deepseek-ai/dsh-client-runtime",
                  "@deepseek-ai/dsh-client-ui-conversation"
              ],
              bridgePackage.dsh.client.platform == "web",
              let upstreamPackage = decodePackageIdentity(upstream),
              upstreamPackage.name == "@deepseek-ai/dsh-mcp-client",
              let credentialsPackage = decodePackageIdentity(upstreamCredentials),
              credentialsPackage.name == "@deepseek-ai/dsh-credentials",
              let schemasteryPackage = decodePackageIdentity(upstreamSchemastery),
              schemasteryPackage.name == "@deepseek-ai/schemastery",
              localPackage.peerDependencies == [
                  "@deepseek-ai/dsh-credentials": credentialsPackage.version,
                  "@deepseek-ai/dsh-mcp-client": upstreamPackage.version,
                  "@deepseek-ai/schemastery": schemasteryPackage.version
              ],
              let appPackage = decodePackage(runtimeManifest),
              appPackage.name == "@deepseek-ai/dsh",
              appPackage.version == upstreamPackage.version,
              appPackage.version == credentialsPackage.version,
              appPackage.dependencies?.filter({ $0.key.hasPrefix("@local-harness/") }) == [
                  "@local-harness/dsh-client-security-bridge": reviewedClientBridgeVersion,
                  "@local-harness/dsh-credentials-keychain": "1.0.8",
                  "@local-harness/dsh-fs-confined": "1.0.0",
                  "@local-harness/dsh-mcp-guarded": "1.0.0",
                  "@local-harness/dsh-performance-profile": "1.2.0",
                  "@local-harness/dsh-web-fetch-safe": "1.0.0"
              ],
              let patchData = BundleSecurityIO.readRegularFile(
                  at: patch, inside: resources, maximumBytes: maximumPatchBytes
              ),
              let patchText = String(data: patchData, encoding: .utf8),
              patchText.components(separatedBy: "- id: mcp-guarded").count == 2,
              patchText.components(separatedBy: "name: '@local-harness/dsh-mcp-guarded'").count == 2,
              patchText.components(separatedBy: "catalogPath: !!js process.env.LOCAL_HARNESS_MCP_CATALOG").count == 2,
              patchText.components(separatedBy: "- id: client-security-bridge").count == 2,
              patchText.components(separatedBy: "name: '@local-harness/dsh-client-security-bridge'").count == 2,
              patchText.components(separatedBy: "- id: web-fetch-safe").count == 2,
              patchText.components(separatedBy: "name: '@local-harness/dsh-web-fetch-safe'").count == 2 else {
            return false
        }
        return true
    }

    private static func decodePackage(_ url: URL) -> Package? {
        guard let data = BundleSecurityIO.readRegularFile(
            at: url,
            inside: url.deletingLastPathComponent(),
            maximumBytes: maximumPackageJSONBytes
        ) else { return nil }
        return try? JSONDecoder().decode(Package.self, from: data)
    }

    private static func decodePackageIdentity(_ url: URL) -> PackageIdentity? {
        guard let data = BundleSecurityIO.readRegularFile(
            at: url,
            inside: url.deletingLastPathComponent(),
            maximumBytes: maximumPackageJSONBytes
        ) else { return nil }
        return try? JSONDecoder().decode(PackageIdentity.self, from: data)
    }

    private static func decodeClientBridgePackage(_ url: URL) -> ClientBridgePackage? {
        guard let data = BundleSecurityIO.readRegularFile(
            at: url,
            inside: url.deletingLastPathComponent(),
            maximumBytes: maximumPackageJSONBytes
        ) else { return nil }
        return try? JSONDecoder().decode(ClientBridgePackage.self, from: data)
    }

    private static func secureDirectory(_ candidate: URL, inside root: URL) -> Bool {
        secureNode(candidate, inside: root, expectedType: S_IFDIR)
    }

    private static func secureFile(_ candidate: URL, inside root: URL, maximumBytes: Int) -> Bool {
        guard secureNode(candidate, inside: root, expectedType: S_IFREG) else { return false }
        return BundleSecurityIO.isRegularFile(candidate, inside: root, maximumBytes: maximumBytes)
    }

    private static func secureNode(_ candidate: URL, inside root: URL, expectedType: mode_t) -> Bool {
        let canonicalRoot = root.resolvingSymlinksInPath().standardizedFileURL.path
        let standardized = candidate.standardizedFileURL.path
        let canonical = candidate.resolvingSymlinksInPath().standardizedFileURL.path
        guard standardized == canonical,
              canonical == canonicalRoot || canonical.hasPrefix(canonicalRoot.hasSuffix("/") ? canonicalRoot : canonicalRoot + "/") else {
            return false
        }
        var metadata = stat()
        return Darwin.lstat(canonical, &metadata) == 0
            && metadata.st_mode & S_IFMT == expectedType
            && (metadata.st_uid == geteuid() || metadata.st_uid == 0)
            && metadata.st_mode & (S_IWGRP | S_IWOTH) == 0
    }
}
