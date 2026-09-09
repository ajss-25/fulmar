import Foundation
import Security

enum BundleIntegrityVerifier {
    static func verify() -> Bool {
        (try? verify(cancellationCheck: {})) ?? false
    }

    static func verify(cancellationCheck: () throws -> Void) throws -> Bool {
        try cancellationCheck()
        guard Bundle.main.bundleURL.pathExtension == "app" else { return true }
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(Bundle.main.bundleURL as CFURL, [], &staticCode) == errSecSuccess,
              let staticCode else { return false }
        let flags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate | kSecCSCheckNestedCode)
        // Authenticate the bundle before parsing any mutable bytes. Retain a
        // second signature pass and a second bounded structural pass so a path
        // replacement racing verification fails closed.
        guard SecStaticCodeCheckValidity(staticCode, flags, nil) == errSecSuccess else { return false }
        try cancellationCheck()
        guard PresetSecurityPolicy.verifyBundledRuntime() else { return false }
        try cancellationCheck()
        guard MCPBundleSecurityPolicy.verifyBundledRuntime() else { return false }
        try cancellationCheck()
        guard SecStaticCodeCheckValidity(staticCode, flags, nil) == errSecSuccess else { return false }
        try cancellationCheck()
        guard PresetSecurityPolicy.verifyBundledRuntime() else { return false }
        try cancellationCheck()
        guard MCPBundleSecurityPolicy.verifyBundledRuntime() else { return false }
        try cancellationCheck()
        return true
    }
}
