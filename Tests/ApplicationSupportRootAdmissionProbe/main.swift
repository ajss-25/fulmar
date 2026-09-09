import Darwin
import Foundation
import LocalHarnessApplicationSupportAdmission

private enum ProbeFailure: Error {
    case setup
    case aclNotInstalled
    case admissionUnexpectedlySucceeded
    case aclWasRemoved
}

@main
private struct ApplicationSupportRootAdmissionProbe {
    static func main() throws {
        let parent = FileManager.default.temporaryDirectory.appendingPathComponent(
            "fulmar-support-admission-probe-\(UUID().uuidString)",
            isDirectory: true
        )
        let support = parent.appendingPathComponent("support", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: parent) }
        try FileManager.default.createDirectory(
            at: support,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        guard chmod(parent.path, 0o700) == 0,
              chmod(support.path, 0o700) == 0 else {
            throw ProbeFailure.setup
        }

        let addACL = Process()
        addACL.executableURL = URL(fileURLWithPath: "/bin/chmod", isDirectory: false)
        addACL.arguments = ["+a", "everyone deny write", support.path]
        try addACL.run()
        addACL.waitUntilExit()
        guard addACL.terminationReason == .exit, addACL.terminationStatus == 0 else {
            throw ProbeFailure.aclNotInstalled
        }

        if case .success = ApplicationSupportRootAdmission(url: support).admit() {
            throw ProbeFailure.admissionUnexpectedlySucceeded
        }
        guard let acl = acl_get_file(support.path, ACL_TYPE_EXTENDED) else {
            throw ProbeFailure.aclWasRemoved
        }
        _ = acl_free(UnsafeMutableRawPointer(acl))
        print("FULMAR_APPLICATION_SUPPORT_ACL_REJECTION_OK")
    }
}
