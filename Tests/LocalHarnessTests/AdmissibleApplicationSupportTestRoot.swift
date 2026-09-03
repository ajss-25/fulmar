import Darwin
import Foundation

/// Creates a disposable directory whose complete ancestry satisfies the same
/// ownership and write-permission policy as Fulmar's production app-support
/// directory. macOS temporary directories live below world-writable `/tmp`, so
/// they are deliberately unsuitable for tests that exercise production
/// application-support admission.
func makeAdmissibleApplicationSupportTestRoot(prefix: String) throws -> URL {
    guard !prefix.isEmpty,
          prefix.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "-" }),
          let account = getpwuid(geteuid()),
          let home = account.pointee.pw_dir else {
        throw CocoaError(.fileNoSuchFile)
    }

    let root = URL(fileURLWithPath: String(cString: home), isDirectory: true)
        .appendingPathComponent("Library/Caches", isDirectory: true)
        .appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
    do {
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        return root
    } catch {
        try? FileManager.default.removeItem(at: root)
        throw error
    }
}
