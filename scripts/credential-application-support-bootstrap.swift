import Darwin
import Foundation

/// Reproduce native applicationDidFinishLaunching's root admission before a
/// packaged-helper canary, without launching the app or accessing Keychain.
@main
private enum CredentialApplicationSupportBootstrap {
    static func main() {
        guard CommandLine.arguments.count == 2 else {
            diagnostic("Expected one Application Support root.")
            exit(64)
        }
        let path = CommandLine.arguments[1]
        let url = URL(fileURLWithPath: path, isDirectory: true)
        guard path.hasPrefix("/"), !path.contains("\0"), url.path == path else {
            diagnostic("The Application Support root is not an absolute canonical path.")
            exit(64)
        }
        let admission = ApplicationSupportRootAdmission(url: url)
        switch admission.admit() {
        case .success:
            print("Credential canary native Application Support admission passed.")
        case .failure(let error):
            diagnostic(error.localizedDescription)
            exit(1)
        }
    }

    private static func diagnostic(_ message: String) {
        FileHandle.standardError.write(Data((message + "\n").utf8))
    }
}
