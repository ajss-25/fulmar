import Darwin
import Foundation
import LocalHarnessApplicationSupportAdmission
import Testing

private struct ApplicationSupportAdmissionFixture {
    let parent: URL
    let support: URL

    init() throws {
        guard let account = getpwuid(geteuid()),
              let home = account.pointee.pw_dir else {
            throw ApplicationSupportRootAdmissionError.unsafePath
        }
        parent = URL(fileURLWithPath: String(cString: home), isDirectory: true)
            .appendingPathComponent(
                "Library/Caches/fulmar-support-admission-\(UUID().uuidString)",
                isDirectory: true
            )
        support = parent.appendingPathComponent("support", isDirectory: true)
        try FileManager.default.createDirectory(
            at: parent,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        guard chmod(parent.path, 0o700) == 0 else {
            throw POSIXError(.init(rawValue: errno) ?? .EIO)
        }
    }

    func createSupport(mode: mode_t = 0o700) throws {
        try FileManager.default.createDirectory(
            at: support,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: Int(mode)]
        )
        guard chmod(support.path, mode) == 0 else {
            throw POSIXError(.init(rawValue: errno) ?? .EIO)
        }
    }

    func mode(of url: URL) throws -> mode_t {
        var value = stat()
        guard lstat(url.path, &value) == 0 else {
            throw POSIXError(.init(rawValue: errno) ?? .EIO)
        }
        return value.st_mode & 0o7777
    }

    func cleanup() { try? FileManager.default.removeItem(at: parent) }
}

@Suite("Application Support root admission")
struct ApplicationSupportRootAdmissionTests {
    @Test("An absent final leaf is created privately and retained")
    func absentRoot() throws {
        let fixture = try ApplicationSupportAdmissionFixture(); defer { fixture.cleanup() }
        let admission = ApplicationSupportRootAdmission(url: fixture.support)
        #expect(try admission.admit().get() == fixture.support.standardizedFileURL)
        #expect(try fixture.mode(of: fixture.support) == 0o700)
        // A directory's link count legitimately changes as Fulmar creates
        // child directories. Revalidation must retain the exact root inode,
        // owner, and mode without mistaking normal child creation for a root
        // replacement.
        try FileManager.default.createDirectory(
            at: fixture.support.appendingPathComponent("HarnessHome", isDirectory: true),
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        #expect(try admission.admit().get() == fixture.support.standardizedFileURL)
    }

    @Test("A preplanted symlink is rejected without touching its target")
    func symlinkPreplant() throws {
        let fixture = try ApplicationSupportAdmissionFixture(); defer { fixture.cleanup() }
        let target = fixture.parent.appendingPathComponent("target", isDirectory: true)
        try FileManager.default.createDirectory(at: target, withIntermediateDirectories: false)
        guard chmod(target.path, 0o750) == 0,
              symlink(target.path, fixture.support.path) == 0 else {
            throw POSIXError(.init(rawValue: errno) ?? .EIO)
        }
        let sentinel = target.appendingPathComponent("must-remain.txt")
        try Data("opaque".utf8).write(to: sentinel)

        let admission = ApplicationSupportRootAdmission(url: fixture.support)
        #expect(throws: ApplicationSupportRootAdmissionError.self) {
            _ = try admission.admit().get()
        }
        #expect(try fixture.mode(of: target) == 0o750)
        #expect(try Data(contentsOf: sentinel) == Data("opaque".utf8))
    }

    @Test("Existing broad and special permission bits fail without chmod")
    func exactModeOnly() throws {
        for mode: mode_t in [0o755, 0o1700, 0o2700, 0o4700] {
            let fixture = try ApplicationSupportAdmissionFixture(); defer { fixture.cleanup() }
            try fixture.createSupport(mode: mode)
            #expect(try fixture.mode(of: fixture.support) == mode)
            let admission = ApplicationSupportRootAdmission(url: fixture.support)
            #expect(throws: ApplicationSupportRootAdmissionError.self) {
                _ = try admission.admit().get()
            }
            #expect(try fixture.mode(of: fixture.support) == mode)
        }
    }

    @Test("An existing extended ACL is rejected without being removed")
    func extendedACL() throws {
        let fixture = try ApplicationSupportAdmissionFixture(); defer { fixture.cleanup() }
        try fixture.createSupport()
        let chmodProcess = Process()
        chmodProcess.executableURL = URL(fileURLWithPath: "/bin/chmod", isDirectory: false)
        chmodProcess.arguments = ["+a", "everyone deny write", fixture.support.path]
        try chmodProcess.run()
        chmodProcess.waitUntilExit()
        #expect(chmodProcess.terminationReason == .exit)
        #expect(chmodProcess.terminationStatus == 0)

        let admission = ApplicationSupportRootAdmission(url: fixture.support)
        #expect(throws: ApplicationSupportRootAdmissionError.self) {
            _ = try admission.admit().get()
        }
        let listProcess = Process()
        let output = Pipe()
        listProcess.executableURL = URL(fileURLWithPath: "/bin/ls", isDirectory: false)
        listProcess.arguments = ["-lde", fixture.support.path]
        listProcess.standardOutput = output
        try listProcess.run()
        listProcess.waitUntilExit()
        let listing = String(
            decoding: output.fileHandleForReading.readDataToEndOfFile(),
            as: UTF8.self
        )
        #expect(listProcess.terminationStatus == 0)
        #expect(listing.contains("everyone deny"))
    }

    @Test("A post-admission replacement permanently fails the retained identity")
    func replacementRace() throws {
        let fixture = try ApplicationSupportAdmissionFixture(); defer { fixture.cleanup() }
        try fixture.createSupport()
        let admission = ApplicationSupportRootAdmission(url: fixture.support)
        _ = try admission.admit().get()

        let displaced = fixture.parent.appendingPathComponent("support-retained", isDirectory: true)
        try FileManager.default.moveItem(at: fixture.support, to: displaced)
        try fixture.createSupport()
        let sentinel = fixture.support.appendingPathComponent("replacement.txt")
        try Data("replacement".utf8).write(to: sentinel)

        #expect(throws: ApplicationSupportRootAdmissionError.self) {
            _ = try admission.admit().get()
        }
        #expect(try Data(contentsOf: sentinel) == Data("replacement".utf8))
        #expect(throws: ApplicationSupportRootAdmissionError.self) {
            _ = try admission.admit().get()
        }
    }

    @Test("The failure sink cannot resolve or alias user state")
    func failureSink() {
        let sink = ApplicationSupportRootAdmission.unavailableSink
        #expect(sink.path == "/dev/null/Fulmar-Unsafe-Application-Support")
        var value = stat()
        #expect(lstat(sink.path, &value) != 0)
        #expect(errno == ENOTDIR)
    }
}
