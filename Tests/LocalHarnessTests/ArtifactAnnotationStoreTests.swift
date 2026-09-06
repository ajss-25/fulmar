import Foundation
import Testing
@testable import LocalHarness

private func artifactNoteFixture() -> (root: URL, artifact: URL) {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("artifact-notes-\(UUID().uuidString)", isDirectory: true)
    return (root, root.appendingPathComponent("artifact.txt"))
}

@Test func artifactNotesRoundTripPrivatelyAndDeleteEmptyNotes() throws {
    let fixture = artifactNoteFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let store = ArtifactAnnotationStore(applicationSupport: fixture.root)

    #expect(try store.read(for: fixture.artifact).isEmpty)
    try store.write("A private note", for: fixture.artifact)
    #expect(try store.read(for: fixture.artifact) == "A private note")
    let note = store.noteURL(for: fixture.artifact)
    let attributes = try FileManager.default.attributesOfItem(atPath: note.path)
    #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)

    try store.write("  \n", for: fixture.artifact)
    #expect(try store.read(for: fixture.artifact).isEmpty)
    #expect(!FileManager.default.fileExists(atPath: note.path))
}

@Test func artifactNotesRejectOversizeInvalidUTF8LinksAndUnsafePermissions() throws {
    let fixture = artifactNoteFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let limits = ArtifactAnnotationStore.Limits(
        maximumNoteBytes: 16,
        maximumNotes: 4,
        maximumAggregateBytes: 64,
        maximumDirectoryEntries: 8,
        scanDuration: 1
    )
    let store = ArtifactAnnotationStore(applicationSupport: fixture.root, limits: limits)
    try store.write("safe", for: fixture.artifact)
    let note = store.noteURL(for: fixture.artifact)

    try Data(repeating: 0x41, count: 17).write(to: note, options: .atomic)
    #expect(throws: ArtifactAnnotationError.noteTooLarge(maximumBytes: 16)) {
        _ = try store.read(for: fixture.artifact)
    }

    try Data([0xFF, 0xFE]).write(to: note, options: .atomic)
    #expect(throws: ArtifactAnnotationError.invalidUTF8) {
        _ = try store.read(for: fixture.artifact)
    }

    try Data("safe".utf8).write(to: note, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o666], ofItemAtPath: note.path)
    #expect(throws: ArtifactAnnotationError.unsafeStorage) {
        _ = try store.read(for: fixture.artifact)
    }

    try FileManager.default.removeItem(at: note)
    let outside = fixture.root.appendingPathComponent("outside.txt")
    try Data("outside".utf8).write(to: outside)
    try FileManager.default.createSymbolicLink(at: note, withDestinationURL: outside)
    #expect(throws: ArtifactAnnotationError.unsafeStorage) {
        _ = try store.read(for: fixture.artifact)
    }
    #expect(throws: ArtifactAnnotationError.unsafeStorage) {
        try store.write("replacement", for: fixture.artifact)
    }
}

@Test func artifactNotesEnforceCountAggregateAndDirectoryShapeLimits() throws {
    let fixture = artifactNoteFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let limits = ArtifactAnnotationStore.Limits(
        maximumNoteBytes: 10,
        maximumNotes: 1,
        maximumAggregateBytes: 10,
        maximumDirectoryEntries: 2,
        scanDuration: 1
    )
    let store = ArtifactAnnotationStore(applicationSupport: fixture.root, limits: limits)
    try store.write("1234567890", for: fixture.artifact)
    #expect(throws: ArtifactAnnotationError.noteTooLarge(maximumBytes: 10)) {
        try store.write("12345678901", for: fixture.artifact)
    }
    #expect(throws: ArtifactAnnotationError.storageLimitExceeded) {
        try store.write("second", for: fixture.root.appendingPathComponent("second.txt"))
    }

    let notesDirectory = store.noteURL(for: fixture.artifact).deletingLastPathComponent()
    try Data().write(to: notesDirectory.appendingPathComponent("unexpected"))
    #expect(throws: ArtifactAnnotationError.storageLimitExceeded) {
        try store.write("changed", for: fixture.artifact)
    }
}

@Test func artifactNotesRejectLinkedOrPermissiveStorageDirectory() throws {
    let fixture = artifactNoteFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let store = ArtifactAnnotationStore(applicationSupport: fixture.root)
    _ = try store.read(for: fixture.artifact)
    let notesDirectory = store.noteURL(for: fixture.artifact).deletingLastPathComponent()
    try FileManager.default.setAttributes([.posixPermissions: 0o777], ofItemAtPath: notesDirectory.path)
    // The store owns this directory and safely tightens its mode through an
    // already-open no-follow descriptor.
    try store.write("safe", for: fixture.artifact)
    let attributes = try FileManager.default.attributesOfItem(atPath: notesDirectory.path)
    #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o700)

    try FileManager.default.removeItem(at: notesDirectory)
    let outside = fixture.root.appendingPathComponent("outside-notes", isDirectory: true)
    try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
    try FileManager.default.createSymbolicLink(at: notesDirectory, withDestinationURL: outside)
    #expect(throws: ArtifactAnnotationError.unsafeStorage) {
        _ = try store.read(for: fixture.artifact)
    }
}
