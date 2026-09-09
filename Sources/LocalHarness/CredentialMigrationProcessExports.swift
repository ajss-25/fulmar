// The bounded migration runner is a small Foundation/Darwin library rather
// than part of the GUI executable. Besides keeping the process boundary
// reusable, this lets the separately launched descriptor-collision probe link
// the exact production implementation without importing or linking AppKit.
@_exported import LocalHarnessCredentialMigrationProcess
