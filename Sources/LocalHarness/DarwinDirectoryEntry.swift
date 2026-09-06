import Darwin
import Foundation

/// Decodes a Darwin `dirent` without materializing the imported 1,024-byte
/// `d_name` tuple. `readdir` may return a variable-length record near the end
/// of its internal buffer, so reading the whole Swift tuple can cross the
/// record and the allocation even though the filename itself is short.
enum DarwinDirectoryEntry {
    private static let nameOffset = MemoryLayout<dirent>.offset(of: \dirent.d_name)

    static func name(_ entry: UnsafeMutablePointer<dirent>) -> String? {
        let byteCount = Int(entry.pointee.d_namlen)
        let recordByteCount = Int(entry.pointee.d_reclen)
        guard let nameOffset,
              byteCount > 0,
              byteCount <= Int(MAXNAMLEN),
              recordByteCount <= MemoryLayout<dirent>.size,
              nameOffset <= recordByteCount,
              byteCount < recordByteCount - nameOffset else {
            return nil
        }

        let bytes = UnsafeRawBufferPointer(
            start: UnsafeRawPointer(entry).advanced(by: nameOffset),
            count: byteCount + 1
        )
        let nameBytes = bytes.prefix(byteCount)
        guard bytes[byteCount] == 0,
              !nameBytes.contains(0),
              !nameBytes.contains(47) else {
            return nil
        }
        return String(bytes: nameBytes, encoding: .utf8)
    }
}
