import Foundation

@main
enum IconPacker {
    static func main() throws {
        guard CommandLine.arguments.count == 3 else {
            throw PackerError.usage
        }

        let iconset = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        let output = URL(fileURLWithPath: CommandLine.arguments[2])
        let entries = [
            ("icp4", "icon_16x16.png"),
            ("icp5", "icon_32x32.png"),
            ("icp6", "icon_32x32@2x.png"),
            ("ic07", "icon_128x128.png"),
            ("ic08", "icon_256x256.png"),
            ("ic09", "icon_512x512.png"),
            ("ic10", "icon_512x512@2x.png")
        ]

        var body = Data()
        for (type, filename) in entries {
            let imageURL = iconset.appendingPathComponent(filename)
            let image = try Data(contentsOf: imageURL)
            body.append(Data(type.utf8))
            body.appendBigEndian(UInt32(image.count + 8))
            body.append(image)
        }

        var container = Data("icns".utf8)
        container.appendBigEndian(UInt32(body.count + 8))
        container.append(body)
        try container.write(to: output, options: .atomic)
    }
}

private extension Data {
    mutating func appendBigEndian(_ value: UInt32) {
        var value = value.bigEndian
        Swift.withUnsafeBytes(of: &value) { bytes in
            append(contentsOf: bytes)
        }
    }
}

private enum PackerError: LocalizedError {
    case usage

    var errorDescription: String? {
        "Usage: IconPacker <AppIcon.iconset> <AppIcon.icns>"
    }
}
