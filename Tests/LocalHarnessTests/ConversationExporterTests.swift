import Darwin
import Foundation
import Testing
@testable import LocalHarness

@Suite(.serialized)
struct ConversationExporterTests {
    @Test("Recommended JSON export redacts credentials and carries metadata without blobs")
    func recommendedJSONExport() throws {
        let encodedImage = "c3VwZXItc2VjcmV0LWJsb2I="
        let prompt = try ConversationExportMessage.userPrompt(
            sequence: 4,
            date: Date(timeIntervalSince1970: 1_700_000_000),
            content: [
                .text("Use api_key=sk-abcdefghijklmnop and Authorization: Bearer abcdefghijklmnop"),
                .image(mediaType: .png, data: encodedImage, name: "private-photo.png")
            ]
        )
        let session = HarnessConversationSession(
            id: HarnessSessionID("private/session/identifier"),
            selection: HarnessWireModelSelection(
                provider: ProviderID("ollama"),
                model: ModelID("qwen3:27b"),
                reasoningEffort: "high"
            ),
            agentPreset: "standard"
        )
        let artifact = try ConversationExporter.prepare(
            session: session,
            boundary: .onDevice,
            title: "Private build",
            providerName: "Ollama",
            modelName: "Qwen 3 27B",
            messages: [prompt],
            format: .json,
            exportedAt: Date(timeIntervalSince1970: 1_700_000_100)
        )
        let text = try #require(String(data: artifact.data, encoding: .utf8))
        #expect(!text.contains("sk-abcdefghijklmnop"))
        #expect(!text.contains("abcdefghijklmnop"))
        #expect(!text.contains(encodedImage))
        #expect(!text.contains("private/session/identifier"))
        #expect(!text.contains("private-photo.png"))
        #expect(text.contains("[REDACTED"))

        let root = try jsonObject(artifact.data)
        #expect(root["schemaVersion"] as? Int == 1)
        #expect(root["sessionIdentifier"] == nil)
        #expect(root["sessionIdentifierRedacted"] as? Bool == true)
        let route = try #require(root["route"] as? [String: Any])
        #expect(route["providerID"] as? String == "ollama")
        #expect(route["modelID"] as? String == "qwen3:27b")
        #expect(route["boundary"] as? String == "onDevice")
        let messages = try #require(root["messages"] as? [[String: Any]])
        let attachments = try #require(messages.first?["attachments"] as? [[String: Any]])
        let attachment = try #require(attachments.first)
        #expect(attachment["kind"] as? String == "image")
        #expect(attachment["mediaType"] as? String == "image/png")
        #expect(attachment["byteCount"] as? Int == 17)
        #expect(attachment["name"] == nil)
        #expect(attachment["nameRedacted"] as? Bool == true)
        #expect(artifact.attachmentCount == 1)
        #expect(artifact.contentType == "application/json")
    }

    @Test("Recommended export redacts secrets from title, filename, route, and message provenance")
    func recommendedMetadataRedaction() throws {
        let values = [
            "title-secret-abcdefghijklmnop",
            "provider-id-secret-abcdefghijklmnop",
            "model-id-secret-abcdefghijklmnop",
            "provider-name-secret-abcdefghijklmnop",
            "model-name-secret-abcdefghijklmnop",
            "reasoning-secret-abcdefghijklmnop",
            "source-provider-secret-abcdefghijklmnop",
            "source-model-secret-abcdefghijklmnop"
        ]
        let message = ConversationExportMessage(
            sequence: 1,
            role: .assistant,
            text: "safe answer",
            date: Date(timeIntervalSince1970: 100),
            source: SessionTranscriptSource(
                route: ModelRoute(
                    provider: ProviderID("api_key=\(values[6])"),
                    model: ModelID("access_token=\(values[7])")
                ),
                boundary: .cloud
            )
        )
        let session = HarnessConversationSession(
            id: HarnessSessionID("redacted-session"),
            selection: HarnessWireModelSelection(
                provider: ProviderID("api_key=\(values[1])"),
                model: ModelID("access_token=\(values[2])"),
                reasoningEffort: "password=\(values[5])"
            ),
            agentPreset: "standard"
        )
        let artifact = try ConversationExporter.prepare(
            session: session,
            boundary: .cloud,
            title: "secret=\(values[0])",
            providerName: "client_secret=\(values[3])",
            modelName: "auth_token=\(values[4])",
            messages: [message],
            format: .json,
            redaction: .recommended,
            exportedAt: Date(timeIntervalSince1970: 101)
        )
        let payload = String(decoding: artifact.data, as: UTF8.self)
        for value in values {
            #expect(!payload.contains(value))
            #expect(!artifact.suggestedFilename.contains(value))
        }
        #expect(payload.contains("[REDACTED"))
        #expect(ConversationExportFilename.isSafeDestinationBasename(artifact.suggestedFilename))
    }

    @Test("Explicit unredacted export keeps reviewed metadata but still omits paths and bytes")
    func explicitUnredactedMetadata() throws {
        let digest = String(repeating: "A", count: 64)
        let message = ConversationExportMessage(
            sequence: 1,
            role: .user,
            text: "The deliberately preserved token is sk-abcdefghijklmnop.",
            date: Date(timeIntervalSince1970: 10),
            attachments: [
                ConversationExportAttachmentMetadata(
                    kind: .binary,
                    name: "../../private/report.pdf",
                    mediaType: "application/pdf",
                    byteCount: 42,
                    sha256: digest
                )
            ]
        )
        let artifact = try makeLiveArtifact(
            messages: [message],
            format: .json,
            redaction: .none
        )
        let text = try #require(String(data: artifact.data, encoding: .utf8))
        #expect(text.contains("sk-abcdefghijklmnop"))
        #expect(!text.contains("../../private/report.pdf"))
        #expect(!text.contains("file://"))
        let root = try jsonObject(artifact.data)
        #expect(root["sessionIdentifier"] as? String == "session/export-test")
        let messages = try #require(root["messages"] as? [[String: Any]])
        let attachments = try #require(messages[0]["attachments"] as? [[String: Any]])
        #expect(attachments[0]["kind"] as? String == "binary")
        #expect(attachments[0]["name"] == nil)
        #expect(attachments[0]["nameOmittedForSafety"] as? Bool == true)
        #expect(attachments[0]["mediaType"] as? String == "application/pdf")
        #expect(attachments[0]["byteCount"] as? Int == 42)
        #expect(attachments[0]["sha256"] as? String == digest.lowercased())
    }

    @Test("Markdown treats hostile message Markdown as inert fenced content")
    func markdownIsInert() throws {
        let hostile = "Hello\n```\n![tracking pixel](https://tracker.invalid/pixel)\n~~~\n<script>alert(1)</script>"
        let message = ConversationExportMessage(
            sequence: 1,
            role: .assistant,
            text: hostile,
            date: Date(timeIntervalSince1970: 20),
            interrupted: true
        )
        let artifact = try makeLiveArtifact(messages: [message], format: .markdown, redaction: .none)
        let markdown = try #require(String(data: artifact.data, encoding: .utf8))
        #expect(markdown.contains("## Assistant"))
        #expect(markdown.contains("- Status: interrupted"))
        #expect(markdown.contains("````\n" + hostile + "\n````"))
        #expect(markdown.contains("Attachment bytes and local paths are never embedded."))
        #expect(artifact.suggestedFilename.hasSuffix(".md"))
    }

    @Test("Session detail exports expose partial and unavailable state without guessing")
    func detailPartialState() throws {
        let detail = SessionHistoryDetailSnapshot(
            sessionID: HarnessSessionID("must-not-leak"),
            transcript: SessionTranscriptPage(
                messages: [SessionTranscriptMessage(
                    sequence: 9,
                    role: .assistant,
                    text: "private answer",
                    date: Date(timeIntervalSince1970: 50),
                    interrupted: false,
                    source: SessionTranscriptSource(
                        route: ModelRoute(provider: ProviderID("future"), model: ModelID("model")),
                        boundary: .cloud
                    )
                )],
                olderBeforeSequence: 9
            ),
            route: .unavailable
        )
        let artifact = try ConversationExporter.prepare(
            from: detail,
            title: "must-not-leak-title",
            format: .json,
            redaction: .structureOnly,
            exportedAt: Date(timeIntervalSince1970: 60)
        )
        let text = try #require(String(data: artifact.data, encoding: .utf8))
        #expect(artifact.sourceWasPartial)
        #expect(artifact.suggestedFilename == "fulmar-conversation-undated.json")
        #expect(!text.contains("must-not-leak"))
        #expect(!text.contains("private answer"))
        #expect(!text.contains("future"))
        let root = try jsonObject(artifact.data)
        #expect(root["sourceWasPartial"] as? Bool == true)
        #expect(root["routeStatus"] as? String == "unavailable")
        let messages = try #require(root["messages"] as? [[String: Any]])
        #expect(messages[0]["content"] as? String == "[Message content redacted]")
        #expect(messages[0]["timestamp"] == nil)
        #expect(messages[0]["source"] == nil)
    }

    @Test("Filenames are deterministic, ASCII, bounded, and path-safe")
    func safeFilenames() {
        let date = Date(timeIntervalSince1970: 1_700_000_000)
        let first = ConversationExportFilename.suggested(
            title: "../../Résumé\u{202E} 💥 Final",
            latestMessageDate: date,
            format: .json
        )
        let second = ConversationExportFilename.suggested(
            title: "../../Résumé\u{202E} 💥 Final",
            latestMessageDate: date,
            format: .json
        )
        #expect(first == "fulmar-resume-final-20231114-221320.json")
        #expect(first == second)
        #expect(first.utf8.allSatisfy { $0 < 128 })
        #expect(ConversationExportFilename.isSafeDestinationBasename(first))
        #expect(!ConversationExportFilename.isSafeDestinationBasename(".hidden.json"))
        #expect(!ConversationExportFilename.isSafeDestinationBasename("bad\u{202E}name.json"))
        #expect(!ConversationExportFilename.isSafeDestinationBasename("e\u{301}.json"))
        #expect(!ConversationExportFilename.isSafeDestinationBasename("bad:name.json"))
    }

    @Test("Message, text, attachment, metadata, and output limits fail closed")
    func boundedExports() throws {
        let first = exportMessage(sequence: 1, text: "one")
        let second = exportMessage(sequence: 2, text: "two")
        let oneMessage = ConversationExportLimits(
            maximumMessages: 1,
            maximumMessageCharacters: 100,
            maximumMessageUTF8Bytes: 400,
            maximumTotalTextBytes: 1_000,
            maximumAttachments: 10,
            maximumAttachmentNameCharacters: 100,
            maximumOutputBytes: 10_000
        )
        #expect(throws: ConversationExportError.messageLimitExceeded(1)) {
            _ = try makeLiveArtifact(messages: [first, second], format: .json, limits: oneMessage)
        }
        #expect(throws: ConversationExportError.duplicateSequence(1)) {
            _ = try makeLiveArtifact(
                messages: [first, exportMessage(sequence: 1, text: "duplicate")],
                format: .json
            )
        }

        let smallMessage = ConversationExportLimits(
            maximumMessages: 5,
            maximumMessageCharacters: 2,
            maximumMessageUTF8Bytes: 8,
            maximumTotalTextBytes: 100,
            maximumAttachments: 5,
            maximumAttachmentNameCharacters: 100,
            maximumOutputBytes: 10_000
        )
        #expect(throws: ConversationExportError.messageTooLarge(sequence: 1)) {
            _ = try makeLiveArtifact(messages: [first], format: .json, limits: smallMessage)
        }

        let tinyTextTotal = ConversationExportLimits(
            maximumMessages: 5,
            maximumMessageCharacters: 100,
            maximumMessageUTF8Bytes: 400,
            maximumTotalTextBytes: 2,
            maximumAttachments: 5,
            maximumAttachmentNameCharacters: 100,
            maximumOutputBytes: 10_000
        )
        #expect(throws: ConversationExportError.totalTextLimitExceeded(2)) {
            _ = try makeLiveArtifact(messages: [first], format: .json, limits: tinyTextTotal)
        }

        let attachment = ConversationExportAttachmentMetadata(kind: .image, name: "a.png")
        let noAttachments = ConversationExportLimits(
            maximumMessages: 5,
            maximumMessageCharacters: 100,
            maximumMessageUTF8Bytes: 400,
            maximumTotalTextBytes: 100,
            maximumAttachments: 0,
            maximumAttachmentNameCharacters: 100,
            maximumOutputBytes: 10_000
        )
        #expect(throws: ConversationExportError.attachmentLimitExceeded(0)) {
            _ = try makeLiveArtifact(
                messages: [ConversationExportMessage(
                    sequence: 1,
                    role: .user,
                    text: "x",
                    date: Date(timeIntervalSince1970: 0),
                    attachments: [attachment]
                )],
                format: .json,
                limits: noAttachments
            )
        }

        let invalidDigest = ConversationExportAttachmentMetadata(
            kind: .binary,
            sha256: "not-a-sha256"
        )
        #expect(throws: ConversationExportError.invalidAttachmentMetadata) {
            _ = try makeLiveArtifact(
                messages: [ConversationExportMessage(
                    sequence: 1,
                    role: .user,
                    text: "x",
                    date: Date(timeIntervalSince1970: 0),
                    attachments: [invalidDigest]
                )],
                format: .json,
                redaction: .none
            )
        }

        let tinyOutput = ConversationExportLimits(
            maximumMessages: 5,
            maximumMessageCharacters: 100,
            maximumMessageUTF8Bytes: 400,
            maximumTotalTextBytes: 100,
            maximumAttachments: 5,
            maximumAttachmentNameCharacters: 100,
            maximumOutputBytes: 10
        )
        #expect(throws: ConversationExportError.outputLimitExceeded(10)) {
            _ = try makeLiveArtifact(messages: [first], format: .json, limits: tinyOutput)
        }
    }

    @Test("Prompt projection validates base64 without retaining or decoding it")
    func promptProjection() {
        #expect(throws: ConversationExportError.invalidAttachmentMetadata) {
            _ = try ConversationExportMessage.userPrompt(
                sequence: 1,
                date: Date(),
                content: [.image(mediaType: .png, data: "not-base64!", name: nil)]
            )
        }
        #expect(throws: ConversationExportError.invalidAttachmentMetadata) {
            _ = try ConversationExportMessage.userPrompt(
                sequence: 1,
                date: Date(),
                content: [.image(mediaType: .png, data: "YWJjZA==", name: nil)],
                maximumEncodedAttachmentCharacters: 4
            )
        }
    }

    @Test("Final assistant wire messages preserve provenance without inventing it")
    func assistantWireProjection() {
        let wire = HarnessAssistantFinalMessage(
            rpcID: "rpc",
            sessionID: HarnessSessionID("session"),
            sequence: 7,
            time: 1_700_000_000_123,
            turn: 1,
            step: 0,
            messageID: "message",
            textBlocks: ["hello", " world"],
            provider: ProviderID("deepseek"),
            model: ModelID("deepseek-chat"),
            interrupted: false
        )
        let projected = ConversationExportMessage(assistantFinal: wire, boundary: .cloud)
        #expect(projected.sequence == 7)
        #expect(projected.role == .assistant)
        #expect(projected.text == "hello world")
        #expect(abs(projected.date.timeIntervalSince1970 - 1_700_000_000.123) < 0.001)
        #expect(projected.source?.route.provider == ProviderID("deepseek"))
        #expect(projected.source?.route.model == ModelID("deepseek-chat"))
        #expect(projected.source?.boundary == .cloud)
    }

    @Test("Writes are atomic, owner-only, exclusive, and reject symlink destinations")
    func secureWrite() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("conversation-export-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let artifact = try makeLiveArtifact(
            messages: [exportMessage(sequence: 1, text: "complete payload")],
            format: .json
        )
        let destination = root.appendingPathComponent("conversation.json")
        let result = try ConversationExporter.write(artifact, to: destination)
        #expect(result == destination.standardizedFileURL)
        #expect(try Data(contentsOf: destination) == artifact.data)
        let attributes = try FileManager.default.attributesOfItem(atPath: destination.path)
        let permissions = try #require(attributes[.posixPermissions] as? NSNumber)
        #expect(permissions.intValue & 0o777 == 0o600)
        let leftovers = try FileManager.default.contentsOfDirectory(atPath: root.path)
            .filter { $0.hasPrefix(".local-harness-export-") }
        #expect(leftovers.isEmpty)

        #expect(throws: ConversationExportError.destinationAlreadyExists) {
            _ = try ConversationExporter.write(artifact, to: destination)
        }
        #expect(try Data(contentsOf: destination) == artifact.data)

        let target = root.appendingPathComponent("target.json")
        try Data("preserve".utf8).write(to: target)
        let symlink = root.appendingPathComponent("linked.json")
        try FileManager.default.createSymbolicLink(at: symlink, withDestinationURL: target)
        #expect(throws: ConversationExportError.destinationAlreadyExists) {
            _ = try ConversationExporter.write(artifact, to: symlink)
        }
        #expect(try String(contentsOf: target, encoding: .utf8) == "preserve")

        let parentTarget = root.appendingPathComponent("real-parent", isDirectory: true)
        try FileManager.default.createDirectory(at: parentTarget, withIntermediateDirectories: false)
        let parentLink = root.appendingPathComponent("linked-parent", isDirectory: true)
        try FileManager.default.createSymbolicLink(at: parentLink, withDestinationURL: parentTarget)
        #expect(throws: ConversationExportError.invalidDestination) {
            _ = try ConversationExporter.write(
                artifact,
                to: parentLink.appendingPathComponent("through-link.json")
            )
        }
        #expect(!FileManager.default.fileExists(atPath: parentTarget.appendingPathComponent("through-link.json").path))

        #expect(throws: ConversationExportError.invalidDestination) {
            _ = try ConversationExporter.write(
                artifact,
                to: root.appendingPathComponent("wrong-extension.md")
            )
        }
    }
}

private func makeLiveArtifact(
    messages: [ConversationExportMessage],
    format: ConversationExportFormat,
    redaction: ConversationExportRedactionOptions = .recommended,
    limits: ConversationExportLimits = .init()
) throws -> ConversationExportArtifact {
    try ConversationExporter.prepare(
        session: HarnessConversationSession(
            id: HarnessSessionID("session/export-test"),
            selection: HarnessWireModelSelection(
                provider: ProviderID("ollama"),
                model: ModelID("qwen3:27b"),
                reasoningEffort: nil
            ),
            agentPreset: "standard"
        ),
        boundary: .onDevice,
        title: "Export test",
        messages: messages,
        format: format,
        redaction: redaction,
        exportedAt: Date(timeIntervalSince1970: 100),
        limits: limits
    )
}

private func exportMessage(sequence: Int, text: String) -> ConversationExportMessage {
    ConversationExportMessage(
        sequence: sequence,
        role: .user,
        text: text,
        date: Date(timeIntervalSince1970: Double(sequence))
    )
}

private func jsonObject(_ data: Data) throws -> [String: Any] {
    try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
}
