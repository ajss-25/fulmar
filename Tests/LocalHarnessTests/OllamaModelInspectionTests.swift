import Foundation
import Testing
@testable import LocalHarness

private func showResponse(
    capabilities: Any = ["completion", "tools"],
    modelInfo: Any = [
        "general.architecture": "qwen2",
        "qwen2.context_length": 32_768
    ]
) throws -> Data {
    try JSONSerialization.data(withJSONObject: [
        "capabilities": capabilities,
        "model_info": modelInfo
    ])
}

private func versionResponse(_ value: String) -> Data {
    Data("{\"version\":\"\(value)\"}\n".utf8)
}

@Test func stableOllamaVersionBoundaryAcceptsMinimumTestedAndNewerReleases() throws {
    let minimum = try OllamaVersionCompatibilityPolicy.parseResponse(versionResponse("0.33.2"))
    #expect(minimum == OllamaVersionCompatibilityPolicy.minimum)

    let tested = try OllamaVersionCompatibilityPolicy.parseResponse(versionResponse("0.33.2"))
    #expect(tested == OllamaVersionCompatibilityPolicy.tested)

    let newer = try OllamaVersionCompatibilityPolicy.parseResponse(
        Data(" \t{ \"version\" : \"0.33.99+official.arm64\" }\r\n".utf8)
    )
    #expect(newer.major == 0)
    #expect(newer.minor == 33)
    #expect(newer.patch == 99)
    #expect(newer.buildMetadata == "official.arm64")
    #expect(newer.rawValue == "0.33.99+official.arm64")

    for unqualified in ["0.34.0", "1.4.0+official.arm64"] {
        #expect(throws: OllamaVersionCompatibilityError.newerUnqualified(
            actual: unqualified,
            qualifiedSeries: "0.33.x"
        )) {
            try OllamaVersionCompatibilityPolicy.parseResponse(versionResponse(unqualified))
        }
    }
    #expect(OllamaVersionCompatibilityError.newerUnqualified(
        actual: "0.34.0",
        qualifiedSeries: "0.33.x"
    ).localizedDescription.contains("Install a Fulmar update"))
}

@Test func oldOllamaVersionFailsWithAnActionableMinimum() {
    for oldVersion in ["0.32.12", "0.33.1"] {
        #expect(throws: OllamaVersionCompatibilityError.unsupported(
            actual: oldVersion,
            minimum: "0.33.2"
        )) {
            try OllamaVersionCompatibilityPolicy.parseResponse(versionResponse(oldVersion))
        }
    }
    #expect(OllamaVersionCompatibilityError.unsupported(
        actual: "0.33.1",
        minimum: "0.33.2"
    ).localizedDescription.contains("Update the official Ollama app"))
    #expect(OllamaVersionCompatibilityError.unavailable.localizedDescription.contains(
        "restart Fulmar"
    ))
}

@Test func hostileOllamaVersionPayloadsFailClosed() {
    let hostile: [Data] = [
        Data(),
        Data("{}".utf8),
        Data("{\"version\":null}".utf8),
        Data("{\"version\":true}".utf8),
        Data("{\"version\":\"0.33.2\",\"extra\":true}".utf8),
        Data("{\"version\":\"0.33.2\",\"version\":\"9.0.0\"}".utf8),
        Data("{\"version\":\"0\\u002e33.2\"}".utf8),
        versionResponse("00.33.2"),
        versionResponse("0.033.2"),
        versionResponse("0.33.02"),
        versionResponse("0.33"),
        versionResponse("0.33.2.1"),
        versionResponse("0.33.2-rc.1"),
        versionResponse("v0.33.2"),
        versionResponse("2147483648.0.0"),
        Data([0x7B, 0x22, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x22,
              0x3A, 0x22, 0xFF, 0x22, 0x7D]),
        Data(repeating: 0x20, count: OllamaVersionCompatibilityPolicy.maximumResponseBytes + 1)
    ]
    for payload in hostile {
        #expect(throws: OllamaVersionCompatibilityError.malformedResponse) {
            try OllamaVersionCompatibilityPolicy.parseResponse(payload)
        }
    }
}

@Test func toolCapableNonThinkingModelIsCompatible() throws {
    let result = try OllamaClient.assessModelShowResponse(
        showResponse(),
        requestedModel: "local-tools:latest"
    )
    #expect(result == .compatible(contextLength: 32_768, supportsThinking: false))
}

@Test func missingToolsIsAnExplicitIncompatibility() throws {
    let result = try OllamaClient.assessModelShowResponse(
        showResponse(capabilities: ["completion"]),
        requestedModel: "local-text:latest"
    )
    #expect(result == .incompatible(.toolsUnavailable))
}

@Test func thinkingModelRequiresExplicitSupport() throws {
    let result = try OllamaClient.assessModelShowResponse(
        showResponse(capabilities: ["completion", "tools", "thinking"]),
        requestedModel: "local-thinking:latest"
    )
    #expect(result == .incompatible(.thinkingRequiresExplicitSupport(contextLength: 32_768)))
}

@Test func missingContextFailsClosed() throws {
    let data = try showResponse(modelInfo: ["general.architecture": "qwen2"])
    #expect(throws: OllamaModelInspectionError.missingContextLength) {
        try OllamaClient.assessModelShowResponse(data, requestedModel: "local:latest")
    }
}

@Test func contextOutsideReviewedBoundsIsIncompatible() throws {
    let tooSmall = try showResponse(modelInfo: [
        "general.architecture": "qwen2", "qwen2.context_length": 4_096
    ])
    #expect(try OllamaClient.assessModelShowResponse(tooSmall, requestedModel: "small:latest")
        == .incompatible(.contextTooSmall(actual: 4_096, minimum: 8_192)))

    let tooLarge = try showResponse(modelInfo: [
        "general.architecture": "qwen2", "qwen2.context_length": 2_097_152
    ])
    #expect(try OllamaClient.assessModelShowResponse(tooLarge, requestedModel: "large:latest")
        == .incompatible(.contextTooLarge(actual: 2_097_152, maximum: 1_048_576)))
}

@Test func malformedDuplicateAndUnsafeCapabilitiesFailClosed() throws {
    #expect(throws: OllamaModelInspectionError.malformedResponse) {
        try OllamaClient.assessModelShowResponse(Data("{".utf8), requestedModel: "local:latest")
    }
    #expect(throws: OllamaModelInspectionError.invalidCapabilities) {
        try OllamaClient.assessModelShowResponse(
            showResponse(capabilities: ["completion", "tools", "tools"]),
            requestedModel: "local:latest"
        )
    }
    #expect(throws: OllamaModelInspectionError.invalidCapabilities) {
        try OllamaClient.assessModelShowResponse(
            showResponse(capabilities: ["completion", "tools", "future-network"]),
            requestedModel: "local:latest"
        )
    }
}

@Test func malformedArchitectureAndContextTypesFailClosed() throws {
    let unsafeArchitecture = try showResponse(modelInfo: [
        "general.architecture": "../qwen", "../qwen.context_length": 32_768
    ])
    #expect(throws: OllamaModelInspectionError.invalidArchitecture) {
        try OllamaClient.assessModelShowResponse(unsafeArchitecture, requestedModel: "local:latest")
    }

    let fractional = try showResponse(modelInfo: [
        "general.architecture": "qwen2", "qwen2.context_length": 8_192.5
    ])
    #expect(throws: OllamaModelInspectionError.missingContextLength) {
        try OllamaClient.assessModelShowResponse(fractional, requestedModel: "local:latest")
    }
}
