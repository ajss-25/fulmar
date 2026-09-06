import Foundation
import Testing
@testable import LocalHarness

private let qualifiedQwen = ModelSelection.defaultLocal
private let compatibleLocal = ModelSelection(
    route: ModelRoute(
        provider: BuiltInProviderDescriptors.ollama.id,
        model: ModelID("llama-tools:latest")
    ),
    reasoningEffort: "high",
    performanceProfile: .deep
)

private let gibibyte = UInt64(1_073_741_824)

private func installedModel(
    name: String,
    digest: String?,
    size: Int64 = 18_000_000_000
) -> OllamaModel {
    OllamaModel(
        name: name,
        digest: digest,
        size: size,
        modifiedAt: "2026-08-29T00:00:00Z",
        details: nil
    )
}

@Test func qualifiedQwenRequiresTheExactImmutableOfficialManifest() throws {
    #expect(BuiltInProviderDescriptors.qwenLocalModelManifestDigest.count == 64)
    #expect(BuiltInProviderDescriptors.qwenLocalModelManifestDigest.allSatisfy {
        $0.isHexDigit && !$0.isUppercase
    })
    #expect(!BuiltInProviderDescriptors.qwenLocalModelManifestDigest.hasPrefix("sha256:"))

    try LocalModelCompatibilityPolicy.validateInstalledIdentity(
        selection: qualifiedQwen,
        installedModels: [installedModel(
            name: qualifiedQwen.route.model.rawValue,
            digest: BuiltInProviderDescriptors.qwenLocalModelManifestDigest
        )]
    )

    for digest in [
        nil,
        String(repeating: "0", count: 64),
        "sha256:" + BuiltInProviderDescriptors.qwenLocalModelManifestDigest
    ] {
        #expect(throws: LocalModelAdmissionError.qualifiedModelIdentityMismatch) {
            try LocalModelCompatibilityPolicy.validateInstalledIdentity(
                selection: qualifiedQwen,
                installedModels: [installedModel(
                    name: qualifiedQwen.route.model.rawValue,
                    digest: digest
                )]
            )
        }
    }
    #expect(throws: LocalModelAdmissionError.qualifiedModelIdentityMismatch) {
        try LocalModelCompatibilityPolicy.validateInstalledIdentity(
            selection: qualifiedQwen,
            installedModels: [
                installedModel(
                    name: qualifiedQwen.route.model.rawValue,
                    digest: BuiltInProviderDescriptors.qwenLocalModelManifestDigest
                ),
                installedModel(
                    name: qualifiedQwen.route.model.rawValue,
                    digest: BuiltInProviderDescriptors.qwenLocalModelManifestDigest
                )
            ]
        )
    }
    let identityRemediation = LocalModelAdmissionError.qualifiedModelIdentityMismatch
        .localizedDescription
    #expect(identityRemediation.contains("Remove the mismatched tag"))
    #expect(identityRemediation.contains("differently tagged compatible local model"))
    #expect(!identityRemediation.contains("choose Compatibility mode"))
}

@Test func qualifiedQwenAcceptsTheExactOllamaTagsWireDigest() throws {
    let payload = Data(#"""
    {
      "name": "qwen3.8:27b-mlx",
      "digest": "5642e97495e1a088883805981563dcdc4a040c2f53388b7a41d1f24d3622cf7e",
      "size": 18174721847,
      "modified_at": "2026-08-29T00:00:00Z",
      "details": {
        "parameter_size": "27.8B",
        "quantization_level": "nvfp4"
      }
    }
    """#.utf8)
    let model = try JSONDecoder().decode(OllamaModel.self, from: payload)

    #expect(model.digest == BuiltInProviderDescriptors.qwenLocalModelManifestDigest)
    try LocalModelCompatibilityPolicy.validateInstalledIdentity(
        selection: qualifiedQwen,
        installedModels: [model]
    )
}

@Test func ollamaCatalogueNormalizationPreservesQualifiedIdentityAmbiguity() {
    let exact = installedModel(
        name: qualifiedQwen.route.model.rawValue,
        digest: BuiltInProviderDescriptors.qwenLocalModelManifestDigest
    )
    let retagged = installedModel(
        name: qualifiedQwen.route.model.rawValue,
        digest: "sha256:" + String(repeating: "0", count: 64)
    )

    let normalized = OllamaClient.normalizedModels([exact, retagged])

    #expect(normalized.count == 2)
    #expect(throws: LocalModelAdmissionError.qualifiedModelIdentityMismatch) {
        try LocalModelCompatibilityPolicy.validateInstalledIdentity(
            selection: qualifiedQwen,
            installedModels: normalized
        )
    }
}

@Test func localModelsPresentationDistinguishesQualifiedCompatibilityAndIdentityMismatch() throws {
    let exact = installedModel(
        name: qualifiedQwen.route.model.rawValue,
        digest: BuiltInProviderDescriptors.qwenLocalModelManifestDigest
    )
    let compatibility = installedModel(name: "llama-tools:latest", digest: nil)
    let rows = ModelManagerWindowController.catalogueRows(
        models: [compatibility, exact],
        running: []
    )

    let exactRow = try #require(rows.first { $0.model.name == exact.name })
    #expect(exactRow.supportStatus == .releaseQualified)
    #expect(exactRow.supportStatus.label == "Release-qualified")
    #expect(exactRow.canSelectForNewTasks)

    let compatibilityRow = try #require(rows.first { $0.model.name == compatibility.name })
    #expect(compatibilityRow.supportStatus == .compatibility)
    #expect(compatibilityRow.supportStatus.label == "Compatibility candidate")
    #expect(compatibilityRow.supportStatus.help.contains("not release-qualified"))
    #expect(compatibilityRow.supportStatus.help.contains("again at startup"))
    #expect(compatibilityRow.canSelectForNewTasks)

    let mismatchRows = ModelManagerWindowController.catalogueRows(
        models: [installedModel(
            name: qualifiedQwen.route.model.rawValue,
            digest: "sha256:" + String(repeating: "0", count: 64)
        )],
        running: []
    )
    let mismatch = try #require(mismatchRows.first)
    #expect(mismatch.supportStatus == .officialTagIdentityMismatch)
    #expect(mismatch.supportStatus.label == "Identity mismatch")
    #expect(!mismatch.canSelectForNewTasks)
    #expect(mismatch.supportStatus.help.contains("immutable manifest"))
}

@Test func duplicateLocalModelTagsCollapseWithoutCrashOrSelectionAmbiguity() throws {
    let exact = installedModel(
        name: qualifiedQwen.route.model.rawValue,
        digest: BuiltInProviderDescriptors.qwenLocalModelManifestDigest
    )
    let retagged = installedModel(
        name: qualifiedQwen.route.model.rawValue,
        digest: "sha256:" + String(repeating: "f", count: 64)
    )
    let compatibility = installedModel(name: "llama-tools:latest", digest: nil)
    let runningDuplicate = OllamaRunningModel(
        name: compatibility.name,
        size: compatibility.size,
        sizeVRAM: 1_000,
        expiresAt: nil
    )
    let runningLargerDuplicate = OllamaRunningModel(
        name: compatibility.name,
        size: compatibility.size,
        sizeVRAM: 2_000,
        expiresAt: nil
    )
    let rows = ModelManagerWindowController.catalogueRows(
        models: [exact, retagged, compatibility, compatibility],
        running: [runningDuplicate, runningLargerDuplicate]
    )

    #expect(rows.count == 2)
    let officialTag = try #require(rows.first { $0.model.name == exact.name })
    #expect(officialTag.installedVariantCount == 2)
    #expect(officialTag.supportStatus == .officialTagIdentityMismatch)
    #expect(!officialTag.canSelectForNewTasks)

    let duplicateCompatibility = try #require(rows.first { $0.model.name == compatibility.name })
    #expect(duplicateCompatibility.installedVariantCount == 2)
    #expect(duplicateCompatibility.supportStatus == .duplicateCompatibilityTag)
    #expect(!duplicateCompatibility.canSelectForNewTasks)
    #expect(duplicateCompatibility.running?.sizeVRAM == 2_000)
}

@Test func compatibilityModelsDoNotMasqueradeAsDigestQualified() throws {
    try LocalModelCompatibilityPolicy.validateInstalledIdentity(
        selection: compatibleLocal,
        installedModels: [installedModel(name: compatibleLocal.route.model.rawValue, digest: nil)]
    )
}

@Test func qualifiedQwenHostAdmissionRequiresTheReleaseQualifiedMemoryClass() throws {
    try QualifiedLocalModelHostAdmissionPolicy.validate(
        selection: qualifiedQwen,
        physicalMemoryBytes: 48 * gibibyte
    )

    #expect(throws: QualifiedLocalModelHostAdmissionError.insufficientPhysicalMemory(
        requiredBytes: 48 * gibibyte,
        availableBytes: 47 * gibibyte
    )) {
        try QualifiedLocalModelHostAdmissionPolicy.validate(
            selection: qualifiedQwen,
            physicalMemoryBytes: 47 * gibibyte
        )
    }
}

@Test func compatibilityAndCloudRoutesDoNotInheritTheQualifiedQwenMemoryClaim() throws {
    try QualifiedLocalModelHostAdmissionPolicy.validate(
        selection: compatibleLocal,
        physicalMemoryBytes: 16 * gibibyte
    )
    try QualifiedLocalModelHostAdmissionPolicy.validate(
        selection: ModelSelection(
            route: ModelRoute(provider: ProviderID("deepseek"), model: ModelID("deepseek-chat"))
        ),
        physicalMemoryBytes: 8 * gibibyte
    )
}

@Test func compatibilityModelRequiresConservativeWeightAndRuntimeHeadroom() throws {
    let modelName = compatibleLocal.route.model.rawValue
    let fiveGiB = Int64(5) * Int64(gibibyte)
    let sevenGiB = Int64(7) * Int64(gibibyte)

    try LocalModelCompatibilityPolicy.validateHostMemory(
        selection: compatibleLocal,
        installedModels: [installedModel(name: modelName, digest: nil, size: fiveGiB)],
        physicalMemoryBytes: 16 * gibibyte
    )

    #expect(throws: LocalModelAdmissionError.insufficientPhysicalMemory(
        requiredBytes: 18 * gibibyte,
        availableBytes: 16 * gibibyte
    )) {
        try LocalModelCompatibilityPolicy.validateHostMemory(
            selection: compatibleLocal,
            installedModels: [installedModel(name: modelName, digest: nil, size: sevenGiB)],
            physicalMemoryBytes: 16 * gibibyte
        )
    }
}

@Test func compatibilityMemoryAdmissionCoversDocumentedEightThroughSixtyFourPlusGiBTiers() throws {
    let modelName = compatibleLocal.route.model.rawValue
    let reserve = UInt64(4) * gibibyte
    for hostGiB in [8, 16, 24, 32, 48, 64, 96] {
        let hostBytes = UInt64(hostGiB) * gibibyte
        let maximumAdmittedModelBytes = (hostBytes - reserve) / 2
        try LocalModelCompatibilityPolicy.validateHostMemory(
            selection: compatibleLocal,
            installedModels: [installedModel(
                name: modelName,
                digest: nil,
                size: Int64(maximumAdmittedModelBytes)
            )],
            physicalMemoryBytes: hostBytes
        )

        let rejectedModelBytes = maximumAdmittedModelBytes + 1
        #expect(throws: LocalModelAdmissionError.insufficientPhysicalMemory(
            requiredBytes: rejectedModelBytes * 2 + reserve,
            availableBytes: hostBytes
        )) {
            try LocalModelCompatibilityPolicy.validateHostMemory(
                selection: compatibleLocal,
                installedModels: [installedModel(
                    name: modelName,
                    digest: nil,
                    size: Int64(rejectedModelBytes)
                )],
                physicalMemoryBytes: hostBytes
            )
        }
    }
}

@Test func qualifiedQwenAndCloudRoutesCoverDocumentedHardwareTiersWithoutPolicyLeakage() throws {
    for hostGiB in [8, 16, 24, 32] {
        let hostBytes = UInt64(hostGiB) * gibibyte
        #expect(throws: QualifiedLocalModelHostAdmissionError.insufficientPhysicalMemory(
            requiredBytes: 48 * gibibyte,
            availableBytes: hostBytes
        )) {
            try LocalModelCompatibilityPolicy.validateHostMemory(
                selection: qualifiedQwen,
                installedModels: [],
                physicalMemoryBytes: hostBytes
            )
        }
    }

    for hostGiB in [48, 64, 96] {
        try LocalModelCompatibilityPolicy.validateHostMemory(
            selection: qualifiedQwen,
            installedModels: [],
            physicalMemoryBytes: UInt64(hostGiB) * gibibyte
        )
    }

    for provider in [
        BuiltInProviderDescriptors.deepSeekOfficial.id,
        BuiltInProviderDescriptors.openAI.id,
        BuiltInProviderDescriptors.anthropic.id,
        ProviderID("custom-openai-compatible")
    ] {
        for hostGiB in [8, 16, 24, 32, 48, 64, 96] {
            try LocalModelCompatibilityPolicy.validateHostMemory(
                selection: ModelSelection(
                    route: ModelRoute(provider: provider, model: ModelID("fixture-model"))
                ),
                installedModels: [],
                physicalMemoryBytes: UInt64(hostGiB) * gibibyte
            )
        }
    }
}

@Test func compatibilityMemoryAdmissionRejectsMissingInvalidAndAmbiguousSizes() {
    let modelName = compatibleLocal.route.model.rawValue
    for installed in [
        [OllamaModel](),
        [installedModel(name: modelName, digest: nil, size: 0)],
        [installedModel(name: modelName, digest: nil, size: -1)],
        [
            installedModel(name: modelName, digest: nil, size: Int64(gibibyte)),
            installedModel(name: modelName, digest: nil, size: Int64(gibibyte))
        ]
    ] {
        #expect(throws: LocalModelAdmissionError.modelSizeUnavailable) {
            try LocalModelCompatibilityPolicy.validateHostMemory(
                selection: compatibleLocal,
                installedModels: installed,
                physicalMemoryBytes: 48 * gibibyte
            )
        }
    }
}

@Test func cloudRoutesNeverInheritLocalWeightAdmission() throws {
    try LocalModelCompatibilityPolicy.validateHostMemory(
        selection: ModelSelection(
            route: ModelRoute(provider: ProviderID("deepseek"), model: ModelID("deepseek-chat"))
        ),
        installedModels: [],
        physicalMemoryBytes: gibibyte
    )
}

@Test func unknownLocalSelectionIsAlwaysNormalizedToFixedCompatibilityLimits() {
    #expect(compatibleLocal.performanceProfile == .compatibility)
    #expect(compatibleLocal.reasoningEffort == nil)
    #expect(compatibleLocal.effectivePerformanceSettings == .compatibilityLocalModel)
}

@Test func qualifiedQwenRequiresThinkingToolsAndEnoughContext() throws {
    #expect(try LocalModelCompatibilityPolicy.validate(
        selection: qualifiedQwen,
        assessment: .incompatible(.thinkingRequiresExplicitSupport(contextLength: 262_144))
    ) == 262_144)

    #expect(throws: LocalModelAdmissionError.qualifiedModelMetadataMismatch) {
        try LocalModelCompatibilityPolicy.validate(
            selection: qualifiedQwen,
            assessment: .compatible(contextLength: 262_144, supportsThinking: false)
        )
    }

    #expect(throws: LocalModelAdmissionError.selectedContextUnavailable(actual: 32_768, required: 49_152)) {
        try LocalModelCompatibilityPolicy.validate(
            selection: qualifiedQwen,
            assessment: .incompatible(.thinkingRequiresExplicitSupport(contextLength: 32_768))
        )
    }
}

@Test func compatibilityModeAcceptsOnlyNonThinkingToolModelsWithinBounds() throws {
    #expect(try LocalModelCompatibilityPolicy.validate(
        selection: compatibleLocal,
        assessment: .compatible(contextLength: 32_768, supportsThinking: false)
    ) == 32_768)
    #expect(throws: LocalModelAdmissionError.toolsUnavailable) {
        try LocalModelCompatibilityPolicy.validate(
            selection: compatibleLocal,
            assessment: .incompatible(.toolsUnavailable)
        )
    }
    #expect(throws: LocalModelAdmissionError.thinkingModelNotQualified) {
        try LocalModelCompatibilityPolicy.validate(
            selection: compatibleLocal,
            assessment: .incompatible(.thinkingRequiresExplicitSupport(contextLength: 32_768))
        )
    }
}
