import Foundation

enum LocalModelAdmissionError: Error, Equatable, LocalizedError {
    case qualifiedModelMetadataMismatch
    case qualifiedModelIdentityMismatch
    case selectedContextUnavailable(actual: Int, required: Int)
    case toolsUnavailable
    case thinkingModelNotQualified
    case fixedCompatibilityProfile
    case variableProfilesRequireQualifiedLocalModel
    case contextTooSmall(actual: Int, minimum: Int)
    case metadataOutOfBounds
    case modelSizeUnavailable
    case insufficientPhysicalMemory(requiredBytes: UInt64, availableBytes: UInt64)

    var errorDescription: String? {
        switch self {
        case .qualifiedModelMetadataMismatch:
            return "The installed Qwen model no longer reports the thinking and tool capabilities required by Fulmar's qualified profile. Reinstall the expected model or choose another provider."
        case .qualifiedModelIdentityMismatch:
            return "The selected Qwen tag does not match Fulmar's release-qualified immutable model digest. Remove the mismatched tag and pull the documented official model again, choose a differently tagged compatible local model, or use an API provider."
        case .selectedContextUnavailable(let actual, let required):
            return "The installed model reports a \(actual)-token context, below the selected \(required)-token Fulmar profile. Choose a smaller performance profile."
        case .toolsUnavailable:
            return "This installed model does not advertise tool use, so it cannot run DeepSeek Harness agent tasks."
        case .thinkingModelNotQualified:
            return "This thinking-capable model is not yet qualified for Fulmar compatibility mode. Its reasoning controls differ by model, so Fulmar will not guess."
        case .fixedCompatibilityProfile:
            return "This local model uses Fulmar's fixed 8K context and 2K output compatibility profile. Choose the qualified Qwen model to use Fast, Balanced, or Deep settings."
        case .variableProfilesRequireQualifiedLocalModel:
            return "Fast, Balanced, and Deep are available only for Fulmar's release-qualified local Qwen model on an admitted Mac. Cloud providers and alternate Ollama models keep their own independent limits."
        case .contextTooSmall(let actual, let minimum):
            return "This installed model reports a \(actual)-token context. Fulmar compatibility mode requires at least \(minimum) tokens."
        case .metadataOutOfBounds:
            return "Ollama reported model limits outside Fulmar's reviewed compatibility bounds."
        case .modelSizeUnavailable:
            return "Ollama did not report one valid installed size for the selected model. Fulmar cannot verify that it fits safely on this Mac."
        case .insufficientPhysicalMemory(let requiredBytes, let availableBytes):
            let gibibyte = UInt64(1_073_741_824)
            let required = (requiredBytes + gibibyte - 1) / gibibyte
            let available = availableBytes / gibibyte
            return "This local model needs a conservative minimum of \(required) GB of physical memory for its weights, runtime overhead, and macOS. This Mac reports \(available) GB. Choose a smaller local model or use an API provider."
        }
    }
}

/// Converts Ollama's bounded `/api/show` assessment into the exact admission
/// contract used by every local-model startup. A model name alone never grants
/// Qwen reasoning metadata or the 27B performance presets.
enum LocalModelCompatibilityPolicy {
    static func validateInstalledIdentity(
        selection: ModelSelection,
        installedModels: [OllamaModel]
    ) throws {
        guard selection.isReleaseQualifiedLocalQwen else { return }
        let matches = installedModels.filter { $0.name == selection.route.model.rawValue }
        guard matches.count == 1,
              matches[0].digest == BuiltInProviderDescriptors.qwenLocalModelManifestDigest else {
            throw LocalModelAdmissionError.qualifiedModelIdentityMismatch
        }
    }

    /// Compatibility mode cannot promise a model-specific memory footprint,
    /// but it can refuse configurations that are clearly unsafe. Requiring
    /// twice the installed model bytes plus a 4 GiB system/runtime reserve is
    /// deliberately conservative for the fixed 8K/2K compatibility profile.
    /// It is an admission floor, not a claim that every admitted model will
    /// have identical peak memory use.
    static func validateHostMemory(
        selection: ModelSelection,
        installedModels: [OllamaModel],
        physicalMemoryBytes: UInt64
    ) throws {
        guard selection.route.provider == BuiltInProviderDescriptors.ollama.id else { return }
        if selection.isReleaseQualifiedLocalQwen {
            try QualifiedLocalModelHostAdmissionPolicy.validate(
                selection: selection,
                physicalMemoryBytes: physicalMemoryBytes
            )
            return
        }

        let matches = installedModels.filter { $0.name == selection.route.model.rawValue }
        guard matches.count == 1, matches[0].size > 0 else {
            throw LocalModelAdmissionError.modelSizeUnavailable
        }
        let modelBytes = UInt64(matches[0].size)
        let reserve = UInt64(4) * 1_073_741_824
        guard modelBytes <= (UInt64.max - reserve) / 2 else {
            throw LocalModelAdmissionError.modelSizeUnavailable
        }
        let required = modelBytes * 2 + reserve
        guard physicalMemoryBytes >= required else {
            throw LocalModelAdmissionError.insufficientPhysicalMemory(
                requiredBytes: required,
                availableBytes: physicalMemoryBytes
            )
        }
    }

    @discardableResult
    static func validate(
        selection: ModelSelection,
        assessment: OllamaModelCompatibility
    ) throws -> Int {
        precondition(selection.route.provider == BuiltInProviderDescriptors.ollama.id)

        if selection.isReleaseQualifiedLocalQwen {
            guard case .incompatible(.thinkingRequiresExplicitSupport(let contextLength)) = assessment else {
                throw LocalModelAdmissionError.qualifiedModelMetadataMismatch
            }
            let required = selection.effectivePerformanceSettings.contextWindowTokens
            guard contextLength >= required else {
                throw LocalModelAdmissionError.selectedContextUnavailable(actual: contextLength, required: required)
            }
            return contextLength
        }

        switch assessment {
        case .compatible(let contextLength, supportsThinking: false):
            return contextLength
        case .compatible:
            throw LocalModelAdmissionError.thinkingModelNotQualified
        case .incompatible(.toolsUnavailable):
            throw LocalModelAdmissionError.toolsUnavailable
        case .incompatible(.thinkingRequiresExplicitSupport):
            throw LocalModelAdmissionError.thinkingModelNotQualified
        case .incompatible(.contextTooSmall(let actual, let minimum)):
            throw LocalModelAdmissionError.contextTooSmall(actual: actual, minimum: minimum)
        case .incompatible(.contextTooLarge):
            throw LocalModelAdmissionError.metadataOutOfBounds
        }
    }
}
