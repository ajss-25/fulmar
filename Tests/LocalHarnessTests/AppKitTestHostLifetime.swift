import AppKit
import Testing

@MainActor
private enum AppKitTestHostLifetime {
    static var applicationInitializationCount = 0

    static let application: NSApplication = {
        applicationInitializationCount += 1
        return NSApplication.shared
    }()

    static var snapshot: (
        initializationCount: Int,
        applicationIdentity: ObjectIdentifier,
        delegateIdentity: ObjectIdentifier?
    ) {
        let application = application
        return (
            applicationInitializationCount,
            ObjectIdentifier(application),
            application.delegate.map { ObjectIdentifier($0) }
        )
    }
}

@MainActor
func ensureAppKitTestHostSurvivesAutomaticTermination() {
    withExtendedLifetime(AppKitTestHostLifetime.application) {}
}

private struct SwiftSourceBrace {
    enum Direction {
        case opening
        case closing
    }

    let line: Int
    let column: Int
    let direction: Direction
}

private struct SwiftSourceStringDelimiter: Equatable {
    let hashCount: Int
    let isMultiline: Bool
}

private func sourceCharacters(
    _ source: [Character],
    at index: Int,
    match pattern: [Character]
) -> Bool {
    guard index >= 0, index + pattern.count <= source.count else { return false }
    return source[index..<(index + pattern.count)].elementsEqual(pattern)
}

/// Finds structural braces while ignoring comments and normal, raw, multiline,
/// and interpolated Swift strings. Test/suite ownership must follow lexical
/// scopes; indentation alone previously missed actor isolation inherited from a
/// suite and can silently associate an attribute with the wrong declaration.
private func structuralSwiftBraces(in source: String) -> (
    braces: [SwiftSourceBrace],
    isLexicallyComplete: Bool
) {
    let characters = Array(source)
    let lineCommentStart = Array("//")
    let blockCommentStart = Array("/*")
    let blockCommentEnd = Array("*/")
    var braces: [SwiftSourceBrace] = []
    var index = 0
    var line = 0
    var column = 0
    var blockCommentDepth = 0
    var stringDelimiter: SwiftSourceStringDelimiter?
    var interpolationStack: [(delimiter: SwiftSourceStringDelimiter, depth: Int)] = []

    func quoteDelimiterMatches(
        _ delimiter: SwiftSourceStringDelimiter,
        at candidate: Int
    ) -> Bool {
        let quoteCount = delimiter.isMultiline ? 3 : 1
        guard candidate + quoteCount + delimiter.hashCount <= characters.count else {
            return false
        }
        guard characters[candidate..<(candidate + quoteCount)].allSatisfy({ $0 == "\"" }) else {
            return false
        }
        return characters[(candidate + quoteCount)..<(candidate + quoteCount + delimiter.hashCount)]
            .allSatisfy { $0 == "#" }
    }

    func advance(_ count: Int) {
        for _ in 0..<count where index < characters.count {
            if characters[index] == "\n" {
                line += 1
                column = 0
            } else {
                column += 1
            }
            index += 1
        }
    }

    while index < characters.count {
        if blockCommentDepth > 0 {
            if sourceCharacters(characters, at: index, match: blockCommentStart) {
                blockCommentDepth += 1
                advance(2)
            } else if sourceCharacters(characters, at: index, match: blockCommentEnd) {
                blockCommentDepth -= 1
                advance(2)
            } else {
                advance(1)
            }
            continue
        }

        if let delimiter = stringDelimiter {
            if quoteDelimiterMatches(delimiter, at: index) {
                advance((delimiter.isMultiline ? 3 : 1) + delimiter.hashCount)
                stringDelimiter = nil
                continue
            }
            if characters[index] == "\\" {
                var interpolationIndex = index + 1
                var matchedHashes = 0
                while matchedHashes < delimiter.hashCount,
                      interpolationIndex < characters.count,
                      characters[interpolationIndex] == "#" {
                    interpolationIndex += 1
                    matchedHashes += 1
                }
                if matchedHashes == delimiter.hashCount,
                   interpolationIndex < characters.count,
                   characters[interpolationIndex] == "(" {
                    advance(interpolationIndex - index + 1)
                    interpolationStack.append((delimiter, 1))
                    stringDelimiter = nil
                    continue
                }
                if delimiter.hashCount == 0, index + 1 < characters.count {
                    advance(2)
                    continue
                }
            }
            advance(1)
            continue
        }

        if sourceCharacters(characters, at: index, match: lineCommentStart) {
            while index < characters.count, characters[index] != "\n" {
                advance(1)
            }
            continue
        }
        if sourceCharacters(characters, at: index, match: blockCommentStart) {
            blockCommentDepth = 1
            advance(2)
            continue
        }

        var hashCount = 0
        var quoteIndex = index
        while quoteIndex < characters.count, characters[quoteIndex] == "#" {
            hashCount += 1
            quoteIndex += 1
        }
        if quoteIndex < characters.count, characters[quoteIndex] == "\"" {
            let isMultiline = quoteIndex + 2 < characters.count
                && characters[quoteIndex + 1] == "\""
                && characters[quoteIndex + 2] == "\""
            stringDelimiter = SwiftSourceStringDelimiter(
                hashCount: hashCount,
                isMultiline: isMultiline
            )
            advance(hashCount + (isMultiline ? 3 : 1))
            continue
        }

        if !interpolationStack.isEmpty, characters[index] == "(" {
            interpolationStack[interpolationStack.count - 1].depth += 1
            advance(1)
            continue
        }
        if !interpolationStack.isEmpty, characters[index] == ")" {
            interpolationStack[interpolationStack.count - 1].depth -= 1
            let completed = interpolationStack[interpolationStack.count - 1].depth == 0
            let delimiter = interpolationStack[interpolationStack.count - 1].delimiter
            advance(1)
            if completed {
                interpolationStack.removeLast()
                stringDelimiter = delimiter
            }
            continue
        }

        if characters[index] == "{" {
            braces.append(SwiftSourceBrace(line: line, column: column, direction: .opening))
        } else if characters[index] == "}" {
            braces.append(SwiftSourceBrace(line: line, column: column, direction: .closing))
        }
        advance(1)
    }

    return (
        braces,
        blockCommentDepth == 0 && stringDelimiter == nil && interpolationStack.isEmpty
    )
}

private func matchingClosingBrace(
    for openingIndex: Int,
    in braces: [SwiftSourceBrace]
) -> Int? {
    guard braces.indices.contains(openingIndex), braces[openingIndex].direction == .opening else {
        return nil
    }
    var depth = 0
    for index in openingIndex..<braces.count {
        switch braces[index].direction {
        case .opening:
            depth += 1
        case .closing:
            depth -= 1
            if depth == 0 { return index }
        }
    }
    return nil
}

private func attachedAttributeStart(in lines: [String], before index: Int) -> Int {
    var start = index
    while start > 0 {
        let previous = lines[start - 1].trimmingCharacters(in: .whitespaces)
        guard previous.hasPrefix("@") else { break }
        start -= 1
    }
    return start
}

private func firstExecutableLine(in body: [String]) -> Int? {
    var blockCommentDepth = 0
    for (lineIndex, line) in body.enumerated() {
        let characters = Array(line)
        var index = 0
        while index < characters.count {
            while index < characters.count, characters[index].isWhitespace { index += 1 }
            guard index < characters.count else { break }

            if blockCommentDepth > 0 {
                if index + 1 < characters.count,
                   characters[index] == "/", characters[index + 1] == "*" {
                    blockCommentDepth += 1
                    index += 2
                } else if index + 1 < characters.count,
                          characters[index] == "*", characters[index + 1] == "/" {
                    blockCommentDepth -= 1
                    index += 2
                } else {
                    index += 1
                }
                continue
            }
            if index + 1 < characters.count,
               characters[index] == "/", characters[index + 1] == "/" {
                break
            }
            if index + 1 < characters.count,
               characters[index] == "/", characters[index + 1] == "*" {
                blockCommentDepth = 1
                index += 2
                continue
            }
            let executable = String(characters[index...])
            if executable.hasPrefix("@") { break }
            return lineIndex
        }
    }
    return nil
}

@MainActor
@Test func appKitRuntimeTestBodiesAcquireTheHoldBeforeDirectConstruction() throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let testDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    let sourceFiles = try FileManager.default.contentsOfDirectory(
        at: testDirectory,
        includingPropertiesForKeys: nil
    ).filter { $0.pathExtension == "swift" }
    let runtimePatternSources = [
        #"\b(?:NSApplication|NSWorkspace)\.shared\b|\bNSApp\b"#,
        #"\bNS(?:Menu|MenuItem|OpenPanel|SavePanel|Panel|Alert|Popover|StatusBar)\b"#,
        #"\b(?:NS|[A-Z][A-Za-z0-9]*)(?:View|Button|Control|Cell|TextField|TextView|TableView|OutlineView|ScrollView|StackView|ProgressIndicator|PopUpButton|SearchField|SegmentedControl|CollectionView|ImageView|VisualEffectView|Toolbar|ToolbarItem|Window|WindowController|Panel)\s*\("#,
        #"\b(?i:(?:[A-Za-z][A-Za-z0-9]*webView|webView|surface))\.(?:load|callAsyncJavaScript|evaluateJavaScript)\s*\("#,
        #"\.window\b|\.(?:showWindow|orderOut|orderFront\w*|makeKey\w*|performClose|close|performClick|click|sendAction|action)\s*\("#,
    ]
    let runtimePatterns = try runtimePatternSources.map {
        try NSRegularExpression(pattern: $0)
    }
    var testBodyCount = 0
    var directMainActorBodyCount = 0
    var inheritedMainActorBodyCount = 0
    var mainActorSuiteCount = 0
    var appKitImportedActorBodyCount = 0
    var runtimeMarkerBodyCount = 0
    var runtimeMarkerWithoutDirectMainActorCount = 0

    for sourceFile in sourceFiles {
        let source = try String(contentsOf: sourceFile, encoding: .utf8)
        let nestedMainRunLoop = "RunLoop" + ".current.run("
        #expect(
            !source.contains(nestedMainRunLoop),
            Comment(rawValue: "Nested main RunLoop execution is forbidden in Swift Testing: \(sourceFile.lastPathComponent)")
        )
        let lines = source.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        let structural = structuralSwiftBraces(in: source)
        #expect(
            structural.isLexicallyComplete,
            Comment(rawValue: "Lexically incomplete source: \(sourceFile.lastPathComponent)")
        )
        let importsAppKitRuntime = lines.contains("import AppKit") || lines.contains("import WebKit")

        var mainActorSuiteRanges: [ClosedRange<Int>] = []
        for suiteIndex in lines.indices where lines[suiteIndex]
            .trimmingCharacters(in: .whitespaces).hasPrefix("@Suite") {
            guard let declarationIndex = lines.indices.first(where: {
                $0 >= suiteIndex && $0 <= min(suiteIndex + 12, lines.index(before: lines.endIndex))
                    && lines[$0].range(of: #"\bstruct\s+[A-Za-z_]"#, options: .regularExpression) != nil
            }) else {
                Issue.record("Could not associate @Suite in \(sourceFile.lastPathComponent):\(suiteIndex + 1)")
                continue
            }
            let headerStart = attachedAttributeStart(in: lines, before: suiteIndex)
            let header = lines[headerStart...declarationIndex].joined(separator: "\n")
            guard header.contains("@MainActor") else { continue }
            guard let openingIndex = structural.braces.firstIndex(where: {
                $0.direction == .opening
                    && $0.line >= declarationIndex
                    && $0.line <= declarationIndex + 4
            }), let closingIndex = matchingClosingBrace(
                for: openingIndex,
                in: structural.braces
            ) else {
                Issue.record("Could not parse actor suite in \(sourceFile.lastPathComponent):\(declarationIndex + 1)")
                continue
            }
            mainActorSuiteCount += 1
            mainActorSuiteRanges.append(
                structural.braces[openingIndex].line...structural.braces[closingIndex].line
            )
        }

        var parsedDeclarations = Set<Int>()
        for testIndex in lines.indices where lines[testIndex]
            .trimmingCharacters(in: .whitespaces).hasPrefix("@Test") {
            guard let declarationIndex = lines.indices.first(where: {
                $0 >= testIndex && $0 <= min(testIndex + 12, lines.index(before: lines.endIndex))
                    && lines[$0].range(of: #"\bfunc\s+[A-Za-z_]"#, options: .regularExpression) != nil
            }) else {
                Issue.record("Could not associate @Test in \(sourceFile.lastPathComponent):\(testIndex + 1)")
                continue
            }
            #expect(
                parsedDeclarations.insert(declarationIndex).inserted,
                Comment(rawValue: "Duplicate @Test association in \(sourceFile.lastPathComponent):\(declarationIndex + 1)")
            )

            let headerStart = attachedAttributeStart(in: lines, before: testIndex)
            let declarationHeader = lines[headerStart...declarationIndex].joined(separator: "\n")
            let hasDirectMainActor = declarationHeader.contains("@MainActor")
            let inheritsMainActor = !hasDirectMainActor && mainActorSuiteRanges.contains {
                $0.contains(declarationIndex)
            }

            guard let openingIndex = structural.braces.firstIndex(where: {
                $0.direction == .opening
                    && $0.line >= declarationIndex
                    && $0.line <= declarationIndex + 8
            }), let closingIndex = matchingClosingBrace(
                for: openingIndex,
                in: structural.braces
            ) else {
                Issue.record("Could not parse test body in \(sourceFile.lastPathComponent):\(declarationIndex + 1)")
                continue
            }
            let opening = structural.braces[openingIndex]
            let closing = structural.braces[closingIndex]
            guard opening.line < closing.line else {
                Issue.record("One-line test bodies are not silently accepted in \(sourceFile.lastPathComponent):\(declarationIndex + 1)")
                continue
            }
            let openingSuffix = String(Array(lines[opening.line]).dropFirst(opening.column + 1))
                .trimmingCharacters(in: .whitespaces)
            guard openingSuffix.isEmpty || openingSuffix.hasPrefix("//") else {
                Issue.record("Unparsed code after test opening brace in \(sourceFile.lastPathComponent):\(declarationIndex + 1)")
                continue
            }
            let body = Array(lines[(opening.line + 1)..<closing.line])
            let firstExecutable = firstExecutableLine(in: body)
            testBodyCount += 1
            if hasDirectMainActor {
                directMainActorBodyCount += 1
            } else if inheritsMainActor {
                inheritedMainActorBodyCount += 1
            }

            guard hasDirectMainActor || inheritsMainActor else { continue }
            let firstRuntimeMarker = body.firstIndex { line in
                let range = NSRange(line.startIndex..<line.endIndex, in: line)
                return runtimePatterns.contains {
                    $0.firstMatch(in: line, range: range) != nil
                }
            }
            if firstRuntimeMarker != nil {
                runtimeMarkerBodyCount += 1
                if !hasDirectMainActor {
                    runtimeMarkerWithoutDirectMainActorCount += 1
                }
            }

            if importsAppKitRuntime {
                appKitImportedActorBodyCount += 1
                guard let firstExecutable else {
                    Issue.record("Empty AppKit test body in \(sourceFile.lastPathComponent):\(declarationIndex + 1)")
                    continue
                }
                #expect(
                    body[firstExecutable].contains("ensureAppKitTestHostSurvivesAutomaticTermination()"),
                    Comment(rawValue: "AppKit hold is not first in \(sourceFile.lastPathComponent):\(declarationIndex + 1)")
                )
                continue
            }

            guard let firstRuntimeMarker else { continue }
            guard let helperIndex = body.firstIndex(where: {
                $0.contains("ensureAppKitTestHostSurvivesAutomaticTermination()")
            }) else {
                Issue.record("Missing AppKit lifetime hold in \(sourceFile.lastPathComponent):\(declarationIndex + 1)")
                continue
            }
            #expect(
                helperIndex < firstRuntimeMarker,
                Comment(rawValue: "Late AppKit hold in \(sourceFile.lastPathComponent):\(declarationIndex + 1)")
            )
        }
    }

    // These reviewed counts, actor-suite scopes, import rule, and marker vocabulary
    // must be updated consciously whenever test topology or AppKit usage changes.
    #expect(testBodyCount == 1_445)
    #expect(directMainActorBodyCount == 321)
    #expect(mainActorSuiteCount == 4)
    #expect(inheritedMainActorBodyCount == 39)
    #expect(appKitImportedActorBodyCount == 225)
    // Artifact previews now use an injected off-screen NSView factory in tests
    // instead of constructing the live Quick Look surface. The reviewed static
    // runtime-marker topology is therefore one body smaller than the original
    // live-preview inventory; every remaining AppKit-importing actor test is
    // still required to acquire the hold as its first executable statement.
    #expect(runtimeMarkerBodyCount == 175)
    #expect(runtimeMarkerWithoutDirectMainActorCount == 5)
}

@MainActor
private func appKitTestHostLifetimeSnapshot() -> (
    initializationCount: Int,
    applicationIdentity: ObjectIdentifier,
    delegateIdentity: ObjectIdentifier?
) {
    AppKitTestHostLifetime.snapshot
}

@MainActor
@Test func appKitTestHostSurvivesRepeatedLastWindowTransitions() async throws {
    ensureAppKitTestHostSurvivesAutomaticTermination()
    let initial = appKitTestHostLifetimeSnapshot()
    #expect(initial.initializationCount == 1)
    var completedTransitions = 0

    for offset in [CGFloat(40), 100, 160] {
        let window = NSWindow(
            contentRect: NSRect(x: offset, y: offset, width: 40, height: 40),
            styleMask: [.titled],
            backing: .buffered,
            defer: false
        )
        window.isReleasedWhenClosed = false
        window.orderFrontRegardless()
        #expect(window.isVisible)
        #expect(NSApplication.shared.windows.contains { $0 === window })
        window.close()
        completedTransitions += 1
        await Task.yield()
        #expect(!window.isVisible)
        let afterTransition = appKitTestHostLifetimeSnapshot()
        #expect(afterTransition.initializationCount == 1)
        #expect(afterTransition.applicationIdentity == initial.applicationIdentity)
        #expect(afterTransition.delegateIdentity == initial.delegateIdentity)
        #expect(completedTransitions > 0)
    }

    try await Task.sleep(for: .seconds(8))
    let afterNaturalTerminationWindow = appKitTestHostLifetimeSnapshot()
    #expect(afterNaturalTerminationWindow.initializationCount == 1)
    #expect(afterNaturalTerminationWindow.applicationIdentity == initial.applicationIdentity)
    #expect(afterNaturalTerminationWindow.delegateIdentity == initial.delegateIdentity)
    #expect(completedTransitions == 3)
}
