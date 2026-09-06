import AppKit
import Testing
@testable import LocalHarness

private let commandFixture = CommandCenterCommand(
    title: "Models & Providers",
    detail: "Choose local Qwen, DeepSeek or another API",
    symbolName: "memorychip",
    keywords: ["cloud", "ollama", "private"],
    action: #selector(NSApplication.arrangeInFront(_:))
)

@Test func commandCenterSearchMatchesAllTermsAcrossVisibleAndKeywordText() {
    #expect(commandFixture.matches("models"))
    #expect(commandFixture.matches("qwen private"))
    #expect(commandFixture.matches("DEEPSEEK CLOUD"))
    #expect(!commandFixture.matches("history"))
    #expect(!commandFixture.matches("qwen history"))
}

@Test func commandCenterEmptyOrWhitespaceSearchShowsEverything() {
    #expect(commandFixture.matches(""))
    #expect(commandFixture.matches("   "))
}
