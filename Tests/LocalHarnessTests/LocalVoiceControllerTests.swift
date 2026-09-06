import AVFoundation
import Speech
import Testing
@testable import LocalHarness

private final class FailingVoiceCapture: VoiceAudioCapturing {
    enum Failure: Error { case start }

    var isRunning = false
    private(set) var installCount = 0
    private(set) var removeCount = 0
    private(set) var stopCount = 0

    func outputFormat() -> AVAudioFormat {
        AVAudioFormat(standardFormatWithSampleRate: 44_100, channels: 1)!
    }
    func installTap(_ handler: @escaping (AVAudioPCMBuffer, AVAudioTime) -> Void) {
        installCount += 1
    }
    func prepare() {}
    func start() throws { throw Failure.start }
    func stop() { stopCount += 1; isRunning = false }
    func removeTap() { removeCount += 1 }
}

@Test func failedVoiceEngineStartRemovesItsInstalledTapAndAllowsRetry() {
    let capture = FailingVoiceCapture()
    let session = VoiceAudioCaptureSession(capture: capture)

    for _ in 0..<2 {
        let request = SFSpeechAudioBufferRecognitionRequest()
        #expect(throws: FailingVoiceCapture.Failure.self) {
            try session.start(appendingTo: request)
        }
        #expect(session.tapInstalled == false)
    }

    #expect(capture.installCount == 2)
    #expect(capture.removeCount == 2)
    #expect(capture.stopCount == 0)
}
