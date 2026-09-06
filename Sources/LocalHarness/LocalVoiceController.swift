import AVFoundation
import Foundation
import Speech

protocol VoiceAudioCapturing: AnyObject {
    var isRunning: Bool { get }
    func outputFormat() -> AVAudioFormat
    func installTap(_ handler: @escaping (AVAudioPCMBuffer, AVAudioTime) -> Void)
    func prepare()
    func start() throws
    func stop()
    func removeTap()
}

final class SystemVoiceAudioCapture: VoiceAudioCapturing {
    private let engine = AVAudioEngine()

    var isRunning: Bool { engine.isRunning }
    func outputFormat() -> AVAudioFormat { engine.inputNode.outputFormat(forBus: 0) }
    func installTap(_ handler: @escaping (AVAudioPCMBuffer, AVAudioTime) -> Void) {
        let format = outputFormat()
        engine.inputNode.installTap(onBus: 0, bufferSize: 1024, format: format, block: handler)
    }
    func prepare() { engine.prepare() }
    func start() throws { try engine.start() }
    func stop() { engine.stop() }
    func removeTap() { engine.inputNode.removeTap(onBus: 0) }
}

/// Owns the tap independently from the higher-level listening flag. This is
/// important because `AVAudioEngine.start()` may throw after the tap has been
/// installed; cleanup must still remove it before a user retries dictation.
final class VoiceAudioCaptureSession {
    private let capture: VoiceAudioCapturing
    private(set) var tapInstalled = false

    init(capture: VoiceAudioCapturing) {
        self.capture = capture
    }

    func start(appendingTo request: SFSpeechAudioBufferRecognitionRequest) throws {
        let format = capture.outputFormat()
        guard format.sampleRate > 0 else { throw LocalVoiceController.VoiceError.audioUnavailable }
        capture.installTap { buffer, _ in request.append(buffer) }
        tapInstalled = true
        capture.prepare()
        do {
            try capture.start()
        } catch {
            stop(request: request)
            throw error
        }
    }

    func stop(request: SFSpeechAudioBufferRecognitionRequest?) {
        if capture.isRunning { capture.stop() }
        if tapInstalled {
            capture.removeTap()
            tapInstalled = false
        }
        request?.endAudio()
    }
}

final class LocalVoiceController: NSObject {
    enum VoiceError: LocalizedError {
        case permissionsDenied
        case onDeviceUnavailable
        case audioUnavailable
        var errorDescription: String? {
            switch self {
            case .permissionsDenied: return "Microphone and Speech Recognition permission are required for dictation."
            case .onDeviceUnavailable: return "On-device speech recognition is not available for the current language."
            case .audioUnavailable: return "The microphone input could not be started."
            }
        }
    }

    private let captureSession: VoiceAudioCaptureSession
    private let synthesizer = AVSpeechSynthesizer()
    private var request: SFSpeechAudioBufferRecognitionRequest?
    private var task: SFSpeechRecognitionTask?
    private var recognizer: SFSpeechRecognizer?
    private(set) var isListening = false

    override convenience init() {
        self.init(captureSession: VoiceAudioCaptureSession(capture: SystemVoiceAudioCapture()))
    }

    init(captureSession: VoiceAudioCaptureSession) {
        self.captureSession = captureSession
        super.init()
    }

    func start(onText: @escaping (String) -> Void, completion: @escaping (Result<Void, Error>) -> Void) {
        SFSpeechRecognizer.requestAuthorization { [weak self] speechStatus in
            AVCaptureDevice.requestAccess(for: .audio) { microphoneAllowed in
                DispatchQueue.main.async {
                    guard let self else { return }
                    guard speechStatus == .authorized, microphoneAllowed else { completion(.failure(VoiceError.permissionsDenied)); return }
                    do { try self.beginRecognition(onText: onText, completion: completion) }
                    catch { completion(.failure(error)) }
                }
            }
        }
    }

    func stop() {
        captureSession.stop(request: request)
        task?.cancel()
        request = nil; task = nil; isListening = false
    }

    func speak(_ text: String) {
        synthesizer.stopSpeaking(at: .immediate)
        let utterance = AVSpeechUtterance(string: text)
        utterance.rate = AVSpeechUtteranceDefaultSpeechRate
        synthesizer.speak(utterance)
    }

    private func beginRecognition(onText: @escaping (String) -> Void, completion: @escaping (Result<Void, Error>) -> Void) throws {
        stop()
        guard let recognizer = SFSpeechRecognizer(), recognizer.isAvailable, recognizer.supportsOnDeviceRecognition else { throw VoiceError.onDeviceUnavailable }
        self.recognizer = recognizer
        let request = SFSpeechAudioBufferRecognitionRequest()
        request.shouldReportPartialResults = true
        request.requiresOnDeviceRecognition = true
        self.request = request
        try captureSession.start(appendingTo: request)
        isListening = true
        task = recognizer.recognitionTask(with: request) { [weak self] result, error in
            if let result { DispatchQueue.main.async { onText(result.bestTranscription.formattedString) } }
            if error != nil || result?.isFinal == true {
                DispatchQueue.main.async { self?.stop(); completion(error.map { .failure($0) } ?? .success(())) }
            }
        }
    }
}
