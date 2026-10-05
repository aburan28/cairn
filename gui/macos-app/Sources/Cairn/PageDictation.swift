import AVFoundation
import Foundation
import Speech

/// Voice entry for the reader's challenge form. This is separate from the
/// sheet's Dictation: the page needs an explicit stop result and must not
/// interrupt the sheet's recorder. Recognition stays on this Mac; speech
/// recognition without that requirement may send an unposted draft away.
@MainActor
final class PageDictation {
    private var engine: AVAudioEngine?
    private var request: SFSpeechAudioBufferRecognitionRequest?
    private var task: SFSpeechRecognitionTask?
    private var transcript = ""
    private var failure: String?
    private var starting = false
    private var stopping = false
    private var generation = 0

    func start() async throws {
        guard engine == nil && !starting && !stopping else { throw PageDictationError("Dictation is already running.") }
        starting = true
        generation += 1
        let run = generation
        defer { starting = false }
        guard let recognizer = SFSpeechRecognizer(locale: .current),
              recognizer.supportsOnDeviceRecognition else {
            throw PageDictationError("On-device speech recognition is unavailable for this language. Check macOS language settings.")
        }

        let authorized = await withCheckedContinuation { continuation in
            SFSpeechRecognizer.requestAuthorization { status in
                continuation.resume(returning: status == .authorized)
            }
        }
        guard run == generation else { throw PageDictationError("Dictation was cancelled.") }
        guard authorized else { throw PageDictationError("Allow speech recognition for Cairn in System Settings to dictate a challenge.") }
        guard await AVCaptureDevice.requestAccess(for: .audio) else {
            throw PageDictationError("Allow microphone access for Cairn in System Settings to dictate a challenge.")
        }
        guard run == generation else { throw PageDictationError("Dictation was cancelled.") }

        transcript = ""
        failure = nil
        let audio = AVAudioEngine()
        let speech = SFSpeechAudioBufferRecognitionRequest()
        speech.shouldReportPartialResults = true
        speech.requiresOnDeviceRecognition = true
        let input = audio.inputNode
        input.installTap(onBus: 0, bufferSize: 1024, format: input.outputFormat(forBus: 0)) { buffer, _ in
            speech.append(buffer)
        }
        request = speech
        task = recognizer.recognitionTask(with: speech) { [weak self] result, error in
            Task { @MainActor [weak self] in
                guard self?.generation == run else { return }
                if let result { self?.transcript = result.bestTranscription.formattedString }
                if let error { self?.failure = error.localizedDescription }
            }
        }
        do {
            audio.prepare()
            try audio.start()
            engine = audio
        } catch {
            input.removeTap(onBus: 0)
            task?.cancel()
            task = nil
            request = nil
            throw PageDictationError("The microphone could not start: \(error.localizedDescription)")
        }
    }

    func stop() async throws -> String {
        guard let audio = engine else { throw PageDictationError("Dictation is not running.") }
        stopping = true
        defer { stopping = false }
        let run = generation
        audio.stop()
        audio.inputNode.removeTap(onBus: 0)
        engine = nil
        request?.endAudio()
        // Let the local recognizer deliver its final result after the last
        // buffer. The partial transcript remains usable if it does not.
        try? await Task.sleep(nanoseconds: 800_000_000)
        guard run == generation else { throw PageDictationError("Dictation was cancelled.") }
        let text = transcript.trimmingCharacters(in: .whitespacesAndNewlines)
        let error = failure
        task?.cancel()
        task = nil
        request = nil
        engine = nil
        if text.isEmpty { throw PageDictationError(error ?? "No speech was recognized. Try again or type your description.") }
        return text
    }

    func cancel() {
        generation += 1
        engine?.stop()
        engine?.inputNode.removeTap(onBus: 0)
        task?.cancel()
        task = nil
        request = nil
        engine = nil
    }
}

private struct PageDictationError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}
