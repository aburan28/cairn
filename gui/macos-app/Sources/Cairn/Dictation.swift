import AVFoundation
import Foundation
import Speech
import SwiftUI

/// Talking a challenge through instead of typing it: the microphone button
/// beside the description in New Challenge….
///
/// Press to listen, press again (or pause) to stop; what was heard is appended
/// to the field. Recognition runs on this Mac when macOS offers it for the
/// current language (`requiresOnDeviceRecognition`), so a description of a
/// problem nobody has solved does not leave the machine before the person
/// has read it back. Where the system has no on-device model the request
/// goes to Apple's recogniser, which the permission prompt says.
///
/// Two permissions, asked for the first time the button is pressed and never
/// before: speech recognition and the microphone. Both can be refused, and a
/// refusal is shown beside the button with where to change it, rather than a
/// button that silently does nothing. The signed build carries the
/// `audio-input` entitlement the hardened runtime requires
/// (`packaging/macos/Cairn.entitlements`); without it the microphone request
/// fails at once and this says so too.
@MainActor
final class Dictation: ObservableObject {
    enum State: Equatable {
        case idle
        case requesting
        case listening
        case denied(String)
        case failed(String)

        var isListening: Bool { self == .listening }
    }

    @Published private(set) var state: State = .idle
    /// The utterance so far, while listening. Appended to the field when it
    /// is final; shown under the field in the meantime.
    @Published private(set) var transcript = ""

    private var recognizer: SFSpeechRecognizer?
    private var request: SFSpeechAudioBufferRecognitionRequest?
    private var task: SFSpeechRecognitionTask?
    private let engine = AVAudioEngine()
    private var deliver: ((String) -> Void)?

    /// Whether this Mac can recognise speech for the current language at all.
    static var isSupported: Bool { SFSpeechRecognizer(locale: Locale.current) != nil }

    /// Start listening, delivering the final transcript to `into`; or stop,
    /// if already listening.
    func toggle(into deliver: @escaping (String) -> Void) {
        if state.isListening {
            stop()
        } else {
            start(into: deliver)
        }
    }

    func start(into deliver: @escaping (String) -> Void) {
        guard !state.isListening, state != .requesting else { return }
        self.deliver = deliver
        state = .requesting
        SFSpeechRecognizer.requestAuthorization { [weak self] status in
            Task { @MainActor in
                guard let self else { return }
                switch status {
                case .authorized:
                    self.requestMicrophone()
                case .denied:
                    self.state = .denied(
                        "Speech recognition is turned off for Cairn. System Settings → Privacy & Security → Speech Recognition.")
                case .restricted:
                    self.state = .denied("Speech recognition is restricted on this Mac.")
                case .notDetermined:
                    self.state = .denied("Speech recognition was not allowed.")
                @unknown default:
                    self.state = .denied("Speech recognition was not allowed.")
                }
            }
        }
    }

    private func requestMicrophone() {
        AVCaptureDevice.requestAccess(for: .audio) { [weak self] granted in
            Task { @MainActor in
                guard let self else { return }
                if granted {
                    self.listen()
                } else {
                    self.state = .denied(
                        "The microphone is turned off for Cairn. System Settings → Privacy & Security → Microphone.")
                }
            }
        }
    }

    private func listen() {
        guard let recognizer = SFSpeechRecognizer(locale: Locale.current), recognizer.isAvailable else {
            state = .failed("Speech recognition is not available for \(Locale.current.identifier) on this Mac right now.")
            return
        }
        let request = SFSpeechAudioBufferRecognitionRequest()
        request.shouldReportPartialResults = true
        if recognizer.supportsOnDeviceRecognition {
            request.requiresOnDeviceRecognition = true
        }
        let input = engine.inputNode
        let format = input.outputFormat(forBus: 0)
        input.removeTap(onBus: 0)
        input.installTap(onBus: 0, bufferSize: 1024, format: format) { buffer, _ in
            request.append(buffer)
        }
        engine.prepare()
        do {
            try engine.start()
        } catch {
            input.removeTap(onBus: 0)
            state = .failed("The microphone could not be started: \(error.localizedDescription)")
            return
        }
        self.recognizer = recognizer
        self.request = request
        transcript = ""
        state = .listening
        task = recognizer.recognitionTask(with: request) { [weak self] result, error in
            Task { @MainActor in
                guard let self else { return }
                if let result {
                    self.transcript = result.bestTranscription.formattedString
                    if result.isFinal {
                        self.finish()
                        return
                    }
                }
                if error != nil, self.state.isListening {
                    // After a stop, the recogniser reports the cancellation as
                    // an error; with words in hand that is the end of the
                    // utterance, and with none it is a failure worth saying.
                    if self.transcript.isEmpty {
                        self.state = .failed(
                            "Nothing was recognised. Check the input device in System Settings → Sound.")
                        self.tearDown()
                    } else {
                        self.finish()
                    }
                }
            }
        }
    }

    /// Stop listening. What was heard so far is delivered.
    func stop() {
        guard state.isListening else { return }
        request?.endAudio()
        task?.finish()
        if transcript.isEmpty {
            tearDown()
            state = .idle
        } else {
            finish()
        }
    }

    private func finish() {
        let text = transcript.trimmingCharacters(in: .whitespacesAndNewlines)
        tearDown()
        state = .idle
        transcript = ""
        if !text.isEmpty { deliver?(text) }
    }

    private func tearDown() {
        if engine.isRunning { engine.stop() }
        engine.inputNode.removeTap(onBus: 0)
        task?.cancel()
        task = nil
        request = nil
        recognizer = nil
    }

    /// Append an utterance to a field the person may already have typed in:
    /// one space between, none after a line break, nothing at the start.
    /// Pure, and `nonisolated` so a test can call it off the main actor, as
    /// `Node.childEnvironment` is.
    nonisolated static func merge(_ existing: String, _ utterance: String) -> String {
        let spoken = utterance.trimmingCharacters(in: .whitespacesAndNewlines)
        if spoken.isEmpty { return existing }
        if existing.isEmpty { return spoken }
        if let last = existing.last, last.isWhitespace || last.isNewline {
            return existing + spoken
        }
        return existing + " " + spoken
    }
}

/// Reads a draft back aloud, so a statement can be heard as a solver would
/// read it. One voice, the system's for the current language.
final class Speaker: NSObject, ObservableObject, AVSpeechSynthesizerDelegate {
    @Published private(set) var speaking = false
    private let synthesizer = AVSpeechSynthesizer()

    override init() {
        super.init()
        synthesizer.delegate = self
    }

    func toggle(_ text: String) {
        if synthesizer.isSpeaking {
            synthesizer.stopSpeaking(at: .immediate)
            speaking = false
            return
        }
        let utterance = AVSpeechUtterance(string: text)
        utterance.voice = AVSpeechSynthesisVoice(language: Locale.current.identifier)
        speaking = true
        synthesizer.speak(utterance)
    }

    func speechSynthesizer(_ synthesizer: AVSpeechSynthesizer, didFinish utterance: AVSpeechUtterance) {
        DispatchQueue.main.async { self.speaking = false }
    }

    func speechSynthesizer(_ synthesizer: AVSpeechSynthesizer, didCancel utterance: AVSpeechUtterance) {
        DispatchQueue.main.async { self.speaking = false }
    }
}

/// The microphone button and its status line, for any text field.
struct DictationButton: View {
    @ObservedObject var dictation: Dictation
    let into: (String) -> Void

    var body: some View {
        HStack(spacing: 8) {
            Button {
                dictation.toggle(into: into)
            } label: {
                Label(dictation.state.isListening ? "Stop" : "Dictate",
                      systemImage: dictation.state.isListening ? "stop.circle.fill" : "mic")
            }
            .disabled(!Dictation.isSupported || dictation.state == .requesting)
            .help(Dictation.isSupported
                  ? "Say the description instead of typing it; press again to stop. Recognised on this Mac when macOS can."
                  : "Speech recognition is not available for your language on this Mac.")
            switch dictation.state {
            case .idle:
                EmptyView()
            case .requesting:
                ProgressView().controlSize(.small)
            case .listening:
                Text(dictation.transcript.isEmpty ? "Listening…" : dictation.transcript)
                    .font(.caption).foregroundStyle(.secondary)
                    .lineLimit(2)
            case .denied(let why), .failed(let why):
                Text(why).font(.caption).foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}
