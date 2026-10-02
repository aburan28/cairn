import AppKit
import SwiftUI

/// Node → New Challenge…: describe a problem in plain words, and post a
/// challenge whose checker has already been run against a right and a wrong
/// answer.
///
/// The person never meets the objective schema. The model writes the parts
/// that need judgment (statement, answer format, checker, two examples);
/// `ChallengeBuilder` adds the parts that need none (pin, timestamp, shape);
/// `ChallengeTest` runs the checker through the node's own verifier; and
/// nothing is posted until that run says the checker accepts the right
/// answer and rejects the wrong one. The checker is shown, too, because it
/// is what decides who gets paid.
@MainActor
final class ChallengeComposer: ObservableObject {
    enum Phase: Equatable { case compose, drafting, testing, review, posting, posted }

    @Published var phase: Phase = .compose
    @Published var brief = ""
    @Published var reward = 10_000
    @Published var funder = "treasury"
    @Published var draft: ChallengeDraft?
    @Published var outcome: ChallengeTest.Outcome?
    @Published var error: String?
    @Published var feedback = ""
    /// The provider's key, read from `~/.cairn/secrets` when the sheet
    /// opens and kept in memory only while it is open.
    @Published private(set) var apiKey: String?
    @Published private(set) var keyChecked = false

    let node: Node
    private var work: Task<Void, Never>?

    init(node: Node) { self.node = node }

    var config: AIConfig { AIConfig.current() }

    func loadKey() async {
        keyChecked = false
        apiKey = await node.secretValue(config.provider.secretName)
        keyChecked = true
    }

    func saveKey(_ value: String) {
        let key = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !key.isEmpty else { return }
        error = nil
        node.setSecret(name: config.provider.secretName, value: key) { [weak self] err in
            if let err { self?.error = err } else { self?.apiKey = key }
        }
    }

    /// Ask the model, then test what it wrote. A redraft passes the earlier
    /// draft and everything wrong with it: failed tests, and whatever the
    /// person typed.
    func draftChallenge(redraft: Bool = false) {
        guard let key = apiKey else { return }
        var problems = redraft ? (outcome?.problems ?? []) : []
        let note = feedback.trimmingCharacters(in: .whitespacesAndNewlines)
        if redraft, !note.isEmpty { problems.append("The funder asks: \(note)") }
        let previous = redraft ? draft : nil
        error = nil
        phase = .drafting
        let config = self.config
        let request = ChallengeWriter.request(describing: brief, previous: previous, problems: problems)
        work = Task {
            do {
                let object = try await AIClient(config: config, apiKey: key).complete(
                    system: ChallengeWriter.system, user: request,
                    schema: ChallengeWriter.schema, schemaName: "cairn_challenge")
                let fresh = try ChallengeWriter.parse(object)
                try Task.checkCancellation()
                draft = fresh
                feedback = ""
                await test()
            } catch is CancellationError {
                phase = draft == nil ? .compose : .review
            } catch let failure as URLError where failure.code == .cancelled {
                phase = draft == nil ? .compose : .review
            } catch {
                self.error = error.localizedDescription
                phase = draft == nil ? .compose : .review
            }
        }
    }

    func test() async {
        guard let draft else { return }
        phase = .testing
        outcome = nil
        defer { phase = .review }
        guard let binary = node.binary ?? Node.locateBinary() else {
            error = "No cairn command was found, so the checker could not be tested."
            return
        }
        do {
            let built = try ChallengeBuilder.build(draft, reward: UInt64(max(0, reward)), funder: funderName,
                                                   root: node.dataDir)
            outcome = try await ChallengeTest.run(built, draft: draft, binary: binary, root: node.dataDir,
                                                  environment: Node.childEnvironment(node.settings))
        } catch {
            self.error = error.localizedDescription
        }
    }

    /// Built again from what review shows, since the statement, reward and
    /// funder can all be edited there. The checker cannot, so the test that
    /// passed is still the test of what is posted.
    func post(then reload: @escaping () -> Void) {
        guard let draft, outcome?.ok == true else { return }
        error = nil
        let built: BuiltChallenge
        do {
            built = try ChallengeBuilder.build(draft, reward: UInt64(max(0, reward)), funder: funderName,
                                               root: node.dataDir)
        } catch {
            self.error = error.localizedDescription
            return
        }
        phase = .posting
        node.postObjectives(at: [built.objectiveFile.path]) { [weak self] err in
            guard let self else { return }
            if let err {
                self.error = err
                self.phase = .review
            } else {
                self.phase = .posted
                reload()
            }
        }
    }

    func cancel() { work?.cancel() }

    private var funderName: String {
        let name = funder.trimmingCharacters(in: .whitespacesAndNewlines)
        return name.isEmpty ? "treasury" : name
    }
}

struct NewChallengeSheet: View {
    @ObservedObject var node: Node
    @ObservedObject var browser: Browser
    @Binding var isPresented: Bool
    @StateObject private var composer: ChallengeComposer

    init(node: Node, browser: Browser, isPresented: Binding<Bool>) {
        self.node = node
        self.browser = browser
        self._isPresented = isPresented
        self._composer = StateObject(wrappedValue: ChallengeComposer(node: node))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("New challenge", systemImage: "sparkles").font(.headline)
            switch composer.phase {
            case .compose: compose
            case .drafting: working("Drafting with \(composer.config.label)… a careful model can take a minute or two.", cancellable: true)
            case .testing: working("Testing the checker on a right and a wrong answer, in the sandbox the network uses…", cancellable: false)
            case .review, .posting: review
            case .posted: posted
            }
        }
        .padding(20)
        .frame(width: 640)
        .task { await composer.loadKey() }
        .interactiveDismissDisabled(composer.phase == .posting)
    }

    // MARK: compose

    private var compose: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("""
                Describe a problem you want solved and what counts as a correct answer. \
                Cairn writes the challenge and a checker for it, and tests the checker \
                before you post anything.
                """)
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            ZStack(alignment: .topLeading) {
                TextEditor(text: $composer.brief)
                    .font(.body)
                    .frame(height: 150)
                    .scrollContentBackground(.hidden)
                    .padding(6)
                    .background(Color(nsColor: .textBackgroundColor))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                    .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(Color.secondary.opacity(0.3)))
                if composer.brief.isEmpty {
                    Text("For example: find a 16-input sorting network with fewer than 60 comparators. Pay whoever finds one.")
                        .foregroundStyle(.tertiary)
                        .padding(.horizontal, 11).padding(.vertical, 6)
                        .allowsHitTesting(false)
                }
            }

            terms

            if composer.keyChecked && composer.apiKey == nil {
                KeySetup(composer: composer)
            } else if composer.keyChecked {
                HStack(spacing: 6) {
                    Image(systemName: "checkmark.seal").foregroundStyle(.secondary)
                    Text(verbatim: "Drafted by \(composer.config.label)")
                        .font(.callout).foregroundStyle(.secondary)
                    OpenSettingsButton(title: "Change…").font(.callout)
                }
            }

            problem

            HStack {
                Spacer()
                Button("Cancel") { isPresented = false }.keyboardShortcut(.cancelAction)
                Button("Draft Challenge") { composer.draftChallenge() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(composer.brief.trimmingCharacters(in: .whitespacesAndNewlines).count < 10
                              || composer.apiKey == nil || composer.config.problem != nil || node.isAttached)
            }
        }
    }

    private var terms: some View {
        HStack(spacing: 8) {
            Text("Reward")
            TextField("Reward", value: $composer.reward, format: .number)
                .labelsHidden()
                .multilineTextAlignment(.trailing)
                .frame(width: 110)
            Text("units").foregroundStyle(.secondary)
            Spacer()
            Text("Funded by")
            TextField("Funder", text: $composer.funder)
                .labelsHidden()
                .frame(width: 140)
                .help("The name shown on the bounty. It is public, and it is not checked: a name, not a key.")
        }
        .font(.callout)
    }

    // MARK: review

    private var review: some View {
        VStack(alignment: .leading, spacing: 12) {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    if let outcome = composer.outcome { results(outcome) }
                    if let draft = composer.draft {
                        if !draft.notes.isEmpty {
                            Label(draft.notes, systemImage: "lightbulb")
                                .font(.callout)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        VStack(alignment: .leading, spacing: 6) {
                            Text("What solvers see").font(.subheadline.bold())
                            TextField("Goal", text: binding(\.goal))
                                .font(.callout.monospaced())
                            TextEditor(text: binding(\.statement))
                                .font(.callout)
                                .frame(minHeight: 110)
                                .scrollContentBackground(.hidden)
                                .padding(4)
                                .background(Color(nsColor: .textBackgroundColor))
                                .clipShape(RoundedRectangle(cornerRadius: 6))
                        }
                        DisclosureGroup("Checker — this code decides who gets paid") {
                            code(draft.checker)
                        }
                        DisclosureGroup("Answer format") {
                            code(Self.pretty(draft.answerSchema))
                        }
                        terms
                    }
                }
                .padding(.trailing, 8)
            }
            .frame(minHeight: 260, maxHeight: 520)

            problem

            TextField("What should change? Optional, sent with Redraft.", text: $composer.feedback)
                .font(.callout)

            HStack {
                Button("Back") { composer.phase = .compose }
                Button("Redraft") { composer.draftChallenge(redraft: true) }
                    .disabled(composer.apiKey == nil)
                Spacer()
                if composer.phase == .posting { ProgressView().controlSize(.small) }
                Button("Cancel") { isPresented = false }.keyboardShortcut(.cancelAction)
                Button("Post Challenge") { composer.post { browser.reload() } }
                    .keyboardShortcut(.defaultAction)
                    .disabled(composer.outcome?.ok != true || composer.phase == .posting || node.isAttached)
                    .help(composer.outcome?.ok == true
                          ? "Post it to this node's log. The node pauses for a moment: its log has one writer."
                          : "Posting waits for a checker that rejects the wrong answer and accepts the right one.")
            }
        }
    }

    private func results(_ outcome: ChallengeTest.Outcome) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Checker tested").font(.subheadline.bold())
            result(outcome.failing.rejected, "Rejects a wrong answer", outcome.failing)
            if let passing = outcome.passing {
                result(passing.accepted, "Accepts a correct answer", passing)
            } else {
                Label("No correct answer was known to test with. Read the checker before posting.",
                      systemImage: "exclamationmark.triangle")
                    .font(.callout)
                    .foregroundStyle(.orange)
            }
        }
    }

    private func result(_ ok: Bool, _ title: String, _ verdict: ChallengeTest.Verdict) -> some View {
        Label {
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                Text(verbatim: ChallengeTest.Outcome.describe(verdict))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
        } icon: {
            Image(systemName: ok ? "checkmark.circle.fill" : "xmark.octagon.fill")
                .foregroundStyle(ok ? Color.green : Color.red)
        }
        .font(.callout)
    }

    private func code(_ text: String) -> some View {
        ScrollView(.horizontal) {
            Text(verbatim: text)
                .font(.caption.monospaced())
                .textSelection(.enabled)
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Color(nsColor: .textBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 6))
    }

    private func binding(_ path: WritableKeyPath<ChallengeDraft, String>) -> Binding<String> {
        Binding(
            get: { composer.draft?[keyPath: path] ?? "" },
            set: { composer.draft?[keyPath: path] = $0 }
        )
    }

    static func pretty(_ json: String) -> String {
        guard let data = json.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data),
              let out = try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
        else { return json }
        return String(decoding: out, as: UTF8.self)
    }

    // MARK: the rest

    private func working(_ text: String, cancellable: Bool) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            ProgressView().progressViewStyle(.linear)
            Text(text).font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if cancellable {
                HStack {
                    Spacer()
                    Button("Cancel") { composer.cancel() }.keyboardShortcut(.cancelAction)
                }
            }
        }
    }

    private var posted: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Posted. It is listed under Objectives once the node is back.", systemImage: "checkmark.circle.fill")
                .foregroundStyle(.green)
            Text("The checker and the objective are kept in the node's data folder, under challenges/.")
                .font(.callout).foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("Done") { isPresented = false }.keyboardShortcut(.defaultAction)
            }
        }
    }

    @ViewBuilder private var problem: some View {
        if let error = composer.error {
            Label(error, systemImage: "exclamationmark.triangle.fill")
                .font(.callout)
                .foregroundStyle(.red)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        } else if let problem = composer.config.problem {
            Label(problem, systemImage: "exclamationmark.triangle")
                .font(.callout)
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

/// Paste a key without leaving the sheet: the first thing anybody without
/// one needs, and the reason the feature exists.
private struct KeySetup: View {
    @ObservedObject var composer: ChallengeComposer
    @AppStorage(AIConfig.Key.provider) private var providerRaw = AIProvider.anthropic.rawValue
    @State private var pasted = ""

    private var provider: AIProvider { AIProvider(rawValue: providerRaw) ?? .anthropic }

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                Text("Drafting uses a model you have a key for. Paste one to continue.")
                    .font(.callout)
                Picker("Provider", selection: $providerRaw) {
                    ForEach(AIProvider.allCases) { Text($0.title).tag($0.rawValue) }
                }
                .onChange(of: providerRaw) { _ in Task { await composer.loadKey() } }
                HStack {
                    SecureField("\(provider.title) API key", text: $pasted)
                        .onSubmit(save)
                    Button("Save Key", action: save)
                        .disabled(pasted.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
                HStack {
                    if let page = provider.keyPage {
                        Link("Get a key", destination: page).font(.caption)
                    }
                    Spacer()
                    Text(verbatim: "Kept as \(provider.secretName) in ~/.cairn/secrets, readable by your user only.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .padding(4)
        }
    }

    private func save() {
        composer.saveKey(pasted)
        pasted = ""
    }
}
