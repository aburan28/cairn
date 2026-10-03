import AppKit
import SwiftUI

/// Node → New Challenge…: describe a problem in plain words, and post a
/// challenge whose theorem has already been compiled and whose verifier has
/// already refused a hole.
///
/// The person never meets the objective schema. The model writes the parts
/// that need judgment (statement, theorem, preamble, a proof when it knows
/// one); `ChallengeBuilder` adds the parts that need none (timestamp, shape,
/// the verifier's fixed fields); `ChallengeTest` runs the theorem through
/// the node's own verifier and the Lean on this Mac; and nothing is posted
/// until the hole is rejected, the theorem compiles, and the model's proof,
/// if any, is accepted by the kernel. The theorem is shown, because it is
/// what decides who gets paid.
@MainActor
final class ChallengeComposer: ObservableObject {
    enum Phase: Equatable { case compose, drafting, testing, review, posting, posted }

    @Published var phase: Phase = .compose
    @Published var brief = ""
    @Published var reward = 10_000
    @Published var funder = "treasury"
    @Published var draft: ChallengeDraft?
    @Published var outcome: ChallengeTest.Outcome?
    /// Screened tokens in the draft itself, found before any test; a redraft
    /// sends them back.
    @Published var draftProblems: [String] = []
    @Published var error: String?
    @Published var feedback = ""
    /// Where a draft under way has got to: the sheet's bar and checklist.
    @Published var progress = DraftProgress()
    /// The provider's key, read from `~/.cairn/secrets` when the sheet
    /// opens and kept in memory only while it is open.
    @Published private(set) var apiKey: String?
    @Published private(set) var keyChecked = false
    /// The toolchains behind the node's verifiers, as found on the PATH the
    /// node is given. Nil until looked for.
    @Published private(set) var toolchains: ToolchainReport?
    /// Bumped when a key is saved here, so the model picker asks the
    /// provider again.
    @Published var keyEpoch = 0

    let node: Node
    private var work: Task<Void, Never>?
    /// Set when the reader's Post a challenge page handed the description
    /// over. The person already asked for a draft there, so the sheet starts
    /// one as soon as it has a key rather than asking a second time.
    private var handedOver: Bool

    init(node: Node, brief: String? = nil) {
        self.node = node
        handedOver = brief != nil
        self.brief = brief ?? ""
    }

    var config: AIConfig { AIConfig.current() }

    var canDraft: Bool {
        ChallengeWriter.isDraftable(brief) && apiKey != nil && config.problem == nil && !node.isAttached
    }

    /// Start the draft the page asked for: once, and only from here -- not
    /// from switching providers in the picker, which is browsing, not asking.
    func startHandedOver() {
        guard handedOver, canDraft else { return }
        handedOver = false
        draftChallenge()
    }

    func loadKey() async {
        keyChecked = false
        apiKey = await node.secretValue(config.provider.secretName)
        keyChecked = true
    }

    /// Look for Lean, Python and the sandbox where the node will look. Off
    /// the main thread: it may run `lean --print-prefix`.
    func checkToolchains() async {
        let settings = node.settings
        toolchains = await Task.detached(priority: .utility) {
            Toolchains.report(environment: Node.childEnvironment(settings))
        }.value
    }

    func saveKey(_ value: String) {
        let key = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !key.isEmpty else { return }
        error = nil
        node.setSecret(name: config.provider.secretName, value: key) { [weak self] err in
            if let err {
                self?.error = err
            } else {
                self?.apiKey = key
                self?.keyEpoch += 1
                self?.startHandedOver()
            }
        }
    }

    /// Ask the model, then test what it wrote. A redraft passes the earlier
    /// draft and everything wrong with it: failed tests, screened tokens,
    /// and whatever the person typed.
    func draftChallenge(redraft: Bool = false) {
        guard let key = apiKey else { return }
        var problems = redraft ? (outcome?.problems ?? []) + draftProblems : []
        let note = feedback.trimmingCharacters(in: .whitespacesAndNewlines)
        if redraft, !note.isEmpty { problems.append("The funder asks: \(note)") }
        let previous = redraft ? draft : nil
        error = nil
        progress = DraftProgress()
        phase = .drafting
        let config = self.config
        let request = ChallengeWriter.request(describing: brief, previous: previous, problems: problems)
        work = Task {
            do {
                let object = try await AIClient(config: config, apiKey: key).complete(
                    system: ChallengeWriter.system, user: request,
                    schema: ChallengeWriter.schema, schemaName: "cairn_challenge",
                    progress: { [weak self] state in
                        Task { @MainActor in self?.progress.model = state }
                    })
                progress.reached(.read)
                let fresh = try ChallengeWriter.parse(object)
                try Task.checkCancellation()
                draft = fresh
                feedback = ""
                draftProblems = ChallengeWriter.problems(in: fresh)
                if draftProblems.isEmpty {
                    await test()
                } else {
                    outcome = nil
                    progress.failed(at: .read)
                    error = draftProblems.joined(separator: " ")
                    phase = .review
                }
            } catch is CancellationError {
                phase = draft == nil ? .compose : .review
            } catch let failure as URLError where failure.code == .cancelled {
                phase = draft == nil ? .compose : .review
            } catch {
                self.error = error.localizedDescription
                progress.failed(at: progress.current)
                phase = draft == nil ? .compose : .review
            }
        }
    }

    func test() async {
        guard let draft else { return }
        phase = .testing
        outcome = nil
        if draft.proof == nil { progress.stages.removeAll { $0 == .proof } }
        progress.reached(.write)
        defer { phase = .review }
        guard let binary = node.binary ?? Node.locateBinary() else {
            error = "No cairn command was found, so the theorem could not be tested."
            progress.failed(at: .write)
            return
        }
        let settings = node.settings
        let environment = await Task.detached(priority: .userInitiated) {
            Node.childEnvironment(settings)
        }.value
        do {
            let built = try ChallengeBuilder.build(draft, reward: UInt64(max(0, reward)), funder: funderName,
                                                   root: node.dataDir)
            let result = try await ChallengeTest.run(
                built, draft: draft, binary: binary, root: node.dataDir, environment: environment
            ) { [weak self] step in
                Task { @MainActor in self?.progress.reached(step.stage) }
            }
            outcome = result
            progress.finished(ok: result.ok)
        } catch {
            self.error = error.localizedDescription
            progress.failed(at: progress.current)
        }
    }

    /// Built again from what review shows, since the statement, reward and
    /// funder can all be edited there. The theorem cannot, so the test that
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

extension ChallengeTest.Step {
    var stage: DraftProgress.Stage {
        switch self {
        case .posting: return .post
        case .hole: return .hole
        case .statement: return .statement
        case .proof: return .proof
        }
    }
}

struct NewChallengeSheet: View {
    @ObservedObject var node: Node
    @ObservedObject var browser: Browser
    @Binding var isPresented: Bool
    @StateObject private var composer: ChallengeComposer
    @State private var installingLean = false

    init(node: Node, browser: Browser, isPresented: Binding<Bool>) {
        self.node = node
        self.browser = browser
        self._isPresented = isPresented
        self._composer = StateObject(wrappedValue: ChallengeComposer(node: node, brief: node.challengeBrief))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("New challenge", systemImage: "sparkles").font(.headline)
            switch composer.phase {
            case .compose: compose
            case .drafting, .testing: working
            case .review, .posting: review
            case .posted: posted
            }
        }
        .padding(20)
        .frame(width: 660)
        .task {
            await composer.loadKey()
            await composer.checkToolchains()
            composer.startHandedOver()
        }
        .interactiveDismissDisabled(composer.phase == .posting)
        .sheet(isPresented: $installingLean) {
            InstallLeanSheet(isPresented: $installingLean) {
                Task { await composer.checkToolchains() }
            }
        }
    }

    // MARK: compose

    private var compose: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("""
                Describe a problem you want proved and what counts as proving it. Cairn \
                writes it as a Lean 4 theorem, checks that the theorem compiles and that a \
                hole is refused, and shows you all of it before anything is posted. Whoever \
                submits a proof the Lean kernel accepts is paid.
                """)
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            ZStack(alignment: .topLeading) {
                TextEditor(text: $composer.brief)
                    .font(.body)
                    .frame(height: 140)
                    .scrollContentBackground(.hidden)
                    .padding(6)
                    .background(Color(nsColor: .textBackgroundColor))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                    .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(Color.secondary.opacity(0.3)))
                if composer.brief.isEmpty {
                    Text("For example: for every natural number n, the sum of the first n odd numbers is n squared. Pay whoever proves it.")
                        .foregroundStyle(.tertiary)
                        .padding(.horizontal, 11).padding(.vertical, 6)
                        .allowsHitTesting(false)
                }
            }

            terms
            drafter
            environment
            problem

            HStack {
                Spacer()
                Button("Cancel") { isPresented = false }.keyboardShortcut(.cancelAction)
                Button("Draft Challenge") { composer.draftChallenge() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!composer.canDraft)
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

    /// Who drafts, chosen here: the provider and model, and a key when
    /// there is none yet. The same picker as Settings → AI, so nothing
    /// opens another window.
    private var drafter: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Image(systemName: "checkmark.seal").foregroundStyle(.secondary)
                    Text("Drafted by").font(.callout)
                    ModelPicker(node: node, compact: true, keyEpoch: composer.keyEpoch) {
                        Task { await composer.loadKey() }
                    }
                }
                if composer.keyChecked && composer.apiKey == nil {
                    KeySetup(composer: composer)
                }
            }
            .padding(4)
        }
    }

    /// Whether this Mac can compile the theorem: the one thing a Lean
    /// challenge cannot be posted without.
    @ViewBuilder private var environment: some View {
        if let report = composer.toolchains {
            if let lean = report.lean {
                Label {
                    Text(verbatim: "Lean: \(lean.version ?? lean.binary.path)" + (lean.isElan ? " (elan)" : ""))
                        .font(.callout).foregroundStyle(.secondary)
                } icon: {
                    Image(systemName: "checkmark.circle").foregroundStyle(Color.green)
                }
            } else {
                HStack(alignment: .firstTextBaseline) {
                    Label(report.leanProblem ?? "No Lean toolchain was found.", systemImage: "exclamationmark.triangle")
                        .font(.callout)
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer()
                    Button("Install Lean…") { installingLean = true }.font(.callout)
                }
                Text("""
                    Without it the theorem cannot be compiled here, so a challenge cannot be \
                    posted from this Mac, and the node would answer every proof with unavailable.
                    """)
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    // MARK: working

    private var working: some View {
        let p = composer.progress
        return VStack(alignment: .leading, spacing: 12) {
            ProgressView(value: p.fraction)
            TimelineView(.periodic(from: p.startedAt, by: 1)) { context in
                HStack(alignment: .firstTextBaseline) {
                    Text(p.headline)
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer()
                    Text(verbatim: Self.elapsed(since: p.startedAt, now: context.date))
                        .font(.callout.monospacedDigit()).foregroundStyle(.secondary)
                }
            }
            VStack(alignment: .leading, spacing: 5) {
                ForEach(p.stages, id: \.self) { stage in
                    HStack(spacing: 8) {
                        stageIcon(stage, in: p)
                        Text(stage.title)
                            .font(.callout)
                            .foregroundStyle(p.done.contains(stage) || stage == p.current ? Color.primary : Color.secondary)
                        if stage == .model, p.current == .model, p.model.reasoned > 0 {
                            Text(verbatim: "\(p.model.reasoned.formatted()) reasoning · \(p.model.written.formatted()) written")
                                .font(.caption).foregroundStyle(.tertiary)
                        }
                    }
                }
            }
            if p.current == .model, !p.model.tail.isEmpty {
                Text(verbatim: p.model.tail)
                    .font(.caption.monospaced())
                    .foregroundStyle(.tertiary)
                    .lineLimit(3)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(8)
                    .background(Color(nsColor: .textBackgroundColor))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
            }
            Text(verbatim: composer.phase == .drafting
                 ? "Drafting with \(composer.config.label). The reply streams in, so the count moves as the model writes; the bar's advance within that stage is an estimate against a typical draft."
                 : "Testing through the node's own verifier, in the sandbox the network uses, and compiling the theorem with the Lean on this Mac.")
                .font(.caption).foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
            if composer.phase == .drafting {
                HStack {
                    Spacer()
                    Button("Cancel") { composer.cancel() }.keyboardShortcut(.cancelAction)
                }
            }
        }
    }

    @ViewBuilder private func stageIcon(_ stage: DraftProgress.Stage, in p: DraftProgress) -> some View {
        if p.failedAt == stage {
            Image(systemName: "xmark.octagon.fill").foregroundStyle(Color.red)
        } else if p.done.contains(stage) {
            Image(systemName: "checkmark.circle.fill").foregroundStyle(Color.green)
        } else if stage == p.current {
            ProgressView().controlSize(.small).frame(width: 16, height: 16)
        } else {
            Image(systemName: "circle").foregroundStyle(Color.secondary.opacity(0.5))
        }
    }

    static func elapsed(since start: Date, now: Date) -> String {
        let seconds = max(0, Int(now.timeIntervalSince(start)))
        return seconds < 60 ? "\(seconds) s" : "\(seconds / 60) min \(seconds % 60) s"
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
                                .frame(minHeight: 90)
                                .scrollContentBackground(.hidden)
                                .padding(4)
                                .background(Color(nsColor: .textBackgroundColor))
                                .clipShape(RoundedRectangle(cornerRadius: 6))
                        }
                        VStack(alignment: .leading, spacing: 6) {
                            Text("The theorem — a proof of exactly this is what gets paid")
                                .font(.subheadline.bold())
                            code(draft.theorem)
                        }
                        if !draft.preamble.isEmpty {
                            DisclosureGroup("Preamble — definitions and lemmas published with it") {
                                code(draft.preamble)
                            }
                        }
                        if let proof = draft.proof {
                            DisclosureGroup("The model's own proof") {
                                code(proof)
                            }
                        }
                        Text(verbatim: """
                            Kernel time per proof: \(draft.timeoutSeconds) s. A solver submits {"proof": ":= …"}; \
                            sorry, admit, axiom, @[implemented_by] and native_decide are refused before Lean runs.
                            """)
                            .font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        terms
                    }
                }
                .padding(.trailing, 8)
            }
            .frame(minHeight: 260, maxHeight: 520)

            environment
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
                          : "Posting waits for a hole to be refused, the theorem to compile, and the model's proof, if it wrote one, to be accepted.")
            }
        }
    }

    private enum Tone { case good, bad, warn }

    private func results(_ outcome: ChallengeTest.Outcome) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Tested through the node's verifier").font(.subheadline.bold())
            result(outcome.hole.rejected ? .good : .bad, "Refuses a proof that is only a hole",
                   ChallengeTest.Outcome.describe(outcome.hole))
            statementRow(outcome.statement)
            if let proof = outcome.proof {
                result(proof.accepted ? .good : (proof.rejected ? .bad : .warn), "Accepts the model's own proof",
                       ChallengeTest.Outcome.describe(proof))
            } else {
                Label("The model wrote no proof, which is normal for a problem worth paying for. Read the theorem: it is what you are publishing.",
                      systemImage: "info.circle")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    @ViewBuilder private func statementRow(_ statement: ChallengeTest.Statement) -> some View {
        switch statement {
        case .elaborates(let detail): result(.good, "The theorem compiles on its own", "with \(detail)")
        case .broken(let detail): result(.bad, "The theorem does not compile", detail)
        case .untested(let detail): result(.warn, "The theorem was not compiled", detail)
        }
    }

    private func result(_ tone: Tone, _ title: String, _ detail: String) -> some View {
        Label {
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                Text(verbatim: detail)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
        } icon: {
            switch tone {
            case .good: Image(systemName: "checkmark.circle.fill").foregroundStyle(Color.green)
            case .bad: Image(systemName: "xmark.octagon.fill").foregroundStyle(Color.red)
            case .warn: Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Color.orange)
            }
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

    // MARK: the rest

    private var posted: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Posted. It is listed under Objectives once the node is back.", systemImage: "checkmark.circle.fill")
                .foregroundStyle(.green)
            Text("The theorem (Challenge.lean) and the objective are kept in the node's data folder, under challenges/.")
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
/// one needs, and the reason the feature exists. The provider is chosen in
/// the picker above it.
private struct KeySetup: View {
    @ObservedObject var composer: ChallengeComposer
    @State private var pasted = ""

    private var provider: AIProvider { composer.config.provider }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Drafting uses a model you have a key for. Paste one for \(provider.title) to continue.")
                .font(.callout)
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
    }

    private func save() {
        composer.saveKey(pasted)
        pasted = ""
    }
}
