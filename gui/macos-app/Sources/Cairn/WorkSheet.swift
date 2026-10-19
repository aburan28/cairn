import AppKit
import SwiftUI

/// Node → Share this Mac…: choose an objective and what this Mac may give it,
/// then press Start.
///
/// There is no program to choose. The objective's author published a solver
/// package with it (`cairn solver add`, docs/solvers.md), the node checked it
/// against the objective's own verifier, and `cairn work --package auto`
/// fetches it, checks every file against its pin, runs its tests on this Mac
/// and runs each round in the sandbox: no network, nothing of the person's
/// files, held to the cores they offered. An objective nobody has published a
/// solver for cannot be started here; the page offers an agent instead.
///
/// The fields are `cairn work`'s flags and nothing else. The node's pinned
/// checker decides what is paid.
struct WorkSheet: View {
    @ObservedObject var node: Node
    @ObservedObject var worker: Worker
    @Binding var isPresented: Bool

    @State private var address = ""
    @State private var objective = ""
    @State private var objectives: [WorkObjective] = []
    @State private var loadingObjectives = false
    @State private var objectivesProblem: String?
    @State private var problem: String?
    @AppStorage("workName") private var name = ""
    @AppStorage("workThreads") private var threads = max(1, ProcessInfo.processInfo.activeProcessorCount)
    @AppStorage("workHoursPerDay") private var hoursPerDay = 24

    private var selected: WorkObjective? { objectives.first(where: { $0.id == objective }) }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Share this Mac", systemImage: "cpu").font(.headline)
            Text("Choose an objective and what this Mac may give it. Cairn runs the solver its author published, in a sandbox, on a new slice each round, and keeps pending answers moving while paused or stopping. The objective's checker decides what is paid.")
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            form

            if let problem {
                Label(problem, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout).foregroundStyle(.red)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }

            status

            HStack {
                if worker.isRunning {
                    if worker.isPaused {
                        Button("Resume") { problem = worker.resume() }
                            .disabled(worker.isDraining)
                    } else {
                        Button("Pause") { problem = worker.requestPause() }
                            .disabled(worker.isDraining)
                    }
                    Button(worker.isDraining ? "Finishing pending answers…" : "Stop") {
                        problem = worker.requestStop()
                    }.disabled(worker.isDraining)
                    Button("Exit task") {
                        problem = node.exitWork()
                        if problem == nil { objective = "" }
                    }.disabled(worker.isLeaving)
                } else {
                    Button("Start") { start() }
                        .keyboardShortcut(.defaultAction)
                        .disabled(startProblem != nil)
                        .help(startProblem ?? "Start this objective on this Mac")
                    if worker.lastPlan != nil {
                        Button("Exit task") {
                            problem = node.exitWork()
                            if problem == nil { objective = "" }
                        }
                    }
                }
                Button("Show Log") {
                    NSWorkspace.shared.open(node.workLogFile)
                }
                .disabled(!FileManager.default.fileExists(atPath: node.workLogFile.path))
                Spacer()
                Button(worker.isRunning ? "Keep Working" : "Done") { isPresented = false }
                    .keyboardShortcut(.cancelAction)
                    .help(worker.isRunning ? "Close this sheet; the worker keeps running until you stop it or quit" : "Close")
            }
        }
        .padding(20)
        .frame(width: 640)
        .onAppear(perform: fill)
        .task(id: address) { await loadObjectives() }
    }

    private var form: some View {
        Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 12, verticalSpacing: 10) {
            GridRow {
                Text("Challenge").gridColumnAlignment(.trailing)
                HStack {
                    Picker("Challenge", selection: $objective) {
                        if objectives.isEmpty {
                            Text(loadingObjectives ? "Reading open challenges…" : "No open challenges on this node").tag("")
                        } else {
                            Text("Choose a challenge…").tag("")
                            ForEach(objectives) { o in
                                Text("\(o.title) · \(o.workerLabel)").tag(o.id)
                            }
                        }
                    }
                    .labelsHidden()
                    .disabled(worker.isRunning || objectives.isEmpty)
                    Button("Refresh") { Task { await loadObjectives() } }
                        .controlSize(.small)
                        .disabled(loadingObjectives || worker.isRunning)
                }
            }
            if let selected {
                GridRow {
                    Text("").gridColumnAlignment(.trailing)
                    Text("Needs \(selected.resourceLabel)")
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            GridRow {
                Text("Node").gridColumnAlignment(.trailing)
                TextField("http://host:port", text: $address)
                    .textFieldStyle(.roundedBorder)
                    .font(.body.monospaced())
                    .disabled(worker.isRunning)
            }
            if let objectivesProblem {
                GridRow {
                    Text("")
                    Text(objectivesProblem).font(.caption).foregroundStyle(.red)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            GridRow {
                Text("Name").gridColumnAlignment(.trailing)
                VStack(alignment: .leading, spacing: 3) {
                    TextField(WorkPlan.defaultName(), text: $name)
                        .textFieldStyle(.roundedBorder)
                        .font(.body.monospaced())
                        .disabled(worker.isRunning)
                    Text("Shown on the roster. Two machines with different names take different slices.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            GridRow {
                Text("Solver").gridColumnAlignment(.trailing)
                solverInfo
            }
            GridRow {
                Text("CPU cores").gridColumnAlignment(.trailing)
                Stepper("Offer \(threads) of \(ProcessInfo.processInfo.activeProcessorCount) CPU threads", value: $threads,
                        in: 1...max(1, ProcessInfo.processInfo.activeProcessorCount))
                    .disabled(worker.isRunning)
            }
            GridRow {
                Text("Daily limit").gridColumnAlignment(.trailing)
                Stepper(hoursPerDay == 24 ? "Run any time" : "Up to \(hoursPerDay) hours per UTC day",
                        value: $hoursPerDay, in: 1...24)
                    .disabled(worker.isRunning)
            }
            GridRow {
                Text("")
                Text("The sandbox holds the solver to the threads you offer and gives it no network and none of your files. The daily limit is checked between rounds.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    @ViewBuilder private var status: some View {
        switch worker.state {
        case .idle:
            EmptyView()
        case .running(let plan, let since):
            VStack(alignment: .leading, spacing: 6) {
                Label("\(worker.isDraining ? "Finishing pending answers" : worker.isPaused ? (worker.pauseAcknowledged ? "Paused" : "Pausing after this round") : "Working") as \(plan.worker) since \(since.formatted(date: .omitted, time: .shortened)). Paid to this Mac's worker key.",
                      systemImage: "circle.fill")
                    .font(.callout).foregroundStyle(.green)
                log
            }
        case .exited(let plan, let status):
            VStack(alignment: .leading, spacing: 6) {
                Label(status == 0 ? "\(plan.worker) finished." : "\(plan.worker) stopped (status \(status)). The last lines say why.",
                      systemImage: status == 0 ? "checkmark.circle" : "exclamationmark.triangle")
                    .font(.callout).foregroundStyle(status == 0 ? Color.secondary : Color.gray)
                log
            }
        }
    }

    /// What will run: the published package, read-only. Nothing here is a
    /// path or a flag, because nothing a person types should become a
    /// program this Mac executes.
    @ViewBuilder private var solverInfo: some View {
        VStack(alignment: .leading, spacing: 3) {
            switch selected?.solver {
            case .some(let solver) where solver.ready:
                Text("\(solver.name) \(solver.version)").font(.body.monospaced())
                Text(solver.pinned
                     ? "Published with this objective and checked by the node. Runs in a sandbox: no network, no access to your files."
                     : "Published for this objective and checked by the node. Runs in a sandbox: no network, no access to your files.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            case .some:
                Text("This objective's solver is not on this node yet.")
                Text("It pins a solver package this node does not hold. Its operator adds it with `cairn solver add`.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            case .none where selected != nil:
                Text("No solver has been published for this objective.")
                Text("Its author publishes one with `cairn solver add`. Until then it can be worked with an agent from its page.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            case .none:
                Text("Choose an objective.").foregroundStyle(.secondary)
            }
        }
    }

    private var log: some View {
        ScrollView {
            Text(worker.lines.suffix(12).joined(separator: "\n"))
                .font(.caption.monospaced())
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(8)
        }
        .frame(height: 120)
        .background(Color(nsColor: .textBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 6))
    }

    private var plan: WorkPlan {
        WorkPlan(
            node: address.trimmingCharacters(in: .whitespacesAndNewlines),
            objective: objective,
            worker: WorkPlan.cleanName(name.isEmpty ? WorkPlan.defaultName() : name),
            identity: node.settings.workerIdentity.path,
            threads: threads,
            hoursPerDay: hoursPerDay
        )
    }

    private var startProblem: String? {
        if let problem = plan.problem { return problem }
        if let selected, !selected.canStart {
            return selected.solver == nil
                ? "No solver has been published for this objective."
                : "This objective's solver is not on this node yet."
        }
        return nil
    }

    /// This node's address and the objective the page asked for, unless a
    /// worker is up, whose plan the fields show as it is.
    private func fill() {
        if let plan = worker.lastPlan {
            address = plan.node
            objective = plan.objective
            if name.isEmpty { name = plan.worker }
            threads = plan.threads ?? threads
            hoursPerDay = plan.hoursPerDay ?? 24
            return
        }
        if address.isEmpty, let own = node.httpOrigin { address = own }
        if let wanted = node.workObjective { objective = wanted }
    }

    private func loadObjectives() async {
        let base = address.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: base), url.host != nil,
              let route = URL(string: "/objectives", relativeTo: url)?.absoluteURL
        else {
            objectives = []
            return
        }
        loadingObjectives = true
        defer { loadingObjectives = false }
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 5
        do {
            let (data, response) = try await URLSession(configuration: config).data(from: route)
            guard (response as? HTTPURLResponse)?.statusCode == 200 else {
                throw TaskError("\(base) answered \((response as? HTTPURLResponse)?.statusCode ?? 0) for /objectives.")
            }
            let listed = WorkObjective.parse(try JSONSerialization.jsonObject(with: data)).filter(\.open)
            objectives = listed
            objectivesProblem = nil
            // A chosen objective that node does not have is nobody's to
            // work; the first open one is a better start than a blank.
            if !listed.contains(where: { $0.id == objective }) {
                objective = listed.first?.id ?? ""
            }
        } catch {
            objectives = []
            objectivesProblem = "Could not read the objectives at \(base): \(error.localizedDescription)"
        }
    }

    private func start() {
        problem = node.startWork(plan)
    }
}
