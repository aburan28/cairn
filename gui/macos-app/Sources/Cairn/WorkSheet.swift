import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// Node → Work on This Mac…: put this Mac to work on one objective with a
/// solver of your own, without a terminal.
///
/// The fields are `cairn work`'s flags and nothing else, so what this sheet
/// starts is exactly what the Contribute page used to print for a terminal.
/// The solver is still yours: the sheet runs it, each round, with its slice
/// of the work on stdin, and hands what it prints to the node. The node's
/// pinned checker decides what is paid.
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
    /// Remembered between openings: the solver is the one thing here a
    /// person has to find on disk, and they have one or two.
    @AppStorage("workSolver") private var solver = ""
    @AppStorage("workSolverArguments") private var solverArguments = ""
    @AppStorage("workName") private var name = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Work on this Mac", systemImage: "cpu").font(.headline)
            Text("""
                Each round, this Mac takes its slice of the objective's search and runs your \
                solver on it: the slice arrives as one line of JSON on the solver's stdin, and \
                every line of JSON it prints is a candidate answer. Cairn commits each one, \
                reveals it after the epoch turns, and reports in so this Mac shows as \
                *working now* on the challenge page. Only the objective's pinned checker \
                decides what is paid; nothing a solver prints is graded here.
                """)
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
                    Button(worker.isDraining ? "Finishing pending answers…" : "Stop safely") {
                        problem = worker.requestStop()
                    }
                    .disabled(worker.isDraining)
                } else {
                    Button("Start") { start() }
                        .keyboardShortcut(.defaultAction)
                        .disabled(startProblem != nil)
                        .help(startProblem ?? "Start cairn work on this Mac")
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
                Text("Node").gridColumnAlignment(.trailing)
                TextField("http://host:port", text: $address)
                    .textFieldStyle(.roundedBorder)
                    .font(.body.monospaced())
                    .disabled(worker.isRunning)
            }
            GridRow {
                Text("Objective").gridColumnAlignment(.trailing)
                HStack {
                    Picker("Objective", selection: $objective) {
                        if objectives.isEmpty {
                            Text(loadingObjectives ? "Reading the node…" : "No open objective on that node").tag("")
                        } else {
                            Text("Choose…").tag("")
                            ForEach(objectives) { o in
                                Text(o.title).tag(o.id)
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
                VStack(alignment: .leading, spacing: 3) {
                    HStack {
                        TextField("A program on this Mac", text: $solver)
                            .textFieldStyle(.roundedBorder)
                            .font(.body.monospaced())
                            .disabled(worker.isRunning)
                        Button("Choose…") { chooseSolver() }
                            .disabled(worker.isRunning)
                    }
                    TextField("Its arguments, if any", text: $solverArguments)
                        .textFieldStyle(.roundedBorder)
                        .font(.body.monospaced())
                        .disabled(worker.isRunning)
                    Text("Run once per round with the slice on stdin; prints candidate answers, one JSON object per line. Exit 0 with nothing printed means nothing this round.")
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    @ViewBuilder private var status: some View {
        switch worker.state {
        case .idle:
            EmptyView()
        case .running(let plan, let since):
            VStack(alignment: .leading, spacing: 6) {
                Label("\(worker.isDraining ? "Finishing pending answers" : "Working") as \(plan.worker) since \(since.formatted(date: .omitted, time: .shortened)). Paid to this Mac's worker key.",
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
            solver: solver.trimmingCharacters(in: .whitespacesAndNewlines),
            solverArguments: WorkPlan.splitArguments(solverArguments)
        )
    }

    private var startProblem: String? { plan.problem }

    /// This node's address and the objective the page asked for, unless a
    /// worker is up, whose plan the fields show as it is.
    private func fill() {
        if let plan = worker.lastPlan {
            address = plan.node
            objective = plan.objective
            if name.isEmpty { name = plan.worker }
            if solver.isEmpty { solver = plan.solver }
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

    private func chooseSolver() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [.executable, .shellScript, .pythonScript, .unixExecutable, .data]
        panel.message = "Choose the program that searches for answers. It gets its slice of the work on stdin and prints candidates, one JSON object per line."
        panel.prompt = "Use as Solver"
        if panel.runModal() == .OK, let url = panel.url {
            solver = url.path
        }
    }

    private func start() {
        problem = node.startWork(plan)
    }
}
