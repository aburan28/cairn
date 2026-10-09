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
    @AppStorage("workThreads") private var threads = max(1, ProcessInfo.processInfo.activeProcessorCount)
    @AppStorage("workGPUEnabled") private var gpuEnabled = false
    @AppStorage("workGPUNumbers") private var gpuNumbers = "0"
    @AppStorage("workHoursPerDay") private var hoursPerDay = 24
    @AppStorage("workOrbitBatch") private var orbitBatch = 4
    @State private var showSolverOptions = false
    @State private var useCustomSolver = false

    private var bundledWork: (solver: String, arguments: [String])? {
        let environment = ProcessInfo.processInfo.environment
        let configured = environment["CAIRN_PYTHON"]?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let directories = ["/opt/homebrew/bin", "/usr/local/bin"]
            + Toolchains.searchPath(environment) + ["/usr/bin"]
        let candidates = configured.isEmpty ? directories.map { URL(fileURLWithPath: $0).appendingPathComponent("python3") }
            : configured.contains("/") ? [URL(fileURLWithPath: configured)]
            : directories.map { URL(fileURLWithPath: $0).appendingPathComponent(configured) }
        let python = candidates.first {
            FileManager.default.isExecutableFile(atPath: $0.path) && !Toolchains.isShim($0)
        }
        return GuiTasks.bundledWork(for: objective, python: python, count: orbitBatch)
    }

    private var usesBundledWork: Bool { bundledWork != nil && !useCustomSolver }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Work on this Mac", systemImage: "cpu").font(.headline)
            Text("Choose an objective and the resources this Mac may use. Cairn assigns a new slice each round and keeps pending answers moving while paused or stopping. The objective's checker decides what is paid.")
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
                    if bundledWork != nil {
                        Picker("Search program", selection: $useCustomSolver) {
                            Text("Included orbit search").tag(false)
                            Text("Choose another program").tag(true)
                        }
                        .labelsHidden()
                        .disabled(worker.isRunning)
                    }
                    if usesBundledWork {
                        Stepper("\(orbitBatch) orbits per round", value: $orbitBatch, in: 1...16)
                            .disabled(worker.isRunning)
                        Text("Ready to run from this app. No program or checkout to choose.")
                            .font(.caption).foregroundStyle(.secondary)
                    } else {
                        HStack {
                            TextField("A program on this Mac", text: $solver)
                                .textFieldStyle(.roundedBorder)
                                .font(.body.monospaced())
                                .disabled(worker.isRunning)
                            Button("Choose…") { chooseSolver() }
                                .disabled(worker.isRunning)
                        }
                        DisclosureGroup("Advanced solver options", isExpanded: $showSolverOptions) {
                            TextField("Options for this solver", text: $solverArguments)
                                .textFieldStyle(.roundedBorder)
                                .disabled(worker.isRunning)
                        }
                        Text("Choose the search program installed on this Mac. Cairn runs it for each assigned slice.")
                            .font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            GridRow {
                Text("CPU cores").gridColumnAlignment(.trailing)
                if usesBundledWork {
                    Text("1 core for the included search").foregroundStyle(.secondary)
                } else {
                    Stepper("Offer \(threads) of \(ProcessInfo.processInfo.activeProcessorCount) CPU threads", value: $threads,
                            in: 1...max(1, ProcessInfo.processInfo.activeProcessorCount))
                        .disabled(worker.isRunning)
                }
            }
            GridRow {
                Text("GPU").gridColumnAlignment(.trailing)
                if usesBundledWork {
                    Text("CPU search; choose another program for GPU work")
                        .foregroundStyle(.secondary)
                } else {
                    HStack {
                        Toggle("Allow GPU use", isOn: $gpuEnabled)
                            .disabled(worker.isRunning)
                        if gpuEnabled {
                            TextField("Device numbers, e.g. 0,1", text: $gpuNumbers)
                                .textFieldStyle(.roundedBorder)
                                .frame(width: 170)
                                .disabled(worker.isRunning)
                        }
                    }
                }
            }
            GridRow {
                Text("Daily limit").gridColumnAlignment(.trailing)
                Stepper(hoursPerDay == 24 ? "Run any time" : "Up to \(hoursPerDay) hours per UTC day",
                        value: $hoursPerDay, in: 1...24)
                    .disabled(worker.isRunning)
            }
            GridRow {
                Text("")
                Text("CPU and GPU choices are passed to the solver; the solver must honor them. The daily time limit is enforced between rounds.")
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
        let included = usesBundledWork ? bundledWork : nil
        return WorkPlan(
            node: address.trimmingCharacters(in: .whitespacesAndNewlines),
            objective: objective,
            worker: WorkPlan.cleanName(name.isEmpty ? WorkPlan.defaultName() : name),
            identity: node.settings.workerIdentity.path,
            solver: included?.solver ?? solver.trimmingCharacters(in: .whitespacesAndNewlines),
            solverArguments: included?.arguments ?? WorkPlan.splitArguments(solverArguments),
            threads: included == nil ? threads : 1,
            gpus: included == nil && gpuEnabled ? gpuNumbers.trimmingCharacters(in: .whitespacesAndNewlines) : "",
            hoursPerDay: hoursPerDay
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
            threads = plan.threads ?? threads
            gpuEnabled = !(plan.gpus ?? "").isEmpty
            if let gpus = plan.gpus, !gpus.isEmpty { gpuNumbers = gpus }
            hoursPerDay = plan.hoursPerDay ?? 24
            if let included = bundledWork { useCustomSolver = plan.solverArguments.first != included.arguments.first }
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
