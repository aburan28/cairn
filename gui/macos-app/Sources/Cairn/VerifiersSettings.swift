import AppKit
import SwiftUI

/// Settings → Verifiers: the toolchains behind what this node can check,
/// found on the PATH the node is given, beside what the running node itself
/// reports (`GET /verifiers`). Two views of one fact, because the second is
/// the one that counts and the first is the one this app can act on.
struct VerifiersSection: View {
    @ObservedObject var node: Node
    @State private var report: ToolchainReport?
    @State private var fromNode: NodeVerifiers?
    @State private var checking = false
    @State private var installing = false
    @State private var checkID = UUID()

    /// The login service still belongs to this app, even though its window
    /// attaches over HTTP. Installing tools here can repair that node.
    private var usesLocalTools: Bool {
        node.settings.verifiersRunLocally(backgroundServiceURL: node.runsInBackground ? BackgroundService.readerURL : nil)
    }

    var body: some View {
        Section {
            if !usesLocalTools {
                Text("Capabilities below belong to the attached node. This Mac is not running its verifiers.")
                    .font(.callout).foregroundStyle(.secondary)
            } else if let report {
                leanRow(report)
                pythonRow(report)
                sandboxRow(report)
            } else {
                HStack {
                    ProgressView().controlSize(.small)
                    Text("Looking…").foregroundStyle(.secondary)
                }
            }
            nodeRow
            HStack {
                Button("Check Again") { Task { await check() } }
                    .disabled(checking)
                if usesLocalTools, report != nil, report?.lean == nil {
                    Button("Install Lean…") { installing = true }
                }
                Spacer()
                if usesLocalTools, let lean = report?.lean, lean.isElan || lean.underHome {
                    Text("Handed to the node as CAIRN_LEAN and CAIRN_LEAN_ROOT.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        } header: {
            Text("Verifiers")
        } footer: {
            Caption(!usesLocalTools ? "The attached node chooses its verifier tools and isolation policy. Install or repair those on the machine running that node." : """
                A challenge drafted here is a Lean theorem, and the node checks proofs with \
                the Lean on this Mac, inside its sandbox. The node answers unavailable, never \
                wrong, for anything it cannot run; a Mac without Lean cannot post a drafted \
                challenge either, since the theorem cannot be compiled first. Python runs the \
                pinned checkers of curated tasks. Both are looked for on the PATH the node is \
                given: ~/.elan/bin, Homebrew, /usr/local/bin and the system.
                """)
        }
        .task(id: node.state) { await check() }
        .sheet(isPresented: $installing) {
            InstallLeanSheet(isPresented: $installing) {
                Task { await check() }
            }
        }
    }

    private func leanRow(_ report: ToolchainReport) -> some View {
        LabeledContent("Lean 4") {
            if let lean = report.lean {
                tool(ok: true, text: "\(lean.version ?? "found") — \(lean.binary.path)")
            } else {
                tool(ok: false, text: report.leanProblem ?? "Not found")
            }
        }
    }

    private func pythonRow(_ report: ToolchainReport) -> some View {
        LabeledContent("Python 3") {
            if let python = report.python {
                tool(ok: report.pythonProblem == nil,
                     text: report.pythonProblem ?? "\(report.pythonVersion ?? "found") — \(python.path)")
            } else {
                tool(ok: false, text: "Not found; the pinned checkers of curated tasks would be unavailable.")
            }
        }
    }

    private func sandboxRow(_ report: ToolchainReport) -> some View {
        LabeledContent("Sandbox") {
            tool(ok: report.sandbox != nil,
                 text: report.sandbox != nil
                     ? "seatbelt (sandbox-exec): no network, declared reads only, a scratch directory to write"
                     : "sandbox-exec is missing; verification is unavailable until a sandbox works")
        }
    }

    @ViewBuilder private var nodeRow: some View {
        if case .running = node.state {
            LabeledContent(usesLocalTools ? "Running node" : "Attached node") {
                if let fromNode {
                    if fromNode.servesLean {
                        tool(ok: true, text: "Serves lean" + (fromNode.lean?.version.map { " (\($0))" } ?? "")
                             + ", sandbox \(fromNode.sandbox.mechanism)")
                    } else {
                        tool(ok: false, text: (fromNode.unservable["lean"] ?? "Cannot serve lean")
                             + (!usesLocalTools ? ". Repair the verifier on the attached node, then restart it." : ". Restart Node after installing."))
                    }
                } else {
                    Text(checking ? "Reading capabilities…" : "Capabilities could not be read. Check the connection and try again; an older node may not support this report.")
                        .font(.callout).foregroundStyle(.secondary)
                }
            }
            if let fromNode {
                LabeledContent("Verifier isolation") {
                    tool(ok: fromNode.sandbox.required && fromNode.sandbox.jail,
                         text: fromNode.sandbox.required
                            ? (fromNode.sandbox.jail ? "Sandbox required: \(fromNode.sandbox.mechanism)" : "Sandbox required; code execution is unavailable")
                            : "Sandbox optional; this node permits unconfined verification")
                }
                if usesLocalTools, !fromNode.sandbox.required {
                    Button("Restart Node to Require Sandbox") { node.restart() }
                    Text("An existing background service keeps its previous environment until restarted. This applies the app's required isolation policy.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }

    private func tool(ok: Bool, text: String) -> some View {
        Label {
            Text(verbatim: text)
                .font(.callout)
                .lineLimit(3)
                .truncationMode(.middle)
                .textSelection(.enabled)
                .multilineTextAlignment(.trailing)
        } icon: {
            Image(systemName: ok ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                .foregroundStyle(ok ? Color.green : Color.gray)
        }
    }

    private func check() async {
        let id = UUID()
        checkID = id
        checking = true
        report = nil
        fromNode = nil
        defer { if checkID == id { checking = false } }
        let settings = node.settings
        let state = node.state
        let localTools = usesLocalTools
        let local: ToolchainReport?
        if !localTools { local = nil }
        else {
            local = await Task.detached(priority: .utility) {
                Toolchains.report(environment: Node.childEnvironment(settings))
            }.value
        }
        guard !Task.isCancelled, checkID == id, node.state == state, usesLocalTools == localTools else { return }
        let remote: NodeVerifiers?
        if case .running(let url) = state { remote = await NodeVerifiers.fetch(readerURL: url) }
        else { remote = nil }
        guard !Task.isCancelled, checkID == id, node.state == state, usesLocalTools == localTools else { return }
        report = local
        fromNode = remote
    }
}

/// Runs Lean's own installer, elan, and shows what it prints. The command
/// is shown before it runs and is the one from Lean's documentation; nothing
/// is hidden from the person who clicks, and nothing needs an administrator
/// password: elan installs under ~/.elan for this user alone.
@MainActor
final class LeanInstaller: ObservableObject {
    @Published private(set) var lines: [String] = []
    @Published private(set) var running = false
    @Published private(set) var exitStatus: Int32?
    private var process: Process?

    func start() {
        guard !running else { return }
        lines = []
        exitStatus = nil
        running = true
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/sh")
        p.arguments = ["-c", Toolchains.elanInstall]
        var env = ProcessInfo.processInfo.environment
        env["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin"
        env["HOME"] = NSHomeDirectory()
        p.environment = env
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        p.standardInput = FileHandle.nullDevice
        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else {
                handle.readabilityHandler = nil
                return
            }
            let text = String(decoding: data, as: UTF8.self)
            Task { @MainActor in self?.append(text) }
        }
        p.terminationHandler = { [weak self] proc in
            let status = proc.terminationStatus
            Task { @MainActor in
                self?.running = false
                self?.exitStatus = status
            }
        }
        do {
            try p.run()
        } catch {
            lines.append("Could not start /bin/sh: \(error.localizedDescription)")
            running = false
            exitStatus = -1
            return
        }
        process = p
    }

    private func append(_ text: String) {
        for piece in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = piece.replacingOccurrences(of: "\r", with: "").trimmingCharacters(in: .whitespaces)
            if !line.isEmpty { lines.append(line) }
        }
        if lines.count > 400 { lines.removeFirst(lines.count - 400) }
    }

    func cancel() { process?.terminate() }
}

struct InstallLeanSheet: View {
    @Binding var isPresented: Bool
    /// Called once the installer has exited 0.
    var onInstalled: () -> Void
    @StateObject private var installer = LeanInstaller()

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Install Lean", systemImage: "arrow.down.circle").font(.headline)
            Text("""
                Lean's own installer, elan, puts the toolchain in ~/.elan for your user only; \
                no administrator password. It is the command from Lean's documentation, run \
                exactly as shown:
                """)
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            command(Toolchains.elanInstall)
            Text(verbatim: "Or, with Homebrew, in a Terminal: \(Toolchains.brewInstall)")
                .font(.caption).foregroundStyle(.secondary)
            if !installer.lines.isEmpty {
                ScrollViewReader { proxy in
                    ScrollView {
                        VStack(alignment: .leading, spacing: 1) {
                            ForEach(Array(installer.lines.enumerated()), id: \.offset) { item in
                                Text(verbatim: item.element)
                                    .font(.caption.monospaced())
                                    .textSelection(.enabled)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .id(item.offset)
                            }
                        }
                        .padding(8)
                    }
                    .frame(height: 180)
                    .background(Color(nsColor: .textBackgroundColor))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                    .onChange(of: installer.lines.count) { count in
                        if count > 0 { proxy.scrollTo(count - 1, anchor: .bottom) }
                    }
                }
            }
            if let status = installer.exitStatus {
                Label(status == 0
                      ? "Installed. The node finds it in ~/.elan/bin, and is handed the toolchain's own binary."
                      : "The installer exited with status \(status). The lines above say why.",
                      systemImage: status == 0 ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(status == 0 ? Color.green : Color.gray)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                if installer.running {
                    ProgressView().controlSize(.small)
                    Button("Stop") { installer.cancel() }
                }
                Spacer()
                Button(installer.exitStatus == 0 ? "Done" : "Cancel") { isPresented = false }
                    .keyboardShortcut(.cancelAction)
                Button("Install") { installer.start() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(installer.running || installer.exitStatus == 0)
            }
        }
        .padding(20)
        .frame(width: 560)
        .onChange(of: installer.exitStatus) { status in
            if status == 0 { onInstalled() }
        }
    }

    private func command(_ text: String) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Text(verbatim: text)
                .font(.caption.monospaced())
                .textSelection(.enabled)
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(nsColor: .textBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 6))
            Button {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(text, forType: .string)
            } label: {
                Image(systemName: "doc.on.doc")
            }
            .buttonStyle(.borderless)
            .help("Copy")
        }
    }
}
