import AppKit
import SwiftUI

/// Check for Updates…, and what an automatic check opens when it finds one:
/// what is installed, what is out, the release's changelog, and the one
/// button that installs it.
struct UpdateSheet: View {
    @ObservedObject var updater: Updater
    @ObservedObject var node: Node
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .top, spacing: 14) {
                Image(nsImage: NSApp.applicationIconImage)
                    .resizable()
                    .frame(width: 56, height: 56)
                VStack(alignment: .leading, spacing: 4) {
                    Text(headline).font(.title3.weight(.semibold))
                    Text(installedSummary)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            content
        }
        .padding(20)
        .frame(width: 540)
        // Past the password dialog the app is about to quit; a sheet closed
        // then would only hide that it is.
        .interactiveDismissDisabled(isBusy)
    }

    private var isBusy: Bool {
        switch updater.phase {
        case .idle, .checking: return false
        default: return true
        }
    }

    private var headline: String {
        switch updater.phase {
        case .checking: return "Checking for updates…"
        case .downloading, .verifying, .authorizing, .installing:
            return "Updating to Cairn \(updater.available?.version.description ?? "")"
        case .idle:
            if updater.problem != nil { return "Something went wrong" }
            if let release = updater.available { return "Cairn \(release.version) is available" }
            if updater.latest != nil {
                return updater.installed.isEmpty ? "The newest release" : "Cairn is up to date"
            }
            return "Software Update"
        }
    }

    private var installedSummary: String {
        let app = AppVersion.release.map { "This is Cairn \($0)" } ?? "This is a development build of Cairn.app"
        guard let cli = node.cliVersion else { return app + "." }
        if let release = AppVersion.release, release.description == cli {
            return app + ", and the cairn command it runs is the same version."
        }
        return app + ". The cairn command it runs is \(cli)."
    }

    @ViewBuilder private var content: some View {
        switch updater.phase {
        case .checking:
            ProgressView().controlSize(.small)
        case .downloading(let received, let total):
            progress(
                total > 0 ? Double(received) / Double(total) : nil,
                downloading(received, of: total),
                cancellable: true
            )
        case .verifying:
            progress(nil, "Checking the download against its published SHA-256…", cancellable: false)
        case .authorizing:
            progress(nil, "Waiting for an administrator password. The installer runs as root, as it does when opened by hand.", cancellable: false)
        case .installing:
            progress(nil, "Installing. Cairn quits now, stopping its node, and opens again when the installer has finished.", cancellable: false)
        case .idle:
            if let problem = updater.problem {
                failed(problem)
            } else if let release = updater.available {
                offer(release)
            } else if let latest = updater.latest {
                upToDate(latest)
            } else {
                Text("Cairn has not checked for updates yet.").foregroundStyle(.secondary)
                buttons { Button("Check Now") { updater.checkNow() }.keyboardShortcut(.defaultAction) }
            }
        }
    }

    // MARK: states

    private func offer(_ release: Release) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            ScrollView {
                Text(Self.notes(release.notes))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10)
            }
            .frame(minHeight: 120, maxHeight: 260)
            .background(Color(nsColor: .textBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 6))

            if !updater.canInstallInPlace {
                Text("""
                    A development build is not replaced in place: installing here would put \
                    the release in /Applications and quit the build you are running. Install \
                    it from the release page instead.
                    """)
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else if release.installer == nil {
                Text(verbatim: """
                    The Mac installer for \(release.version) is still being uploaded. \
                    Cairn checks again in a few minutes.
                    """)
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                Text("""
                    Installing stops the node, asks for an administrator password, and opens \
                    Cairn again when it is done. The data folder — the ledger and this node's \
                    identity — is not touched.
                    """)
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            buttons {
                Button("Skip This Version") { updater.skip() }
                Button("Release Page") { NSWorkspace.shared.open(release.page) }
                Spacer()
                Button("Later") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                if !updater.canInstallInPlace {
                    Button("Open Release Page") {
                        NSWorkspace.shared.open(release.page)
                        dismiss()
                    }
                    .keyboardShortcut(.defaultAction)
                } else {
                    Button("Install and Relaunch") { updater.install() }
                        .keyboardShortcut(.defaultAction)
                        .disabled(release.installer == nil)
                }
            }
        }
    }

    private func upToDate(_ latest: Release) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(verbatim: updater.installed.isEmpty
                ? "The newest release is \(latest.version). This build cannot tell whether it is older."
                : "\(latest.version) is the newest release.")
            if let when = updater.lastChecked {
                Text("Checked \(when.formatted(.relative(presentation: .named))).")
                    .font(.callout).foregroundStyle(.secondary)
            }
            buttons {
                Button("Release Page") { NSWorkspace.shared.open(latest.page) }
                Spacer()
                Button("OK") { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
    }

    private func failed(_ problem: String) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(problem)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
            buttons {
                if FileManager.default.fileExists(atPath: Updater.logFile.path) {
                    Button("Show Update Log") { NSWorkspace.shared.open(Updater.logFile) }
                }
                Spacer()
                Button("Close") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Check Again") { updater.checkNow() }.keyboardShortcut(.defaultAction)
            }
        }
    }

    private func progress(_ fraction: Double?, _ text: String, cancellable: Bool) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            if let fraction {
                ProgressView(value: fraction)
            } else {
                ProgressView().progressViewStyle(.linear)
            }
            Text(text)
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if cancellable {
                buttons {
                    Spacer()
                    Button("Cancel") { updater.cancel() }.keyboardShortcut(.cancelAction)
                }
            }
        }
    }

    private func buttons<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
        HStack { content() }.padding(.top, 4)
    }

    private func downloading(_ received: Int64, of total: Int64) -> String {
        let name = updater.available?.installer?.name ?? "the release"
        let done = ByteCountFormatter.string(fromByteCount: received, countStyle: .file)
        guard total > 0 else { return "Downloading \(name)… \(done)" }
        let all = ByteCountFormatter.string(fromByteCount: total, countStyle: .file)
        return "Downloading \(name)… \(done) of \(all)"
    }

    /// The changelog release-please writes, readable as text. `Text` renders
    /// inline Markdown -- links, emphasis -- but not headings or lists, which
    /// would show as `##` and `*`; those become bold lines and bullets.
    static func notes(_ markdown: String) -> AttributedString {
        var lines: [String] = []
        for raw in markdown.components(separatedBy: .newlines) {
            var line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("#") {
                line = String(line.drop(while: { $0 == "#" })).trimmingCharacters(in: .whitespaces)
                if !line.isEmpty { line = "**\(line)**" }
            } else if line.hasPrefix("* ") || line.hasPrefix("- ") {
                line = "• " + line.dropFirst(2)
            }
            // One blank line between blocks, however many the source had.
            if line.isEmpty, lines.last?.isEmpty ?? true { continue }
            lines.append(line)
        }
        let text = lines.joined(separator: "\n").trimmingCharacters(in: .whitespacesAndNewlines)
        if text.isEmpty { return AttributedString("No release notes.") }
        let options = AttributedString.MarkdownParsingOptions(interpretedSyntax: .inlineOnlyPreservingWhitespace)
        return (try? AttributedString(markdown: text, options: options)) ?? AttributedString(text)
    }
}
