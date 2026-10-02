import AppKit
import Combine
import Sparkle
import SwiftUI

/// Check for Updates… and the daily check behind it, by Sparkle.
///
/// The feed is `appcast.xml` on the newest GitHub release, written by
/// release.yml only once that release's .dmg is uploaded, so a check never
/// offers a version whose image is not there yet. Each item is the release's
/// .dmg, which holds the same installer a first install runs: Sparkle mounts
/// it, asks for an administrator password, and runs `Install Cairn.pkg`, which
/// replaces both the `cairn` command and this app and opens the app again.
///
/// An update is accepted only if its Ed25519 signature matches
/// `SUPublicEDKey`, which build-dmg.sh writes into Info.plist from the
/// release's signing key. A build without one -- a checkout's, or a release
/// cut before the key existed -- has nothing to verify an update against, so
/// it never starts Sparkle, and Check for Updates… opens the releases page
/// instead.
@MainActor
final class Updates: ObservableObject {
    static let releasesPage = URL(string: "https://github.com/aburan28/cairn/releases/latest")!

    private let controller: SPUStandardUpdaterController?
    private var observations: Set<AnyCancellable> = []

    /// Sparkle says no while a check is already running.
    @Published private(set) var canCheck = true

    /// Off for a build that cannot verify an update; see the type's comment.
    var isEnabled: Bool { controller != nil }

    var automaticallyChecks: Bool {
        get { controller?.updater.automaticallyChecksForUpdates ?? false }
        set {
            objectWillChange.send()
            controller?.updater.automaticallyChecksForUpdates = newValue
        }
    }

    var lastCheck: Date? { controller?.updater.lastUpdateCheckDate }

    init() {
        let key = Bundle.main.object(forInfoDictionaryKey: "SUPublicEDKey") as? String
        guard let key, !key.trimmingCharacters(in: .whitespaces).isEmpty else {
            controller = nil
            return
        }
        controller = SPUStandardUpdaterController(
            startingUpdater: true, updaterDelegate: nil, userDriverDelegate: nil)
        controller?.updater.publisher(for: \.canCheckForUpdates)
            .receive(on: RunLoop.main)
            .sink { [weak self] in self?.canCheck = $0 }
            .store(in: &observations)
    }

    func check() {
        if let controller {
            controller.checkForUpdates(nil)
        } else {
            NSWorkspace.shared.open(Self.releasesPage)
        }
    }
}

/// This app's version as a person should read it. build-dmg.sh stamps the
/// release's version into Info.plist; a checkout's build still says 0.0.0,
/// which is not a version anyone released.
enum AppVersion {
    static var release: String? {
        let v = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
        guard let v, v != "0.0.0" else { return nil }
        return v
    }

    static var label: String { release ?? "development build" }

    /// True when both are known and disagree: the .dmg installs the two
    /// together, so a difference means one was replaced by some other route.
    static func differs(fromNode node: String?) -> Bool {
        guard let release, let node else { return false }
        return release != node
    }
}

/// About Cairn, with the `cairn` command's version under the app's: the
/// standard panel knows only the bundle's.
@MainActor
func showAboutPanel(node: Node) {
    var credits: [String] = []
    if let v = node.binaryVersion {
        credits.append("cairn command \(v)")
        if AppVersion.differs(fromNode: v) {
            credits.append("The app and the command are different versions. Check for Updates, or install the newest .dmg, to bring them together.")
        }
    } else if node.isAttached {
        credits.append("Attached to another node; its reader shows its version.")
    }
    var options: [NSApplication.AboutPanelOptionKey: Any] = [
        .credits: NSAttributedString(
            string: credits.joined(separator: "\n"),
            attributes: [
                .font: NSFont.systemFont(ofSize: NSFont.smallSystemFontSize),
                .foregroundColor: NSColor.secondaryLabelColor,
            ]),
    ]
    if AppVersion.release == nil {
        options[.applicationVersion] = AppVersion.label
        options[.version] = ""
    }
    NSApp.activate(ignoringOtherApps: true)
    NSApp.orderFrontStandardAboutPanel(options: options)
}

/// The app menu's item, under About Cairn, where a Mac app keeps it.
struct CheckForUpdatesButton: View {
    @ObservedObject var updates: Updates

    var body: some View {
        Button("Check for Updates…") { updates.check() }
            .disabled(!updates.canCheck)
    }
}

/// Settings' section: whether to look once a day, and when it last looked.
struct UpdatesSection: View {
    @ObservedObject var updates: Updates
    let nodeVersion: String?

    var body: some View {
        Section {
            if updates.isEnabled {
                Toggle("Check for updates automatically", isOn: Binding(
                    get: { updates.automaticallyChecks },
                    set: { updates.automaticallyChecks = $0 }
                ))
            }
            LabeledContent(version) {
                Button(updates.isEnabled ? "Check Now" : "Open Releases Page") { updates.check() }
                    .disabled(!updates.canCheck)
            }
            if let nodeVersion {
                LabeledContent("cairn command") { Text(verbatim: nodeVersion) }
            }
        } header: {
            Text("Updates")
        } footer: {
            Text(footer)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var version: String { "Cairn \(AppVersion.label)" }

    private var footer: String {
        guard updates.isEnabled else {
            return "This build cannot verify updates, so it does not install them. Download the newest .dmg from the releases page."
        }
        var text = "An update installs the cairn command and this app together, and asks for an administrator password."
        if let last = updates.lastCheck {
            text += " Last checked \(last.formatted(.relative(presentation: .named)))."
        }
        return text
    }
}
