import AppKit
import Combine
import Sparkle
import SwiftUI

/// Check for Updates… and the daily check behind it, by Sparkle.
///
/// The feed is `appcast.xml` on a fixed GitHub release tagged `updates`,
/// which release.yml overwrites only once a release's .dmg is uploaded, so a
/// check never offers a version whose image is not there yet, and a check
/// while that upload is still pending reads the previous feed and says "up to
/// date" rather than failing (releases/latest would 404). Each item is the release's
/// .dmg, which holds the same installer a first install runs: Sparkle mounts
/// it, asks for an administrator password, and runs `Install Cairn.pkg`, which
/// replaces both the `cairn` command and this app and opens the app again.
///
/// An update is installed only if two signatures match the two keys
/// build-dmg.sh wrote into Info.plist from the release's signing key:
///
///   * `SUPublicEDKey`, Ed25519 over the image, which Sparkle checks after
///     the download;
///   * `CairnMLDSA87PublicKey`, ML-DSA-87 -- post-quantum -- over the feed
///     item and that Ed25519 signature, which `UpdateGate` checks before the
///     download (UpdateSignature.swift says why that is as good as over the
///     image).
///
/// A build without both keys -- a checkout's, or a release cut before the
/// key existed -- has nothing to verify an update against, so it never
/// starts Sparkle. A person may open the official release page themselves;
/// this app does not silently download or install an unverified update.
@MainActor
final class Updates: ObservableObject {
    static let releasesURL = URL(string: "https://github.com/aburan28/cairn/releases/latest")!

    private let controller: SPUStandardUpdaterController?
    /// Sparkle holds its delegate weakly; this is the strong reference.
    private let gate: UpdateGate?
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
        let edKey = Bundle.main.object(forInfoDictionaryKey: "SUPublicEDKey") as? String
        guard let edKey, !edKey.trimmingCharacters(in: .whitespaces).isEmpty,
              let pqKey = UpdateSignature.publicKey()
        else {
            controller = nil
            gate = nil
            return
        }
        let gate = UpdateGate(publicKey: pqKey)
        self.gate = gate
        controller = SPUStandardUpdaterController(
            startingUpdater: true, updaterDelegate: gate, userDriverDelegate: nil)
        controller?.updater.publisher(for: \.canCheckForUpdates)
            .receive(on: RunLoop.main)
            .sink { [weak self] in self?.canCheck = $0 }
            .store(in: &observations)
    }

    func check() {
        if let controller {
            controller.checkForUpdates(nil)
            return
        }
        let alert = NSAlert()
        alert.messageText = "This build cannot check for updates"
        alert.informativeText = "This build has no update-signing keys. Cairn cannot verify or install an update from here. Open the official releases page to download the current installer yourself."
        alert.addButton(withTitle: "Open Releases")
        alert.addButton(withTitle: "OK")
        if alert.runModal() == .alertFirstButtonReturn {
            NSWorkspace.shared.open(Self.releasesURL)
        }
    }
}

/// Sparkle's delegate: the one question it is here to answer is whether the
/// update it picked carries a post-quantum signature under the key this app
/// was built with. Thrown errors are shown to the person and stop the
/// update before anything is downloaded.
final class UpdateGate: NSObject, SPUUpdaterDelegate {
    private let publicKey: MLDSA87.PublicKey

    init(publicKey: MLDSA87.PublicKey) {
        self.publicKey = publicKey
    }

    func updater(_ updater: SPUUpdater, shouldProceedWithUpdate updateItem: SUAppcastItem, updateCheck: SPUUpdateCheck) throws {
        try UpdateSignature.check(item: updateItem.propertiesDictionary as? [String: Any] ?? [:], publicKey: publicKey)
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
                Button("Check Now") { updates.check() }
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
            return "This build cannot verify or install updates. Check Now opens the official releases page, where you can download the current installer."
        }
        var text = "An update is installed only if its post-quantum (ML-DSA-87) and Ed25519 signatures match this app's keys. It installs the cairn command and this app together, and asks for an administrator password."
        if let last = updates.lastCheck {
            text += " Last checked \(last.formatted(.relative(presentation: .named)))."
        }
        return text
    }
}
