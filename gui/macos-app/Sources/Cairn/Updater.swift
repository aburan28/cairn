import AppKit
import CryptoKit
import Foundation

/// Whether a newer Cairn has been released, and installing it when asked.
///
/// The update is the release's own disk image -- the same `Install Cairn.pkg`
/// a person would download and open, with the same `preinstall-app` and
/// `postinstall-app` -- installed with `installer` as root. There is no second
/// install path to keep in step with the first, and nothing here knows what a
/// release contains: if the package grows a file, the update carries it.
///
/// What it checks and what it cannot:
///
/// - The image has to match the `.sha256` beside it **and** the SHA-256
///   GitHub recorded for the asset at upload, and is hashed again as root on
///   a root-owned copy right before `installer` runs (`InstallScript`).
///   That catches a damaged download and a package swapped on this Mac
///   between the check and the install.
/// - It does not catch a substituted release. Whoever can publish one can
///   publish a matching checksum, and nothing is signed by a key of this
///   project's -- the "substituted release" row of docs/threat-model.md,
///   which an update inherits rather than improves on.
///
/// So it never installs unasked. Checking is automatic; installing takes a
/// click and an administrator password, every time.
@MainActor
final class Updater: ObservableObject {
    enum Key {
        /// Whether to check without being asked, at launch and every `interval`.
        static let automatic = "checkForUpdates"
        /// A tag "Skip This Version" was chosen for: no badge, no sheet,
        /// until a newer one.
        static let skipped = "skippedUpdateVersion"
        /// The last tag the sheet opened by itself for, so an automatic check
        /// interrupts once per release rather than once per check.
        static let announced = "announcedUpdateVersion"
        /// Set just before quitting to install. The next launch reads it to
        /// tell an update that landed from one that did not.
        static let pending = "pendingUpdateVersion"
        static let lastChecked = "lastUpdateCheck"
    }

    enum Phase: Equatable {
        case idle
        case checking
        case downloading(received: Int64, total: Int64)
        case verifying
        case authorizing
        case installing
    }

    /// Six hours: a node is long-lived, and one left running for a week
    /// should hear about a release the day it ships. One small GET against
    /// GitHub's 60-an-hour unauthenticated limit.
    static let interval: TimeInterval = 6 * 60 * 60
    /// Sooner while the newest release's image is still uploading.
    static let uploadRetry: TimeInterval = 15 * 60
    static let logFile = URL(fileURLWithPath: "/Library/Logs/Cairn/update.log")

    @Published private(set) var phase: Phase = .idle
    @Published private(set) var latest: Release?
    @Published private(set) var lastChecked: Date?
    /// What the sheet says went wrong: an install, a check somebody asked
    /// for, or an update that did not land. Automatic checks never set or
    /// clear it -- a background check that fails because the Mac is offline
    /// is not news, and one that succeeds must not wipe a failed install off
    /// the sheet seconds after the window opened to say so.
    @Published private(set) var problem: String?
    /// Why the last check of either kind failed, for Settings.
    @Published private(set) var checkFailure: String?
    @Published var presentSheet = false

    private let node: Node
    private let defaults = UserDefaults.standard
    private var loop: Task<Void, Never>?
    private var job: Task<Void, Never>?

    init(node: Node) {
        self.node = node
        defaults.register(defaults: [Key.automatic: true])
        lastChecked = defaults.object(forKey: Key.lastChecked) as? Date
    }

    // MARK: what is installed, and what is newer

    /// Every version on this Mac an update would replace: the app's, when it
    /// is a release, and the `cairn` it last ran. One package installs both,
    /// so either being behind is reason enough.
    var installed: [SemVer] {
        [AppVersion.release, node.cliVersion.flatMap(SemVer.init)].compactMap { $0 }
    }

    /// The newest release, if it is newer than something installed.
    var available: Release? {
        guard let latest, installed.contains(where: { latest.version > $0 }) else { return nil }
        return latest
    }

    /// What the toolbar shows a button for: an update nobody said to skip.
    var badge: Release? {
        guard let available, available.tag != defaults.string(forKey: Key.skipped) else { return nil }
        return available
    }

    /// A checkout's build is not replaced in place. Installing would put the
    /// release in /Applications and quit the build someone is working on;
    /// the sheet offers the release page instead.
    var canInstallInPlace: Bool { AppVersion.release != nil }

    /// `CAIRN_UPDATES=off` at launch, as `CAIRN_SEEDS=off` is for seeds:
    /// for a run that must not reach GitHub, without touching Settings.
    var disabledByEnvironment: Bool {
        ProcessInfo.processInfo.environment["CAIRN_UPDATES"]?.lowercased() == "off"
    }

    var checksAutomatically: Bool {
        !disabledByEnvironment && defaults.bool(forKey: Key.automatic)
    }

    // MARK: checking

    /// At launch: say whether the last install landed, then check now and
    /// every `interval`. The first check waits a few seconds so the node's
    /// start has the machine to itself.
    func start() {
        reportUnfinishedInstall()
        loop?.cancel()
        loop = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 5_000_000_000)
            while !Task.isCancelled {
                guard let self else { return }
                if self.checksAutomatically { await self.check(userInitiated: false) }
                let uploading = self.available != nil && self.available?.installer == nil
                let wait = uploading ? Self.uploadRetry : Self.interval
                try? await Task.sleep(nanoseconds: UInt64(wait * 1_000_000_000))
            }
        }
    }

    /// The menu item and the Settings button: check, and show the answer
    /// whatever it is, including "up to date".
    func checkNow() {
        presentSheet = true
        Task { await check(userInitiated: true) }
    }

    func check(userInitiated: Bool) async {
        guard phase == .idle else { return }
        phase = .checking
        checkFailure = nil
        if userInitiated { problem = nil }
        defer { if phase == .checking { phase = .idle } }
        do {
            latest = try await Fetch.latest()
            let now = Date()
            lastChecked = now
            defaults.set(now, forKey: Key.lastChecked)
            // Opened by itself once per release, and only for one there is
            // something to install from.
            if !userInitiated, let release = badge, release.installer != nil,
               release.tag != defaults.string(forKey: Key.announced) {
                defaults.set(release.tag, forKey: Key.announced)
                presentSheet = true
            }
        } catch {
            let message = "Could not check for updates: \(error.localizedDescription)"
            checkFailure = message
            if userInitiated { problem = message }
        }
    }

    func skip() {
        if let available { defaults.set(available.tag, forKey: Key.skipped) }
        presentSheet = false
    }

    /// The window that opens after an install says nothing when it is the
    /// version it was meant to be. One that is still the old version is the
    /// old app, reopened by `InstallScript.finish` after `installer` failed,
    /// and that is worth saying, with where to look.
    private func reportUnfinishedInstall() {
        guard let pending = defaults.string(forKey: Key.pending) else { return }
        defaults.removeObject(forKey: Key.pending)
        guard let wanted = SemVer(pending) else { return }
        if let have = AppVersion.release, have >= wanted { return }
        problem = """
            Cairn \(wanted) was not installed. \(Self.logFile.path) says what the \
            update did, and /var/log/install.log what Installer did.
            """
        presentSheet = true
    }

    // MARK: installing

    func install() {
        guard phase == .idle, canInstallInPlace,
              let release = available, let installer = release.installer else { return }
        problem = nil
        job = Task { await install(release, installer) }
    }

    func cancel() {
        job?.cancel()
    }

    private func install(_ release: Release, _ installer: Release.Installer) async {
        phase = .downloading(received: 0, total: installer.size ?? 0)
        let folder = FileManager.default.temporaryDirectory
            .appendingPathComponent("cairn-update-\(UUID().uuidString)", isDirectory: true)
        // Root has its own copy by the time this runs, or there is nothing
        // to keep.
        defer { try? FileManager.default.removeItem(at: folder) }
        do {
            let text = try await Fetch.text(from: installer.checksum)
            guard let expected = Release.checksum(fromFile: text, for: installer.name) else {
                throw UpdateError("\(installer.name).sha256 holds no SHA-256 for \(installer.name). Nothing was installed.")
            }
            // Two witnesses that are hard to get to disagree by accident:
            // the release job hashed what it built, GitHub hashed what it
            // received. Disagreement means one of them is not this image.
            if let digest = installer.digest, digest != expected {
                throw UpdateError("""
                    \(installer.name).sha256 and GitHub's own record of \(installer.name) \
                    disagree about its SHA-256. Nothing was installed.
                    """)
            }

            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            let file = folder.appendingPathComponent(installer.name)
            let got = try await Fetch.download(installer.image, to: file) { [weak self] received, total in
                await self?.downloaded(received, of: total)
            }
            try Task.checkCancellation()

            phase = .verifying
            guard got == expected else {
                throw UpdateError("""
                    The downloaded \(installer.name) does not match its published SHA-256 \
                    (got \(got), expected \(expected)). Nothing was installed.
                    """)
            }

            phase = .authorizing
            switch await Root.install(image: file, sha256: expected, version: release.version,
                                      bundle: Bundle.main.bundleURL) {
            case .cancelled:
                phase = .idle
                return
            case .failed(let message):
                throw UpdateError(message)
            case .started:
                break
            }

            // Root has its own copy now and is waiting for this process to
            // exit. Quitting stops the node the way it always does
            // (`applicationWillTerminate`), and never returns -- so the
            // download is removed here, not by the `defer`.
            try? FileManager.default.removeItem(at: folder)
            phase = .installing
            defaults.set(release.version.description, forKey: Key.pending)
            NSApp.terminate(nil)
        } catch is CancellationError {
            phase = .idle
        } catch let error as URLError where error.code == .cancelled {
            phase = .idle
        } catch {
            phase = .idle
            problem = error.localizedDescription
        }
    }

    private func downloaded(_ received: Int64, of total: Int64) {
        if case .downloading = phase { phase = .downloading(received: received, total: total) }
    }
}

struct UpdateError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

/// The network half, off the main actor.
private enum Fetch {
    static let session: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 30
        config.httpAdditionalHeaders = ["User-Agent": "Cairn.app/\(AppVersion.bundle)"]
        return URLSession(configuration: config)
    }()

    /// Nil when the repository has no release yet.
    static func latest() async throws -> Release? {
        let url = URL(string: "https://api.github.com/repos/\(Release.repository)/releases/latest")!
        var request = URLRequest(url: url)
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        let (data, response) = try await session.data(for: request)
        switch (response as? HTTPURLResponse)?.statusCode ?? 0 {
        case 200:
            return try Release.parse(data, repository: Release.repository)
        case 404:
            return nil
        case 403, 429:
            throw UpdateError("GitHub is limiting how often this address may ask about releases. Try again in an hour.")
        case let status:
            throw UpdateError("GitHub answered \(status) when asked for the latest release.")
        }
    }

    static func text(from url: URL) async throws -> String {
        let (data, response) = try await session.data(from: url)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else {
            throw UpdateError("Could not fetch \(url.lastPathComponent).")
        }
        return String(decoding: data.prefix(4096), as: UTF8.self)
    }

    /// Write `url` to `file`, hashing as it goes, and return the SHA-256 in
    /// hex. Off the main actor, since it touches every byte.
    ///
    /// A detached task does not inherit its caller's cancellation, so the
    /// sheet's Cancel is forwarded by hand; without it the download ran to
    /// the end and was only then thrown away.
    static func download(
        _ url: URL, to file: URL,
        progress: @escaping @Sendable (Int64, Int64) async -> Void
    ) async throws -> String {
        let task = Task.detached(priority: .userInitiated) {
            let (bytes, response) = try await session.bytes(from: url)
            guard (response as? HTTPURLResponse)?.statusCode == 200 else {
                throw UpdateError("Could not download \(url.lastPathComponent).")
            }
            let total = response.expectedContentLength
            guard FileManager.default.createFile(atPath: file.path, contents: nil) else {
                throw UpdateError("Could not write \(file.path).")
            }
            let handle = try FileHandle(forWritingTo: file)
            defer { try? handle.close() }
            var hasher = SHA256()
            var buffer = Data()
            buffer.reserveCapacity(1 << 16)
            var received: Int64 = 0
            var reported: Int64 = 0
            func flush() throws {
                try Task.checkCancellation()
                try handle.write(contentsOf: buffer)
                hasher.update(data: buffer)
                received += Int64(buffer.count)
                buffer.removeAll(keepingCapacity: true)
            }
            for try await byte in bytes {
                buffer.append(byte)
                if buffer.count == 1 << 16 {
                    try flush()
                    // A release image is a few megabytes. Anything past a
                    // gigabyte is not one, and is not given the disk.
                    if received > 1 << 30 { throw UpdateError("\(url.lastPathComponent) is far larger than any release.") }
                    if received - reported >= 1 << 18 {
                        reported = received
                        await progress(received, total)
                    }
                }
            }
            try flush()
            if total > 0, received != total {
                throw UpdateError("The download of \(url.lastPathComponent) stopped early.")
            }
            await progress(received, total)
            return hasher.finalize().map { String(format: "%02x", $0) }.joined()
        }
        return try await withTaskCancellationHandler {
            try await task.value
        } onCancel: {
            task.cancel()
        }
    }
}

/// The privileged half: one `osascript` that asks for a password and runs
/// `InstallScript.stage1` as root.
///
/// `osascript` rather than `NSAppleScript` in this process, because
/// `NSAppleScript` belongs on the main thread and stage 1 copies and mounts
/// a disk image, which is seconds of a frozen window; and rather than a
/// privileged helper, because a helper needs a Developer ID to bless it and
/// this project has none.
private enum Root {
    enum Outcome {
        case started
        case cancelled
        case failed(String)
    }

    static func install(image: URL, sha256: String, version: SemVer, bundle: URL) async -> Outcome {
        let pid = ProcessInfo.processInfo.processIdentifier
        let uid = getuid()
        return await Task.detached(priority: .userInitiated) { () -> Outcome in
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            p.arguments = InstallScript.osascript.flatMap { ["-e", $0] } + [
                InstallScript.stage1,
                "Cairn wants to install version \(version), which replaces Cairn.app and the cairn command.",
                image.path, sha256, String(pid), String(uid), bundle.path,
            ]
            let err = Pipe()
            p.standardOutput = FileHandle.nullDevice
            p.standardError = err
            do { try p.run() } catch { return .failed(error.localizedDescription) }
            let data = err.fileHandleForReading.readDataToEndOfFile()
            p.waitUntilExit()
            if p.terminationStatus == 0 { return .started }
            let text = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            // AppleScript's "User canceled." -- the password dialog's Cancel.
            if text.hasSuffix("(-128)") { return .cancelled }
            return .failed(Root.message(fromOsascript: text))
        }.value
    }

    /// `0:417: execution error: <what the script said> (1)` → the middle.
    static func message(fromOsascript text: String) -> String {
        var s = Substring(text)
        if let r = s.range(of: "execution error: ") { s = s[r.upperBound...] }
        if let r = s.range(of: #"\s*\(-?\d+\)$"#, options: .regularExpression) { s = s[..<r.lowerBound] }
        let message = s.trimmingCharacters(in: .whitespacesAndNewlines)
        return message.isEmpty ? "The installer could not be started." : message
    }
}
