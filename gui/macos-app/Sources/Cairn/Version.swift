import Foundation

/// A release version, compared the way semver orders them.
///
/// Parsed rather than compared as text, because text puts `1.10.0` before
/// `1.9.0` -- and an updater that reads "older" as "newer" offers a downgrade
/// to every install it reaches.
struct SemVer: Comparable, CustomStringConvertible {
    let major: Int
    let minor: Int
    let patch: Int
    /// Pre-release identifiers, empty for a release. `1.9.0-rc.1` sorts
    /// before `1.9.0`, so a candidate is never offered over its own final.
    let pre: [String]

    /// `v1.9.0`, `1.9.0`, `1.9.0-rc.1` and `1.9.0+build` all parse; anything
    /// that is not three numbers first does not.
    init?(_ raw: String) {
        var s = Substring(raw.trimmingCharacters(in: .whitespacesAndNewlines))
        if s.first == "v" || s.first == "V" { s = s.dropFirst() }
        // Build metadata never affects precedence.
        if let plus = s.firstIndex(of: "+") { s = s[..<plus] }
        var pre: [String] = []
        if let dash = s.firstIndex(of: "-") {
            pre = s[s.index(after: dash)...].split(separator: ".", omittingEmptySubsequences: false).map(String.init)
            guard !pre.isEmpty, pre.allSatisfy({ !$0.isEmpty }) else { return nil }
            s = s[..<dash]
        }
        let core = s.split(separator: ".", omittingEmptySubsequences: false)
        guard core.count == 3,
              core.allSatisfy({ !$0.isEmpty && $0.allSatisfy(\.isASCII) && $0.allSatisfy(\.isNumber) }),
              let major = Int(core[0]), let minor = Int(core[1]), let patch = Int(core[2])
        else { return nil }
        self.major = major
        self.minor = minor
        self.patch = patch
        self.pre = pre
    }

    /// `0.0.0` is what a checkout's build says, and `0.0.0-dispatch.N` what a
    /// release dry run stamps: neither is a release anybody can update from.
    var isPlaceholder: Bool { major == 0 && minor == 0 && patch == 0 }

    var description: String {
        "\(major).\(minor).\(patch)" + (pre.isEmpty ? "" : "-" + pre.joined(separator: "."))
    }

    static func < (a: SemVer, b: SemVer) -> Bool {
        if (a.major, a.minor, a.patch) != (b.major, b.minor, b.patch) {
            return (a.major, a.minor, a.patch) < (b.major, b.minor, b.patch)
        }
        // A release outranks any pre-release of the same numbers.
        if a.pre.isEmpty || b.pre.isEmpty { return !a.pre.isEmpty && b.pre.isEmpty }
        for (x, y) in zip(a.pre, b.pre) where x != y {
            switch (Int(x), Int(y)) {
            case let (i?, j?): return i < j
            case (.some, nil): return true    // numeric identifiers sort first
            case (nil, .some): return false
            case (nil, nil): return x < y
            }
        }
        return a.pre.count < b.pre.count
    }
}

/// What this window and the `cairn` it runs say they are.
enum AppVersion {
    /// `CFBundleShortVersionString`, which `packaging/macos/build-dmg.sh`
    /// stamps with the release's version. A checkout's build says 0.0.0.
    static var bundle: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.0.0"
    }

    /// The release this app was installed from, or nil for a build that is
    /// not one: a checkout's, or a release dry run's.
    static var release: SemVer? {
        guard let v = SemVer(bundle), !v.isPlaceholder else { return nil }
        return v
    }

    /// For the title bar and anywhere else one short phrase fits.
    static var label: String {
        release.map { "Version \($0)" } ?? "Development build"
    }

    /// The version out of `cairn --version`, whose first line is
    /// `cairn 1.8.1` (`print_version` in src/main.rs).
    static func cli(fromVersionOutput output: String) -> String? {
        guard let first = output.split(whereSeparator: \.isNewline).first else { return nil }
        let words = first.split(separator: " ")
        guard words.count >= 2, words[0] == "cairn", SemVer(String(words[1])) != nil else { return nil }
        return String(words[1])
    }
}
