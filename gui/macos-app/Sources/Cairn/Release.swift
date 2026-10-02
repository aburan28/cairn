import Foundation

/// The newest published release, as GitHub's `releases/latest` describes it,
/// and the one asset of it this app can install.
///
/// Foundation only, and kept apart from `Updater` for that reason: what is
/// believed about a release -- its version, which file is the installer,
/// what that file must hash to -- is the part worth checking off a Mac.
struct Release: Equatable {
    let tag: String
    let version: SemVer
    /// The changelog release-please wrote, as Markdown.
    let notes: String
    let page: URL
    /// Nil while the release exists but its disk image has not been uploaded.
    /// `release.yml` publishes the page with the first asset and the image
    /// with one of the last, minutes apart, and a check in that window must
    /// not read the gap as "nothing to install" or try to fetch a 404.
    let installer: Installer?

    struct Installer: Equatable {
        let name: String
        let image: URL
        let checksum: URL
        /// The SHA-256 GitHub itself recorded for the image when it was
        /// uploaded, if the API said. A second witness beside the `.sha256`
        /// file, which the release job wrote -- see `Updater.install`.
        let digest: String?
        let size: Int64?
    }

    /// Where releases are published: `repository` in Cargo.toml.
    /// `CAIRN_UPDATE_REPO=owner/name` at launch points the check at a fork,
    /// which is how the install path is tried before a real release depends
    /// on it. Assets are still only fetched from github.com under that name.
    static let repository: String = {
        let override = ProcessInfo.processInfo.environment["CAIRN_UPDATE_REPO"] ?? ""
        let shape = #"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"#
        return override.range(of: shape, options: .regularExpression) != nil ? override : "aburan28/cairn"
    }()

    /// The name `release.yml` gives the universal image: the tag, not the
    /// bare version, which is why it is `cairn-v1.8.1-…` and not `cairn-1.8.1-…`.
    static func imageName(tag: String) -> String { "cairn-\(tag)-macos-universal.dmg" }

    /// Nil for a release this app should not offer: a draft, a pre-release,
    /// or a tag that is not a version.
    ///
    /// An asset counts only if its URL is where `release.yml` puts it --
    /// github.com, this repository, this tag, this name, over https. The API
    /// is fetched over TLS from GitHub already; the check is so that nothing
    /// about where the bytes come from is left to a field nobody looked at.
    static func parse(_ data: Data, repository: String) throws -> Release? {
        struct Payload: Decodable {
            let tagName: String
            let htmlUrl: URL?
            let body: String?
            let draft: Bool?
            let prerelease: Bool?
            let assets: [Asset]?
        }
        struct Asset: Decodable {
            let name: String
            let state: String?
            let size: Int64?
            let digest: String?
            let browserDownloadUrl: URL
        }
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        let payload = try decoder.decode(Payload.self, from: data)
        guard payload.draft != true, payload.prerelease != true,
              let version = SemVer(payload.tagName), !version.isPlaceholder
        else { return nil }

        let prefix = "/\(repository)/releases/download/\(payload.tagName)/"
        func asset(_ name: String) -> Asset? {
            payload.assets?.first { a in
                let url = a.browserDownloadUrl
                return a.name == name
                    && (a.state ?? "uploaded") == "uploaded"
                    && url.scheme == "https" && url.host == "github.com"
                    && url.path == prefix + name
            }
        }
        let name = imageName(tag: payload.tagName)
        var installer: Installer?
        if let image = asset(name), let sum = asset(name + ".sha256") {
            installer = Installer(
                name: name,
                image: image.browserDownloadUrl,
                checksum: sum.browserDownloadUrl,
                digest: image.digest.flatMap(sha256(fromDigest:)),
                size: image.size
            )
        }
        return Release(
            tag: payload.tagName,
            version: version,
            notes: changelog(fromBody: payload.body ?? ""),
            page: payload.htmlUrl
                ?? URL(string: "https://github.com/\(repository)/releases/tag/\(payload.tagName)")!,
            installer: installer
        )
    }

    /// The release page's text above `packaging/release-notes.sh`'s marker:
    /// the changelog. Below it is how to install the release by hand, which
    /// is not what somebody about to have it installed for them needs.
    static func changelog(fromBody body: String) -> String {
        guard let marker = body.range(of: "<!-- cairn:install-notes") else { return body }
        return String(body[..<marker.lowerBound])
    }

    /// The hash for `name` out of a `.sha256` file, which is `shasum -a 256`
    /// output: `<64 hex>  <name>`. The name is checked too, so the checksum
    /// of some other asset cannot stand in for this one.
    static func checksum(fromFile text: String, for name: String) -> String? {
        for line in text.split(whereSeparator: \.isNewline) {
            let parts = line.split(separator: " ")
            guard parts.count == 2 else { continue }
            var file = parts[1]
            if file.hasPrefix("*") { file = file.dropFirst() }   // shasum's binary-mode marker
            let hash = parts[0].lowercased()
            if file == name, isSHA256(hash) { return hash }
        }
        return nil
    }

    /// GitHub spells an asset digest `sha256:<hex>`.
    static func sha256(fromDigest digest: String) -> String? {
        guard digest.hasPrefix("sha256:") else { return nil }
        let hex = digest.dropFirst("sha256:".count).lowercased()
        return isSHA256(hex) ? hex : nil
    }

    static func isSHA256(_ s: String) -> Bool {
        s.count == 64 && s.allSatisfy { $0.isHexDigit && $0.isASCII }
    }
}

/// What runs as root to install an update: one administrator prompt, then
/// the release's own `Install Cairn.pkg`, the same package a person opens by
/// hand, with the same `preinstall-app` and `postinstall-app`.
///
/// It is two stages because the app has to be gone before the package
/// replaces it, and has to hear about anything that went wrong before it
/// goes. `stage1` runs while the app waits on it, and fails out loud; `finish`
/// is left running to wait for the app to quit, then installs.
///
/// Everything happens on a root-owned copy, and the hash is checked again
/// there. The app checked the download already, but as the user, in a folder
/// the user can write: without the second check, any process of that user
/// could swap the package between the app's check and `installer`, and the
/// password a person typed for Cairn would install something else as root.
enum InstallScript {
    /// `$1` the downloaded image, `$2` its expected SHA-256, `$3` the app's
    /// pid, `$4` the uid to reopen a window for, `$5` the running bundle.
    static let stage1 = #"""
        dmg=$1 sum=$2 pid=$3 uid=$4 app=$5
        work=$(/usr/bin/mktemp -d /private/tmp/cairn-update.XXXXXX) || {
            echo "Could not make a working folder for the update." >&2
            exit 1
        }
        fail() {
            /bin/rm -rf "$work"
            echo "$*" >&2
            exit 1
        }
        /bin/cp "$dmg" "$work/update.dmg" || fail "Could not copy the downloaded disk image."
        got=$(/usr/bin/shasum -a 256 "$work/update.dmg" | /usr/bin/awk '{print $1}')
        [ "$got" = "$sum" ] || fail "The disk image changed after it was checked (SHA-256 $got, expected $sum). Nothing was installed."
        /bin/mkdir "$work/mnt" || fail "Could not make a mount point for the update."
        /usr/bin/hdiutil attach -quiet -nobrowse -readonly -noautoopen -mountpoint "$work/mnt" "$work/update.dmg" \
            || fail "The disk image does not mount."
        /bin/cp "$work/mnt/Install Cairn.pkg" "$work/update.pkg"
        copied=$?
        /usr/bin/hdiutil detach -quiet "$work/mnt" || /usr/bin/hdiutil detach -quiet -force "$work/mnt"
        [ "$copied" -eq 0 ] || fail "The disk image holds no Install Cairn.pkg."
        /bin/rm -f "$work/update.dmg"
        /bin/cat >"$work/finish.sh" <<'FINISH'
        \#(InstallScript.finish)
        FINISH
        /usr/bin/nohup /bin/sh "$work/finish.sh" "$work" "$pid" "$uid" "$app" </dev/null >/dev/null 2>&1 &
        exit 0
        """#

    /// `$1` the root-owned working folder, `$2` the pid to wait for, `$3` the
    /// uid, `$4` the bundle to reopen if the install fails.
    ///
    /// Two minutes for the app to quit, which it does at once unless its node
    /// is slow to stop (seven seconds at most, `Node.reap`). An app still
    /// running after that is not one to install over: Installer would delete
    /// the bundle out from under it, and `postinstall-app`'s `open` would
    /// find the old process and bring that forward instead of the new one.
    static let finish = #"""
        work=$1 pid=$2 uid=$3 app=$4
        /bin/mkdir -p /Library/Logs/Cairn
        exec >>/Library/Logs/Cairn/update.log 2>&1
        echo "$(/bin/date): waiting for Cairn (pid $pid) to quit"
        i=0
        while /bin/kill -0 "$pid" 2>/dev/null; do
            i=$((i + 1))
            if [ "$i" -gt 600 ]; then
                echo "$(/bin/date): Cairn did not quit within two minutes; nothing was installed"
                /bin/rm -rf "$work"
                exit 1
            fi
            /bin/sleep 0.2
        done
        echo "$(/bin/date): installing"
        # Captured at once: under bash, which is macOS's /bin/sh, the `$(date)`
        # in the next echo resets `$?` before the echo reads it.
        /usr/sbin/installer -pkg "$work/update.pkg" -target /
        status=$?
        if [ "$status" -eq 0 ]; then
            echo "$(/bin/date): installed; postinstall-app reopens Cairn"
        else
            echo "$(/bin/date): installer failed with status $status"
            if [ -d "$app" ]; then
                /bin/launchctl asuser "$uid" /usr/bin/open "$app"
            fi
        fi
        /bin/rm -rf "$work"
        """#

    /// `osascript` statements: run `$1` as root under `/bin/sh`, with the
    /// password dialog saying `$2`, and every argument after that passed to
    /// the script. Arguments go through `quoted form of`, so a path with a
    /// space or a quote in it is one word to the shell and nothing more.
    static let osascript = [
        "on run argv",
        "set cmd to \"/bin/sh -c \" & quoted form of (item 1 of argv) & \" cairn-update\"",
        "repeat with i from 3 to (count of argv)",
        "set cmd to cmd & \" \" & quoted form of (item i of argv)",
        "end repeat",
        "do shell script cmd with prompt (item 2 of argv) with administrator privileges",
        "end run",
    ]
}
