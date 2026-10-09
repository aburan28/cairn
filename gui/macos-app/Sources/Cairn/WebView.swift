import AppKit
import SwiftUI
import WebKit

/// Owns the one web view, so the menu's Reload reaches the page the window
/// shows.
@MainActor
final class Browser: NSObject, ObservableObject, WKNavigationDelegate, WKUIDelegate {
    let view: WKWebView
    /// Host (and optional port) of the node this window is showing. Links on
    /// that host stay here; everything else opens in the system browser.
    private var nodeHost: String?
    private var nodePort: Int?
    /// What to do when the reader's Post a challenge page hands over a
    /// description: open New Challenge… with it, or return why not.
    var onDraftChallenge: (@MainActor (String) -> String?)?
    /// The Contribute page turning a role on or off, once the person has
    /// confirmed it natively: apply it and restart the node, or say why not.
    var onSetRole: (@MainActor (PageRole, Bool) -> String?)?
    /// A page opening one of the app's sheets, on an objective or not.
    var onOpen: (@MainActor (PageSheet, String?) -> String?)?
    var onWorkStatus: (@MainActor () -> [String: Any])?
    var onStartWork: (@MainActor (String) -> String?)?
    var onPauseWork: (@MainActor () -> String?)?
    var onResumeWork: (@MainActor () -> String?)?
    var onStopWork: (@MainActor () -> String?)?
    var onExitWork: (@MainActor () -> String?)?
    let pageDictation = PageDictation()
    fileprivate var pageDictationActive = false
    private let bridge: PageBridge

    override init() {
        let configuration = WKWebViewConfiguration()
        // How the reader knows it is in this window rather than a browser tab:
        // it drops the public site's pitch and footer (`.in-app` in
        // ui/app/layout.tsx). Appended to WebKit's own user agent, not
        // replacing it, so nothing that sniffs for Safari changes.
        configuration.applicationNameForUserAgent = "CairnApp/1"
        bridge = PageBridge()
        configuration.userContentController.addScriptMessageHandler(bridge, contentWorld: .page, name: PageBridge.name)
        view = WKWebView(frame: .zero, configuration: configuration)
        super.init()
        bridge.browser = self
        view.navigationDelegate = self
        view.uiDelegate = self
        view.allowsBackForwardNavigationGestures = true
    }

    func show(_ url: URL) {
        let shown = view.url
        nodeHost = url.host
        nodePort = url.port
        // The same node, back from a restart: reload the page the person was
        // on rather than sending them to the overview. Turning a role on
        // from the Contribute page restarts the node, and coming back to a
        // different page than the one with the button read as a failure.
        if let shown, shown.host == url.host, shown.port == url.port, shown.path.hasPrefix(url.path) {
            view.reload()
        } else if shown?.host != url.host || shown?.port != url.port || shown?.path != url.path {
            view.load(URLRequest(url: url))
        }
    }

    func reload() { view.reload() }

    // The window is for this node's pages. A link anywhere else -- a GitHub
    // page, a paper an objective cites -- belongs in the person's browser,
    // where their bookmarks and logins are.
    //
    // Only a link the person clicked, and only to the web or mail. A page --
    // script, a redirect, an iframe, anything on a plain-http LAN node a
    // neighbour can tamper with -- must not hand `smb:`, `file:` or another
    // app's scheme to the system unasked: `smb://` mounts a share and the
    // next `file://` on it launches what is there, with no quarantine flag.
    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                 decisionHandler: @escaping @MainActor (WKNavigationActionPolicy) -> Void) {
        if let url = action.request.url, !isNode(url) {
            if Self.mayOpenExternally(url, action: action) {
                NSWorkspace.shared.open(url)
            }
            decisionHandler(.cancel)
        } else {
            decisionHandler(.allow)
        }
    }

    /// A clicked link, in the main frame or asking for a new window, to
    /// http, https or mailto.
    static func mayOpenExternally(_ url: URL, action: WKNavigationAction) -> Bool {
        guard action.navigationType == .linkActivated else { return false }
        if let frame = action.targetFrame, !frame.isMainFrame { return false }
        return ["http", "https", "mailto"].contains(url.scheme?.lowercased() ?? "")
    }

    func webView(_ webView: WKWebView, didStartProvisionalNavigation navigation: WKNavigation!) {
        pageDictation.cancel()
        pageDictationActive = false
    }

    // `target="_blank"` asks for a new web view; this app has one window.
    func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
                 for action: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        if let url = action.request.url {
            if isNode(url) {
                webView.load(URLRequest(url: url))
            } else if Self.mayOpenExternally(url, action: action) {
                NSWorkspace.shared.open(url)
            }
        }
        return nil
    }

    /// Whether a frame's origin is the node this window opened, over http(s)
    /// only: `isNode` lets `about:` and `data:` documents load, and neither
    /// is the reader.
    fileprivate func isNode(origin: WKSecurityOrigin) -> Bool {
        guard origin.protocol == "http" || origin.protocol == "https" else { return false }
        var parts = URLComponents()
        parts.scheme = origin.protocol
        parts.host = origin.host
        // WebKit says 0 for the scheme's default port.
        if origin.port != 0 { parts.port = origin.port }
        guard let url = parts.url else { return false }
        return isNode(url)
    }

    fileprivate var isLocalChallengePage: Bool {
        guard let nodeHost else { return false }
        return ["localhost", "127.0.0.1", "::1"].contains(nodeHost)
            && view.url?.lastPathComponent == "submit"
    }

    /// A role change asked for by a page: two of the three open a port to
    /// the network and the third stakes money, and a page is scriptable, so
    /// the click that counts is this one.
    fileprivate func confirmRole(_ role: PageRole, on: Bool) -> Bool {
        let prompt = NSAlert()
        switch (role, on) {
        case (.validator, true):
            prompt.messageText = "Check other people's answers?"
            prompt.informativeText = "The node will re-run each claim's checker on this Mac and sign what it found. Every attestation stakes 50,000 units, returned after six epochs and lost if it was wrong. Not paid yet. The node restarts now."
        case (.relay, true):
            prompt.messageText = "Let other nodes connect to this one?"
            prompt.informativeText = "The node's P2P port binds every interface on this Mac, so nodes on your network and beyond can dial it. Not paid. The node restarts now."
        case (.workerHost, true):
            prompt.messageText = "Share this node on your network?"
            prompt.informativeText = "Machines on your network can open this node's pages, read the log, post answers and work its objectives. Nobody can change what has settled. The node restarts now."
        case (_, false):
            prompt.messageText = "Turn off \(role.title)?"
            prompt.informativeText = "The node restarts without it."
        }
        prompt.addButton(withTitle: on ? "Turn On and Restart" : "Turn Off and Restart")
        prompt.addButton(withTitle: "Cancel")
        return prompt.runModal() == .alertFirstButtonReturn
    }

    fileprivate func confirmPageDictation() -> Bool {
        // A page is scriptable, so a bridge request alone cannot prove that
        // the person clicked the microphone button. Require a native action
        // for each recording, even after macOS remembers microphone access.
        let prompt = NSAlert()
        prompt.messageText = "Dictate a challenge?"
        prompt.informativeText = "Cairn will listen on this Mac until you stop. The editable transcript will appear in the challenge form."
        prompt.addButton(withTitle: "Start recording")
        prompt.addButton(withTitle: "Cancel")
        return prompt.runModal() == .alertFirstButtonReturn
    }

    fileprivate func confirmWork(_ action: String) -> Bool {
        let prompt = NSAlert()
        prompt.messageText = action == "exit" ? "Exit this task?" : "Stop working on this Mac?"
        prompt.informativeText = action == "exit"
            ? "Cairn will finish the current round, reveal pending answers, and release this task. This can take another epoch."
            : "Cairn will finish the current round and reveal pending answers before stopping. This can take another epoch."
        prompt.addButton(withTitle: action == "exit" ? "Exit Task" : "Stop Work")
        prompt.addButton(withTitle: "Cancel")
        return prompt.runModal() == .alertFirstButtonReturn
    }

    private func isNode(_ url: URL) -> Bool {
        guard let scheme = url.scheme, scheme == "http" || scheme == "https" else {
            return url.scheme == "about" || url.scheme == "blob" || url.scheme == "data"
        }
        guard let host = url.host else { return false }
        // Loopback aliases count as the same node when that is what we opened.
        let local: Set<String> = ["127.0.0.1", "localhost"]
        if let nodeHost {
            if host == nodeHost { return url.port == nodePort || (url.port == nil && nodePort == nil) }
            if local.contains(host) && local.contains(nodeHost) {
                return url.port == nodePort || (url.port == nil && (nodePort == nil || nodePort == 80))
            }
            return false
        }
        return local.contains(host)
    }
}

/// What the reader's pages may ask of the app: to open New Challenge… with
/// a description typed on Post a challenge (`ui/lib/draft.ts`), to dictate
/// one, and -- from the Contribute page (`ui/lib/contribute.ts`) -- to turn
/// a role on or off or open one of the sheets. None of it is a page's to
/// do: the node has no TLS and must never see the model key, a role is how
/// the node is started, and a worker is a process. The app already does
/// all of it from its menus; this is the page's button for the same thing.
///
/// Its own object rather than the browser, because the content controller
/// keeps its handlers for as long as the view lives, and the browser owns
/// the view.
@MainActor
final class PageBridge: NSObject, WKScriptMessageHandlerWithReply {
    /// `window.webkit.messageHandlers.cairn` on the page.
    static let name = "cairn"
    weak var browser: Browser?

    /// The async form, so the reply is the return value rather than a
    /// closure whose actor and Sendable annotations differ between SDKs.
    func userContentController(_ controller: WKUserContentController,
                               didReceive message: WKScriptMessage) async -> (Any?, String?) {
        // The node's own reader in the window's top frame, and nothing else:
        // not a frame it embeds, and not a page from elsewhere. Starting a
        // draft spends the person's model credits.
        guard let browser, message.frameInfo.isMainFrame,
              browser.isNode(origin: message.frameInfo.securityOrigin)
        else { return (nil, "Only this node's own pages can open New Challenge.") }
        switch PageRequest.parse(message.body) {
        case .failure(let refusal):
            return (nil, refusal.message)
        case .success(.draftChallenge(let brief)):
            guard let open = browser.onDraftChallenge else { return (nil, "New Challenge is not available.") }
            if let refusal = open(brief) { return (nil, refusal) }
            return (true, nil)
        case .success(.setRole(let role, let on)):
            guard let set = browser.onSetRole else { return (nil, "Roles cannot be changed from here.") }
            guard browser.confirmRole(role, on: on) else { return (nil, "Cancelled.") }
            if let refusal = set(role, on) { return (nil, refusal) }
            return (true, nil)
        case .success(.open(let sheet, let objective)):
            guard let open = browser.onOpen else { return (nil, "That is not available here.") }
            if let refusal = open(sheet, objective) { return (nil, refusal) }
            return (true, nil)
        case .success(.workStatus):
            guard let status = browser.onWorkStatus else { return (nil, "Work status is unavailable.") }
            return (status(), nil)
        case .success(.startWork(let objective)):
            guard let start = browser.onStartWork else { return (nil, "Work cannot start here.") }
            if let refusal = start(objective) { return (nil, refusal) }
            return (true, nil)
        case .success(.pauseWork):
            guard let pause = browser.onPauseWork else { return (nil, "Work cannot pause here.") }
            if let refusal = pause() { return (nil, refusal) }
            return (true, nil)
        case .success(.resumeWork):
            guard let resume = browser.onResumeWork else { return (nil, "Work cannot resume here.") }
            if let refusal = resume() { return (nil, refusal) }
            return (true, nil)
        case .success(.stopWork):
            guard let stop = browser.onStopWork else { return (nil, "Work cannot stop here.") }
            guard browser.confirmWork("stop") else { return (nil, "Cancelled.") }
            if let refusal = stop() { return (nil, refusal) }
            return (true, nil)
        case .success(.exitWork):
            guard let exit = browser.onExitWork else { return (nil, "This task cannot be exited here.") }
            guard browser.confirmWork("exit") else { return (nil, "Cancelled.") }
            if let refusal = exit() { return (nil, refusal) }
            return (true, nil)
        case .success(.startDictation):
            guard browser.isLocalChallengePage else {
                return (nil, "Voice entry is available only from this Mac's challenge page.")
            }
            guard browser.confirmPageDictation() else { return (nil, "Recording was cancelled.") }
            do {
                try await browser.pageDictation.start()
                browser.pageDictationActive = true
                return (true, nil)
            } catch {
                return (nil, error.localizedDescription)
            }
        case .success(.stopDictation):
            guard browser.pageDictationActive else {
                return (nil, "No page dictation is running.")
            }
            browser.pageDictationActive = false
            do {
                return (["text": try await browser.pageDictation.stop()], nil)
            } catch {
                return (nil, error.localizedDescription)
            }
        }
    }
}

struct WebView: NSViewRepresentable {
    let browser: Browser

    func makeNSView(context: Context) -> WKWebView { browser.view }
    func updateNSView(_ view: WKWebView, context: Context) {}
}
