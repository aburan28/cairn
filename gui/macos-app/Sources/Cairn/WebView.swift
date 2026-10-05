import AppKit
import SwiftUI
import WebKit

/// Owns the one web view, so the menu's Reload and the toolbar reach the same
/// page the window shows.
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
        nodeHost = url.host
        nodePort = url.port
        if view.url?.host != url.host || view.url?.port != url.port || view.url?.path != url.path {
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

/// What the reader's pages may ask of the app: today one thing, to open New
/// Challenge… with a description typed on Post a challenge
/// (`ui/lib/draft.ts`). The page cannot draft one itself -- the node has no
/// TLS and must never see the model key -- and the app already can.
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
