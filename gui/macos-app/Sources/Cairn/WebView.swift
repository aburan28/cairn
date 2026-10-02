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

    override init() {
        let configuration = WKWebViewConfiguration()
        // How the reader knows it is in this window rather than a browser tab:
        // it drops the public site's pitch and footer (`.in-app` in
        // ui/app/layout.tsx). Appended to WebKit's own user agent, not
        // replacing it, so nothing that sniffs for Safari changes.
        configuration.applicationNameForUserAgent = "CairnApp/1"
        view = WKWebView(frame: .zero, configuration: configuration)
        super.init()
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
    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                 decisionHandler: @escaping @MainActor (WKNavigationActionPolicy) -> Void) {
        if let url = action.request.url, !isNode(url) {
            NSWorkspace.shared.open(url)
            decisionHandler(.cancel)
        } else {
            decisionHandler(.allow)
        }
    }

    // `target="_blank"` asks for a new web view; this app has one window.
    func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
                 for action: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        if let url = action.request.url {
            if isNode(url) { webView.load(URLRequest(url: url)) } else { NSWorkspace.shared.open(url) }
        }
        return nil
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

struct WebView: NSViewRepresentable {
    let browser: Browser

    func makeNSView(context: Context) -> WKWebView { browser.view }
    func updateNSView(_ view: WKWebView, context: Context) {}
}
