import AppKit
import SwiftUI
import WebKit

/// Owns the one web view, so the menu's Reload and the toolbar reach the same
/// page the window shows.
@MainActor
final class Browser: NSObject, ObservableObject, WKNavigationDelegate, WKUIDelegate {
    let view: WKWebView

    override init() {
        view = WKWebView(frame: .zero, configuration: WKWebViewConfiguration())
        super.init()
        view.navigationDelegate = self
        view.uiDelegate = self
        view.allowsBackForwardNavigationGestures = true
    }

    func show(_ url: URL) {
        if view.url?.host != url.host || view.url?.port != url.port {
            view.load(URLRequest(url: url))
        }
    }

    func reload() { view.reload() }

    // The window is for this node's pages. A link anywhere else -- a GitHub
    // page, a paper an objective cites -- belongs in the person's browser,
    // where their bookmarks and logins are.
    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                 decisionHandler: @escaping @MainActor (WKNavigationActionPolicy) -> Void) {
        if let url = action.request.url, !Self.isLocal(url) {
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
            if Self.isLocal(url) { webView.load(URLRequest(url: url)) } else { NSWorkspace.shared.open(url) }
        }
        return nil
    }

    private static func isLocal(_ url: URL) -> Bool {
        guard let scheme = url.scheme, scheme == "http" || scheme == "https" else {
            return url.scheme == "about" || url.scheme == "blob" || url.scheme == "data"
        }
        return url.host == "127.0.0.1" || url.host == "localhost"
    }
}

struct WebView: NSViewRepresentable {
    let browser: Browser

    func makeNSView(context: Context) -> WKWebView { browser.view }
    func updateNSView(_ view: WKWebView, context: Context) {}
}
