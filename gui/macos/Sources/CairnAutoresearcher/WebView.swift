import AppKit
import SwiftUI
import WebKit

/// The node's own reader, embedded. The same pages an operator would open in
/// a browser, reading the same node -- nothing here is rendered twice.
///
/// Links off the node open in the system browser: a GitHub page or a paper
/// an objective cites belongs where the person's bookmarks and logins are,
/// not trapped inside this pane. Same policy as Cairn.app's `Browser`.
struct WebView: NSViewRepresentable {
    let url: URL

    func makeCoordinator() -> Coordinator { Coordinator() }

    func makeNSView(context: Context) -> WKWebView {
        let view = WKWebView(frame: .zero, configuration: WKWebViewConfiguration())
        view.navigationDelegate = context.coordinator
        view.uiDelegate = context.coordinator
        view.allowsBackForwardNavigationGestures = true
        view.load(URLRequest(url: url))
        return view
    }

    func updateNSView(_ view: WKWebView, context: Context) {
        if view.url?.absoluteString != url.absoluteString {
            view.load(URLRequest(url: url))
        }
    }

    final class Coordinator: NSObject, WKNavigationDelegate, WKUIDelegate {
        func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                     decisionHandler: @escaping @MainActor (WKNavigationActionPolicy) -> Void) {
            if let url = action.request.url, !Self.isLocal(url) {
                NSWorkspace.shared.open(url)
                decisionHandler(.cancel)
            } else {
                decisionHandler(.allow)
            }
        }

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
}
