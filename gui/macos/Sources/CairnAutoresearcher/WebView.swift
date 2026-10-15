import AppKit
import SwiftUI
import WebKit
import CairnNodeKit

/// The node's own reader, embedded. The same pages an operator would open in
/// a browser, reading the same node -- nothing here is rendered twice.
///
/// Links off the node open in the system browser: a GitHub page or a paper
/// an objective cites belongs where the person's bookmarks and logins are,
/// not trapped inside this pane. Same policy as Cairn.app's `Browser`.
struct WebView: NSViewRepresentable {
    let url: URL

    func makeCoordinator() -> Coordinator { Coordinator(url) }

    func makeNSView(context: Context) -> WKWebView {
        let view = WKWebView(frame: .zero, configuration: WKWebViewConfiguration())
        view.navigationDelegate = context.coordinator
        view.uiDelegate = context.coordinator
        view.allowsBackForwardNavigationGestures = true
        view.load(URLRequest(url: url))
        return view
    }

    func updateNSView(_ view: WKWebView, context: Context) {
        if context.coordinator.requested != url {
            context.coordinator.requested = url
            view.load(URLRequest(url: url))
        }
    }

    final class Coordinator: NSObject, WKNavigationDelegate, WKUIDelegate {
        var requested: URL
        init(_ url: URL) { requested = url; super.init() }
        func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                     decisionHandler: @escaping @MainActor (WKNavigationActionPolicy) -> Void) {
            if let url = action.request.url, !ReaderNavigation.staysInReader(url, node: requested) {
                if ReaderNavigation.mayOpenExternally(url, clicked: action.navigationType == .linkActivated, mainFrame: action.targetFrame?.isMainFrame ?? true) { NSWorkspace.shared.open(url) }
                decisionHandler(.cancel)
            } else {
                decisionHandler(.allow)
            }
        }

        func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
                     for action: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
            if let url = action.request.url {
                if ReaderNavigation.staysInReader(url, node: requested) { webView.load(URLRequest(url: url)) }
                else if ReaderNavigation.mayOpenExternally(url, clicked: action.navigationType == .linkActivated, mainFrame: true) { NSWorkspace.shared.open(url) }
            }
            return nil
        }


    }
}
