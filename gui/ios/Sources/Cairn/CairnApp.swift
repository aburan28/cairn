import SwiftUI
import CairnUI

/// The same scene the iOS app target launches. Compiled here as a macOS
/// executable so `swift build --package-path gui/ios` fails when a view
/// does, without needing a simulator.
@main
struct CairnApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
        }
    }
}
