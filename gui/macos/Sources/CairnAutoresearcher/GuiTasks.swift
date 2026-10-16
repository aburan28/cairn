import Foundation
import CairnNodeKit

/// Curated work a person picks in **Tasks** instead of hunting through Catalog.
/// Paths are relative to the checkout root, same as [`CatalogItem`].
typealias GuiTask = CuratedTask

enum GuiTasks {
    static let all = CuratedTasks.all

    static func task(matching paths: Set<String>) -> GuiTask? {
        all.first { Set($0.paths) == paths }
    }

    static func task(id: String) -> GuiTask? {
        all.first { $0.id == id }
    }
}
