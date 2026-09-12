import Foundation

/// Where a chain stops being a chain.
///
/// Returns the epoch of the first link whose `prev` is not the link before
/// it, or `nil` if the chain is intact. Checked in the reader rather than
/// assumed because this is the one claim the app makes on its own behalf:
/// the node says "here is a chain", and a reader that renders it without
/// checking is taking that on faith, which is the one thing this project
/// does not do anywhere else. Same function as `firstBrokenLink` in
/// `ui/lib/chain.ts`.
public func firstBrokenLink(_ chain: [EpochLink]) -> Int? {
    var expected = ""
    for link in chain {
        if link.prev != expected { return link.epoch }
        expected = link.link
    }
    return nil
}

/// HTTPS endpoints a published seed list names, in list order.
///
/// Plain `http:` is dropped when the page asking is HTTPS — a browser would
/// block the request and an app that did not would be the one client that
/// silently mixed transports. A user-typed node URL is not filtered here:
/// they chose it, and an operator's LAN node is often `http://192.168.x.x`.
public func readableEndpoints(_ seeds: [Seed], pageIsHTTPS: Bool) -> [String] {
    seeds.compactMap { seed in
        guard let http = seed.http, let url = URL(string: http) else { return nil }
        if pageIsHTTPS, url.scheme?.lowercased() != "https" { return nil }
        return http.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    }
}
