import XCTest
@testable import CairnKit

/// A chain whose links name each other. The hashes are not real digests:
/// `firstBrokenLink` compares `prev` to the previous `link` by value and
/// never recomputes anything — a reader that re-derived the hash would be
/// the third implementation this package refuses to be. Same fixtures as
/// `ui/lib/chain.test.ts`.
func linked(_ epochs: [Int]) -> [EpochLink] {
    var prev = ""
    return epochs.map { epoch in
        let link = "sha256:link-\(epoch)"
        let out = EpochLink(epoch: epoch, claims: ["sha256:claim-\(epoch)"], prev: prev, link: link)
        prev = link
        return out
    }
}

final class ChecksTests: XCTestCase {
    func testEmptyChainIsIntact() {
        XCTAssertNil(firstBrokenLink([]))
    }

    func testChainWhoseEveryLinkNamesTheOneBeforeIt() {
        XCTAssertNil(firstBrokenLink(linked([1, 2, 5])))
    }

    func testFirstLinkMustNameGenesis() {
        var chain = linked([1, 2])
        chain[0].prev = "sha256:something"
        XCTAssertEqual(firstBrokenLink(chain), 1)
    }

    func testReportsTheEpochOfTheFirstBreak() {
        var chain = linked([1, 2, 3, 4])
        chain[2].prev = "sha256:not-link-2"
        XCTAssertEqual(firstBrokenLink(chain), 3)
    }

    func testReportsTheFirstBreakNotTheLast() {
        var chain = linked([1, 2, 3, 4])
        chain[1].prev = "sha256:wrong"
        chain[3].prev = "sha256:also-wrong"
        XCTAssertEqual(firstBrokenLink(chain), 2)
    }

    func testEpochScalesOneLength() {
        XCTAssertEqual(epochScales(linked([2_980_001, 2_980_002, 2_980_007])), [6])
    }

    func testEpochScalesWhenLengthChangedByOrdersOfMagnitude() {
        XCTAssertEqual(epochScales(linked([2_980_001, 1_788_000_000])), [9, 6])
    }

    func testEpochZeroIsIgnored() {
        XCTAssertEqual(epochScales(linked([0, 5])), [0])
    }

    func testPowerOfTenCrossingIsAKnownFalsePositive() {
        // Known and accepted. Epochs 999 and 1000 are consecutive under one
        // divisor, and this reports two scales anyway. The page labels the
        // panel a heuristic for exactly this reason.
        XCTAssertEqual(epochScales(linked([999, 1000])), [3, 2])
    }

    func testTotalClaimsSumsEveryLink() {
        var chain = linked([1, 2])
        chain[1].claims.append("sha256:another")
        XCTAssertEqual(totalClaims(chain), 3)
    }

    func testHttpsSeedsDropPlainHttp() {
        let seeds = [
            Seed(name: "a", http: "https://node.example/"),
            Seed(name: "b", http: "http://192.168.1.5:8080"),
        ]
        XCTAssertEqual(readableEndpoints(seeds, pageIsHTTPS: true), ["https://node.example"])
        XCTAssertEqual(
            readableEndpoints(seeds, pageIsHTTPS: false),
            ["https://node.example", "http://192.168.1.5:8080"]
        )
    }
}
