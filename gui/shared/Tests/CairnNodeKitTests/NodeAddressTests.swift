import XCTest
@testable import CairnNodeKit

final class NodeAddressTests: XCTestCase {
    func testWildcardUsesAnOwnedInterfaceAndTheActualPortWithoutInventingReachability() {
        XCTAssertEqual(NodeAddress.forListener("0.0.0.0:54321", localHosts: ["127.0.0.1", "192.168.1.23"]), "192.168.1.23:54321")
        XCTAssertNil(NodeAddress.forListener("127.0.0.1:9000", localHosts: ["192.168.1.23"]))
        XCTAssertNil(NodeAddress.forListener("0.0.0.0:9000", localHosts: []))
        XCTAssertNil(NodeAddress.forListener("0.0.0.0:0", localHosts: ["192.168.1.23"]))
        XCTAssertNil(NodeAddress.forListener("[::]:9000", localHosts: ["192.168.1.23"]))
        XCTAssertEqual(NodeAddress.forListener("198.51.100.7:9000", localHosts: []), "198.51.100.7:9000")
    }
    func testLoopbackIsLabelledRatherThanOfferedAsAnAddress() {
        for address in ["127.0.0.1:9000", "127.24.1.2:9000", "127.1:9000", "2130706433:9000", "0x7f000001:9000", "localhost:8080", "localhost.:8080", "[::1]:9000", "[0:0:0:0:0:0:0:1]:9000", "[::ffff:127.0.0.1]:9000"] {
            XCTAssertNil(NodeAddress.shareable(address), address)
            XCTAssertEqual(NodeAddress.label(address), "Local connection", address)
        }
    }
    func testWildcardsAreNeverOfferedAsShareableAddresses() {
        for address in ["0.0.0.0:9000", "0:9000", "0x0:9000", "0.0:9000", "[::]:9000", "[0:0:0:0:0:0:0:0]:9000", "[::ffff:0.0.0.0]:9000"] {
            XCTAssertNil(NodeAddress.shareable(address), address)
            XCTAssertEqual(NodeAddress.label(address), "Not advertised", address)
        }
    }
    func testRealNodeAddressesKeepTheirIPAndPort() {
        for address in ["192.168.1.23:9000", "198.51.100.7:80", "[2001:db8::7]:9000", "peer.example:9000", "127.example:9000"] {
            XCTAssertEqual(NodeAddress.shareable(address), address)
            XCTAssertEqual(NodeAddress.label(address), address)
        }
    }
    func testMissingAndCredentialBearingAddressesAreNotShareable() {
        XCTAssertNil(NodeAddress.shareable(nil))
        XCTAssertNil(NodeAddress.shareable(""))
        XCTAssertNil(NodeAddress.shareable("http://user:secret@peer.example"))
    }
}
