import Foundation
import XCTest
@testable import Cairn
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// The port test against real sockets on loopback, and the node's log read
/// in the exact shapes `src/daemon.rs` writes.
final class ConnectivityTests: XCTestCase {
    /// A listening socket on 127.0.0.1 and the port the kernel gave it.
    private func listener() throws -> (fd: Int32, port: UInt16) {
        #if canImport(Darwin)
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        #else
        let fd = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        #endif
        guard fd >= 0 else { throw XCTSkip("no socket") }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let bound = withUnsafeMutablePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, len) == 0 && getsockname(fd, $0, &len) == 0
            }
        }
        XCTAssertTrue(bound)
        XCTAssertEqual(listen(fd, 8), 0)
        return (fd, UInt16(bigEndian: addr.sin_port))
    }

    func testAListeningPortIsOpenAndAClosedOneRefused() async throws {
        let (fd, port) = try listener()
        let open = await PortProbe.tcp("127.0.0.1", port)
        XCTAssertEqual(open, .open)
        close(fd)
        // The same port with its listener gone: the host answers, nobody is home.
        let closed = await PortProbe.tcp("127.0.0.1", port)
        XCTAssertEqual(closed, .refused)
    }

    func testANameThatDoesNotResolveSaysSo() async {
        let result = await PortProbe.tcp("no-such-host.invalid", 9000, timeout: 2)
        guard case .unresolved = result else { return XCTFail("got \(result)") }
    }

    func testAddressesSplitAtTheLastColon() {
        XCTAssertEqual(PortProbe.split("44.251.117.84:9000")?.host, "44.251.117.84")
        XCTAssertEqual(PortProbe.split("[::1]:9000")?.host, "::1")
        XCTAssertEqual(PortProbe.split("[::1]:9000")?.port, 9000)
        XCTAssertNil(PortProbe.split("host"))
        XCTAssertNil(PortProbe.split("host:0"))
        XCTAssertNil(PortProbe.split(":9000"))
    }

    func testTheNodesLogIsReadPerSeedAndPerAddress() {
        let lines = [
            "WARN seeds: us-west at 44.251.117.84:9000 did not hand over its key (Connection refused (os error 61)); asking again in 60s.",
            "INFO seeds: eu at 192.0.2.1:9000 answered at nowhere",  // not a shape daemon.rs writes
            "INFO seeds: us-west answered at 44.251.117.84:9000 with the key its id names; dialable now",
            "WARN outbound session to abcd (10.0.0.5:9000): Connection refused (os error 61)",
        ]
        let seeds = NetworkLog.seeds(in: lines)
        XCTAssertEqual(seeds.map(\.name), ["us-west"], "the latest word per seed, and only the shapes the node writes")
        XCTAssertEqual(seeds.first?.ok, true)
        let failed = NetworkLog.seeds(in: [lines[0]]).first
        XCTAssertEqual(failed?.ok, false)
        XCTAssertEqual(failed?.detail, "the node's handshake failed: Connection refused (os error 61)")
        XCTAssertEqual(NetworkLog.lastDialFailure(to: "10.0.0.5:9000", in: lines), "Connection refused (os error 61)")
        XCTAssertNil(NetworkLog.lastDialFailure(to: "10.0.0.6:9000", in: lines))
    }

    func testABootstrapFileIsReadForItsAddress() throws {
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("bootstrap-\(UUID()).json")
        defer { try? FileManager.default.removeItem(at: file) }
        try Data(#"{"addr":"203.0.113.9:5000","public":"00"}"#.utf8).write(to: file)
        XCTAssertEqual(BootstrapFile.address(file.path), "203.0.113.9:5000")
        XCTAssertNil(BootstrapFile.address(file.path + ".missing"))
    }

    func testLanAddressesExcludeLoopbackAndLinkLocal() {
        for iface in LocalNetwork.ipv4() {
            XCTAssertFalse(iface.address.hasPrefix("127."), iface.address)
            XCTAssertFalse(iface.address.hasPrefix("169.254."), iface.address)
        }
    }
}
