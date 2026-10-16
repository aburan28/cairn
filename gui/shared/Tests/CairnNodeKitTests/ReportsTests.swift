import XCTest
@testable import CairnNodeKit
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

final class ReportsTests: XCTestCase {
    private func fixture(_ name: String) throws -> Data {
        try Data(contentsOf: XCTUnwrap(Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Fixtures")))
    }
    func testPublisherIsDifferentFromAnEmptyMesh() throws {
        let publisher = try JSONDecoder().decode(SessionReport.self, from: fixture("publisher"))
        XCTAssertFalse(publisher.available)
        XCTAssertEqual(publisher.reached, 0)
        let mesh = try JSONDecoder().decode(SessionReport.self, from: fixture("sessions"))
        XCTAssertTrue(mesh.available)
        XCTAssertEqual(mesh.peers.map(\.status), ["reached", "recent", "lost", "unreached"])
        XCTAssertNil(mesh.peers.last?.age_seconds)
        XCTAssertEqual(mesh.this_node?.uptime_seconds, 300)
        XCTAssertEqual(mesh.address_book?.endpoints, 4)
    }
    func testNetworkFixtureFromTheNodeKeepsReportedAndEvidencedFactsSeparate() throws {
        let report = try JSONDecoder().decode(NetworkReport.self, from: fixture("network"))
        XCTAssertEqual(report.compute.live, 0)
        XCTAssertEqual(report.compute.steps_per_second, 0)
        XCTAssertEqual(report.roles.coordinators.total, 0)
        XCTAssertFalse(report.node.runs_p2p)
        XCTAssertFalse(report.compute.note.isEmpty)
    }
    func testReaderURLsPreserveProxyPathsAndCompareOrigins() throws {
        let url = try XCTUnwrap(URL(string: "https://node.test/proxy/cairn/ui/network/?old=1#hash"))
        XCTAssertEqual(NodeEndpoint.origin(url)?.absoluteString, "https://node.test/proxy/cairn")
        XCTAssertEqual(NodeEndpoint.reader(url, page: "coordination", objective: "sha256:abc")?.absoluteString, "https://node.test/proxy/cairn/ui/coordination?id=sha256:abc")
        XCTAssertTrue(NodeEndpoint.sameOrigin(URL(string: "https://node.test")!, URL(string: "https://node.test:443/ui/")!))
        XCTAssertFalse(NodeEndpoint.sameOrigin(URL(string: "https://node.test")!, URL(string: "http://node.test")!))
        XCTAssertNil(NodeEndpoint.origin(URL(string: "file:///tmp/node")!))
    }
    func testReaderNavigationNeverLaunchesSchemesFromScriptOrSubframes() {
        let node = URL(string: "http://127.0.0.1:8080/ui/")!
        XCTAssertTrue(ReaderNavigation.staysInReader(URL(string: "http://127.0.0.1:8080/ui/network")!, node: node))
        XCTAssertFalse(ReaderNavigation.staysInReader(URL(string: "http://127.0.0.1:8081/ui/")!, node: node))
        for text in ["file:///tmp/file", "smb://host/share", "custom://launch"] {
            XCTAssertFalse(ReaderNavigation.mayOpenExternally(URL(string: text)!, clicked: true, mainFrame: true))
        }
        XCTAssertFalse(ReaderNavigation.mayOpenExternally(URL(string: "https://example.org")!, clicked: false, mainFrame: true))
        XCTAssertFalse(ReaderNavigation.mayOpenExternally(URL(string: "https://example.org")!, clicked: true, mainFrame: false))
    }
    func testSecretNamesMatchTheCLIsASCIIEnvironmentNames() {
        XCTAssertTrue(SecretName.isValid("AWS_SECRET_ACCESS_KEY"))
        XCTAssertTrue(SecretName.isValid("_KEY2"))
        for value in ["", "2KEY", "éKEY", "KEY-NAME", "NAME\n", String(repeating: "A", count: 129)] { XCTAssertFalse(SecretName.isValid(value)) }
        XCTAssertEqual(Set(CuratedTasks.all.map(\.id)).count, CuratedTasks.all.count)
        XCTAssertTrue(CuratedTasks.all.allSatisfy { !$0.objectives.isEmpty })
    }
    func testClientUsesTheSelectedOriginAndReportsHTTPFailure() async throws {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [ReportProtocol.self]
        let session = URLSession(configuration: config)
        defer { session.invalidateAndCancel() }
        let client = NodeReportClient(base: URL(string: "https://node.test/proxy/ui/network")!, session: session)
        do { _ = try await client.sessions(); XCTFail("404 must not become an empty mesh") }
        catch NodeReadError.status(let status) { XCTAssertEqual(status, 404) }
        let report = try await client.network()
        XCTAssertEqual(report.compute.live, 0)
    }
}

private final class ReportProtocol: URLProtocol {
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let url = request.url!
        let isNetwork = url.path == "/proxy/network"
        let response = HTTPURLResponse(url: url, statusCode: isNetwork ? 200 : 404, httpVersion: nil, headerFields: ["content-type": "application/json"])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        if isNetwork, let fixture = Bundle.module.url(forResource: "network", withExtension: "json", subdirectory: "Fixtures"), let bytes = try? Data(contentsOf: fixture) { client?.urlProtocol(self, didLoad: bytes) }
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}
