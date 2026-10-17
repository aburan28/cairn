import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import XCTest
@testable import Cairn
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

private func bindAIListener(_ fd: Int32, _ address: UnsafePointer<sockaddr>, _ size: socklen_t) -> Int32 {
    bind(fd, address, size)
}

/// Real URLSession redirects, using only disposable loopback listeners and
/// fixture credentials: a policy helper alone cannot prove the session uses it.
final class AITransportTests: XCTestCase {
    private final class Listener: @unchecked Sendable {
        let fd: Int32
        let port: UInt16

        init() throws {
            #if canImport(Darwin)
            let descriptor = socket(AF_INET, SOCK_STREAM, 0)
            #else
            let descriptor = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
            #endif
            guard descriptor >= 0 else { throw AIError("Could not create a test socket") }
            fd = descriptor
            var address = sockaddr_in()
            address.sin_family = sa_family_t(AF_INET)
            address.sin_addr.s_addr = inet_addr("127.0.0.1")
            var size = socklen_t(MemoryLayout<sockaddr_in>.size)
            let bound = withUnsafeMutablePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    bindAIListener(descriptor, $0, size) == 0 && getsockname(descriptor, $0, &size) == 0
                }
            }
            guard bound, listen(fd, 4) == 0 else {
                close(fd)
                throw AIError("Could not bind a test listener")
            }
            port = UInt16(bigEndian: address.sin_port)
        }

        deinit { close(fd) }

        func hasConnection(timeout: Int32) -> Bool {
            var ready = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            return poll(&ready, 1, timeout) > 0 && ready.revents & Int16(POLLIN) != 0
        }

        func respond(_ responses: [String]) {
            DispatchQueue.global().async {
                for response in responses {
                    guard self.hasConnection(timeout: 5000) else { return }
                    let client = accept(self.fd, nil, nil)
                    guard client >= 0 else { return }
                    var timeout = timeval(tv_sec: 5, tv_usec: 0)
                    _ = setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
                    var request = Data()
                    var chunk = [UInt8](repeating: 0, count: 4096)
                    while request.count < 8192 {
                        let count = recv(client, &chunk, chunk.count, 0)
                        guard count > 0 else { break }
                        request.append(contentsOf: chunk.prefix(count))
                        guard let end = request.range(of: Data("\r\n\r\n".utf8)) else { continue }
                        let headers = String(decoding: request[..<end.lowerBound], as: UTF8.self)
                        let length = headers.components(separatedBy: "\r\n")
                            .first { $0.lowercased().hasPrefix("content-length:") }
                            .flatMap { Int($0.dropFirst("content-length:".count).trimmingCharacters(in: .whitespaces)) } ?? 0
                        if request.count >= end.upperBound + length { break }
                    }
                    let bytes = Array(response.utf8)
                    bytes.withUnsafeBytes { buffer in
                        var sent = 0
                        while sent < buffer.count {
                            let count = send(client, buffer.baseAddress!.advanced(by: sent), buffer.count - sent, 0)
                            guard count > 0 else { break }
                            sent += count
                        }
                    }
                    close(client)
                }
            }
        }

        var url: URL { URL(string: "http://127.0.0.1:\(port)/v1/messages")! }
    }

    func testTheProviderSessionDoesNotForwardCredentialsOrBodyToAnotherOrigin() async throws {
        let destination = try Listener()
        let origin = try Listener()
        origin.respond(["HTTP/1.1 307 Temporary Redirect\r\nLocation: \(destination.url)\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"])
        var request = URLRequest(url: origin.url)
        request.httpMethod = "POST"
        request.setValue("fixture-key", forHTTPHeaderField: "x-api-key")
        request.httpBody = Data("private-challenge-fixture".utf8)
        let (_, response) = try await AIClient.session.data(for: request)
        XCTAssertEqual((response as? HTTPURLResponse)?.statusCode, 307)
        XCTAssertFalse(destination.hasConnection(timeout: 100), "No request, header or body may reach the other origin")
    }

    func testTheProviderSessionStillFollowsRedirectsWithinItsOrigin() async throws {
        let origin = try Listener()
        origin.respond([
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: /canonical/messages\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        ])
        let (body, response) = try await AIClient.session.data(from: origin.url)
        XCTAssertEqual((response as? HTTPURLResponse)?.statusCode, 200)
        XCTAssertEqual(String(decoding: body, as: UTF8.self), "ok")
    }
}
