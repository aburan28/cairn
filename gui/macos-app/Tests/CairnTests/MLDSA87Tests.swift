import Foundation
import XCTest
@testable import Cairn

/// The post-quantum check on an update, held to what OpenSSL signed: the
/// hash it is built on, the signature OpenSSL made over the fixture feed, and
/// the ways a feed can be wrong.
final class MLDSA87Tests: XCTestCase {
    private func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: SHAKE, against `openssl dgst -shake128/-shake256 -xoflen`

    func testShake128Empty() {
        XCTAssertEqual(hex(MLDSA87.shake128([], outputCount: 32)),
                       "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
    }

    func testShake256Short() {
        XCTAssertEqual(hex(MLDSA87.shake256(Array("abc".utf8), outputCount: 64)),
                       "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4")
    }

    /// Longer than one block, so the permutation runs mid-absorb.
    func testShake256AcrossBlocks() {
        let input = [UInt8](repeating: UInt8(ascii: "x"), count: 200)
        XCTAssertEqual(hex(MLDSA87.shake256(input, outputCount: 32)),
                       "4f2abcdeb0d29fd6c0f9d83c77cffe81df99dc8d32cd0e37230a96d409e2ed41")
    }

    /// Squeezing in pieces reads the same stream as squeezing at once.
    func testSqueezeIsAStream() {
        var one = Shake(rate: 136)
        one.absorb(Array("abc".utf8))
        let whole = one.squeeze(300)
        var two = Shake(rate: 136)
        two.absorb(Array("abc".utf8))
        var pieces: [UInt8] = []
        for n in [1, 3, 8, 135, 136, 17] {
            pieces += two.squeeze(n)
        }
        XCTAssertEqual(pieces, Array(whole.prefix(pieces.count)))
    }

    // MARK: the fixture feed

    private var publicKey: MLDSA87.PublicKey {
        MLDSA87.PublicKey(rawRepresentation: Data(base64Encoded: UpdateFeedFixture.pqPublicKey)!)!
    }

    private var signature: Data { Data(base64Encoded: UpdateFeedFixture.pqSignature)! }

    private var message: Data {
        UpdateSignature.message(
            version: UpdateFeedFixture.version, url: UpdateFeedFixture.url,
            length: UpdateFeedFixture.length, edSignature: UpdateFeedFixture.edSignature)
    }

    private var context: Data { Data(UpdateSignature.context.utf8) }

    func testKeyAndSignatureSizes() {
        XCTAssertEqual(Data(base64Encoded: UpdateFeedFixture.pqPublicKey)!.count, MLDSA87.publicKeySize)
        XCTAssertEqual(signature.count, MLDSA87.signatureSize)
        XCTAssertNil(MLDSA87.PublicKey(rawRepresentation: Data(repeating: 0, count: MLDSA87.publicKeySize - 1)))
    }

    func testOpenSSLSignatureVerifies() {
        XCTAssertTrue(publicKey.isValidSignature(signature, for: message, context: context))
    }

    func testOtherContextDoesNot() {
        XCTAssertFalse(publicKey.isValidSignature(signature, for: message, context: Data()))
        XCTAssertFalse(publicKey.isValidSignature(signature, for: message, context: Data("cairn-updates".utf8)))
    }

    func testChangedMessageDoesNot() {
        var changed = message
        changed[changed.count - 2] ^= 0x01
        XCTAssertFalse(publicKey.isValidSignature(signature, for: changed, context: context))
        XCTAssertFalse(publicKey.isValidSignature(signature, for: message + Data([0]), context: context))
    }

    func testChangedSignatureDoesNot() {
        for offset in [0, 63, 64, 2000, 64 + 640 * 7, MLDSA87.signatureSize - 1] {
            var changed = signature
            changed[offset] ^= 0x01
            XCTAssertFalse(publicKey.isValidSignature(changed, for: message, context: context), "byte \(offset)")
        }
        XCTAssertFalse(publicKey.isValidSignature(signature.dropLast(), for: message, context: context))
        XCTAssertFalse(publicKey.isValidSignature(signature + Data([0]), for: message, context: context))
    }

    func testOtherKeyDoesNot() {
        var other = Data(base64Encoded: UpdateFeedFixture.pqPublicKey)!
        other[0] ^= 0x01
        XCTAssertFalse(MLDSA87.PublicKey(rawRepresentation: other)!.isValidSignature(signature, for: message, context: context))
    }

    /// A hint encoding other than the one canonical form is a different
    /// signature, and the standard rejects it rather than reading past it.
    func testNonCanonicalHintsDoNot() {
        let hints = 64 + 640 * 7
        var changed = signature
        // A position past the count, where the padding must be zero.
        let count = Int(changed[hints + MLDSA87.omega])
        if count < MLDSA87.omega {
            changed[hints + count] = 1
            XCTAssertFalse(publicKey.isValidSignature(changed, for: message, context: context))
        }
        // A count past omega.
        changed = signature
        changed[hints + MLDSA87.omega + 7] = UInt8(MLDSA87.omega + 1)
        XCTAssertFalse(publicKey.isValidSignature(changed, for: message, context: context))
    }

    // MARK: the feed item as Sparkle hands it over

    private var properties: [String: Any] {
        [
            "sparkle:version": UpdateFeedFixture.version,
            "enclosure": [
                "url": UpdateFeedFixture.url,
                "length": UpdateFeedFixture.length,
                "type": "application/octet-stream",
                "sparkle:installationType": "package",
                "sparkle:edSignature": UpdateFeedFixture.edSignature,
            ],
            UpdateSignature.feedElement: UpdateFeedFixture.pqSignature,
        ]
    }

    func testFeedItemPasses() throws {
        try UpdateSignature.check(item: properties, publicKey: publicKey)
    }

    func testMessageIsWhatTheScriptSigns() {
        XCTAssertEqual(
            String(decoding: message, as: UTF8.self),
            "cairn-update/1\nversion=1.11.0\nurl=\(UpdateFeedFixture.url)\nlength=24\ned25519=\(UpdateFeedFixture.edSignature)\n")
    }

    private func expectFailure(_ item: [String: Any], _ line: UInt = #line) {
        XCTAssertThrowsError(try UpdateSignature.check(item: item, publicKey: publicKey), line: line) { error in
            XCTAssertTrue(error is UpdateSignature.Failure, line: line)
            XCTAssertFalse((error.localizedDescription).isEmpty, line: line)
        }
    }

    func testFeedItemWithAnotherImageFails() {
        var item = properties
        var enclosure = item["enclosure"] as! [String: String]
        enclosure["url"] = UpdateFeedFixture.url.replacingOccurrences(of: "v1.11.0/", with: "v1.11.1/")
        item["enclosure"] = enclosure
        expectFailure(item)

        item = properties
        enclosure = item["enclosure"] as! [String: String]
        enclosure["length"] = "25"
        item["enclosure"] = enclosure
        expectFailure(item)

        item = properties
        enclosure = item["enclosure"] as! [String: String]
        enclosure["sparkle:edSignature"] = String(UpdateFeedFixture.edSignature.dropFirst()) + "A"
        item["enclosure"] = enclosure
        expectFailure(item)

        item = properties
        item["sparkle:version"] = "1.11.1"
        expectFailure(item)
    }

    func testFeedItemWithoutTheSignatureFails() {
        var item = properties
        item.removeValue(forKey: UpdateSignature.feedElement)
        expectFailure(item)

        item = properties
        item[UpdateSignature.feedElement] = "not base64 at all"
        expectFailure(item)

        item = properties
        item.removeValue(forKey: "enclosure")
        expectFailure(item)
    }

    func testPublicKeyReadFromABundle() {
        XCTAssertNil(UpdateSignature.publicKey(in: Bundle(for: MLDSA87Tests.self)))
    }
}
