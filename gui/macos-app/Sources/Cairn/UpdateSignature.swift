import Foundation

/// The second signature on an update, checked before Sparkle downloads it.
///
/// Sparkle checks an Ed25519 signature over the image once it has it. This
/// checks an ML-DSA-87 signature (post-quantum, FIPS 204) over the feed
/// item -- its version, URL, length and that Ed25519 signature -- against the
/// key the app was built with. Signing the Ed25519 signature rather than the
/// image is what makes the two one check: Ed25519 is deterministic and
/// hashes with SHA-512, so no other image produces the signature value this
/// one vouches for, quantum computer or not. packaging/macos/updates.sh signs
/// the same bytes, in the same order; change either side, change both.
enum UpdateSignature {
    /// Info.plist key holding the raw ML-DSA-87 public key, base64.
    static let publicKeyInfoKey = "CairnMLDSA87PublicKey"
    /// The feed item's element, as Sparkle names it in `propertiesDictionary`.
    static let feedElement = "cairn:mlDSA87Signature"
    static let header = "cairn-update/1"
    /// FIPS 204's context string: a signature made for anything else does not
    /// verify here even under the same key.
    static let context = "cairn-update"

    enum Failure: LocalizedError {
        case missing(String)
        case malformed(String)
        case rejected

        var errorDescription: String? {
            switch self {
            case .missing(let what):
                return "The update feed has no \(what), so this update cannot be verified."
            case .malformed(let what):
                return "The update feed's \(what) is not readable, so this update cannot be verified."
            case .rejected:
                return "The update's post-quantum signature does not match the key this app trusts, so it was not downloaded."
            }
        }
    }

    /// The bytes the signature is over.
    static func message(version: String, url: String, length: String, edSignature: String) -> Data {
        Data("\(header)\nversion=\(version)\nurl=\(url)\nlength=\(length)\ned25519=\(edSignature)\n".utf8)
    }

    /// The key from Info.plist, or nil when the build has none (or a broken one).
    static func publicKey(in bundle: Bundle = .main) -> MLDSA87.PublicKey? {
        guard let text = bundle.object(forInfoDictionaryKey: publicKeyInfoKey) as? String,
              let raw = Data(base64Encoded: text.trimmingCharacters(in: .whitespacesAndNewlines))
        else { return nil }
        return MLDSA87.PublicKey(rawRepresentation: raw)
    }

    /// Throws unless the feed item, as Sparkle parsed it, carries a signature
    /// under `publicKey` over exactly the fields Sparkle will act on.
    static func check(item properties: [String: Any], publicKey: MLDSA87.PublicKey) throws {
        guard let enclosure = properties["enclosure"] as? [String: String] else {
            throw Failure.missing("enclosure")
        }
        guard let url = enclosure["url"] else { throw Failure.missing("download URL") }
        guard let length = enclosure["length"] else { throw Failure.missing("download length") }
        guard let edSignature = enclosure["sparkle:edSignature"] else { throw Failure.missing("Ed25519 signature") }
        guard let version = properties["sparkle:version"] as? String else { throw Failure.missing("version") }
        guard let text = properties[feedElement] as? String else { throw Failure.missing("post-quantum signature") }
        guard let signature = Data(base64Encoded: text.trimmingCharacters(in: .whitespacesAndNewlines)),
              signature.count == MLDSA87.signatureSize
        else { throw Failure.malformed("post-quantum signature") }

        let message = message(version: version, url: url, length: length, edSignature: edSignature)
        guard publicKey.isValidSignature(signature, for: message, context: Data(context.utf8)) else {
            throw Failure.rejected
        }
    }
}
