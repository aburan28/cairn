import Foundation

/// ML-DSA-87 signature verification (FIPS 204), and the SHAKE it is built on.
///
/// Verification only: the app never signs. Written here rather than taken
/// from CryptoKit because CryptoKit's ML-DSA begins with macOS 26 and this
/// app runs on 13, and the one other Swift implementation, swift-crypto, is
/// CryptoKit under another name on a Mac. Checking a signature handles no
/// secret, so the usual reasons not to write one's own -- timing, and the
/// key -- do not apply; what does apply is correctness, which
/// Tests/CairnTests/MLDSA87Tests.swift holds to signatures OpenSSL made.
///
/// Parameters are ML-DSA-87's, the strongest set the standard defines
/// (NIST security category 5). Nothing here is generic over the others.
enum MLDSA87 {
    static let q = 8_380_417
    static let k = 8
    static let l = 7
    static let tau = 60
    static let gamma1 = 1 << 19
    static let gamma2 = (q - 1) / 32
    static let beta = tau * 2  // tau * eta
    static let omega = 75
    static let twoToD = 1 << 13

    static let publicKeySize = 32 + 32 * k * 10  // 2592
    static let signatureSize = 64 + l * 32 * 20 + omega + k  // 4627

    struct PublicKey {
        let bytes: [UInt8]

        /// FIPS 204's serialization: rho, then t1 packed ten bits a coefficient.
        init?<D: DataProtocol>(rawRepresentation: D) {
            let bytes = Array(rawRepresentation)
            guard bytes.count == MLDSA87.publicKeySize else { return nil }
            self.bytes = bytes
        }

        /// ML-DSA.Verify with a context string, as OpenSSL's
        /// `pkeyutl -pkeyopt context-string:` signs.
        func isValidSignature<S: DataProtocol, D: DataProtocol, C: DataProtocol>(
            _ signature: S, for message: D, context: C
        ) -> Bool {
            let context = Array(context)
            guard context.count <= 255 else { return false }
            var mPrime: [UInt8] = [0, UInt8(context.count)]
            mPrime += context
            mPrime += Array(message)
            return MLDSA87.verifyInternal(publicKey: bytes, message: mPrime, signature: Array(signature))
        }
    }

    // MARK: Algorithm 8, ML-DSA.Verify_internal

    private static func verifyInternal(publicKey pk: [UInt8], message mPrime: [UInt8], signature sig: [UInt8]) -> Bool {
        guard sig.count == signatureSize else { return false }

        let rho = Array(pk[0..<32])
        var t1: [[Int]] = []
        for i in 0..<k {
            let start = 32 + 320 * i
            t1.append(simpleBitUnpack(pk[start..<start + 320], bits: 10))
        }

        let cTilde = Array(sig[0..<64])
        var z: [[Int]] = []
        for i in 0..<l {
            let start = 64 + 640 * i
            // BitUnpack(v, gamma1 - 1, gamma1): gamma1 minus the raw value.
            z.append(simpleBitUnpack(sig[start..<start + 640], bits: 20).map { gamma1 - $0 })
        }
        guard let hints = hintBitUnpack(Array(sig[(64 + 640 * l)...])) else { return false }

        // ||z||_inf < gamma1 - beta, before any of the work below.
        for poly in z {
            for coefficient in poly where abs(coefficient) >= gamma1 - beta {
                return false
            }
        }

        let tr = shake256(pk, outputCount: 64)
        let mu = shake256(tr + mPrime, outputCount: 64)
        let cHat = ntt(sampleInBall(cTilde))
        let zHat = z.map { ntt($0.map(reduce)) }

        var w1Bytes: [UInt8] = []
        w1Bytes.reserveCapacity(k * 128)
        for r in 0..<k {
            var accumulator = [Int](repeating: 0, count: 256)
            for s in 0..<l {
                let a = rejNTTPoly(rho: rho, s: s, r: r)
                for j in 0..<256 {
                    accumulator[j] = (accumulator[j] + a[j] * zHat[s][j]) % q
                }
            }
            let t1Hat = ntt(t1[r].map { $0 * twoToD % q })
            for j in 0..<256 {
                accumulator[j] = reduce(accumulator[j] - cHat[j] * t1Hat[j] % q)
            }
            let wApprox = inverseNTT(accumulator)
            var w1 = [Int](repeating: 0, count: 256)
            for j in 0..<256 {
                w1[j] = useHint(hints[r][j], wApprox[j])
            }
            w1Bytes += simpleBitPack(w1, bits: 4)
        }

        let cTilde2 = shake256(mu + w1Bytes, outputCount: 64)
        var difference: UInt8 = 0
        for i in 0..<64 {
            difference |= cTilde[i] ^ cTilde2[i]
        }
        return difference == 0
    }

    // MARK: arithmetic mod q

    private static func reduce(_ x: Int) -> Int {
        let r = x % q
        return r < 0 ? r + q : r
    }

    /// zeta^BitRev8(i) mod q, for the butterflies.
    private static let zetas: [Int] = {
        var table = [Int](repeating: 0, count: 256)
        for i in 0..<256 {
            var reversed = 0
            for bit in 0..<8 where i & (1 << bit) != 0 {
                reversed |= 1 << (7 - bit)
            }
            var power = 1
            var base = 1753
            var exponent = reversed
            while exponent > 0 {
                if exponent & 1 == 1 { power = power * base % q }
                base = base * base % q
                exponent >>= 1
            }
            table[i] = power
        }
        return table
    }()

    /// Algorithm 41.
    private static func ntt(_ w: [Int]) -> [Int] {
        var w = w
        var m = 0
        var len = 128
        while len >= 1 {
            var start = 0
            while start < 256 {
                m += 1
                let z = zetas[m]
                for j in start..<start + len {
                    let t = z * w[j + len] % q
                    w[j + len] = reduce(w[j] - t)
                    w[j] = reduce(w[j] + t)
                }
                start += 2 * len
            }
            len /= 2
        }
        return w
    }

    /// Algorithm 42.
    private static func inverseNTT(_ w: [Int]) -> [Int] {
        var w = w
        var m = 256
        var len = 1
        while len < 256 {
            var start = 0
            while start < 256 {
                m -= 1
                let z = q - zetas[m]
                for j in start..<start + len {
                    let t = w[j]
                    w[j] = reduce(t + w[j + len])
                    w[j + len] = reduce(t - w[j + len])
                    w[j + len] = z * w[j + len] % q
                }
                start += 2 * len
            }
            len *= 2
        }
        let f = 8_347_681  // 256^-1 mod q
        return w.map { $0 * f % q }
    }

    // MARK: sampling

    /// Algorithm 30, one entry of ExpandA: A-hat[r][s] from rho || s || r.
    private static func rejNTTPoly(rho: [UInt8], s: Int, r: Int) -> [Int] {
        var xof = Shake(rate: 168)
        xof.absorb(rho + [UInt8(s), UInt8(r)])
        var a = [Int](repeating: 0, count: 256)
        var j = 0
        while j < 256 {
            let b = xof.squeeze(3)
            let z = Int(b[0]) | Int(b[1]) << 8 | Int(b[2] & 0x7F) << 16
            if z < q {
                a[j] = z
                j += 1
            }
        }
        return a
    }

    /// Algorithm 29: tau coefficients of ±1, placed by the challenge hash.
    private static func sampleInBall(_ seed: [UInt8]) -> [Int] {
        var xof = Shake(rate: 136)
        xof.absorb(seed)
        let signs = xof.squeeze(8)
        var c = [Int](repeating: 0, count: 256)
        for i in (256 - tau)..<256 {
            var j: Int
            repeat {
                j = Int(xof.squeeze(1)[0])
            } while j > i
            c[i] = c[j]
            let bit = i + tau - 256
            c[j] = (signs[bit / 8] >> (bit % 8)) & 1 == 1 ? q - 1 : 1
        }
        return c
    }

    // MARK: rounding

    /// Algorithm 40 over Algorithm 36: the high bits of r, corrected by the
    /// signer's hint.
    private static func useHint(_ hint: Int, _ r: Int) -> Int {
        let alpha = 2 * gamma2
        let m = (q - 1) / alpha  // 16
        var r0 = r % alpha
        if r0 > gamma2 { r0 -= alpha }
        var r1: Int
        if r - r0 == q - 1 {
            r1 = 0
            r0 -= 1
        } else {
            r1 = (r - r0) / alpha
        }
        if hint == 1 {
            r1 = r0 > 0 ? (r1 + 1) % m : (r1 + m - 1) % m
        }
        return r1
    }

    // MARK: encoding

    /// Algorithm 19: 256 coefficients of `bits` bits each, little-endian.
    private static func simpleBitUnpack(_ bytes: ArraySlice<UInt8>, bits: Int) -> [Int] {
        let bytes = Array(bytes)
        var out = [Int](repeating: 0, count: 256)
        for i in 0..<256 {
            var value = 0
            for b in 0..<bits {
                let bitIndex = i * bits + b
                value |= Int((bytes[bitIndex / 8] >> (bitIndex % 8)) & 1) << b
            }
            out[i] = value
        }
        return out
    }

    /// Algorithm 16, the inverse, for w1Encode.
    private static func simpleBitPack(_ w: [Int], bits: Int) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 32 * bits)
        for i in 0..<256 {
            for b in 0..<bits where (w[i] >> b) & 1 == 1 {
                let bitIndex = i * bits + b
                out[bitIndex / 8] |= 1 << (bitIndex % 8)
            }
        }
        return out
    }

    /// Algorithm 21: at most omega hint positions, sorted within each
    /// polynomial, with the running count after each one. Nil for any
    /// encoding the standard rejects, so a signature has one valid form.
    private static func hintBitUnpack(_ y: [UInt8]) -> [[Int]]? {
        guard y.count == omega + k else { return nil }
        var h = [[Int]](repeating: [Int](repeating: 0, count: 256), count: k)
        var index = 0
        for i in 0..<k {
            let end = Int(y[omega + i])
            if end < index || end > omega { return nil }
            let first = index
            while index < end {
                if index > first, y[index - 1] >= y[index] { return nil }
                h[i][Int(y[index])] = 1
                index += 1
            }
        }
        for i in index..<omega where y[i] != 0 {
            return nil
        }
        return h
    }

    // MARK: hashing

    static func shake256(_ input: [UInt8], outputCount: Int) -> [UInt8] {
        var xof = Shake(rate: 136)
        xof.absorb(input)
        return xof.squeeze(outputCount)
    }

    static func shake128(_ input: [UInt8], outputCount: Int) -> [UInt8] {
        var xof = Shake(rate: 168)
        xof.absorb(input)
        return xof.squeeze(outputCount)
    }
}

/// SHAKE128 (rate 168) and SHAKE256 (rate 136), FIPS 202: absorb, then
/// squeeze as many bytes as wanted, a few at a time.
struct Shake {
    private var state = [UInt64](repeating: 0, count: 25)
    private let rate: Int
    private var position = 0
    private var squeezing = false

    init(rate: Int) {
        self.rate = rate
    }

    private mutating func xorByte(_ byte: UInt8, at index: Int) {
        state[index / 8] ^= UInt64(byte) << (8 * UInt64(index % 8))
    }

    private func byte(at index: Int) -> UInt8 {
        UInt8(truncatingIfNeeded: state[index / 8] >> (8 * UInt64(index % 8)))
    }

    mutating func absorb(_ bytes: [UInt8]) {
        precondition(!squeezing, "absorb after squeeze")
        for b in bytes {
            xorByte(b, at: position)
            position += 1
            if position == rate {
                Keccak.permute(&state)
                position = 0
            }
        }
    }

    mutating func squeeze(_ count: Int) -> [UInt8] {
        if !squeezing {
            xorByte(0x1F, at: position)
            xorByte(0x80, at: rate - 1)
            Keccak.permute(&state)
            position = 0
            squeezing = true
        }
        var out: [UInt8] = []
        out.reserveCapacity(count)
        while out.count < count {
            if position == rate {
                Keccak.permute(&state)
                position = 0
            }
            out.append(byte(at: position))
            position += 1
        }
        return out
    }
}

enum Keccak {
    private static let roundConstants: [UInt64] = [
        0x0000_0000_0000_0001, 0x0000_0000_0000_8082, 0x8000_0000_0000_808A, 0x8000_0000_8000_8000,
        0x0000_0000_0000_808B, 0x0000_0000_8000_0001, 0x8000_0000_8000_8081, 0x8000_0000_0000_8009,
        0x0000_0000_0000_008A, 0x0000_0000_0000_0088, 0x0000_0000_8000_8009, 0x0000_0000_8000_000A,
        0x0000_0000_8000_808B, 0x8000_0000_0000_008B, 0x8000_0000_0000_8089, 0x8000_0000_0000_8003,
        0x8000_0000_0000_8002, 0x8000_0000_0000_0080, 0x0000_0000_0000_800A, 0x8000_0000_8000_000A,
        0x8000_0000_8000_8081, 0x8000_0000_0000_8080, 0x0000_0000_8000_0001, 0x8000_0000_8000_8008,
    ]

    /// Rotation offsets, indexed x + 5y.
    private static let rotations: [UInt64] = [
        0, 1, 62, 28, 27,
        36, 44, 6, 55, 20,
        3, 10, 43, 25, 39,
        41, 45, 15, 21, 8,
        18, 2, 61, 56, 14,
    ]

    private static func rotl(_ x: UInt64, _ n: UInt64) -> UInt64 {
        n == 0 ? x : (x << n) | (x >> (64 - n))
    }

    /// Keccak-f[1600], 24 rounds, lanes indexed x + 5y.
    static func permute(_ a: inout [UInt64]) {
        var b = [UInt64](repeating: 0, count: 25)
        var c = [UInt64](repeating: 0, count: 5)
        for round in 0..<24 {
            // theta
            for x in 0..<5 {
                c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20]
            }
            for x in 0..<5 {
                let d = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1)
                for y in 0..<5 {
                    a[x + 5 * y] ^= d
                }
            }
            // rho and pi
            for x in 0..<5 {
                for y in 0..<5 {
                    b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(a[x + 5 * y], rotations[x + 5 * y])
                }
            }
            // chi
            for y in 0..<5 {
                for x in 0..<5 {
                    a[x + 5 * y] = b[x + 5 * y] ^ (~b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y])
                }
            }
            // iota
            a[0] ^= roundConstants[round]
        }
    }
}
