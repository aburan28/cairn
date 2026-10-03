import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// The search jobs this reader knows the shape of, keyed by the checker that
/// pins each one. The same table as `ui/lib/jobs.ts`, for the same reason.
///
/// `GET /progress/{id}` reports what the log has paid for: units, and the
/// steps those units cost. Turning that into *how far along the search is*
/// needs two numbers the log does not hold: the group order, which sets the
/// expected cost of a Pollard rho, and the size of the equivalence class the
/// walk runs on, which divides it. Both live in the job document the checker
/// pins by hash, and the node never parses that document. So the reader
/// carries the handful of constants it needs.
///
/// A copy is safe here because an objective pins its checker by SHA-256, the
/// checker pins the job by id, and the job's constants are inside that id.
/// Changing any of them posts a different objective with a different checker
/// hash, which this table does not know and the screen then shows without an
/// expected cost rather than with a wrong one. `ui/lib/jobs.test.ts` re-reads
/// every job file in the repository against the same constants.
///
/// Nothing here is used for payment. `expectedSteps` is the textbook
/// `sqrt(pi * n / 2)` divided by the square root of the class size, which for
/// ECC2K-130 is the 2^60.8 that Bailey et al. and the campaign's own status
/// page quote.
public struct SearchJob: Hashable, Sendable {
    /// The job's own `name`.
    public var name: String
    /// Repository-relative path of the job document.
    public var path: String
    public var version: Int
    /// The group order `n`, lowercase hex.
    public var order: String
    /// How many points one walk state stands for: `2m` for a version 2 orbit
    /// walk, `2` with the negation map, `1` without.
    public var classSize: Double
    /// Version 2: the field degree and the distinguishing weight.
    public var m: Int?
    public var dpMaxWeight: Int?
    /// Version 1: a point is distinguished when its low `dpBits` bits are zero.
    public var dpBits: Int?
    /// Version 2: `seed = (unit << trailBits) | trail`.
    public var trailBits: Int?

    /// What one paid unit is called on this job.
    public var unitNoun: String { version == 2 ? "orbits" : "points" }
}

public let searchJobs: [String: SearchJob] = [
    // examples/certicom-ecdlp/objective-ecc2k130-orbit-batch.json
    "502f5b58881ed1a83b0f882153f78b724bc4319744853d080e8b2134aec661a3": SearchJob(
        name: "certicom ecc2k-130",
        path: "examples/certicom-ecdlp/jobs/ecc2k130.json",
        version: 2,
        order: "200000000000000004d4fdd5703a3f269",
        classSize: 262,
        m: 131,
        dpMaxWeight: 34,
        trailBits: 16
    ),
    // examples/certicom-ecdlp/objective-ecc2k-23-orbit-batch.json
    "0ba12ff65fbdf7170cbd1f70732fac3ee6cfb222e0f4bdc8712ed0c162079626": SearchJob(
        name: "cairn ecc2k-23 orbit rho",
        path: "examples/certicom-ecdlp/jobs/ecc2k-23.json",
        version: 2,
        order: "1ffaed",
        classSize: 46,
        m: 23,
        dpMaxWeight: 8,
        trailBits: 16
    ),
    // examples/certicom-ecdlp/objective-nums-50-rho-batch.json
    "9c69e6f201d15d30f34fa7a2d53409c92a456dcec0e529c4081ec7e1b380c01c": SearchJob(
        name: "cairn nums-50 rho",
        path: "examples/certicom-ecdlp/jobs/nums-50-rho.json",
        version: 1,
        order: "4000002c8af47",
        classSize: 1,
        dpBits: 16
    ),
    // examples/certicom-ecdlp/objective-eccp131-rho-batch.json
    "24e217f87140ab291d405c18e7b9d4d5f423905fe22f2e4ead8bb7c64f044787": SearchJob(
        name: "cairn certicom eccp131 rho",
        path: "examples/certicom-ecdlp/jobs/eccp131-rho.json",
        version: 1,
        order: "48e1d43f293469e317f7ed728f6b8e6f1",
        classSize: 2,
        dpBits: 44
    ),
]

/// The job an objective's pinned checker runs, if this reader knows it.
public func jobFor(checkerSha256: String?) -> SearchJob? {
    guard let hash = checkerSha256?.lowercased() else { return nil }
    return searchJobs[hash]
}

/// The expected number of group operations to a collision: `sqrt(pi * n / 2)`
/// divided by the square root of the class size. The order is at most 2^131,
/// so reading it into a double loses nothing a sixth significant figure
/// would notice.
public func expectedSteps(_ job: SearchJob) -> Double? {
    guard let n = hexValue(job.order), n > 0, job.classSize > 0 else { return nil }
    return (Double.pi * n / (2 * job.classSize)).squareRoot()
}

/// Expected steps to one distinguished unit.
///
/// Version 1 is the mask: `2^dpBits`. Version 2 is the weight test: points
/// of odd order on a Koblitz curve have trace-zero abscissae, so only even
/// weights occur, and the hit rate is the share of the `2^(m-1)` even-weight
/// strings with weight at most the cutoff. `orbit_dp.py dp_expected_bits`
/// computes the same ratio, floored to a power of two.
public func stepsPerUnit(_ job: SearchJob) -> Double? {
    if job.version == 1 {
        guard let bits = job.dpBits else { return nil }
        return pow(2, Double(bits))
    }
    guard let m = job.m, let cutoff = job.dpMaxWeight, m > 0 else { return nil }
    var hits = 0.0
    var weight = 0
    while weight <= cutoff {
        hits += binomial(m, weight)
        weight += 2
    }
    guard hits > 0 else { return nil }
    return pow(2, Double(m - 1)) / hits
}

/// The expected number of units the whole search produces.
public func expectedUnits(_ job: SearchJob) -> Double? {
    guard let steps = expectedSteps(job), let per = stepsPerUnit(job), per > 0 else { return nil }
    return steps / per
}

/// `C(n, k)` in doubles: exact to the last bit for small arguments, and
/// within a few ulps for C(131, 34), which has 107 bits and is only ever
/// compared at one decimal of its logarithm.
private func binomial(_ n: Int, _ k: Int) -> Double {
    guard k >= 0, k <= n else { return 0 }
    var result = 1.0
    for i in 0..<k {
        result = result * Double(n - i) / Double(i + 1)
    }
    return result
}

/// A lowercase hex integer as a double, rounding past 53 bits.
private func hexValue(_ hex: String) -> Double? {
    guard !hex.isEmpty else { return nil }
    var value = 0.0
    for character in hex.lowercased() {
        guard let digit = character.hexDigitValue else { return nil }
        value = value * 16 + Double(digit)
    }
    return value
}
