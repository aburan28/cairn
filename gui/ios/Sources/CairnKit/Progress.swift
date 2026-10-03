import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// One objective's search in flight: `GET /progress/{id}`.
///
/// Mirrors `src/serve.rs::progress_of`, `src/progress.rs` and the website's
/// `ui/lib/progress.ts`. The answer has two halves and this file keeps them
/// as two types on purpose. `Derived` is recomputed from the node's log and
/// is what the search has been paid for. `Reported` is what workers said
/// about themselves over `POST /progress`, held in the node's memory and
/// verified by nobody. A screen renders both and says which is which: the
/// rule every other screen here follows about live and snapshot numbers,
/// applied to a distinction that matters more, because a reported rate is
/// what a reader will extrapolate from.
///
/// What this file computes for itself is arithmetic on numbers the node
/// published, plus the expected-cost figures from `Jobs.swift`, which are
/// statements about Pollard rho rather than about any node. Nothing here
/// re-derives a payment.
///
/// Step counts are `Double`. The node's totals are exact `u128`s; an `Int`
/// would hold a search's whole expected cost (2^60.8) but a count the node
/// ever published above 2^63 would not decode at all, and the screen would
/// show nothing rather than a rounded figure. A double keeps 53 bits, so a
/// count above nine quadrillion is rounded in its sixteenth digit, which
/// changes nothing a display does with it.

public struct ProgressWindow: Codable, Hashable, Sendable {
    public var claims_paid: Int
    public var units_paid: Int
    public var steps: Double
}

public struct DerivedWorker: Codable, Hashable, Identifiable, Sendable {
    public var submitter: String
    public var claims_paid: Int
    public var claims: Int
    public var rejected: Int
    public var in_flight: Int
    public var elements: Int
    public var units_paid: Int
    public var reward: Int
    public var steps: Double
    public var first_paid_at: String?
    public var last_paid_at: String?
    public var id: String { submitter }
}

public struct Coverage: Codable, Hashable, Sendable {
    public var bins: Int
    public var units: Int
    public var trail_bits: Int
    public var counts: [Int]
    public var units_touched: Int
    public var unbinned: Int
    public var method: String
}

public struct ProgressHour: Codable, Hashable, Identifiable, Sendable {
    public var hour: String
    public var claims_paid: Int
    public var units_paid: Int
    public var steps: Double
    public var id: String { hour }
}

public struct Derived: Codable, Sendable {
    public var claims_paid: Int
    public var claims: Int
    public var rejected: Int
    public var in_flight: Int
    public var elements: Int
    public var units_paid: Int
    public var reward: Int
    public var steps: Double
    public var first_paid_at: String?
    public var last_paid_at: String?
    public var workers: [DerivedWorker]
    public var hourly: [ProgressHour]
    public var last_hour: ProgressWindow
    public var last_day: ProgressWindow
    public var coverage: Coverage?
    public var steps_method: String
    public var note: String
}

public enum Liveness: String, Sendable {
    case live, stale, gone
}

public struct UnitRange: Codable, Hashable, Sendable {
    public var first: Int
    public var end: Int
}

public struct ReportedWorker: Codable, Hashable, Identifiable, Sendable {
    public var worker: String
    /// `live`, `stale` or `gone`, as the node wrote it. Kept as the string
    /// so a status this reader does not know fails one badge, not the decode.
    public var status: String
    public var first_seen_at: String
    public var received_at: String
    public var age_seconds: Double
    public var epoch: Int?
    public var units: UnitRange?
    public var unit: Int?
    public var steps: Double
    public var trails: Int
    public var capped: Int
    public var units_pending: Int
    public var units_submitted: Int
    public var reported_steps_per_second: Double?
    public var measured_steps_per_second: Double?
    public var device: String?
    public var lanes: Int?
    public var client: String?
    public var id: String { worker }
    public var liveness: Liveness { Liveness(rawValue: status) ?? .gone }
}

public struct Reported: Codable, Sendable {
    public var workers: [ReportedWorker]
    public var live: Int
    public var stale: Int
    public var gone: Int
    /// Sum over live workers of the measured rate, else the reported one.
    public var steps_per_second: Double
    public var steps: Double
    public var units_pending: Int
    public var live_within_seconds: Int
    public var stale_within_seconds: Int
    public var note: String
}

public struct ProgressResponse: Codable, Sendable {
    public var objective_id: String
    public var goal: String
    public var kind: String
    public var generated_at: String
    public var settled: Bool
    public var open: Bool
    public var piecework: Piecework?
    public var derived: Derived
    public var reported: Reported
    public var note: String
}

// MARK: - The two halves on one row

/// Live first, then stale, then gone, then names only the log knows.
public enum WorkerStanding: Int, Sendable {
    case live = 0, stale, gone, settled
}

/// One worker as the list shows it: what the log paid, beside what it said.
public struct WorkerRow: Identifiable, Sendable {
    public var name: String
    public var derived: DerivedWorker?
    public var reported: ReportedWorker?
    public var standing: WorkerStanding
    public var id: String { name }
}

/// Join the two halves on the worker's name, which is the submitter the
/// claims were made under. Within a standing, most paid first.
public func mergeWorkers(derived: [DerivedWorker], reported: [ReportedWorker]) -> [WorkerRow] {
    var rows: [String: WorkerRow] = [:]
    for worker in derived {
        rows[worker.submitter] = WorkerRow(name: worker.submitter, derived: worker, reported: nil, standing: .settled)
    }
    for worker in reported {
        let standing: WorkerStanding
        switch worker.liveness {
        case .live: standing = .live
        case .stale: standing = .stale
        case .gone: standing = .gone
        }
        if var row = rows[worker.worker] {
            row.reported = worker
            row.standing = standing
            rows[worker.worker] = row
        } else {
            rows[worker.worker] = WorkerRow(name: worker.worker, derived: nil, reported: worker, standing: standing)
        }
    }
    return rows.values.sorted { a, b in
        if a.standing.rawValue != b.standing.rawValue { return a.standing.rawValue < b.standing.rawValue }
        let paidA = a.derived?.units_paid ?? 0
        let paidB = b.derived?.units_paid ?? 0
        if paidA != paidB { return paidA > paidB }
        return a.name < b.name
    }
}

/// A worker's own rate: the one the node measured between two heartbeats
/// when it has one, else the one the worker reported, else nothing.
public func workerRate(_ worker: ReportedWorker?) -> Double? {
    guard let worker else { return nil }
    return worker.measured_steps_per_second ?? worker.reported_steps_per_second
}

// MARK: - The search as a whole

/// `steps / expected`, unclamped: a search past its expected cost reads over 1.
public func shareOfExpected(steps: Double, expected: Double) -> Double? {
    guard expected > 0, steps.isFinite else { return nil }
    return steps / expected
}

/// The chance a collision has already happened after `steps` of a search
/// whose expected cost is `expected`: `1 - exp(-pi/4 * (W/E)^2)`, the
/// birthday bound with the expectation normalised to `E`. Even odds fall at
/// 0.94 E and nine in ten at 1.71 E, which is why a search past its expected
/// cost is not late. The campaign's status page draws the same curve.
public func collisionOdds(steps: Double, expected: Double) -> Double? {
    guard let ratio = shareOfExpected(steps: steps, expected: expected) else { return nil }
    return -expm1(-Double.pi / 4 * ratio * ratio)
}

/// The work at which the odds reach `p`: the inverse of `collisionOdds`.
public func workForOdds(_ p: Double, expected: Double) -> Double? {
    guard expected > 0, p > 0, p < 1 else { return nil }
    return expected * ((-4 * log1p(-p)) / Double.pi).squareRoot()
}

/// Seconds until the search reaches its expected cost at `rate` steps a
/// second, or nil with no rate. Negative means past it, which
/// `collisionOdds` reads as a 54% chance of being done, not an overrun.
public func etaSeconds(steps: Double, expected: Double, rate: Double?) -> Double? {
    guard let rate, rate > 0, expected > 0 else { return nil }
    return (expected - steps) / rate
}

/// The share of bins with at least one paid element in them.
public func coverageFraction(_ coverage: Coverage?) -> Double? {
    guard let coverage, coverage.bins > 0 else { return nil }
    return Double(coverage.counts.filter { $0 > 0 }.count) / Double(coverage.bins)
}

/// The last `hours` hourly buckets ending at the hour containing `now`,
/// with empty hours as zeros, so a chart shows the gaps: an hour with no
/// settlement is a fact about the search, not a missing bar.
public func denseHours(_ hourly: [ProgressHour], hours: Int, now: Date) -> [ProgressHour] {
    let parser = ISO8601DateFormatter()
    var byStart: [Int: ProgressHour] = [:]
    for hour in hourly {
        guard let date = parser.date(from: hour.hour) else { continue }
        let at = Int(date.timeIntervalSince1970)
        byStart[at - at % 3600] = hour
    }
    let nowSeconds = Int(now.timeIntervalSince1970)
    let end = nowSeconds - nowSeconds % 3600
    var out: [ProgressHour] = []
    guard hours > 0 else { return out }
    for back in stride(from: hours - 1, through: 0, by: -1) {
        let start = end - back * 3600
        if let found = byStart[start] {
            out.append(found)
        } else {
            out.append(ProgressHour(hour: hourLabel(start), claims_paid: 0, units_paid: 0, steps: 0))
        }
    }
    return out
}

/// `2026-10-03T11:00:00+00:00`, the way the node spells an hour.
private func hourLabel(_ epochSeconds: Int) -> String {
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.timeZone = TimeZone(secondsFromGMT: 0)
    formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss"
    return formatter.string(from: Date(timeIntervalSince1970: TimeInterval(epochSeconds))) + "+00:00"
}

/// The command that works this objective from a checkout, with this node
/// and this objective filled in. The reference worker and the job document
/// are named by path rather than linked: nothing in this reader points at a
/// hosting site's web UI.
public func workerCommand(origin: String, id: String, job: SearchJob?) -> String {
    [
        "python3 examples/certicom-ecdlp/tools/orbit_worker.py",
        "--node \(origin)",
        "--job \(job?.path ?? "<job document>")",
        "--objective \(id)",
        "--worker <your name>",
    ].joined(separator: " \\\n  ")
}

// MARK: - Formatting, as ui/lib/progress.ts spells it

/// `2^60.81`, for a count whose magnitude is the point.
public func formatLog2(_ value: Double) -> String {
    guard value > 0 else { return "2^−∞" }
    return "2^" + String(format: "%.2f", log2(value))
}

/// `1.40 G`, `12.3 M`, `950`.
public func formatMagnitude(_ value: Double) -> String {
    guard value.isFinite else { return "—" }
    let scales: [(Double, String)] = [(1e15, "P"), (1e12, "T"), (1e9, "G"), (1e6, "M"), (1e3, "k")]
    for (scale, suffix) in scales where value >= scale {
        let scaled = value / scale
        let digits = scaled >= 100 ? 0 : (scaled >= 10 ? 1 : 2)
        return String(format: "%.\(digits)f", scaled) + " " + suffix
    }
    return String(Int(value.rounded()))
}

/// `1.40 G it/s`, `12.3 M it/s`, `950 it/s`.
public func formatRate(_ stepsPerSecond: Double?) -> String {
    guard let stepsPerSecond, stepsPerSecond.isFinite else { return "—" }
    return formatMagnitude(stepsPerSecond) + " it/s"
}

/// `3 d 4 h`, `12 min`, `2.5 y`; negative reads as `past by …`.
public func formatDuration(_ seconds: Double?) -> String {
    guard let seconds, seconds.isFinite else { return "—" }
    let past = seconds < 0
    let s = abs(seconds)
    let text: String
    if s < 60 {
        text = "\(Int(s.rounded())) s"
    } else if s < 3600 {
        text = "\(Int((s / 60).rounded())) min"
    } else if s < 86_400 {
        let minutes = Int((s.truncatingRemainder(dividingBy: 3600) / 60).rounded())
        text = "\(Int(s / 3600)) h \(minutes) min"
    } else if s < 365.25 * 86_400 {
        let hours = Int((s.truncatingRemainder(dividingBy: 86_400) / 3600).rounded())
        text = "\(Int(s / 86_400)) d \(hours) h"
    } else {
        text = String(format: "%.1f", s / (365.25 * 86_400)) + " y"
    }
    return past ? "past by \(text)" : text
}

/// A percentage with the precision its size deserves: 0.004% is not 0%.
public func formatPercent(_ fraction: Double?) -> String {
    guard let fraction, fraction.isFinite else { return "—" }
    let pct = fraction * 100
    if pct == 0 { return "0%" }
    if pct < 0.01 { return exponential(pct, digits: 1) + "%" }
    if pct < 1 { return String(format: "%.3f", pct) + "%" }
    if pct < 10 { return String(format: "%.2f", pct) + "%" }
    return String(format: "%.1f", pct) + "%"
}

/// JavaScript's `toExponential(digits)`: `4.0e-3`, not C's `4.0e-03`.
private func exponential(_ value: Double, digits: Int) -> String {
    guard value != 0, value.isFinite else { return String(format: "%.\(digits)f", value) }
    var exponent = Int(floor(log10(abs(value))))
    var mantissa = value / pow(10, Double(exponent))
    if abs(mantissa) >= 10 - 0.5 * pow(10, -Double(digits)) {
        mantissa /= 10
        exponent += 1
    }
    let sign = exponent < 0 ? "-" : "+"
    return String(format: "%.\(digits)f", mantissa) + "e" + sign + String(abs(exponent))
}

/// `42 s ago`, `3 min ago`, `2 h ago`.
public func formatAge(_ seconds: Double) -> String {
    if seconds < 60 { return "\(Int(seconds.rounded())) s ago" }
    if seconds < 3600 { return "\(Int((seconds / 60).rounded())) min ago" }
    if seconds < 86_400 { return "\(Int((seconds / 3600).rounded())) h ago" }
    return "\(Int((seconds / 86_400).rounded())) d ago"
}
