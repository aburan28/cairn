import Foundation
import CoreFoundation

/// Parse NDJSON into records, one line at a time.
///
/// Per line, and guarded per line, rather than one decode over the whole
/// body: a single malformed line used to throw out of the loop and leave
/// the reader with an error where the log should be. What a reader needs
/// from a corrupt line is *which* line, and the ones around it still
/// rendered. Same contract as `parseLog` in `ui/lib/log.ts`.
public func parseLog(_ text: String) -> ParsedLog {
    var records: [LogRecord] = []
    var problems: [String] = []
    let lines = text.split(separator: "\n", omittingEmptySubsequences: false)
    for (index, line) in lines.enumerated() {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { continue }
        do {
            records.append(try decodeLogRecord(trimmed, line: index + 1))
        } catch {
            problems.append("line \(index + 1): \(error.localizedDescription)")
        }
    }
    return ParsedLog(records: records, problems: problems)
}

private func decodeLogRecord(_ line: String, line number: Int) throws -> LogRecord {
    guard let data = line.data(using: .utf8) else {
        throw NodeError.shape("line \(number) is not UTF-8")
    }
    let object = try JSONSerialization.jsonObject(with: data)
    guard let dict = object as? [String: Any] else {
        throw NodeError.shape("line \(number) is not an object")
    }
    guard let seq = intValue(dict["seq"]) else {
        throw NodeError.shape("line \(number) missing seq")
    }
    guard let kind = dict["kind"] as? String else {
        throw NodeError.shape("line \(number) missing kind")
    }
    guard let hash = dict["hash"] as? String else {
        throw NodeError.shape("line \(number) missing hash")
    }
    guard dict["payload"] != nil else {
        throw NodeError.shape("line \(number) missing payload")
    }
    // `prev` is null at genesis, so it is deliberately not required.
    let prev: String?
    if dict["prev"] is NSNull || dict["prev"] == nil {
        prev = nil
    } else {
        prev = dict["prev"] as? String
    }
    let ts = dict["ts"] as? String ?? ""
    let payload = jsonValue(dict["payload"]).object
    return LogRecord(seq: seq, kind: kind, hash: hash, prev: prev, ts: ts, payload: payload)
}

private func intValue(_ value: Any?) -> Int? {
    switch value {
    case let n as Int: return n
    case let n as Int64: return Int(n)
    case let n as NSNumber: return n.intValue
    default: return nil
    }
}

extension JSONValue {
    fileprivate var object: [String: JSONValue] {
        if case let .object(object) = self { return object }
        return [:]
    }
}

func jsonValue(_ value: Any?) -> JSONValue {
    switch value {
    case nil, is NSNull: return .null
    case let s as String: return .string(s)
    case let n as Bool: return .bool(n)
    case let n as Int: return .int(n)
    case let n as Int64: return .int(Int(n))
    case let n as NSNumber:
        // NSNumber is also Bool. `CFGetTypeID` is the honest check; comparing
        // against `true as NSNumber` is what Swift's overlay already does and
        // would collapse 1 into true.
        if CFGetTypeID(n) == CFBooleanGetTypeID() { return .bool(n.boolValue) }
        if CFNumberIsFloatType(n) { return .double(n.doubleValue) }
        return .int(n.intValue)
    case let obj as [String: Any]:
        return .object(obj.mapValues { jsonValue($0) })
    case let arr as [Any]:
        return .array(arr.map { jsonValue($0) })
    default:
        return .string(String(describing: value!))
    }
}
