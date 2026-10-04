import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// A hosted model this app can ask to draft a challenge.
///
/// The node cannot make these calls: `tests/cipher_policy.rs` keeps every TLS
/// crate out of it, and that is a property worth more than this feature. So
/// the app does, with URLSession, and the node only ever sees the finished
/// objective -- the same file a person could have written by hand.
enum AIProvider: String, CaseIterable, Identifiable {
    case anthropic, openai, fireworks, opencode, openrouter, custom

    var id: String { rawValue }

    var title: String {
        switch self {
        case .anthropic: return "Claude (Anthropic)"
        case .openai: return "OpenAI"
        case .fireworks: return "Fireworks AI"
        case .opencode: return "OpenCode Zen"
        case .openrouter: return "OpenRouter"
        case .custom: return "Other (OpenAI-compatible)"
        }
    }

    /// The name the key is kept under in `~/.cairn/secrets`, which is the
    /// environment variable each provider's own tools read: the key pasted
    /// here is the one `cairn secret run --env ANTHROPIC_API_KEY -- claude`
    /// (or opencode) hands a terminal agent, rather than a second copy.
    var secretName: String {
        switch self {
        case .anthropic: return "ANTHROPIC_API_KEY"
        case .openai: return "OPENAI_API_KEY"
        case .fireworks: return "FIREWORKS_API_KEY"
        case .opencode: return "OPENCODE_API_KEY"
        case .openrouter: return "OPENROUTER_API_KEY"
        case .custom: return "CAIRN_AI_API_KEY"
        }
    }

    /// A model that writes careful Python, per each provider's own
    /// recommendation for code. Any id the provider serves can replace it.
    var defaultModel: String {
        switch self {
        case .anthropic: return "claude-opus-5-5"
        case .openai: return "gpt-6.1-sol"
        case .fireworks: return "accounts/fireworks/models/kimi-k3"
        case .opencode: return "kimi-k3"
        case .openrouter: return "moonshotai/kimi-k3"
        case .custom: return ""
        }
    }

    var defaultBaseURL: String {
        switch self {
        case .anthropic: return "https://api.anthropic.com/v1"
        case .openai: return "https://api.openai.com/v1"
        case .fireworks: return "https://api.fireworks.ai/inference/v1"
        case .opencode: return "https://opencode.ai/zen/v1"
        case .openrouter: return "https://openrouter.ai/api/v1"
        case .custom: return ""
        }
    }

    /// Where a person gets a key.
    var keyPage: URL? {
        switch self {
        case .anthropic: return URL(string: "https://platform.claude.com/settings/keys")
        case .openai: return URL(string: "https://platform.openai.com/api-keys")
        case .fireworks: return URL(string: "https://app.fireworks.ai/settings/users/api-keys")
        case .opencode: return URL(string: "https://opencode.ai/docs/zen/")
        case .openrouter: return URL(string: "https://openrouter.ai/settings/keys")
        case .custom: return nil
        }
    }
}

/// Which of the two request shapes a provider and model speak.
enum AIWire {
    /// Anthropic Messages: `POST /messages`, `x-api-key`.
    case messages
    /// OpenAI Chat Completions: `POST /chat/completions`, `Authorization: Bearer`.
    /// Every provider here but Anthropic speaks it, for at least some models.
    case chatCompletions
}

/// What Settings chose: a provider, a model, and for "Other" an endpoint.
struct AIConfig: Equatable {
    var provider: AIProvider
    var model: String
    var baseURL: String

    enum Key {
        static let provider = "aiProvider"
        static let customBaseURL = "aiCustomBaseURL"
        /// Per provider, so switching away and back keeps a chosen model.
        static func model(_ provider: AIProvider) -> String { "aiModel.\(provider.rawValue)" }
    }

    static func current(_ defaults: UserDefaults = .standard) -> AIConfig {
        let provider = AIProvider(rawValue: defaults.string(forKey: Key.provider) ?? "") ?? .anthropic
        let chosen = (defaults.string(forKey: Key.model(provider)) ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let base = provider == .custom
            ? (defaults.string(forKey: Key.customBaseURL) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            : provider.defaultBaseURL
        return AIConfig(provider: provider, model: chosen.isEmpty ? provider.defaultModel : chosen, baseURL: base)
    }

    var wire: AIWire {
        switch provider {
        case .anthropic: return .messages
        // Zen routes by model: Claude models only on its Anthropic-format
        // path, and they are refused on /chat/completions.
        case .opencode: return model.hasPrefix("claude-") ? .messages : .chatCompletions
        default: return .chatCompletions
        }
    }

    /// Why this configuration cannot be used yet, in a sentence, or nil.
    var problem: String? {
        if model.isEmpty { return "Choose a model in Settings → AI." }
        if let problem = endpointProblem { return problem }
        // Zen serves GPT models only on its Responses API, which this app
        // does not speak; asked on /chat/completions it refuses them.
        if provider == .opencode, model.hasPrefix("gpt-") {
            return "OpenCode Zen serves GPT models only through the Responses API. Choose a Kimi, GLM, DeepSeek or Claude model."
        }
        return nil
    }

    /// Why the endpoint alone cannot be called, before any model is chosen:
    /// what listing the models needs.
    var endpointProblem: String? {
        guard let url = URL(string: baseURL), let scheme = url.scheme?.lowercased(),
              scheme == "https" || (scheme == "http" && Self.isLoopback(url.host)), url.host != nil
        else {
            return baseURL.isEmpty
                ? "Enter the provider's API address in Settings → AI."
                : "\(baseURL) is not an https address."
        }
        return nil
    }

    /// Plain http only to this Mac, for a local model server. A key sent
    /// anywhere else in the clear is a key given away.
    static func isLoopback(_ host: String?) -> Bool {
        guard let host else { return false }
        return host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]"
    }

    var label: String { "\(provider.title) · \(model)" }
}

struct AIError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

/// One request in, one JSON object out -- streamed in, so a person watching
/// can see it arrive, and so the connection never sits idle long enough for
/// something between here and the provider to drop it.
struct AIClient {
    let config: AIConfig
    let apiKey: String
    var session: URLSession = AIClient.session

    /// Long, because a model that thinks before writing a checker can take
    /// minutes before its first byte, and this is one non-streaming request.
    static let session: URLSession = {
        let c = URLSessionConfiguration.ephemeral
        c.timeoutIntervalForRequest = 900
        c.timeoutIntervalForResource = 1200
        return URLSession(configuration: c)
    }()

    /// Models that take `output_config.effort`. Others refuse the field.
    static func takesEffort(_ model: String) -> Bool {
        ["claude-opus-5", "claude-fable-5", "claude-sonnet-5", "claude-mythos-5"].contains { model.hasPrefix($0) }
    }

    /// Models the server-side refusal fallback serves, on Anthropic's own API.
    static let fallbackModels: Set<String> = ["claude-fable-5-1", "claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5"]

    #if canImport(Darwin)
    /// Ask, and read the answer as it streams. `progress` is called off the
    /// main thread with every stretch of the answer that arrives; the reply
    /// is the one JSON object the whole answer parses to, exactly as before.
    ///
    /// A provider that ignores `stream` and answers with one object is read
    /// the old way, so nothing depends on streaming being honoured.
    func complete(system: String, user: String, schema: [String: Any], schemaName: String,
                  progress: (@Sendable (AIProgress) -> Void)? = nil) async throws -> [String: Any] {
        if let problem = config.problem { throw AIError(problem) }
        let request = try makeRequest(system: system, user: user, schema: schema, schemaName: schemaName, stream: true)
        let (bytes, response) = try await session.bytes(for: request)
        let http = response as? HTTPURLResponse
        let status = http?.statusCode ?? 0
        guard status == 200 else {
            let body = try await Self.collect(bytes, upTo: 1 << 20)
            throw Self.failure(status: status, body: body, provider: config.provider)
        }
        let contentType = (http?.value(forHTTPHeaderField: "Content-Type") ?? "").lowercased()
        guard contentType.contains("text/event-stream") else {
            let body = try await Self.collect(bytes, upTo: 64 << 20)
            return try Self.jsonObject(in: try Self.text(from: body, wire: config.wire))
        }
        var parser = SSEParser()
        var reader = AIStreamReader(wire: config.wire)
        var state = AIProgress()
        progress?(state)
        for try await line in bytes.lines {
            try Task.checkCancellation()
            guard let event = parser.feed(line) else { continue }
            if try reader.take(event, into: &state) { progress?(state) }
            if reader.finished { break }
        }
        if !reader.finished, let event = parser.flush() {
            _ = try reader.take(event, into: &state)
        }
        return try Self.jsonObject(in: try reader.reply())
    }

    /// The rest of a response body, bounded.
    private static func collect(_ bytes: URLSession.AsyncBytes, upTo limit: Int) async throws -> Data {
        var data = Data()
        for try await byte in bytes {
            data.append(byte)
            if data.count >= limit { break }
        }
        return data
    }
    #else
    /// A Foundation without `URLSession.bytes` reads the reply whole; the
    /// one-shot readers below understand it. Only the macOS app ships.
    func complete(system: String, user: String, schema: [String: Any], schemaName: String,
                  progress: (@Sendable (AIProgress) -> Void)? = nil) async throws -> [String: Any] {
        if let problem = config.problem { throw AIError(problem) }
        let request = try makeRequest(system: system, user: user, schema: schema, schemaName: schemaName)
        let (data, response) = try await session.data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard status == 200 else { throw Self.failure(status: status, body: data, provider: config.provider) }
        return try Self.jsonObject(in: try Self.text(from: data, wire: config.wire))
    }
    #endif

    func makeRequest(system: String, user: String, schema: [String: Any], schemaName: String,
                     stream: Bool = false) throws -> URLRequest {
        let base = config.baseURL.hasSuffix("/") ? String(config.baseURL.dropLast()) : config.baseURL
        var body: [String: Any]
        var request: URLRequest
        switch config.wire {
        case .messages:
            request = URLRequest(url: URL(string: base + "/messages")!)
            request.setValue(apiKey, forHTTPHeaderField: "x-api-key")
            request.setValue("2023-06-01", forHTTPHeaderField: "anthropic-version")
            var output: [String: Any] = ["format": ["type": "json_schema", "schema": schema]]
            // A checker decides who is paid, so it is worth the thinking.
            if Self.takesEffort(config.model) { output["effort"] = "high" }
            body = [
                "model": config.model,
                "max_tokens": 16000,
                "system": system,
                "messages": [["role": "user", "content": user]],
                "output_config": output,
            ]
            // A request a safety classifier declines is re-run on the
            // model Anthropic routes that category to, rather than coming
            // back empty. Only on Anthropic's API, where the beta exists.
            if config.provider == .anthropic, Self.fallbackModels.contains(config.model) {
                request.setValue("server-side-fallback-2026-07-01", forHTTPHeaderField: "anthropic-beta")
                body["fallbacks"] = "default"
            }
        case .chatCompletions:
            request = URLRequest(url: URL(string: base + "/chat/completions")!)
            request.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
            let openai = config.provider == .openai
            // Strict schemas on OpenAI. The others promise only "valid JSON",
            // so the reply is parsed and checked field by field.
            let format: [String: Any] = openai
                ? ["type": "json_schema", "json_schema": ["name": schemaName, "strict": true, "schema": schema] as [String: Any]]
                : ["type": "json_object"]
            // OpenAI's newer models take instructions as `developer`;
            // everything else here still reads `system`.
            let messages: [[String: Any]] = [
                ["role": openai ? "developer" : "system", "content": system],
                ["role": "user", "content": user],
            ]
            body = ["model": config.model, "messages": messages, "response_format": format]
            body[openai ? "max_completion_tokens" : "max_tokens"] = 16000
            if openai, config.model.hasPrefix("gpt-6") { body["reasoning_effort"] = "high" }
        }
        if stream { body["stream"] = true }
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        return request
    }

    /// Whether the key works, by the cheapest authenticated call each
    /// provider has. Zen has none that reads -- its model list answers 200
    /// to anybody -- so it gets a one-token completion on its cheapest model.
    func test() async throws {
        if let problem = config.problem { throw AIError(problem) }
        let base = config.baseURL.hasSuffix("/") ? String(config.baseURL.dropLast()) : config.baseURL
        var request: URLRequest
        switch config.provider {
        case .anthropic:
            request = URLRequest(url: URL(string: base + "/models")!)
            request.setValue(apiKey, forHTTPHeaderField: "x-api-key")
            request.setValue("2023-06-01", forHTTPHeaderField: "anthropic-version")
        case .openrouter:
            request = URLRequest(url: URL(string: base + "/key")!)
            request.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
        case .opencode:
            request = URLRequest(url: URL(string: base + "/chat/completions")!)
            request.httpMethod = "POST"
            request.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try JSONSerialization.data(withJSONObject: [
                "model": "deepseek-v4-flash",
                "max_tokens": 1,
                "messages": [["role": "user", "content": "ping"]],
            ])
        case .openai, .fireworks, .custom:
            request = URLRequest(url: URL(string: base + "/models")!)
            request.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
        }
        request.timeoutInterval = 30
        let (data, response) = try await session.data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard status == 200 else { throw Self.failure(status: status, body: data, provider: config.provider) }
    }

    // MARK: discovering models

    /// The model ids this provider serves, from the list every one of them
    /// publishes at `GET /models` (Anthropic's under its own headers, and
    /// paged, so the largest page is asked for). The key goes along even
    /// where the list is public, so a provider that filters by account --
    /// Fireworks shows an account its own deployments -- answers for this
    /// one. Needs no model chosen: this is how one gets chosen.
    func models() async throws -> [String] {
        if let problem = config.endpointProblem { throw AIError(problem) }
        let base = config.baseURL.hasSuffix("/") ? String(config.baseURL.dropLast()) : config.baseURL
        var request: URLRequest
        switch config.provider {
        case .anthropic:
            request = URLRequest(url: URL(string: base + "/models?limit=1000")!)
            request.setValue(apiKey, forHTTPHeaderField: "x-api-key")
            request.setValue("2023-06-01", forHTTPHeaderField: "anthropic-version")
        default:
            request = URLRequest(url: URL(string: base + "/models")!)
            request.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
        }
        request.timeoutInterval = 30
        let (data, response) = try await session.data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard status == 200 else { throw Self.failure(status: status, body: data, provider: config.provider) }
        return try Self.modelIDs(in: data)
    }

    /// The ids in a `/models` reply: `data: [{id}]` on every provider here,
    /// and `models: [{name}]` from an Ollama behind "Other". In the
    /// provider's order, which is the order its own console lists them.
    /// A model the provider marks as not for chat (Fireworks' embedders,
    /// `supports_chat: false`) cannot draft and is left out.
    static func modelIDs(in data: Data) throws -> [String] {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw AIError("The provider's model list was not JSON.")
        }
        let entries = (json["data"] ?? json["models"]) as? [[String: Any]] ?? []
        var seen = Set<String>()
        let ids = entries
            .filter { ($0["supports_chat"] as? Bool) != false }
            .compactMap { ($0["id"] ?? $0["name"]) as? String }
            .filter { seen.insert($0).inserted }
        guard !ids.isEmpty else { throw AIError("The provider listed no models for this key.") }
        return ids
    }

    /// A served id that goes by the chosen id's own name, when the chosen id
    /// itself is not served: a renamed or re-versioned model, which is the
    /// usual way a default goes stale. `accounts/fireworks/models/kimi-k3`
    /// finds `accounts/fireworks/models/kimi-k3-instruct`; `kimi-k3` on
    /// OpenRouter finds `moonshotai/kimi-k3`. Nil when the chosen id is
    /// served, or nothing is close.
    static func nearest(to model: String, in served: [String]) -> String? {
        let chosen = model.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !chosen.isEmpty, !served.contains(chosen) else { return nil }
        let stem = (chosen.split(separator: "/").last.map(String.init) ?? chosen).lowercased()
        if let match = served.first(where: { $0.lowercased().contains(stem) }) { return match }
        // Down to the family: `kimi-k3-0905` → `kimi-k3` → `kimi`.
        var family = stem
        while let dash = family.lastIndex(of: "-") {
            family = String(family[..<dash])
            if family.count < 3 { break }
            if let match = served.first(where: { $0.lowercased().contains(family) }) { return match }
        }
        return nil
    }

    // MARK: reading replies

    /// The model's text. A refusal or a reply cut off at the token limit is
    /// said as such, rather than surfacing later as "not valid JSON".
    static func text(from data: Data, wire: AIWire) throws -> String {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw AIError("The provider's reply was not JSON.")
        }
        switch wire {
        case .messages:
            let stop = json["stop_reason"] as? String
            if stop == "refusal" {
                let why = (json["stop_details"] as? [String: Any])?["explanation"] as? String
                throw AIError("The model declined this request" + (why.map { ": \($0)" } ?? "."))
            }
            if stop == "max_tokens" {
                throw AIError("The model ran out of room before finishing. Try a narrower description.")
            }
            let blocks = json["content"] as? [[String: Any]] ?? []
            let text = blocks.filter { $0["type"] as? String == "text" }
                .compactMap { $0["text"] as? String }
                .joined()
            guard !text.isEmpty else { throw AIError("The model's reply had no text in it.") }
            return text
        case .chatCompletions:
            guard let choice = (json["choices"] as? [[String: Any]])?.first,
                  let message = choice["message"] as? [String: Any]
            else { throw AIError("The provider's reply had no message in it.") }
            if choice["finish_reason"] as? String == "length" {
                throw AIError("The model ran out of room before finishing. Try a narrower description.")
            }
            if let refusal = message["refusal"] as? String, !refusal.isEmpty {
                throw AIError("The model declined this request: \(refusal)")
            }
            guard let text = message["content"] as? String, !text.isEmpty else {
                throw AIError("The model's reply had no text in it.")
            }
            return text
        }
    }

    /// The JSON object in a reply, tolerating the code fence or the sentence
    /// of preamble a model without strict output sometimes adds.
    static func jsonObject(in text: String) throws -> [String: Any] {
        var candidate = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if let start = candidate.firstIndex(of: "{"), let end = candidate.lastIndex(of: "}"), start < end {
            candidate = String(candidate[start...end])
        }
        guard let data = candidate.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { throw AIError("The model did not reply with a JSON object. Try again, or choose a stronger model.") }
        return object
    }

    /// An HTTP failure in the words a person can act on, with the
    /// provider's own message, which usually names the actual problem.
    static func failure(status: Int, body: Data, provider: AIProvider) -> AIError {
        let json = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any]
        let error = json?["error"] as? [String: Any]
        let message = (error?["message"] as? String) ?? (json?["message"] as? String)
        let kind = error?["type"] as? String
        let detail = message.map { " (\($0))" } ?? ""
        switch (status, kind) {
        case (_, "CreditsError"), (402, _):
            return AIError("\(provider.title) says this account is out of credits\(detail).")
        case (_, "MonthlyLimitError"):
            return AIError("\(provider.title) says this account reached its monthly limit\(detail).")
        case (_, "ModelError"), (404, _):
            return AIError("\(provider.title) does not serve that model\(detail). Settings → AI lists the models it does.")
        case (401, _), (403, _):
            return AIError("\(provider.title) refused the API key\(detail).")
        case (429, _):
            return AIError("\(provider.title) is rate-limiting this key\(detail). Wait a minute and try again.")
        default:
            return AIError("\(provider.title) answered HTTP \(status)\(detail).")
        }
    }
}

// MARK: streaming

/// What a streamed answer has produced so far: the numbers a person waiting
/// on a slow model can watch move, which the one-shot request could not give
/// because nothing arrived until everything had.
struct AIProgress: Equatable, Sendable {
    enum Stage: Equatable, Sendable {
        /// The request is out and nothing has come back yet.
        case connecting
        /// The provider has answered; the model is working but has written
        /// none of the answer -- its reasoning, where a model streams that.
        case thinking
        /// The answer is arriving.
        case writing
    }

    var stage: Stage = .connecting
    /// Characters of the answer so far.
    var written = 0
    /// Characters of reasoning so far, on models that stream it.
    var reasoned = 0
    /// The answer's last stretch, for a live glimpse of what is being written.
    var tail = ""
}

/// One server-sent event: the optional `event:` name and the `data:` lines,
/// joined as the format says.
struct SSEEvent: Equatable {
    var event: String?
    var data: String
}

/// The text/event-stream framing, fed one line at a time without its line
/// ending: fields accumulate until a blank line dispatches them. Comments
/// (`: keep-alive`) and fields this app has no use for are skipped. Both
/// wires use the framing; what is inside `data:` differs, and
/// `AIStreamReader` reads that.
struct SSEParser {
    private var event: String?
    private var data: [String] = []

    mutating func feed(_ line: String) -> SSEEvent? {
        if line.isEmpty { return flush() }
        if line.hasPrefix(":") { return nil }
        let field: Substring
        var value: Substring
        if let colon = line.firstIndex(of: ":") {
            field = line[..<colon]
            value = line[line.index(after: colon)...]
            if value.hasPrefix(" ") { value = value.dropFirst() }
        } else {
            field = Substring(line)
            value = ""
        }
        if field == "event" {
            event = String(value)
        } else if field == "data" {
            data.append(String(value))
        }
        return nil
    }

    /// Whatever is pending, for a stream that ended without a final blank line.
    mutating func flush() -> SSEEvent? {
        let pending = data.isEmpty ? nil : SSEEvent(event: event, data: data.joined(separator: "\n"))
        event = nil
        data = []
        return pending
    }
}

/// Folds a provider's stream into the reply, raising the same errors the
/// one-shot reader raises for a refusal or an answer cut off at the token
/// limit. Each wire's chunk shape is read here and nowhere else.
struct AIStreamReader {
    let wire: AIWire
    private(set) var text = ""
    private(set) var reasoned = 0
    /// The provider said the message is over.
    private(set) var finished = false

    init(wire: AIWire) { self.wire = wire }

    /// Apply one event. True when `progress` changed in a way worth showing.
    mutating func take(_ event: SSEEvent, into progress: inout AIProgress) throws -> Bool {
        if event.data == "[DONE]" {
            finished = true
            return false
        }
        guard let json = try? JSONSerialization.jsonObject(with: Data(event.data.utf8)) as? [String: Any] else {
            return false
        }
        switch wire {
        case .messages: return try takeMessages(json, named: event.event, into: &progress)
        case .chatCompletions: return try takeChat(json, into: &progress)
        }
    }

    /// The whole reply, once the stream has ended.
    func reply() throws -> String {
        guard !text.isEmpty else { throw AIError("The model's reply had no text in it.") }
        return text
    }

    private mutating func wrote(_ piece: String, into progress: inout AIProgress) {
        text += piece
        progress.stage = .writing
        progress.written = text.count
        progress.tail = String(text.suffix(160))
    }

    private mutating func thought(_ piece: String, into progress: inout AIProgress) {
        reasoned += piece.count
        progress.reasoned = reasoned
        if progress.stage == .connecting { progress.stage = .thinking }
    }

    /// Anthropic Messages: typed events, the text in `content_block_delta`,
    /// the stop reason in `message_delta`.
    private mutating func takeMessages(_ json: [String: Any], named name: String?,
                                       into progress: inout AIProgress) throws -> Bool {
        switch (json["type"] as? String) ?? name ?? "" {
        case "error":
            let message = (json["error"] as? [String: Any])?["message"] as? String
            throw AIError(message ?? "The provider reported an error mid-stream.")
        case "message_start", "content_block_start":
            guard progress.stage == .connecting else { return false }
            progress.stage = .thinking
            return true
        case "content_block_delta":
            guard let delta = json["delta"] as? [String: Any] else { return false }
            switch delta["type"] as? String {
            case "text_delta":
                guard let piece = delta["text"] as? String, !piece.isEmpty else { return false }
                wrote(piece, into: &progress)
                return true
            case "thinking_delta":
                guard let piece = delta["thinking"] as? String, !piece.isEmpty else { return false }
                thought(piece, into: &progress)
                return true
            default:
                return false
            }
        case "message_delta":
            guard let delta = json["delta"] as? [String: Any],
                  let reason = delta["stop_reason"] as? String else { return false }
            switch reason {
            case "refusal":
                let why = (delta["stop_details"] as? [String: Any])?["explanation"] as? String
                throw AIError("The model declined this request" + (why.map { ": \($0)" } ?? "."))
            case "max_tokens":
                throw AIError("The model ran out of room before finishing. Try a narrower description.")
            default:
                return false
            }
        case "message_stop":
            finished = true
            return false
        default:
            return false
        }
    }

    /// OpenAI Chat Completions and everything that imitates it: one
    /// `choices[0].delta` per chunk, `finish_reason` on the last.
    private mutating func takeChat(_ json: [String: Any], into progress: inout AIProgress) throws -> Bool {
        if let error = json["error"] as? [String: Any] {
            throw AIError((error["message"] as? String) ?? "The provider reported an error mid-stream.")
        }
        guard let choice = (json["choices"] as? [[String: Any]])?.first else { return false }
        var changed = false
        if progress.stage == .connecting {
            progress.stage = .thinking
            changed = true
        }
        if let delta = choice["delta"] as? [String: Any] {
            if let refusal = delta["refusal"] as? String, !refusal.isEmpty {
                throw AIError("The model declined this request: \(refusal)")
            }
            // Fireworks and DeepSeek stream reasoning as reasoning_content;
            // OpenRouter as reasoning.
            if let piece = (delta["reasoning_content"] as? String) ?? (delta["reasoning"] as? String),
               !piece.isEmpty {
                thought(piece, into: &progress)
                changed = true
            }
            if let piece = delta["content"] as? String, !piece.isEmpty {
                wrote(piece, into: &progress)
                changed = true
            }
        }
        if let reason = choice["finish_reason"] as? String {
            switch reason {
            case "length":
                throw AIError("The model ran out of room before finishing. Try a narrower description.")
            case "content_filter":
                throw AIError("The model declined this request.")
            default:
                finished = true
            }
        }
        return changed
    }
}
