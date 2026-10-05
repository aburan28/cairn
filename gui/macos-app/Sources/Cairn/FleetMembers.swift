import AppKit
import SwiftUI

/// One machine enrolled in the fleet this Mac leads: a row of
/// `cairn fleet list --json`.
struct FleetMember: Identifiable, Equatable, Decodable {
    /// The member's public key, 64 hex.
    let member: String
    let name: String
    let invite: String?
    let joinedAt: String
    let expiresAt: String?
    /// `member`, `expired` or `revoked`.
    let state: String
    let revokedAt: String?
    let revokedReason: String?

    var id: String { member }

    static func decode(_ text: String) throws -> [FleetMember] {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode([FleetMember].self, from: Data(text.utf8))
    }

    /// Whether `name`, a worker or host on the node's roster, is this
    /// member's: its own name, or one of its slices (`name/gpu0`).
    func owns(_ name: String) -> Bool {
        name == self.name || name.hasPrefix(self.name + "/")
    }
}

/// What `cairn fleet invite --json` prints: the token, once.
struct FleetInvitation: Equatable, Decodable {
    let token: String
    let invite: String
    let uses: Int
    let expiresAt: String
    let join: String

    static func decode(_ text: String) throws -> FleetInvitation {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(FleetInvitation.self, from: Data(text.utf8))
    }
}

enum FleetFacts {
    /// Names on the node's rosters that an enrolled member signed for and
    /// that are live: heartbeating workers and registered hosts, from
    /// `GET /network`. Self-reported, like everything on those rosters; the
    /// `member` flag is what the node itself checked.
    static func liveMemberNames(_ network: [String: Any]) -> [String] {
        let compute = network["compute"] as? [String: Any]
        let workers = compute?["workers"] as? [[String: Any]] ?? []
        let hosts = (compute?["hosts"] as? [String: Any])?["hosts"] as? [[String: Any]] ?? []
        let live: ([String: Any]) -> Bool = { row in
            (row["member"] as? Bool) == true && (row["status"] as? String) == "live"
        }
        return workers.filter(live).compactMap { $0["worker"] as? String }
            + hosts.filter(live).compactMap { $0["host"] as? String }
    }

    /// The address a machine elsewhere should dial this node at: the router's
    /// public mapping of the HTTP port when there is one, else its first LAN
    /// address, else nothing.
    static func joinAddress(_ network: [String: Any]) -> String? {
        let reach = (network["node"] as? [String: Any])?["reach"] as? [String: Any]
        if let external = reach?["external"] as? [String: Any],
           (external["status"] as? String) == "mapped",
           (external["public"] as? Bool) == true,
           let address = external["address"] as? String {
            return "http://\(address)"
        }
        return (reach?["urls"] as? [String])?.first
    }
}

/// The members of the fleet this Mac leads, each with Revoke, and the way to
/// invite another. Read from `cairn fleet list`; changed only through
/// `cairn fleet invite` and `cairn fleet revoke`, the same commands an
/// operator on a Linux leader runs.
struct FleetMembersView: View {
    @ObservedObject var node: Node
    @State private var members: [FleetMember] = []
    @State private var live: [String] = []
    @State private var problem: String?
    @State private var inviting = false
    @State private var revoking: FleetMember?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Button("Invite a machine…") { inviting = true }
                Button("Refresh") { load() }
                    .controlSize(.small)
            }
            if members.isEmpty {
                Text("No machines yet. An invitation is a token you hand to one machine, or to a batch of rented ones; each joins from wherever it is, with no tunnel.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            ForEach(members) { member in
                row(member)
            }
            if let problem {
                Text(problem).font(.caption).foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .onAppear(perform: load)
        .sheet(isPresented: $inviting, onDismiss: load) {
            InviteSheet(node: node, isPresented: $inviting)
        }
        .confirmationDialog(
            "Revoke \(revoking?.name ?? "this machine")?",
            isPresented: Binding(get: { revoking != nil }, set: { if !$0 { revoking = nil } }),
            presenting: revoking
        ) { member in
            Button("Revoke", role: .destructive) { revoke(member) }
        } message: { _ in
            Text("Its next request is refused, and its key can never join again. Other machines are not affected.")
        }
    }

    private func row(_ member: FleetMember) -> some View {
        HStack(spacing: 8) {
            Circle()
                .fill(dot(member))
                .frame(width: 7, height: 7)
            Text(member.name).font(.body.monospaced())
            Text(caption(member))
                .font(.caption).foregroundStyle(.secondary)
                .lineLimit(1)
            Spacer()
            if member.state == "member" {
                Button("Revoke") { revoking = member }
                    .controlSize(.small)
            }
        }
    }

    private func isLive(_ member: FleetMember) -> Bool {
        member.state == "member" && live.contains { member.owns($0) }
    }

    private func dot(_ member: FleetMember) -> Color {
        if member.state != "member" { return .secondary.opacity(0.4) }
        return isLive(member) ? .green : .secondary
    }

    private func caption(_ member: FleetMember) -> String {
        switch member.state {
        case "revoked":
            let why = (member.revokedReason ?? "").isEmpty ? "" : " (\(member.revokedReason!))"
            return "revoked \(member.revokedAt ?? "")\(why)"
        case "expired":
            return "membership ended \(member.expiresAt ?? "")"
        default:
            let until = member.expiresAt.map { ", until \($0)" } ?? ""
            return (isLive(member) ? "live" : "not heard from lately") + until
        }
    }

    private func load() {
        node.fleet(["list", "--json"]) { output, failure in
            if let failure {
                problem = failure
                return
            }
            do {
                members = try FleetMember.decode(output ?? "[]")
                problem = nil
            } catch {
                problem = "Could not read `cairn fleet list`: \(error.localizedDescription)"
            }
        }
        Task {
            if let network = await node.networkFacts() {
                live = FleetFacts.liveMemberNames(network)
            }
        }
    }

    private func revoke(_ member: FleetMember) {
        node.fleet(["revoke", member.member, "--reason", "revoked in Cairn.app"]) { _, failure in
            problem = failure
            load()
        }
    }
}

/// Invite one machine, or a batch, and show the join line once.
struct InviteSheet: View {
    @ObservedObject var node: Node
    @Binding var isPresented: Bool

    @State private var batch = false
    @State private var count = 4
    @State private var name = ""
    @State private var prefix = "rented"
    @State private var expires = "24h"
    @State private var lasting = "12h"
    @State private var address = ""
    @State private var invitation: FleetInvitation?
    @State private var problem: String?
    @State private var busy = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Invite a machine").font(.headline)
            if let invitation {
                result(invitation)
            } else {
                form
            }
        }
        .padding(20)
        .frame(width: 540)
        .task {
            if address.isEmpty, let network = await node.networkFacts(),
               let found = FleetFacts.joinAddress(network) {
                address = found
            }
        }
    }

    private var form: some View {
        VStack(alignment: .leading, spacing: 10) {
            Picker("Invite", selection: $batch) {
                Text("One machine").tag(false)
                Text("A batch").tag(true)
            }
            .pickerStyle(.segmented)
            if batch {
                Stepper("\(count) machines", value: $count, in: 2...256)
                TextField("Named", text: $prefix)
                    .font(.body.monospaced())
                Text("Each is named \(prefix.isEmpty ? "rented" : prefix), a dash, and the first 12 hex digits of its key, for as long as it keeps that key.")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                TextField("Its name here (optional; it asks for its hostname otherwise)", text: $name)
                    .font(.body.monospaced())
            }
            Picker("The invitation lasts", selection: $expires) {
                Text("1 hour").tag("1h")
                Text("24 hours").tag("24h")
                Text("7 days").tag("7d")
            }
            Picker("Each membership ends", selection: $lasting) {
                Text("When I revoke it").tag("")
                Text("12 hours after joining").tag("12h")
                Text("24 hours after joining").tag("24h")
                Text("7 days after joining").tag("7d")
            }
            TextField("This Mac's address, as the machine will dial it", text: $address)
                .font(.body.monospaced())
            Text("Behind a home router, a machine elsewhere reaches this Mac only if the router forwards the HTTP port (`CAIRN_PORTMAP_HTTP=on`), which makes this node reachable from the internet. A cloud leader needs nothing.")
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if let problem {
                Text(problem).font(.caption).foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button("Cancel") { isPresented = false }
                    .keyboardShortcut(.cancelAction)
                Button(busy ? "Inviting…" : "Create Invitation") { create() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(busy)
            }
        }
    }

    private func result(_ invitation: FleetInvitation) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("On the machine, run:").font(.caption).foregroundStyle(.secondary)
            Text(invitation.join)
                .font(.caption.monospaced())
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .padding(8)
                .background(Color(nsColor: .textBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 6))
            Text("Shown once, and a secret: whoever holds it can join until \(invitation.uses == 1 ? "it is used" : "\(invitation.uses) machines have used it") or \(invitation.expiresAt). Hand it over directly -- a paste, cloud-init, a secret store -- not in a chat or a ticket.")
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Button("Copy") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(invitation.join, forType: .string)
                }
                Spacer()
                Button("Done") { isPresented = false }
                    .keyboardShortcut(.defaultAction)
            }
        }
    }

    private func create() {
        let identity = NodeSettings.current().leaderIdentity
        guard FileManager.default.fileExists(atPath: identity.path) else {
            problem = "The fleet identity does not exist yet. Start the node once with Lead a fleet on, and it is made."
            return
        }
        var args = ["invite", "--json", "--identity", identity.path, "--expires", expires]
        if batch {
            args += ["--uses", String(count), "--prefix", prefix.isEmpty ? "rented" : prefix]
        } else if !name.trimmingCharacters(in: .whitespaces).isEmpty {
            args += ["--name", name.trimmingCharacters(in: .whitespaces)]
        }
        if !lasting.isEmpty { args += ["--member-ttl", lasting] }
        let dial = address.trimmingCharacters(in: .whitespaces)
        if !dial.isEmpty { args += ["--node", dial] }
        busy = true
        problem = nil
        node.fleet(args) { output, failure in
            busy = false
            if let failure {
                problem = failure
                return
            }
            do {
                invitation = try FleetInvitation.decode(output ?? "")
            } catch {
                problem = "Could not read `cairn fleet invite`: \(error.localizedDescription)"
            }
        }
    }
}
