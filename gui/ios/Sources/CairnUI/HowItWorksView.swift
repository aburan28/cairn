import SwiftUI

/// The protocol, short enough to read on a phone. The long form is
/// `/how-it-works` on the site; restating it here would be a second place
/// for a payout curve or an honest limit to drift.
public struct HowItWorksView: View {
    public init() {}

    public var body: some View {
        List {
            Section {
                Text("Pay for verified outputs. Never pay for claimed effort.")
                    .font(.headline)
                Text("An objective is a funded question with its checker pinned by hash. Editing the evaluator produces a different objective; mid-bounty rule changes are unrepresentable.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            Section("how a result is paid") {
                paid("Score first", detail: "The pinned verifier is ground truth. Your own assessment of an artifact is worth nothing here.")
                paid("Commit, then reveal", detail: "A reveal must land in a strictly later epoch than its commitment. One call leaves a commitment nobody opened.")
                paid("Cite the frontier", detail: "Once an objective has one, every later submission must cite the claim holding it. The citation is checked, not trusted.")
                paid("cites pays; relations do not", detail: "A refute is not a bill, and a supersede is not a way to take someone else's frontier.")
                paid("Copying earns zero", detail: "A duplicate verifies and mints nothing.")
                paid("unavailable is not reject", detail: "The node could not check; it did not fail the artifact. Retry later.")
            }

            Section("what this app is") {
                Text("A reader. It does not run the researcher, does not sign, and does not write the log. Every number says where it came from — a node that answered, or the launch snapshot that ships in the repository.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                Text("The check that means something is `cairn audit` on a copy of the log. Nothing on this phone re-derives a settlement or a chain.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
        }
        .navigationTitle("How it works")
    }

    private func paid(_ title: String, detail: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.subheadline.weight(.semibold))
            Text(detail).font(.footnote).foregroundStyle(.secondary)
        }
        .padding(.vertical, 2)
    }
}
