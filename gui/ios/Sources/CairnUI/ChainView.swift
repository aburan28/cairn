import SwiftUI
import CairnKit

public struct ChainView: View {
    @EnvironmentObject private var model: AppModel

    public init() {}

    public var body: some View {
        List {
            if let sourced = model.chain {
                let chain = sourced.value
                let broken = firstBrokenLink(chain.chain)
                Section {
                    LabeledContent("head") { HashText(chain.head, chars: 10) }
                    LabeledContent("links") { Text("\(chain.links)") }
                    LabeledContent("height") { Text("\(chain.height)") }
                    LabeledContent("ledger head") { HashText(chain.ledger_head, chars: 10) }
                    LabeledContent("claims") { Text("\(totalClaims(chain.chain))") }
                    ProvenanceLine(sourced.provenance)
                } footer: {
                    Text("height and ledger_head are the ledger's — the units a checkpoint signs — and not interchangeable with links and head.")
                }
                if let broken {
                    Section {
                        Text("This is not a chain. Epoch \(broken) does not name the link before it. The head is untrustworthy.")
                            .foregroundStyle(.red)
                    } header: {
                        Text("broken")
                    }
                }
                let scales = epochScales(chain.chain)
                if scales.count > 1 {
                    Section {
                        Text("Epoch numbers jump by orders of magnitude (\(scales.map(String.init).joined(separator: ", "))). That is a heuristic — the epoch length is never stored — but two CAIRN_EPOCH_SECONDS settings disagree about which reveals were legal.")
                            .font(.footnote)
                    } header: {
                        Text("epoch length (heuristic)")
                    }
                }
                Section("links") {
                    if chain.chain.isEmpty {
                        Text("This snapshot only carries the chain's counts, not each link. Point the app at a live node to walk them.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    ForEach(chain.chain, id: \.link) { link in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Text("epoch \(link.epoch)")
                                    .font(.subheadline.weight(.semibold))
                                Spacer()
                                Text("\(link.claims.count) claim\(link.claims.count == 1 ? "" : "s")")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            HashText(link.link, chars: 10)
                            if broken == link.epoch {
                                Text("prev does not match the previous link")
                                    .font(.caption)
                                    .foregroundStyle(.red)
                            }
                        }
                    }
                }
            } else {
                Section { Text("Reading…") }
            }
        }
        .navigationTitle("Chain")
        .refreshable { await model.refresh() }
    }
}
