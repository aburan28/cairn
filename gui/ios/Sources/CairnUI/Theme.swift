import SwiftUI
import CairnKit
#if canImport(UIKit)
import UIKit
#endif

/// Semantic colours taken from `ui/app/globals.css`, so the phone and the
/// site are one palette. Values flip with the system appearance the same
/// way the site's tokens flip with `data-theme`.
public enum CairnColor {
    public static let accent = Color("CairnAccent", bundle: .main, fallback: Color(red: 0.04, green: 0.49, blue: 0.32))
    public static let warn = Color(red: 0.60, green: 0.38, blue: 0.02)
}

private extension Color {
    init(_ name: String, bundle: Bundle, fallback: Color) {
        #if canImport(UIKit)
        if UIColor(named: name) != nil {
            self.init(name, bundle: bundle)
            return
        }
        #endif
        self = fallback
    }
}

public struct HashText: View {
    let value: String
    var chars: Int = 8

    public init(_ value: String, chars: Int = 8) {
        self.value = value
        self.chars = chars
    }

    public var body: some View {
        Text(shortHash(value, head: chars, tail: max(4, chars / 2)))
            .font(.system(.caption, design: .monospaced))
            .lineLimit(1)
            .help(value)
    }
}

public struct ProvenanceLine: View {
    let sourced: String
    public init(_ sourced: String) { self.sourced = sourced }
    public var body: some View {
        Text(sourced)
            .font(.caption)
            .foregroundStyle(.secondary)
    }
}

public struct UntrustedStatement: View {
    let text: String
    var limit: Int = 0

    public init(_ text: String, limit: Int = 0) {
        self.text = text
        self.limit = limit
    }

    public var body: some View {
        let shown = limit > 0 && text.count > limit ? String(text.prefix(limit)) + "…" : text
        (Text("statement (untrusted): ").foregroundStyle(.tertiary) + Text(shown))
            .font(.subheadline)
            .foregroundStyle(.secondary)
    }
}

public struct StatusBadge: View {
    let label: String
    var kind: Kind = .neutral
    public enum Kind { case accent, neutral, info, warn, bad }

    public init(_ label: String, kind: Kind = .neutral) {
        self.label = label
        self.kind = kind
    }

    public var body: some View {
        Text(label)
            .font(.caption.weight(.medium))
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(background, in: Capsule())
            .foregroundStyle(foreground)
    }

    private var background: Color {
        switch kind {
        case .accent: return Color.green.opacity(0.15)
        case .neutral: return Color.primary.opacity(0.08)
        case .info: return Color.blue.opacity(0.12)
        case .warn: return Color.orange.opacity(0.14)
        case .bad: return Color.red.opacity(0.14)
        }
    }

    private var foreground: Color {
        switch kind {
        case .accent: return .green
        case .neutral: return .secondary
        case .info: return .blue
        case .warn: return .orange
        case .bad: return .red
        }
    }
}

public struct StatTile: View {
    let label: String
    let value: String
    var from: String?

    public init(_ label: String, value: String, from: String? = nil) {
        self.label = label
        self.value = value
        self.from = from
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label.uppercased())
                .font(.caption2.weight(.semibold))
                .foregroundStyle(.secondary)
            Text(value)
                .font(.title3.weight(.semibold))
                .minimumScaleFactor(0.6)
                .lineLimit(1)
            if let from {
                Text(from)
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .lineLimit(2)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 12))
    }
}

#if os(iOS) || os(macOS)
public extension View {
    func cairnCard() -> some View {
        self
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.background.secondary, in: RoundedRectangle(cornerRadius: 12))
    }
}
#endif
