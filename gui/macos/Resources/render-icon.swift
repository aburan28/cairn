// Renders the app icon -- a cairn, stones stacked on a hill -- as PNGs of
// every size an .iconset needs. Run by build.sh; needs nothing but the
// Command Line Tools:
//
//   swift render-icon.swift <output.iconset>
import AppKit

let outDir = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "AppIcon.iconset"
try? FileManager.default.createDirectory(atPath: outDir, withIntermediateDirectories: true)

func render(_ size: Int) -> NSImage {
    let s = CGFloat(size)
    let image = NSImage(size: NSSize(width: s, height: s))
    image.lockFocus()
    guard let ctx = NSGraphicsContext.current?.cgContext else { return image }

    // Rounded square, night sky.
    let inset = s * 0.04
    let square = CGRect(x: inset, y: inset, width: s - 2 * inset, height: s - 2 * inset)
    let path = CGPath(roundedRect: square, cornerWidth: s * 0.22, cornerHeight: s * 0.22, transform: nil)
    ctx.addPath(path)
    ctx.clip()
    let sky = CGGradient(colorsSpace: CGColorSpaceCreateDeviceRGB(),
                         colors: [NSColor(red: 0.09, green: 0.13, blue: 0.24, alpha: 1).cgColor,
                                  NSColor(red: 0.16, green: 0.30, blue: 0.46, alpha: 1).cgColor] as CFArray,
                         locations: [0, 1])!
    ctx.drawLinearGradient(sky, start: CGPoint(x: 0, y: 0), end: CGPoint(x: 0, y: s), options: [])

    // Hill.
    ctx.setFillColor(NSColor(red: 0.20, green: 0.36, blue: 0.30, alpha: 1).cgColor)
    ctx.addEllipse(in: CGRect(x: -s * 0.2, y: -s * 0.55, width: s * 1.4, height: s * 0.85))
    ctx.fillPath()

    // Stones, widest at the bottom, each slightly offset like a real pile.
    let stones: [(w: CGFloat, h: CGFloat, dx: CGFloat, tone: CGFloat)] = [
        (0.62, 0.15, 0.00, 0.62), (0.50, 0.13, 0.03, 0.70), (0.40, 0.12, -0.02, 0.78),
        (0.30, 0.10, 0.02, 0.84), (0.20, 0.08, -0.01, 0.90),
    ]
    var y = s * 0.22
    for st in stones {
        let w = s * st.w, h = s * st.h
        let rect = CGRect(x: (s - w) / 2 + s * st.dx, y: y, width: w, height: h)
        ctx.setFillColor(NSColor(white: st.tone, alpha: 1).cgColor)
        ctx.addPath(CGPath(roundedRect: rect, cornerWidth: h * 0.45, cornerHeight: h * 0.45, transform: nil))
        ctx.fillPath()
        // A shadow line under each stone gives the stack its weight.
        ctx.setFillColor(NSColor(white: 0, alpha: 0.18).cgColor)
        ctx.addPath(CGPath(roundedRect: CGRect(x: rect.minX + h * 0.2, y: rect.minY - h * 0.12, width: w - h * 0.4, height: h * 0.2),
                           cornerWidth: h * 0.1, cornerHeight: h * 0.1, transform: nil))
        ctx.fillPath()
        y += h * 0.92
    }

    // A checkmark: the verified result the network pays for.
    ctx.setStrokeColor(NSColor(red: 0.45, green: 0.95, blue: 0.70, alpha: 1).cgColor)
    ctx.setLineWidth(s * 0.045)
    ctx.setLineCap(.round)
    ctx.setLineJoin(.round)
    ctx.move(to: CGPoint(x: s * 0.66, y: s * 0.62))
    ctx.addLine(to: CGPoint(x: s * 0.74, y: s * 0.54))
    ctx.addLine(to: CGPoint(x: s * 0.88, y: s * 0.72))
    ctx.strokePath()

    image.unlockFocus()
    return image
}

for (name, size) in [("icon_16x16", 16), ("icon_16x16@2x", 32), ("icon_32x32", 32), ("icon_32x32@2x", 64),
                     ("icon_128x128", 128), ("icon_128x128@2x", 256), ("icon_256x256", 256), ("icon_256x256@2x", 512),
                     ("icon_512x512", 512), ("icon_512x512@2x", 1024)] {
    let image = render(size)
    guard let tiff = image.tiffRepresentation, let rep = NSBitmapImageRep(data: tiff),
          let png = rep.representation(using: .png, properties: [:]) else { continue }
    try? png.write(to: URL(fileURLWithPath: "\(outDir)/\(name).png"))
}
print("rendered \(outDir)")
