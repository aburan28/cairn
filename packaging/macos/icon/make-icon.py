#!/usr/bin/env python3
"""Draw the Cairn app icon and build AppIcon.icns from it.

    python3 packaging/macos/icon/make-icon.py            # -> AppIcon.icns, AppIcon-1024.png, *.svg here
    python3 packaging/macos/icon/make-icon.py --variant green

The picture is a cairn: four pebbles stacked on a dark rounded square, the
capstone in the reader's green, the verified result the pile is built to
mark. It follows Apple's macOS icon grid (an 824pt body centred on a 1024pt
canvas, with its own drop shadow), so it sits at the same size as other apps
in the Dock. Sizes of 32px and under use a three-stone drawing, because four
stones and their gaps blur into one shape at 16px.

The SVGs are the source; the .icns is committed so a Mac build needs nothing
beyond the Command Line Tools. Regenerating needs Chromium (to render the
SVG), Pillow and icnsutil: `python3 -m pip install pillow icnsutil`.
"""
import argparse, io, os, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

# Background top/bottom, then each stone's gradient top/bottom, bottom stone first.
VARIANTS = {
    "night": dict(bg=("#1b2230", "#0b0f16"), ground="#000000", rim=("#ffffff", 0.10),
                  stones=[("#9aa0a8", "#5d636c"), ("#a9aeb5", "#6a7078"),
                          ("#b9bdc3", "#787d85"), ("#5ef0a8", "#14a46a")]),
    "green": dict(bg=("#19b273", "#0a7d52"), ground="#04442c", rim=("#ffffff", 0.0),
                  stones=[("#ffffff", "#dfe7e2"), ("#ffffff", "#e3eae6"),
                          ("#ffffff", "#e7eee9"), ("#ffffff", "#ecf2ee")]),
    "paper": dict(bg=("#fbfaf7", "#e9e6df"), ground="#7a7466", rim=("#000000", 0.06),
                  stones=[("#4a4f57", "#262a30"), ("#575c64", "#2e3238"),
                          ("#646971", "#363a41"), ("#2fd08a", "#0a7d52")]),
}

# width, height, x offset, tilt in degrees, how far the crown leans; bottom first.
FULL = [(500, 158, 0, 0, 0.02), (392, 138, 10, -3, -0.04),
        (296, 120, -8, 2.5, 0.05), (204, 104, 6, -2, -0.03)]
SMALL = [(560, 190, 0, 0, 0.0), (420, 165, 8, -3, -0.03), (270, 140, -4, 2, 0.03)]


def pebble(cx, base, w, h, skew):
    """A pebble resting at y=base: flat underneath, full and rounded on top."""
    l, r, top, peak = cx - w / 2, cx + w / 2, base - h, cx + skew * w
    return (f"M{l:.1f},{base-h*0.42:.1f} "
            f"C{l:.1f},{base-h*0.80:.1f} {peak-w*0.30:.1f},{top:.1f} {peak:.1f},{top:.1f} "
            f"C{peak+w*0.30:.1f},{top:.1f} {r:.1f},{base-h*0.80:.1f} {r:.1f},{base-h*0.42:.1f} "
            f"C{r:.1f},{base-h*0.10:.1f} {cx+w*0.30:.1f},{base:.1f} {cx:.1f},{base:.1f} "
            f"C{cx-w*0.30:.1f},{base:.1f} {l:.1f},{base-h*0.10:.1f} {l:.1f},{base-h*0.42:.1f} Z")


def svg(v, small=False):
    stones = SMALL if small else FULL
    colours = [v["stones"][0], v["stones"][1], v["stones"][3]] if small else v["stones"]
    gap = 26 if small else 14
    base = 800 if small else 772
    grads, body = [], []
    for i, (a, b) in enumerate(colours):
        grads.append(f'<linearGradient id="s{i}" x1="0" y1="0" x2="0" y2="1">'
                     f'<stop offset="0" stop-color="{a}"/><stop offset="1" stop-color="{b}"/></linearGradient>')
    if not small:
        body.append(f'<ellipse cx="512" cy="{base+6}" rx="300" ry="26" fill="{v["ground"]}" filter="url(#soft)"/>')
    for i, (w, h, dx, rot, skew) in enumerate(stones):
        cx = 512 + dx
        d = pebble(cx, base, w, h, skew)
        hl = "" if small else f'<path d="{d}" fill="url(#hl)" opacity="0.22"/>'
        body.append(f'<g transform="rotate({rot} {cx} {base-h/2})"><path d="{d}" fill="url(#s{i})"/>{hl}</g>')
        base -= h + gap
    rim, rim_op = v["rim"]
    nl = "\n"
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024" width="1024" height="1024">
<defs>
<linearGradient id="bg" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="{v["bg"][0]}"/><stop offset="1" stop-color="{v["bg"][1]}"/></linearGradient>
<radialGradient id="hl" cx="0.35" cy="0.15" r="0.6"><stop offset="0" stop-color="#fff"/><stop offset="1" stop-color="#fff" stop-opacity="0"/></radialGradient>
{nl.join(grads)}
<filter id="blur" x="-10%" y="-10%" width="120%" height="120%"><feGaussianBlur stdDeviation="14"/></filter>
<filter id="soft" x="-30%" y="-100%" width="160%" height="300%"><feGaussianBlur stdDeviation="14"/></filter>
<clipPath id="body"><rect x="100" y="100" width="824" height="824" rx="185"/></clipPath>
</defs>
<rect x="100" y="112" width="824" height="824" rx="185" fill="#000" opacity="0.30" filter="url(#blur)"/>
<rect x="100" y="100" width="824" height="824" rx="185" fill="url(#bg)"/>
<g clip-path="url(#body)">
{nl.join(body)}
</g>
<rect x="101" y="101" width="822" height="822" rx="184" fill="none" stroke="{rim}" stroke-opacity="{rim_op}" stroke-width="2"/>
</svg>
'''


def chromium():
    for c in (os.environ.get("CHROMIUM"), "/opt/pw-browsers/chromium", "chromium", "chromium-browser",
              "google-chrome", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"):
        if c and shutil.which(c):
            return shutil.which(c)
    sys.exit("no Chromium found; set CHROMIUM to one")


def render(svg_path, out_png):
    subprocess.run([chromium(), "--headless", "--no-sandbox", "--disable-gpu", "--hide-scrollbars",
                    "--default-background-color=00000000", "--window-size=1024,1024",
                    f"--screenshot={out_png}", "file://" + os.path.abspath(svg_path)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--variant", choices=VARIANTS, default="night")
    ap.add_argument("--out", default=HERE)
    a = ap.parse_args()
    from PIL import Image
    from icnsutil import IcnsFile

    v = VARIANTS[a.variant]
    full_svg, small_svg = os.path.join(a.out, "AppIcon.svg"), os.path.join(a.out, "AppIcon-small.svg")
    open(full_svg, "w").write(svg(v))
    open(small_svg, "w").write(svg(v, small=True))
    with tempfile.TemporaryDirectory() as tmp:
        render(full_svg, os.path.join(tmp, "full.png"))
        render(small_svg, os.path.join(tmp, "small.png"))
        full = Image.open(os.path.join(tmp, "full.png")).convert("RGBA")
        small = Image.open(os.path.join(tmp, "small.png")).convert("RGBA")
    full.save(os.path.join(a.out, "AppIcon-1024.png"))

    icns = IcnsFile()
    # ic04/ic05 are 16 and 32; ic11 and ic12 are their @2x; the rest are 128 to 1024.
    for key, px in [("ic04", 16), ("ic05", 32), ("ic11", 32), ("ic12", 64), ("ic07", 128),
                    ("ic08", 256), ("ic13", 256), ("ic09", 512), ("ic14", 512), ("ic10", 1024)]:
        src = small if px <= 32 else full
        buf = io.BytesIO()
        src.resize((px, px), Image.LANCZOS).save(buf, "PNG", optimize=True)
        icns.add_media(key, data=buf.getvalue())
    icns.write(os.path.join(a.out, "AppIcon.icns"))
    print(f"wrote AppIcon.icns, AppIcon-1024.png and the SVGs to {a.out} ({a.variant})")


if __name__ == "__main__":
    main()
