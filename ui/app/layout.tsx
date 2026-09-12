import type { Metadata, Viewport } from "next";
import { Shell } from "@/components/Shell";
import "./globals.css";

/**
 * `viewport-fit=cover` is what makes `env(safe-area-inset-*)` non-zero on a
 * notched phone. Without it the sticky header sits under the status bar when
 * someone adds this site to their home screen — which is now a supported way
 * in, see `app/manifest.ts`. The theme-color tags match the canvas token so
 * Safari's chrome does not flash a default white around a dark page.
 */
export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  viewportFit: "cover",
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#fbfbfa" },
    { media: "(prefers-color-scheme: dark)", color: "#0b0c0e" },
  ],
};

export const metadata: Metadata = {
  // A template rather than one fixed string. Every page here answers a
  // different question, and an operator comparing two nodes ends up with four
  // tabs all called "cairn" otherwise.
  title: {
    default: "cairn — a research network where verified results are the unit of account",
    template: "%s · cairn",
  },
  description:
    "Post a question with a pinned checker and a bounty; anyone who moves the "
    + "answer forward is paid in proportion to how far they moved it, and every "
    + "payment is re-derivable from the log by anyone who has it.",
  applicationName: "cairn",
  // Home-screen install. A service worker would intercept fetches and is a
  // new cache the project would then have to trust; the manifest and the
  // apple-touch-icon are same-origin files and enough for "Add to Home
  // Screen" to open this reader as its own app. The native iOS reader in
  // gui/ios is the same pages without a browser chrome.
  appleWebApp: {
    capable: true,
    title: "cairn",
    statusBarStyle: "default",
  },
  // No `metadataBase` and no og:image, deliberately. An absolute URL would bake
  // the public site's origin into the copy of this app that ships inside every
  // node binary, and an image would be another file the daemon carries for a
  // link preview no operator will ever see. The text tags work relative.
  openGraph: {
    type: "website",
    siteName: "cairn",
    title: "cairn — verified results are the unit of account",
    description:
      "Pay for verified outputs, never for claimed effort. An auditable log, "
      + "pinned checkers, and citation-flow attribution.",
  },
};

/**
 * Apply the stored theme before the first paint.
 *
 * A static export has no server to read a cookie, so without this the page
 * renders in the *system* theme and then swaps once React hydrates — a white
 * flash on every navigation for anyone who chose dark on a light machine.
 *
 * Inline, and it must stay inline: a separate file would be a second request,
 * and this app is built on the promise that it makes none. It is also the
 * whole of the script — no analytics, no font loader, nothing else has any
 * business running before paint.
 *
 * Wrapped in try/catch because `localStorage` *throws* on access in a browser
 * set to block site data, rather than returning null, and an exception here
 * would take the rest of the document with it.
 */
const THEME_SCRIPT = `try{var t=localStorage.getItem("cairn-theme");if(t==="light"||t==="dark")document.documentElement.setAttribute("data-theme",t)}catch(e){}`;

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }} />
      </head>
      <body>
        <Shell>{children}</Shell>
      </body>
    </html>
  );
}
