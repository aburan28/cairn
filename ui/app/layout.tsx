import type { Metadata } from "next";
import { Shell } from "@/components/Shell";
import "./globals.css";

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
