import type { Metadata } from "next";
import Link from "next/link";
import { REPO, repoLink } from "@/lib/site";
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

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        {/* Plain links rather than an active-state nav: knowing which page you
            are on is what the <h1> under it is for.

            The same nav serves the public site and the reader a node embeds at
            /ui/, which is why "how it works" sits beside "chain". One app, so
            an operator gets the explanation too, rather than a second site
            drifting from this one. */}
        <nav className="nav">
          <Link href="/">cairn</Link>
          <Link href="/how-it-works">how it works</Link>
          <Link href="/objectives">objectives</Link>
          <Link href="/chain">chain</Link>
          <Link href="/peers">peers</Link>
          <Link href="/log">log</Link>
          <Link href="/docs">docs</Link>
        </nav>
        {children}
        <footer className="foot">
          <div className="footLinks">
            <a href={REPO}>source</a>
            <a href={`${REPO}/releases/latest`}>releases</a>
            <Link href="/docs">docs</Link>
            <a href={repoLink("docs/threat-model.md")}>threat model</a>
            <a href={repoLink("LICENSE")}>Apache-2.0</a>
          </div>
          <div className="dim">
            Stage 0 — one operator, no token, no consensus. What it does provide
            is the property that matters: anyone can independently re-derive
            every result the network has settled, from nothing but a copy of the
            log.
          </div>
          {/* Worth saying on the page and not only in ui/README.md: an operator
              reading their own node through an SSH tunnel can confirm it by
              watching the network tab stay empty. */}
          <div className="dim">
            This page loads no font, script, or image from anywhere but where it
            was served. The only host it talks to is the node you point it at.
          </div>
        </footer>
      </body>
    </html>
  );
}
