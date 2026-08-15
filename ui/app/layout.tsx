import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "cairn",
  description:
    "A research network where verified results are the unit of account: pinned "
    + "checkers, an auditable log, and citation-flow attribution.",
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
            are on is what the <h1> under it is for. */}
        <nav className="nav">
          <Link href="/">cairn</Link>
          <Link href="/objectives">objectives</Link>
          <Link href="/chain">chain</Link>
          <Link href="/peers">peers</Link>
        </nav>
        {children}
      </body>
    </html>
  );
}
