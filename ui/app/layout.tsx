import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "proofwork — a node reader",
  description:
    "What a proofwork node will pay for, and the epoch chain it settles against.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        {/* Plain links rather than an active-state nav: this is three pages,
            and knowing which one you are on is what the <h1> under it is for. */}
        <nav className="nav">
          <Link href="/objectives">objectives</Link>
          <Link href="/peers">peers</Link>
          <Link href="/">chain</Link>
        </nav>
        {children}
      </body>
    </html>
  );
}
