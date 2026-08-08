import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "proofwork — knowledge chain",
  description:
    "The epoch chain a proofwork node settles against: each link commits to the one before it.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
