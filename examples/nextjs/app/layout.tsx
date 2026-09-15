import "./globals.css";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "ntcept example",
  description: "A Next.js app that makes outbound calls, so ntcept has something to intercept.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
