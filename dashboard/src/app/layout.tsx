import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "IDR Sentinel — Kill Chain Dashboard",
  description:
    "Real-time intrusion detection and response dashboard for DPRK-001 campaign monitoring",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body
        style={{
          margin: 0,
          padding: 0,
          backgroundColor: "#0a0a0f",
          color: "#e0e0e0",
          fontFamily:
            "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
          minHeight: "100vh",
        }}
      >
        {children}
      </body>
    </html>
  );
}
