import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Vector58 Browser Security',
  description: 'Cloud-managed browser security console',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen antialiased">{children}</body>
    </html>
  );
}
