import Link from 'next/link';

export default function DeniedPage() {
  return (
    <main className="flex min-h-screen items-center justify-center p-6 text-center">
      <div>
        <h1 className="text-lg font-semibold">Access denied</h1>
        <p className="mt-1 text-sm text-muted">Your role does not grant permission to view this page.</p>
        <Link href="/" className="mt-4 inline-block text-sm text-primary hover:underline">Go to your home page</Link>
      </div>
    </main>
  );
}
