import Link from 'next/link';

export default function NotFound() {
  return (
    <main className="flex min-h-screen items-center justify-center p-6 text-center">
      <div>
        <h1 className="text-lg font-semibold">Not found</h1>
        <p className="mt-1 text-sm text-muted">The resource does not exist or you do not have access to it.</p>
        <Link href="/" className="mt-4 inline-block text-sm text-primary hover:underline">Go home</Link>
      </div>
    </main>
  );
}
