import { ShieldCheck } from 'lucide-react';
import { LoginForm } from './login-form';

export default function LoginPage() {
  return (
    <main className="flex min-h-screen items-center justify-center p-6">
      <div className="w-full max-w-sm rounded-lg border border-border bg-surface p-6 shadow-sm">
        <div className="mb-6 flex items-center gap-2">
          <ShieldCheck className="h-6 w-6 text-primary" aria-hidden />
          <div>
            <h1 className="text-base font-semibold">Vector58 Browser Security</h1>
            <p className="text-xs text-muted">Sign in to the security console</p>
          </div>
        </div>
        <LoginForm />
      </div>
    </main>
  );
}
