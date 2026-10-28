/**
 * Typed application errors. API layers map `code` to HTTP status codes in a
 * single place (see apps/admin/src/server/http.ts) so business logic never
 * deals with transport concerns.
 */
export type AppErrorCode =
  | 'UNAUTHENTICATED'
  | 'FORBIDDEN'
  | 'NOT_FOUND'
  | 'VALIDATION_FAILED'
  | 'CONFLICT'
  | 'TENANT_DISABLED'
  | 'RATE_LIMITED'
  | 'INTERNAL';

export class AppError extends Error {
  readonly code: AppErrorCode;
  readonly details: unknown;

  constructor(code: AppErrorCode, message: string, details?: unknown) {
    super(message);
    this.name = 'AppError';
    this.code = code;
    this.details = details;
  }
}

export const isAppError = (e: unknown): e is AppError => e instanceof AppError;

export const unauthenticated = (message = 'Authentication required') =>
  new AppError('UNAUTHENTICATED', message);
export const forbidden = (message = 'You do not have permission to perform this action') =>
  new AppError('FORBIDDEN', message);
export const notFound = (message = 'Resource not found') => new AppError('NOT_FOUND', message);
export const validationFailed = (message: string, details?: unknown) =>
  new AppError('VALIDATION_FAILED', message, details);
export const conflict = (message: string) => new AppError('CONFLICT', message);
