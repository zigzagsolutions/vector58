import 'server-only';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

export const sha256 = (value: string): string => createHash('sha256').update(value, 'utf8').digest('hex');

/** 256-bit random token, URL-safe, with a short type prefix for secret scanners. */
export const generateToken = (prefix: string): string => `${prefix}_${randomBytes(32).toString('base64url')}`;

export function constantTimeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}
