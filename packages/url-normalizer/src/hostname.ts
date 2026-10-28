import { err, ok, type Result } from '@bsp/shared';
import type { NormalizationError } from './types';

export const MAX_HOSTNAME_LENGTH = 253;
export const MAX_LABEL_LENGTH = 63;
export const MAX_URL_LENGTH = 2048;

const LABEL_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
const IPV4_RE = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

export const isIPv4 = (host: string): boolean => IPV4_RE.test(host);

/**
 * Normalise a bare hostname to its canonical ASCII form.
 * Uses the WHATWG URL parser for IDNA/punycode so the server and the browser
 * extension agree byte-for-byte with how Chromium itself canonicalises hosts.
 */
export function normalizeHostname(input: string): Result<string, NormalizationError> {
  const raw = input.trim();
  if (!raw) return err({ code: 'EMPTY_INPUT', message: 'Hostname is empty', input });
  if (raw.startsWith('[') || raw.includes(':')) {
    return err({
      code: 'IP_V6_NOT_SUPPORTED',
      message: 'IPv6 literals and ports are not supported in domain rules',
      input,
    });
  }

  let host: string;
  try {
    host = new URL(`http://${raw}/`).hostname;
  } catch {
    return err({ code: 'INVALID_HOSTNAME', message: `"${raw}" is not a valid hostname`, input });
  }

  // Chromium treats "example.com." and "example.com" as the same site.
  host = host.replace(/\.+$/, '');

  if (!host) return err({ code: 'INVALID_HOSTNAME', message: 'Hostname is empty', input });
  if (host.length > MAX_HOSTNAME_LENGTH) {
    return err({ code: 'TOO_LONG', message: 'Hostname exceeds 253 characters', input });
  }
  if (isIPv4(host)) return ok(host);

  const labels = host.split('.');
  if (labels.length < 2) {
    return err({
      code: 'SINGLE_LABEL_HOSTNAME',
      message: 'Hostname must contain at least two labels (e.g. example.com)',
      input,
    });
  }
  for (const label of labels) {
    if (label.length > MAX_LABEL_LENGTH || !LABEL_RE.test(label)) {
      return err({
        code: 'INVALID_HOSTNAME',
        message: `Hostname label "${label}" is invalid`,
        input,
      });
    }
  }
  // Final label (TLD) must not be all-numeric unless the whole host is an IPv4.
  if (/^\d+$/.test(labels[labels.length - 1] ?? '')) {
    return err({ code: 'INVALID_HOSTNAME', message: 'Top-level domain cannot be numeric', input });
  }
  return ok(host);
}
