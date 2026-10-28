/**
 * SHA-256 helpers built on WebCrypto so the same code runs in Node 22+,
 * Vercel functions, Supabase Edge Functions (Deno) and MV3 service workers.
 */
const encoder = new TextEncoder();

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer), (b) => b.toString(16).padStart(2, '0')).join('');
}

export async function sha256Hex(input: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', encoder.encode(input));
  return toHex(digest);
}
