import type { PolicyPayload } from '@bsp/policy-types';
import { canonicalJson, sha256Hex, type CanonicalValue } from '@bsp/shared';

/**
 * checksum = sha256(canonicalJson(payload minus `checksum` and `signature`)).
 * The Windows agent (C#) and the extension recompute this before applying.
 */
export function checksumInput(
  payload: Omit<PolicyPayload, 'checksum' | 'signature'> &
    Partial<Pick<PolicyPayload, 'checksum' | 'signature'>>,
): string {
  const { checksum: _c, signature: _s, ...rest } = payload;
  return canonicalJson(rest as unknown as CanonicalValue);
}

export function computePolicyChecksum(
  payload: Omit<PolicyPayload, 'checksum' | 'signature'> &
    Partial<Pick<PolicyPayload, 'checksum' | 'signature'>>,
): Promise<string> {
  return sha256Hex(checksumInput(payload));
}

export async function verifyPolicyChecksum(payload: PolicyPayload): Promise<boolean> {
  return (await computePolicyChecksum(payload)) === payload.checksum;
}
