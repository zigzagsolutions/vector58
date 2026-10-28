/** Next immutable version number for a policy. Versions start at 1 and never reuse numbers. */
export function nextPolicyVersion(existing: readonly number[]): number {
  return existing.length === 0 ? 1 : Math.max(...existing) + 1;
}
