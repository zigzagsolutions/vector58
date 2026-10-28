/**
 * Canonical JSON serialisation used for policy checksums.
 *
 * Rules (mirrored exactly by the C# implementation in
 * services/windows-agent/src/BrowserSecurity.Agent.Shared/Policy/CanonicalJson.cs):
 *  - object keys sorted by UTF-16 code unit order
 *  - no insignificant whitespace
 *  - `undefined` object members are omitted
 *  - only finite integers are permitted as numbers (no floats, avoids
 *    cross-runtime formatting differences)
 *  - strings escaped exactly like JSON.stringify
 */
export type CanonicalValue =
  | null
  | boolean
  | number
  | string
  | readonly CanonicalValue[]
  | { readonly [key: string]: CanonicalValue | undefined };

export function canonicalJson(value: CanonicalValue): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isSafeInteger(value)) {
        throw new TypeError(`canonicalJson only supports safe integers, got ${value}`);
      }
      return String(value);
    case 'string':
      return JSON.stringify(value);
    case 'object': {
      if (Array.isArray(value)) {
        return `[${(value as readonly CanonicalValue[]).map(canonicalJson).join(',')}]`;
      }
      const obj = value as { readonly [key: string]: CanonicalValue | undefined };
      const keys = Object.keys(obj)
        .filter((k) => obj[k] !== undefined)
        .sort();
      return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k] as CanonicalValue)}`).join(',')}}`;
    }
    default:
      throw new TypeError(`Unsupported value type in canonicalJson: ${typeof value}`);
  }
}
