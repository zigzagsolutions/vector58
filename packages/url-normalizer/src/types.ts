export type NormalizationErrorCode =
  | 'EMPTY_INPUT'
  | 'TOO_LONG'
  | 'MALFORMED'
  | 'UNSUPPORTED_SCHEME'
  | 'MISSING_SCHEME'
  | 'INVALID_HOSTNAME'
  | 'IP_V6_NOT_SUPPORTED'
  | 'SINGLE_LABEL_HOSTNAME';

export interface NormalizationError {
  readonly code: NormalizationErrorCode;
  readonly message: string;
  readonly input: string;
}

export type IndicatorKind = 'domain' | 'exact_url';

export interface NormalizedIndicator {
  readonly kind: IndicatorKind;
  /** Canonical value used for storage, dedupe and policy compilation. */
  readonly value: string;
  /** Hostname (ASCII / punycode) the indicator applies to. */
  readonly hostname: string;
}
