import { normalizeExactUrl, parseHttpUrl } from './normalize';

/** True when `hostname` equals `ruleDomain` or is a subdomain of it. */
export function hostnameMatchesDomain(hostname: string, ruleDomain: string): boolean {
  return hostname === ruleDomain || hostname.endsWith(`.${ruleDomain}`);
}

/** Does a navigated URL fall under a domain rule? */
export function urlMatchesDomainRule(url: string, ruleDomain: string): boolean {
  const parsed = parseHttpUrl(url);
  return parsed.ok && hostnameMatchesDomain(parsed.value.hostname, ruleDomain);
}

/** Does a navigated URL equal an exact-URL rule after normalisation? */
export function urlMatchesExactRule(url: string, ruleUrl: string): boolean {
  const n = normalizeExactUrl(url);
  return n.ok && n.value === ruleUrl;
}
