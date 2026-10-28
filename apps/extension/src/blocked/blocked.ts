import type { BlockReportResult } from '../background/controller';

/**
 * Block page. Reads the rule id from ?r= and, when the redirect captured it,
 * the original URL from the fragment, then asks the service worker to report
 * URL_BLOCKED. The worker re-validates the report against the applied policy
 * and returns only verified details, which are what this page displays.
 */
const CATEGORY_LABELS: Record<string, string> = {
  phishing: 'Phishing',
  malware: 'Malware',
  'command-and-control': 'Command and control',
  'credential-theft': 'Credential theft',
  fraud: 'Fraud',
  'malicious-download': 'Malicious download',
  custom: 'Blocked by your organization',
};

function setText(id: string, text: string) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function originalUrl(): string | null {
  const fragment = location.hash.slice(1);
  if (!fragment) return null;
  try {
    return new URL(decodeURIComponent(fragment)).href;
  } catch {
    return null;
  }
}

async function main() {
  const ruleId = Number(new URLSearchParams(location.search).get('r'));
  const url = originalUrl();
  // The page is the only place the original URL is visible; strip it from history.
  if (location.hash) history.replaceState(null, '', location.pathname + location.search);

  let verified: BlockReportResult | null;
  try {
    verified = (await chrome.runtime.sendMessage({
      type: 'BLOCK_PAGE_REPORT',
      ruleId,
      url,
    })) as BlockReportResult | null;
  } catch {
    verified = null;
  }
  if (!verified) return;
  if (verified.domain) setText('site', verified.domain);
  if (verified.category)
    setText('category', CATEGORY_LABELS[verified.category] ?? verified.category);
  if (verified.ruleId) setText('rule', `#${verified.ruleId}`);
}

void main();
