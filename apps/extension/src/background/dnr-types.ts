/**
 * Minimal structural types for declarativeNetRequest rules so the converter
 * stays pure and unit-testable outside a browser.
 */
export type ResourceType =
  | 'main_frame' | 'sub_frame' | 'stylesheet' | 'script' | 'image' | 'font' | 'object' | 'xmlhttprequest'
  | 'ping' | 'csp_report' | 'media' | 'websocket' | 'webtransport' | 'webbundle' | 'other';

export const ALL_RESOURCE_TYPES: ResourceType[] = [
  'main_frame', 'sub_frame', 'stylesheet', 'script', 'image', 'font', 'object', 'xmlhttprequest',
  'ping', 'csp_report', 'media', 'websocket', 'webtransport', 'webbundle', 'other',
];

export interface DnrRule {
  id: number;
  priority: number;
  action:
    | { type: 'block' }
    | { type: 'allow' }
    | { type: 'redirect'; redirect: { regexSubstitution: string } | { extensionPath: string } };
  condition: {
    requestDomains?: string[];
    regexFilter?: string;
    urlFilter?: string;
    isUrlFilterCaseSensitive?: boolean;
    resourceTypes?: ResourceType[];
    excludedResourceTypes?: ResourceType[];
  };
}
