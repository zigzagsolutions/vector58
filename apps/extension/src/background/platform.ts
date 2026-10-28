import type { DnrRule } from './dnr-types';

/**
 * The subset of browser APIs the extension logic depends on. The service
 * worker passes real `chrome.*` implementations; unit tests pass fakes.
 */
export interface ExtensionPlatform {
  readonly dnr: {
    getDynamicRules(): Promise<DnrRule[]>;
    updateDynamicRules(update: { removeRuleIds: number[]; addRules: DnrRule[] }): Promise<void>;
    isRegexSupported?(regex: string): Promise<boolean>;
  };
  readonly storage: {
    get<T>(key: string): Promise<T | undefined>;
    set(key: string, value: unknown): Promise<void>;
  };
  readonly extensionOrigin: string;
  readonly now: () => Date;
  readonly randomId: () => string;
}

export function chromePlatform(): ExtensionPlatform {
  return {
    dnr: {
      getDynamicRules: () => chrome.declarativeNetRequest.getDynamicRules() as unknown as Promise<DnrRule[]>,
      updateDynamicRules: (u) =>
        chrome.declarativeNetRequest.updateDynamicRules(u as unknown as chrome.declarativeNetRequest.UpdateRuleOptions),
      isRegexSupported: async (regex) => {
        const r = await chrome.declarativeNetRequest.isRegexSupported({ regex, isCaseSensitive: false });
        return r.isSupported;
      },
    },
    storage: {
      get: async <T>(key: string) => (await chrome.storage.local.get(key))[key] as T | undefined,
      set: (key, value) => chrome.storage.local.set({ [key]: value }),
    },
    extensionOrigin: `chrome-extension://${chrome.runtime.id}`,
    now: () => new Date(),
    randomId: () => crypto.randomUUID(),
  };
}
