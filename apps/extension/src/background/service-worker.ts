import { NATIVE_HOST_NAME } from '@bsp/shared';
import { ExtensionController, type BlockReportMessage } from './controller';
import { chromeNativeConnector } from './native-port';
import { chromePlatform } from './platform';

/**
 * MV3 service worker entry point. All logic lives in ExtensionController;
 * this file only wires Chrome/Edge APIs.
 *
 * An open native messaging port keeps the service worker alive. The
 * keepalive alarm is a backstop that re-establishes the connection if the
 * worker was terminated anyway (e.g. after the host crashed).
 */
const KEEPALIVE_ALARM = 'bsp-native-keepalive';

function browserVersion(): string | null {
  const ua = navigator.userAgent;
  const m = __BROWSER__ === 'edge' ? /Edg\/([\d.]+)/.exec(ua) : /Chrome\/([\d.]+)/.exec(ua);
  return m?.[1] ?? null;
}

const controller = new ExtensionController({
  platform: chromePlatform(),
  connect: chromeNativeConnector(NATIVE_HOST_NAME),
  client: {
    browser: __BROWSER__,
    browserVersion: browserVersion(),
    extensionVersion: chrome.runtime.getManifest().version,
  },
  setBadge: (s) => {
    void chrome.action.setBadgeText({ text: s === 'ok' ? '' : '!' });
    void chrome.action.setBadgeBackgroundColor({ color: '#b45309' });
    void chrome.action.setTitle({
      title: s === 'ok' ? 'Browser Security: protected' : 'Browser Security: degraded (agent unreachable, last policy enforced)',
    });
  },
  schedule: (fn, ms) => setTimeout(fn, ms),
});

chrome.runtime.onInstalled.addListener(() => {
  void chrome.alarms.create(KEEPALIVE_ALARM, { periodInMinutes: 1 });
  void controller.ensureConnected();
});
chrome.runtime.onStartup.addListener(() => void controller.ensureConnected());
chrome.alarms.onAlarm.addListener((a) => {
  if (a.name === KEEPALIVE_ALARM) void controller.ensureConnected();
});

chrome.runtime.onMessage.addListener((message: unknown, sender, sendResponse) => {
  const m = message as { type?: string } | null;
  if (m?.type === 'BLOCK_PAGE_REPORT') {
    void controller.onBlockPageReport(message as BlockReportMessage, sender, chrome.runtime.id).then(sendResponse);
    return true;
  }
  if (m?.type === 'GET_STATUS' && sender.id === chrome.runtime.id) {
    void controller.status().then(sendResponse);
    return true;
  }
  return false;
});

// Top-level: runs every time the worker starts.
void controller.ensureConnected();
