/**
 * Abstraction over chrome.runtime.Port for the native messaging connection so
 * the controller can be exercised with an in-memory fake.
 */
export interface NativePort {
  postMessage(message: unknown): void;
  onMessage(listener: (message: unknown) => void): void;
  onDisconnect(listener: (error: string | null) => void): void;
  disconnect(): void;
}

export type NativeConnector = () => NativePort;

export function chromeNativeConnector(hostName: string): NativeConnector {
  return () => {
    const port = chrome.runtime.connectNative(hostName);
    return {
      postMessage: (m) => port.postMessage(m),
      onMessage: (l) => port.onMessage.addListener((m: unknown) => l(m)),
      onDisconnect: (l) =>
        port.onDisconnect.addListener(() => l(chrome.runtime.lastError?.message ?? null)),
      disconnect: () => port.disconnect(),
    };
  };
}

/** Exponential backoff with jitter, capped. attempt starts at 0. */
export function reconnectDelayMs(attempt: number, random: () => number = Math.random): number {
  const base = Math.min(60_000, 1_000 * 2 ** Math.min(attempt, 6));
  return Math.round(base * (0.8 + random() * 0.4));
}
