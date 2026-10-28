import type { ExtensionController } from '../background/controller';

type Status = Awaited<ReturnType<ExtensionController['status']>>;

function setText(id: string, text: string) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

async function main() {
  const s = (await chrome.runtime.sendMessage({ type: 'GET_STATUS' })) as Status | undefined;
  if (!s) return;
  const state = document.getElementById('state')!;
  const protectedWithPolicy = s.policyVersion !== null;
  if (s.nativeConnected && protectedWithPolicy) {
    state.textContent = 'Protected';
    state.className = 'state ok';
  } else if (protectedWithPolicy) {
    state.textContent = 'Degraded: agent unreachable, last policy still enforced';
    state.className = 'state degraded';
  } else {
    state.textContent = 'Waiting for first policy from the agent';
    state.className = 'state degraded';
  }
  setText('native', s.nativeConnected ? 'Connected' : 'Disconnected');
  setText('policy', s.policyVersion === null ? 'None' : `v${s.policyVersion}`);
  setText('rules', String(s.ruleCount));
  setText('applied', s.appliedAt ? new Date(s.appliedAt).toLocaleString() : 'Never');
  setText('queued', String(s.queuedEvents));
  setText('version', `${s.extensionVersion} (${s.browser})`);
  if (s.lastError) {
    const e = document.getElementById('error')!;
    e.hidden = false;
    e.textContent = s.lastError;
  }
}

void main();
