import { h, clear } from './util.js';
import * as api from './api.js';
import { state, loadPrefs, applyPrefs } from './store.js';
import { showAuth } from './auth.js';
import { startShell } from './shell.js';

const root = document.getElementById('root');
let shell = null;

async function boot() {
  shell?.teardown(); shell = null;
  document.getElementById('modal-root').replaceChildren();
  try {
    const status = await api.get('setup-status');
    if (status.needs_setup) { await showAuth(root, status); return boot(); }
    try { state.me = await api.get('me'); }
    catch (e) {
      if (e.status !== 401) throw e;
      await showAuth(root, status);
      return boot();
    }
    await loadPrefs();
    shell = await startShell(root, { onLogout: boot });
  } catch (e) {
    clear(root).append(h('div', { class: 'auth' }, h('div', { class: 'auth-card panel' },
      h('h2', {}, 'PiOS nicht erreichbar'), h('p', { class: 'muted' }, e.message),
      h('button', { class: 'btn primary', onclick: boot }, 'Erneut versuchen'))));
  }
}

let rebooting = false;
api.apiEvents.on('unauthorized', async () => {
  if (rebooting) return;
  rebooting = true;
  try { await boot(); } finally { rebooting = false; }
});

applyPrefs();
boot();
