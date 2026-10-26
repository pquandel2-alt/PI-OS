// Shared client state: current user, preferences, live system metrics, events.
import { Emitter } from './util.js';
import * as api from './api.js';

export const bus = new Emitter();
export const state = { me: null, prefs: { accent: 'cyan', animations: true, orb: true, density: 'comfortable', clock24: true, restore_apps: true }, system: null, apps: [], appMeta: null };

const reduce = matchMedia('(prefers-reduced-motion: reduce)');

export function applyPrefs() {
  const p = state.prefs, d = document.body.dataset;
  d.accent = p.accent;
  d.density = p.density;
  d.motion = p.animations && !reduce.matches ? 'on' : 'off';
  d.orb = p.orb ? 'on' : 'off';
  bus.emit('prefs', p);
}
reduce.addEventListener?.('change', applyPrefs);

export async function loadPrefs() {
  state.prefs = await api.get('prefs');
  applyPrefs();
}
export async function savePrefs(patch) {
  state.prefs = { ...state.prefs, ...patch };
  applyPrefs();
  await api.put('prefs', state.prefs);
}

// ---- live system metrics (one poller shared by tray, orb and Monitor) ----
let timer = null, knownVersion = null;
export const history = { cpu: [], ram: [], temp: [] };
export async function pollSystem() {
  try {
    state.system = await api.get('system', { quiet: true });
    if (knownVersion && state.system.version !== knownVersion) bus.emit('version-changed', { from: knownVersion, to: state.system.version });
    knownVersion = state.system.version;
    for (const [k, v] of [['cpu', state.system.cpu], ['ram', state.system.ram.percent], ['temp', state.system.temp ?? 0]]) {
      history[k].push(v); if (history[k].length > 60) history[k].shift();
    }
    bus.emit('system', state.system);
  } catch (e) {
    if (e.status === 0) bus.emit('system-offline');
  }
}
export function startPolling() {
  stopPolling();
  pollSystem();
  const loop = () => { if (!document.hidden) pollSystem(); };
  timer = setInterval(loop, 2500);
}
export function stopPolling() { clearInterval(timer); timer = null; knownVersion = null; }

// ---- events / notifications ----
let since = 0, evTimer = null;
export const notifications = [];
export async function pollEvents() {
  try {
    const r = await api.get('events?since=' + since, { quiet: true });
    since = r.last < since ? 0 : r.last;
    for (const e of r.events) {
      if (e.kind === 'notification') { notifications.unshift(e); bus.emit('notification', e); }
    }
  } catch { /* offline or logged out */ }
}
export function startEvents() { stopEvents(); pollEvents(); evTimer = setInterval(() => !document.hidden && pollEvents(), 4000); }
export function stopEvents() { clearInterval(evTimer); evTimer = null; since = 0; notifications.length = 0; }
