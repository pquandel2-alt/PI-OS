// Host for sandboxed (third-party style) apps.
//
// The app runs in an <iframe sandbox="allow-scripts"> with an opaque origin and a CSP that forbids any
// network access. Its only channel to PiOS is postMessage to this bridge. The bridge calls /api/sdk/*
// with a signed capability token; the *server* decides what the app may do (see pios/apps.py).
import { post } from './api.js';
import { toast } from './ui.js';
import { bus, state } from './store.js';

const instances = new Set();
const MAX_CALLS_PER_SEC = 200;

async function sdkFetch(inst, method, path, { json, body, raw } = {}, retry = true) {
  if (!inst.token) inst.token = (await post(`apps/${inst.app.id}/token`)).token;
  const headers = { Authorization: 'Bearer ' + inst.token };
  if (json !== undefined) headers['Content-Type'] = 'application/json';
  const r = await fetch('/api/sdk/' + path, { method, headers, body: json !== undefined ? JSON.stringify(json) : body, credentials: 'omit' });
  if (r.status === 401 && retry) { inst.token = null; return sdkFetch(inst, method, path, { json, body, raw }, false); }
  if (!r.ok) {
    let msg = `Fehler ${r.status}`;
    try { const d = await r.json(); if (typeof d.detail === 'string') msg = d.detail; } catch { /* no body */ }
    throw Object.assign(new Error(msg), { status: r.status });
  }
  return raw ? r.arrayBuffer() : r.json();
}

const enc = encodeURIComponent;
const handlers = {
  hello: inst => ({ app: inst.app.id, version: inst.app.version, api: 1, permissions: inst.app.permissions, accent: state.prefs.accent, motion: document.body.dataset.motion }),
  // pios.window
  'window.setTitle': (inst, p) => inst.win.setTitle(String(p.title ?? '').slice(0, 60)),
  'window.close': inst => inst.win.close(),
  'window.minimize': inst => inst.win.minimize(),
  'window.toggleMaximize': inst => inst.win.toggleMax(),
  // pios.ui
  'ui.toast': (inst, p) => toast(String(p.title ?? '').slice(0, 80), String(p.body ?? '').slice(0, 200), ['info', 'warn', 'error'].includes(p.level) ? p.level : 'info'),
  // pios.storage
  'storage.get': async (inst, p) => (await sdkFetch(inst, 'GET', `storage/${enc(p.key)}`)).value,
  'storage.set': (inst, p) => sdkFetch(inst, 'PUT', `storage/${enc(p.key)}`, { json: { value: p.value } }).then(() => null),
  'storage.remove': (inst, p) => sdkFetch(inst, 'DELETE', `storage/${enc(p.key)}`).then(() => null),
  // pios.files
  'files.list': (inst, p) => sdkFetch(inst, 'GET', `files?path=${enc(p.path ?? '')}`),
  'files.read': (inst, p) => sdkFetch(inst, 'GET', `files/content?path=${enc(p.path)}`, { raw: true }),
  'files.write': (inst, p) => sdkFetch(inst, 'PUT', `files/content?path=${enc(p.path)}`, { body: p.data }).then(() => null),
  // pios.system / pios.notifications
  'system.info': inst => sdkFetch(inst, 'GET', 'system'),
  'notifications.show': (inst, p) => sdkFetch(inst, 'POST', 'notifications', { json: { title: String(p.title ?? ''), body: String(p.body ?? ''), level: p.level || 'info' } }).then(() => null),
  // pios.events: apps may only publish in their own namespace "<appId>.*"
  'events.on': (inst, p) => { inst.topics.add(String(p.topic)); return null; },
  'events.off': (inst, p) => { inst.topics.delete(String(p.topic)); return null; },
  'events.emit': (inst, p) => {
    const topic = String(p.topic ?? '');
    if (!topic.startsWith(inst.app.id + '.')) throw Object.assign(new Error('Events dürfen nur im eigenen Namensraum veröffentlicht werden'), { status: 403 });
    for (const o of instances) if (o !== inst && o.topics.has(topic)) o.send({ event: 'event', data: { topic, data: p.data, from: inst.app.id } });
    return null;
  },
};

export function mountSandboxed(win, app) {
  const frame = document.createElement('iframe');
  frame.setAttribute('sandbox', 'allow-scripts');
  frame.setAttribute('referrerpolicy', 'no-referrer');
  frame.setAttribute('title', app.name);
  frame.src = `/apps/${app.id}/${app.entry}`;
  win.body.append(frame);

  const inst = { app, win, token: null, topics: new Set(), calls: [], send: msg => frame.contentWindow?.postMessage({ pios: 1, ...msg }, '*') };
  instances.add(inst);

  const onMessage = async ev => {
    if (ev.source !== frame.contentWindow) return;
    const m = ev.data;
    if (!m || m.pios !== 1 || typeof m.method !== 'string' || typeof m.id !== 'number') return;
    const now = Date.now();
    inst.calls = inst.calls.filter(t => now - t < 1000);
    if (inst.calls.push(now) > MAX_CALLS_PER_SEC) return inst.send({ id: m.id, error: { message: 'Zu viele Aufrufe', status: 429 } });
    const fn = Object.hasOwn(handlers, m.method) ? handlers[m.method] : null;
    if (!fn) return inst.send({ id: m.id, error: { message: 'Unbekannte Methode: ' + m.method, status: 404 } });
    try { inst.send({ id: m.id, result: (await fn(inst, m.params && typeof m.params === 'object' ? m.params : {})) ?? null }); }
    catch (e) { inst.send({ id: m.id, error: { message: e.message || 'Fehler', status: e.status || 500 } }); }
  };
  window.addEventListener('message', onMessage);
  const offPrefs = bus.on('prefs', p => inst.send({ event: 'theme', data: { accent: p.accent, motion: document.body.dataset.motion } }));
  win.on('close', () => { window.removeEventListener('message', onMessage); offPrefs(); instances.delete(inst); });
}
