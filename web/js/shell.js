// NOVA Shell: top bar, desktop with orb, window host, dock, launcher, tray.
import { h, clear, debounce, ago } from './util.js';
import { icon, hasIcon } from './icons.js';
import * as api from './api.js';
import { bus, state, startPolling, stopPolling, startEvents, stopEvents, notifications } from './store.js';
import { WindowManager } from './wm.js';
import { createOrb } from './orb.js';
import { createLauncher } from './search.js';
import { mountSandboxed } from './sandbox.js';
import { toast, contextMenu, button } from './ui.js';

export async function startShell(root, { onLogout }) {
  const [appList, desktopState] = await Promise.all([api.get('apps'), api.get('desktop')]);
  state.appMeta = appList;
  state.apps = appList.apps.filter(a => a.id !== 'updates' || state.me.role === 'admin');
  const saved = desktopState || { windows: {}, open: [] };
  const byId = id => state.apps.find(a => a.id === id);

  // ---- layout ----
  const desktop = h('main', { class: 'desktop', 'aria-label': 'Desktop' });
  const orb = createOrb({ size: 'large' });
  const stage = h('div', { class: 'orb-stage' }, orb);
  desktop.append(stage);
  const wm = new WindowManager(desktop);
  const dockEl = h('nav', { class: 'dock', 'aria-label': 'Dock' });
  const launcher = createLauncher({ apps: () => state.apps, launch: (id, p) => launch(id, p) });

  // ---- top bar / tray ----
  const titleEl = h('span', { class: 'tb-title' });
  const cpuChip = h('span', { class: 'chip mono', title: 'CPU-Auslastung' }, icon('cpu'), h('span', {}, '–'));
  const tempChip = h('span', { class: 'chip mono', title: 'CPU-Temperatur' }, icon('temp'), h('span', {}, '–'));
  const netDot = h('span', { class: 'dot', title: 'Netzwerk' });
  const netEl = h('span', { class: 'tb-net', title: 'Netzwerk' }, icon('wifi'), netDot);
  const badge = h('i', { class: 'badge hidden' });
  const bell = h('button', { class: 'tb-btn', type: 'button', 'aria-label': 'Benachrichtigungen', onclick: () => togglePanel() }, icon('bell'), badge);
  const clock = h('button', { class: 'tb-btn clock mono', type: 'button', title: 'Datum', onclick: () => toast(new Date().toLocaleDateString('de-DE', { dateStyle: 'full' })) });
  const userBtn = h('button', { class: 'tb-btn', type: 'button', 'aria-label': 'Benutzermenü', onclick: e => {
    const r = e.currentTarget.getBoundingClientRect();
    contextMenu(r.right - 190, r.bottom + 4, [
      { label: `Angemeldet als ${state.me.username}`, icon: 'user', run: () => launch('settings') },
      '-', { label: 'Abmelden', icon: 'logout', run: logout }]);
  } }, icon('user'), h('span', { class: 'tb-user' }, state.me.username));
  const topbar = h('header', { class: 'topbar' },
    h('button', { class: 'tb-brand', type: 'button', onclick: () => launcher.toggle(), 'aria-label': 'App-Launcher' }, icon('spark'), h('b', {}, 'NOVA')), titleEl,
    h('span', { class: 'spacer' }), cpuChip, tempChip, netEl, bell, clock, userBtn);

  const panel = h('div', { class: 'notif-panel hidden panel corners', role: 'region', 'aria-label': 'Benachrichtigungen' });
  const togglePanel = () => { panel.classList.toggle('hidden'); if (!panel.classList.contains('hidden')) { renderPanel(); badge.classList.add('hidden'); } };
  const renderPanel = () => {
    clear(panel);
    panel.append(h('div', { class: 'label panel-title' }, 'Benachrichtigungen'));
    if (!notifications.length) panel.append(h('div', { class: 'hint' }, 'Keine Benachrichtigungen'));
    for (const n of notifications.slice(0, 20)) panel.append(h('div', { class: 'notif ' + (n.level || 'info') }, h('b', {}, n.title), n.body && h('div', { class: 'muted' }, n.body), h('small', { class: 'hint' }, `${n.app} · ${ago(n.time)}`)));
  };

  clear(root);
  root.append(h('div', { class: 'shell' }, topbar, desktop, dockEl, launcher.el, panel));

  // ---- apps ----
  const loaders = new Map();
  async function mountApp(win, app, params) {
    const spin = h('div', { class: 'empty' }, h('div', { class: 'spinner' }));
    win.body.append(spin);
    try {
      if (app.kind === 'sandboxed') mountSandboxed(win, app);
      else {
        const mod = await import(`./apps/${app.id}.js`);
        const inst = await mod.default.mount(win.body, { win, params, launch, toast, wm });
        loaders.set(win.id, inst || {});
        win.on('close', () => { try { inst?.destroy?.(); } catch (e) { console.error(e); } loaders.delete(win.id); });
      }
    } catch (e) {
      console.error(e);
      win.body.append(h('div', { class: 'empty' }, icon('close'), h('b', {}, `${app.name} konnte nicht gestartet werden`), h('span', {}, e.message), button('Schließen', { onclick: () => win.close() })));
    } finally { spin.remove(); }
  }

  function launch(id, params) {
    const app = byId(id);
    if (!app) return toast('App nicht gefunden', id, 'error');
    let win = wm.get(id);
    if (win) { win.restore(); if (params) loaders.get(id)?.params?.(params); return win; }
    win = wm.create({ id, title: app.name, icon: app.icon, width: app.window.width, height: app.window.height, minWidth: 300, minHeight: 220 }, saved.windows?.[id]);
    if (wm.mobile) win.el.classList.remove('opening');
    mountApp(win, app, params);
    return win;
  }

  // ---- dock ----
  const dockItems = new Map();
  function buildDock() {
    clear(dockEl);
    dockItems.clear();
    dockEl.append(h('button', { class: 'dock-item launcher-btn', type: 'button', title: 'Apps (Strg+K)', 'aria-label': 'App-Launcher', onclick: () => launcher.toggle() }, icon('grid')), h('span', { class: 'dock-sep' }));
    for (const app of state.apps) {
      const b = h('button', { class: 'dock-item', type: 'button', title: app.name, 'aria-label': app.name, onclick: () => {
        const w = wm.get(app.id);
        if (!w) launch(app.id);
        else if (w.min) w.restore();
        else if (wm.active === w && !wm.mobile) w.minimize();
        else w.focus();
      } }, icon(hasIcon(app.icon) ? app.icon : 'app'), h('span', { class: 'dock-tip' }, app.name));
      dockItems.set(app.id, b);
      dockEl.append(b);
    }
  }
  buildDock();
  wm.on('change', () => {
    for (const [id, b] of dockItems) {
      const w = wm.get(id);
      b.classList.toggle('running', !!w);
      b.classList.toggle('active', !!w && wm.active === w && !w.min);
    }
    titleEl.textContent = wm.active && !wm.active.min ? wm.active.titleEl.textContent : '';
  });
  wm.on('persist', data => api.put('desktop', data, { quiet: true }).catch(() => {}));

  // ---- tray ----
  const fmtClock = () => {
    const d = new Date();
    clock.textContent = d.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit', hour12: !state.prefs.clock24 });
  };
  fmtClock();
  const clockTimer = setInterval(fmtClock, 5000);
  const offSys = bus.on('system', s => {
    cpuChip.lastChild.textContent = Math.round(s.cpu) + '%';
    tempChip.lastChild.textContent = s.temp != null ? Math.round(s.temp) + '°' : '–';
    tempChip.classList.toggle('hot', s.temp != null && s.temp >= 75);
    netDot.className = 'dot ' + (s.net.online ? 'ok' : 'danger');
    const ip = s.net.interfaces.find(i => i.ip)?.ip;
    netEl.title = s.net.online ? `Online · ${ip} · ${s.net.hostname}` : 'Kein Netzwerk';
  });
  const offOffline = bus.on('system-offline', () => netDot.className = 'dot danger');
  const offNote = bus.on('notification', n => {
    toast(n.title, n.body, n.level);
    if (panel.classList.contains('hidden')) badge.classList.remove('hidden'); else renderPanel();
  });
  const offPrefs = bus.on('prefs', fmtClock);
  const offVer = bus.on('version-changed', ({ to }) => {
    toast('PiOS wurde aktualisiert', `Version ${to} – die Oberfläche wird neu geladen …`, 'info', 6000);
    setTimeout(() => location.reload(), 2500);
  });
  const markUpdate = on => dockItems.get('updates')?.classList.toggle('has-update', on);
  const offUpd = bus.on('notification', n => { if (n.app === 'updates' && /verfügbar/.test(n.title)) markUpdate(true); });
  if (state.me.role === 'admin') api.get('updates', { quiet: true }).then(u => markUpdate(!!(u.available && u.available.compatible))).catch(() => {});
  startPolling();
  startEvents();

  document.addEventListener('pointerdown', e => { if (!panel.contains(e.target) && !bell.contains(e.target)) panel.classList.add('hidden'); });

  // ---- restore previous session ----
  if (state.prefs.restore_apps) {
    for (const id of saved.open || []) if (byId(id)) { const w = launch(id); if (saved.minimized?.includes(id)) w.minimize(); }
    const a = saved.active && wm.get(saved.active);
    if (a && !a.min) a.focus();
  }
  wm.persist.cancel();

  async function logout() {
    try { await api.post('logout'); } catch { /* already logged out */ }
    teardown(); onLogout();
  }
  function teardown() {
    clearInterval(clockTimer); offSys(); offOffline(); offNote(); offPrefs(); offVer(); offUpd();
    stopPolling(); stopEvents();
    for (const w of [...wm.wins.values()]) w.emit('close');
  }
  return { teardown, launch };
}
