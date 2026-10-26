// NOVA Settings: profile, appearance, desktop, users (admin), apps, about.
import { h, clear, dateTime, duration, ago } from '../util.js';
import { icon } from '../icons.js';
import * as api from '../api.js';
import { state, savePrefs, bus } from '../store.js';
import { button, field, toggle, segmented, confirmDialog, promptDialog, toast, errorToast, customDialog } from '../ui.js';

const row = (title, hint, control) => h('div', { class: 'set-row' }, h('div', { class: 'set-text' }, h('b', {}, title), hint && h('div', { class: 'hint' }, hint)), control);

export default {
  mount(body, { win, wm, params, launch }) {
    const tabs = { profile: 'Profil', look: 'Darstellung', desktop: 'Desktop', ...(state.me.role === 'admin' ? { security: 'Sicherheit', users: 'Benutzer' } : {}), apps: 'Apps', about: 'System' };
    const content = h('div', { class: 'set-content' });
    const tabBar = h('div', { class: 'tabs', role: 'tablist' });
    body.append(h('div', { class: 'settings-app' }, tabBar, content));
    let current = params?.tab || 'profile';
    const show = t => {
      current = t;
      clear(tabBar).append(...Object.entries(tabs).map(([k, v]) => h('button', { role: 'tab', 'aria-selected': String(k === t), onclick: () => show(k) }, v)));
      clear(content);
      views[t](content);
    };
    const pref = (k, v) => savePrefs({ [k]: v }).catch(errorToast);

    const views = {
      async profile(el) {
        const cur = h('input', { class: 'input', type: 'password', autocomplete: 'current-password', maxlength: 256 });
        const nw = h('input', { class: 'input', type: 'password', autocomplete: 'new-password', minlength: 12, maxlength: 256 });
        const rep = h('input', { class: 'input', type: 'password', autocomplete: 'new-password', maxlength: 256 });
        const msg = h('div', { class: 'error-text', role: 'alert' });
        const sessions = h('div', { class: 'list' });
        el.append(
          h('div', { class: 'panel corners set-card' }, h('div', { class: 'profile-head' }, h('div', { class: 'avatar' }, icon('user')), h('div', {}, h('b', { class: 'profile-name' }, state.me.username), h('div', { class: 'hint' }, state.me.role === 'admin' ? 'Administrator' : 'Benutzer')))),
          h('form', { class: 'panel set-card', onsubmit: async e => {
            e.preventDefault(); msg.textContent = '';
            if (nw.value !== rep.value) { msg.textContent = 'Die neuen Passwörter stimmen nicht überein.'; return; }
            try { await api.put('me/password', { current: cur.value, new: nw.value }); toast('Passwort geändert', 'Andere Geräte wurden abgemeldet.'); cur.value = nw.value = rep.value = ''; loadSessions(); }
            catch (x) { msg.textContent = x.message; }
          } }, h('div', { class: 'label panel-title' }, 'Passwort ändern'), field('Aktuelles Passwort', cur), field('Neues Passwort', nw, 'Mindestens 12 Zeichen.'), field('Neues Passwort wiederholen', rep), msg, (() => { const b = button('Passwort ändern', { variant: 'primary' }); b.type = 'submit'; return b; })()),
          h('div', { class: 'panel set-card' }, h('div', { class: 'label panel-title' }, 'Aktive Sitzungen'), sessions));
        async function loadSessions() {
          try {
            const list = await api.get('sessions', { quiet: true });
            clear(sessions).append(...list.map(s => h('div', { class: 'row' }, icon(s.kind === 'local' ? 'monitor' : 'net'), h('div', { class: 'set-text' }, h('b', {}, (s.kind === 'local' ? 'HDMI-Bildschirm' : 'Browser') + (s.current ? ' (dieses Gerät)' : '')), h('div', { class: 'hint' }, `${s.agent.slice(0, 60) || 'Unbekannt'} · aktiv ${ago(s.last_seen)}`)),
              !s.current && button('Abmelden', { variant: 'danger', onclick: async () => { try { await api.del('sessions/' + s.id); loadSessions(); } catch (x) { errorToast(x); } } }))));
          } catch (x) { errorToast(x); }
        }
        loadSessions();
      },
      look(el) {
        const p = state.prefs;
        el.append(h('div', { class: 'panel corners set-card' },
          row('Akzentfarbe', 'Farbe der Leuchtakzente im NOVA Interface.', segmented([['cyan', 'Cyan'], ['violet', 'Violett']], p.accent, v => pref('accent', v))),
          row('Animationen', 'Deaktivieren spart Rechenleistung auf dem Raspberry Pi. Wird auch durch „Bewegung reduzieren“ des Systems ausgeschaltet.', toggle(p.animations, v => pref('animations', v), 'Animationen')),
          row('NOVA Orb anzeigen', 'Der Orb zeigt den Systemzustand auf dem Desktop an.', toggle(p.orb, v => pref('orb', v), 'Orb anzeigen')),
          row('Dichte', 'Abstände in Listen und Formularen.', segmented([['comfortable', 'Komfortabel'], ['compact', 'Kompakt']], p.density, v => pref('density', v)))));
      },
      desktop(el) {
        const p = state.prefs;
        el.append(h('div', { class: 'panel corners set-card' },
          row('24-Stunden-Uhr', null, toggle(p.clock24, v => pref('clock24', v), '24-Stunden-Uhr')),
          row('Apps beim Anmelden wiederherstellen', 'Geöffnete Apps und Fensterpositionen werden pro Gerätetyp (HDMI-Bildschirm / Browser) gespeichert.', toggle(p.restore_apps, v => pref('restore_apps', v), 'Apps wiederherstellen')),
          row('Fensteranordnung zurücksetzen', 'Setzt die gespeicherten Positionen für dieses Gerät zurück.', button('Zurücksetzen', { onclick: async () => {
            if (!await confirmDialog({ title: 'Fensteranordnung zurücksetzen?', message: 'Alle Fenster werden geschlossen und die gespeicherten Positionen gelöscht.', confirm: 'Zurücksetzen' })) return;
            try { await api.put('desktop', { windows: {}, open: [] }); location.reload(); } catch (x) { errorToast(x); }
          } }))));
      },
      async security(el) {
        const card = h('div', { class: 'panel corners set-card' }, h('div', { class: 'label panel-title' }, icon('shield'), ' Sicherheit'), h('div', { class: 'spinner' }));
        el.append(card);
        try {
          const j = await api.get('shield', { quiet: true });
          const bad = j.checks.filter(c => !['ok', 'info'].includes(c.level));
          clear(card).append(h('div', { class: 'label panel-title' }, icon('shield'), ' Sicherheit'),
            h('div', { class: 'upd-row' }, h('b', { class: 'sh-status-inline ' + j.status }, j.label), j.threats ? h('span', { class: 'chip critical' }, `${j.threats} Bedrohung(en)`) : null),
            ...(bad.length ? bad.slice(0, 4).map(c => h('div', { class: 'hint' }, `• ${c.title}: ${c.detail}`)) : [h('div', { class: 'hint' }, 'Alle erforderlichen Prüfungen bestanden.')]),
            h('div', { class: 'upd-actions' }, button('NOVA Shield öffnen', { icon: 'shield', variant: 'primary', onclick: () => launch('shield') }), button('Firewall', { onclick: () => launch('shield', { tab: 'firewall' }) }), button('Virenschutz', { onclick: () => launch('shield', { tab: 'malware' }) })));
        } catch (e) { clear(card).append(h('div', { class: 'error-text' }, e.message)); }
      },
      async users(el) {
        const box = h('div', { class: 'panel corners set-card' });
        el.append(box);
        const load = async () => {
          try {
            const users = await api.get('users');
            clear(box).append(h('div', { class: 'label panel-title' }, 'Benutzer'),
              ...users.map(u => h('div', { class: 'row' }, icon('user'), h('div', { class: 'set-text' }, h('b', {}, u.username), h('div', { class: 'hint' }, `${u.role === 'admin' ? 'Administrator' : 'Benutzer'} · seit ${dateTime(u.created)}`)),
                u.id !== state.me.id && button('Löschen', { variant: 'danger', onclick: async () => {
                  if (!await confirmDialog({ title: `„${u.username}“ löschen?`, message: 'Konto, Notizen und alle Dateien dieses Benutzers werden unwiderruflich gelöscht.', confirm: 'Löschen', danger: true })) return;
                  try { await api.del('users/' + u.id); load(); } catch (x) { errorToast(x); }
                } }))),
              h('div', { class: 'set-add' }, button('Benutzer hinzufügen', { icon: 'plus', variant: 'primary', onclick: addUser })));
          } catch (x) { errorToast(x); }
        };
        function addUser() {
          customDialog('Benutzer hinzufügen', (m, close) => {
            const n = h('input', { class: 'input', autocomplete: 'off', maxlength: 40, autofocus: true }), pw = h('input', { class: 'input', type: 'password', autocomplete: 'new-password', maxlength: 256 });
            const role = h('select', { class: 'select' }, h('option', { value: 'user' }, 'Benutzer'), h('option', { value: 'admin' }, 'Administrator'));
            const err = h('div', { class: 'error-text' });
            m.append(field('Benutzername', n), field('Passwort', pw, 'Mindestens 12 Zeichen.'), field('Rolle', role), err,
              h('div', { class: 'actions' }, button('Abbrechen', { onclick: () => close() }), button('Erstellen', { variant: 'primary', onclick: async () => {
                try { await api.post('users', { username: n.value.trim(), password: pw.value, role: role.value }); close(); load(); } catch (x) { err.textContent = x.message; }
              } })));
          });
        }
        load();
      },
      apps(el) {
        const { apps, permissions, errors } = state.appMeta;
        el.append(h('div', { class: 'panel corners set-card' }, h('div', { class: 'label panel-title' }, 'Installierte Apps'),
          ...apps.map(a => h('div', { class: 'row app-row' }, h('span', { class: 'f-icon' }, icon(a.icon)), h('div', { class: 'set-text' }, h('b', {}, `${a.name} `, h('small', { class: 'hint' }, `v${a.version}`)), h('div', { class: 'hint' }, a.description),
            a.permissions.length ? h('div', { class: 'perm-list' }, ...a.permissions.map(p => h('span', { class: 'chip', title: permissions[p] }, p))) : h('div', { class: 'hint' }, 'Keine besonderen Berechtigungen')), h('span', { class: 'chip' }, a.kind === 'system' ? 'System' : 'Sandbox'))),
          Object.keys(errors).length > 0 && h('div', { class: 'error-text' }, 'Nicht geladen: ' + Object.entries(errors).map(([k, v]) => `${k} (${v})`).join('; '))));
      },
      async about(el) {
        const box = h('div', { class: 'panel corners set-card' }, h('div', { class: 'spinner' }));
        el.append(box);
        const s = state.system || await api.get('system');
        const kv = (k, v) => h('div', { class: 'kv' }, h('span', { class: 'label' }, k), h('span', { class: 'mono' }, v));
        clear(box).append(h('div', { class: 'about-head' }, h('div', { class: 'brand' }, 'PiOS ', h('b', {}, 'NOVA')), h('span', { class: 'chip' }, 'Version ' + s.version)),
          kv('Hostname', s.net.hostname), kv('Adressen', s.net.interfaces.filter(i => i.ip).map(i => `${i.ip} (${i.name})`).join(', ') || '–'),
          kv('Laufzeit', duration(s.uptime)), kv('App-API', 'v' + state.appMeta.api), kv('Browser', navigator.userAgent.slice(0, 80)));
        if (state.me.role === 'admin') el.append(await updatesCard());
      },
    };
    async function updatesCard() {
      const card = h('div', { class: 'panel corners set-card upd-settings' }, h('div', { class: 'label panel-title' }, icon('update'), ' Updates'));
      try {
        const u = await api.get('updates', { quiet: true });
        card.append(
          row('Installierte Version', u.available ? `Version ${u.available.version} ist verfügbar.` : 'PiOS ist aktuell.', h('b', { class: 'mono' }, u.installed.version || '–')),
          row('Updatekanal', 'Beta enthält neue, noch nicht auf echter Hardware validierte Versionen.', segmented([['stable', 'Stable'], ['beta', 'Beta']], u.channel, async v => {
            try { await api.put('updates/config', { channel: v }); api.post('updates/check').catch(() => {}); } catch (x) { errorToast(x); }
          })),
          row('Update Center', 'Prüfen, installieren, Verlauf und Rollback.', button(u.available ? 'Update verfügbar – öffnen' : 'Öffnen', { icon: 'update', variant: u.available ? 'primary' : '', onclick: () => launch('updates') })));
      } catch (e) {
        card.append(h('div', { class: 'hint' }, e.status === 503 ? 'Der Update-Dienst ist nur im PiOS-Image aktiv.' : e.message));
      }
      return card;
    }
    show(current);
    return { params: p => p?.tab && show(p.tab) };
  },
};
