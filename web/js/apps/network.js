// NOVA Netzwerk & Geräte: Wi-Fi, Ethernet, Bluetooth, connected devices, hardware & drivers.
// Everything shown comes from /api/net, /api/bt and /api/hw (pios-connd talking to NetworkManager, BlueZ, sysfs and udev). Passwords are typed into a
// dialog, sent once over the API and removed from the DOM; they are never kept in state, storage or URLs.
import { h, clear, ago } from '../util.js';
import { icon } from '../icons.js';
import * as api from '../api.js';
import { state } from '../store.js';
import { button, toggle, confirmDialog, customDialog, field, toast, errorToast } from '../ui.js';

const PAGES = [['wifi', 'WLAN', 'wifi'], ['ethernet', 'Ethernet', 'ethernet'], ['bluetooth', 'Bluetooth', 'bluetooth'], ['devices', 'Verbundene Geräte', 'mouse'], ['hardware', 'Hardware & Treiber', 'cpu']];
const COUNTRIES = [['DE', 'Deutschland'], ['AT', 'Österreich'], ['CH', 'Schweiz'], ['LU', 'Luxemburg'], ['NL', 'Niederlande'], ['BE', 'Belgien'], ['FR', 'Frankreich'], ['IT', 'Italien'], ['ES', 'Spanien'],
  ['PL', 'Polen'], ['CZ', 'Tschechien'], ['DK', 'Dänemark'], ['SE', 'Schweden'], ['NO', 'Norwegen'], ['GB', 'Vereinigtes Königreich'], ['IE', 'Irland'], ['US', 'USA'], ['CA', 'Kanada']];
const STATE_LEVEL = { ok: 'ok', warn: 'limited', fail: 'critical', unknown: 'unknown' };
const row = (title, hint, control) => h('div', { class: 'set-row' }, h('div', { class: 'set-text' }, h('b', {}, title), hint && h('div', { class: 'hint' }, hint)), control);
const chip = (t, cls = '', title) => h('span', { class: 'chip ' + cls, title }, t);
const bars = s => h('span', { class: 'sigbars', title: `Signal ${s}%`, 'aria-label': `Signal ${s}%` }, ...[20, 40, 60, 80].map(t => h('i', { class: s >= t ? 'on' : '' })));
const isAdmin = () => state.me.role === 'admin';

export default {
  mount(body, ctx) { return mountPanel(body, ctx); },
};

export function mountPanel(body, { params, launch } = {}) {
  let page = params?.page || 'wifi', alive = true, timers = [], seq = 0;
  const nav = h('nav', { class: 'net-nav', role: 'tablist', 'aria-label': 'Netzwerk & Geräte' });
  const content = h('div', { class: 'net-content' });
  body.append(h('div', { class: 'net-app' }, nav, content));
  const every = (ms, fn) => timers.push(setInterval(() => alive && !document.hidden && fn(), ms));
  const stop = () => { timers.forEach(clearInterval); timers = []; };
  const guard = async fn => { try { return await fn(); } catch (e) { errorToast(e); return null; } };
  const unavailable = (el, e) => clear(el).append(h('div', { class: 'upd-warn bad' }, icon('alert'),
    e.status === 503 ? 'Der Verbindungsdienst (pios-connd) ist nicht erreichbar. Er ist nur im PiOS-Image vorhanden.' : e.message));

  function show(p) {
    page = p; stop(); seq++;
    const my = seq, live = () => alive && my === seq;
    clear(nav).append(...PAGES.map(([k, label, ic]) => h('button', { role: 'tab', 'aria-selected': String(k === p), onclick: () => show(k) }, icon(ic), h('span', {}, label))));
    clear(content);
    if (!isAdmin() && p !== 'hardware') { summaryOnly(content, live); return; }
    views[p](content, live).catch(e => live() && unavailable(content, e));
  }

  // -------------------------------------------------------------------------------------------- normal users: read-only summary
  async function summaryOnly(el, live) {
    const box = h('div', { class: 'panel corners set-card' });
    el.append(box, h('div', { class: 'hint' }, 'Netzwerk- und Geräteeinstellungen können nur Administratoren ändern.'));
    const load = async () => {
      const s = await api.get('net/summary', { quiet: true }); if (!live()) return;
      clear(box).append(h('div', { class: 'label panel-title' }, icon('net'), ' Verbindungsstatus'),
        row('Netzwerk', null, chip(s.online ? 'Online' : 'Offline', s.online ? 'ok' : 'critical')),
        row('WLAN', s.wifi.present ? (s.wifi.connected ? s.wifi.ssid : (s.wifi.enabled ? 'Nicht verbunden' : 'Ausgeschaltet')) : 'Kein Adapter', s.wifi.connected ? bars(s.wifi.signal || 0) : null),
        row('Ethernet', s.ethernet.present ? (s.ethernet.connected ? 'Verbunden' : 'Kein Kabel') : 'Kein Adapter', null),
        row('Bluetooth', s.bluetooth.present ? (s.bluetooth.powered ? (s.bluetooth.connected.length ? s.bluetooth.connected.join(', ') : 'An') : 'Aus') : 'Kein Controller', null));
    };
    await load().catch(e => live() && unavailable(el, e));
    timers.push(setInterval(() => live() && load().catch(() => {}), 8000));
  }

  const views = {
    // ------------------------------------------------------------------------------------------ WLAN
    async wifi(el, live) {
      const status = h('div', { class: 'panel corners set-card' }, h('div', { class: 'spinner' }));
      const list = h('div', { class: 'panel corners set-card' });
      const saved = h('div', { class: 'panel corners set-card' });
      el.append(status, list, saved);
      let scanning = false;

      async function loadStatus() {
        const st = await api.get('net', { quiet: true }); if (!live()) return st;
        const w = st.wifi, dev = w.devices[0];
        const connected = dev && dev.state === 100;
        const info = [];
        if (connected) {
          const ip = dev.ip4?.addresses?.[0];
          info.push(row('Verbunden mit', dev.active_ap ? `${dev.active_ap.frequency > 4000 ? '5 GHz' : '2,4 GHz'} · ${dev.active_ap.signal}%` : null, h('b', {}, dev.connection?.id || dev.active_ap?.ssid || '–')),
            row('IP-Adresse', dev.dhcp ? 'Automatisch (DHCP)' : 'Manuell', h('span', { class: 'mono' }, ip ? `${ip.address}/${ip.prefix}` : '–')),
            row('Gateway · DNS', null, h('span', { class: 'mono' }, `${dev.ip4?.gateway || '–'} · ${(dev.ip4?.dns || []).join(', ') || '–'}`)),
            h('div', { class: 'upd-actions' }, button('Trennen', { icon: 'close', onclick: () => disconnect(dev.iface) })));
        }
        clear(status).append(h('div', { class: 'label panel-title' }, icon('wifi'), ' WLAN'),
          !w.present ? h('div', { class: 'upd-warn' }, icon('info'), 'Kein WLAN-Adapter erkannt. Unter „Hardware & Treiber“ siehst du, ob eine Firmware oder ein Treiber fehlt.') : null,
          w.present && row('WLAN', st.rfkill?.some(r => r.type === 'wlan' && r.hard_blocked) ? 'Durch einen Hardware-Schalter blockiert.' : 'Funkmodul ein- oder ausschalten.',
            toggle(w.enabled, v => guard(async () => { const r = await api.post('net/wifi/enabled', { enabled: v }); if (r.protected) toast('Bestätigung nötig', 'Bestätige die Änderung innerhalb von 60 Sekunden.', 'warn'); setTimeout(refresh, 800); }), 'WLAN')),
          w.present && row('Land (Funkregeln)', st.country && st.country !== '00' ? `Aktuell: ${st.country}. Bestimmt erlaubte Kanäle und Sendeleistung.` : 'Nicht gesetzt: WLAN bleibt eingeschränkt, bis ein Land gewählt ist.', countrySelect(st.country)),
          dev && !connected && h('div', { class: 'hint' }, `Adapter ${dev.iface}: ${dev.state_text}`), ...info);
        return st;
      }
      const countrySelect = cur => {
        const sel = h('select', { class: 'select', 'aria-label': 'WLAN-Land', onchange: async () => { if (await guard(() => api.put('net/wifi/country', { code: sel.value }))) { toast('Land gesetzt', sel.value); refresh(); } } },
          ...(COUNTRIES.some(c => c[0] === cur) ? [] : [h('option', { value: '' }, '– wählen –')]), ...COUNTRIES.map(([c, n]) => h('option', { value: c }, `${n} (${c})`)));
        sel.value = cur && cur !== '00' ? cur : '';
        return sel;
      };
      async function loadNetworks() {
        let nets = [];
        try { nets = (await api.get('net/wifi/networks', { quiet: true })).networks; } catch (e) { if (e.status !== 404 && e.status !== 409) throw e; }
        if (!live()) return;
        clear(list).append(h('div', { class: 'panel-title' }, h('span', { class: 'label' }, icon('search'), ' Verfügbare Netzwerke'), h('span', { class: 'spacer' }),
          button('Verstecktes Netzwerk', { onclick: () => connectDialog(null) }), button(scanning ? 'Suche läuft …' : 'Suchen', { icon: 'refresh', disabled: scanning, onclick: scan })),
          ...(nets.length ? nets.map(netRow) : [h('div', { class: 'hint' }, 'Keine Netzwerke gefunden. Starte eine Suche.')]));
      }
      const netRow = n => h('div', { class: 'row net-row', tabindex: 0, role: 'button', 'aria-label': `${n.ssid}, ${n.label}, Signal ${n.signal}%`, onclick: () => !n.in_use && connectDialog(n),
        onkeydown: e => (e.key === 'Enter' || e.key === ' ') && !n.in_use && (e.preventDefault(), connectDialog(n)) },
        bars(n.signal), h('div', { class: 'set-text' }, h('b', {}, n.ssid), h('div', { class: 'hint' }, `${n.label} · ${n.band}${n.known ? ' · gespeichert' : ''}`)),
        n.in_use ? chip('Verbunden', 'ok') : !n.supported ? chip('Nicht unterstützt', 'limited', n.reason) : n.security === 'open' ? chip('Offen', 'attention', 'Unverschlüsselt: Daten können mitgelesen werden') : icon('lock'));
      async function loadSaved(st) {
        if (!live()) return;
        clear(saved).append(h('div', { class: 'label panel-title' }, icon('history'), ' Gespeicherte Netzwerke'),
          ...(st.known.length ? st.known.map(k => h('div', { class: 'row' }, icon(k.secured ? 'lock' : 'alert'), h('div', { class: 'set-text' }, h('b', {}, k.id || k.ssid), h('div', { class: 'hint' }, k.active ? 'Aktiv' : k.timestamp ? 'Zuletzt ' + ago(k.timestamp) : '')),
            h('span', { class: 'hint' }, 'Automatisch'), toggle(k.autoconnect, v => guard(() => api.put('net/wifi/known/' + k.uuid, { autoconnect: v })), 'Automatisch verbinden'),
            button('Entfernen', { variant: 'danger', onclick: () => forget(k) }))) : [h('div', { class: 'hint' }, 'Noch keine Netzwerke gespeichert.')]));
      }
      async function refresh() { const st = await loadStatus().catch(e => { unavailable(status, e); return null; }); if (!st) return; await Promise.all([loadNetworks().catch(() => {}), loadSaved(st)]); }
      async function scan() {
        scanning = true; await loadNetworks();
        await guard(() => api.post('net/wifi/scan'));
        setTimeout(async () => { scanning = false; if (live()) await loadNetworks().catch(() => {}); }, 4000);
      }
      async function disconnect(iface) {
        if (!await confirmDialog({ title: 'WLAN trennen?', message: 'Wenn du über dieses WLAN auf PiOS zugreifst, wird die Verbindung getrennt. Bei Gefahr eines Aussperrens wird die Änderung automatisch zurückgenommen, falls du sie nicht bestätigst.', confirm: 'Trennen' })) return;
        const r = await guard(() => api.post('net/disconnect', { iface })); if (r?.protected) toast('Bestätigung nötig', 'Bestätige die Änderung innerhalb von 60 Sekunden.', 'warn');
        setTimeout(refresh, 800);
      }
      async function forget(k) {
        if (!await confirmDialog({ title: `„${k.id || k.ssid}“ entfernen?`, message: 'Das gespeicherte Passwort wird gelöscht.', confirm: 'Entfernen', danger: true })) return;
        if (await guard(() => api.del('net/wifi/known/' + k.uuid))) { toast('Netzwerk entfernt'); refresh(); }
      }
      function connectDialog(n) {
        customDialog(n ? `Mit „${n.ssid}“ verbinden` : 'Mit verstecktem Netzwerk verbinden', (m, close) => {
          const ssid = h('input', { class: 'input', autocomplete: 'off', maxlength: 32, value: n?.ssid || '', disabled: !!n });
          const needs = n ? n.needs_password && !n.known : true;
          const pw = h('input', { class: 'input', type: 'password', autocomplete: 'off', maxlength: 63, 'aria-label': 'WLAN-Passwort', spellcheck: 'false' });
          const hid = h('input', { type: 'checkbox' });
          const auto = h('input', { type: 'checkbox', checked: true });
          const err = h('div', { class: 'error-text', role: 'alert' });
          const status = h('div', { class: 'hint', 'aria-live': 'polite' });
          let busy = false;
          const submit = async () => {
            if (busy) return;
            const body = { ssid: ssid.value, hidden: !n, autoconnect: auto.checked };
            if (pw.value) body.psk = pw.value;
            if (!n && !pw.value && !hid.checked) { err.textContent = 'Für offene Netzwerke „Offenes Netzwerk (ohne Passwort)“ ankreuzen.'; return; }
            busy = true; err.textContent = ''; status.textContent = 'Verbinde …';
            try {
              const r = await api.post('net/wifi/connect', body);
              pw.value = ''; pw.remove();                        // the secret leaves the DOM as soon as it was sent
              const res = await waitOp(r.op, status);
              if (res.state === 'connected') { close(); toast('WLAN verbunden', ssid.value, 'info'); if (r.protected) confirmPending(); refresh(); }
              else { err.textContent = res.message || 'Verbindung fehlgeschlagen.'; status.textContent = ''; busy = false; }
            } catch (x) { err.textContent = x.message; status.textContent = ''; busy = false; }
          };
          m.append(field('Netzwerkname (SSID)', ssid),
            n && n.security === 'open' ? h('div', { class: 'upd-warn' }, icon('alert'), 'Dieses Netzwerk ist unverschlüsselt. Andere können deinen Datenverkehr mitlesen.') : null,
            n && n.known && !pw.value ? h('div', { class: 'hint' }, 'Gespeicherte Zugangsdaten werden verwendet. Gib nur ein Passwort ein, wenn es geändert wurde.') : null,
            (needs || (n && n.known) || !n) ? field('Passwort', pw, 'WPA2/WPA3: 8–63 Zeichen. Es wird nicht angezeigt oder im Browser gespeichert.') : null,
            !n ? h('label', { class: 'check' }, hid, ' Offenes Netzwerk (ohne Passwort)') : null,
            h('label', { class: 'check' }, auto, ' Automatisch verbinden'), err, status,
            h('div', { class: 'actions' }, button('Abbrechen', { onclick: () => close() }), button('Verbinden', { variant: 'primary', onclick: submit })));
          pw.addEventListener('keydown', e => e.key === 'Enter' && submit());
          if (!n) hid.addEventListener('change', () => { pw.disabled = hid.checked; });
        });
      }
      await refresh();
      every(6000, () => refresh().catch(() => {}));
    },

    // ------------------------------------------------------------------------------------------ Ethernet
    async ethernet(el, live) {
      const box = h('div', { class: 'panel corners set-card' }, h('div', { class: 'spinner' }));
      el.append(box);
      const load = async () => {
        const st = await api.get('net', { quiet: true }); if (!live()) return;
        const devs = st.ethernet.devices;
        clear(box).append(h('div', { class: 'label panel-title' }, icon('ethernet'), ' Ethernet'),
          ...(devs.length ? devs.flatMap(d => {
            const ip = d.ip4?.addresses?.[0];
            return [row(d.iface, `${d.carrier ? 'Kabel verbunden' : 'Kein Kabel'}${d.speed_mbps ? ` · ${d.speed_mbps} Mbit/s` : ''} · ${d.state_text}`, chip(d.state === 100 ? 'Verbunden' : d.carrier ? 'Verbinde …' : 'Getrennt', d.state === 100 ? 'ok' : '')),
              row('MAC-Adresse', null, h('span', { class: 'mono' }, d.mac || '–')),
              d.state === 100 && row('IP-Adresse', d.dhcp ? 'Automatisch (DHCP)' : 'Manuell vergeben', h('span', { class: 'mono' }, ip ? `${ip.address}/${ip.prefix}` : '–')),
              d.state === 100 && row('Gateway · DNS', null, h('span', { class: 'mono' }, `${d.ip4?.gateway || '–'} · ${(d.ip4?.dns || []).join(', ') || '–'}`)),
              d.connection && !d.dhcp && row('Auf DHCP umstellen', 'Bezieht die Adresse automatisch vom Router. Wird zunächst provisorisch angewendet und muss bestätigt werden.', button('DHCP aktivieren', { onclick: () => dhcp(d.iface) }))];
          }) : [h('div', { class: 'hint' }, 'Kein Ethernet-Adapter gefunden.')]),
          h('div', { class: 'hint' }, 'Statische IP-Adressen lassen sich hier noch nicht setzen; PiOS verwaltet nur DHCP, damit du dich nicht aussperrst.'));
      };
      async function dhcp(iface) {
        if (!await confirmDialog({ title: 'Auf DHCP umstellen?', message: 'Die IP-Adresse kann sich ändern. Öffne PiOS danach unter der neuen Adresse und bestätige die Änderung, sonst wird sie nach 60 Sekunden automatisch zurückgenommen.', confirm: 'Umstellen' })) return;
        const r = await guard(() => api.post('net/ethernet/dhcp', { iface })); if (r) { toast('DHCP aktiviert', r.protected ? 'Bestätige die Änderung innerhalb von 60 Sekunden.' : ''); setTimeout(load, 1000); }
      }
      await load();
      every(5000, () => load().catch(() => {}));
    },

    // ------------------------------------------------------------------------------------------ Bluetooth
    async bluetooth(el, live) {
      const head = h('div', { class: 'panel corners set-card' }, h('div', { class: 'spinner' }));
      const found = h('div', { class: 'panel corners set-card' });
      el.append(head, found);
      let st = null, scanning = false, dialog = null;
      const load = async () => {
        try { st = await api.get('bt', { quiet: true }); } catch (e) { if (e.status === 503 && /bluetoothd|Bluetooth/.test(e.message)) { clear(head).append(h('div', { class: 'upd-warn bad' }, icon('alert'), e.message)); return; } throw e; }
        if (!live()) return;
        const ad = st.adapters[0];
        clear(head).append(h('div', { class: 'label panel-title' }, icon('bluetooth'), ' Bluetooth'),
          !ad ? h('div', { class: 'upd-warn' }, icon('info'), 'Kein Bluetooth-Controller erkannt. Prüfe unter „Hardware & Treiber“, ob Firmware fehlt.') : [
            row('Bluetooth', st.rfkill?.some(r => r.hard_blocked) ? 'Durch einen Hardware-Schalter blockiert.' : `Controller ${ad.address}`, toggle(ad.powered, v => guard(async () => { await api.post('bt/power', { powered: v }); load(); }), 'Bluetooth')),
            row('Gerätesuche', 'Neue Geräte müssen im Kopplungsmodus sein. PiOS ist nicht dauerhaft für andere sichtbar.', button(ad.discovering ? 'Suche beenden' : 'Nach Geräten suchen', { icon: ad.discovering ? 'close' : 'search', disabled: !ad.powered,
              onclick: () => guard(async () => { if (ad.discovering) await api.post('bt/scan/stop'); else await api.post('bt/scan', { seconds: 30 }); setTimeout(load, 400); }) }))]);
        clear(found).append(h('div', { class: 'label panel-title' }, icon('mouse'), ' Geräte'), ...(st.devices.length ? st.devices.map(devRow) : [h('div', { class: 'hint' }, ad?.powered ? 'Noch keine Geräte gefunden.' : 'Bluetooth ist ausgeschaltet.')]));
        handlePairing(st);
      };
      const devRow = d => h('div', { class: 'row bt-row' }, icon(d.type === 'mouse' ? 'mouse' : d.type === 'keyboard' ? 'keyboard' : d.type === 'headphones' || d.type === 'speaker' ? 'headphones' : 'bluetooth'),
        h('div', { class: 'set-text' }, h('b', {}, d.name), h('div', { class: 'hint' }, `${d.type_label}${d.rssi != null ? ` · Signal ${d.rssi} dBm` : ''}${d.trusted ? ' · vertraut' : ''}`)),
        d.connected ? chip('Verbunden', 'ok') : d.paired ? chip('Gekoppelt') : null,
        !d.paired ? button('Koppeln', { variant: 'primary', onclick: () => pair(d) })
          : d.connected ? button('Trennen', { onclick: () => guard(async () => { await api.post('bt/disconnect', { address: d.address }); load(); }) }) : button('Verbinden', { variant: 'primary', onclick: () => guard(async () => { await api.post('bt/connect', { address: d.address }); load(); }) }),
        d.paired && button('Entfernen', { variant: 'danger', onclick: async () => { if (await confirmDialog({ title: `„${d.name}“ entfernen?`, message: 'Die Kopplung wird gelöscht. Zum erneuten Verbinden musst du das Gerät neu koppeln.', confirm: 'Entfernen', danger: true })) guard(async () => { await api.post('bt/remove', { address: d.address }); load(); }); } }));
      const pair = d => guard(async () => { await api.post('bt/pair', { address: d.address }); toast('Kopplung gestartet', d.name); handlePairing(await api.get('bt/pairing', { quiet: true })); });

      // Pairing prompts exist only because the admin started a pairing in this window; each one counts down and can be declined or cancelled.
      function handlePairing(s) {
        const reqs = s.requests || [], sess = (s.sessions || []).filter(x => x.state === 'pairing' || x.state === 'awaiting_user');
        if (!reqs.length) { if (dialog && !sess.length) { dialog.close(); dialog = null; } return; }
        const r = reqs[0];
        if (dialog && dialog.id === r.id) { dialog.tick(r.expires_in); return; }
        dialog?.close();
        customDialog(`Kopplung mit „${r.name}“`, (m, close) => {
          const left = h('div', { class: 'hint', 'aria-live': 'off' }, `Läuft ab in ${r.expires_in} s`);
          const input = h('input', { class: 'input', inputmode: r.kind === 'passkey' ? 'numeric' : 'text', autocomplete: 'off', maxlength: r.kind === 'passkey' ? 6 : 16, 'aria-label': 'PIN' });
          const reply = async accept => { try { await api.post('bt/pair/answer', { id: r.id, accept, value: accept && r.wants_input ? input.value : null }); } catch (x) { errorToast(x); } close(); dialog = null; setTimeout(load, 500); };
          m.append(r.kind === 'confirm' ? h('p', {}, 'Stimmt dieser Code mit der Anzeige auf dem Gerät überein?') : h('p', {}, r.wants_input ? 'Gib die PIN ein, die das Gerät verlangt (bei Tastaturen: die auf der Tastatur getippte Ziffernfolge).' : 'Bestätige die Kopplung.'),
            r.passkey != null ? h('div', { class: 'passkey mono', 'aria-label': 'Kopplungscode' }, String(r.passkey).padStart(6, '0')) : null, r.wants_input ? field('PIN', input) : null, left,
            h('div', { class: 'actions' }, button('Ablehnen', { variant: 'danger', onclick: () => reply(false) }), button('Bestätigen', { variant: 'primary', onclick: () => reply(true) })));
          dialog = { id: r.id, close, tick: s2 => { left.textContent = `Läuft ab in ${s2} s`; } };
        }).then(() => { dialog = null; });
      }
      await load();
      every(1500, () => api.get('bt/pairing', { quiet: true }).then(handlePairing).catch(() => {}));
      every(4000, () => load().catch(() => {}));
    },

    // ------------------------------------------------------------------------------------------ connected devices (input focus)
    async devices(el, live) {
      const box = h('div', { class: 'panel corners set-card' }, h('div', { class: 'spinner' }));
      const diag = h('div', { class: 'panel corners set-card' });
      el.append(box, diag);
      const load = async () => {
        const [inv, bt] = await Promise.all([api.get('hw', { quiet: true }), api.get('bt', { quiet: true }).catch(() => ({ devices: [] }))]); if (!live()) return;
        const inputs = inv.input.filter(i => i.mouse || i.keyboard);
        clear(box).append(h('div', { class: 'label panel-title' }, icon('mouse'), ' Eingabegeräte'),
          ...(inputs.length ? inputs.map(i => row(i.name, `${i.transport === 'usb' ? 'USB' : i.transport === 'bluetooth' ? 'Bluetooth' : i.transport} · ${i.mouse ? 'Zeigegerät' : 'Tastatur'}`, icon(i.mouse ? 'mouse' : 'keyboard'))) : [h('div', { class: 'hint' }, 'Es sind keine Maus oder Tastatur erkannt.')]),
          h('div', { class: 'label panel-title net-sub' }, icon('bluetooth'), ' Bluetooth'),
          ...(bt.devices?.filter(d => d.paired).map(d => row(d.name, d.type_label, chip(d.connected ? 'Verbunden' : 'Gekoppelt', d.connected ? 'ok' : ''))) || []),
          h('div', { class: 'label panel-title net-sub' }, icon('plug'), ' USB'), ...inv.usb.filter(u => !u.is_hub).map(u => row(u.product || `${u.vendor_id}:${u.product_id}`, `${u.manufacturer || ''} ${u.speed_mbps ? '· ' + u.speed_mbps + ' Mbit/s' : ''}`.trim(), chip(u.interfaces.some(i => i.driver) ? 'Treiber aktiv' : 'Kein Treiber', u.interfaces.some(i => i.driver) ? 'ok' : 'limited'))));
      };
      clear(diag).append(h('div', { class: 'label panel-title' }, icon('search'), ' Maus-Diagnose'), h('div', { class: 'hint' }, 'Prüft Schicht für Schicht, wo ein Eingabegerät verloren geht: USB, Kernel-Treiber, Eingabegerät, udev, Rechte, libinput, Sitzung, Compositor und Cursor.'),
        isAdmin() ? button('Diagnose starten', { icon: 'search', variant: 'primary', onclick: run }) : h('div', { class: 'hint' }, 'Nur Administratoren können die Diagnose starten.'));
      async function run() {
        clear(diag).append(h('div', { class: 'label panel-title' }, icon('search'), ' Maus-Diagnose'), h('div', { class: 'spinner' }));
        const d = await guard(() => api.get('hw/input-diagnosis')); if (!d || !live()) return;
        clear(diag).append(h('div', { class: 'label panel-title' }, icon('search'), ' Maus-Diagnose'),
          h('div', { class: 'upd-warn' + (d.verdict.state === 'fail' ? ' bad' : '') }, icon(d.verdict.state === 'ok' ? 'check' : 'alert'), h('div', {}, h('b', {}, d.verdict.title || 'Ergebnis'), h('div', {}, d.verdict.cause))),
          ...d.stages.map(s => h('div', { class: 'row diag-row' }, chip(s.state === 'ok' ? 'OK' : s.state === 'fail' ? 'Fehler' : s.state === 'warn' ? 'Warnung' : '?', STATE_LEVEL[s.state] || ''), h('div', { class: 'set-text' }, h('b', {}, s.title), h('div', { class: 'hint' }, s.detail)))),
          ...(d.hints?.length ? [h('div', { class: 'label panel-title net-sub' }, 'Hinweise aus dem Kernel-Log'), ...d.hints.map(t => h('div', { class: 'hint mono' }, t))] : []),
          h('div', { class: 'upd-actions' }, button('Erneut prüfen', { icon: 'refresh', onclick: run }), button('Geräte neu erkennen', { onclick: () => guard(async () => { await api.post('hw/rescan'); toast('Geräte werden neu erkannt'); setTimeout(load, 2000); }) })));
      }
      await load();
      every(5000, () => load().catch(() => {}));
    },

    // ------------------------------------------------------------------------------------------ hardware & drivers
    async hardware(el, live) {
      const box = h('div', { class: 'panel corners set-card' }, h('div', { class: 'spinner' }));
      const drv = h('div', { class: 'panel corners set-card' });
      el.append(box); if (isAdmin()) el.append(drv);
      const load = async () => {
        const i = await api.get('hw', { quiet: true }); if (!live()) return;
        const p = i.platform, sec = (t, ic) => h('div', { class: 'label panel-title net-sub' }, icon(ic), ' ' + t);
        clear(box).append(h('div', { class: 'label panel-title' }, icon('cpu'), ' Hardware'),
          row(p.model, `${p.cpu} · ${p.cores} Kerne · ${(p.memory_mb / 1024).toFixed(1)} GB RAM`, null), row('Kernel', p.os, h('span', { class: 'mono' }, p.kernel)),
          p.bootloader_build ? row('Bootloader', p.bootloader_update ? `Update: ${p.bootloader_update}` : null, h('span', { class: 'mono' }, p.bootloader_build)) : null,
          sec('Netzwerk', 'net'), ...i.network.filter(n => n.kind !== 'virtual' && n.kind !== 'loopback').map(n => row(n.iface, `${n.kind}${n.driver ? ' · Treiber ' + n.driver : ' · kein Treiber'}`, chip(n.state === 'up' ? 'Aktiv' : n.state, n.state === 'up' ? 'ok' : ''))),
          sec('Bluetooth', 'bluetooth'), ...(i.bluetooth.length ? i.bluetooth.map(b => row(b.name, b.bus ? `Anbindung: ${b.bus}` : '', chip(b.driver ? `Treiber ${b.driver}` : 'Kein Treiber', b.driver ? 'ok' : 'limited'))) : [h('div', { class: 'hint' }, 'Kein Controller erkannt.')]),
          sec('Anzeige', 'monitor'), ...(i.displays.filter(d => d.status === 'connected').map(d => row(d.monitor || d.connector, `${d.connector} · ${d.mode || ''}`, null)) || []),
          sec('Audio', 'bell'), ...(i.audio.length ? i.audio.map(a => row(a.name, a.driver || '', null)) : [h('div', { class: 'hint' }, 'Keine Audiogeräte erkannt.')]),
          sec('Speicher', 'disk'), ...i.storage.map(s => row(`${s.vendor || ''} ${s.model || s.name}`.trim(), `${s.name} · ${s.transport || ''}${s.removable ? ' · Wechseldatenträger' : ''}`, h('span', { class: 'mono' }, `${s.size_gb} GB`))),
          i.problems.length ? sec('Probleme', 'alert') : null, ...i.problems.map(x => h('div', { class: 'upd-warn' }, icon('alert'), h('div', {}, h('b', {}, x.device || x.title || 'Gerät'), h('div', {}, x.problem || x.text || '')))));
      };
      async function loadDrivers() {
        clear(drv).append(h('div', { class: 'label panel-title' }, icon('update'), ' Treiber & Firmware'), h('div', { class: 'spinner' }));
        const d = await guard(() => api.get('hw/drivers')); if (!d || !live()) return;
        clear(drv).append(h('div', { class: 'label panel-title' }, icon('update'), ' Treiber & Firmware'),
          h('div', { class: 'hint' }, 'PiOS installiert nur freigegebene Firmware-Pakete aus den offiziellen Debian- und Raspberry-Pi-Quellen, nach deiner Bestätigung. Keine Treiber aus dem Internet, keine Skripte.'),
          ...(d.findings.length ? d.findings.map(findingCard) : [h('div', { class: 'upd-warn' }, icon('check'), 'Es wurden keine fehlenden Treiber oder Firmware-Dateien erkannt.')]),
          h('div', { class: 'upd-actions' }, button('Erneut prüfen', { icon: 'refresh', onclick: loadDrivers })));
      }
      const findingCard = f => h('div', { class: 'upd-warn' + (f.state === 'missing' ? '' : '') }, icon('alert'), h('div', { class: 'set-text' }, h('b', {}, f.title), h('div', {}, f.advice), f.detail && h('div', { class: 'hint mono' }, f.detail),
        ...f.packages.map(p => h('div', { class: 'row' }, h('div', { class: 'set-text' }, h('b', {}, p.package), h('div', { class: 'hint' }, p.installed ? `installiert (${p.installed})` : p.available ? `Version ${p.candidate} aus ${p.origins.join(', ')}` : p.reason)),
          p.needs_install && p.installable ? button('Installieren', { variant: 'primary', onclick: () => install(p, f) }) : p.installed ? chip('Installiert', 'ok') : chip(p.official ? 'Nicht freigegeben' : 'Quelle nicht offiziell', 'limited')))));
      async function install(p, f) {
        if (!await confirmDialog({ title: `${p.package} installieren?`, message: `Paket ${p.package} Version ${p.candidate} aus den offiziellen Quellen (${p.origins.join(', ')}) wird installiert. Danach ist ein Neustart oder erneutes Laden des Treibers nötig. Die Installation läuft über den gesicherten PiOS-Systemdienst und wird im Sicherheitsprotokoll vermerkt.`, confirm: 'Installieren' })) return;
        if (await guard(() => api.post('hw/packages/install', { package: p.package, version: p.candidate }))) { toast('Installation gestartet', p.package); setTimeout(loadDrivers, 6000); }
      }
      await load();
      if (isAdmin()) loadDrivers();
      every(8000, () => load().catch(() => {}));
    },
  };

  async function waitOp(op, statusEl) {
    for (let i = 0; i < 70 && alive; i++) {
      await new Promise(r => setTimeout(r, 1000));
      const r = await api.get('net/operation/' + op, { quiet: true });
      if (r.state !== 'activating') return r;
      statusEl.textContent = 'Verbinde …';
    }
    return { state: 'failed', message: 'Zeitüberschreitung.' };
  }
  const confirmPending = () => document.dispatchEvent(new CustomEvent('pios-net-pending'));

  show(page);
  return { params: p => p?.page && show(p.page), destroy() { alive = false; stop(); if (page === 'bluetooth') api.post('bt/pair/cancel', {}, { quiet: true }).catch(() => {}); } };
}
