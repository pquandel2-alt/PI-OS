// NOVA Shield: security status, firewall, malware protection, app permissions, OS updates, audit log.
// Every value shown here comes from a real check in the backend (/api/shield); nothing is simulated.
import { h, clear, bytes, dateTime, ago, debounce } from '../util.js';
import { icon } from '../icons.js';
import * as api from '../api.js';
import { button, toggle, segmented, confirmDialog, customDialog, toast, errorToast, meter } from '../ui.js';

const LEVEL = { ok: ['check', 'OK', 'ok'], info: ['info', 'Info', ''], unknown: ['alert', 'Unbekannt', 'unknown'], limited: ['alert', 'Eingeschränkt', 'limited'],
  attention: ['alert', 'Handlungsbedarf', 'attention'], critical: ['close', 'Kritisch', 'critical'] };
const SEV = { info: '', notice: 'ok', warning: 'limited', critical: 'critical' };
const PERM = {};
const TABS = [['overview', 'Übersicht', 'shield'], ['firewall', 'Firewall', 'lock'], ['malware', 'Virenschutz', 'eye'], ['apps', 'Apps', 'app'], ['system', 'Updates', 'update'], ['audit', 'Protokoll', 'history']];

const row = (title, hint, control) => h('div', { class: 'set-row' }, h('div', { class: 'set-text' }, h('b', {}, title), hint && h('div', { class: 'hint' }, hint)), control);
const chip = (t, cls = '') => h('span', { class: 'chip ' + cls }, t);

export default {
  async mount(body, { win, launch, params }) {
    let tab = params?.tab || 'overview', timers = [], seq = 0, alive = true;
    const content = h('div', { class: 'sh-content' });
    const tabBar = h('div', { class: 'tabs', role: 'tablist' });
    body.append(h('div', { class: 'shield-app' }, tabBar, content));
    const every = (ms, fn) => { const t = setInterval(() => alive && !document.hidden && fn(), ms); timers.push(t); };
    const stopTimers = () => { timers.forEach(clearInterval); timers = []; };
    const guard = async fn => { try { return await fn(); } catch (e) { errorToast(e); return null; } };

    function show(t) {
      tab = t; stopTimers(); seq++;
      clear(tabBar).append(...TABS.map(([k, label, ic]) => h('button', { role: 'tab', 'aria-selected': String(k === t), onclick: () => show(k) }, icon(ic), ' ', label)));
      clear(content);
      const my = seq;
      views[t](content, () => my === seq).catch(e => { if (my === seq) content.append(h('div', { class: 'upd-warn bad' }, icon('alert'), e.message)); });
    }

    // ---------------------------------------------------------------- overview
    async function overview(el, live) {
      const hero = h('section', { class: 'panel corners sh-hero' }, h('div', { class: 'spinner' }));
      const grid = h('div', { class: 'sh-grid' });
      const events = h('section', { class: 'panel corners' });
      el.append(hero, grid, events);
      async function load() {
        const j = await api.get('shield', { quiet: true });
        if (!live()) return;
        hero.dataset.status = j.status;
        clear(hero).append(
          h('div', { class: 'sh-emblem', 'data-status': j.status }, h('svg', { viewBox: '0 0 100 100', class: 'sh-emblem-svg', 'aria-hidden': 'true' },
            ...[ [50, 6, 'M50 6 L88 20 V50 C88 74 70 90 50 96 C30 90 12 74 12 50 V20 Z'], ].map(([, , d]) => svgPath(d, 'sh-shield-outline')), svgPath('M50 18 L78 28 V50 C78 68 65 80 50 85 C35 80 22 68 22 50 V28 Z', 'sh-shield-inner'),
            j.status === 'protected' ? svgPath('M36 52 L46 62 L66 40', 'sh-check') : svgPath('M50 34 V56 M50 66 V68', 'sh-check'))),
          h('div', { class: 'sh-hero-text' }, h('div', { class: 'label' }, 'Sicherheitsstatus'), h('h2', { class: 'sh-status' }, j.label),
            h('div', { class: 'hint' }, summary(j))),
          h('div', { class: 'sh-hero-actions' }, button('Neu prüfen', { icon: 'refresh', onclick: () => guard(load) }), j.threats ? chip(`${j.threats} Bedrohung(en)`, 'critical') : null));
        clear(grid).append(...j.checks.filter(c => c.level !== 'info' || c.id === 'transport').map(checkCard));
        clear(events).append(h('div', { class: 'label panel-title' }, icon('history'), ' Letzte Sicherheitsereignisse'), ...j.recent_events.map(auditRow),
          h('div', { class: 'upd-actions' }, button('Alle anzeigen', { variant: 'ghost', onclick: () => show('audit') })));
      }
      await load();
      every(30000, () => load().catch(() => {}));
    }
    const svgPath = (d, cls) => { const p = document.createElementNS('http://www.w3.org/2000/svg', 'path'); p.setAttribute('d', d); p.setAttribute('class', cls); return p; };
    const summary = j => { const bad = j.checks.filter(c => !['ok', 'info'].includes(c.level)); return bad.length ? `${bad.length} Punkt(e) benötigen Aufmerksamkeit: ${bad.map(c => c.title).join(', ')}` : 'Alle erforderlichen Prüfungen wurden durchgeführt und bestanden.'; };
    function checkCard(c) {
      const [ic, label, cls] = LEVEL[c.level];
      const go = { firewall: 'firewall', malware: 'malware', os: 'system', sandbox: 'apps', audit: 'audit', access: 'audit' }[c.id];
      return h('section', { class: 'panel sh-card ' + cls },
        h('div', { class: 'sh-card-head' }, h('span', { class: 'sh-card-ic ' + cls }, icon(ic)), h('b', {}, c.title), chip(label, cls)),
        h('p', { class: 'sh-detail' }, c.detail), h('div', { class: 'hint' }, 'Geprüft ' + ago(c.checked_at)),
        c.id === 'ota' ? button('Update Center öffnen', { icon: 'update', variant: 'ghost', onclick: () => launch('updates') }) : go ? button('Details', { variant: 'ghost', onclick: () => show(go) }) : null);
    }
    const auditRow = e => h('div', { class: 'row sh-audit' }, chip(e.severity, SEV[e.severity]), h('span', { class: 'sh-audit-kind mono' }, e.kind),
      h('span', { class: 'sh-audit-detail' }, [e.actor, e.ip, ...Object.entries(e.detail || {}).map(([k, v]) => `${k}=${v}`)].filter(Boolean).join(' · ')), h('span', { class: 'hint' }, dateTime(e.ts)));

    // ---------------------------------------------------------------- firewall
    async function firewall(el, live) {
      const box = h('div', { class: 'sh-stack' });
      el.append(box);
      let draft = null;
      async function load() {
        let st;
        try { st = await api.get('shield/firewall', { quiet: true }); }
        catch (e) { if (!live()) return; clear(box).append(h('div', { class: 'empty' }, icon('lock'), h('b', {}, 'Firewall-Dienst nicht erreichbar'), h('span', {}, e.message), h('span', { class: 'hint' }, 'Solange das nicht geprüft werden kann, gilt der Schutz als unbekannt.'))); return; }
        if (!live()) return;
        draft = draft || { ...st.config, web_cidrs: [...st.config.web_cidrs] };
        render(st);
      }
      function render(st) {
        const pend = st.pending;
        clear(box);
        if (pend) {
          box.append(h('section', { class: 'panel corners sh-pending' }, h('div', { class: 'sh-pending-head' }, icon('alert'), h('b', {}, `Änderung aktiv – noch ${pend.seconds_left} s zum Bestätigen`)),
            h('p', { class: 'hint' }, 'Du kannst diese Seite noch erreichen, wenn du sie siehst. Ohne Bestätigung wird automatisch die vorherige, bestätigte Regel wiederhergestellt – du sperrst dich nicht aus.'),
            meter(pend.seconds_left / st.confirm_seconds * 100, pend.seconds_left < 15 ? 'warn' : ''),
            h('div', { class: 'upd-actions' }, button('Bestätigen und speichern', { icon: 'check', variant: 'primary', onclick: () => guard(async () => { await api.post('shield/firewall/confirm'); toast('Firewall-Regeln gespeichert'); draft = null; await load(); }) }),
              button('Sofort zurücksetzen', { icon: 'rollback', variant: 'danger', onclick: () => guard(async () => { await api.post('shield/firewall/revert'); draft = null; await load(); }) }))));
        }
        const ok = st.active;
        box.append(h('section', { class: 'panel corners' },
          h('div', { class: 'label panel-title' }, icon('lock'), ' Zustand'),
          h('div', { class: 'upd-row' }, h('span', { class: 'dot ' + (ok ? 'ok' : 'danger') }), h('b', {}, ok ? 'Firewall aktiv (nftables, eingehend standardmäßig gesperrt)' : 'Firewall NICHT wie konfiguriert aktiv')),
          st.problems.length ? h('div', { class: 'upd-warn bad' }, icon('alert'), st.problems.join('; ')) : null,
          h('div', { class: 'sh-ports' }, h('span', { class: 'label' }, 'Freigegeben (eingehend)'),
            ...st.expected_ports.tcp.map(p => chip(`${p}/tcp ${p === 80 ? 'PiOS' : p === 22 ? 'SSH' : ''}`, p === 22 ? 'limited' : 'ok')),
            ...st.expected_ports.udp.map(p => chip(`${p}/udp ${p === 5353 ? 'mDNS (pios.local)' : 'DHCP-Antworten'}`)),
            chip('ICMPv6 Nachbarerkennung', ''), st.config.ping ? chip('Ping (begrenzt)') : null),
          h('div', { class: 'hint' }, `Quellen: ${st.config.web_scope === 'lan' ? 'lokales Netz (private Adressen und direkt verbundene Netze, IPv4 + IPv6)' : st.config.web_cidrs.join(', ')} · Ausgehend: erlaubt · Weiterleitung: gesperrt`),
          st.last_event ? h('div', { class: 'hint' }, `Letztes Ereignis: ${({ confirmed: 'Änderung bestätigt', reverted: 'manuell zurückgesetzt', auto_reverted: 'AUTOMATISCH zurückgesetzt (keine Bestätigung)' })[st.last_event.kind]} ${ago(st.last_event.time)}`) : null));
        if (!pend) box.append(policyForm(st));
      }
      function policyForm(st) {
        const cidr = h('textarea', { class: 'textarea mono', rows: 3, placeholder: '192.168.1.0/24\nfd00::/8', 'aria-label': 'Erlaubte Netze', oninput: e => { draft.web_cidrs = e.target.value.split(/[\s,]+/).filter(Boolean); } });
        cidr.value = draft.web_cidrs.join('\n');
        const cidrBox = h('div', { class: 'field' }, h('span', { class: 'label' }, 'Erlaubte Netze (eines pro Zeile)'), cidr, h('span', { class: 'hint' }, 'Nur Geräte aus diesen Netzen erreichen PiOS. Falsche Eingaben werden nach 60 s automatisch zurückgenommen.'));
        cidrBox.classList.toggle('hidden', draft.web_scope !== 'custom');
        const preview = h('pre', { class: 'mono sh-script hidden' });
        return h('section', { class: 'panel corners set-card' }, h('div', { class: 'label panel-title' }, 'Richtlinie ändern'),
          row('Wer darf PiOS im Netzwerk erreichen?', 'Standard: nur Geräte im lokalen Netz.', segmented([['lan', 'Lokales Netz'], ['custom', 'Bestimmte Netze']], draft.web_scope, v => { draft.web_scope = v; cidrBox.classList.toggle('hidden', v !== 'custom'); })), cidrBox,
          row('SSH (Port 22) freigeben', 'Nur nötig für Wartung. Besser deaktiviert lassen.', toggle(draft.ssh, v => { draft.ssh = v; }, 'SSH')),
          row('mDNS (pios.local)', 'Ohne mDNS ist PiOS nur per IP-Adresse erreichbar.', toggle(draft.mdns, v => { draft.mdns = v; }, 'mDNS')),
          row('Ping erlauben', 'Begrenzt auf 5/s aus dem erlaubten Netz.', toggle(draft.ping, v => { draft.ping = v; }, 'Ping')),
          preview,
          h('div', { class: 'upd-actions' },
            button('Regeln prüfen (Vorschau)', { icon: 'eye', onclick: () => guard(async () => { const r = await api.post('shield/firewall/preview', body()); preview.textContent = r.script; preview.classList.remove('hidden'); toast('Regelwerk ist gültig', 'nft hat es im Testlauf akzeptiert.'); }) }),
            button('Änderung anwenden', { icon: 'check', variant: 'primary', onclick: apply })));
      }
      const body = () => ({ web_scope: draft.web_scope, web_cidrs: draft.web_scope === 'custom' ? draft.web_cidrs : [], ssh: draft.ssh, mdns: draft.mdns, ping: draft.ping });
      async function apply() {
        const ok = await confirmDialog({ title: 'Firewall-Änderung anwenden?', confirm: 'Jetzt anwenden', danger: draft.web_scope === 'custom',
          message: 'Die Regeln werden sofort aktiv. Du hast 60 Sekunden Zeit, sie zu bestätigen. Bleibt die Bestätigung aus (z. B. weil du dich ausgesperrt hast), stellt PiOS automatisch die vorherige Konfiguration wieder her.' });
        if (ok) guard(async () => { await api.post('shield/firewall/apply', body()); await load(); });
      }
      await load();
      every(1000, () => load().catch(() => {}));
    }

    // ---------------------------------------------------------------- malware
    async function malwareTab(el, live) {
      const box = h('div', { class: 'sh-stack' });
      el.append(box);
      let cur = null;
      async function load() {
        const [st, scans, q] = await Promise.all([api.get('shield/malware', { quiet: true }), api.get('shield/scans', { quiet: true }), api.get('shield/quarantine', { quiet: true })]);
        if (!live()) return;
        cur = { st, scans, q };
        render();
      }
      const set = patch => guard(async () => { await api.put('shield/malware/settings', patch); await load(); });
      function render() {
        const { st, scans, q } = cur, sig = st.signatures, running = scans.running, job = scans.scans[0];
        clear(box);
        box.append(h('section', { class: 'panel corners set-card' }, h('div', { class: 'label panel-title' }, icon('eye'), ' Virenschutz (ClamAV, on-demand)'),
          h('div', { class: 'upd-chips' }, chip(st.enabled ? 'aktiviert' : 'deaktiviert', st.enabled ? 'ok' : 'limited'), chip(st.installed ? 'ClamAV installiert' : 'ClamAV fehlt', st.installed ? 'ok' : 'limited'),
            chip(st.running ? 'Scanner läuft' : 'Scanner schläft (RAM frei)', ''), chip(sig.present ? `Signaturen ${sig.age_days} Tage alt` : 'keine Signaturen', sig.present && sig.age_days < 7 ? 'ok' : 'limited')),
          st.version ? h('div', { class: 'hint mono' }, st.version) : null,
          row('Virenschutz aktiv', 'Uploads landen zuerst in einer gesperrten Quarantäne und werden vor der Freigabe geprüft.', toggle(st.enabled, v => set({ enabled: v }), 'Virenschutz')),
          row('Wenn der Scanner nicht verfügbar ist', 'Fail-closed (empfohlen): Uploads bleiben gesperrt. Alternativ werden sie freigegeben und als „NICHT geprüft“ markiert.',
            segmented([['fail_closed', 'Gesperrt halten'], ['allow_unscanned', 'Ungeprüft freigeben']], st.policy, v => v === 'allow_unscanned'
              ? confirmDialog({ title: 'Ungeprüfte Uploads erlauben?', danger: true, confirm: 'Erlauben', message: 'Ist der Scanner nicht verfügbar, werden Dateien ohne Prüfung freigegeben. Sie werden als „nicht geprüft“ gekennzeichnet und im Protokoll vermerkt.' }).then(o => o ? set({ policy: v }) : render()) : set({ policy: v }))),
          row('Scanner nur bei Bedarf starten', 'clamd belegt ~1 GB RAM. Mit „bei Bedarf“ läuft er nur, solange Dateien geprüft werden.', toggle(st.on_demand, v => set({ on_demand: v }), 'On-demand')),
          row('Wöchentlicher Scan', 'Sonntag nach 03:30 Uhr, nur bei geringer Last.', segmented([['weekly', 'Wöchentlich'], ['off', 'Aus']], st.schedule, v => set({ schedule: v }))),
          h('div', { class: 'upd-actions' }, button('Signaturen jetzt aktualisieren', { icon: 'refresh', onclick: () => guard(async () => { await api.post('shield/signatures/update'); toast('Signatur-Update gestartet', 'Das kann einige Minuten dauern.'); }) }))));
        box.append(h('section', { class: 'panel corners set-card' }, h('div', { class: 'label panel-title' }, 'Scan der Benutzerdateien'),
          running ? h('div', {}, h('b', {}, `Scan läuft … ${job.files} Dateien geprüft, ${job.infected} Funde`), h('div', { class: 'meter indeterminate' }, h('i')),
            h('div', { class: 'upd-actions' }, button('Abbrechen', { icon: 'close', variant: 'danger', onclick: () => guard(async () => { await api.post(`shield/scans/${job.id}/cancel`); await load(); }) })))
            : h('div', { class: 'upd-actions' }, button('Jetzt alle Dateien scannen', { icon: 'eye', variant: 'primary', disabled: !st.enabled, onclick: () => guard(async () => { await api.post('shield/scans', { scope: 'all' }); await load(); }) }),
              h('span', { class: 'hint' }, 'Gefundene Malware wird isoliert (nicht gelöscht). Andere Dateien bleiben unberührt.')),
          ...scans.scans.slice(0, 5).map(s => h('div', { class: 'row sh-audit' }, chip({ done: 'fertig', running: 'läuft', cancelled: 'abgebrochen', failed: 'fehlgeschlagen' }[s.state] || s.state, s.state === 'done' ? (s.infected ? 'critical' : 'ok') : s.state === 'failed' ? 'critical' : ''),
            h('span', {}, `${s.kind === 'scheduled' ? 'Geplant' : 'Manuell'} · ${s.files} Dateien · ${bytes(s.bytes)} · ${s.infected} Funde · ${s.errors} Fehler`), h('span', { class: 'hint' }, s.note), h('span', { class: 'hint' }, dateTime(s.started))))));
        box.append(h('section', { class: 'panel corners set-card' }, h('div', { class: 'label panel-title' }, icon('lock'), ' Quarantäne'),
          q.length ? null : h('div', { class: 'hint' }, 'Quarantäne ist leer.'),
          ...q.filter(i => !['released'].includes(i.state)).map(i => h('div', { class: 'row sh-q' }, chip(STATE[i.state]?.[0] || i.state, STATE[i.state]?.[1] || ''),
            h('div', { class: 'set-text' }, h('b', {}, i.name), h('div', { class: 'hint' }, `${i.user} · ${bytes(i.size)} · ${i.detected_type} · ${dateTime(i.created)}${i.scanned ? ' · geprüft ' + ago(i.scanned) : ''}`),
              h('div', { class: i.state === 'infected' ? 'upd-warn bad' : 'hint' }, [i.detection, i.reason].filter(Boolean).join(' – '))),
            ['held', 'error'].includes(i.state) ? button('Erneut prüfen', { variant: 'ghost', onclick: () => guard(async () => { await api.post(`shield/quarantine/${i.id}/rescan`); await load(); }) }) : null,
            button('Löschen', { icon: 'trash', variant: 'danger', onclick: async () => { if (await confirmDialog({ title: `„${i.name}“ endgültig löschen?`, danger: true, confirm: 'Löschen', message: 'Die Datei wird unwiderruflich entfernt. Eine Freigabe erkannter Malware ist nicht vorgesehen.' })) guard(async () => { await api.del(`shield/quarantine/${i.id}`); await load(); }); } }))),
          q.some(i => i.state === 'released_unscanned') ? h('div', { class: 'hint' }, 'Hinweis: Einträge „NICHT geprüft“ wurden ohne Scan freigegeben (Policy „Ungeprüft freigeben“).') : null));
      }
      await load();
      every(1500, () => load().catch(() => {}));
    }
    const STATE = { pending: ['wartet', ''], held: ['gesperrt (Scanner fehlt)', 'limited'], scanning: ['wird geprüft', ''], infected: ['MALWARE', 'critical'], blocked: ['blockiert', 'critical'], error: ['Scanfehler', 'limited'], released_unscanned: ['NICHT geprüft', 'limited'], released: ['frei', 'ok'] };

    // ---------------------------------------------------------------- apps
    async function appsTab(el, live) {
      const j = await api.get('shield/apps');
      if (!live()) return;
      const list = h('div', { class: 'sh-stack' });
      el.append(h('section', { class: 'panel corners' }, h('div', { class: 'label panel-title' }, icon('app'), ' App-Berechtigungen'),
        h('p', { class: 'hint' }, 'Sandbox-Apps laufen isoliert (iframe ohne Netzwerk). Jede Berechtigung wird bei jedem Zugriff serverseitig geprüft; ein Entzug wirkt sofort und macht bestehende Tokens unbrauchbar.')), list);
      for (const a of j.apps) {
        const sandboxed = a.kind === 'sandboxed';
        list.append(h('section', { class: 'panel sh-card' },
          h('div', { class: 'sh-card-head' }, h('span', { class: 'sh-card-ic' }, icon('app')), h('b', {}, `${a.name} `), h('span', { class: 'hint' }, `v${a.version}`), chip(sandboxed ? 'Sandbox' : 'System', sandboxed ? 'ok' : ''), chip(a.origin === 'bundled' ? 'mitgeliefert' : a.origin)),
          h('div', { class: 'hint' }, a.description), h('div', { class: 'hint' }, `Isolation: ${a.isolation}${a.updated ? ' · aktualisiert ' + dateTime(a.updated) : ''}`),
          !a.requested.length ? h('div', { class: 'hint' }, 'Fordert keine besonderen Berechtigungen an.') : h('div', { class: 'sh-perms' }, ...a.requested.map(p => {
            const granted = a.granted.includes(p), g = a.grants[p];
            return h('div', { class: 'set-row' }, h('div', { class: 'set-text' }, h('b', { class: 'mono' }, p), h('div', { class: 'hint' }, `${j.permissions[p] || ''}${g ? ` · erteilt von ${g.by} ${ago(g.time)}` : ' · angefragt, noch nicht erteilt'}`)),
              sandboxed ? toggle(granted, async v => { try { await api.put(`shield/apps/${a.id}/grants`, { permission: p, allow: v }); toast(v ? 'Berechtigung erteilt' : 'Berechtigung entzogen', `${a.name}: ${p}`); } catch (e) { errorToast(e); } }, p)
                : chip('System', ''));
          }))));
      }
    }

    // ---------------------------------------------------------------- OS / OTA updates
    async function systemTab(el, live) {
      const box = h('div', { class: 'sh-stack' });
      el.append(box);
      async function load() {
        let os = null, osErr = '';
        try { os = await api.get('shield/os', { quiet: true }); } catch (e) { osErr = e.message; }
        let ota = null;
        try { ota = await api.get('updates', { quiet: true }); } catch { /* no updater */ }
        if (!live()) return;
        clear(box);
        box.append(h('section', { class: 'panel corners set-card' }, h('div', { class: 'label panel-title' }, icon('update'), ' PiOS-Anwendungsupdates (signierte Releases)'),
          ota ? h('div', {}, h('div', { class: 'upd-row' }, h('b', { class: 'mono' }, ota.installed.version), ota.available ? chip(`${ota.available.version} verfügbar`, 'limited') : chip('aktuell', 'ok'), chip(`Kanal ${ota.channel}`)),
            h('div', { class: 'hint' }, `Prüfung der Ed25519-Signatur mit fest hinterlegtem Schlüssel${ota.last_success ? ' · zuletzt erfolgreich ' + ago(ota.last_success) : ''}${ota.last_error ? ' · letzter Fehler: ' + ota.last_error : ''}`),
            Object.keys(ota.rejected || {}).length ? h('div', { class: 'upd-warn bad' }, icon('alert'), 'Abgelehnt wegen ungültiger Signatur: ' + Object.keys(ota.rejected).join(', ')) : null)
            : h('div', { class: 'hint' }, 'Update-Dienst nicht erreichbar.'),
          h('div', { class: 'upd-actions' }, button('Update Center öffnen', { icon: 'update', onclick: () => launch('updates') })),
          h('div', { class: 'hint' }, 'Ein PiOS-Rollback stellt nur die Anwendung (und ggf. ihre Datenbank) wieder her – nicht Linux, Kernel oder Systempakete.')));
        if (!os) { box.append(h('section', { class: 'panel corners' }, h('div', { class: 'label panel-title' }, ' Betriebssystem (Debian)'), h('div', { class: 'upd-warn' }, icon('alert'), osErr || 'nicht verfügbar'))); return; }
        const s = os.status || {}, lu = os.last_upgrade || {};
        box.append(h('section', { class: 'panel corners set-card' }, h('div', { class: 'label panel-title' }, icon('shield'), ' Betriebssystem-Sicherheitsupdates (Debian/APT)'),
          h('div', { class: 'upd-chips' }, s.checked_at ? chip('geprüft ' + ago(s.checked_at), '') : chip('noch nie geprüft', 'limited'),
            s.signature_ok === true ? chip('Paketsignaturen geprüft', 'ok') : s.signature_ok === false ? chip('Signaturprüfung FEHLGESCHLAGEN', 'critical') : chip('Signaturprüfung offen', 'unknown'),
            chip(s.security?.length ? `${s.security.length} Sicherheitsupdate(s)` : 'keine Sicherheitsupdates', s.security?.length ? 'limited' : 'ok'), os.reboot_required ? chip('Neustart erforderlich', 'critical') : null),
          s.error ? h('div', { class: 'upd-warn bad' }, icon('alert'), s.error) : null,
          ...(s.source_problems || []).map(p => h('div', { class: 'upd-warn bad' }, icon('alert'), p)),
          s.security?.length ? h('div', { class: 'hint mono' }, s.security.join(', ')) : null,
          s.upgradable?.length ? h('div', { class: 'hint' }, `${s.upgradable.length} Paketupdate(s) insgesamt (Kernel/Firmware werden nie automatisch installiert).`) : null,
          lu.time ? h('div', { class: lu.ok ? 'hint' : 'upd-warn bad' }, `Letzte automatische Installation ${ago(lu.time)}: ${lu.ok ? (lu.upgraded?.length ? lu.upgraded.join(', ') : 'nichts zu tun') : lu.error}`) : null,
          row('Sicherheitsupdates automatisch installieren', 'Täglich, nur Debian-Security (und Chromium); nie mit automatischem Neustart.', toggle(os.auto_security, v => guard(async () => { await api.put('shield/os/config', { auto_security: v }); toast(v ? 'Automatische Sicherheitsupdates an' : 'Automatische Sicherheitsupdates aus'); await load(); }), 'Automatisch')),
          h('div', { class: 'upd-actions' }, button(os.check_running ? 'Prüfung läuft …' : 'Jetzt prüfen', { icon: 'refresh', disabled: os.check_running || os.upgrade_running, onclick: () => guard(async () => { await api.post('shield/os/check'); toast('Prüfung gestartet'); setTimeout(load, 4000); }) }),
            button(os.upgrade_running ? 'Installation läuft …' : 'Sicherheitsupdates jetzt installieren', { icon: 'download', variant: 'primary', disabled: os.upgrade_running || os.check_running || !s.security?.length,
              onclick: async () => { if (await confirmDialog({ title: 'Sicherheitsupdates installieren?', confirm: 'Installieren', message: 'APT installiert die ausstehenden Debian-Sicherheitsupdates. Währenddessen sind keine anderen Paketoperationen (auch keine PiOS-Updates) möglich. Ein Neustart erfolgt nicht automatisch.' })) guard(async () => { await api.post('shield/os/upgrade'); toast('Installation gestartet'); setTimeout(load, 4000); }); } }))));
      }
      await load();
      every(5000, () => load().catch(() => {}));
    }

    // ---------------------------------------------------------------- audit log
    async function auditTab(el, live) {
      let sev = '', kind = '';
      const list = h('div', { class: 'list' }), integrity = h('div');
      const kindInput = h('input', { class: 'input', placeholder: 'Typ filtern, z. B. auth oder malware', maxlength: 40, 'aria-label': 'Typ', oninput: debounce(e => { kind = e.target.value.trim(); load(); }, 250) });
      el.append(h('section', { class: 'panel corners' }, h('div', { class: 'label panel-title' }, icon('history'), ' Sicherheitsprotokoll'), integrity,
        h('div', { class: 'toolbar' }, segmented([['', 'Alle'], ['notice', 'Notiz+'], ['warning', 'Warnung+'], ['critical', 'Kritisch']], '', v => { sev = v; load(); }), kindInput),
        list, h('div', { class: 'hint' }, 'Das Protokoll ist nur für Administratoren lesbar und kann über die Oberfläche weder geändert noch gelöscht werden. Einträge sind per Hash-Kette gegen nachträgliche Veränderung gesichert; Passwörter und Tokens werden nie gespeichert.')));
      async function load() {
        const q = new URLSearchParams({ limit: 300 }); if (kind) q.set('kind', kind);
        let r = await api.get('shield/audit?' + q, { quiet: true });
        if (!live()) return;
        let entries = r.entries;
        if (sev) { const order = ['info', 'notice', 'warning', 'critical']; entries = entries.filter(e => order.indexOf(e.severity) >= order.indexOf(sev)); }
        clear(integrity).append(r.integrity.ok ? chip(`Integrität geprüft: ${r.integrity.entries} Einträge, Kette intakt`, 'ok') : h('div', { class: 'upd-warn bad' }, icon('alert'), `Integritätsfehler ab Eintrag ${r.integrity.first_bad_id}: ${r.integrity.reason}`));
        clear(list).append(...(entries.length ? entries.map(auditRow) : [h('div', { class: 'hint' }, 'Keine Einträge.')]));
      }
      await load();
    }

    const views = { overview, firewall, malware: malwareTab, apps: appsTab, system: systemTab, audit: auditTab };
    win.setTitle('NOVA Shield');
    show(tab);
    return { destroy() { alive = false; stopTimers(); }, params: p => p?.tab && show(p.tab) };
  },
};
