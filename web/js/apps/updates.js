// NOVA Update Center: version, channel, release notes, live install progress, history, rollback.
import { h, clear, bytes, dateTime, ago, mdLite } from '../util.js';
import { icon } from '../icons.js';
import * as api from '../api.js';
import { state } from '../store.js';
import { button, toggle, segmented, confirmDialog, customDialog, toast, errorToast, meter } from '../ui.js';

const RESULT = {
  success: ['check', 'Installiert', 'ok'],
  rolled_back: ['rollback', 'Zurückgesetzt', 'warn'],
  rollback_manual: ['rollback', 'Zurückgewechselt', 'ok'],
  failed: ['alert', 'Fehlgeschlagen', 'danger'],
  failed_critical: ['alert', 'Kritisch', 'danger'],
};
const RUNNING = ['running', 'rolling_back'];

export default {
  mount(body, { win, launch }) {
    let st = null, unavailable = false, connected = false, busy = false, health = null, es = null, lastJobId = null;

    const root = h('div', { class: 'upd-app' });
    body.append(root);

    // ---------- data ----------
    async function loadHealth() {
      try { health = await (await fetch('/healthz', { cache: 'no-store' })).json(); } catch { health = null; }
      render();
    }
    function connect() {
      es = new EventSource('/api/updates/stream');
      es.addEventListener('status', e => {
        connected = true; unavailable = false;
        const prev = st; st = JSON.parse(e.data);
        const j = st.job;
        if (prev?.job?.state === 'running' && j && !RUNNING.includes(j.state) && j.id === prev.job.id) loadHealth();
        render();
      });
      es.addEventListener('unavailable', () => { unavailable = true; render(); });
      es.onerror = () => { connected = false; render(); };
    }
    const act = async (fn, okMsg) => {
      busy = true; render();
      try { const r = await fn(); if (r) st = r; if (okMsg) toast(okMsg); }
      catch (e) { errorToast(e); }
      finally { busy = false; render(); }
    };

    // ---------- pieces ----------
    const chip = (text, cls = '', ic) => h('span', { class: 'chip ' + cls }, ic && icon(ic), text);

    function heroCard() {
      const inst = st.installed;
      return h('section', { class: 'panel corners upd-hero' },
        h('div', { class: 'upd-ver' }, h('div', { class: 'label' }, 'Installierte Version'), h('div', { class: 'upd-ver-num mono' }, inst.version || '–'),
          h('div', { class: 'hint' }, st.last_check ? `Zuletzt geprüft ${ago(st.last_check)}` : 'Noch nie geprüft')),
        h('div', { class: 'upd-facts' },
          h('div', {}, h('span', { class: 'label' }, 'Kanal'), h('div', { class: 'upd-channel' }, segmented([['stable', 'Stable'], ['beta', 'Beta']], st.channel, chooseChannel))),
          h('div', {}, h('span', { class: 'label' }, 'Systemgesundheit'), healthChips()),
          h('div', {}, h('span', { class: 'label' }, 'Automatische Prüfung'), h('div', { class: 'upd-row' }, toggle(st.auto_check, v => act(() => api.put('updates/config', { auto_check: v })), 'Automatisch prüfen'), h('span', { class: 'hint' }, 'täglich')))),
        h('div', { class: 'upd-actions' }, button(busy ? 'Prüfe …' : 'Jetzt nach Updates suchen', { icon: 'refresh', disabled: busy || isRunning(), onclick: () => act(() => api.post('updates/check'), null) })));
    }
    function healthChips() {
      if (!health) return h('div', { class: 'hint' }, 'wird geladen …');
      const c = health.checks || {};
      return h('div', { class: 'upd-chips' }, chip('Dienst', health.ok ? 'ok' : 'danger', health.ok ? 'check' : 'alert'), chip('Datenbank', c.db ? 'ok' : 'danger', c.db ? 'check' : 'alert'),
        chip('Apps', c.apps ? 'ok' : 'danger', c.apps ? 'check' : 'alert'), chip('Schema ' + (health.schema ?? '?'), ''));
    }
    async function chooseChannel(v) {
      if (v === st.channel) return;
      const msg = v === 'beta'
        ? 'Der Beta-Kanal liefert neue, noch nicht auf echter Hardware validierte Versionen. Sie können Fehler enthalten.'
        : 'Es werden nur noch freigegebene Versionen angeboten. Eine bereits installierte Beta-Version wird dadurch NICHT automatisch zurückgestuft.';
      if (await confirmDialog({ title: `Kanal auf „${v === 'beta' ? 'Beta' : 'Stable'}“ wechseln?`, message: msg, confirm: 'Wechseln' })) {
        await act(() => api.put('updates/config', { channel: v }));
        act(() => api.post('updates/check'));
      } else render();
    }

    function availableCard() {
      const a = st.available, failed = a && st.failed_versions?.[a.version];
      if (!a) {
        return h('section', { class: 'panel corners upd-card upd-ok' }, icon('check'),
          h('div', {}, h('b', {}, 'PiOS ist auf dem neuesten Stand'),
            st.last_error ? h('div', { class: 'upd-warn' }, icon('alert'), `Letzte Prüfung fehlgeschlagen: ${st.last_error}. Angezeigt wird der letzte bekannte Stand.`)
              : h('div', { class: 'hint' }, st.channel === 'stable' ? 'Im Stable-Kanal ist nichts Neueres verfügbar.' : 'Im Beta-Kanal ist nichts Neueres verfügbar.')));
      }
      const snoozed = st.snoozed_until > Date.now() / 1000;
      return h('section', { class: 'panel corners upd-card upd-new' },
        h('div', { class: 'upd-new-head' }, h('div', { class: 'upd-badge' }, icon('update')),
          h('div', {}, h('div', { class: 'label' }, 'Update verfügbar'), h('h2', { class: 'upd-title' }, `PiOS NOVA ${a.version} verfügbar`),
            h('div', { class: 'upd-meta' }, chip(a.channel === 'beta' || a.prerelease ? 'Beta' : 'Stable', a.channel === 'beta' ? 'warn' : 'ok'), chip(`${bytes(a.size)} Download`), chip(a.released ? dateTime(Date.parse(a.released) / 1000) : '', '', 'clock')))),
        a.highlights?.length ? h('div', {}, h('div', { class: 'label' }, 'Neue Funktionen'), h('ul', { class: 'md-list' }, ...a.highlights.map(x => h('li', {}, x)))) : null,
        a.notes ? h('div', { class: 'upd-notes' }, ...mdLite(a.notes).slice(0, 8)) : null,
        a.channel === 'beta' || a.prerelease ? h('div', { class: 'upd-warn' }, icon('alert'), 'Beta-Version: noch nicht auf echter Raspberry-Pi-Hardware validiert. Ein automatisches Rollback ist eingerichtet.') : null,
        failed ? h('div', { class: 'upd-warn bad' }, icon('alert'), `Diese Version ist auf diesem Gerät bereits fehlgeschlagen (${failed.reason}).`) : null,
        !a.compatible ? h('div', { class: 'upd-warn bad' }, icon('alert'), 'Nicht installierbar: ' + a.problems.join('; ')) : null,
        h('div', { class: 'upd-actions' },
          button(failed ? 'Erneut versuchen' : 'Jetzt installieren', { icon: 'download', variant: 'primary', disabled: !a.compatible || busy || isRunning(), onclick: () => install(a) }),
          button(snoozed ? 'Erinnerung aktiv' : 'Später erinnern', { icon: 'clock', disabled: snoozed || busy, onclick: () => act(() => api.post('updates/snooze', { version: a.version, hours: 24 }), 'Ich erinnere dich in 24 Stunden.') }),
          button('Release Notes anzeigen', { icon: 'file', variant: 'ghost', onclick: () => notesDialog(a) })));
    }
    async function install(a) {
      const ok = await confirmDialog({ title: `PiOS NOVA ${a.version} installieren?`, confirm: 'Jetzt installieren',
        message: 'Vor der Installation wird automatisch ein Backup erstellt. Der PiOS-Dienst wird kurz neu gestartet; die Oberfläche lädt danach selbst neu. Schlägt die Systemprüfung fehl, wird automatisch die bisherige Version wiederhergestellt. Deine Dateien bleiben unberührt. Das Update läuft auch weiter, wenn du den Browser schließt.' });
      if (ok) act(() => api.post('updates/install', { version: a.version }));
    }
    function notesDialog(a) {
      customDialog(`Release Notes ${a.version}`, (box, close) => {
        box.append(h('div', { class: 'upd-notes full' }, ...(mdLite(a.notes).length ? mdLite(a.notes) : [h('p', { class: 'hint' }, 'Keine Release Notes angegeben.')])),
          h('div', { class: 'actions' }, button('Schließen', { variant: 'primary', onclick: () => close() })));
      });
    }

    const isRunning = () => !!st?.job && RUNNING.includes(st.job.state);
    function progressCard() {
      const j = st.job;
      if (!j) return null;
      const running = RUNNING.includes(j.state);
      const finished = !running;
      if (finished && lastJobId === j.id && j.dismissed) return null;
      const title = running ? (j.kind === 'rollback' ? 'Rollback läuft …' : `Update auf ${j.to} läuft …`)
        : j.state === 'success' ? (j.kind === 'rollback' ? 'Zurückgewechselt' : 'Update erfolgreich abgeschlossen')
          : j.state === 'rolled_back' ? 'Update fehlgeschlagen – vorherige Version wiederhergestellt'
            : j.state === 'failed_critical' ? 'Update UND Rollback fehlgeschlagen' : 'Update fehlgeschlagen';
      const cls = running ? 'run' : j.state === 'success' ? 'ok' : j.state === 'rolled_back' ? 'warn' : 'bad';
      const steps = j.steps.map(s => {
        const pct = s.percent;
        return h('li', { class: 'upd-step ' + s.status }, h('span', { class: 'upd-dot' }, s.status === 'done' ? icon('check') : s.status === 'error' ? icon('close') : null),
          h('div', { class: 'upd-step-body' }, h('span', {}, s.label),
            s.status === 'running' ? (pct != null ? meter(pct) : h('div', { class: 'meter indeterminate' }, h('i'))) : null),
          s.status === 'running' && pct != null ? h('span', { class: 'mono hint' }, pct + ' %') : null);
      });
      return h('section', { class: 'panel corners upd-card upd-progress ' + cls },
        h('div', { class: 'upd-prog-head' }, h('b', {}, title), running && !connected ? chip('Verbindung wird wiederhergestellt …', 'warn') : null),
        h('ol', { class: 'upd-steps' }, ...steps),
        j.error ? h('div', { class: 'upd-warn bad' }, icon('alert'), j.error) : null,
        j.state === 'success' && j.kind !== 'rollback' ? h('div', { class: 'hint' }, 'Die Oberfläche lädt in wenigen Sekunden automatisch neu.') : null,
        h('details', { class: 'upd-log' }, h('summary', {}, 'Technische Details'), h('pre', { class: 'mono' }, (j.log || []).join('\n') || '–')));
    }

    function historyCard() {
      const rows = (st.history || []).map(e => {
        const [ic, label, cls] = RESULT[e.result] || ['info', e.result, ''];
        return h('div', { class: 'row upd-hist' }, h('span', { class: 'upd-hist-ic ' + cls }, icon(ic)),
          h('div', { class: 'set-text' }, h('b', {}, `${e.from ? e.from + ' → ' : ''}${e.version}`), e.error ? h('div', { class: 'hint' }, e.error) : null),
          chip(label, cls), h('span', { class: 'hint' }, dateTime(e.time)));
      });
      return h('section', { class: 'panel corners upd-card' }, h('div', { class: 'label panel-title' }, icon('history'), ' Update-Verlauf'),
        rows.length ? h('div', { class: 'list' }, ...rows) : h('div', { class: 'hint' }, 'Noch keine Updates installiert.'),
        st.previous ? h('div', { class: 'upd-actions' }, button(`Zur vorherigen Version ${st.previous.version} zurück`, { icon: 'rollback', variant: 'danger', disabled: busy || isRunning(), onclick: rollback })) : null);
    }
    async function rollback() {
      const prev = st.previous;
      const ok = await confirmDialog({ title: `Zu PiOS ${prev.version} zurückwechseln?`, danger: true, confirm: 'Zurückwechseln',
        message: 'Das ist ein Anwendungs-Rollback: Nur PiOS selbst wird zurückgesetzt, nicht Linux, Kernel oder Systempakete. Vorher wird ein Backup erstellt. Deine Dateien bleiben unberührt.' });
      if (!ok) return;
      busy = true; render();
      try { st = await api.post('updates/rollback', { restore_backup: false }); }
      catch (e) {
        if (e.status === 409 && /Backup/.test(e.message)) {
          if (await confirmDialog({ title: 'Datenbank-Backup wiederherstellen?', danger: true, confirm: 'Backup wiederherstellen', message: e.message })) {
            try { st = await api.post('updates/rollback', { restore_backup: true }); } catch (x) { errorToast(x); }
          }
        } else errorToast(e);
      } finally { busy = false; render(); }
    }

    // ---------- render ----------
    function render() {
      clear(root);
      if (unavailable) {
        root.append(h('div', { class: 'empty' }, icon('alert'), h('b', {}, 'Update-Dienst nicht erreichbar'),
          h('span', {}, 'Das Update Center ist nur im PiOS-Image aktiv (Dienst pios-updater). In einer Entwicklungsumgebung gibt es keine Updates.'),
          h('span', { class: 'hint' }, 'PiOS selbst läuft normal weiter.')));
        return;
      }
      if (!st) { root.append(h('div', { class: 'empty' }, h('div', { class: 'spinner' }), connected ? '' : 'Verbinde …')); return; }
      root.append(h('div', { class: 'upd-scroll' }, heroCard(), progressCard(), isRunning() ? null : availableCard(), historyCard()));
    }

    win.setTitle('NOVA Updates');
    render(); loadHealth(); connect();
    return { destroy() { es?.close(); } };
  },
};
