// NOVA Files
import { h, clear, bytes, dateTime } from '../util.js';
import { icon } from '../icons.js';
import * as api from '../api.js';
import { button, meter, contextMenu, confirmDialog, promptDialog, customDialog, toast, errorToast } from '../ui.js';

const TEXT_EXT = /\.(txt|md|json|log|csv|ya?ml|ini|conf|py|js|ts|css|html?|xml|sh|toml|cfg)$/i;
const INLINE_MEDIA = /^(audio\/(mpeg|ogg|wav|flac)|video\/(mp4|webm))$/;
const join = (dir, name) => (dir ? dir + '/' : '') + name;
const parent = p => p.split('/').slice(0, -1).join('/');

export default {
  async mount(body, { win, params }) {
    let path = '', entries = [], sel = null, loadSeq = 0;
    const uploads = [];

    const crumbs = h('nav', { class: 'crumbs', 'aria-label': 'Pfad' });
    const list = h('div', { class: 'files-list list', role: 'listbox' });
    const preview = h('aside', { class: 'files-preview hidden' });
    const usageBar = meter(0), usageText = h('span', { class: 'hint' });
    const queue = h('div', { class: 'upload-queue' });
    const pendingBox = h('div', { class: 'upload-queue pending-scan' });
    let pendingTimer = null, pendingIds = '';
    const input = h('input', { type: 'file', multiple: true, class: 'hidden', onchange: () => { addUploads([...input.files]); input.value = ''; } });
    const upBtn = button('', { icon: 'up', title: 'Ordner nach oben', onclick: () => go(parent(path)), variant: 'ghost' });

    const toolbar = h('div', { class: 'toolbar' }, upBtn,
      button('', { icon: 'refresh', title: 'Aktualisieren', variant: 'ghost', onclick: () => refresh() }), crumbs, h('span', { class: 'spacer' }),
      button('Ordner', { icon: 'folderPlus', onclick: newFolder }), button('Hochladen', { icon: 'upload', variant: 'primary', onclick: () => input.click() }), input);
    const main = h('div', { class: 'files-main' }, list, preview);
    const footer = h('footer', { class: 'files-footer' }, pendingBox, queue, h('div', { class: 'usage' }, usageText, usageBar));
    body.append(h('div', { class: 'files-app' }, toolbar, main, footer));
    const root = body.firstChild;
    const ro = new ResizeObserver(() => root.classList.toggle('narrow', root.clientWidth < 620)); ro.observe(root);

    // ---- data ----
    async function refresh(select) {
      const my = ++loadSeq;
      try {
        const d = await api.get('files?' + api.q({ path }));
        if (my !== loadSeq) return;
        path = d.path; entries = d.entries;
        if (select !== undefined) sel = select;
        if (sel && !entries.some(e => e.name === sel)) sel = null;
        render(); loadUsage();
      } catch (e) {
        errorToast(e);
        if (path) { path = ''; refresh(); }
      }
    }
    async function loadUsage() {
      try {
        const u = await api.get('files/usage', { quiet: true });
        usageText.textContent = `${bytes(u.used)} belegt · ${bytes(u.disk_free)} frei von ${bytes(u.disk_total)}`;
        const pct = (u.disk_total - u.disk_free) / u.disk_total * 100;
        usageBar.set(pct, pct > 95 ? 'danger' : pct > 85 ? 'warn' : '');
      } catch { /* ignore */ }
    }
    const go = p => { path = p; sel = null; refresh(); };
    win.setTitle('NOVA Files');

    // ---- rendering ----
    function renderCrumbs() {
      clear(crumbs);
      const parts = path ? path.split('/') : [];
      const item = (label, target, ic) => {
        const b = h('button', { class: 'crumb', type: 'button', onclick: () => go(target) }, ic && icon(ic), label);
        setupDrop(b, target);
        return b;
      };
      crumbs.append(item('Meine Dateien', '', 'files'));
      parts.forEach((p, i) => crumbs.append(icon('chevronRight', 'crumb-sep'), item(p, parts.slice(0, i + 1).join('/'))));
      upBtn.disabled = !path;
    }
    function kindIcon(e) { return e.type === 'dir' ? 'files' : e.mime.startsWith('image/') ? 'image' : 'file'; }
    function render() {
      renderCrumbs();
      clear(list);
      if (!entries.length) list.append(h('div', { class: 'empty' }, icon('files'), h('span', {}, 'Dieser Ordner ist leer.'), h('span', { class: 'hint' }, 'Dateien hierher ziehen oder „Hochladen“ wählen.')));
      for (const e of entries) {
        const row = h('div', { class: 'row file-row' + (e.type === 'dir' ? ' is-dir' : ''), role: 'option', tabindex: '0', draggable: 'true', 'aria-selected': String(sel === e.name), dataset: { name: e.name },
          onclick: () => select(e.name), ondblclick: () => open(e),
          onkeydown: ev => { if (ev.key === 'Enter') open(e); else if (ev.key === 'Delete') remove(e); else if (ev.key === 'F2') rename(e); },
          oncontextmenu: ev => { ev.preventDefault(); select(e.name); menu(ev.clientX, ev.clientY, e); },
          ondragstart: ev => { ev.dataTransfer.setData('application/x-pios-path', join(path, e.name)); ev.dataTransfer.effectAllowed = 'move'; } },
          h('span', { class: 'f-icon ' + (e.type === 'dir' ? 'dir' : '') }, icon(kindIcon(e))),
          h('span', { class: 'f-name' }, e.name),
          h('span', { class: 'f-size mono' }, e.type === 'dir' ? '' : bytes(e.size)),
          h('span', { class: 'f-date' }, dateTime(e.mtime)),
          h('button', { class: 'btn ghost icon-only f-more', type: 'button', 'aria-label': 'Aktionen', onclick: ev => { ev.stopPropagation(); select(e.name); const r = ev.currentTarget.getBoundingClientRect(); menu(r.left - 150, r.bottom, e); } }, icon('more')));
        if (e.type === 'dir') setupDrop(row, join(path, e.name));
        list.append(row);
      }
      renderPreview();
    }
    function select(name) {
      sel = name;
      for (const r of list.children) r.setAttribute('aria-selected', String(r.dataset?.name === name));
      renderPreview();
    }
    function menu(x, y, e) {
      contextMenu(x, y, [
        { label: e.type === 'dir' ? 'Öffnen' : 'Vorschau', icon: 'eye', run: () => open(e) },
        e.type === 'file' && { label: 'Herunterladen', icon: 'download', run: () => download(e) },
        { label: 'Umbenennen', icon: 'edit', run: () => rename(e) },
        { label: 'Verschieben …', icon: 'move', run: () => moveTo(e) },
        '-', { label: 'Löschen', icon: 'trash', danger: true, run: () => remove(e) },
      ].filter(Boolean));
    }
    function renderPreview() {
      const e = entries.find(x => x.name === sel);
      preview.classList.toggle('hidden', !e);
      root.classList.toggle('has-preview', !!e);
      if (!e) return;
      clear(preview);
      const p = join(path, e.name);
      let content;
      if (e.type === 'dir') content = h('div', { class: 'pv-big' }, icon('files'));
      else if (e.mime.startsWith('image/') && e.mime !== 'image/svg+xml') content = h('img', { class: 'pv-img', alt: e.name, src: api.fileUrl(p, true) });
      else if (INLINE_MEDIA.test(e.mime)) content = h(e.mime.startsWith('audio') ? 'audio' : 'video', { class: 'pv-img', controls: true, src: api.fileUrl(p, true) });
      else if (e.mime.startsWith('text/') || TEXT_EXT.test(e.name)) {
        content = h('pre', { class: 'pv-text mono' }, 'Lade …');
        if (e.size > 512 * 1024) content.textContent = 'Datei zu groß für die Vorschau.';
        else fetch(api.fileUrl(p), { credentials: 'same-origin' }).then(r => r.text()).then(t => { content.textContent = t.slice(0, 100000); }).catch(() => { content.textContent = 'Vorschau nicht verfügbar.'; });
      } else content = h('div', { class: 'pv-big' }, icon('file'));
      preview.append(
        h('div', { class: 'pv-head' }, h('b', { class: 'pv-name' }, e.name), button('', { icon: 'close', variant: 'ghost', title: 'Vorschau schließen', onclick: () => { sel = null; select(null); } })),
        h('div', { class: 'pv-content' }, content),
        h('dl', { class: 'pv-meta' }, h('dt', {}, 'Typ'), h('dd', {}, e.type === 'dir' ? 'Ordner' : e.mime), e.type === 'file' && [h('dt', {}, 'Größe'), h('dd', {}, bytes(e.size))], h('dt', {}, 'Geändert'), h('dd', {}, dateTime(e.mtime))),
        h('div', { class: 'pv-actions' }, e.type === 'file' && button('Herunterladen', { icon: 'download', onclick: () => download(e) }), button('Umbenennen', { icon: 'edit', onclick: () => rename(e) }), button('Löschen', { icon: 'trash', variant: 'danger', onclick: () => remove(e) })));
    }

    // ---- actions ----
    const open = e => (e.type === 'dir' ? go(join(path, e.name)) : select(e.name));
    function download(e) { const a = h('a', { href: api.fileUrl(join(path, e.name)), download: e.name }); document.body.append(a); a.click(); a.remove(); }
    async function newFolder() {
      const name = await promptDialog({ title: 'Neuer Ordner', label: 'Name', confirm: 'Erstellen', validate: v => (!v ? 'Bitte einen Namen eingeben' : /[\/\\]/.test(v) ? 'Kein / oder \\ im Namen' : '') });
      if (!name) return;
      try { await api.post('files/mkdir', { path, name }); refresh(name); } catch (e) { errorToast(e); }
    }
    async function rename(e) {
      const name = await promptDialog({ title: 'Umbenennen', label: 'Neuer Name', value: e.name, confirm: 'Umbenennen', validate: v => (!v ? 'Bitte einen Namen eingeben' : /[\/\\]/.test(v) ? 'Kein / oder \\ im Namen' : '') });
      if (!name || name === e.name) return;
      try { await api.post('files/rename', { path: join(path, e.name), new_name: name }); refresh(name); } catch (x) { errorToast(x); }
    }
    async function remove(e) {
      const ok = await confirmDialog({ title: `„${e.name}“ löschen?`, message: e.type === 'dir' ? 'Der Ordner und sein gesamter Inhalt werden unwiderruflich gelöscht.' : 'Die Datei wird unwiderruflich gelöscht.', confirm: 'Löschen', danger: true });
      if (!ok) return;
      try { await api.del('files?' + api.q({ path: join(path, e.name) })); sel = null; refresh(); } catch (x) { errorToast(x); }
    }
    async function moveItem(from, dest) {
      const name = from.split('/').pop();
      if (parent(from) === dest) return;
      try { await api.post('files/move', { path: from, dest }); toast('Verschoben', `${name} → ${dest || 'Meine Dateien'}`); refresh(); } catch (x) { errorToast(x); }
    }
    function moveTo(e) {
      const from = join(path, e.name);
      customDialog(`„${e.name}“ verschieben`, (box, close) => {
        let cur = '';
        const lbl = h('div', { class: 'hint' }), dirs = h('div', { class: 'list move-list' });
        const ok = button('Hierher verschieben', { variant: 'primary', onclick: () => { close(); moveItem(from, cur); } });
        async function show(p) {
          const d = await api.get('files?' + api.q({ path: p }), { quiet: true });
          cur = d.path; lbl.textContent = 'Ziel: ' + (cur || 'Meine Dateien');
          clear(dirs);
          if (cur) dirs.append(h('button', { class: 'row', type: 'button', onclick: () => show(parent(cur)) }, icon('up'), '..'));
          for (const x of d.entries.filter(x => x.type === 'dir' && join(cur, x.name) !== from)) dirs.append(h('button', { class: 'row', type: 'button', onclick: () => show(join(cur, x.name)) }, icon('files'), x.name));
        }
        box.append(lbl, dirs, h('div', { class: 'actions' }, button('Abbrechen', { onclick: () => close() }), ok));
        show(path).catch(errorToast);
      });
    }
    function setupDrop(el, destPath) {
      el.addEventListener('dragover', ev => {
        const t = ev.dataTransfer.types;
        if (t.includes('application/x-pios-path') || t.includes('Files')) { ev.preventDefault(); ev.stopPropagation(); el.classList.add('drop'); }
      });
      el.addEventListener('dragleave', () => el.classList.remove('drop'));
      el.addEventListener('drop', ev => {
        ev.preventDefault(); ev.stopPropagation(); el.classList.remove('drop');
        const from = ev.dataTransfer.getData('application/x-pios-path');
        if (from) { if (from !== destPath) moveItem(from, destPath); }
        else addUploads([...ev.dataTransfer.files], destPath);
      });
    }
    // ---- uploads ----
    function addUploads(files, dest = path) {
      for (const f of files) {
        const bar = meter(0);
        const item = h('div', { class: 'up-item' }, h('span', { class: 'up-name' }, f.name), bar);
        queue.append(item);
        uploads.push((async () => {
          try { const res = await api.upload(dest, f, p => bar.set(p * 100)); bar.set(100); scanResult(f.name, res); }
          catch (e) { toast(`Upload fehlgeschlagen: ${f.name}`, e.message, 'error', 7000); }
          finally { setTimeout(() => item.remove(), 600); }
        })());
      }
      Promise.allSettled(uploads.splice(0)).then(() => { refresh(); });
    }
    // the list itself accepts OS file drops into the current folder
    list.addEventListener('dragover', ev => { if (ev.dataTransfer.types.includes('Files')) ev.preventDefault(); });
    list.addEventListener('drop', ev => { if (ev.target === list || ev.target.closest('.empty')) { ev.preventDefault(); addUploads([...ev.dataTransfer.files]); } });

    // ---- virus-scan feedback: uploads are quarantined and released only after a clean verdict ----
    function scanResult(name, r) {
      const st = r?.status;
      if (!st || st === 'released') return;
      if (st === 'pending' || st === 'held' || st === 'scanning') { toast(`„${name}“ wird geprüft`, 'Die Datei erscheint, sobald der Virenscan abgeschlossen ist.'); pollPending(); }
      else if (st === 'infected') toast('Schadsoftware erkannt', `„${name}“: ${r.detection || ''}. Die Datei wurde gesperrt.`, 'error', 9000);
      else if (st === 'blocked') toast('Datei blockiert', `„${name}“: ${r.reason}`, 'error', 9000);
      else if (st === 'error') toast('Prüfung fehlgeschlagen', `„${name}“ bleibt gesperrt: ${r.reason}`, 'warn', 9000);
      else if (st.startsWith('released_unscanned')) toast('Ohne Virenprüfung gespeichert', `„${name}“ wurde NICHT geprüft (Virenschutz deaktiviert oder Scanner nicht verfügbar).`, 'warn', 9000);
    }
    async function pollPending() {
      clearTimeout(pendingTimer);
      let items = [];
      try { items = await api.get('files/pending', { quiet: true }); } catch { return; }
      const waiting = items.filter(i => ['pending', 'held', 'scanning'].includes(i.state));
      clear(pendingBox);
      for (const i of items) pendingBox.append(h('div', { class: 'up-item' }, h('span', { class: 'up-name' }, `${i.name} – ${({ pending: 'wartet auf Virenscan', held: 'gesperrt: Scanner nicht bereit', scanning: 'wird geprüft', infected: 'MALWARE – gesperrt', blocked: 'blockiert', error: 'Prüfung fehlgeschlagen' })[i.state] || i.state}`),
        h('span', { class: 'chip ' + (['infected', 'blocked', 'error'].includes(i.state) ? 'critical' : 'limited') }, i.state === 'infected' ? 'gesperrt' : '…')));
      const key = waiting.map(i => i.id).join(',');
      if (pendingIds && key !== pendingIds) refresh();          // something was released meanwhile
      pendingIds = key;
      if (waiting.length) pendingTimer = setTimeout(pollPending, 2500);
    }

    await refresh();
    pollPending();
    return { destroy() { ro.disconnect(); clearTimeout(pendingTimer); } };
  },
};
