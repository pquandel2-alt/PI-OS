// NOVA Notes: SQLite-backed notes with search and autosave.
import { h, clear, debounce, ago } from '../util.js';
import { icon } from '../icons.js';
import * as api from '../api.js';
import { button, confirmDialog, errorToast } from '../ui.js';

export default {
  async mount(body, { win, params }) {
    let notes = [], cur = null, term = '', status = 'saved', seq = 0;
    const search = h('input', { class: 'input', type: 'search', placeholder: 'Notizen suchen …', 'aria-label': 'Notizen suchen', maxlength: 100 });
    const list = h('div', { class: 'notes-list list', role: 'listbox' });
    const title = h('input', { class: 'input note-title', placeholder: 'Titel', 'aria-label': 'Titel', maxlength: 150 });
    const text = h('textarea', { class: 'textarea note-body', placeholder: 'Schreibe etwas …', 'aria-label': 'Inhalt', maxlength: 200000 });
    const stat = h('span', { class: 'hint note-status' });
    const back = button('', { icon: 'chevronLeft', title: 'Zur Liste', variant: 'ghost', onclick: () => root.classList.remove('editing') });
    const del = button('', { icon: 'trash', title: 'Notiz löschen', variant: 'ghost', onclick: remove });
    const editor = h('section', { class: 'note-editor' }, h('div', { class: 'toolbar' }, back, stat, h('span', { class: 'spacer' }), del), h('div', { class: 'note-fields' }, title, text));
    const side = h('aside', { class: 'notes-side' }, h('div', { class: 'toolbar' }, search, button('', { icon: 'plus', variant: 'primary', title: 'Neue Notiz', onclick: create })), list);
    const root = h('div', { class: 'notes-app' }, side, editor);
    body.append(root);

    const setStatus = s => { status = s; stat.textContent = s === 'saving' ? 'Speichert …' : s === 'dirty' ? 'Ungespeichert' : s === 'error' ? 'Speichern fehlgeschlagen' : cur ? 'Gespeichert · ' + ago(cur.updated) : ''; stat.classList.toggle('bad', s === 'error'); };

    async function load(select) {
      const my = ++seq;
      try {
        const r = await api.get('notes?' + api.q({ q: term }), { quiet: true });
        if (my !== seq) return;
        notes = r;
        if (select != null) cur = notes.find(n => n.id === select) || cur;
        renderList(); renderEditor();
      } catch (e) { errorToast(e); }
    }
    function renderList() {
      clear(list);
      if (!notes.length) list.append(h('div', { class: 'empty' }, icon('notes'), term ? 'Keine Treffer' : 'Noch keine Notizen'));
      for (const n of notes) {
        list.append(h('button', { class: 'row note-row', type: 'button', role: 'option', 'aria-selected': String(cur?.id === n.id), onclick: () => choose(n) },
          h('span', { class: 'n-text' }, h('b', {}, n.title || 'Ohne Titel'), h('small', {}, (n.body.replace(/\s+/g, ' ').slice(0, 60)) || 'Leer')), h('small', { class: 'hint' }, ago(n.updated))));
      }
    }
    function renderEditor() {
      editor.classList.toggle('none', !cur);
      if (!cur) return;
      if (document.activeElement !== title) title.value = cur.title;
      if (document.activeElement !== text) text.value = cur.body;
      setStatus(status === 'dirty' ? 'dirty' : 'saved');
    }
    async function choose(n) {
      await flushNow();
      cur = notes.find(x => x.id === n.id) || n;
      title.value = cur.title; text.value = cur.body;
      root.classList.add('editing'); renderList(); setStatus('saved');
      if (matchMedia('(min-width: 600px)').matches) text.focus();
    }
    async function create() {
      await flushNow();
      try {
        const { id } = await api.post('notes', { title: 'Neue Notiz', body: '' });
        term = ''; search.value = '';
        await load(id); root.classList.add('editing'); title.focus(); title.select();
      } catch (e) { errorToast(e); }
    }
    async function remove() {
      if (!cur) return;
      if (!await confirmDialog({ title: 'Notiz löschen?', message: `„${cur.title || 'Ohne Titel'}“ wird unwiderruflich gelöscht.`, confirm: 'Löschen', danger: true })) return;
      save.cancel(); const id = cur.id; cur = null;
      try { await api.del('notes/' + id); } catch (e) { errorToast(e); }
      root.classList.remove('editing'); load();
    }

    // autosave: 700 ms after the last keystroke, plus on blur/close
    let saving = null;
    const doSave = async () => {
      if (!cur) return;
      const n = cur, t = title.value, b = text.value;
      setStatus('saving');
      try {
        saving = api.put('notes/' + n.id, { title: t, body: b }, { quiet: false });
        await saving;
        n.title = t; n.body = b; n.updated = Math.floor(Date.now() / 1000);
        if (cur === n && title.value === t && text.value === b) setStatus('saved'); else setStatus('dirty');
        renderList();
      } catch (e) { setStatus('error'); errorToast(e); }
      finally { saving = null; }
    };
    const save = debounce(doSave, 700);
    async function flushNow() { if (status === 'dirty') { save.cancel(); await doSave(); } else if (saving) await saving.catch(() => {}); }
    const dirty = () => { setStatus('dirty'); save(); };
    title.addEventListener('input', dirty); text.addEventListener('input', dirty);
    title.addEventListener('blur', flushNow); text.addEventListener('blur', flushNow);
    search.addEventListener('input', debounce(async () => { term = search.value.trim(); await load(); }, 200));
    win.on('close', () => { if (status === 'dirty') { save.cancel(); doSave(); } });

    await load();
    const want = params?.note;
    if (want != null) { cur = notes.find(n => n.id === want) || null; if (cur) { root.classList.add('editing'); renderList(); renderEditor(); } }
    else if (notes.length && matchMedia('(min-width: 600px)').matches) { cur = notes[0]; renderList(); renderEditor(); }
    return {
      params: p => { if (p?.note != null) { cur = notes.find(n => n.id === p.note) || cur; root.classList.add('editing'); renderList(); renderEditor(); } },
    };
  },
};
