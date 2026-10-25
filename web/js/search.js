// App launcher + global search (apps and notes). Opens with Ctrl+K or the dock grid button.
import { h, clear, debounce } from './util.js';
import { icon } from './icons.js';
import * as api from './api.js';

export function createLauncher({ apps, launch }) {
  const input = h('input', { class: 'input launcher-input', type: 'search', placeholder: 'Apps und Notizen durchsuchen …', 'aria-label': 'Suche', autocomplete: 'off', maxlength: 100 });
  const results = h('div', { class: 'launcher-results', role: 'listbox' });
  const el = h('div', { class: 'launcher hidden', onpointerdown: e => e.target === el && close() },
    h('div', { class: 'launcher-box panel corners' }, h('div', { class: 'launcher-search' }, icon('search'), input), results));
  let items = [], idx = 0, seq = 0;

  const run = it => { close(); it.run(); };
  const render = () => {
    clear(results);
    if (!items.length) { results.append(h('div', { class: 'empty' }, 'Keine Treffer')); return; }
    items.forEach((it, i) => results.append(h('button', { class: 'launcher-item', role: 'option', 'aria-selected': String(i === idx), type: 'button', onclick: () => run(it), onmousemove: () => { if (idx !== i) { idx = i; mark(); } } },
      h('span', { class: 'li-icon' }, icon(it.icon)), h('span', { class: 'li-text' }, h('b', {}, it.title), it.sub && h('small', {}, it.sub)), h('span', { class: 'li-kind' }, it.kind))));
  };
  const mark = () => [...results.children].forEach((c, i) => { c.setAttribute('aria-selected', String(i === idx)); if (i === idx) c.scrollIntoView({ block: 'nearest' }); });

  const search = debounce(async () => {
    const term = input.value.trim().toLowerCase(), my = ++seq;
    const appItems = apps().filter(a => !term || (a.name + ' ' + a.description).toLowerCase().includes(term))
      .map(a => ({ kind: 'App', icon: a.icon, title: a.name, sub: a.description, run: () => launch(a.id) }));
    items = appItems; idx = 0; render();
    if (term.length >= 2) {
      try {
        const notes = await api.get('notes?' + api.q({ q: term }), { quiet: true });
        if (my !== seq) return;
        items = [...appItems, ...notes.slice(0, 6).map(n => ({ kind: 'Notiz', icon: 'notes', title: n.title || 'Ohne Titel', sub: n.body.slice(0, 70), run: () => launch('notes', { note: n.id }) }))];
        render();
      } catch { /* ignore */ }
    }
  }, 120);

  input.addEventListener('input', search);
  input.addEventListener('keydown', e => {
    if (e.key === 'ArrowDown') { e.preventDefault(); idx = Math.min(idx + 1, items.length - 1); mark(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); idx = Math.max(idx - 1, 0); mark(); }
    else if (e.key === 'Enter' && items[idx]) run(items[idx]);
    else if (e.key === 'Escape') close();
  });

  function open() { el.classList.remove('hidden'); input.value = ''; search(); input.focus(); }
  function close() { el.classList.add('hidden'); }
  const toggle = () => (el.classList.contains('hidden') ? open() : close());
  document.addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); toggle(); }
    else if (e.key === 'Escape' && !el.classList.contains('hidden')) close();
  });
  return { el, open, close, toggle };
}
