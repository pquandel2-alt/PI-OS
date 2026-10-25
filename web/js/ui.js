// NOVA UI kit: dialogs, menus, toasts and small data-visualisation widgets.
import { h, append, clear } from './util.js';
import { icon } from './icons.js';

const modalRoot = () => document.getElementById('modal-root');

export function button(label, { icon: ic, variant = '', onclick, title, disabled } = {}) {
  return h('button', { type: 'button', class: 'btn ' + variant + (label ? '' : ' icon-only'), onclick, title, 'aria-label': title || label || null, disabled },
    ic && icon(ic), label);
}
export function field(label, input, hint) {
  return h('label', { class: 'field' }, h('span', { class: 'label' }, label), input, hint && h('span', { class: 'hint' }, hint));
}
export function toggle(checked, onchange, label) {
  const i = h('input', { type: 'checkbox', role: 'switch', 'aria-label': label || null, onchange: e => onchange(e.target.checked) });
  i.checked = !!checked;
  return h('span', { class: 'switch' }, i, h('span', { class: 'track' }));
}
export function segmented(options, value, onchange) {
  const wrap = h('div', { class: 'seg', role: 'group' });
  const render = v => {
    clear(wrap);
    for (const [val, label] of options) {
      wrap.append(h('button', { type: 'button', 'aria-pressed': String(val === v), onclick: () => { render(val); onchange(val); } }, label));
    }
  };
  render(value);
  return wrap;
}
export function meter(percent, level) {
  const bar = h('i');
  const m = h('div', { class: 'meter', role: 'progressbar', 'aria-valuemin': 0, 'aria-valuemax': 100 }, bar);
  m.set = (p, lvl = '') => {
    bar.style.width = Math.max(0, Math.min(100, p)) + '%';
    m.className = 'meter ' + lvl;
    m.setAttribute('aria-valuenow', Math.round(p));
  };
  m.set(percent, level);
  return m;
}

// ---- modal dialogs ------------------------------------------------------------
function modal(build) {
  return new Promise(resolve => {
    const prev = document.activeElement;
    const close = v => { backdrop.remove(); document.removeEventListener('keydown', onKey, true); prev?.focus?.(); resolve(v); };
    const box = h('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true' });
    const backdrop = h('div', { class: 'modal-backdrop', onmousedown: e => e.target === backdrop && close(null) }, box);
    const onKey = e => {
      if (e.key === 'Escape') { e.stopPropagation(); close(null); }
      if (e.key === 'Tab') { // keep focus inside the dialog
        const f = [...box.querySelectorAll('button,input,select,textarea,[tabindex]')].filter(x => !x.disabled);
        if (!f.length) return;
        const first = f[0], last = f[f.length - 1];
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
      }
    };
    document.addEventListener('keydown', onKey, true);
    build(box, close);
    modalRoot().append(backdrop);
    (box.querySelector('[autofocus]') || box.querySelector('input,textarea,button.primary,button'))?.focus();
  });
}

export function confirmDialog({ title, message, confirm = 'OK', danger = false }) {
  return modal((box, close) => append(box,
    h('h2', {}, title), h('p', {}, message),
    h('div', { class: 'actions' }, button('Abbrechen', { onclick: () => close(false) }),
      button(confirm, { variant: danger ? 'danger' : 'primary', onclick: () => close(true) }))));
}
export function promptDialog({ title, label, value = '', confirm = 'OK', validate }) {
  return modal((box, close) => {
    const input = h('input', { class: 'input', value, autofocus: true, maxlength: 255 });
    const err = h('div', { class: 'error-text' });
    const submit = () => {
      const v = input.value.trim();
      const bad = validate?.(v);
      if (bad) { err.textContent = bad; return; }
      close(v);
    };
    input.addEventListener('keydown', e => e.key === 'Enter' && submit());
    append(box, h('h2', {}, title), field(label, input), err,
      h('div', { class: 'actions' }, button('Abbrechen', { onclick: () => close(null) }), button(confirm, { variant: 'primary', onclick: submit })));
    queueMicrotask(() => { input.focus(); input.select(); });
  });
}
export function customDialog(title, build) {
  return modal((box, close) => { box.append(h('h2', {}, title)); build(box, close); });
}

// ---- context menu ---------------------------------------------------------------
let openMenu = null;
export function closeMenu() { openMenu?.remove(); openMenu = null; }
export function contextMenu(x, y, items) {
  closeMenu();
  const m = h('div', { class: 'menu', role: 'menu' });
  for (const it of items) {
    if (it === '-') { m.append(h('hr')); continue; }
    m.append(h('button', { role: 'menuitem', class: it.danger ? 'danger' : '', onclick: () => { closeMenu(); it.run(); } }, it.icon && icon(it.icon), it.label));
  }
  document.body.append(m);
  const r = m.getBoundingClientRect();
  m.style.left = Math.max(4, Math.min(x, innerWidth - r.width - 4)) + 'px';
  m.style.top = Math.max(4, Math.min(y, innerHeight - r.height - 4)) + 'px';
  openMenu = m;
  m.querySelector('button')?.focus();
  const off = e => { if (!m.contains(e.target)) { closeMenu(); cleanup(); } };
  const key = e => { if (e.key === 'Escape') { closeMenu(); cleanup(); } };
  const cleanup = () => { document.removeEventListener('pointerdown', off, true); document.removeEventListener('keydown', key, true); };
  setTimeout(() => { document.addEventListener('pointerdown', off, true); document.addEventListener('keydown', key, true); });
}

// ---- toasts ----------------------------------------------------------------------
export function toast(title, body = '', level = 'info', ms = 4500) {
  const t = h('div', { class: 'toast ' + level, role: level === 'error' ? 'alert' : 'status' }, h('b', {}, title), body && h('span', {}, body));
  document.getElementById('toast-root').append(t);
  const kill = () => t.remove();
  t.addEventListener('click', kill);
  setTimeout(kill, ms);
}
export const errorToast = e => toast('Fehler', e?.message || String(e), 'error', 6000);

// ---- widgets: ring gauge + sparkline ----------------------------------------------
const NS = 'http://www.w3.org/2000/svg';
const svg = (tag, attrs = {}) => { const e = document.createElementNS(NS, tag); for (const k in attrs) e.setAttribute(k, attrs[k]); return e; };

/** Ring gauge: returns an element with .set(value 0-100, centreText, level). */
export function gauge(label, ic) {
  const R = 44, C = 2 * Math.PI * R;
  const s = svg('svg', { viewBox: '0 0 100 100', class: 'gauge-svg' });
  const track = svg('circle', { cx: 50, cy: 50, r: R, class: 'gauge-track' });
  const arc = svg('circle', { cx: 50, cy: 50, r: R, class: 'gauge-arc', 'stroke-dasharray': `0 ${C}`, transform: 'rotate(-90 50 50)' });
  s.append(track, arc);
  const val = h('div', { class: 'gauge-val mono' }, '–');
  const el = h('div', { class: 'gauge' }, s, h('div', { class: 'gauge-center' }, icon(ic), val), h('div', { class: 'label gauge-label' }, label));
  el.set = (pct, text, level = '') => {
    const p = pct == null ? 0 : Math.max(0, Math.min(100, pct));
    arc.setAttribute('stroke-dasharray', `${C * p / 100} ${C}`);
    val.textContent = text;
    el.dataset.level = level;
  };
  return el;
}

export function sparkline(max = 100, points = 60) {
  const s = svg('svg', { viewBox: `0 0 ${points - 1} 30`, preserveAspectRatio: 'none', class: 'spark' });
  const area = svg('polygon', { class: 'spark-area' });
  const line = svg('polyline', { class: 'spark-line' });
  s.append(area, line);
  const data = [];
  s.push = v => {
    data.push(v ?? 0); if (data.length > points) data.shift();
    const off = points - data.length;
    const pts = data.map((d, i) => `${i + off},${(30 - Math.min(d, max) / max * 28 - 1).toFixed(1)}`);
    line.setAttribute('points', pts.join(' '));
    area.setAttribute('points', `${off},30 ${pts.join(' ')} ${points - 1},30`);
  };
  return s;
}
