// Small DOM + formatting helpers shared by the shell and all system apps.
const SVG_NS = 'http://www.w3.org/2000/svg';

/** h('div', {class:'x', onclick:fn, dataset:{a:1}}, child, 'text', [more]) — no innerHTML, no inline styles. */
export function h(tag, props = {}, ...children) {
  const el = SVG_TAGS.has(tag) ? document.createElementNS(SVG_NS, tag) : document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.setAttribute('class', v);
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else if (k === 'style') for (const [p, val] of Object.entries(v)) el.style.setProperty(p, val);
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else if (k === 'value') el.value = v;
    else if (v === true) el.setAttribute(k, '');
    else el.setAttribute(k, v);
  }
  append(el, ...children);
  return el;
}
const SVG_TAGS = new Set(['svg', 'path', 'circle', 'g', 'line', 'polyline', 'rect', 'ellipse', 'defs', 'radialGradient', 'linearGradient', 'stop']);

export function append(el, ...children) {
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return el;
}
export const clear = el => { while (el.firstChild) el.removeChild(el.firstChild); return el; };
export const $ = (sel, root = document) => root.querySelector(sel);

export function debounce(fn, ms) {
  let t;
  const d = (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
  d.flush = () => { if (t) { clearTimeout(t); t = null; fn(); } };
  d.cancel = () => { clearTimeout(t); t = null; };
  return d;
}

export function bytes(n) {
  if (n == null) return '–';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n : n.toFixed(n < 10 ? 1 : 0)) + ' ' + u[i];
}
export function duration(sec) {
  const d = Math.floor(sec / 86400), hh = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60);
  return d ? `${d} d ${hh} h` : hh ? `${hh} h ${m} min` : `${m} min`;
}
export function dateTime(ts) {
  return new Date(ts * 1000).toLocaleString('de-DE', { dateStyle: 'short', timeStyle: 'short' });
}
export function ago(ts) {
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (s < 60) return 'gerade eben';
  if (s < 3600) return `vor ${Math.floor(s / 60)} min`;
  if (s < 86400) return `vor ${Math.floor(s / 3600)} h`;
  return dateTime(ts);
}
export const clamp = (v, lo, hi) => Math.min(Math.max(v, lo), hi);

export class Emitter {
  #h = new Map();
  on(ev, fn) { (this.#h.get(ev) || this.#h.set(ev, new Set()).get(ev)).add(fn); return () => this.#h.get(ev)?.delete(fn); }
  emit(ev, data) { this.#h.get(ev)?.forEach(fn => { try { fn(data); } catch (e) { console.error(e); } }); }
}

/** Minimal, safe Markdown for release notes: "## heading", "- item", paragraphs, `code`. Builds DOM nodes, never HTML. */
export function mdLite(text) {
  const out = [];
  let list = null;
  const inline = line => {
    const parts = String(line).split(/(`[^`]+`)/g);
    return parts.map(p => (p.startsWith('`') && p.endsWith('`') && p.length > 2 ? h('code', {}, p.slice(1, -1)) : p));
  };
  for (const raw of String(text || '').split('\n')) {
    const line = raw.trimEnd();
    if (/^\s*[-*] /.test(line)) {
      if (!list) { list = h('ul', { class: 'md-list' }); out.push(list); }
      list.append(h('li', {}, inline(line.replace(/^\s*[-*] /, ''))));
    } else {
      list = null;
      if (/^#{1,3} /.test(line)) out.push(h('h4', { class: 'md-h' }, line.replace(/^#{1,3} /, '')));
      else if (line.trim()) out.push(h('p', { class: 'md-p' }, inline(line)));
    }
  }
  return out;
}
