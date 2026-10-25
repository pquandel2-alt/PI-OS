// NOVA window manager: move, resize, minimise, maximise, focus/z-order, persistence, mobile mode.
import { h, Emitter, clamp, debounce } from './util.js';
import { icon } from './icons.js';

const HANDLES = ['n', 's', 'e', 'w', 'ne', 'nw', 'se', 'sw'];
const GRAB = 80; // px of a window that must stay reachable inside the desktop

export class Win extends Emitter {
  constructor(wm, opts) {
    super();
    this.wm = wm;
    this.id = opts.id;
    this.minW = opts.minWidth || 280;
    this.minH = opts.minHeight || 200;
    this.rect = { x: 0, y: 0, w: opts.width || 720, h: opts.height || 480 };
    this.max = false;
    this.min = false;
    this.z = 0;
    this.titleEl = h('span', { class: 'win-title' }, opts.title);
    this.body = h('div', { class: 'win-body' });
    const btn = (cls, ic, label, fn) => h('button', { class: 'win-btn ' + cls, type: 'button', 'aria-label': label, title: label, onclick: fn, onpointerdown: e => e.stopPropagation() }, icon(ic));
    this.maxBtn = btn('max', 'maximize', 'Maximieren', () => this.toggleMax());
    this.titlebar = h('div', { class: 'win-titlebar' },
      h('span', { class: 'win-icon' }, icon(opts.icon || 'app')), this.titleEl,
      h('span', { class: 'spacer' }),
      btn('min', 'minimize', 'Minimieren', () => this.minimize()), this.maxBtn, btn('close', 'close', 'Schließen', () => this.close()));
    this.frame = h('div', { class: 'win-frame' }, this.titlebar, this.body, ...HANDLES.map(d => h('div', { class: 'rz rz-' + d, dataset: { dir: d } })));
    this.el = h('section', { class: 'win opening', role: 'dialog', 'aria-label': opts.title, tabindex: '-1' }, this.frame);
    this.el.addEventListener('pointerdown', () => this.focus(), true);
    this.titlebar.addEventListener('dblclick', () => this.toggleMax());
    this.titlebar.addEventListener('pointerdown', e => this.#drag(e));
    for (const r of this.frame.querySelectorAll('.rz')) r.addEventListener('pointerdown', e => this.#resize(e, r.dataset.dir));
    requestAnimationFrame(() => requestAnimationFrame(() => this.el.classList.remove('opening')));
  }

  setTitle(t) { this.titleEl.textContent = t; this.el.setAttribute('aria-label', t); this.wm.emit('change'); }
  focus() { this.wm.focus(this); }
  minimize() { this.min = true; this.el.classList.add('min'); this.wm.afterChange(this); }
  restore() { this.min = false; this.el.classList.remove('min'); this.wm.focus(this); }
  toggleMax() {
    this.max = !this.max;
    this.#apply();
    this.wm.afterChange(this);
  }
  close() {
    this.emit('close');
    this.el.classList.add('opening');
    setTimeout(() => this.el.remove(), 160);
    this.wm.remove(this);
  }

  place(rect) {
    const area = this.wm.area();
    this.rect.w = clamp(rect.w, this.minW, Math.max(this.minW, area.width));
    this.rect.h = clamp(rect.h, this.minH, Math.max(this.minH, area.height));
    this.rect.x = clamp(rect.x, GRAB - this.rect.w, area.width - GRAB);
    this.rect.y = clamp(rect.y, 0, Math.max(0, area.height - 40));
    this.#apply();
  }
  #apply() {
    const e = this.el.style, r = this.rect;
    if (this.max) { e.transform = 'translate3d(0,0,0)'; e.width = '100%'; e.height = '100%'; }
    else { e.transform = `translate3d(${Math.round(r.x)}px,${Math.round(r.y)}px,0)`; e.width = r.w + 'px'; e.height = r.h + 'px'; }
    this.el.classList.toggle('maximized', this.max);
    this.maxBtn.replaceChildren(icon(this.max ? 'restore' : 'maximize'));
    this.maxBtn.setAttribute('aria-label', this.max ? 'Wiederherstellen' : 'Maximieren');
  }

  #drag(e) {
    if (e.button !== 0 || this.wm.mobile) return;
    const start = { px: e.clientX, py: e.clientY, x: this.rect.x, y: this.rect.y };
    let restored = false;
    this.#track(e, ev => {
      if (this.max) { // dragging a maximised window restores it under the pointer
        if (!restored && Math.hypot(ev.clientX - start.px, ev.clientY - start.py) < 6) return;
        if (!restored) {
          restored = true; this.max = false;
          start.x = ev.clientX - this.rect.w * (start.px / this.wm.area().width); start.y = 0; start.px = ev.clientX; start.py = ev.clientY;
        }
      }
      this.place({ ...this.rect, x: start.x + ev.clientX - start.px, y: start.y + ev.clientY - start.py });
    });
  }
  #resize(e, dir) {
    if (e.button !== 0 || this.max || this.wm.mobile) return;
    e.stopPropagation();
    const o = { ...this.rect, px: e.clientX, py: e.clientY }, area = this.wm.area();
    this.#track(e, ev => {
      const dx = ev.clientX - o.px, dy = ev.clientY - o.py;
      let { x, y, w, h: hh } = o;
      if (dir.includes('e')) w = o.w + dx;
      if (dir.includes('s')) hh = o.h + dy;
      if (dir.includes('w')) { w = o.w - dx; if (w < this.minW) { w = this.minW; } x = o.x + o.w - w; }
      if (dir.includes('n')) { hh = o.h - dy; if (hh < this.minH) { hh = this.minH; } y = o.y + o.h - hh; }
      w = Math.min(w, area.width); hh = Math.min(hh, area.height);
      this.place({ x, y: Math.max(0, y), w, h: hh });
      this.emit('resize');
    });
  }
  #track(e, move) {
    e.preventDefault();
    const target = e.currentTarget;
    target.setPointerCapture?.(e.pointerId);
    this.wm.desktop.classList.add('dragging');
    const onMove = ev => move(ev);
    const end = () => {
      target.removeEventListener('pointermove', onMove);
      target.removeEventListener('pointerup', end);
      target.removeEventListener('pointercancel', end);
      this.wm.desktop.classList.remove('dragging');
      this.wm.afterChange(this);
    };
    target.addEventListener('pointermove', onMove);
    target.addEventListener('pointerup', end);
    target.addEventListener('pointercancel', end);
  }
}

export class WindowManager extends Emitter {
  constructor(desktop) {
    super();
    this.desktop = desktop;
    this.wins = new Map();
    this.zTop = 10;
    this.active = null;
    const mq = matchMedia('(max-width: 820px)');
    this.mobile = mq.matches;
    mq.addEventListener('change', () => { this.mobile = mq.matches; desktop.classList.toggle('mobile', this.mobile); this.#reflow(); });
    desktop.classList.toggle('mobile', this.mobile);
    new ResizeObserver(debounce(() => this.#reflow(), 100)).observe(desktop);
    this.persist = debounce(() => this.emit('persist', this.serialize()), 700);
  }
  area() { return { width: this.desktop.clientWidth, height: this.desktop.clientHeight }; }
  get(id) { return this.wins.get(id); }

  create(opts, saved) {
    const w = new Win(this, opts);
    const n = this.wins.size, a = this.area();
    const def = { w: opts.width || 720, h: opts.height || 480 };
    def.w = Math.min(def.w, a.width - 24); def.h = Math.min(def.h, a.height - 24);
    const r = saved ? { ...saved } : { x: (a.width - def.w) / 2 + (n % 6) * 28 - 56, y: Math.max(12, (a.height - def.h) / 2 + (n % 6) * 28 - 80), ...def };
    w.max = !!saved?.max;
    w.place({ x: r.x, y: r.y, w: r.w, h: r.h });
    this.wins.set(w.id, w);
    this.desktop.append(w.el);
    this.focus(w);
    this.emit('change');
    return w;
  }
  focus(w) {
    if (w.min) { w.min = false; w.el.classList.remove('min'); }
    if (this.zTop > 9000) this.#renormalize();
    if (this.active !== w || !w.z) w.z = ++this.zTop;
    w.el.style.zIndex = w.z;
    this.active = w;
    for (const x of this.wins.values()) x.el.classList.toggle('active', x === w);
    this.afterChange(w);
  }
  remove(w) {
    this.wins.delete(w.id);
    if (this.active === w) {
      this.active = [...this.wins.values()].filter(x => !x.min).sort((a, b) => b.z - a.z)[0] || null;
      if (this.active) this.active.el.classList.add('active');
    }
    this.emit('change');
    this.persist();
  }
  afterChange() { this.emit('change'); this.persist(); }
  #renormalize() {
    [...this.wins.values()].sort((a, b) => a.z - b.z).forEach((w, i) => { w.z = i + 10; w.el.style.zIndex = w.z; });
    this.zTop = this.wins.size + 10;
  }
  #reflow() { for (const w of this.wins.values()) w.place(w.rect); }

  serialize() {
    const windows = {};
    for (const w of this.wins.values()) windows[w.id] = { x: Math.round(w.rect.x), y: Math.round(w.rect.y), w: w.rect.w, h: w.rect.h, max: w.max };
    const open = [...this.wins.values()].sort((a, b) => a.z - b.z).map(w => w.id);
    return { windows, open, active: this.active?.id || null, minimized: [...this.wins.values()].filter(w => w.min).map(w => w.id) };
  }
}
