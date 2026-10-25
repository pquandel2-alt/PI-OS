// NOVA Orb: the system indicator. Pure CSS/SVG animation (compositor-only transforms), no canvas, no JS per frame.
import { h } from './util.js';
import { bus, state } from './store.js';
import { apiEvents } from './api.js';

const NS = 'http://www.w3.org/2000/svg';
const s = (tag, a = {}) => { const e = document.createElementNS(NS, tag); for (const k in a) e.setAttribute(k, a[k]); return e; };

const LABELS = {
  ready: 'System betriebsbereit',
  activity: 'Hintergrundaktivität',
  action: 'App-Aktion',
  warn: 'Systemwarnung',
};

function ring(r, dash, cls) {
  const c = s('circle', { cx: 100, cy: 100, r, class: 'orb-ring ' + cls });
  if (dash) c.setAttribute('stroke-dasharray', dash);
  return c;
}

function ticks() {
  const g = s('g', { class: 'orb-ticks' });
  for (let i = 0; i < 60; i++) {
    const a = i * 6 * Math.PI / 180, long = i % 5 === 0;
    const r1 = 92, r2 = long ? 85 : 88.5;
    g.append(s('line', { x1: 100 + r1 * Math.sin(a), y1: 100 - r1 * Math.cos(a), x2: 100 + r2 * Math.sin(a), y2: 100 - r2 * Math.cos(a), class: long ? 'tick long' : 'tick' }));
  }
  return g;
}

/** @returns element with .setState(name) and .destroy() */
export function createOrb({ size = 'large', status = true } = {}) {
  const svg = s('svg', { viewBox: '0 0 200 200', class: 'orb-svg', 'aria-hidden': 'true' });
  const defs = s('defs');
  const grad = s('radialGradient', { id: 'orb-core-' + size, cx: '50%', cy: '45%', r: '60%' });
  grad.append(s('stop', { offset: '0%', class: 'orb-stop-a' }), s('stop', { offset: '55%', class: 'orb-stop-b' }), s('stop', { offset: '100%', class: 'orb-stop-c' }));
  defs.append(grad);
  const spin1 = s('g', { class: 'orb-spin slow' }); spin1.append(ring(78, '2 9', 'dotted'), ring(70, '90 40 30 60', 'arc'));
  const spin2 = s('g', { class: 'orb-spin rev' }); spin2.append(ring(60, '40 100 20 80', 'arc thin'));
  svg.append(defs, ticks(), ring(96, '', 'outer'), spin1, spin2, s('circle', { cx: 100, cy: 100, r: 44, fill: `url(#orb-core-${size})`, class: 'orb-core' }));

  const pulse = h('div', { class: 'orb-pulse' });
  const label = status ? h('div', { class: 'orb-label' }, LABELS.ready) : null;
  const el = h('div', { class: 'orb ' + size, 'data-state': 'ready', role: 'img', 'aria-label': 'NOVA Orb' }, pulse, svg, label);

  let actionTimer = null, forced = null;
  const compute = () => {
    const sys = state.system;
    const warn = sys && ((sys.temp != null && sys.temp >= 75) || sys.ram.percent >= 92 || sys.disk.percent >= 95 || sys.cpu >= 95);
    return forced || (warn ? 'warn' : busy > 0 ? 'activity' : 'ready');
  };
  let busy = 0;
  const apply = () => {
    const st = compute();
    if (el.dataset.state !== st) {
      el.dataset.state = st;
      if (label) label.textContent = LABELS[st];
    }
  };
  el.setState = st => { forced = st; apply(); };

  if (status) {
    const offA = apiEvents.on('activity', ({ inflight, write }) => {
      busy = inflight; apply();
      if (write && inflight === 0) { forced = 'action'; apply(); clearTimeout(actionTimer); actionTimer = setTimeout(() => { forced = null; apply(); }, 1400); }
    });
    const offS = bus.on('system', apply);
    el.destroy = () => { offA(); offS(); clearTimeout(actionTimer); };
    apply();
  } else el.destroy = () => {};
  return el;
}
