// NOVA Monitor: live system metrics, updated by the shared poller (no reloads).
import { h, bytes, duration } from '../util.js';
import { icon } from '../icons.js';
import { bus, state, history } from '../store.js';
import { gauge, sparkline, meter } from '../ui.js';

const lvl = (v, warn, danger) => (v >= danger ? 'danger' : v >= warn ? 'warn' : '');

export default {
  mount(body) {
    const cpu = gauge('CPU', 'cpu'), ram = gauge('RAM', 'ram'), temp = gauge('Temperatur', 'temp');
    const cpuSpark = sparkline(100), ramSpark = sparkline(100), tempSpark = sparkline(90);
    const cell = (g, s, sub) => h('div', { class: 'panel mon-card corners' }, g, s, sub);
    const cpuSub = h('div', { class: 'hint mono' }), ramSub = h('div', { class: 'hint mono' }), tempSub = h('div', { class: 'hint mono' });
    const diskBar = meter(0), diskText = h('div', { class: 'mono' });
    const uptime = h('div', { class: 'mon-big mono' }), load = h('div', { class: 'hint mono' });
    const netList = h('div', { class: 'net-list' }), rates = h('div', { class: 'hint mono' });
    const status = h('span', { class: 'chip' }, h('i', { class: 'dot' }), h('span', {}, 'verbinde …'));

    body.append(h('div', { class: 'monitor-app' },
      h('div', { class: 'mon-grid' }, cell(cpu, cpuSpark, cpuSub), cell(ram, ramSpark, ramSub), cell(temp, tempSpark, tempSub)),
      h('div', { class: 'mon-grid two' },
        h('div', { class: 'panel corners' }, h('div', { class: 'label panel-title' }, icon('disk'), ' Speicher'), diskText, diskBar),
        h('div', { class: 'panel corners' }, h('div', { class: 'label panel-title' }, icon('clock'), ' Laufzeit'), uptime, load)),
      h('div', { class: 'panel corners' }, h('div', { class: 'label panel-title' }, icon('net'), ' Netzwerk'), status, netList, rates)));

    let last = null;
    const render = s => {
      cpu.set(s.cpu, Math.round(s.cpu) + '%', lvl(s.cpu, 75, 90)); cpuSpark.push(s.cpu);
      cpuSub.textContent = `${s.cores} Kerne · Last ${s.load.join(' / ') || '–'}`;
      ram.set(s.ram.percent, Math.round(s.ram.percent) + '%', lvl(s.ram.percent, 80, 92)); ramSpark.push(s.ram.percent);
      ramSub.textContent = `${bytes(s.ram.used)} von ${bytes(s.ram.total)}`;
      const t = s.temp;
      temp.set(t == null ? 0 : t / 90 * 100, t == null ? 'n/v' : t.toFixed(0) + '°C', t == null ? '' : lvl(t, 65, 78)); tempSpark.push(t ?? 0);
      tempSub.textContent = t == null ? 'Kein Sensor gefunden' : t >= 78 ? 'Zu heiß – Kühlung prüfen' : t >= 65 ? 'Warm' : 'Normal';
      diskText.textContent = `${bytes(s.disk.used)} von ${bytes(s.disk.total)} belegt · ${bytes(s.disk.free)} frei`;
      diskBar.set(s.disk.percent, lvl(s.disk.percent, 85, 95));
      uptime.textContent = duration(s.uptime); load.textContent = `Version PiOS ${s.version}`;
      status.firstChild.className = 'dot ' + (s.net.online ? 'ok' : 'danger');
      status.lastChild.textContent = s.net.online ? 'Online' : 'Offline';
      netList.replaceChildren(...s.net.interfaces.map(i => h('div', { class: 'net-row mono' }, h('i', { class: 'dot ' + (i.up ? 'ok' : '') }), h('b', {}, i.name), h('span', {}, i.ip || '–'), h('span', { class: 'hint' }, i.speed ? i.speed + ' Mbit/s' : ''))), h('div', { class: 'hint mono' }, 'Hostname: ' + s.net.hostname));
      if (last) {
        const dt = s.time - last.time || 1;
        rates.textContent = `↓ ${bytes(Math.max(0, (s.net.rx - last.net.rx) / dt))}/s   ↑ ${bytes(Math.max(0, (s.net.tx - last.net.tx) / dt))}/s`;
      }
      last = s;
    };
    for (let i = 0; i < history.cpu.length; i++) { cpuSpark.push(history.cpu[i]); ramSpark.push(history.ram[i]); tempSpark.push(history.temp[i]); }
    if (state.system) render(state.system);
    const off = bus.on('system', render);
    return { destroy: off };
  },
};
