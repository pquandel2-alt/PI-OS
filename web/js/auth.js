// Setup wizard and login screen.
import { h, clear } from './util.js';
import * as api from './api.js';
import { button, field } from './ui.js';
import { createOrb } from './orb.js';
import { icon } from './icons.js';

function shell(...content) {
  const orb = createOrb({ size: 'small', status: false });
  return h('div', { class: 'auth' }, h('div', { class: 'auth-card panel corners' },
    h('div', { class: 'auth-head' }, orb, h('div', {}, h('div', { class: 'brand' }, 'PiOS ', h('b', {}, 'NOVA')), h('div', { class: 'label' }, 'Lokales Betriebssystem'))),
    ...content));
}

export function showAuth(root, status) {
  return new Promise(resolve => {
    clear(root);
    root.append(status.needs_setup ? setupView(resolve, status) : loginView(resolve));
  });
}

function loginView(done) {
  const user = h('input', { class: 'input', name: 'username', autocomplete: 'username', required: true, autofocus: true, maxlength: 40 });
  const pass = h('input', { class: 'input', name: 'password', type: 'password', autocomplete: 'current-password', required: true, maxlength: 256 });
  const err = h('div', { class: 'error-text', role: 'alert' });
  const btn = button('Anmelden', { variant: 'primary', icon: 'lock' }); btn.type = 'submit';
  const form = h('form', { class: 'auth-form', onsubmit: async e => {
    e.preventDefault(); err.textContent = ''; btn.disabled = true;
    try { await api.post('login', { username: user.value.trim(), password: pass.value }); done(); }
    catch (x) { err.textContent = x.message; pass.value = ''; pass.focus(); }
    finally { btn.disabled = false; }
  } }, field('Benutzername', user), field('Passwort', pass), err, btn);
  const el = shell(form);
  queueMicrotask(() => user.focus());
  return el;
}

function setupView(done, status) {
  const f = {
    username: h('input', { class: 'input', autocomplete: 'username', required: true, maxlength: 40, placeholder: 'z. B. admin' }),
    password: h('input', { class: 'input', type: 'password', autocomplete: 'new-password', required: true, minlength: 12, maxlength: 256 }),
    repeat: h('input', { class: 'input', type: 'password', autocomplete: 'new-password', required: true, minlength: 12, maxlength: 256 }),
    code: h('input', { class: 'input mono', autocomplete: 'off', required: status.needs_code, maxlength: 16, placeholder: 'XXXX-XXXX', autocapitalize: 'characters' }),
  };
  const err = h('div', { class: 'error-text', role: 'alert' });
  const btn = button('Administratorkonto erstellen', { variant: 'primary', icon: 'shield' }); btn.type = 'submit';
  const form = h('form', { class: 'auth-form', onsubmit: async e => {
    e.preventDefault(); err.textContent = '';
    if (f.password.value !== f.repeat.value) { err.textContent = 'Die Passwörter stimmen nicht überein.'; return; }
    btn.disabled = true;
    try {
      const creds = { username: f.username.value.trim(), password: f.password.value };
      await api.post('setup', { ...creds, setup_code: f.code.value });
      await api.post('login', creds);
      done();
    } catch (x) { err.textContent = x.message; } finally { btn.disabled = false; }
  } },
    h('p', { class: 'muted' }, 'Willkommen. Lege das Administratorkonto für dieses Gerät an.'),
    status.needs_code && field('Setup-Code', f.code, 'Steht auf dem HDMI-Bildschirm des Raspberry Pi oder in der Datei PIOS-SETUP.txt auf der SD-Karte (Boot-Partition).'),
    field('Benutzername', f.username), field('Passwort', f.password, 'Mindestens 12 Zeichen.'), field('Passwort wiederholen', f.repeat), err, btn);
  return shell(form);
}
