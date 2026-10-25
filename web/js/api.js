// Backend client. Adds the CSRF header, normalises errors, tracks activity for the orb.
import { Emitter } from './util.js';

export const apiEvents = new Emitter();
let inflight = 0;

export class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function message(status, body) {
  const d = body && body.detail;
  if (typeof d === 'string') return d;
  if (Array.isArray(d)) return d.map(x => (x.msg || '').replace(/^Value error, /, '')).filter(Boolean).join('; ') || 'Eingabe ungültig';
  return `Fehler ${status}`;
}

function track(method, quiet) {
  if (quiet) return () => {};
  inflight++;
  apiEvents.emit('activity', { inflight, write: method !== 'GET' });
  return () => { inflight--; apiEvents.emit('activity', { inflight, write: method !== 'GET' }); };
}

export async function api(method, path, body, { quiet = false, form = false, signal } = {}) {
  const done = track(method, quiet);
  try {
    const opts = { method, credentials: 'same-origin', headers: { 'X-PiOS': '1' }, signal };
    if (body !== undefined) {
      if (form) opts.body = body;
      else { opts.body = JSON.stringify(body); opts.headers['Content-Type'] = 'application/json'; }
    }
    let r;
    try { r = await fetch('/api/' + path, opts); }
    catch (e) { if (e.name === 'AbortError') throw e; throw new ApiError(0, 'Keine Verbindung zu PiOS'); }
    let data = null;
    if ((r.headers.get('content-type') || '').includes('json')) data = await r.json().catch(() => null);
    if (!r.ok) {
      if (r.status === 401 && !path.startsWith('login') && !path.startsWith('setup')) apiEvents.emit('unauthorized');
      throw new ApiError(r.status, message(r.status, data));
    }
    return data;
  } finally { done(); }
}
export const get = (p, o) => api('GET', p, undefined, o);
export const post = (p, b, o) => api('POST', p, b ?? {}, o);
export const put = (p, b, o) => api('PUT', p, b, o);
export const del = (p, o) => api('DELETE', p, undefined, o);
export const q = obj => new URLSearchParams(obj).toString();

/** Upload with progress via XHR (fetch cannot report upload progress). */
export function upload(path, file, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/files/upload?' + q({ path }));
    xhr.setRequestHeader('X-PiOS', '1');
    xhr.upload.onprogress = e => e.lengthComputable && onProgress?.(e.loaded / e.total);
    xhr.onload = () => {
      let d = null; try { d = JSON.parse(xhr.responseText); } catch { /* not JSON */ }
      xhr.status < 300 ? resolve(d) : reject(new ApiError(xhr.status, message(xhr.status, d)));
    };
    xhr.onerror = () => reject(new ApiError(0, 'Keine Verbindung zu PiOS'));
    const fd = new FormData(); fd.append('file', file, file.name);
    const done = track('POST', false);
    xhr.onloadend = done;
    xhr.send(fd);
  });
}
export const fileUrl = (path, inline = false) => '/api/files/download?' + q({ path, inline: inline ? 'true' : 'false' });
