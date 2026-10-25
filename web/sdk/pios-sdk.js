/*! PiOS SDK 1 — include with <script src="/sdk/pios-sdk.js"></script>.
 *  Apps run sandboxed without network access; every call is a message to the NOVA shell,
 *  and the PiOS server enforces the permissions declared in manifest.json. */
(function () {
  'use strict';
  var seq = 0, pending = {}, subs = {}, themeSubs = [];
  function call(method, params) {
    return new Promise(function (resolve, reject) {
      var id = ++seq;
      pending[id] = { resolve: resolve, reject: reject };
      parent.postMessage({ pios: 1, id: id, method: method, params: params || {} }, '*');
    });
  }
  function applyTheme(t) {
    if (!t) return;
    document.body.dataset.accent = t.accent;
    document.body.dataset.motion = t.motion;
    themeSubs.forEach(function (f) { f(t); });
  }
  window.addEventListener('message', function (e) {
    if (e.source !== parent) return;
    var m = e.data;
    if (!m || m.pios !== 1) return;
    if (m.event === 'theme') return applyTheme(m.data);
    if (m.event === 'event') { (subs[m.data.topic] || []).forEach(function (f) { f(m.data.data, m.data.from); }); return; }
    var p = pending[m.id];
    if (!p) return;
    delete pending[m.id];
    if (m.error) { var err = new Error(m.error.message); err.status = m.error.status; p.reject(err); } else p.resolve(m.result);
  });

  var textDecoder = new TextDecoder();
  window.pios = {
    apiVersion: 1,
    /** Resolves with { app, version, api, permissions, accent }. */
    ready: call('hello').then(function (info) { var go = function () { applyTheme(info); }; document.body ? go() : document.addEventListener('DOMContentLoaded', go); return info; }),
    window: {
      setTitle: function (title) { return call('window.setTitle', { title: title }); },
      close: function () { return call('window.close'); },
      minimize: function () { return call('window.minimize'); },
      toggleMaximize: function () { return call('window.toggleMaximize'); }
    },
    ui: {
      toast: function (title, body, level) { return call('ui.toast', { title: title, body: body, level: level }); },
      onTheme: function (fn) { themeSubs.push(fn); }
    },
    storage: {  // permission: storage
      get: function (key) { return call('storage.get', { key: key }); },
      set: function (key, value) { return call('storage.set', { key: key, value: value }); },
      remove: function (key) { return call('storage.remove', { key: key }); }
    },
    files: {    // permissions: files.app (own folder) | files.read | files.write
      list: function (path) { return call('files.list', { path: path || '' }); },
      read: function (path) { return call('files.read', { path: path }); },
      readText: function (path) { return call('files.read', { path: path }).then(function (b) { return textDecoder.decode(b); }); },
      write: function (path, data) { return call('files.write', { path: path, data: typeof data === 'string' ? new TextEncoder().encode(data) : data }); }
    },
    system: {   // permission: system.read
      info: function () { return call('system.info'); }
    },
    notifications: {  // permission: notifications
      show: function (title, body, level) { return call('notifications.show', { title: title, body: body, level: level }); }
    },
    events: {   // publish only to "<yourAppId>.*"; subscribe to any topic
      emit: function (topic, data) { return call('events.emit', { topic: topic, data: data }); },
      on: function (topic, fn) { (subs[topic] = subs[topic] || []).push(fn); return call('events.on', { topic: topic }); }
    }
  };
})();
