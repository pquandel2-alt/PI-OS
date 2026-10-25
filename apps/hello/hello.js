(async function () {
  const $ = id => document.getElementById(id);
  const fail = e => { $('err').textContent = e.message; };
  try {
    const info = await pios.ready;
    $('greeting').textContent = 'Hallo von ' + info.app + ' ' + info.version;
    let n = (await pios.storage.get('count')) || 0;
    const show = () => { $('count').textContent = n; };
    show();
    $('inc').onclick = () => { n++; show(); pios.storage.set('count', n).catch(fail); };
    $('reset').onclick = () => { n = 0; show(); pios.storage.set('count', 0).catch(fail); };
    $('notify').onclick = () => pios.notifications.show('Hello NOVA', 'Zählerstand: ' + n).catch(fail);
    const tick = async () => {
      try { const s = await pios.system.info(); $('sys').textContent = 'CPU ' + Math.round(s.cpu) + '% · RAM ' + Math.round(s.ram.percent) + '%'; }
      catch (e) { fail(e); }
    };
    tick(); setInterval(tick, 3000);
  } catch (e) { fail(e); }
})();
