/* app.js: the teardown dashboard. It talks to the documented HTTP API only (docs/api/http.md):
 * POST /api/analyze, GET /api/analyses, GET|DELETE /api/analyses/{id}, GET /api/analyses/{id}/strings,
 * GET /api/health and the GET /api/events stream. Everything from the server is rendered as text through Aurora.el.
 *
 * The page is an Aurora shell (rail, top bar, sub bar, status bar) and two routes drawn into it:
 *   #/                    the upload zone and the list of analyses
 *   #/analysis/<id>       the report (report-view.js) */
(function () {
  'use strict';

  const A = window.Aurora;
  const V = window.TeardownView;
  const { el, fmt, icon } = A;
  const vis = V.vis;
  const plural = (n) => `${fmt.int(n)} ${n === 1 ? 'analysis' : 'analyses'}`;
  A.init();

  const ID = /^an_[0-9a-f]{12}$/;
  const STATIC_ONLY = 'Static analysis only; files are never executed';
  const PAGE = 10; // analyses shown per step on the home page
  let routeToken = 0;
  let current = null;
  let firstPage = true;
  const home = { sort: 'newest' }; // the order survives a visit to a report

  /* ───────────────────────── API client ───────────────────────── */
  class ApiError extends Error {
    constructor(status, code, message) {
      super(message);
      this.name = 'ApiError';
      this.status = status;
      this.code = code;
    }
  }
  async function request(path, init) {
    let res;
    try {
      res = await fetch(path, init);
    } catch (e) {
      throw new ApiError(0, 'network', 'The teardown server is not reachable. Is it still running?');
    }
    if (!res.ok) {
      let code = 'http_error';
      let message = `The server answered ${res.status}.`;
      try {
        const body = await res.json();
        if (body && body.error) { code = body.error.code; message = body.error.message; }
      } catch (e) { /* not the JSON error envelope: keep the generic message */ }
      throw new ApiError(res.status, code, message);
    }
    return res.status === 204 ? null : res.json();
  }
  const api = {
    health: () => request('/api/health'),
    list: () => request('/api/analyses'),
    get: (id) => request(`/api/analyses/${id}`),
    remove: (id) => request(`/api/analyses/${id}`, { method: 'DELETE' }),
    strings(id, q) {
      const p = new URLSearchParams();
      if (q.categories.length) p.set('category', q.categories.join(','));
      if (q.q) p.set('q', q.q);
      p.set('limit', String(q.limit));
      p.set('offset', String(q.offset));
      return request(`/api/analyses/${id}/strings?${p}`);
    },
    // XMLHttpRequest, because fetch cannot report upload progress.
    upload(file, onProgress) {
      return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/api/analyze');
        xhr.responseType = 'json';
        xhr.upload.onprogress = (e) => { if (e.lengthComputable) onProgress(e.loaded, e.total); };
        xhr.onerror = () => reject(new ApiError(0, 'network', 'The teardown server is not reachable. Is it still running?'));
        xhr.onload = () => {
          const body = xhr.response;
          if (xhr.status === 201 && body && body.report) { resolve(body); return; }
          const e = body && body.error;
          reject(new ApiError(xhr.status, e ? e.code : 'http_error', e ? e.message : `The server answered ${xhr.status}.`));
        };
        const form = new FormData();
        form.append('file', file, file.name);
        xhr.send(form);
      });
    },
  };

  /* ───────────────────────── store of analysis summaries ───────────────────────── */
  const byNewest = (a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt);
  const store = {
    items: [],
    listeners: new Set(),
    set(items) { this.items = items.filter((x) => ID.test(x.id)).sort(byNewest); this.emit(); },
    upsert(s) {
      if (!ID.test(s.id)) return;
      const i = this.items.findIndex((x) => x.id === s.id);
      if (i >= 0) this.items[i] = s; else this.items.push(s);
      this.items.sort(byNewest);
      this.emit();
    },
    drop(id) { this.items = this.items.filter((x) => x.id !== id); this.emit(); },
    emit() { this.listeners.forEach((fn) => fn(this.items)); recentCommands(); paintStatus(); },
  };
  async function refresh() {
    try { store.set(await api.list()); } catch (e) { /* the live indicator already says the server is away */ }
  }

  /* ───────────────────────── the shell ───────────────────────── */
  const live = A.live(null, { label: 'Live' });
  const picker = el('input', { type: 'file', multiple: true, hidden: true, tabindex: '-1', 'aria-hidden': 'true' });
  const shell = A.shell({
    brand: { name: 'teardown', href: '#/', mark: 'cpu' },
    rail: [
      [{ id: 'home', label: 'Analyses', icon: 'layers', href: '#/', active: true },
       { id: 'api', label: 'API', icon: 'code', href: '/api/openapi.json', external: true }],
      'spacer',
      [{ id: 'upload', label: 'Upload a file', icon: 'upload', onClick: () => picker.click() },
       { id: 'palette', label: 'Command palette', icon: 'command', cmdk: true }],
    ],
    crumbs: ['teardown', 'Analyses'],
    actions: [live.el],
    status: { start: ['teardown'], end: [STATIC_ONLY] },
  });
  const view = shell.container;
  let version = '';
  function paintStatus() {
    shell.setStatus({ start: [`teardown${version ? ' ' + version : ''}`, `${plural(store.items.length)} in memory`], end: [STATIC_ONLY] });
  }
  paintStatus();
  api.health().then((h) => { if (h && typeof h.version === 'string') { version = vis(h.version); paintStatus(); } }, () => { /* the status bar just keeps the name */ });

  /* ───────────────────────── live events ───────────────────────── */
  const eventListeners = new Set();
  let stream = null;
  let retries = 0;
  function connect() {
    live.set('connecting');
    stream = new EventSource('/api/events');
    stream.addEventListener('open', () => { retries = 0; live.set('live', 'Live'); refresh(); });
    ['analysis.started', 'analysis.completed', 'analysis.failed'].forEach((type) => {
      stream.addEventListener(type, (ev) => {
        let data;
        try { data = JSON.parse(ev.data); } catch (e) { return; }
        if (!data || !ID.test(data.id)) return;
        eventListeners.forEach((fn) => fn(type, data));
        if (type === 'analysis.completed') store.upsert(summaryOf(data));
      });
    });
    stream.addEventListener('error', () => {
      live.set('offline', 'Reconnecting…');
      if (stream.readyState === window.EventSource.CLOSED) {
        stream.close();
        retries = Math.min(retries + 1, 6);
        setTimeout(connect, Math.min(15000, 600 * Math.pow(2, retries)));
      }
    });
  }
  const summaryOf = (d) => ({ id: d.id, name: d.name, size: d.size, type: d.type, typeLabel: d.typeLabel, risk: d.risk, createdAt: d.createdAt });

  /* ───────────────────────── command palette ───────────────────────── */
  let recentIds = [];
  function recentCommands() {
    A.cmdk.unregister(recentIds);
    const commands = store.items.slice(0, 25).map((s) => ({
      id: `open:${s.id}`, label: `Open ${vis(s.name)}`, group: 'Recent analyses', hint: `risk ${s.risk.score}`,
      keywords: `${vis(s.typeLabel)} ${s.risk.label} report`, run: () => { location.hash = `#/analysis/${s.id}`; },
    }));
    recentIds = commands.map((c) => c.id);
    A.cmdk.register(commands);
  }
  picker.addEventListener('change', () => { startUploads(Array.from(picker.files)); picker.value = ''; });
  document.body.appendChild(picker);
  A.cmdk.register([
    { id: 'go-home', label: 'Go to analyses', group: 'Navigate', hint: 'home', keywords: 'recent list home', run: () => { location.hash = '#/'; } },
    { id: 'upload', label: 'Upload a file to analyse…', group: 'Actions', hint: 'file', keywords: 'analyse analyze add drop', run: () => picker.click() },
    { id: 'theme', label: 'Toggle light / dark theme', group: 'Actions', keywords: 'appearance mode', run: () => A.theme.toggle() },
    { id: 'api', label: 'Open the API description (OpenAPI)', group: 'Navigate', hint: 'json', keywords: 'docs swagger openapi', run: () => window.open('/api/openapi.json', '_blank', 'noopener') },
  ]);

  /* ───────────────────────── uploads ───────────────────────── */
  const uploads = (() => {
    const list = el('ul', { class: 'td-uploads__list' });
    const node = el('section', { class: 'a-card', 'aria-label': 'Uploads', hidden: true },
      el('div', { class: 'a-card__head' }, el('div', null, el('div', { class: 'a-card__title' }, 'Uploads'), el('div', { class: 'a-card__sub' }, 'Files are streamed to the server, analysed and deleted. Nothing is executed.'))),
      el('div', { class: 'a-card__body' }, list));
    return { el: node, list };
  })();

  function uploadRow(file) {
    const status = el('span', { class: 'a-muted', role: 'status' }, 'Waiting…');
    const bar = el('div', { class: 'td-upload__bar' });
    const meter = A.meter(bar, { value: 0, max: 100, thin: true, label: null, format: (v) => `${Math.round(v)}%` });
    const actions = el('span', { class: 'td-upload__actions' });
    const row = el('li', { class: 'td-upload' }, el('div', { class: 'td-upload__head' }, el('span', { class: 'td-upload__name' }, vis(file.name)), el('span', { class: 'a-tag a-num' }, fmt.bytes(file.size)), el('span', { class: 'a-spacer' }), status, actions), bar);
    uploads.list.insertBefore(row, uploads.list.firstChild);
    uploads.el.hidden = false;
    return {
      progress(loaded, total) {
        meter.update((loaded / total) * 100);
        status.textContent = loaded >= total ? 'Analysing…' : `Uploading ${Math.round((loaded / total) * 100)}%`;
      },
      done(id, report) {
        meter.update(100);
        row.classList.add('is-done');
        status.textContent = '';
        actions.appendChild(V.riskBadge(report.risk));
        actions.appendChild(el('a', { class: 'a-btn a-btn--sm', href: `#/analysis/${id}` }, 'Open report'));
      },
      fail(err) {
        row.classList.add('is-failed');
        bar.hidden = true;
        status.textContent = '';
        actions.appendChild(A.badge(err.code === 'too_large' ? 'Too large' : 'Failed', { kind: 'critical' }));
        row.appendChild(el('p', { class: 'td-upload__error' }, err.message));
        actions.appendChild(el('button', { class: 'a-btn a-btn--ghost a-btn--icon a-btn--sm', type: 'button', 'aria-label': `Dismiss ${vis(file.name)}`, onclick: () => { row.remove(); if (!uploads.list.children.length) uploads.el.hidden = true; } }, icon('x')));
      },
    };
  }

  let queue = Promise.resolve();
  function startUploads(files) {
    if (!files.length) return;
    if (location.hash !== '#/' && location.hash !== '') location.hash = '#/';
    // rows are inserted newest first, so a batch is inserted backwards to keep its own order on screen
    const rows = new Map();
    files.slice().reverse().forEach((file) => rows.set(file, uploadRow(file)));
    files.forEach((file) => {
      const row = rows.get(file);
      queue = queue.then(() => api.upload(file, row.progress).then(
        (res) => {
          row.done(res.id, res.report);
          store.upsert({ id: res.id, name: res.report.file.name, size: res.report.file.size, type: res.report.type.id, typeLabel: res.report.type.label, risk: { score: res.report.risk.score, label: res.report.risk.label }, createdAt: res.report.generatedAt });
          if (files.length === 1) location.hash = `#/analysis/${res.id}`;
        },
        (err) => { row.fail(err); A.toast(`${vis(file.name)}: ${err.message}`, { kind: 'critical', duration: 6000 }); },
      ));
    });
  }

  // A file dropped anywhere on the page is analysed. The drop zone of the home page takes its own drops
  // and the event then bubbles up to the page-wide listener, which must not analyse the same files twice.
  const drop = { inZone: false };
  document.addEventListener('drop', () => { drop.inZone = false; }, true);
  A.pageDrop({ title: 'Drop to analyse', hint: 'The file is parsed, never executed.', onFiles: (files) => { if (!drop.inZone) startUploads(files); } });

  /* ───────────────────────── home ───────────────────────── */
  function confirmDelete(row) {
    return A.confirm({ title: 'Delete this analysis?', message: `${vis(row.name)} will be removed from the server's memory. The file itself was already deleted after the analysis.`, confirmLabel: 'Delete', kind: 'danger' }).then((ok) => {
      if (!ok) return false;
      return api.remove(row.id).then(() => { store.drop(row.id); A.toast('Analysis deleted', { kind: 'good' }); return true; }, (err) => { A.toast(err.message, { kind: 'critical' }); return false; });
    });
  }

  // One analysis of the list: the risk, the name, the type and size, how long ago, and a delete button.
  function recentRow(s) {
    const when = new Date(s.createdAt);
    const name = vis(s.name);
    const type = vis(s.typeLabel);
    const open = el('a', { class: 'a-recent', href: `#/analysis/${s.id}` },
      el('span', { class: 'td-recent__main' }, V.riskBadge(s.risk), el('span', { class: 'a-recent__title', title: name }, name), el('span', { class: 'td-recent__type', title: type }, type)),
      el('span', { class: 'td-recent__size a-num' }, fmt.bytes(s.size)),
      el('time', { datetime: isNaN(when) ? null : when.toISOString(), title: fmt.date(when, { time: true }) }, fmt.relative(when)));
    const del = el('button', { class: 'a-btn a-btn--ghost a-btn--icon a-btn--sm td-recent__del', type: 'button', title: `Delete ${name}`, 'aria-label': `Delete ${name}`, onclick: () => confirmDelete(s) }, icon('trash', { size: 15 }));
    return el('li', { class: 'td-recent', 'data-id': s.id }, open, del);
  }

  // An analysis another client has started or that failed: shown at the top until it completes (or is dismissed).
  function pendingRow(type, d, dismiss) {
    const failed = type === 'analysis.failed';
    const row = el('li', { class: 'td-recent td-recent--pending', 'data-id': d.id }, el('div', { class: 'a-recent' },
      el('span', { class: 'td-recent__main' }, failed ? A.badge('Failed', { kind: 'critical' }) : A.badge('Analysing', { kind: 'info' }), el('span', { class: 'a-recent__title', title: vis(d.name) }, vis(d.name)), failed ? el('span', { class: 'td-recent__type', title: vis(d.error) }, vis(d.error)) : null),
      el('span', { class: 'td-recent__size a-num' }, fmt.bytes(d.size))));
    if (failed) row.appendChild(el('button', { class: 'a-btn a-btn--ghost a-btn--icon a-btn--sm td-recent__del', type: 'button', 'aria-label': `Dismiss ${vis(d.name)}`, onclick: dismiss }, icon('x', { size: 15 })));
    return row;
  }

  function showHome() {
    const root = el('div', { class: 'td-home' });
    view.replaceChildren(root);
    shell.setCrumbs(['teardown', 'Analyses']);
    const state = { q: '', shown: PAGE };
    const pending = new Map(); // id -> { type, data }: analyses of other clients that are not in the list (yet)

    root.appendChild(el('section', { class: 'a-hero' },
      el('p', { class: 'a-greet' }, 'Static triage'),
      el('h1', { class: 'a-headline', id: 'td-title', tabindex: '-1' }, 'Triage a file without running it'),
      el('p', { class: 'a-lede' }, 'Drop a binary or an app package anywhere on this page. ', el('strong', 'teardown'), ' reads it, never runs it, and lists each finding with its evidence and the ways it can be wrong.')));

    const zone = el('div', { class: 'td-drop' });
    root.appendChild(zone);
    A.dropzone(zone, { title: 'Drop a file to analyse', hint: 'PE, ELF, Mach-O, APK, JAR, ASAR, WebAssembly, GGUF and more · or click to choose', multiple: true, onFiles: (files) => { drop.inZone = true; startUploads(files); } });
    root.appendChild(uploads.el);

    // the list: a filter, the rows on a timeline, and a button for the rest
    const filter = el('input', { class: 'a-input', type: 'search', placeholder: 'Filter analyses…', 'aria-label': 'Filter analyses by name or type', autocomplete: 'off', spellcheck: 'false', maxlength: '200' });
    const list = el('ul', { class: 'a-recents__list' });
    const empty = el('p', { class: 'td-recents__empty a-muted' });
    const more = el('button', { class: 'a-btn a-btn--sm td-recents__more', type: 'button', onclick: () => { state.shown += PAGE; draw(); } });
    const announce = el('div', { class: 'a-sr-only', role: 'status', 'aria-live': 'polite' });
    const section = el('section', { class: 'a-recents td-recents', 'aria-labelledby': 'td-recents-title' },
      el('div', { class: 'td-recents__head' },
        el('h2', { class: 'a-recents__title', id: 'td-recents-title' }, icon('clock', { size: 14 }), 'Recent analyses'),
        el('div', { class: 'td-search' }, icon('search', { size: 15 }), filter)),
      list, empty, more, announce);
    root.appendChild(section);

    const count = el('span');
    shell.setViews({
      ariaLabel: 'Order of the analyses', active: home.sort,
      items: [{ id: 'newest', label: 'Newest', icon: 'clock' }, { id: 'risk', label: 'Highest risk', icon: 'alert' }],
      onChange: (id) => { home.sort = id; state.shown = PAGE; draw(); },
    });
    shell.setSubbarEnd([el('span', { class: 'a-pill', title: 'Analyses kept in memory by the server' }, icon('layers', { size: 14 }), count)]);

    let known = new Set(store.items.map((s) => s.id)); // what the page has seen, so only analyses that arrive later flash
    function draw() {
      const needle = state.q.toLowerCase();
      let items = store.items.filter((s) => !needle || `${s.name} ${s.typeLabel}`.toLowerCase().indexOf(needle) >= 0);
      if (home.sort === 'risk') items = items.slice().sort((a, b) => b.risk.score - a.risk.score || byNewest(a, b));
      const shown = items.slice(0, state.shown);
      const rows = [];
      pending.forEach((p, id) => rows.push(pendingRow(p.type, p.data, () => { pending.delete(id); draw(); })));
      shown.forEach((s) => {
        const row = recentRow(s);
        if (!known.has(s.id)) row.classList.add('is-new');
        rows.push(row);
      });
      known = new Set(store.items.map((s) => s.id));
      // rebuilding the rows must not throw away the keyboard focus
      const focused = document.activeElement && list.contains(document.activeElement) ? document.activeElement : null;
      const focusRow = focused && focused.closest('li') ? focused.closest('li').getAttribute('data-id') : null;
      const focusTag = focused ? focused.tagName.toLowerCase() : '';
      list.replaceChildren(...rows);
      if (focusRow) {
        const target = Array.from(list.children).find((li) => li.getAttribute('data-id') === focusRow);
        const control = target && target.querySelector(focusTag);
        if (control) control.focus({ preventScroll: true });
      }
      list.hidden = !rows.length;
      empty.hidden = rows.length > 0;
      empty.textContent = store.items.length ? `No analysis matches “${state.q}”.` : 'No analyses yet. Drop a file above, or run examples/upload-samples.sh against this server.';
      const left = items.length - shown.length;
      more.hidden = left <= 0;
      more.textContent = `Show ${fmt.int(Math.min(PAGE, left))} more (${fmt.int(left)} left)`;
      count.textContent = plural(store.items.length);
    }
    filter.addEventListener('input', A.debounce(() => { state.q = filter.value.trim(); state.shown = PAGE; draw(); }, 120));
    store.listeners.add(draw);
    draw();
    // "3m ago" stays true without rebuilding the rows
    const tick = setInterval(() => list.querySelectorAll('time[datetime]').forEach((t) => { t.textContent = fmt.relative(new Date(t.getAttribute('datetime'))); }), 30000);

    const onEvent = (type, d) => {
      if (type === 'analysis.completed') { pending.delete(d.id); announce.textContent = `${vis(d.name)} analysed: risk ${(d.risk || {}).score}, ${vis((d.risk || {}).label)}.`; return; }
      pending.set(d.id, { type, data: d });
      announce.textContent = type === 'analysis.failed' ? `${vis(d.name)} failed: ${vis(d.error)}` : `Analysing ${vis(d.name)}.`;
      draw();
    };
    eventListeners.add(onEvent);
    document.title = 'teardown';
    return { destroy() { store.listeners.delete(draw); eventListeners.delete(onEvent); clearInterval(tick); uploads.el.remove(); } };
  }

  /* ───────────────────────── report ───────────────────────── */
  const crumbsFor = (last) => ['teardown', { label: 'Analyses', href: '#/' }, last];

  function showError(root, err) {
    const box = el('div', { class: 'td-error' });
    root.replaceChildren(box);
    shell.setSubbarEnd([]);
    shell.setCrumbs(crumbsFor(err.status === 404 ? 'Not found' : 'Error'));
    A.empty(box, {
      icon: 'alert', title: err.status === 404 ? 'This analysis is gone' : 'Could not load the analysis', text: err.message,
      action: { label: 'Back to analyses', onClick: () => { location.hash = '#/'; } },
    });
    document.title = 'teardown';
  }

  async function showReport(id, token) {
    const root = el('div');
    view.replaceChildren(root);
    shell.setCrumbs(crumbsFor('Report'));
    shell.setSubbarEnd([el('span', { class: 'a-pill' }, 'Loading…')]); // keeps the sub bar (and the page) from jumping when the report arrives
    const sk = el('div', { class: 'td-loading' });
    A.skeleton(sk, { lines: 2, height: '34px' });
    A.skeleton(sk, { lines: 6, height: '18px' });
    root.appendChild(sk);
    let rep;
    try { rep = await api.get(id); } catch (err) { if (token === routeToken) showError(root, err); return { destroy() {} }; }
    if (token !== routeToken) return { destroy() {} };
    sk.remove();

    const name = (rep.file && rep.file.name) || 'report';
    shell.setCrumbs(crumbsFor(vis(name)));
    const download = el('a', { class: 'a-btn a-btn--sm', href: `/api/analyses/${id}`, download: `${name.replace(/[^\w.-]+/g, '_')}.report.json` }, icon('download', { size: 15 }), 'JSON');
    const remove = el('button', { class: 'a-btn a-btn--sm', type: 'button', onclick: () => confirmDelete({ id, name }).then((ok) => { if (ok) location.hash = '#/'; }) }, icon('trash', { size: 15 }), 'Delete');
    const report = V.render(root, rep, { actions: [download, remove], stringsSource: (q) => api.strings(id, q) });
    V.dock(shell, report);
    const commands = report.commands.concat([
      { id: 'report:delete', label: 'Delete this analysis…', group: 'This report', hint: 'danger', keywords: 'remove', run: () => remove.click() },
    ]);
    A.cmdk.register(commands);
    document.title = `${vis(name)} · teardown`;
    return { destroy() { A.cmdk.unregister(commands.map((c) => c.id)); report.destroy(); } };
  }

  /* ───────────────────────── router ───────────────────────── */
  async function route() {
    const token = ++routeToken;
    if (current) { current.destroy(); current = null; }
    shell.setViews(null);
    shell.setTabs(null);
    shell.setSubbarEnd([]);
    const m = /^#\/analysis\/(.+)$/.exec(location.hash);
    let next;
    if (m && ID.test(m[1])) next = await showReport(m[1], token);
    else if (m) { next = { destroy() {} }; showError(view, new ApiError(404, 'not_found', 'That is not an analysis id. Open one from the list.')); }
    else next = showHome();
    if (token !== routeToken) { next.destroy(); return; }
    current = next;
    window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
    // a new page takes the keyboard to its heading; the first page leaves the natural order (skip link, rail, bars, content)
    const title = document.getElementById('td-title');
    if (title && !firstPage) title.focus({ preventScroll: true });
    firstPage = false;
  }
  window.addEventListener('hashchange', route);

  connect();
  refresh().then(route);
})();
