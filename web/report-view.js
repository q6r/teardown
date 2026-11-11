/* report-view.js: the report page, shared by the dashboard (app.js) and by the single-file
 * `teardown analyze --html` export. A classic script (no modules) that needs aurora.js and
 * aurora-charts.js. Everything that comes out of the analysed file is untrusted: it is only ever
 * handed to Aurora.el (textContent) and passes through vis(), which makes bidirectional controls and
 * other invisible characters visible. No markup is built from data anywhere in this file.
 *
 *   TeardownView.render(parent, report, {
 *     actions:       Node[]                     // buttons for the page header (the host decides)
 *     stringsSource: async ({categories, q, limit, offset}) => ({total, items})   // default: the report's own list
 *   }) -> { el, commands, sections, pills, jumpTo(id), watch(fn), destroy() }
 *
 *   TeardownView.dock(shell, view, { anchors })  // the sections become tab pills in the sub bar of an
 *                                                 // Aurora shell and the facts of the file become pills
 */
(function (root) {
  'use strict';

  const A = root.Aurora;
  const AC = root.AuroraCharts;
  const { el, fmt, icon } = A;
  const View = (root.TeardownView = {});

  /* Kept in step with the Go engine: internal/render has a test that compares these numbers. */
  const PACKING_THRESHOLD = 7.2; // rules.HighEntropySection, bits per byte
  const RISK_BANDS = [20, 45, 70]; // risk label changes at medium, high and critical

  const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
  const RISK = {
    low: { kind: 'good', label: 'Low' },
    medium: { kind: 'warn', label: 'Medium' },
    high: { kind: 'serious', label: 'High' },
    critical: { kind: 'critical', label: 'Critical' },
  };
  const HARDENING = {
    enabled: { kind: 'good', label: 'Enabled' },
    disabled: { kind: 'warn', label: 'Disabled' },
    unknown: { kind: 'info', label: 'Unknown' },
    'n/a': { kind: 'neutral', label: 'Not applicable' },
  };
  // the icon Aurora.badge uses for each status kind, so a pill and a badge read the same
  const STATUS_ICON = { good: 'check-circle', warn: 'alert', serious: 'alert-octagon', critical: 'x-circle', info: 'info', neutral: 'dot' };
  const FORMAT_NAMES = { pe: 'PE', elf: 'ELF', macho: 'Mach-O', go: 'Go build', archive: 'Archive', asar: 'ASAR', wasm: 'WebAssembly', gguf: 'GGUF' };
  const FACT_ORDER = {
    pe: ['kind', 'machine', 'bits', 'subsystem', 'timestamp', 'entryPoint', 'entrySection', 'imageBase', 'signed', 'overlaySize', 'pdbPath', 'dotNet', 'dotNetVersion', 'packerHints'],
    elf: ['class', 'endian', 'osAbi', 'type', 'machine', 'entry', 'linking', 'interpreter', 'needed', 'rpath', 'runpath', 'soname', 'stripped', 'buildId'],
    macho: ['fat', 'primarySlice'],
    go: ['goVersion', 'path', 'goos', 'goarch', 'cgo', 'compiler', 'buildMode'],
    archive: ['kind', 'entryCount', 'totalCompressed', 'totalUncompressed', 'ratio', 'signed', 'encryptedEntries', 'classCount'],
    asar: ['headerSize', 'fileCount', 'totalSize'],
    wasm: ['version', 'functionCount', 'importCount', 'exportCount'],
    gguf: ['version', 'architecture', 'name', 'tensorCount', 'kvCount', 'contextLength', 'parameterCount'],
  };
  const SECTION_LABELS = {
    'td-findings': 'Findings', 'td-hardening': 'Hardening', 'td-entropy': 'Entropy', 'td-sections': 'Sections',
    'td-imports': 'Imports', 'td-strings': 'Strings', 'td-details': 'Format details', 'td-limitations': 'Limitations',
  };

  /* ───────────────────────── helpers ───────────────────────── */
  // Control characters, bidi overrides and zero-width characters, shown as [U+XXXX] instead of acted upon.
  // The character class is built from code points: no escape sequence has to be typed into this file.
  const SUSPECT_RANGES = [[0, 8], [0x0b, 0x1f], [0x7f, 0x9f], [0x61c, 0x61c], [0x200b, 0x200f], [0x2028, 0x202e], [0x2060, 0x2060], [0x2066, 0x2069], [0xfeff, 0xfeff]];
  const SUSPECT = new RegExp('[' + SUSPECT_RANGES.map(([a, b]) => String.fromCharCode(a) + (b > a ? '-' + String.fromCharCode(b) : '')).join('') + ']', 'g');
  const vis = (s) => String(s == null ? '' : s).replace(SUSPECT, (c) => '[U+' + c.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0') + ']');
  const list = (v) => (Array.isArray(v) ? v : []);
  const plural = (n, one, many) => `${fmt.int(n)} ${n === 1 ? one : many || one + 's'}`;
  const sevRank = (s) => { const i = SEVERITIES.indexOf(s); return i < 0 ? SEVERITIES.length : i; };
  const ACRONYMS = { abi: 'ABI', cpu: 'CPU', dex: 'DEX', dll: 'DLL', guid: 'GUID', id: 'ID', kv: 'KV', os: 'OS', pdb: 'PDB', rpath: 'RPATH', runpath: 'RUNPATH', sdk: 'SDK', soname: 'SONAME', tls: 'TLS', url: 'URL', uuid: 'UUID', va: 'VA', vcs: 'VCS' };
  const humanize = (key) => {
    const words = String(key).replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase().split(' ').map((w) => ACRONYMS[w] || w);
    const s = words.join(' ').replace(/^dot net(?![a-z])/, '.NET');
    return s.charAt(0).toUpperCase() + s.slice(1);
  };
  const labelTable = (host, text) => { const t = host.querySelector('table'); if (t) t.setAttribute('aria-label', text); };
  const isScalar = (v) => v === null || ['string', 'number', 'boolean'].indexOf(typeof v) >= 0;
  const isObject = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
  const hex = (n) => '0x' + Math.max(0, Math.round(+n || 0)).toString(16);

  function riskInfo(label) { return RISK[label] || { kind: 'neutral', label: vis(label) }; }
  function riskBadge(risk) {
    const r = riskInfo(risk && risk.label);
    return A.badge(`${fmt.int(risk ? risk.score : 0)} · ${r.label}`, { kind: r.kind, title: `Risk ${risk ? risk.score : 0} of 100 (${r.label.toLowerCase()})` });
  }
  function copyButton(value, label) {
    return el('button', { class: 'a-btn a-btn--ghost a-btn--icon a-btn--sm', type: 'button', title: `Copy ${label}`, 'aria-label': `Copy ${label}`, onclick: () => A.copy(value, { label: `${label} copied` }) }, icon('copy', { size: 15 }));
  }
  function tag(text, extra) { return el('span', { class: extra ? `a-tag ${extra}` : 'a-tag' }, vis(text)); }
  function bulletList(items, cls) { return el('ul', { class: `td-list${cls ? ' ' + cls : ''}` }, items.map((t) => el('li', vis(t)))); }
  function card(id, title, sub, o) {
    o = o || {};
    const head = el('div', { class: 'a-card__head' },
      el('div', null, el('div', { class: 'a-card__title', role: 'heading', 'aria-level': '2', id: `${id}-title` }, title), sub ? el('div', { class: 'a-card__sub' }, sub) : null),
      o.actions ? el('div', { class: 'a-card__actions' }, o.actions) : null);
    const body = el('div', { class: o.flush ? 'td-flush' : 'a-card__body' });
    const node = el('section', { class: `a-card a-reveal${o.flush ? ' a-card--flush' : ''}`, id, tabindex: '-1', 'aria-labelledby': `${id}-title` }, head, body);
    return { el: node, body };
  }

  /* ───────────────────────── derived facts ───────────────────────── */
  // The import rules cite the APIs they matched as "[role: ]library!Function" evidence lines; that is how
  // the imports list knows which functions to highlight, without a second list that could drift.
  function citedImports(rep) {
    const cited = new Map();
    list(rep.findings).forEach((f) => {
      if (f.category !== 'imports') return;
      list(f.evidence).forEach((line) => {
        const text = String(line);
        const m = /(\S+)!(\S+)\s*$/.exec(text);
        if (!m) return;
        const role = text.slice(0, m.index).replace(/:\s*$/, '');
        const key = `${m[1]}!${m[2]}`.toLowerCase();
        const entry = cited.get(key) || { findings: [], rank: SEVERITIES.length };
        entry.findings.push({ id: f.id, severity: f.severity, role });
        entry.rank = Math.min(entry.rank, sevRank(f.severity));
        cited.set(key, entry);
      });
    });
    return cited;
  }
  const citation = (cited, lib, fn) => cited.get(`${lib}!${fn}`.toLowerCase()) || cited.get(`${fn}`.toLowerCase());

  function stringCounts(rep) {
    const by = (rep.strings && rep.strings.byCategory) || {};
    const total = (rep.strings && rep.strings.total) || 0;
    return { by, total, secrets: by.secret || 0, plain: by.plain || 0, classified: Math.max(0, total - (by.plain || 0)) };
  }

  function collectFacts(obj, path, depth, rows, tables) {
    Object.keys(obj).forEach((k) => {
      const v = obj[k];
      const label = path ? `${path} › ${humanize(k)}` : humanize(k);
      if (v === null || v === '' || v === undefined) return;
      if (Array.isArray(v)) {
        if (!v.length) return;
        if (v.every(isScalar)) rows.push([label, v.slice(0, 16).map(scalarText).join(', ') + (v.length > 16 ? ` … +${v.length - 16} more` : '')]);
        else if (v.every(isObject)) tables.push([label, v]);
        else rows.push([label, plural(v.length, 'item')]);
      } else if (isObject(v)) {
        if (!Object.keys(v).length) return;
        if (depth < 2) collectFacts(v, label, depth + 1, rows, tables);
        else rows.push([label, plural(Object.keys(v).length, 'key')]);
      } else rows.push([label, scalarText(v)]);
    });
  }
  function scalarText(v) {
    if (typeof v === 'boolean') return v ? 'yes' : 'no';
    if (typeof v === 'number') return Number.isInteger(v) ? (Math.abs(v) >= 10000 ? fmt.int(v) : String(v)) : fmt.number(v, 3);
    return vis(v);
  }
  function orderedKeys(format, obj) {
    const first = FACT_ORDER[format] || [];
    const keys = Object.keys(obj);
    return first.filter((k) => keys.indexOf(k) >= 0).concat(keys.filter((k) => first.indexOf(k) < 0).sort());
  }

  /* ───────────────────────── sections of the page ───────────────────────── */
  function headerBlock(rep, o) {
    const t = rep.type || {};
    const when = rep.generatedAt ? fmt.date(new Date(rep.generatedAt), { time: true }) : '';
    const meta = [vis(t.label || 'Unknown type'), fmt.bytes((rep.file || {}).size)];
    if (rep.durationMs != null) meta.push(`analysed in ${fmt.duration(rep.durationMs)}`);
    if (when) meta.push(when);
    const tags = list(t.tags).map((x) => tag(x));
    if (t.confidence) tags.push(el('span', { class: 'a-tag' }, `type confidence ${vis(t.confidence)}`));
    return el('header', { class: 'a-pagehead td-head a-reveal' },
      el('div', { class: 'td-head__main' },
        el('div', { class: 'a-eyebrow' }, [vis((t.id || 'file').toUpperCase()), t.family !== t.id ? vis(t.family || '') : ''].filter(Boolean).join(' · ')),
        el('h1', { class: 'a-h1 td-title', id: 'td-title', tabindex: '-1' }, vis((rep.file || {}).name || 'unnamed file')),
        el('p', { class: 'td-meta' }, meta.map((m, i) => el('span', i ? el('span', { class: 'td-meta__sep', 'aria-hidden': 'true' }, '·') : null, m))),
        tags.length ? el('div', { class: 'a-row td-tags' }, tags) : null),
      o.actions && o.actions.length ? el('div', { class: 'a-pagehead__actions' }, o.actions) : null);
  }

  // The facts of the file as pills for the sub bar: the risk (status icon + label + score), the size, the type.
  function factPills(rep) {
    const risk = rep.risk || { score: 0, label: 'low' };
    const info = riskInfo(risk.label);
    const t = rep.type || {};
    return [
      el('span', { class: 'a-pill td-pill', 'data-kind': info.kind, title: `Risk ${risk.score} of 100 (${info.label.toLowerCase()})` },
        icon(STATUS_ICON[info.kind] || 'dot', { size: 14 }), el('span', info.label), el('span', { class: 'a-pill__count' }, fmt.int(risk.score))),
      el('span', { class: 'a-pill td-pill td-pill--minor', title: 'File size' }, icon('file', { size: 14 }), el('span', fmt.bytes((rep.file || {}).size))),
      el('span', { class: 'a-pill td-pill td-pill--minor', title: 'Detected type' }, icon('tag', { size: 14 }), el('span', vis((t.id || 'file').toUpperCase()))),
    ];
  }

  function riskBlock(rep) {
    const risk = rep.risk || { score: 0, label: 'low', basis: [] };
    const info = riskInfo(risk.label);
    const c = card('td-risk', 'Risk', 'Triage score from 0 to 100');
    c.el.classList.add('td-risk');
    const ringHost = el('div', { class: 'td-risk__ring' });
    c.body.appendChild(ringHost);
    AC.ring(ringHost, {
      value: risk.score, max: 100, size: 200, label: 'Risk score', sublabel: info.label, baseKind: 'good',
      thresholds: RISK_BANDS.map((at, i) => ({ at: at / 100, kind: ['warn', 'serious', 'critical'][i] })),
    });
    const side = el('div', { class: 'td-risk__side' }, el('p', { class: 'td-risk__note a-muted' }, 'A triage aid for ordering a review queue, not a verdict.'));
    if (list(risk.basis).length) A.details(side, { summary: 'How this score is computed', content: bulletList(risk.basis, 'td-list--mono') });
    c.body.appendChild(side);
    return c.el;
  }

  function hashesBlock(rep) {
    const H = rep.hashes || {};
    const rows = [['MD5', H.md5], ['SHA-1', H.sha1], ['SHA-256', H.sha256], ['Imphash', H.imphash]].filter((r) => r[1]);
    const c = card('td-hashes', 'Hashes', 'Computed in one streaming pass');
    A.kv(c.body, rows.map(([label, v]) => [label, el('span', { class: 'td-hash' }, el('code', { class: 'td-hash__value' }, vis(v)), copyButton(v, label))]));
    return c.el;
  }

  function tilesBlock(rep) {
    const wrap = el('div', { class: 'td-tiles' });
    const counts = {};
    list(rep.findings).forEach((f) => { counts[f.severity] = (counts[f.severity] || 0) + 1; });
    const top = SEVERITIES.filter((s) => counts[s]).slice(0, 3).map((s) => `${counts[s]} ${s}`).join(' · ');
    A.stat(wrap, { label: 'Findings', value: list(rep.findings).length, format: 'int', hint: top || 'nothing flagged' });
    const sections = list(rep.sections);
    if (sections.length) {
      const odd = sections.filter((s) => s.suspicious).length;
      A.stat(wrap, { label: 'Sections', value: sections.length, format: 'int', hint: odd ? `${odd} flagged` : 'none flagged' });
    }
    const imports = list(rep.imports);
    if (imports.length) A.stat(wrap, { label: 'Imports', value: imports.reduce((n, i) => n + (i.count || 0), 0), format: 'compact', hint: plural(imports.length, 'library', 'libraries') });
    const sc = stringCounts(rep);
    A.stat(wrap, { label: 'Strings', value: sc.total, format: 'compact', hint: sc.secrets ? `${sc.classified} classified · ${plural(sc.secrets, 'secret')}` : `${fmt.int(sc.classified)} classified` });
    return wrap;
  }

  function findingsBlock(rep) {
    const items = list(rep.findings).slice().sort((a, b) => sevRank(a.severity) - sevRank(b.severity) || String(a.id).localeCompare(String(b.id)));
    const c = card('td-findings', 'Findings', items.length ? 'Sorted by severity. Each one lists its evidence and how it can be wrong.' : null);
    if (!items.length) {
      A.empty(c.body, { title: 'No findings', text: 'None of the rules fired. That is not a guarantee: see the limitations below.', icon: 'check-circle' });
      return c.el;
    }
    const counts = {};
    items.forEach((f) => { counts[f.severity] = (counts[f.severity] || 0) + 1; });
    const entries = [];
    const bar = el('div', { class: 'a-row td-filter', role: 'group', 'aria-label': 'Filter findings by severity' });
    const chips = [];
    const apply = (level) => {
      chips.forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.level === level)));
      entries.forEach((e) => { e.node.hidden = !!level && e.sev !== level; });
    };
    const chip = (level, label, n) => {
      const b = el('button', { class: 'a-chip', type: 'button', 'aria-pressed': String(!level), dataset: { level }, onclick: () => apply(b.getAttribute('aria-pressed') === 'true' && level ? '' : level) }, label, el('span', { class: 'a-chip__n' }, String(n)));
      chips.push(b); bar.appendChild(b);
    };
    chip('', 'All', items.length);
    SEVERITIES.filter((s) => counts[s]).forEach((s) => chip(s, A.severity(s).label, counts[s]));
    if (SEVERITIES.filter((s) => counts[s]).length > 1) c.body.appendChild(bar);
    const holder = el('div', { class: 'td-findings' });
    c.body.appendChild(holder);
    items.forEach((f, i) => {
      const sev = A.severity(f.severity);
      const summary = el('span', { class: 'td-finding__summary' },
        el('span', { class: 'td-finding__line' }, A.badge(sev.label, { kind: sev.kind }), el('span', { class: 'td-finding__title' }, vis(f.title))),
        el('span', { class: 'td-finding__meta' }, tag(f.id), el('span', { class: 'a-tag' }, `${vis(f.confidence)} confidence`)));
      const content = el('div', { class: 'a-stack td-finding__body' },
        list(f.evidence).length ? el('div', null, el('div', { class: 'td-label' }, 'Evidence'), bulletList(f.evidence)) : null,
        list(f.limitations).length ? el('div', null, el('div', { class: 'td-label' }, 'How this can be wrong'), bulletList(f.limitations)) : null);
      const d = A.details(holder, { summary, content, open: items.length <= 2 || i === 0 });
      entries.push({ node: d, sev: f.severity });
    });
    return c.el;
  }

  function hardeningBlock(rep) {
    const items = list(rep.hardening);
    if (!items.length) return null;
    const applicable = items.filter((h) => h.status !== 'n/a');
    const on = applicable.filter((h) => h.status === 'enabled').length;
    const c = card('td-hardening', 'Hardening', 'Exploit mitigations and integrity features');
    if (applicable.length) A.meter(c.body, { value: on, max: applicable.length, label: 'Mitigations enabled', format: (v) => `${v} of ${applicable.length}` });
    c.body.appendChild(el('ul', { class: 'td-checks' }, items.map((h) => {
      const s = HARDENING[h.status] || { kind: 'neutral', label: vis(h.status) };
      return el('li', { class: 'td-check' }, el('div', { class: 'td-check__row' }, el('span', { class: 'td-check__label' }, vis(h.label || h.id)), A.badge(s.label, { kind: s.kind })), h.detail ? el('div', { class: 'td-check__detail a-muted' }, vis(h.detail)) : null);
    })));
    return c.el;
  }

  function entropyBlock(rep, slot, charts) {
    const E = rep.entropy || {};
    const windows = list(E.windows);
    if (!windows.length) return false;
    const size = E.windowSize || 1;
    const span = windows.length * size;
    const unit = span < 4096 ? { size: 1, name: 'B' } : span < 4 * 1048576 ? { size: 1024, name: 'KiB' } : span < 4 * 1073741824 ? { size: 1048576, name: 'MiB' } : { size: 1073741824, name: 'GiB' };
    const high = windows.filter((y) => y >= PACKING_THRESHOLD).length;
    const sub = `${plural(windows.length, 'window')} of ${fmt.bytes(size)} · overall ${fmt.number(E.overall, 2)} of 8 bits per byte${high ? ` · ${high} at or above ${PACKING_THRESHOLD}` : ''}`;
    const c = AC.card(slot, {
      title: 'Entropy profile', subtitle: sub,
      render: (body) => {
        const chart = AC.line(body, {
          series: [{ id: 'entropy', name: 'Entropy', color: 1, values: windows.map((y, i) => ({ x: (i * size) / unit.size, y })) }],
          x: { type: 'linear', label: 'File offset', format: (v) => `${fmt.number(v, Number.isInteger(v) ? 0 : 1)} ${unit.name}`, tooltipFormat: (v) => { const from = Math.round(v * unit.size); return `${fmt.bytes(from)} to ${fmt.bytes(from + size)} (${hex(from)})`; } },
          y: { min: 0, max: 8 },
          valueFormat: (v) => `${fmt.number(v, 2)} bits per byte`,
          area: true, curve: 'linear', legend: 'never', height: 260,
          thresholds: [{ y: PACKING_THRESHOLD, label: `${PACKING_THRESHOLD} · packed or encrypted data reads this high` }],
          ariaLabel: `Entropy by file offset, ${windows.length} windows, overall ${fmt.number(E.overall, 2)} bits per byte`, title: 'Entropy by file offset',
        });
        body.appendChild(el('p', { class: 'td-caption a-muted' }, 'Compressed or encrypted data sits near 8; code and text stay well below. Images, archives and fonts are legitimately high, so a peak is a lead, not a verdict.'));
        return chart;
      },
    });
    c.el.id = 'td-entropy';
    c.el.setAttribute('tabindex', '-1');
    charts.push(c);
    return true;
  }

  function permissions(flags) {
    const set = list(flags);
    const bits = ['R', 'W', 'X'].map((f) => el('span', { class: `td-perm${set.indexOf(f) >= 0 ? ' is-on' : ''}`, 'aria-hidden': 'true' }, f));
    const names = { R: 'read', W: 'write', X: 'execute' };
    const wrap = el('span', { class: 'td-perms', role: 'img', 'aria-label': set.length ? set.map((f) => names[f] || vis(f)).join(', ') : 'no access' }, bits);
    const rwx = set.indexOf('W') >= 0 && set.indexOf('X') >= 0;
    return rwx ? el('span', { class: 'td-perm-cell' }, wrap, A.badge('RWX', { kind: 'warn', title: 'Writable and executable' })) : wrap;
  }

  function sectionsBlock(rep) {
    const sections = list(rep.sections);
    if (!sections.length) return null;
    const odd = sections.filter((s) => s.suspicious).length;
    const c = card('td-sections', 'Sections', `${plural(sections.length, 'section')}${odd ? ` · ${odd} flagged` : ''}`, { flush: true });
    A.table(c.body, {
      dense: true,
      columns: [
        { key: 'name', label: 'Name', sortable: false, format: (v, r) => el('div', { class: 'td-secname' }, el('div', { class: 'a-row td-secname__row' }, el('span', { class: 'a-mono' }, vis(v)), r.suspicious ? A.badge('Flagged', { kind: 'warn', title: list(r.reasons).map(vis).join('; ') }) : null), list(r.reasons).length ? el('ul', { class: 'td-reasons' }, list(r.reasons).map((x) => el('li', vis(x)))) : null) },
        { key: 'virtualSize', label: 'Virtual', align: 'right', format: (v) => fmt.bytes(v) },
        { key: 'rawSize', label: 'Raw', align: 'right', format: (v) => fmt.bytes(v) },
        { key: 'offset', label: 'Offset', align: 'right', mono: true, format: (v) => hex(v) },
        { key: 'entropy', label: 'Entropy', width: '190px', format: (v) => entropyCell(v) },
        { key: 'flagText', label: 'Access', format: (v, r) => permissions(r.flags) },
      ],
      rows: sections.map((s) => Object.assign({ flagText: list(s.flags).join('') }, s)),
    });
    labelTable(c.body, 'Sections of the file');
    return c.el;
  }
  function entropyCell(v) {
    const cell = el('div', { class: 'td-ebar' });
    A.meter(cell, { value: +v || 0, max: 8, thin: true, label: null, thresholds: [{ at: PACKING_THRESHOLD / 8, kind: 'warn' }], format: (x) => fmt.number(x, 2) });
    cell.appendChild(el('span', { class: 'a-num td-ebar__n' }, fmt.number(v, 2)));
    return cell;
  }

  // Chips a page at a time, so a library with hundreds of functions does not make the page endless.
  function pagedChips(host, items, make, page) {
    let shown = 0;
    const more = el('button', { class: 'a-btn a-btn--sm', type: 'button', onclick: () => draw() });
    function draw() {
      const next = items.slice(shown, shown + page);
      next.forEach((item) => host.insertBefore(make(item), more));
      shown += next.length;
      if (shown >= items.length) more.remove();
      else more.textContent = `Show ${fmt.int(Math.min(page, items.length - shown))} more (${fmt.int(items.length - shown)} left)`;
    }
    host.appendChild(more);
    draw();
  }

  function importsBlock(rep) {
    const libs = list(rep.imports);
    const exports = list(rep.exports);
    if (!libs.length && !exports.length) return null;
    const cited = citedImports(rep);
    const total = libs.reduce((n, l) => n + (l.count || 0), 0);
    const decorated = libs.map((l) => {
      const hits = list(l.functions).filter((fn) => { const c = citation(cited, l.library, fn); return c && c.rank <= sevRank('low'); });
      return { lib: l, hits: hits.length };
    }).sort((a, b) => b.hits - a.hits || (b.lib.count || 0) - (a.lib.count || 0) || String(a.lib.library).localeCompare(String(b.lib.library)));
    const hitTotal = decorated.reduce((n, d) => n + d.hits, 0);
    const c = card('td-imports', 'Imports', `${plural(libs.length, 'library', 'libraries')} · ${plural(total, 'function')}${hitTotal ? ` · ${hitTotal} cited by findings` : ''}`);
    const holder = el('div', { class: 'td-imports' });
    c.body.appendChild(holder);
    decorated.forEach((d, i) => {
      const lib = d.lib;
      const content = el('div', { class: 'td-fns' });
      let built = false;
      const fill = () => {
        if (built) return;
        built = true;
        const fns = list(lib.functions);
        const flagged = (fn) => { const hit = citation(cited, lib.library, fn); return hit && hit.rank <= sevRank('low') ? hit : null; };
        const ordered = fns.filter((fn) => flagged(fn)).concat(fns.filter((fn) => !flagged(fn))); // cited functions first
        pagedChips(content, ordered, (fn) => {
          const hit = citation(cited, lib.library, fn);
          if (flagged(fn)) {
            const sev = A.severity(SEVERITIES[hit.rank]);
            return A.badge(vis(fn), { kind: sev.kind, title: hit.findings.map((f) => `${f.id}${f.role ? ': ' + f.role : ''}`).join('; ') });
          }
          return el('span', { class: 'a-tag', title: hit ? hit.findings.map((f) => f.id).join('; ') : null }, vis(fn));
        }, 100);
        if ((lib.count || 0) > fns.length) content.appendChild(el('span', { class: 'a-muted td-more' }, `The report lists ${fmt.int(fns.length)} of ${fmt.int(lib.count)} functions.`));
        if (!fns.length) content.appendChild(el('span', { class: 'a-muted' }, 'No function names were recorded for this library.'));
      };
      const meta = el('span', { class: 'td-tagrow' }, d.hits ? A.badge(`${d.hits} cited`, { kind: 'warn', title: 'Functions that a finding names as evidence' }) : null, el('span', { class: 'a-tag a-num' }, plural(lib.count || 0, 'function')));
      const open = i === 0 && d.hits > 0;
      if (open) fill();
      const det = A.details(holder, { summary: el('span', { class: 'a-mono' }, vis(lib.library)), meta, content, open });
      det.addEventListener('toggle', () => { if (det.open) fill(); });
    });
    if (exports.length) {
      const content = el('div', { class: 'td-fns' });
      pagedChips(content, exports, (n) => el('span', { class: 'a-tag' }, vis(n)), 100);
      A.details(holder, { summary: 'Exports', meta: el('span', { class: 'a-tag a-num' }, plural(exports.length, 'name')), content });
    }
    return c.el;
  }

  /* strings: a part-to-whole bar, category chips, a search box and a table fed by a pluggable source */
  function localStrings(rep) {
    return (q) => {
      const needle = (q.q || '').toLowerCase();
      const hits = list(rep.strings && rep.strings.items).filter((it) => (!q.categories.length || q.categories.indexOf(it.category) >= 0) && (!needle || String(it.value).toLowerCase().indexOf(needle) >= 0));
      return Promise.resolve({ total: hits.length, items: hits.slice(q.offset, q.offset + q.limit) });
    };
  }

  function stringsBlock(rep, source) {
    const S = rep.strings || {};
    const sc = stringCounts(rep);
    if (!sc.total) return null;
    const c = card('td-strings', 'Strings', `${plural(sc.total, 'string')} found · minimum length ${S.minLength || 5}${S.truncated && list(S.items).length < sc.total ? ` · ${fmt.int(list(S.items).length)} kept in this report, classified ones first` : ''}`);
    const cats = Object.keys(sc.by).filter((k) => sc.by[k] > 0).sort((a, b) => (sc.by[b] - sc.by[a]) || a.localeCompare(b));
    const interesting = cats.filter((k) => k !== 'plain');
    if (interesting.length) {
      const head = interesting.slice(0, 5).map((k) => ({ name: k, value: sc.by[k] }));
      const rest = interesting.slice(5).reduce((n, k) => n + sc.by[k], 0);
      if (rest) head.push({ name: 'Other', value: rest });
      c.body.appendChild(el('div', { class: 'td-segwrap' }, el('div', { class: 'td-label' }, `Classified strings by category${sc.plain ? ` (${fmt.int(sc.plain)} plain strings not shown)` : ''}`), (() => { const h = el('div'); A.segbar(h, { parts: head, tall: true, valueFormat: fmt.int }); return h; })()));
    }

    const state = { cats: new Set(), q: '', offset: 0, limit: 50, total: 0, seq: 0 };
    const tools = el('div', { class: 'td-strtools' });
    const search = el('input', { class: 'a-input', type: 'search', placeholder: 'Search strings…', 'aria-label': 'Search strings', autocomplete: 'off', spellcheck: 'false', maxlength: '200' });
    tools.appendChild(el('div', { class: 'td-search' }, icon('search', { size: 15 }), search));
    const chipRow = el('div', { class: 'a-row td-filter', role: 'group', 'aria-label': 'Filter strings by category' });
    const chipEls = {};
    const mkChip = (key, label, n) => {
      const b = el('button', { class: 'a-chip', type: 'button', 'aria-pressed': String(key === ''), onclick: () => toggle(key) }, label, el('span', { class: 'a-chip__n' }, fmt.compact(n)));
      chipEls[key] = b; chipRow.appendChild(b);
    };
    mkChip('', 'All', sc.total);
    cats.forEach((k) => mkChip(k, k, sc.by[k]));
    tools.appendChild(chipRow);
    c.body.appendChild(tools);

    const tableHost = el('div', { class: 'td-strtable' });
    const status = el('div', { class: 'a-muted', 'aria-live': 'polite' });
    const prev = el('button', { class: 'a-btn a-btn--sm', type: 'button', onclick: () => { state.offset = Math.max(0, state.offset - state.limit); load(); } }, 'Previous');
    const next = el('button', { class: 'a-btn a-btn--sm', type: 'button', onclick: () => { state.offset += state.limit; load(); } }, 'Next');
    const pager = el('div', { class: 'a-pager td-pager' }, status, prev, next);
    c.body.appendChild(tableHost);
    c.body.appendChild(pager);

    const table = A.table(tableHost, {
      dense: true, empty: { title: 'No strings match', text: 'Try another category or search term.' },
      columns: [
        { key: 'offset', label: 'Offset', sortable: false, mono: true, align: 'right', width: '110px', format: (v) => hex(v) },
        { key: 'encoding', label: 'Encoding', sortable: false, width: '100px', format: (v) => tag(v === 'utf16le' ? 'UTF-16LE' : String(v).toUpperCase()) },
        { key: 'category', label: 'Category', sortable: false, width: '130px', format: (v) => (v === 'secret' ? A.badge('secret', { kind: 'serious' }) : tag(v)) },
        { key: 'value', label: 'Value', sortable: false, format: (v, r) => el('div', { class: 'td-strval' }, el('span', { class: 'td-strval__text' }, vis(v)), r.redacted ? el('span', { class: 'a-tag td-redacted', title: 'The engine hides the middle of secrets: only the first four characters and the length are kept.' }, icon('lock', { size: 12 }), `redacted${r.kind ? ' · ' + vis(r.kind) : ''}`) : null) },
      ],
      rows: [],
    });
    labelTable(tableHost, 'Strings found in the file');

    function toggle(key) {
      if (key === '') state.cats.clear();
      else if (state.cats.has(key)) state.cats.delete(key); else state.cats.add(key);
      Object.keys(chipEls).forEach((k) => chipEls[k].setAttribute('aria-pressed', String(k === '' ? state.cats.size === 0 : state.cats.has(k))));
      state.offset = 0;
      load();
    }
    function load() {
      const mine = ++state.seq;
      tableHost.classList.add('a-refreshing');
      source({ categories: Array.from(state.cats), q: state.q, limit: state.limit, offset: state.offset }).then((res) => {
        if (mine !== state.seq) return;
        state.total = res.total;
        table.update(list(res.items));
        const from = res.total ? state.offset + 1 : 0;
        const to = Math.min(res.total, state.offset + state.limit);
        status.textContent = `${fmt.int(from)}–${fmt.int(to)} of ${fmt.int(res.total)}`;
        prev.disabled = state.offset === 0;
        next.disabled = state.offset + state.limit >= res.total;
        tableHost.classList.remove('a-refreshing');
      }, (err) => {
        if (mine !== state.seq) return;
        tableHost.classList.remove('a-refreshing');
        status.textContent = 'Could not load strings.';
        A.toast(err && err.message ? err.message : 'Could not load strings.', { kind: 'critical' });
      });
    }
    search.addEventListener('input', A.debounce(() => { state.q = search.value.trim(); state.offset = 0; load(); }, 180));
    load();
    return c.el;
  }

  function detailsBlock(rep) {
    const details = rep.details || {};
    const formats = Object.keys(details).filter((k) => isObject(details[k]));
    if (!formats.length) return null;
    const c = card('td-details', 'Format details', 'Facts the format parsers read from the file');
    const holder = el('div', { class: 'td-formats' });
    c.body.appendChild(holder);
    formats.forEach((format) => {
      const obj = details[format];
      const ordered = {};
      orderedKeys(format, obj).forEach((k) => { ordered[k] = obj[k]; });
      const rows = []; const tables = [];
      collectFacts(ordered, '', 0, rows, tables);
      const content = el('div', { class: 'a-stack' });
      if (rows.length) A.kv(content, rows);
      tables.forEach(([label, items]) => {
        const keys = Object.keys(items[0]).filter((k) => isScalar(items[0][k])).slice(0, 6);
        if (!keys.length) return;
        const host = el('div', { class: 'td-subtable' });
        A.details(content, { summary: `${label}`, meta: el('span', { class: 'a-tag a-num' }, plural(items.length, 'item')), content: host });
        A.table(host, { dense: true, pageSize: 10, columns: keys.map((k) => ({ key: k, label: humanize(k), sortable: false, format: (v) => scalarText(v) })), rows: items.slice(0, 500) });
        labelTable(host, label);
      });
      A.details(holder, { summary: FORMAT_NAMES[format] || humanize(format), meta: el('span', { class: 'a-tag a-num' }, plural(rows.length + tables.length, 'fact')), content, open: formats.length === 1 && rows.length + tables.length <= 14 });
    });
    return c.el;
  }

  function limitationsBlock(rep) {
    const items = list(rep.limitations);
    if (!items.length) return null;
    const c = card('td-limitations', 'Limitations', 'What this analysis could not see');
    c.body.appendChild(bulletList(items));
    return c.el;
  }

  /* ───────────────────────── page ───────────────────────── */
  View.riskBadge = riskBadge;
  View.vis = vis;

  View.render = function (parent, rep, o) {
    o = o || {};
    const charts = [];
    const stops = [];
    const wrap = el('div', { class: 'td-view' });
    parent.appendChild(wrap);
    wrap.appendChild(headerBlock(rep, o));

    // the first row: the risk ring beside the tiles and the hashes; below it every section takes the full
    // width, one under the other, in the order of the pills
    const present = [];
    const put = (node) => { if (!node) return false; wrap.appendChild(node); present.push(node.id); return true; };
    const top = el('div', { class: 'td-top' });
    wrap.appendChild(top);
    top.appendChild(riskBlock(rep));
    const right = el('div', { class: 'td-right' });
    top.appendChild(right);
    right.appendChild(tilesBlock(rep));
    right.appendChild(hashesBlock(rep));

    put(findingsBlock(rep));
    put(hardeningBlock(rep));
    if (entropyBlock(rep, wrap, charts)) present.push('td-entropy');
    put(sectionsBlock(rep));
    put(importsBlock(rep));
    put(stringsBlock(rep, o.stringsSource || localStrings(rep)));
    put(detailsBlock(rep));
    put(limitationsBlock(rep));

    // the sections that exist, in page order, with the number each pill shows (none where a count means nothing)
    const sc = stringCounts(rep);
    const counts = {
      'td-findings': list(rep.findings).length, 'td-hardening': list(rep.hardening).length, 'td-sections': list(rep.sections).length,
      'td-imports': list(rep.imports).length, 'td-strings': sc.total, 'td-limitations': list(rep.limitations).length,
    };
    const sections = Object.keys(SECTION_LABELS).filter((id) => present.indexOf(id) >= 0)
      .map((id) => ({ id, label: SECTION_LABELS[id], count: counts[id] ? fmt.compact(counts[id]) : null }));

    const jumpTo = (id) => {
      const target = wrap.querySelector(`#${id}`);
      if (!target) return;
      target.scrollIntoView({ behavior: A.reducedMotion() ? 'auto' : 'smooth', block: 'start' });
      target.focus({ preventScroll: true });
    };

    // Reports which section the reader is in, so the host can mark its pill: the section that crosses a line just
    // under the sticky bars (where a jump puts the top of its target), the last one passed when the line falls
    // between two sections, and the last section once the page is scrolled to the bottom.
    const watch = (fn) => {
      const targets = sections.map((s) => wrap.querySelector(`#${s.id}`)).filter(Boolean);
      if (!targets.length) return () => {};
      let current = '';
      const check = () => {
        const chrome = root.document.querySelector('.a-chrome');
        const line = (chrome ? chrome.getBoundingClientRect().bottom : 0) + 40;
        let idx = 0;
        targets.forEach((t, i) => { if (t.getBoundingClientRect().top <= line) idx = i; });
        const doc = root.document.documentElement;
        if (root.scrollY > 0 && root.innerHeight + root.scrollY >= doc.scrollHeight - 2) idx = targets.length - 1;
        if (targets[idx].id !== current) { current = targets[idx].id; fn(current); }
      };
      const onScroll = A.throttle(check, 80);
      root.addEventListener('scroll', onScroll, { passive: true });
      root.addEventListener('resize', onScroll);
      check();
      const stop = () => { root.removeEventListener('scroll', onScroll); root.removeEventListener('resize', onScroll); };
      stops.push(stop);
      return stop;
    };

    const H = rep.hashes || {};
    const commands = sections.map((s) => ({ id: `jump:${s.id}`, label: `Jump to ${s.label}`, group: 'This report', hint: 'section', keywords: 'scroll go section', run: () => jumpTo(s.id) }));
    [['SHA-256', H.sha256], ['SHA-1', H.sha1], ['MD5', H.md5]].forEach(([label, v]) => {
      if (v) commands.push({ id: `copy:${label}`, label: `Copy ${label}`, group: 'This report', hint: 'clipboard', keywords: 'hash digest', run: () => A.copy(v, { label: `${label} copied` }) });
    });
    A.reveal(wrap);
    return {
      el: wrap, commands, sections, pills: factPills(rep), jumpTo, watch,
      destroy() { stops.forEach((stop) => stop()); charts.forEach((c) => { if (c.chart && c.chart.destroy) c.chart.destroy(); }); wrap.remove(); },
    };
  };

  /* The sub bar of the Aurora shell: one tab pill per section (with its count) that takes the reader there and
   * follows the scroll, and the facts of the file (risk, size, type) as pills at the right. Without `anchors` the
   * pills are buttons that scroll (the dashboard routes on the hash, so a #fragment link would leave the page);
   * with `anchors` they are plain #fragment links, which keep working in the single-file export. */
  View.dock = function (shell, view, o) {
    o = o || {};
    const anchors = !!o.anchors;
    const items = view.sections.map((s) => ({ id: s.id, label: s.label, count: s.count, href: anchors ? `#${s.id}` : undefined }));
    const tabs = shell.setTabs({ ariaLabel: 'Report sections', items, active: items.length ? items[0].id : undefined, onChange: anchors ? undefined : (id) => view.jumpTo(id) });
    if (tabs && !anchors) {
      // Aurora only reports a change of tab, and a click on the pill that is already marked must scroll as well.
      // A capturing listener runs before Aurora's own handler has moved the mark.
      tabs.el.addEventListener('click', (e) => {
        const pill = e.target && e.target.closest ? e.target.closest('[data-id]') : null;
        if (pill && pill.classList.contains('is-active')) view.jumpTo(pill.getAttribute('data-id'));
      }, true);
    }
    shell.setSubbarEnd(view.pills);
    if (tabs) view.watch((id) => tabs.select(id, true));
    return tabs;
  };
})(typeof window !== 'undefined' ? window : globalThis);
