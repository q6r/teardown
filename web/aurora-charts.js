/*! Aurora charts — window.AuroraCharts · MIT
 *  Dependency-free SVG charts that follow the data-viz rules: validated categorical slots in fixed
 *  order, 2px lines, bars <= 24px with a 4px rounded data end, hairline solid grid, text in ink
 *  tokens, legend for >= 2 series, crosshair/per-mark tooltips, keyboard parity and a table view for
 *  every chart. Requires aurora.js. Colours are CSS variables, so theme switches need no redraw. */
(function (root) {
  'use strict';

  const doc = root.document;
  const A = root.Aurora;
  if (!A) throw new Error('aurora.js must be loaded before aurora-charts.js');
  const { el, svg, fmt } = A;
  const AC = (root.AuroraCharts = root.AuroraCharts || {});
  AC.version = '2.0.0';

  /* ───────────────────────── helpers ───────────────────────── */
  const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
  const finite = (n) => typeof n === 'number' && isFinite(n);
  const STATUS_VARS = { good: 'var(--good)', warn: 'var(--warn)', serious: 'var(--serious)', critical: 'var(--critical)' };
  // 1..8 → categorical slot; 'good'|'warn'|'serious'|'critical' → status colour (only for series that MEAN health)
  const slotVar = (i) => (typeof i === 'string' && STATUS_VARS[i] ? STATUS_VARS[i] : `var(--series-${clamp(Math.round(+i) || 1, 1, 8)})`);
  const tw = (s, px) => String(s).length * (px || 6.4);
  const truncate = (s, maxChars) => { s = String(s); return s.length <= maxChars ? s : `${s.slice(0, Math.max(1, maxChars - 1))}…`; };
  // characters that fit in px; the epsilon stops 9 * 6.4 / 6.4 = 8.999999999999998 from costing a character
  const fitChars = (px) => Math.floor(px / 6.4 + 1e-6);
  const defaultValueFormat = (v) => (Number.isInteger(v) ? fmt.int(v) : fmt.number(v, 2));
  const MIN = 60e3; const HOUR = 36e5; const DAY = 864e5;
  let gradientSeq = 0;
  AC.slot = slotVar;

  function niceStep(range, count) {
    const raw = range / Math.max(1, count);
    const pow = Math.pow(10, Math.floor(Math.log10(raw)));
    const f = raw / pow;
    return (f < 1.5 ? 1 : f < 3 ? 2 : f < 7 ? 5 : 10) * pow;
  }
  function niceScale(min, max, count, fixedMax) {
    if (min === max) max = min + 1;
    const step = niceStep(max - min, count);
    const lo = Math.floor(min / step + 1e-9) * step;
    const hi = fixedMax ? max : Math.ceil(max / step - 1e-9) * step;
    const ticks = [];
    for (let v = lo; v <= hi + step / 2; v += step) ticks.push(+v.toFixed(10));
    return { min: lo, max: hi, ticks };
  }
  // utc = true lays the ticks out on UTC boundaries instead of the viewer's local ones.
  function timeTicks(min, max, n, utc) {
    const span = max - min;
    const steps = [MIN, 5 * MIN, 15 * MIN, 30 * MIN, HOUR, 3 * HOUR, 6 * HOUR, 12 * HOUR, DAY, 2 * DAY, 7 * DAY, 14 * DAY];
    const ticks = [];
    const step = steps.find((s) => span / s <= n);
    if (step) {
      const tz = utc ? 0 : -new Date(min).getTimezoneOffset() * MIN;
      for (let t = Math.ceil((min + tz) / step) * step - tz; t <= max; t += step) ticks.push(t);
      return { ticks, step, months: 0 };
    }
    const months = [1, 2, 3, 6, 12, 24, 60].find((m) => span / (m * 30.4 * DAY) <= n) || 120;
    const d = new Date(min);
    const year = utc ? d.getUTCFullYear() : d.getFullYear();
    let month = (utc ? d.getUTCMonth() : d.getMonth()) + 1;
    const first = (mo) => (utc ? Date.UTC(year, mo, 1) : +new Date(year, mo, 1));
    for (let cur = first(month); cur <= max; cur = first(month)) { ticks.push(cur); month += months; }
    return { ticks, step: months * 30.4 * DAY, months };
  }
  function tickFormatter(step, months, utc) {
    const mk = (o) => { const f = new Intl.DateTimeFormat(fmt.locale, utc ? Object.assign({ timeZone: 'UTC' }, o) : o); return (t) => f.format(new Date(t)); };
    if (months) return mk({ month: 'short', year: 'numeric' });
    if (step < DAY) return mk({ hour: '2-digit', minute: '2-digit', hour12: false });
    return mk({ month: 'short', day: 'numeric' });
  }
  function monotonePath(pts) {
    const clean = pts.filter((p, i) => i === 0 || p[0] > pts[i - 1][0]);
    const n = clean.length;
    if (n === 0) return '';
    if (n === 1) return `M${clean[0][0]},${clean[0][1]}`;
    if (n === 2) return `M${clean[0][0]},${clean[0][1]}L${clean[1][0]},${clean[1][1]}`;
    const dx = []; const m = []; const t = [];
    for (let i = 0; i < n - 1; i++) { dx[i] = clean[i + 1][0] - clean[i][0]; m[i] = (clean[i + 1][1] - clean[i][1]) / dx[i]; }
    t[0] = m[0]; t[n - 1] = m[n - 2];
    for (let i = 1; i < n - 1; i++) {
      if (m[i - 1] * m[i] <= 0) t[i] = 0;
      else { const w1 = 2 * dx[i] + dx[i - 1]; const w2 = dx[i] + 2 * dx[i - 1]; t[i] = (w1 + w2) / (w1 / m[i - 1] + w2 / m[i]); }
    }
    let d = `M${clean[0][0]},${clean[0][1]}`;
    for (let i = 0; i < n - 1; i++) {
      const h = dx[i];
      d += `C${(clean[i][0] + h / 3).toFixed(2)},${(clean[i][1] + (t[i] * h) / 3).toFixed(2)} ${(clean[i + 1][0] - h / 3).toFixed(2)},${(clean[i + 1][1] - (t[i + 1] * h) / 3).toFixed(2)} ${clean[i + 1][0]},${clean[i + 1][1]}`;
    }
    return d;
  }
  const linearPath = (pts) => pts.map((p, i) => `${i ? 'L' : 'M'}${p[0]},${p[1]}`).join('');
  function barPath(x, y, w, h, r, dir) {
    r = Math.max(0, Math.min(r, w / 2, h / 2));
    if (dir === 'right') return `M${x},${y}H${x + w - r}a${r},${r} 0 0 1 ${r},${r}V${y + h - r}a${r},${r} 0 0 1 ${-r},${r}H${x}Z`;
    if (dir === 'up') return `M${x},${y + h}V${y + r}a${r},${r} 0 0 1 ${r},${-r}H${x + w - r}a${r},${r} 0 0 1 ${r},${r}V${y + h}Z`;
    return `M${x},${y}H${x + w}V${y + h}H${x}Z`;
  }
  function bisect(xs, v) {
    let lo = 0; let hi = xs.length - 1;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (xs[mid] < v) lo = mid + 1; else hi = mid; }
    if (lo > 0 && Math.abs(xs[lo - 1] - v) <= Math.abs(xs[lo] - v)) lo--;
    return lo;
  }

  /* ───────────────────────── shared tooltip ───────────────────────── */
  const Tip = (() => {
    let node = null;
    const ensure = () => { if (!node || !node.isConnected) { node = el('div', { class: 'a-tt', role: 'tooltip' }); doc.body.appendChild(node); } return node; };
    return {
      show(spec, cx, cy) {
        const t = ensure();
        while (t.firstChild) t.removeChild(t.firstChild);
        if (spec.title) t.appendChild(el('div', { class: 'a-tt__title' }, spec.title));
        (spec.rows || []).forEach((r) => t.appendChild(el('div', { class: 'a-tt__row' },
          r.color ? el('span', { class: `a-tt__key${r.shape === 'rect' ? ' a-tt__key--rect' : ''}`, style: { '--c': r.color } }) : null,
          el('span', { class: 'a-tt__name' }, r.name), el('span', { class: 'a-tt__val' }, r.value))));
        if (spec.sub) t.appendChild(el('div', { class: 'a-tt__sub' }, spec.sub));
        t.classList.add('is-on');
        const w = t.offsetWidth; const h = t.offsetHeight;
        let x = cx + 16; let y = cy - h - 14;
        if (x + w > root.innerWidth - 8) x = cx - w - 16;
        if (x < 8) x = 8;
        if (y < 8) y = Math.min(cy + 20, root.innerHeight - h - 8);
        t.style.left = `${Math.round(x)}px`;
        t.style.top = `${Math.round(y)}px`;
      },
      hide() { if (node) node.classList.remove('is-on'); },
    };
  })();

  /* ───────────────────────── legend ───────────────────────── */
  function makeLegend(host, onToggle) {
    let items = [];
    const node = el('div', { class: 'a-legend', role: 'group', 'aria-label': 'Series' });
    host.appendChild(node);
    return {
      el: node,
      set(next) {
        items = next;
        while (node.firstChild) node.removeChild(node.firstChild);
        items.forEach((it) => node.appendChild(el('button', {
          class: 'a-legend__item', type: 'button', 'aria-pressed': String(!it.hidden), title: 'Click to toggle · double-click to isolate',
          onclick: () => onToggle(it.id, 'toggle'), ondblclick: () => onToggle(it.id, 'isolate'),
        }, el('span', { class: `a-legend__key${it.shape === 'rect' ? ' a-legend__key--rect' : ''}`, style: { '--c': it.color } }), it.name)));
      },
      sync(hidden) { Array.from(node.children).forEach((b, i) => b.setAttribute('aria-pressed', String(!hidden.has(items[i].id)))); },
      show(on) { node.hidden = !on; },
    };
  }
  function toggleHidden(hidden, allIds, id, mode) {
    if (mode === 'isolate') {
      const onlyThis = allIds.every((x) => (x === id ? !hidden.has(x) : hidden.has(x)));
      hidden.clear();
      if (!onlyThis) allIds.forEach((x) => { if (x !== id) hidden.add(x); });
    } else if (hidden.has(id)) hidden.delete(id); else if (allIds.length - hidden.size > 1) hidden.add(id);
  }

  /* ───────────────────────── chart scaffold ───────────────────────── */
  function scaffold(parent) {
    const host = el('div', { class: 'a-chart' });
    const legendHost = el('div');
    const sr = el('div', { class: 'a-sr-only', 'aria-live': 'polite' });
    host.appendChild(legendHost);
    host.appendChild(sr);
    parent.appendChild(host);
    return { host, legendHost, sr };
  }
  function swap(host, anchor, prev, next) {
    const focused = prev && doc.activeElement === prev;
    if (prev && prev.parentNode === host) host.replaceChild(next, prev); else host.insertBefore(next, anchor);
    if (focused) next.focus();
    return next;
  }
  function watch(host, render) {
    if (!root.ResizeObserver) return null;
    let last = 0; let raf = 0;
    const ro = new root.ResizeObserver(() => {
      const w = Math.round(host.clientWidth);
      if (w === last) return;
      last = w;
      root.cancelAnimationFrame(raf);
      raf = root.requestAnimationFrame(render);
    });
    ro.observe(host);
    return ro;
  }
  const emptyBox = (text) => el('div', { class: 'a-chart-empty' }, text || 'No data for this range');

  /* ───────────────────────── line / area ───────────────────────── */
  function line(parent, o) {
    const { host, legendHost, sr } = scaffold(parent);
    let opts = o || {};
    const hidden = new Set();
    let animateNext = opts.animate !== false;
    let svgEl = null; let model = null; let activeIdx = -1;
    const gid = `ac-grad-${++gradientSeq}`;
    const legend = makeLegend(legendHost, (id, mode) => {
      toggleHidden(hidden, (opts.series || []).map((s, i) => (s.id != null ? s.id : `s${i}`)), id, mode);
      legend.sync(hidden); animateNext = false; render();
    });

    function normalize() {
      const xt = (opts.x && opts.x.type) || 'time';
      const cats = [];
      const toX = (v) => {
        if (xt === 'time') return v instanceof Date ? +v : +new Date(v);
        if (xt === 'band') { let i = cats.indexOf(String(v)); if (i < 0) { cats.push(String(v)); i = cats.length - 1; } return i; }
        return +v;
      };
      const series = (opts.series || []).map((s, i) => {
        const pts = (s.values || []).map((p) => ({ x: toX(p.x), y: +p.y })).filter((p) => finite(p.x) && finite(p.y)).sort((a, b) => a.x - b.x);
        return { id: s.id != null ? s.id : `s${i}`, name: s.name != null ? String(s.name) : `Series ${i + 1}`, slot: s.color || i + 1, pts, map: new Map(pts.map((p) => [p.x, p.y])) };
      });
      return { xt, cats, series };
    }
    function render() {
      const width = Math.max(260, Math.round(host.clientWidth || 640));
      const height = opts.height || 260;
      const m = normalize();
      const vis = m.series.filter((s) => !hidden.has(s.id));
      const xsSet = new Set();
      vis.forEach((s) => s.pts.forEach((p) => xsSet.add(p.x)));
      const xs = Array.from(xsSet).sort((a, b) => a - b);
      const allPts = vis.reduce((n, s) => n + s.pts.length, 0);
      legend.set(m.series.map((s) => ({ id: s.id, name: s.name, color: slotVar(s.slot), shape: 'line', hidden: hidden.has(s.id) })));
      legend.show(opts.legend === 'always' || (opts.legend !== 'never' && m.series.length >= 2));
      Tip.hide(); activeIdx = -1;

      if (!allPts) {
        const box = swap(host, legendHost, svgEl, emptyBox(opts.emptyText));
        svgEl = box; model = { m, xs, vis, sx: null }; sr.textContent = ''; return;
      }
      let xmin = m.xt === 'band' ? -0.5 : xs[0]; let xmax = m.xt === 'band' ? Math.max(0, m.cats.length - 1) + 0.5 : xs[xs.length - 1];
      if (xmin === xmax) { const pad = m.xt === 'time' ? HOUR : 1; xmin -= pad; xmax += pad; }
      const ys = []; vis.forEach((s) => s.pts.forEach((p) => ys.push(p.y)));
      const dMin = Math.min.apply(null, ys); const dMax = Math.max.apply(null, ys);
      const yo = opts.y || {};
      const lo = yo.min != null ? yo.min : dMin >= 0 ? 0 : dMin;
      const hi = yo.max != null ? yo.max : dMax <= lo ? lo + 1 : dMax;
      const ysc = niceScale(lo, hi, 5, yo.max != null);
      const ymin = yo.min != null ? yo.min : ysc.min; const ymax = yo.max != null ? yo.max : ysc.max;
      const yf = yo.format || fmt.compact;
      const vf = opts.valueFormat || yo.tooltipFormat || defaultValueFormat;
      const endLabels = !!opts.endLabels;
      const margin = { top: 12, right: endLabels ? 92 : 16, bottom: 28, left: Math.max(34, Math.max.apply(null, ysc.ticks.map((t) => tw(yf(t), 6.6))) + 16) };
      const iw = width - margin.left - margin.right; const ih = height - margin.top - margin.bottom;
      const sx = (x) => margin.left + ((x - xmin) / (xmax - xmin)) * iw;
      const sy = (y) => margin.top + ih - ((y - ymin) / (ymax - ymin || 1)) * ih;

      const s = svg('svg', { width, height, viewBox: `0 0 ${width} ${height}`, role: 'img', tabindex: '0', 'aria-label': opts.ariaLabel || opts.title || 'Line chart' });
      const defs = svg('defs');
      s.appendChild(defs);
      ysc.ticks.filter((t) => t >= ymin - 1e-9 && t <= ymax + 1e-9).forEach((t) => {
        s.appendChild(svg('line', { class: 'a-grid-line', x1: margin.left, x2: width - margin.right, y1: sy(t), y2: sy(t) }));
        s.appendChild(svg('text', { x: margin.left - 8, y: sy(t) + 4, 'text-anchor': 'end' }, yf(t)));
      });
      s.appendChild(svg('line', { class: 'a-axis-line', x1: margin.left, x2: width - margin.right, y1: sy(ymin), y2: sy(ymin) }));

      let xTicks; let xLabel;
      if (m.xt === 'time') {
        const utc = !!(opts.x && opts.x.utc);
        const tt = timeTicks(xmin, xmax, Math.max(2, Math.floor(iw / 96)), utc);
        xTicks = tt.ticks; const df = tickFormatter(tt.step, tt.months, utc);
        xLabel = (v) => (opts.x && opts.x.format ? opts.x.format(v) : df(v));
      } else if (m.xt === 'band') {
        const stride = Math.max(1, Math.ceil(m.cats.length / Math.max(2, Math.floor(iw / 70))));
        xTicks = m.cats.map((_, i) => i).filter((i) => i % stride === 0);
        xLabel = (v) => (opts.x && opts.x.format ? opts.x.format(m.cats[v], v) : truncate(m.cats[v], 12));
      } else {
        xTicks = niceScale(xmin, xmax, Math.max(2, Math.floor(iw / 80))).ticks.filter((t) => t >= xmin && t <= xmax);
        xLabel = (v) => (opts.x && opts.x.format ? opts.x.format(v) : fmt.compact(v));
      }
      xTicks.forEach((t) => {
        const px = sx(t);
        s.appendChild(svg('text', { x: px, y: height - 8, 'text-anchor': px < margin.left + 18 ? 'start' : px > width - margin.right - 18 ? 'end' : 'middle' }, xLabel(t)));
      });
      (opts.thresholds || []).forEach((th) => {
        if (th.y < ymin || th.y > ymax) return;
        s.appendChild(svg('line', { class: 'a-threshold', x1: margin.left, x2: width - margin.right, y1: sy(th.y), y2: sy(th.y) }));
        if (th.label) s.appendChild(svg('text', { class: 'a-t-2', x: width - margin.right - 4, y: sy(th.y) - 5, 'text-anchor': 'end' }, th.label));
      });

      const paths = [];
      const endPts = [];
      vis.forEach((ser, k) => {
        if (!ser.pts.length) return;
        const pts = ser.pts.map((p) => [+sx(p.x).toFixed(2), +sy(p.y).toFixed(2)]);
        const d = opts.curve === 'linear' ? linearPath(pts) : monotonePath(pts);
        const color = slotVar(ser.slot);
        if (opts.area) {
          const id = `${gid}-${k}`;
          defs.appendChild(svg('linearGradient', { id, x1: 0, y1: 0, x2: 0, y2: 1 },
            svg('stop', { offset: '0%', style: { 'stop-color': color, 'stop-opacity': 0.26 } }), svg('stop', { offset: '100%', style: { 'stop-color': color, 'stop-opacity': 0.02 } })));
          const last = pts[pts.length - 1]; const first = pts[0];
          s.appendChild(svg('path', { class: 'a-area', d: `${d}L${last[0]},${sy(ymin)}L${first[0]},${sy(ymin)}Z`, style: { fill: `url(#${id})` } }));
        }
        const p = svg('path', { class: 'a-line', d, style: { stroke: color } });
        s.appendChild(p); paths.push(p);
        const end = pts[pts.length - 1];
        const dot = svg('circle', { class: 'a-dot', cx: end[0], cy: end[1], r: 4.5, style: { fill: color } });
        s.appendChild(dot);
        if (animateNext && !A.reducedMotion()) { dot.classList.add('a-fade-in'); dot.style.animationDelay = '900ms'; }
        endPts.push({ ser, x: end[0], y: end[1] });
      });
      if (endLabels) {
        let prevY = -Infinity;
        endPts.slice().sort((a, b) => a.y - b.y).forEach((e) => {
          if (e.y - prevY < 14) return;
          prevY = e.y;
          s.appendChild(svg('text', { class: 'a-t-2', x: e.x + 10, y: e.y + 4 }, truncate(e.ser.name, 14)));
        });
      }

      const cross = svg('line', { class: 'a-crosshair', y1: margin.top, y2: margin.top + ih, visibility: 'hidden' });
      s.appendChild(cross);
      const markers = vis.map((ser) => { const c = svg('circle', { class: 'a-dot', r: 4.5, visibility: 'hidden', style: { fill: slotVar(ser.slot) } }); s.appendChild(c); return c; });
      const hit = svg('rect', { class: 'a-hit', x: margin.left, y: margin.top, width: iw, height: ih });
      s.appendChild(hit);

      let minGap = Infinity;
      for (let i = 1; i < xs.length && i < 600; i++) minGap = Math.min(minGap, xs[i] - xs[i - 1]);
      const titleOf = (x) => {
        if (opts.x && opts.x.tooltipFormat) return opts.x.tooltipFormat(m.xt === 'band' ? m.cats[x] : x);
        if (m.xt === 'band') return m.cats[x];
        if (m.xt === 'time') return fmt.date(x, { time: minGap < DAY, utc: !!(opts.x && opts.x.utc) });
        return fmt.number(x, 0);
      };
      function showAt(i, cx, cy) {
        if (i < 0 || i >= xs.length) return;
        activeIdx = i;
        const x = xs[i]; const px = sx(x);
        cross.setAttribute('x1', px); cross.setAttribute('x2', px); cross.setAttribute('visibility', 'visible');
        const rows = [];
        vis.forEach((ser, k) => {
          const v = ser.map.get(x);
          if (v === undefined) { markers[k].setAttribute('visibility', 'hidden'); return; }
          markers[k].setAttribute('cx', px); markers[k].setAttribute('cy', sy(v)); markers[k].setAttribute('visibility', 'visible');
          rows.push({ name: ser.name, value: vf(v), color: slotVar(ser.slot), shape: 'line' });
        });
        if (cx == null) { const r = s.getBoundingClientRect(); cx = r.left + px; cy = r.top + margin.top + ih / 2; }
        Tip.show({ title: titleOf(x), rows }, cx, cy);
        sr.textContent = `${titleOf(x)}: ${rows.map((r) => `${r.name} ${r.value}`).join(', ')}`;
      }
      function clear() {
        activeIdx = -1; cross.setAttribute('visibility', 'hidden');
        markers.forEach((c) => c.setAttribute('visibility', 'hidden')); Tip.hide();
      }
      const move = (e) => { const r = s.getBoundingClientRect(); showAt(bisect(xs, xmin + ((e.clientX - r.left - margin.left) / iw) * (xmax - xmin)), e.clientX, e.clientY); };
      hit.addEventListener('pointermove', move);
      hit.addEventListener('pointerdown', move);
      hit.addEventListener('pointerleave', clear);
      s.addEventListener('keydown', (e) => {
        if (e.key === 'ArrowRight') { e.preventDefault(); showAt(Math.min(xs.length - 1, activeIdx + 1)); }
        else if (e.key === 'ArrowLeft') { e.preventDefault(); showAt(Math.max(0, activeIdx < 0 ? xs.length - 1 : activeIdx - 1)); }
        else if (e.key === 'Home') { e.preventDefault(); showAt(0); } else if (e.key === 'End') { e.preventDefault(); showAt(xs.length - 1); }
        else if (e.key === 'Escape') clear();
      });
      s.addEventListener('focus', () => { if (activeIdx < 0) showAt(xs.length - 1); });
      s.addEventListener('blur', clear);

      svgEl = swap(host, legendHost, svgEl, s);
      model = { m, xs, vis, vf, titleOf };
      if (animateNext && !A.reducedMotion()) {
        paths.forEach((p) => {
          let len = 0;
          try { len = p.getTotalLength(); } catch (e) { len = 0; }
          if (len > 0) { p.style.setProperty('--len', String(Math.ceil(len))); p.classList.add('is-draw'); }
        });
      }
      animateNext = false;
    }
    const ro = watch(host, () => { animateNext = false; render(); });
    render();

    return {
      el: host,
      update(next) { opts = Object.assign({}, opts, next || {}); animateNext = opts.animate !== false; render(); },
      setHidden(ids) { hidden.clear(); (ids || []).forEach((i) => hidden.add(i)); legend.sync(hidden); animateNext = false; render(); },
      destroy() { if (ro) ro.disconnect(); Tip.hide(); host.remove(); },
      table() {
        const { m, xs, vf, titleOf } = model || { m: { series: [] }, xs: [] };
        const cols = [{ key: 'x', label: (opts.x && opts.x.label) || 'Time' }].concat(m.series.map((s, i) => ({ key: `s${i}`, label: s.name, align: 'right', format: (v) => (v == null ? '–' : (vf || defaultValueFormat)(v)) })));
        const rows = (xs || []).map((x) => { const r = { x: titleOf ? titleOf(x) : String(x) }; m.series.forEach((s, i) => { r[`s${i}`] = s.map.has(x) ? s.map.get(x) : null; }); return r; });
        return { caption: opts.title || 'Line chart data', columns: cols, rows };
      },
    };
  }
  AC.line = line;

  /* ───────────────────────── bars ───────────────────────── */
  function bars(parent, o) {
    const { host, legendHost, sr } = scaffold(parent);
    legendHost.hidden = true;
    let opts = o || {};
    let animateNext = opts.animate !== false;
    let svgEl = null; let active = -1; let current = [];

    function render() {
      const width = Math.max(220, Math.round(host.clientWidth || 480));
      const data = (opts.data || []).map((d, i) => ({ id: d.id != null ? d.id : i, label: String(d.label), value: +d.value || 0, sub: d.sub, color: d.color }));
      current = data; active = -1; Tip.hide();
      if (!data.length) { svgEl = swap(host, legendHost, svgEl, emptyBox(opts.emptyText)); return; }
      const horiz = (opts.orientation || 'horizontal') !== 'vertical';
      const vf = opts.valueFormat || defaultValueFormat;
      const max = opts.max != null ? opts.max : Math.max(1e-9, Math.max.apply(null, data.map((d) => d.value)));
      const fillOf = (d) => (opts.highlight != null && d.id !== opts.highlight ? 'var(--chart-muted)' : slotVar(d.color || opts.color || 1));
      let height; const els = [];
      const s0 = (h) => svg('svg', { width, height: h, viewBox: `0 0 ${width} ${h}`, role: 'img', tabindex: '0', 'aria-label': opts.ariaLabel || opts.title || 'Bar chart' });
      let s; const hits = [];
      if (horiz) {
        const rowH = 34; const barH = 18; const padT = 4;
        height = data.length * rowH + padT * 2;
        s = s0(height);
        const labelW = clamp(Math.max.apply(null, data.map((d) => tw(d.label))) + 16, 60, Math.min(220, width * 0.42));
        const valueW = Math.max.apply(null, data.map((d) => tw(vf(d.value), 7))) + 12;
        const plotW = Math.max(40, width - labelW - valueW - 8);
        s.appendChild(svg('line', { class: 'a-axis-line', x1: labelW, x2: labelW, y1: padT, y2: height - padT }));
        data.forEach((d, i) => {
          const y = padT + i * rowH; const cy = y + rowH / 2;
          const w = d.value > 0 ? Math.max(2, (d.value / max) * plotW) : 0;
          const lab = svg('text', { class: 'a-t-2', x: labelW - 10, y: cy + 4, 'text-anchor': 'end' }, truncate(d.label, fitChars(labelW - 16)));
          if (d.label.length > fitChars(labelW - 16)) lab.appendChild(svg('title', d.label));
          s.appendChild(lab);
          let bar = null;
          if (w > 0) {
            bar = svg('path', { class: `a-bar${animateNext ? ' is-grow-x' : ''}`, d: barPath(labelW, cy - barH / 2, w, barH, 4, 'right'), style: { fill: fillOf(d), '--i': i } });
            s.appendChild(bar);
          }
          s.appendChild(svg('text', { class: 'a-t-strong', x: labelW + w + 8, y: cy + 4 }, vf(d.value)));
          hits.push({ bar, x: 0, y, w: width, h: rowH, cx: labelW + w / 2, cy });
        });
      } else {
        const padL = 8; const padR = 8; const padT = 22; const padB = 28;
        height = opts.height || 220;
        s = s0(height);
        const pw = width - padL - padR; const ph = height - padT - padB;
        const band = pw / data.length; const bw = Math.min(24, band * 0.6); const base = padT + ph;
        s.appendChild(svg('line', { class: 'a-axis-line', x1: padL, x2: width - padR, y1: base, y2: base }));
        const stride = Math.max(1, Math.ceil(data.length / Math.max(1, Math.floor(pw / 56))));
        data.forEach((d, i) => {
          const x0 = padL + i * band + (band - bw) / 2; const h = d.value > 0 ? Math.max(2, (d.value / max) * ph) : 0; const y = base - h;
          let bar = null;
          if (h > 0) { bar = svg('path', { class: `a-bar${animateNext ? ' is-grow-y' : ''}`, d: barPath(x0, y, bw, h, 4, 'up'), style: { fill: fillOf(d), '--i': i } }); s.appendChild(bar); }
          if (tw(vf(d.value), 7) < band + 6) s.appendChild(svg('text', { class: 'a-t-strong', x: x0 + bw / 2, y: y - 6, 'text-anchor': 'middle' }, vf(d.value)));
          if (i % stride === 0) s.appendChild(svg('text', { x: x0 + bw / 2, y: height - 8, 'text-anchor': 'middle' }, truncate(d.label, Math.max(3, Math.floor((band * stride) / 6.2)))));
          hits.push({ bar, x: padL + i * band, y: 0, w: band, h: height, cx: x0 + bw / 2, cy: y });
        });
      }
      const tipFor = (i) => { const d = data[i]; return { title: d.label, rows: [{ name: opts.valueLabel || 'Value', value: vf(d.value), color: fillOf(d), shape: 'rect' }], sub: d.sub }; };
      const setActive = (i, cx, cy) => {
        hits.forEach((h, k) => { if (h.bar) h.bar.classList.toggle('is-active', k === i); });
        active = i;
        if (i < 0) { Tip.hide(); return; }
        if (cx == null) { const r = s.getBoundingClientRect(); cx = r.left + hits[i].cx; cy = r.top + hits[i].cy; }
        Tip.show(tipFor(i), cx, cy);
        sr.textContent = `${data[i].label}: ${vf(data[i].value)}${data[i].sub ? ', ' + data[i].sub : ''}`;
      };
      hits.forEach((h, i) => {
        const r = svg('rect', { class: 'a-hit', x: h.x, y: h.y, width: h.w, height: h.h });
        r.addEventListener('pointermove', (e) => setActive(i, e.clientX, e.clientY));
        r.addEventListener('pointerleave', () => setActive(-1));
        if (opts.onSelect) { r.style.cursor = 'pointer'; r.addEventListener('click', () => opts.onSelect(data[i])); }
        s.appendChild(r); els.push(r);
      });
      s.addEventListener('keydown', (e) => {
        const next = e.key === 'ArrowDown' || e.key === 'ArrowRight' ? 1 : e.key === 'ArrowUp' || e.key === 'ArrowLeft' ? -1 : 0;
        if (next) { e.preventDefault(); setActive(clamp(active < 0 ? (next > 0 ? 0 : data.length - 1) : active + next, 0, data.length - 1)); }
        else if (e.key === 'Home') { e.preventDefault(); setActive(0); } else if (e.key === 'End') { e.preventDefault(); setActive(data.length - 1); }
        else if ((e.key === 'Enter' || e.key === ' ') && active >= 0 && opts.onSelect) { e.preventDefault(); opts.onSelect(data[active]); }
        else if (e.key === 'Escape') setActive(-1);
      });
      s.addEventListener('focus', () => { if (active < 0) setActive(0); });
      s.addEventListener('blur', () => setActive(-1));
      svgEl = swap(host, legendHost, svgEl, s);
      animateNext = false;
    }
    const ro = watch(host, () => { animateNext = false; render(); });
    render();
    return {
      el: host,
      update(next) { opts = Object.assign({}, opts, next || {}); animateNext = opts.animate !== false; render(); },
      destroy() { if (ro) ro.disconnect(); Tip.hide(); host.remove(); },
      table() {
        const vf = opts.valueFormat || defaultValueFormat;
        const hasSub = current.some((d) => d.sub);
        const columns = [{ key: 'label', label: opts.labelHeader || 'Item' }, { key: 'value', label: opts.valueLabel || 'Value', align: 'right', format: (v) => vf(v) }];
        if (hasSub) columns.push({ key: 'sub', label: 'Detail' });
        return { caption: opts.title || 'Bar chart data', columns, rows: current.map((d) => ({ label: d.label, value: d.value, sub: d.sub || '' })) };
      },
    };
  }
  AC.bars = bars;

  /* ───────────────────────── stacked bars ───────────────────────── */
  function stacked(parent, o) {
    const { host, legendHost, sr } = scaffold(parent);
    let opts = o || {};
    const hidden = new Set();
    let animateNext = opts.animate !== false;
    let svgEl = null; let active = -1; let snapshot = null;
    const legend = makeLegend(legendHost, (id, mode) => {
      toggleHidden(hidden, (opts.series || []).map((s, i) => (s.id != null ? s.id : `s${i}`)), id, mode);
      legend.sync(hidden); animateNext = false; render();
    });
    function render() {
      const width = Math.max(260, Math.round(host.clientWidth || 640));
      const horiz = opts.orientation === 'horizontal';
      const cats = (opts.categories || []).map(String);
      const series = (opts.series || []).map((s, i) => ({ id: s.id != null ? s.id : `s${i}`, name: String(s.name || `Series ${i + 1}`), slot: s.color || i + 1, values: (s.values || []).map((v) => Math.max(0, +v || 0)) }));
      const vis = series.filter((s) => !hidden.has(s.id));
      const vf = opts.valueFormat || defaultValueFormat;
      legend.set(series.map((s) => ({ id: s.id, name: s.name, color: slotVar(s.slot), shape: 'rect', hidden: hidden.has(s.id) })));
      legend.show(opts.legend !== 'never');
      Tip.hide(); active = -1;
      const totals = cats.map((_, i) => vis.reduce((n, s) => n + (s.values[i] || 0), 0));
      snapshot = { cats, series, totals, vf };
      if (!cats.length || !Math.max.apply(null, [0].concat(totals))) { svgEl = swap(host, legendHost, svgEl, emptyBox(opts.emptyText)); return; }
      const sc = niceScale(0, Math.max.apply(null, totals), 5);
      const yf = opts.axisFormat || fmt.compact;
      const height = horiz ? Math.max(160, cats.length * 34 + 40) : opts.height || 260;
      const labelW = horiz ? clamp(Math.max.apply(null, cats.map((c) => tw(c))) + 16, 50, Math.min(200, width * 0.4)) : 0;
      const margin = { top: 10, right: 16, bottom: 28, left: horiz ? labelW : Math.max(34, tw(yf(sc.max), 6.6) + 16) };
      const iw = width - margin.left - margin.right; const ih = height - margin.top - margin.bottom;
      const s = svg('svg', { width, height, viewBox: `0 0 ${width} ${height}`, role: 'img', tabindex: '0', 'aria-label': opts.ariaLabel || opts.title || 'Stacked bar chart' });
      sc.ticks.forEach((t) => {
        if (horiz) {
          const px = margin.left + (t / sc.max) * iw;
          s.appendChild(svg('line', { class: 'a-grid-line', x1: px, x2: px, y1: margin.top, y2: margin.top + ih }));
          s.appendChild(svg('text', { x: px, y: height - 8, 'text-anchor': 'middle' }, yf(t)));
        } else {
          const py = margin.top + ih - (t / sc.max) * ih;
          s.appendChild(svg('line', { class: 'a-grid-line', x1: margin.left, x2: width - margin.right, y1: py, y2: py }));
          s.appendChild(svg('text', { x: margin.left - 8, y: py + 4, 'text-anchor': 'end' }, yf(t)));
        }
      });
      const catLen = horiz ? ih : iw; const band = catLen / cats.length; const bw = Math.min(24, band * 0.6);
      const stride = Math.max(1, Math.ceil(cats.length / Math.max(1, Math.floor(iw / 56))));
      const hitsEl = [];
      cats.forEach((c, i) => {
        let acc = 0;
        const segs = vis.filter((sr_) => (sr_.values[i] || 0) > 0);
        segs.forEach((ser, k) => {
          const v = ser.values[i]; const p0 = (acc / sc.max) * (horiz ? iw : ih); const p1 = ((acc + v) / sc.max) * (horiz ? iw : ih); acc += v;
          const last = k === segs.length - 1; const gap = 2;
          let d;
          if (horiz) d = barPath(margin.left + p0, margin.top + i * band + (band - bw) / 2, Math.max(1, p1 - p0 - (last ? 0 : gap)), bw, 4, last ? 'right' : 'flat');
          else { const hh = Math.max(1, p1 - p0 - (last ? 0 : gap)); d = barPath(margin.left + i * band + (band - bw) / 2, margin.top + ih - p0 - hh, bw, hh, 4, last ? 'up' : 'flat'); }
          s.appendChild(svg('path', { class: `a-bar${animateNext ? (horiz ? ' is-grow-x' : ' is-grow-y') : ''}`, d, style: { fill: slotVar(ser.slot), '--i': i } }));
        });
        if (horiz) s.appendChild(svg('text', { class: 'a-t-2', x: margin.left - 10, y: margin.top + i * band + band / 2 + 4, 'text-anchor': 'end' }, truncate(c, fitChars(labelW - 16))));
        else if (i % stride === 0) s.appendChild(svg('text', { x: margin.left + i * band + band / 2, y: height - 8, 'text-anchor': 'middle' }, truncate(c, Math.max(3, Math.floor((band * stride) / 6.2)))));
        hitsEl.push(horiz ? { x: 0, y: margin.top + i * band, w: width, h: band } : { x: margin.left + i * band, y: 0, w: band, h: height });
      });
      s.appendChild(svg('line', { class: 'a-axis-line', x1: margin.left, x2: horiz ? margin.left : width - margin.right, y1: margin.top + ih, y2: horiz ? margin.top : margin.top + ih }));
      const show = (i, cx, cy) => {
        active = i;
        if (i < 0) { Tip.hide(); return; }
        const rows = vis.map((ser) => ({ name: ser.name, value: vf(ser.values[i] || 0), color: slotVar(ser.slot), shape: 'rect' })).filter((r) => r.value !== '0');
        rows.push({ name: 'Total', value: vf(totals[i]) });
        if (cx == null) { const r = s.getBoundingClientRect(); cx = r.left + hitsEl[i].x + hitsEl[i].w / 2; cy = r.top + margin.top + 20; }
        Tip.show({ title: cats[i], rows }, cx, cy);
        sr.textContent = `${cats[i]}: ${rows.map((r) => `${r.name} ${r.value}`).join(', ')}`;
      };
      hitsEl.forEach((h, i) => {
        const r = svg('rect', { class: 'a-hit', x: h.x, y: h.y, width: h.w, height: h.h });
        r.addEventListener('pointermove', (e) => show(i, e.clientX, e.clientY));
        r.addEventListener('pointerleave', () => show(-1));
        s.appendChild(r);
      });
      s.addEventListener('keydown', (e) => {
        const next = e.key === 'ArrowRight' || e.key === 'ArrowDown' ? 1 : e.key === 'ArrowLeft' || e.key === 'ArrowUp' ? -1 : 0;
        if (next) { e.preventDefault(); show(clamp(active < 0 ? (next > 0 ? 0 : cats.length - 1) : active + next, 0, cats.length - 1)); } else if (e.key === 'Escape') show(-1);
      });
      s.addEventListener('focus', () => { if (active < 0) show(0); });
      s.addEventListener('blur', () => show(-1));
      svgEl = swap(host, legendHost, svgEl, s);
      animateNext = false;
    }
    const ro = watch(host, () => { animateNext = false; render(); });
    render();
    return {
      el: host,
      update(next) { opts = Object.assign({}, opts, next || {}); animateNext = opts.animate !== false; render(); },
      setHidden(ids) { hidden.clear(); (ids || []).forEach((i) => hidden.add(i)); legend.sync(hidden); animateNext = false; render(); },
      destroy() { if (ro) ro.disconnect(); Tip.hide(); host.remove(); },
      table() {
        const { cats, series, totals, vf } = snapshot || { cats: [], series: [], totals: [], vf: defaultValueFormat };
        const columns = [{ key: 'cat', label: opts.categoryLabel || 'Category' }].concat(series.map((s, i) => ({ key: `s${i}`, label: s.name, align: 'right', format: (v) => vf(v) })), [{ key: 'total', label: 'Total', align: 'right', format: (v) => vf(v) }]);
        return { caption: opts.title || 'Stacked bar data', columns, rows: cats.map((c, i) => { const r = { cat: c, total: totals[i] }; series.forEach((s, k) => { r[`s${k}`] = s.values[i] || 0; }); return r; }) };
      },
    };
  }
  AC.stacked = stacked;

  /* ───────────────────────── heatmap (calendar + matrix) ───────────────────────── */
  const dayOf = (v) => {
    if (v instanceof Date) return Date.UTC(v.getFullYear(), v.getMonth(), v.getDate());
    const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(String(v));
    return m ? Date.UTC(+m[1], +m[2] - 1, +m[3]) : NaN;
  };
  function levelFn(values) {
    const nz = values.filter((v) => v > 0).sort((a, b) => a - b);
    if (!nz.length) return () => 0;
    const q = [0.2, 0.4, 0.6, 0.8].map((p) => nz[Math.min(nz.length - 1, Math.floor(p * nz.length))]);
    return (v) => (v > 0 ? 1 + q.filter((t) => v > t).length : 0);
  }
  function heatmap(parent, o) {
    const { host, legendHost, sr } = scaffold(parent);
    let opts = o || {};
    let svgEl = null; let animateNext = opts.animate !== false; let tableRows = []; let tableCols = [];
    const scale = el('div', { class: 'a-scale', 'aria-hidden': 'true' });
    legendHost.appendChild(scale);
    function renderScale(vf, max) {
      while (scale.firstChild) scale.removeChild(scale.firstChild);
      scale.appendChild(el('span', 'Less'));
      for (let i = 0; i <= 5; i++) scale.appendChild(el('i', { style: { '--c': `var(--seq-${i})` } }));
      scale.appendChild(el('span', max ? `More (${vf(max)} max)` : 'More'));
    }
    function render() {
      const width = Math.max(260, Math.round(host.clientWidth || 640));
      const vf = opts.valueFormat || defaultValueFormat;
      const unit = opts.unit ? ` ${opts.unit}` : '';
      Tip.hide();
      const calendar = (opts.kind || 'calendar') === 'calendar';
      let s; let cellEls = []; let titleFor; let valuesAll = [];
      if (calendar) {
        const byDay = new Map(); let maxDay = -Infinity;
        (opts.cells || []).forEach((c) => { const t = dayOf(c.date); if (isNaN(t)) return; byDay.set(t, (byDay.get(t) || 0) + (+c.value || 0)); if (t > maxDay) maxDay = t; });
        const weekStart = opts.weekStart == null ? 1 : opts.weekStart;
        const endDay = opts.end ? dayOf(opts.end) : isFinite(maxDay) ? maxDay : dayOf(new Date());
        const dow = (t) => (new Date(t).getUTCDay() - weekStart + 7) % 7;
        const gap = 3; const labelW = 32; const top = 20;
        const weeks = Math.min(opts.weeks || 53, Math.max(8, Math.floor((width - labelW) / (8 + gap))));
        const cs = clamp(Math.floor((width - labelW) / weeks) - gap, 8, 18);
        const startDay = endDay - dow(endDay) * DAY - (weeks - 1) * 7 * DAY;
        const height = top + 7 * (cs + gap);
        s = svg('svg', { width, height, viewBox: `0 0 ${width} ${height}`, role: 'img', tabindex: '0', 'aria-label': opts.ariaLabel || opts.title || 'Activity calendar' });
        const names = new Intl.DateTimeFormat(fmt.locale, { weekday: 'short', timeZone: 'UTC' });
        [0, 2, 4].forEach((r) => {
          s.appendChild(svg('text', { x: 0, y: top + r * (cs + gap) + cs - 2 }, names.format(new Date(startDay + r * DAY))));
        });
        const months = new Intl.DateTimeFormat(fmt.locale, { month: 'short', timeZone: 'UTC' });
        let lastLabelCol = -10;
        for (let c = 0; c < weeks; c++) {
          let firstOfMonth = false;
          for (let r = 0; r < 7; r++) if (new Date(startDay + (c * 7 + r) * DAY).getUTCDate() === 1) firstOfMonth = true;
          if (firstOfMonth && c - lastLabelCol >= 3) {
            s.appendChild(svg('text', { x: labelW + c * (cs + gap), y: 11 }, months.format(new Date(startDay + (c * 7 + 6) * DAY))));
            lastLabelCol = c;
          }
        }
        const days = [];
        for (let c = 0; c < weeks; c++) for (let r = 0; r < 7; r++) { const t = startDay + (c * 7 + r) * DAY; if (t <= endDay) days.push({ t, c, r, v: byDay.get(t) || 0 }); }
        valuesAll = days.map((d) => d.v);
        const lv = levelFn(valuesAll);
        const dtf = new Intl.DateTimeFormat(fmt.locale, { weekday: 'short', year: 'numeric', month: 'short', day: 'numeric', timeZone: 'UTC' });
        days.forEach((d, i) => {
          const rect = svg('rect', { class: `a-cell${animateNext ? ' is-in' : ''}`, x: labelW + d.c * (cs + gap), y: top + d.r * (cs + gap), width: cs, height: cs, rx: 3, style: { fill: `var(--seq-${lv(d.v)})`, '--i': Math.min(d.c, 60) }, 'data-i': i });
          s.appendChild(rect); cellEls.push({ el: rect, d, cx: +rect.getAttribute('x') + cs / 2, cy: +rect.getAttribute('y') });
        });
        titleFor = (item) => ({ title: dtf.format(new Date(item.d.t)), rows: [{ name: opts.unit ? opts.unit.charAt(0).toUpperCase() + opts.unit.slice(1) : 'Value', value: vf(item.d.v) }] });
        tableRows = days.map((d) => ({ a: fmt.date(d.t, { utc: true }), b: d.v })); tableCols = [{ key: 'a', label: 'Date' }, { key: 'b', label: opts.unit ? opts.unit.charAt(0).toUpperCase() + opts.unit.slice(1) : 'Value', align: 'right', format: (v) => vf(v) }];
      } else {
        const rowsL = (opts.rows || []).map(String); const colsL = (opts.cols || []).map(String);
        const labelW = clamp(Math.max.apply(null, [3].concat(rowsL.map((r) => tw(r)))) + 12, 28, 120);
        const top = 20; const gap = 2;
        const cw = (width - labelW) / Math.max(1, colsL.length); const ch = clamp(cw, 14, 26);
        const height = top + rowsL.length * ch;
        s = svg('svg', { width, height, viewBox: `0 0 ${width} ${height}`, role: 'img', tabindex: '0', 'aria-label': opts.ariaLabel || opts.title || 'Heatmap' });
        const stride = Math.max(1, Math.ceil(36 / Math.max(1, cw)));
        colsL.forEach((c, j) => { if (j % stride === 0) s.appendChild(svg('text', { x: labelW + j * cw + cw / 2, y: 12, 'text-anchor': 'middle' }, truncate(c, Math.max(2, Math.floor((cw * stride) / 6))))); });
        rowsL.forEach((r, i) => s.appendChild(svg('text', { x: labelW - 8, y: top + i * ch + ch / 2 + 4, 'text-anchor': 'end' }, r)));
        const grid = new Map();
        (opts.cells || []).forEach((c) => {
          const i = typeof c.row === 'number' ? c.row : rowsL.indexOf(String(c.row)); const j = typeof c.col === 'number' ? c.col : colsL.indexOf(String(c.col));
          if (i >= 0 && j >= 0) grid.set(`${i}:${j}`, (grid.get(`${i}:${j}`) || 0) + (+c.value || 0));
        });
        valuesAll = Array.from(grid.values());
        const lv = levelFn(valuesAll);
        for (let i = 0; i < rowsL.length; i++) for (let j = 0; j < colsL.length; j++) {
          const v = grid.get(`${i}:${j}`) || 0;
          const rect = svg('rect', { class: `a-cell${animateNext ? ' is-in' : ''}`, x: labelW + j * cw + gap / 2, y: top + i * ch + gap / 2, width: Math.max(2, cw - gap), height: ch - gap, rx: 3, style: { fill: `var(--seq-${lv(v)})`, '--i': j } });
          s.appendChild(rect); cellEls.push({ el: rect, d: { i, j, v }, cx: labelW + j * cw + cw / 2, cy: top + i * ch });
        }
        titleFor = (item) => ({ title: `${rowsL[item.d.i]} · ${colsL[item.d.j]}`, rows: [{ name: opts.unit ? opts.unit.charAt(0).toUpperCase() + opts.unit.slice(1) : 'Value', value: vf(item.d.v) }] });
        tableRows = []; rowsL.forEach((r, i) => colsL.forEach((c, j) => { const v = grid.get(`${i}:${j}`); if (v) tableRows.push({ a: r, b: c, c: v }); }));
        tableCols = [{ key: 'a', label: opts.rowLabel || 'Row' }, { key: 'b', label: opts.colLabel || 'Column' }, { key: 'c', label: opts.unit ? opts.unit.charAt(0).toUpperCase() + opts.unit.slice(1) : 'Value', align: 'right', format: (v) => vf(v) }];
      }
      renderScale(vf, valuesAll.length ? Math.max.apply(null, valuesAll) : 0);
      let activeCell = -1;
      const setActive = (i, cx, cy) => {
        if (activeCell >= 0 && cellEls[activeCell]) cellEls[activeCell].el.classList.remove('is-active');
        activeCell = i;
        if (i < 0) { Tip.hide(); return; }
        const item = cellEls[i]; item.el.classList.add('is-active');
        if (cx == null) { const r = s.getBoundingClientRect(); cx = r.left + item.cx; cy = r.top + item.cy; }
        const spec = titleFor(item);
        Tip.show(spec, cx, cy);
        sr.textContent = `${spec.title}: ${spec.rows[0].value}${unit}`;
      };
      cellEls.forEach((item, i) => {
        item.el.addEventListener('pointermove', (e) => setActive(i, e.clientX, e.clientY));
        item.el.addEventListener('pointerleave', () => setActive(-1));
      });
      s.addEventListener('keydown', (e) => {
        const next = e.key === 'ArrowRight' || e.key === 'ArrowDown' ? 1 : e.key === 'ArrowLeft' || e.key === 'ArrowUp' ? -1 : 0;
        if (next) { e.preventDefault(); setActive(clamp(activeCell < 0 ? 0 : activeCell + next, 0, cellEls.length - 1)); } else if (e.key === 'Escape') setActive(-1);
      });
      s.addEventListener('focus', () => { if (activeCell < 0) setActive(cellEls.length - 1); });
      s.addEventListener('blur', () => setActive(-1));
      svgEl = swap(host, legendHost, svgEl, s);
      animateNext = false;
    }
    const ro = watch(host, () => { animateNext = false; render(); });
    render();
    return {
      el: host,
      update(next) { opts = Object.assign({}, opts, next || {}); animateNext = opts.animate !== false; render(); },
      destroy() { if (ro) ro.disconnect(); Tip.hide(); host.remove(); },
      table() { return { caption: opts.title || 'Heatmap data', columns: tableCols, rows: tableRows }; },
    };
  }
  AC.heatmap = heatmap;

  /* ───────────────────────── sparkline ───────────────────────── */
  function spark(parent, o) {
    o = o || {};
    const w = o.width || 96; const h = o.height || 28;
    const holder = el('span', { class: 'a-spark-wrap', role: 'img' });
    parent.appendChild(holder);
    function render(values) {
      while (holder.firstChild) holder.removeChild(holder.firstChild);
      const v = (values || []).map(Number).filter(finite);
      holder.setAttribute('aria-label', v.length ? `Trend of ${v.length} points, latest ${fmt.compact(v[v.length - 1])}` : 'No trend data');
      const s = svg('svg', { class: 'a-spark', width: w, height: h, viewBox: `0 0 ${w} ${h}`, 'aria-hidden': 'true' });
      if (v.length) {
        const lo = Math.min.apply(null, v); const hi = Math.max.apply(null, v); const span = hi - lo || 1;
        const pad = 4; const x = (i) => (v.length === 1 ? w / 2 : pad + (i / (v.length - 1)) * (w - pad * 2));
        const y = (val) => h - pad - ((val - lo) / span) * (h - pad * 2);
        if (o.kind === 'bars') {
          const bw = Math.max(2, (w - pad * 2) / v.length - 2);
          v.forEach((val, i) => s.appendChild(svg('rect', { x: x(i) - bw / 2, y: y(val), width: bw, height: Math.max(2, h - pad - y(val)), rx: 1.5, style: { fill: i === v.length - 1 ? 'var(--series-1)' : 'var(--chart-muted)' } })));
        } else {
          const pts = v.map((val, i) => [+x(i).toFixed(2), +y(val).toFixed(2)]);
          s.appendChild(svg('path', { class: 'a-line', d: linearPath(pts) }));
          if (pts.length > 1) s.appendChild(svg('path', { class: 'a-line', d: linearPath(pts.slice(-2)), style: { stroke: 'var(--series-1)' } }));
          const last = pts[pts.length - 1];
          s.appendChild(svg('circle', { class: 'a-last', cx: last[0], cy: last[1], r: 3 }));
        }
      }
      holder.appendChild(s);
    }
    render(o.values);
    return { el: holder, update: render };
  }
  AC.spark = spark;

  /* ───────────────────────── ring meter ───────────────────────── */
  const KIND_COLOR = { info: 'var(--accent-1)', good: 'var(--good)', warn: 'var(--warn)', serious: 'var(--serious)', critical: 'var(--critical)' };
  function ring(parent, o) {
    o = o || {};
    const size = o.size || 168; const sw = Math.max(10, Math.round(size * 0.085));
    const r = (size - sw) / 2; const C = 2 * Math.PI * r; const max = o.max || 100;
    const f = o.format || fmt.int;
    const thresholds = (o.thresholds || [{ at: 0.4, kind: 'warn' }, { at: 0.7, kind: 'critical' }]).slice().sort((a, b) => a.at - b.at);
    const fill = svg('circle', { class: 'a-ring__fill', cx: size / 2, cy: size / 2, r, 'stroke-width': sw, 'stroke-dasharray': C, 'stroke-dashoffset': C });
    const valueEl = el('div', { class: 'a-ring__value' }, '0');
    const node = el('div', { class: 'a-ring', role: 'img', style: { width: `${size}px`, height: `${size}px`, '--ring-size': `${size}px` } },
      svg('svg', { width: size, height: size, viewBox: `0 0 ${size} ${size}`, 'aria-hidden': 'true' }, svg('circle', { class: 'a-ring__track', cx: size / 2, cy: size / 2, r, 'stroke-width': sw }), fill),
      el('div', { class: 'a-ring__label' }, valueEl, o.sublabel ? el('div', { class: 'a-ring__sub' }, o.sublabel) : null));
    parent.appendChild(node);
    let current = 0;
    function set(v) {
      const ratio = clamp(v / max, 0, 1);
      let kind = o.baseKind || 'info';
      thresholds.forEach((t) => { if (ratio >= t.at) kind = t.kind; });
      node.style.setProperty('--_c', KIND_COLOR[kind] || KIND_COLOR.info);
      node.setAttribute('aria-label', `${o.label || 'Score'}: ${f(v)} of ${f(max)}`);
      fill.style.strokeDashoffset = String(C * (1 - ratio));
      A.countUp(valueEl, v, { from: current, format: f, duration: 1100 });
      current = v;
    }
    root.requestAnimationFrame(() => root.requestAnimationFrame(() => set(o.value || 0)));
    return { el: node, update: set };
  }
  AC.ring = ring;

  /* ───────────────────────── chart card (title + Chart|Table toggle) ───────────────────────── */
  function card(parent, o) {
    o = o || {};
    const body = el('div', { class: 'a-card__body' });
    const tableHost = el('div', { class: 'a-card__body', hidden: true });
    let chart = null;
    const bChart = el('button', { class: 'a-chip', type: 'button', 'aria-pressed': 'true', onclick: () => showTable(false) }, 'Chart');
    const bTable = el('button', { class: 'a-chip', type: 'button', 'aria-pressed': 'false', onclick: () => showTable(true) }, 'Table');
    const toggle = el('div', { class: 'a-row', role: 'group', 'aria-label': 'View', style: { '--gap': '4px', flexWrap: 'nowrap' } }, bChart, bTable);
    const head = el('div', { class: 'a-card__head' },
      el('div', null, el('div', { class: 'a-card__title' }, o.title || ''), o.subtitle ? el('div', { class: 'a-card__sub' }, o.subtitle) : null),
      el('div', { class: 'a-card__actions' }, o.actions || null, toggle));
    const node = el('section', { class: 'a-card a-reveal', 'aria-label': o.title || 'Chart' }, head, body, tableHost);
    parent.appendChild(node);
    A.reveal(node);
    chart = o.render ? o.render(body) : null;
    if (!chart || !chart.table) toggle.hidden = true;
    function showTable(on) {
      if (!chart || !chart.table) return;
      bChart.setAttribute('aria-pressed', String(!on));
      bTable.setAttribute('aria-pressed', String(on));
      body.hidden = on; tableHost.hidden = !on;
      Tip.hide();
      if (on) {
        while (tableHost.firstChild) tableHost.removeChild(tableHost.firstChild);
        const t = chart.table();
        A.table(tableHost, { columns: t.columns, rows: t.rows, caption: t.caption, dense: true, pageSize: 12, sort: null });
      }
    }
    return { el: node, body, get chart() { return chart; }, setChart(c) { chart = c; toggle.hidden = !(c && c.table); }, showTable };
  }
  AC.card = card;
})(typeof window !== 'undefined' ? window : globalThis);
