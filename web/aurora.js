/*! Aurora UI kit — window.Aurora · MIT
 *  Classic script (no modules): works from file://, inlines into single-file reports and
 *  runs under a strict CSP — it never writes `style=""` attributes or inline handlers.
 *  There is no innerHTML API anywhere: all text goes through textContent. */
(function (root) {
  'use strict';

  const doc = root.document;
  const NS = 'http://www.w3.org/2000/svg';
  const Aurora = (root.Aurora = root.Aurora || {});
  Aurora.version = '2.0.0';

  /* ───────────────────────── helpers ───────────────────────── */
  const isNode = (x) => !!x && typeof x === 'object' && typeof x.nodeType === 'number';
  const isPlain = (x) => !!x && typeof x === 'object' && !isNode(x) && !Array.isArray(x);
  const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
  const SAFE_URL = /^(?:https?:|mailto:|tel:|#|\/|[^:]*$)/i;
  const URL_ATTRS = new Set(['href', 'src', 'action', 'formaction', 'xlink:href']);
  let uidCounter = 0;

  function append(parent, child) {
    if (child == null || child === false || child === true) return;
    if (Array.isArray(child)) { child.forEach((c) => append(parent, c)); return; }
    parent.appendChild(isNode(child) ? child : doc.createTextNode(String(child)));
  }

  function applyAttrs(node, attrs) {
    if (!attrs) return node;
    Object.keys(attrs).forEach((k) => {
      const v = attrs[k];
      if (v == null || v === false) return;
      if (k === 'class' || k === 'className') node.setAttribute('class', v);
      else if (k === 'text') node.textContent = String(v);
      else if (k === 'dataset') Object.keys(v).forEach((d) => { node.dataset[d] = v[d]; });
      else if (k === 'style') {
        if (typeof v === 'object') Object.keys(v).forEach((p) => {
          if (p.indexOf('-') >= 0) node.style.setProperty(p, v[p]); else node.style[p] = v[p];
        });
      } else if (k.slice(0, 2) === 'on') {
        if (typeof v === 'function') node.addEventListener(k.slice(2).toLowerCase(), v);
      } else if (v === true) node.setAttribute(k, '');
      else if (URL_ATTRS.has(k)) node.setAttribute(k, SAFE_URL.test(String(v).trim()) ? String(v) : '#');
      else node.setAttribute(k, String(v));
    });
    return node;
  }

  function build(create, tag, attrs, rest) {
    const node = create(tag);
    let start = 0;
    if (isPlain(attrs)) { applyAttrs(node, attrs); start = 0; } else if (attrs !== undefined) append(node, attrs);
    for (let i = start; i < rest.length; i++) append(node, rest[i]);
    return node;
  }
  const el = (tag, attrs, ...rest) => build((t) => doc.createElement(t), tag, attrs, rest);
  const svg = (tag, attrs, ...rest) => build((t) => doc.createElementNS(NS, t), tag, attrs, rest);

  const uid = (prefix) => `${prefix || 'a'}-${++uidCounter}`;
  const noop = () => {};
  function debounce(fn, ms) {
    let t;
    return function () { const a = arguments; const self = this; clearTimeout(t); t = setTimeout(() => fn.apply(self, a), ms); };
  }
  function throttle(fn, ms) {
    let last = 0; let timer = null;
    return function () {
      const a = arguments; const self = this; const now = Date.now();
      if (now - last >= ms) { last = now; fn.apply(self, a); } else if (!timer) {
        timer = setTimeout(() => { timer = null; last = Date.now(); fn.apply(self, a); }, ms - (now - last));
      }
    };
  }
  const reducedMotion = () => !!(root.matchMedia && root.matchMedia('(prefers-reduced-motion: reduce)').matches);

  Object.assign(Aurora, { el, svg, uid, debounce, throttle, reducedMotion });

  /* ───────────────────────── icons (24×24, stroke) ───────────────────────── */
  const P = (d) => ['path', { d }];
  const L = (x1, y1, x2, y2) => ['line', { x1, y1, x2, y2 }];
  const PL = (points) => ['polyline', { points }];
  const C = (cx, cy, r) => ['circle', { cx, cy, r }];
  const R = (x, y, w, h, rx) => ['rect', { x, y, width: w, height: h, rx: rx || 0 }];
  const ICONS = {
    check: [PL('20 6 9 17 4 12')],
    'check-circle': [P('M22 11.08V12a10 10 0 1 1-5.93-9.14'), PL('22 4 12 14.01 9 11.01')],
    x: [L(18, 6, 6, 18), L(6, 6, 18, 18)],
    'x-circle': [C(12, 12, 10), L(15, 9, 9, 15), L(9, 9, 15, 15)],
    alert: [P('M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z'), L(12, 9, 12, 13), L(12, 17, 12.01, 17)],
    'alert-octagon': [['polygon', { points: '7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2' }], L(12, 8, 12, 12), L(12, 16, 12.01, 16)],
    info: [C(12, 12, 10), L(12, 16, 12, 12), L(12, 8, 12.01, 8)],
    dot: [C(12, 12, 4)],
    copy: [R(9, 9, 13, 13, 2), P('M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1')],
    search: [C(11, 11, 8), L(21, 21, 16.65, 16.65)],
    download: [P('M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4'), PL('7 10 12 15 17 10'), L(12, 15, 12, 3)],
    upload: [P('M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4'), PL('17 8 12 3 7 8'), L(12, 3, 12, 15)],
    file: [P('M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z'), PL('13 2 13 9 20 9')],
    sun: [C(12, 12, 5), L(12, 1, 12, 3), L(12, 21, 12, 23), L(4.22, 4.22, 5.64, 5.64), L(18.36, 18.36, 19.78, 19.78), L(1, 12, 3, 12), L(21, 12, 23, 12), L(4.22, 19.78, 5.64, 18.36), L(18.36, 5.64, 19.78, 4.22)],
    moon: [P('M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z')],
    command: [P('M18 3a3 3 0 0 0-3 3v12a3 3 0 0 0 3 3 3 3 0 0 0 3-3 3 3 0 0 0-3-3H6a3 3 0 0 0-3 3 3 3 0 0 0 3 3 3 3 0 0 0 3-3V6a3 3 0 0 0-3-3 3 3 0 0 0-3 3 3 3 0 0 0 3 3h12a3 3 0 0 0 3-3 3 3 0 0 0-3-3z')],
    'arrow-up': [L(12, 19, 12, 5), PL('5 12 12 5 19 12')],
    'arrow-down': [L(12, 5, 12, 19), PL('19 12 12 19 5 12')],
    'chevron-right': [PL('9 18 15 12 9 6')],
    'chevron-down': [PL('6 9 12 15 18 9')],
    external: [P('M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6'), PL('15 3 21 3 21 9'), L(10, 14, 21, 3)],
    trash: [PL('3 6 5 6 21 6'), P('M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6m3 0V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2')],
    plus: [L(12, 5, 12, 19), L(5, 12, 19, 12)],
    qr: [R(3, 3, 7, 7, 1), R(14, 3, 7, 7, 1), R(3, 14, 7, 7, 1), L(14, 14, 14, 14.01), L(17, 14, 21, 14), L(14, 17, 14, 21), L(17, 17, 17, 17.01), L(21, 17, 21, 21), L(17, 21, 18, 21)],
    link: [P('M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71'), P('M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71')],
    refresh: [PL('23 4 23 10 17 10'), PL('1 20 1 14 7 14'), P('M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15')],
    shield: [P('M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z')],
    bug: [P('M8 2l1.88 1.88M14.12 3.88L16 2M9 7.13v-1a3.003 3.003 0 1 1 6 0v1'), P('M12 20c-3.3 0-6-2.7-6-6v-3a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v3c0 3.3-2.7 6-6 6'), L(12, 20, 12, 11), P('M6.53 9C4.6 8.8 3 7.1 3 5M6 13H2M3 21c0-2.1 1.7-3.9 3.8-4M20.97 5c0 2.1-1.6 3.8-3.5 4M22 13h-4M17.2 17c2.1.1 3.8 1.9 3.8 4')],
    cpu: [R(4, 4, 16, 16, 2), R(9, 9, 6, 6), L(9, 1, 9, 4), L(15, 1, 15, 4), L(9, 20, 9, 23), L(15, 20, 15, 23), L(20, 9, 23, 9), L(20, 14, 23, 14), L(1, 9, 4, 9), L(1, 14, 4, 14)],
    hash: [L(4, 9, 20, 9), L(4, 15, 20, 15), L(10, 3, 8, 21), L(16, 3, 14, 21)],
    code: [PL('16 18 22 12 16 6'), PL('8 6 2 12 8 18')],
    bolt: [['polygon', { points: '13 2 3 14 12 14 11 22 21 10 12 10 13 2' }]],
    globe: [C(12, 12, 10), L(2, 12, 22, 12), P('M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z')],
    clock: [C(12, 12, 10), PL('12 6 12 12 16 14')],
    user: [P('M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2'), C(12, 7, 4)],
    filter: [['polygon', { points: '22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3' }]],
    lock: [R(3, 11, 18, 11, 2), P('M7 11V7a5 5 0 0 1 10 0v4')],
    sparkle: [P('M12 3l1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9z'), P('M19 16l.7 1.8L21.5 18.5l-1.8.7L19 21l-.7-1.8-1.8-.7 1.8-.7z')],
    edit: [P('M17 3a2.83 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z')],
    play: [['polygon', { points: '6 3 20 12 6 21 6 3' }]],
    pause: [R(6, 4, 4, 16, 1), R(14, 4, 4, 16, 1)],
    // navigation and layout
    prism: [['polygon', { points: '12 3 21.5 19.5 2.5 19.5' }], L(12, 3, 12, 19.5), L(7.2, 11.5, 12, 14.5)],
    home: [P('M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z'), PL('9 22 9 12 15 12 15 22')],
    layers: [['polygon', { points: '12 2 2 7 12 12 22 7 12 2' }], PL('2 17 12 22 22 17'), PL('2 12 12 17 22 12')],
    layout: [R(3, 3, 18, 18, 2), L(3, 9, 21, 9), L(9, 21, 9, 9)],
    grid: [R(3, 3, 7, 7, 1), R(14, 3, 7, 7, 1), R(14, 14, 7, 7, 1), R(3, 14, 7, 7, 1)],
    list: [L(8, 6, 21, 6), L(8, 12, 21, 12), L(8, 18, 21, 18), L(3, 6, 3.01, 6), L(3, 12, 3.01, 12), L(3, 18, 3.01, 18)],
    menu: [L(3, 12, 21, 12), L(3, 6, 21, 6), L(3, 18, 21, 18)],
    'more-horizontal': [C(12, 12, 1), C(19, 12, 1), C(5, 12, 1)],
    sliders: [L(4, 21, 4, 14), L(4, 10, 4, 3), L(12, 21, 12, 12), L(12, 8, 12, 3), L(20, 21, 20, 16), L(20, 12, 20, 3), L(1, 14, 7, 14), L(9, 8, 15, 8), L(17, 16, 23, 16)],
    settings: [C(12, 12, 3), P('M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z')],
    help: [C(12, 12, 10), P('M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3'), L(12, 17, 12.01, 17)],
    'arrow-left': [L(19, 12, 5, 12), PL('12 19 5 12 12 5')],
    'arrow-right': [L(5, 12, 19, 12), PL('12 5 19 12 12 19')],
    'chevron-left': [PL('15 18 9 12 15 6')],
    'chevron-up': [PL('18 15 12 9 6 15')],
    // data and content
    'bar-chart': [L(18, 20, 18, 10), L(12, 20, 12, 4), L(6, 20, 6, 14)],
    'trending-up': [PL('23 6 13.5 15.5 8.5 10.5 1 18'), PL('17 6 23 6 23 12')],
    'pie-chart': [P('M21.21 15.89A10 10 0 1 1 8 2.83'), P('M22 12A10 10 0 0 0 12 2v10z')],
    activity: [PL('22 12 18 12 15 21 9 3 6 12 2 12')],
    folder: [P('M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z')],
    'file-text': [P('M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z'), PL('14 2 14 8 20 8'), L(16, 13, 8, 13), L(16, 17, 8, 17), L(10, 9, 8, 9)],
    package: [L(16.5, 9.4, 7.5, 4.21), P('M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z'), PL('3.27 6.96 12 12.01 20.73 6.96'), L(12, 22.08, 12, 12)],
    database: [['ellipse', { cx: 12, cy: 5, rx: 9, ry: 3 }], P('M21 12c0 1.66-4 3-9 3s-9-1.34-9-3'), P('M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5')],
    server: [R(2, 2, 20, 8, 2), R(2, 14, 20, 8, 2), L(6, 6, 6.01, 6), L(6, 18, 6.01, 18)],
    terminal: [PL('4 17 10 11 4 5'), L(12, 19, 20, 19)],
    book: [P('M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z'), P('M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z')],
    image: [R(3, 3, 18, 18, 2), C(8.5, 8.5, 1.5), PL('21 15 16 10 5 21')],
    eye: [P('M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z'), C(12, 12, 3)],
    flag: [P('M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z'), L(4, 22, 4, 15)],
    star: [['polygon', { points: '12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2' }]],
    calendar: [R(3, 4, 18, 18, 2), L(16, 2, 16, 6), L(8, 2, 8, 6), L(3, 10, 21, 10)],
    message: [P('M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z')],
    tag: [P('M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z'), L(7, 7, 7.01, 7)],
    users: [P('M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2'), C(9, 7, 4), P('M23 21v-2a4 4 0 0 0-3-3.87'), P('M16 3.13a4 4 0 0 1 0 7.75')],
    'git-branch': [L(6, 3, 6, 15), C(18, 6, 3), C(6, 18, 3), P('M18 9a9 9 0 0 1-9 9')],
    'git-commit': [C(12, 12, 4), L(1.05, 12, 7, 12), L(17.01, 12, 22.96, 12)],
    key: [P('M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4')],
    // documents and places (brkit)
    'id-card': [R(2, 5, 20, 14, 2), C(8, 11, 2), P('M5 16c.6-1.4 1.7-2 3-2s2.4.6 3 2'), L(14, 10, 19, 10), L(14, 14, 19, 14)],
    building: [R(4, 2, 16, 20, 2), P('M9 22v-4h6v4'), L(8, 6, 8.01, 6), L(12, 6, 12.01, 6), L(16, 6, 16.01, 6), L(8, 10, 8.01, 10), L(12, 10, 12.01, 10), L(16, 10, 16.01, 10), L(8, 14, 8.01, 14), L(12, 14, 12.01, 14), L(16, 14, 16.01, 14)],
    'credit-card': [R(1, 4, 22, 16, 2), L(1, 10, 23, 10)],
    car: [P('M3 13l2-5.5A2 2 0 0 1 6.9 6h10.2a2 2 0 0 1 1.9 1.5L21 13'), R(2, 13, 20, 5, 2), C(7, 18, 1.5), C(17, 18, 1.5), L(5.5, 15.5, 5.51, 15.5), L(18.5, 15.5, 18.51, 15.5)],
    phone: [P('M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z')],
    'map-pin': [P('M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z'), C(12, 10, 3)],
    bot: [R(4, 8, 16, 12, 3), L(12, 4, 12, 8), C(12, 3.5, 1), L(9, 13, 9.01, 13), L(15, 13, 15.01, 13), L(9, 17, 15, 17)],
  };
  function icon(name, o) {
    const size = (o && o.size) || 16;
    const s = svg('svg', { class: 'a-icon', viewBox: '0 0 24 24', width: size, height: size, fill: 'none', stroke: 'currentColor', 'stroke-width': 2, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true', focusable: 'false' });
    (ICONS[name] || []).forEach(([tag, attrs]) => s.appendChild(svg(tag, attrs)));
    return s;
  }
  Aurora.icon = icon;

  /* ───────────────────────── strings: every built-in label can be replaced (i18n) ───────────────────────── */
  const STR = {
    'cmdk.placeholder': 'Type a command or search…', 'cmdk.label': 'Command palette', 'cmdk.empty': 'No matching commands',
    'table.search': 'Search…', 'table.searchLabel': 'Search table', 'table.noMatches': 'No matches', 'table.nothing': 'Nothing to show',
    'table.tryAnother': 'Try a different search term.', 'table.prev': 'Previous', 'table.next': 'Next', 'table.of': 'of',
    'theme.toLight': 'Switch to light theme', 'theme.toDark': 'Switch to dark theme',
    'copy.done': 'Copied', 'copy.failed': 'Copy failed', 'code.copy': 'Copy to clipboard',
    'dialog.close': 'Close', 'confirm.cancel': 'Cancel', 'confirm.ok': 'Confirm',
    'dropzone.title': 'Drop a file here', 'dropzone.hint': 'or click to browse', 'dropzone.choose': 'Choose a file', 'pagedrop.title': 'Drop to upload',
    'empty.title': 'Nothing here yet', 'live.live': 'Live', 'live.connecting': 'Connecting…', 'live.offline': 'Offline',
    'meter.progress': 'Progress', 'shell.rail': 'Primary', 'shell.here': 'You are here', 'shell.search': 'Search…', 'shell.skip': 'Skip to content', 'shell.theme': 'Theme', 'segbar.nodata': 'No data', 'tabs.sections': 'Sections', 'range.label': 'Date range',
  };
  const t = (key) => (STR[key] != null ? STR[key] : key);
  Aurora.strings = STR;
  /** Replace built-in labels, e.g. Aurora.setStrings({ 'cmdk.placeholder': 'Digite um comando…' }). Unknown keys are kept for your own use. */
  Aurora.setStrings = (next) => { Object.keys(next || {}).forEach((k) => { if (typeof next[k] === 'string') STR[k] = next[k]; }); };

  /* ───────────────────────── formatting ───────────────────────── */
  const nfCache = new Map();
  function nf(digits, extra) {
    const key = `${fmt.locale}|${digits}|${extra ? extra.notation : ''}`;
    let f = nfCache.get(key);
    if (!f) {
      f = new Intl.NumberFormat(fmt.locale, Object.assign({ minimumFractionDigits: digits, maximumFractionDigits: digits }, extra || {}));
      nfCache.set(key, f);
    }
    return f;
  }
  const pad = (n) => String(n).padStart(2, '0');
  const toDate = (d) => (d instanceof Date ? d : new Date(d));
  const finite = (n) => typeof n === 'number' && isFinite(n);
  const fmt = {
    locale: 'en-US',
    int: (n) => (finite(+n) ? nf(0).format(Math.round(+n)) : '–'),
    number: (n, digits) => (finite(+n) ? nf(digits == null ? 2 : digits).format(+n) : '–'),
    compact(n) {
      n = +n;
      if (!finite(n)) return '–';
      if (Math.abs(n) < 10000) return nf(0).format(Math.round(n));
      return nf(0, { notation: 'compact', maximumFractionDigits: 1, minimumFractionDigits: 0 }).format(n);
    },
    pct: (r, digits) => (finite(+r) ? nf(digits == null ? 1 : digits).format(+r * 100) + '%' : '–'),
    signed(n, digits) {
      n = +n;
      if (!finite(n)) return '–';
      return (n > 0 ? '+' : n < 0 ? '−' : '') + nf(digits == null ? 1 : digits).format(Math.abs(n));
    },
    bytes(n) {
      n = +n;
      if (!finite(n) || n < 0) return '–';
      if (n < 1024) return `${Math.round(n)} B`;
      const units = ['KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
      let v = n; let i = -1;
      do { v /= 1024; i++; } while (v >= 1024 && i < units.length - 1);
      return `${nf(v >= 100 ? 0 : v >= 10 ? 1 : 2).format(v)} ${units[i]}`;
    },
    duration(ms) {
      ms = +ms;
      if (!finite(ms) || ms < 0) return '–';
      if (ms < 1000) return `${Math.round(ms)} ms`;
      if (ms < 60000) return `${(ms / 1000).toFixed(1)} s`;
      const s = Math.round(ms / 1000);
      if (s < 3600) return `${Math.floor(s / 60)}m ${pad(s % 60)}s`;
      return `${Math.floor(s / 3600)}h ${pad(Math.floor((s % 3600) / 60))}m`;
    },
    date(d, o) {
      const x = toDate(d);
      if (isNaN(x)) return '–';
      const utc = !!(o && o.utc);
      const g = (a, b) => (utc ? x[a]() : x[b]());
      const day = `${g('getUTCFullYear', 'getFullYear')}-${pad(g('getUTCMonth', 'getMonth') + 1)}-${pad(g('getUTCDate', 'getDate'))}`;
      return o && o.time ? `${day} ${pad(g('getUTCHours', 'getHours'))}:${pad(g('getUTCMinutes', 'getMinutes'))}` : day;
    },
    relative(d, now) {
      const x = toDate(d);
      if (isNaN(x)) return '–';
      const s = Math.round((x - (now ? toDate(now) : new Date())) / 1000);
      const a = Math.abs(s); const future = s > 0;
      if (a < 45) return 'just now';
      const m = Math.round(a / 60);
      if (m < 60) return future ? `in ${m}m` : `${m}m ago`;
      const h = Math.round(a / 3600);
      if (h < 24) return future ? `in ${h}h` : `${h}h ago`;
      const dd = Math.round(a / 86400);
      if (dd === 1) return future ? 'tomorrow' : 'yesterday';
      if (dd < 30) return future ? `in ${dd}d` : `${dd}d ago`;
      return fmt.date(x);
    },
  };
  Aurora.fmt = fmt;
  const formatterFor = (format, digits) => {
    if (typeof format === 'function') return format;
    if (format === 'compact') return fmt.compact;
    if (format === 'pct') return (v) => fmt.pct(v, digits);
    if (format === 'bytes') return fmt.bytes;
    if (format === 'duration') return fmt.duration;
    if (format === 'number') return (v) => fmt.number(v, digits);
    return digits != null ? (v) => fmt.number(v, digits) : fmt.int;
  };

  /* ───────────────────────── theme ───────────────────────── */
  const THEME_KEY = 'aurora-theme';
  const resolveTheme = (pref) => (pref === 'light' || pref === 'dark' ? pref : root.matchMedia && root.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
  const theme = {
    pref: () => doc.documentElement.getAttribute('data-theme') || 'auto',
    get() { return resolveTheme(theme.pref()); },
    set(name, persist) {
      const next = name === 'light' || name === 'dark' ? name : 'auto';
      doc.documentElement.setAttribute('data-theme', next);
      if (persist !== false) { try { root.localStorage.setItem(THEME_KEY, next); } catch (e) { /* storage unavailable */ } }
      doc.dispatchEvent(new CustomEvent('aurora:theme', { detail: { theme: theme.get(), preference: next } }));
    },
    toggle() { theme.set(theme.get() === 'dark' ? 'light' : 'dark'); },
  };
  Aurora.theme = theme;
  /** Puts the right icon and label on every [data-theme-toggle] button. */
  function syncToggles() {
    const dark = theme.get() === 'dark';
    doc.querySelectorAll('[data-theme-toggle]').forEach((b) => {
      while (b.firstChild && b.firstChild.nodeType === 1 && b.firstChild.classList.contains('a-icon')) b.removeChild(b.firstChild);
      b.insertBefore(icon(dark ? 'sun' : 'moon', { size: 17 }), b.firstChild);
      b.setAttribute('aria-label', dark ? t('theme.toLight') : t('theme.toDark'));
    });
  }
  theme.sync = syncToggles;

  /* ───────────────────────── reveal on scroll ───────────────────────── */
  let revealIO = null;
  function reveal(scope) {
    scope = scope || doc;
    if (!revealIO && 'IntersectionObserver' in root) {
      revealIO = new IntersectionObserver((entries) => {
        entries.forEach((e) => { if (e.isIntersecting) { e.target.classList.add('in'); revealIO.unobserve(e.target); } });
      }, { threshold: 0.06, rootMargin: '0px 0px -3% 0px' });
    }
    const nodes = Array.from(scope.querySelectorAll ? scope.querySelectorAll('.a-reveal:not(.in):not([data-a-seen])') : []);
    if (scope.matches && scope.matches('.a-reveal:not(.in):not([data-a-seen])')) nodes.unshift(scope);
    const perParent = new Map();
    nodes.forEach((n) => {
      n.setAttribute('data-a-seen', '');
      const i = perParent.get(n.parentNode) || 0;
      perParent.set(n.parentNode, i + 1);
      if (!n.style.getPropertyValue('--i')) n.style.setProperty('--i', Math.min(i, 12));
      if (revealIO) revealIO.observe(n); else n.classList.add('in');
    });
  }
  Aurora.reveal = reveal;

  /* ───────────────────────── count-up ───────────────────────── */
  const counters = new WeakMap();
  function countUp(node, to, o) {
    o = o || {};
    const f = formatterFor(o.format, o.digits);
    const prev = counters.get(node);
    if (prev) prev.cancel();
    to = +to;
    if (!finite(to)) { node.textContent = '–'; return { cancel: noop }; }
    const from = o.from != null ? +o.from : 0;
    node.dataset.value = String(to);
    if (reducedMotion() || doc.hidden || from === to) { node.textContent = f(to); return { cancel: noop }; }
    const dur = o.duration || 900;
    let start = null; let raf = 0;
    const step = (ts) => {
      if (start === null) start = ts;
      const t = Math.min(1, (ts - start) / dur);
      node.textContent = f(from + (to - from) * (t === 1 ? 1 : 1 - Math.pow(2, -10 * t)));
      if (t < 1) raf = root.requestAnimationFrame(step); else counters.delete(node);
    };
    node.textContent = f(from);
    raf = root.requestAnimationFrame(step);
    const handle = { cancel() { root.cancelAnimationFrame(raf); counters.delete(node); node.textContent = f(to); } };
    counters.set(node, handle);
    return handle;
  }
  Aurora.countUp = countUp;

  /* ───────────────────────── badge + severity ───────────────────────── */
  const BADGE_ICON = { good: 'check-circle', warn: 'alert', serious: 'alert-octagon', critical: 'x-circle', info: 'info', neutral: 'dot' };
  function badge(text, o) {
    o = o || {};
    const kind = BADGE_ICON[o.kind] ? o.kind : 'neutral';
    return el('span', { class: `a-badge a-badge--${kind}`, title: o.title }, o.icon === false ? null : icon(BADGE_ICON[kind], { size: 14 }), text);
  }
  const SEVERITY = {
    critical: ['critical', 'Critical'], high: ['serious', 'High'], medium: ['warn', 'Medium'], low: ['info', 'Low'], info: ['neutral', 'Info'],
    ok: ['good', 'OK'], pass: ['good', 'Pass'], good: ['good', 'Good'], warning: ['warn', 'Warning'], error: ['critical', 'Error'],
  };
  Aurora.severity = (level) => {
    const hit = SEVERITY[String(level).toLowerCase()];
    return hit ? { kind: hit[0], label: hit[1] } : { kind: 'neutral', label: String(level) };
  };
  Aurora.badge = badge;

  /* ───────────────────────── stat tile ───────────────────────── */
  function stat(parent, o) {
    const f = formatterFor(o.format || 'compact', o.digits);
    const valueEl = el('div', { class: 'a-stat__value', 'aria-hidden': 'true' }, '0');
    const row = el('div', { class: 'a-stat__row' });
    let hintEl = o.hint ? el('div', { class: 'a-stat__hint' }, o.hint) : null;
    const root_ = el('div', { class: `a-card a-stat a-reveal${o.hero ? ' a-stat--hero' : ''}`, role: 'group' },
      el('div', { class: 'a-stat__label' }, o.label), valueEl, hintEl, row);
    let sparkChart = null;
    let current = 0;

    function renderHint(text) {
      if (text == null || text === '') { if (hintEl) { hintEl.remove(); hintEl = null; } return; }
      if (!hintEl) { hintEl = el('div', { class: 'a-stat__hint' }); root_.insertBefore(hintEl, row); }
      hintEl.textContent = String(text);
    }

    function renderDelta(d) {
      row.querySelectorAll('.a-delta').forEach((n) => n.remove());
      if (!d || d.value == null || !finite(+d.value)) return;
      const v = +d.value;
      const sign = v > 0 ? 1 : v < 0 ? -1 : 0;
      const good = d.good === 'down' ? sign < 0 : sign > 0;
      const cls = sign === 0 ? 'flat' : good ? 'good' : 'bad';
      const text = `${fmt.signed(v * 100, Math.abs(v) < 0.1 ? 1 : 0)}%`;
      const node = el('span', { class: `a-delta a-delta--${cls}`, 'aria-label': `${sign > 0 ? 'up' : sign < 0 ? 'down' : 'flat'} ${fmt.pct(Math.abs(v), 1)}${d.period ? ' ' + d.period : ''}` },
        el('span', { class: 'a-delta__v' }, sign === 0 ? null : icon(sign > 0 ? 'arrow-up' : 'arrow-down', { size: 13 }), text), d.period ? el('small', d.period) : null);
      row.insertBefore(node, row.firstChild);
    }
    function renderSpark(values) {
      if (!Array.isArray(values) || !values.length || !root.AuroraCharts) return;
      if (sparkChart) { sparkChart.update(values); return; }
      const holder = el('div', { class: 'a-stat__spark' });
      row.appendChild(holder);
      sparkChart = root.AuroraCharts.spark(holder, { values });
    }
    function set(next) {
      if (next.value != null) {
        const target = +next.value;
        countUp(valueEl, target, { from: current, format: f, duration: 900 });
        current = finite(target) ? target : 0;
        root_.setAttribute('aria-label', `${o.label}: ${f(target)}`);
      }
      if ('hint' in next) renderHint(next.hint);
      if ('delta' in next) renderDelta(next.delta);
      if ('spark' in next) renderSpark(next.spark);
    }
    parent.appendChild(root_);
    reveal(root_);
    set({ value: o.value, delta: o.delta, spark: o.spark });
    return { el: root_, update: (next) => set(next || {}) };
  }
  Aurora.stat = stat;

  /* ───────────────────────── meter + segmented bar ───────────────────────── */
  function meter(parent, o) {
    const max = o.max || 100;
    const thresholds = (o.thresholds || []).slice().sort((a, b) => a.at - b.at);
    const f = o.format || fmt.int;
    const fill = el('i');
    const valueEl = el('span', { class: 'a-num' });
    const bar = el('div', { class: 'a-meter__bar', role: 'progressbar', 'aria-valuemin': 0, 'aria-valuemax': max, 'aria-label': o.label || t('meter.progress') }, fill);
    const node = el('div', { class: `a-meter${o.thin ? ' a-meter--thin' : ''}` }, o.label ? el('div', { class: 'a-meter__head' }, el('span', o.label), valueEl) : null, bar);
    function set(v) {
      const r = clamp(v / max, 0, 1);
      let kind = '';
      thresholds.forEach((t) => { if (r >= t.at) kind = t.kind; });
      node.dataset.kind = kind;
      bar.setAttribute('aria-valuenow', String(v));
      valueEl.textContent = f(v);
      fill.style.width = `${(r * 100).toFixed(2)}%`;
    }
    parent.appendChild(node);
    root.requestAnimationFrame(() => root.requestAnimationFrame(() => set(o.value || 0)));
    return { el: node, update: set };
  }
  Aurora.meter = meter;

  const SEG_COLOR = /^(?:#[0-9a-f]{3,8}|var\(--[\w-]+\))$/i;
  function segbar(parent, o) {
    const tall = !!o.tall;
    const vf = o.valueFormat || fmt.compact;
    const bar = el('div', { class: 'a-segbar__bar', role: 'img' });
    const legend = o.legend === false ? null : el('div', { class: 'a-segbar__legend' });
    const node = el('div', { class: `a-segbar${tall ? ' a-segbar--tall' : ''}` }, bar, legend);
    const colorOf = (p, i) => {
      if (typeof p.color === 'number') return `var(--series-${clamp(p.color, 1, 8)})`;
      if (typeof p.color === 'string' && SEG_COLOR.test(p.color)) return p.color;
      return p.name === 'Other' ? 'var(--chart-muted)' : `var(--series-${Math.min(8, i + 1)})`;
    };
    function render(parts) {
      const shown = parts.filter((p) => p.value > 0);
      const total = shown.reduce((s, p) => s + p.value, 0) || 1;
      while (bar.firstChild) bar.removeChild(bar.firstChild);
      if (legend) while (legend.firstChild) legend.removeChild(legend.firstChild);
      bar.setAttribute('aria-label', shown.map((p) => `${p.name} ${fmt.pct(p.value / total, 0)}`).join(', ') || t('segbar.nodata'));
      const made = []; // [element, part] created by THIS render, so a later update() in the same frame cannot confuse the labelling pass
      shown.forEach((p, i) => {
        const c = colorOf(p, i);
        const on = c === 'var(--series-4)' ? '#0b0b0b' : c === 'var(--chart-muted)' ? 'var(--ink-1)' : '#fff';
        const part = el('div', { class: 'a-segbar__part', tabindex: '0', title: `${p.name}: ${vf(p.value)} (${fmt.pct(p.value / total, 1)})`, 'aria-label': `${p.name}: ${vf(p.value)}, ${fmt.pct(p.value / total, 1)}`, style: { '--w': (p.value / total).toFixed(5), '--c': c, '--on': on } });
        bar.appendChild(part);
        made.push([part, p]);
        if (legend) legend.appendChild(el('span', { style: { '--c': c } }, el('i'), p.name));
      });
      if (tall) root.requestAnimationFrame(() => {
        made.forEach(([part, p]) => {
          if (!part.isConnected || !part.offsetWidth) return;
          const label = el('span', fmt.pct(p.value / total, 0));
          part.appendChild(label);
          if (label.offsetWidth + 16 > part.offsetWidth) label.remove();
        });
      });
    }
    parent.appendChild(node);
    render(o.parts || []);
    return { el: node, update: render };
  }
  Aurora.segbar = segbar;

  /* ───────────────────────── empty · skeleton · live ───────────────────────── */
  function empty(parent, o) {
    o = o || {};
    const node = el('div', { class: 'a-empty' },
      el('div', { class: 'a-empty__icon' }, icon(o.icon || 'sparkle', { size: 22 })),
      el('div', { class: 'a-empty__title' }, o.title || t('empty.title')),
      o.text ? el('div', { class: 'a-empty__text' }, o.text) : null,
      o.action ? el('button', { class: 'a-btn a-btn--sm a-btn--primary', type: 'button', onclick: o.action.onClick }, o.action.label) : null);
    if (parent) parent.appendChild(node);
    return node;
  }
  Aurora.empty = empty;
  Aurora.skeleton = (parent, o) => {
    o = o || {};
    const node = el('div', { class: 'a-stack', 'aria-hidden': 'true', style: { '--gap': '10px' } });
    for (let i = 0; i < (o.lines || 3); i++) node.appendChild(el('div', { class: 'a-skel', style: { height: o.height || '14px', width: i === (o.lines || 3) - 1 ? '62%' : '100%' } }));
    if (parent) parent.appendChild(node);
    return node;
  };
  Aurora.live = (parent, o) => {
    const text = el('span', (o && o.label) || t('live.live'));
    const node = el('span', { class: 'a-live', 'data-state': 'connecting', role: 'status' }, el('span', { class: 'a-live__dot' }), text);
    if (parent) parent.appendChild(node);
    return { el: node, set(state, label) { node.setAttribute('data-state', state); text.textContent = label || { live: t('live.live'), connecting: t('live.connecting'), offline: t('live.offline') }[state] || state; } };
  };

  /* ───────────────────────── toast ───────────────────────── */
  let toastHost = null;
  function toast(message, o) {
    o = o || {};
    const kind = ['good', 'warn', 'critical'].indexOf(o.kind) >= 0 ? o.kind : 'info';
    if (!toastHost || !toastHost.isConnected) { toastHost = el('div', { class: 'a-toasts', role: 'status', 'aria-live': 'polite' }); doc.body.appendChild(toastHost); }
    const node = el('div', { class: `a-toast a-toast--${kind}` }, icon({ good: 'check-circle', warn: 'alert', critical: 'x-circle', info: 'info' }[kind], { size: 18 }), el('div', message));
    toastHost.appendChild(node);
    while (toastHost.children.length > 4) toastHost.firstChild.remove();
    const dismiss = () => {
      if (!node.isConnected || node.classList.contains('is-leaving')) return;
      node.classList.add('is-leaving');
      setTimeout(() => node.remove(), 230);
    };
    node.addEventListener('click', dismiss);
    setTimeout(dismiss, o.duration || 3200);
    return { dismiss };
  }
  Aurora.toast = toast;

  /* ───────────────────────── dialog · drawer · confirm ───────────────────────── */
  function dialog(o) {
    o = o || {};
    const titleId = uid('dlg');
    const d = el('dialog', { class: `a-dialog${o.size ? ' a-dialog--' + o.size : ''}${o.drawer ? ' a-dialog--drawer' : ''}`, 'aria-labelledby': titleId });
    const closeBtn = el('button', { class: 'a-btn a-btn--ghost a-btn--icon a-btn--sm', type: 'button', 'aria-label': t('dialog.close'), onclick: () => d.close() }, icon('x'));
    d.appendChild(el('div', { class: 'a-dialog__head' }, el('div', { class: 'a-dialog__title', id: titleId }, o.title || ''), el('span', { class: 'a-spacer' }), closeBtn));
    d.appendChild(el('div', { class: 'a-dialog__body' }, o.content));
    if (o.actions && o.actions.length) {
      d.appendChild(el('div', { class: 'a-dialog__foot' }, o.actions.map((a) => el('button', {
        class: `a-btn${a.kind ? ' a-btn--' + a.kind : ''}`, type: 'button',
        onclick: (ev) => { const r = a.onClick ? a.onClick(ev) : undefined; if (a.closes !== false && r !== false) d.close(); },
      }, a.label))));
    }
    d.addEventListener('click', (e) => { if (e.target === d) d.close(); });
    d.addEventListener('close', () => { if (o.keep !== true) d.remove(); if (o.onClose) o.onClose(); });
    const open = () => { if (!d.isConnected) doc.body.appendChild(d); if (!d.open) { if (d.showModal) d.showModal(); else d.setAttribute('open', ''); } };
    if (o.open !== false) open();
    return { el: d, open, close: () => d.close() };
  }
  Aurora.dialog = dialog;
  Aurora.confirm = (o) => new Promise((resolve) => {
    let answered = false;
    const answer = (v) => { answered = true; resolve(v); };
    dialog({
      title: o.title || 'Are you sure?', size: 'sm', content: el('p', { class: 'a-muted' }, o.message || ''),
      actions: [{ label: o.cancelLabel || t('confirm.cancel'), kind: 'ghost', onClick: () => answer(false) }, { label: o.confirmLabel || t('confirm.ok'), kind: o.kind === 'danger' ? 'danger' : 'primary', onClick: () => answer(true) }],
      onClose: () => { if (!answered) resolve(false); },
    });
  });

  /* ───────────────────────── command palette ───────────────────────── */
  const cmdk = { items: [], dlg: null, state: null };
  function fuzzy(q, text) {
    q = q.toLowerCase(); text = text.toLowerCase();
    if (!q) return 0;
    let ti = 0; let score = 0; let streak = 0;
    for (let qi = 0; qi < q.length; qi++) {
      const at = text.indexOf(q[qi], ti);
      if (at < 0) return -1;
      streak = at === ti ? streak + 1 : 0;
      score += 1 + streak * 2 + (at === 0 || ' -_/.'.indexOf(text[at - 1]) >= 0 ? 3 : 0);
      ti = at + 1;
    }
    return score - text.length * 0.01;
  }
  /** Adds (or replaces, by id) commands. Returns a function that removes exactly these commands again. */
  cmdk.register = (list) => {
    list.forEach((c) => {
      const i = cmdk.items.findIndex((x) => x.id === c.id);
      if (i >= 0) cmdk.items[i] = c; else cmdk.items.push(c);
    });
    return () => cmdk.unregister(list.map((c) => c.id));
  };
  /** Removes commands by id (string or array), or every command of a group: unregister({ group: 'Recent' }). */
  cmdk.unregister = (what) => {
    const ids = new Set([].concat(what && typeof what === 'object' && !Array.isArray(what) ? cmdk.items.filter((c) => c.group === what.group).map((c) => c.id) : what));
    cmdk.items = cmdk.items.filter((c) => !ids.has(c.id));
  };
  cmdk.close = () => { if (cmdk.dlg && cmdk.dlg.open) cmdk.dlg.close(); };
  cmdk.open = () => {
    if (cmdk.dlg && cmdk.dlg.open) return;
    const input = el('input', { class: 'a-cmdk__input', type: 'text', placeholder: t('cmdk.placeholder'), role: 'combobox', 'aria-expanded': 'true', 'aria-controls': 'a-cmdk-list', 'aria-autocomplete': 'list', autocomplete: 'off', spellcheck: 'false' });
    const list = el('ul', { class: 'a-cmdk__list', id: 'a-cmdk-list', role: 'listbox' });
    const dlg = el('dialog', { class: 'a-cmdk', 'aria-label': t('cmdk.label') }, input, list);
    let shown = []; let sel = 0;
    function render() {
      while (list.firstChild) list.removeChild(list.firstChild);
      const q = input.value.trim();
      shown = cmdk.items.map((c) => ({ c, s: Math.max(fuzzy(q, c.label), c.keywords ? fuzzy(q, c.keywords) - 1 : -1) })).filter((x) => x.s >= 0)
        .sort((a, b) => (q ? b.s - a.s : 0)).map((x) => x.c);
      sel = clamp(sel, 0, Math.max(0, shown.length - 1));
      if (!shown.length) { list.appendChild(el('li', { class: 'a-cmdk__empty' }, t('cmdk.empty'))); return; }
      let group = null;
      shown.forEach((c, i) => {
        if (c.group && c.group !== group) { group = c.group; list.appendChild(el('li', { class: 'a-cmdk__group', role: 'presentation' }, group)); }
        list.appendChild(el('li', { class: 'a-cmdk__item', role: 'option', id: `a-cmdk-o${i}`, 'aria-selected': String(i === sel), onclick: () => run(i), onmousemove: () => { if (sel !== i) { sel = i; mark(); } } },
          el('span', c.label), c.hint ? el('span', { class: 'a-cmdk__hint' }, c.hint) : null));
      });
      input.setAttribute('aria-activedescendant', `a-cmdk-o${sel}`);
    }
    function mark() {
      list.querySelectorAll('.a-cmdk__item').forEach((n, i) => n.setAttribute('aria-selected', String(i === sel)));
      input.setAttribute('aria-activedescendant', `a-cmdk-o${sel}`);
      const n = list.querySelector(`#a-cmdk-o${sel}`);
      if (n && n.scrollIntoView) n.scrollIntoView({ block: 'nearest' });
    }
    function run(i) { const c = shown[i]; dlg.close(); if (c && c.run) setTimeout(() => c.run(), 0); }
    input.addEventListener('input', () => { sel = 0; render(); });
    input.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowDown') { e.preventDefault(); sel = shown.length ? (sel + 1) % shown.length : 0; mark(); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); sel = shown.length ? (sel - 1 + shown.length) % shown.length : 0; mark(); }
      else if (e.key === 'Enter') { e.preventDefault(); run(sel); }
    });
    dlg.addEventListener('click', (e) => { if (e.target === dlg) dlg.close(); });
    dlg.addEventListener('close', () => { dlg.remove(); cmdk.dlg = null; });
    doc.body.appendChild(dlg);
    cmdk.dlg = dlg;
    render();
    if (dlg.showModal) dlg.showModal(); else dlg.setAttribute('open', '');
    input.focus();
  };
  Aurora.cmdk = cmdk;

  /* ───────────────────────── clipboard ───────────────────────── */
  function copy(text, o) {
    o = o || {};
    const done = (ok) => { if (o.toast !== false) toast(ok ? o.label || t('copy.done') : t('copy.failed'), { kind: ok ? 'good' : 'critical', duration: 1800 }); return ok; };
    const legacy = () => {
      const ta = el('textarea', { readonly: '', 'aria-hidden': 'true', style: { position: 'fixed', top: '-1000px', opacity: '0' } });
      ta.value = String(text);
      doc.body.appendChild(ta);
      ta.select();
      let ok = false;
      try { ok = doc.execCommand('copy'); } catch (e) { ok = false; }
      ta.remove();
      return done(ok);
    };
    if (root.navigator && root.navigator.clipboard && root.isSecureContext) {
      return root.navigator.clipboard.writeText(String(text)).then(() => done(true), () => legacy());
    }
    return Promise.resolve(legacy());
  }
  Aurora.copy = copy;

  /* ───────────────────────── key-value · code · details · feed ───────────────────────── */
  Aurora.kv = (parent, items, o) => {
    const dl = el('dl', { class: `a-kv${o && o.mono ? ' a-kv--mono' : ''}` });
    (items || []).forEach((pair) => { dl.appendChild(el('dt', pair[0])); dl.appendChild(el('dd', pair[1] == null || pair[1] === '' ? '–' : pair[1])); });
    if (parent) parent.appendChild(dl);
    return dl;
  };
  Aurora.code = (parent, text, o) => {
    o = o || {};
    const wrap = el('div', { class: 'a-code-wrap' }, el('pre', { class: `a-code${o.wrap ? ' a-code--wrap' : ''}`, tabindex: '0' }, el('code', String(text))));
    if (o.copy !== false) wrap.appendChild(el('button', { class: 'a-btn a-btn--ghost a-btn--icon a-btn--sm a-code__copy', type: 'button', 'aria-label': (o && o.copyLabel) || t('code.copy'), onclick: () => copy(text) }, icon('copy', { size: 15 })));
    if (parent) parent.appendChild(wrap);
    return wrap;
  };
  Aurora.details = (parent, o) => {
    o = o || {};
    const d = el('details', { class: 'a-details', open: !!o.open }, el('summary', el('span', o.summary), o.meta ? el('span', { class: 'a-spacer' }) : null, o.meta || null), el('div', { class: 'a-details__body' }, o.content));
    if (parent) parent.appendChild(d);
    return d;
  };
  Aurora.feed = (parent, o) => {
    const max = (o && o.max) || 20;
    const ul = el('ul', { class: 'a-feed' });
    if (parent) parent.appendChild(ul);
    return {
      el: ul,
      push(node) { const li = el('li', { class: 'a-feed__item' }, node); ul.insertBefore(li, ul.firstChild); while (ul.children.length > max) ul.lastChild.remove(); return li; },
      clear() { while (ul.firstChild) ul.removeChild(ul.firstChild); },
    };
  };

  /* ───────────────────────── dropzone ───────────────────────── */
  function dropzone(node, o) {
    o = o || {};
    node.classList.add('a-dropzone');
    node.setAttribute('role', 'button');
    node.setAttribute('tabindex', '0');
    node.setAttribute('aria-label', o.title || t('dropzone.choose'));
    const input = el('input', { type: 'file', hidden: true, tabindex: '-1', 'aria-hidden': 'true' });
    if (o.accept) input.setAttribute('accept', o.accept);
    if (o.multiple) input.multiple = true;
    node.appendChild(el('div', { class: 'a-dropzone__icon' }, icon('upload', { size: 24 })));
    node.appendChild(el('div', { class: 'a-dropzone__title' }, o.title || t('dropzone.title')));
    node.appendChild(el('div', { class: 'a-dropzone__hint' }, o.hint || t('dropzone.hint')));
    node.appendChild(input);
    function handle(list) {
      const files = Array.prototype.slice.call(list || []);
      const ok = [];
      files.forEach((f) => {
        if (o.maxBytes && f.size > o.maxBytes) { if (o.onReject) o.onReject({ reason: 'too-large', file: f, maxBytes: o.maxBytes }); } else ok.push(f);
      });
      if (ok.length && o.onFiles) o.onFiles(o.multiple ? ok : [ok[0]]);
    }
    node.addEventListener('click', (e) => { if (e.target !== input) input.click(); });
    node.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });
    input.addEventListener('change', () => { handle(input.files); input.value = ''; });
    ['dragenter', 'dragover'].forEach((t) => node.addEventListener(t, (e) => { e.preventDefault(); node.classList.add('is-over'); }));
    ['dragleave', 'dragend'].forEach((t) => node.addEventListener(t, () => node.classList.remove('is-over')));
    node.addEventListener('drop', (e) => { e.preventDefault(); node.classList.remove('is-over'); handle(e.dataTransfer && e.dataTransfer.files); });
    return { el: node, setBusy(b) { node.classList.toggle('is-busy', !!b); node.setAttribute('aria-busy', String(!!b)); } };
  }
  Aurora.dropzone = dropzone;

  /* ───────────────────────── page-wide drop: drag a file anywhere over the page ───────────────────────── */
  // Aurora.pageDrop({ onFiles(files), title, hint }) -> { destroy() }. Only reacts to drags that carry files.
  Aurora.pageDrop = (o) => {
    o = o || {};
    let depth = 0; let overlay = null;
    const hasFiles = (e) => !!(e.dataTransfer && Array.prototype.indexOf.call(e.dataTransfer.types || [], 'Files') >= 0);
    const hide = () => { depth = 0; if (overlay) { overlay.remove(); overlay = null; } };
    const on = {
      dragenter(e) {
        if (!hasFiles(e)) return;
        e.preventDefault(); depth++;
        if (!overlay) {
          overlay = el('div', { class: 'a-pagedrop', 'aria-hidden': 'true' }, el('div', { class: 'a-pagedrop__card' }, icon('upload', { size: 30 }), el('strong', o.title || t('pagedrop.title')), o.hint ? el('span', o.hint) : null));
          doc.body.appendChild(overlay);
        }
      },
      dragover(e) { if (hasFiles(e)) e.preventDefault(); },
      dragleave(e) { if (hasFiles(e)) { depth = Math.max(0, depth - 1); if (!depth) hide(); } },
      drop(e) {
        if (!hasFiles(e)) return;
        e.preventDefault(); hide();
        const files = Array.prototype.slice.call(e.dataTransfer.files || []);
        if (files.length && o.onFiles) o.onFiles(files);
      },
    };
    Object.keys(on).forEach((k) => doc.addEventListener(k, on[k]));
    return { destroy() { hide(); Object.keys(on).forEach((k) => doc.removeEventListener(k, on[k])); } };
  };

  /* ───────────────────────── tabs ───────────────────────── */
  function tabs(parent, o) {
    const items = o.tabs.slice();
    let active = o.active || (items[0] && items[0].id);
    const thumb = el('span', { class: 'a-tabs__thumb', 'aria-hidden': 'true' });
    const node = el('div', { class: 'a-tabs', role: 'tablist', 'aria-label': o.ariaLabel || t('tabs.sections') }, thumb);
    const btns = {};
    const counts = {};
    items.forEach((t) => {
      const count = t.count != null ? el('span', { class: 'a-tab__count' }, String(t.count)) : null;
      counts[t.id] = count;
      btns[t.id] = el('button', { class: 'a-tab', role: 'tab', type: 'button', id: uid('tab'), 'aria-selected': 'false', tabindex: '-1', onclick: () => select(t.id) }, t.label, count);
      node.appendChild(btns[t.id]);
    });
    function place() {
      const b = btns[active];
      if (!b || !b.offsetWidth) return;
      thumb.style.width = `${b.offsetWidth}px`;
      thumb.style.transform = `translateX(${b.offsetLeft}px)`;
      node.classList.add('has-thumb');
    }
    function select(id, silent) {
      if (!btns[id]) return;
      const changed = id !== active;
      active = id;
      items.forEach((t) => {
        const on = t.id === id;
        btns[t.id].setAttribute('aria-selected', String(on));
        btns[t.id].tabIndex = on ? 0 : -1;
        if (o.panels && o.panels[t.id]) o.panels[t.id].hidden = !on;
      });
      place();
      if (changed && !silent && o.onChange) o.onChange(id);
    }
    node.addEventListener('keydown', (e) => {
      const i = items.findIndex((t) => t.id === active);
      let n = -1;
      if (e.key === 'ArrowRight') n = (i + 1) % items.length;
      else if (e.key === 'ArrowLeft') n = (i - 1 + items.length) % items.length;
      else if (e.key === 'Home') n = 0;
      else if (e.key === 'End') n = items.length - 1;
      if (n >= 0) { e.preventDefault(); select(items[n].id); btns[items[n].id].focus(); }
    });
    parent.appendChild(node);
    select(active, true);
    root.requestAnimationFrame(place);
    if (root.ResizeObserver) new root.ResizeObserver(place).observe(node);
    if (doc.fonts && doc.fonts.ready) doc.fonts.ready.then(place);
    return {
      el: node, select,
      setLabel(id, text) {
        const b = btns[id];
        if (!b) return;
        if (b.firstChild && b.firstChild.nodeType === 3) b.firstChild.nodeValue = String(text);
        else b.insertBefore(doc.createTextNode(String(text)), b.firstChild);
        place();
      },
      setCount(id, n) {
        if (!btns[id]) return;
        if (!counts[id]) { counts[id] = el('span', { class: 'a-tab__count' }); btns[id].appendChild(counts[id]); }
        counts[id].textContent = String(n);
        place();
      },
    };
  }
  Aurora.tabs = tabs;

  /* ───────────────────────── table ───────────────────────── */
  const cmp = (a, b) => {
    if (a == null && b == null) return 0;
    if (a == null) return 1;
    if (b == null) return -1;
    if (a instanceof Date) a = +a;
    if (b instanceof Date) b = +b;
    if (typeof a === 'number' && typeof b === 'number') return a - b;
    return String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' });
  };
  function table(parent, o) {
    o = o || {};
    const cols = o.columns || [];
    const st = { rows: (o.rows || []).slice(), sort: o.sort ? { key: o.sort.key, dir: o.sort.dir || 'desc' } : null, q: '', page: 0 };
    const pageSize = o.pageSize > 0 ? o.pageSize : 0;
    const searchOpts = o.search === true ? {} : o.search && typeof o.search === 'object' ? o.search : null;
    const thead = el('thead'); const tbody = el('tbody');
    const tbl = el('table', { class: `a-table${o.dense ? ' a-table--dense' : ''}${o.captionVisible ? ' a-table--captioned' : ''}` }, o.caption ? el('caption', o.caption) : null, thead, tbody);
    const pager = pageSize ? el('div', { class: 'a-pager' }) : null;
    const searchInput = searchOpts ? el('input', { class: 'a-input', type: 'search', placeholder: searchOpts.placeholder || t('table.search'), 'aria-label': searchOpts.placeholder || t('table.searchLabel'), oninput: debounce((e) => { st.q = e.target.value; st.page = 0; render(); }, 120) }) : null;
    const node = el('div', { class: 'a-table-root' }, searchInput ? el('div', { class: 'a-toolbar' }, icon('search', { size: 16 }), searchInput) : null, el('div', { class: 'a-tablewrap' }, tbl), pager);

    function view() {
      let rows = st.rows;
      if (st.q) {
        const q = st.q.toLowerCase();
        const keys = (searchOpts && searchOpts.keys) || cols.map((c) => c.key);
        rows = rows.filter((r) => keys.some((k) => String(r[k] == null ? '' : r[k]).toLowerCase().indexOf(q) >= 0));
      }
      if (st.sort) {
        const dir = st.sort.dir === 'asc' ? 1 : -1;
        const key = st.sort.key;
        rows = rows.slice().sort((a, b) => dir * cmp(a[key], b[key]));
      }
      return rows;
    }
    function head() {
      while (thead.firstChild) thead.removeChild(thead.firstChild);
      const tr = el('tr');
      cols.forEach((c) => {
        const sortable = c.sortable !== false;
        const on = st.sort && st.sort.key === c.key;
        const th = el('th', { scope: 'col', 'data-align': c.align || 'left', style: c.width ? { width: c.width } : null, 'aria-sort': on ? (st.sort.dir === 'asc' ? 'ascending' : 'descending') : null });
        if (sortable) {
          th.appendChild(el('button', { type: 'button', onclick: () => { setSort(c.key, on && st.sort.dir === 'desc' ? 'asc' : 'desc'); } }, c.label, on ? icon(st.sort.dir === 'asc' ? 'arrow-up' : 'arrow-down', { size: 12 }) : null));
        } else th.textContent = c.label;
        tr.appendChild(th);
      });
      thead.appendChild(tr);
    }
    function render() {
      const rows = view();
      const total = rows.length;
      const pages = pageSize ? Math.max(1, Math.ceil(total / pageSize)) : 1;
      st.page = clamp(st.page, 0, pages - 1);
      const slice = pageSize ? rows.slice(st.page * pageSize, (st.page + 1) * pageSize) : rows;
      while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
      if (!slice.length) {
        const e = o.empty || {};
        tbody.appendChild(el('tr', el('td', { colspan: String(cols.length || 1) }, empty(null, { title: e.title || (st.q ? t('table.noMatches') : t('table.nothing')), text: e.text || (st.q ? t('table.tryAnother') : '') }))));
      }
      slice.forEach((row) => {
        const tr = el('tr');
        if (o.onRowClick) {
          tr.setAttribute('data-clickable', ''); tr.tabIndex = 0;
          tr.addEventListener('click', (ev) => o.onRowClick(row, ev));
          // only when the row itself has focus: Enter/Space on a button or link inside the row belongs to that control
          tr.addEventListener('keydown', (ev) => { if (ev.target === tr && (ev.key === 'Enter' || ev.key === ' ')) { ev.preventDefault(); o.onRowClick(row, ev); } });
        }
        cols.forEach((c) => {
          const v = row[c.key];
          const out = c.format ? c.format(v, row) : v == null ? '' : v instanceof Date ? fmt.date(v, { time: true }) : String(v);
          const td = el('td', { 'data-align': c.align || 'left', class: c.mono ? 'is-mono' : null });
          if (isNode(out)) td.appendChild(out); else { td.textContent = String(out); if (String(out).length > 48) td.title = String(out); }
          tr.appendChild(td);
        });
        tbody.appendChild(tr);
      });
      if (pager) {
        while (pager.firstChild) pager.removeChild(pager.firstChild);
        pager.hidden = total <= pageSize;
        const from = total ? st.page * pageSize + 1 : 0;
        pager.appendChild(el('span', { class: 'a-num', 'aria-live': 'polite' }, `${fmt.int(from)}–${fmt.int(Math.min(total, (st.page + 1) * pageSize))} ${t('table.of')} ${fmt.int(total)}`));
        pager.appendChild(el('button', { class: 'a-btn a-btn--sm', type: 'button', disabled: st.page === 0, onclick: () => { st.page--; render(); } }, t('table.prev')));
        pager.appendChild(el('button', { class: 'a-btn a-btn--sm', type: 'button', disabled: st.page >= pages - 1, onclick: () => { st.page++; render(); } }, t('table.next')));
      }
    }
    function setSort(key, dir) { st.sort = { key, dir: dir || 'desc' }; head(); render(); }
    parent.appendChild(node);
    head();
    render();
    return {
      el: node,
      update(rows) { st.rows = (rows || []).slice(); render(); },
      setSort,
      filter(text) { st.q = text || ''; st.page = 0; if (searchInput) searchInput.value = st.q; render(); },
    };
  }
  Aurora.table = table;

  /* ───────────────────────── date-range menu ───────────────────────── */
  function dateRange(parent, o) {
    const presets = o.presets || [];
    let current = o.value || (presets[0] && presets[0].id);
    const labelOf = (id) => { const p = presets.find((x) => x.id === id); return p ? p.label : String(id); };
    const label = el('span', labelOf(current));
    const btn = el('button', { class: 'a-btn a-btn--sm', type: 'button', 'aria-haspopup': 'listbox', 'aria-expanded': 'false' }, icon('clock', { size: 14 }), label, icon('chevron-down', { size: 14 }));
    const wrap = el('div', { class: 'a-menu-wrap' }, btn);
    let menu = null;
    const onOutside = (e) => { if (menu && !wrap.contains(e.target)) close(); };
    const onKey = (e) => {
      if (!menu) return;
      const items = Array.from(menu.querySelectorAll('.a-menu__item'));
      const i = items.indexOf(doc.activeElement);
      if (e.key === 'Escape') { e.preventDefault(); close(); btn.focus(); }
      else if (e.key === 'ArrowDown') { e.preventDefault(); items[(i + 1) % items.length].focus(); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); items[(i - 1 + items.length) % items.length].focus(); }
      else if (e.key === 'Tab') close();
    };
    function close() {
      if (!menu) return;
      menu.remove(); menu = null;
      btn.setAttribute('aria-expanded', 'false');
      doc.removeEventListener('pointerdown', onOutside, true);
      doc.removeEventListener('keydown', onKey, true);
    }
    function choose(id) {
      const changed = id !== current;
      current = id; label.textContent = labelOf(id); close(); btn.focus();
      if (changed && o.onChange) o.onChange(id);
    }
    btn.addEventListener('click', () => {
      if (menu) { close(); return; }
      menu = el('div', { class: 'a-menu', role: 'listbox', 'aria-label': t('range.label') }, presets.map((p) => el('button', { class: 'a-menu__item', type: 'button', role: 'option', 'aria-selected': String(p.id === current), onclick: () => choose(p.id) }, p.label, icon('check', { size: 16 }))));
      wrap.appendChild(menu);
      btn.setAttribute('aria-expanded', 'true');
      doc.addEventListener('pointerdown', onOutside, true);
      doc.addEventListener('keydown', onKey, true);
      (menu.querySelector('[aria-selected="true"]') || menu.firstChild).focus();
    });
    parent.appendChild(wrap);
    return { el: wrap, value: () => current };
  }
  Aurora.dateRange = dateRange;

  /* ───────────────────────── segmented switch and pill tabs ───────────────────────── */
  /** One row of choices, as links (a router) or as buttons (a tablist). kind: 'seg' (the view switch) or 'pills' (the tab pills). */
  function choice(parent, o, kind) {
    const seg = kind === 'seg';
    const cls = seg ? ['a-seg', 'a-seg__item'] : ['a-pilltabs', 'a-pilltab'];
    const countCls = seg ? 'a-tab__count' : 'a-pilltab__count';
    const node = el('div', { class: cls[0] });
    const nodes = {};
    let items = [];
    let active = o.active;

    function select(id, silent) {
      const changed = id !== active;
      active = id;
      items.forEach((it) => {
        const b = nodes[it.id];
        if (!b) return;
        const on = it.id === id;
        b.classList.toggle('is-active', on);
        if (it.href) { if (on) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current'); }
        else { b.setAttribute('aria-selected', String(on)); b.tabIndex = on ? 0 : -1; }
      });
      if (changed && !silent && o.onChange) o.onChange(id, items.find((it) => it.id === id));
    }
    function render(list, current) {
      items = (list || []).slice();
      if (current !== undefined) active = current;
      if (!items.some((it) => it.id === active)) active = items[0] ? items[0].id : undefined;
      while (node.firstChild) node.removeChild(node.firstChild);
      const links = items.some((it) => it.href);
      node.setAttribute('role', links ? 'navigation' : 'tablist');
      if (o.ariaLabel) node.setAttribute('aria-label', o.ariaLabel);
      items.forEach((it) => {
        const kids = [it.icon ? icon(it.icon, { size: 14 }) : null, el('span', { class: 'a-choice__label' }, it.label), it.count != null ? el('span', { class: countCls }, String(it.count)) : null];
        const attrs = { class: cls[1], title: it.title, 'data-id': it.id };
        let b;
        if (it.href) { b = el('a', Object.assign(attrs, { href: it.href }), kids); b.addEventListener('click', () => select(it.id)); }
        else b = el('button', Object.assign(attrs, { type: 'button', role: 'tab', onclick: () => select(it.id) }), kids);
        nodes[it.id] = b;
        node.appendChild(b);
      });
      select(active, true);
    }
    node.addEventListener('keydown', (e) => {
      if (items.some((it) => it.href)) return;
      const i = items.findIndex((it) => it.id === active);
      let n = -1;
      if (e.key === 'ArrowRight') n = (i + 1) % items.length;
      else if (e.key === 'ArrowLeft') n = (i - 1 + items.length) % items.length;
      else if (e.key === 'Home') n = 0;
      else if (e.key === 'End') n = items.length - 1;
      if (n >= 0) { e.preventDefault(); select(items[n].id); nodes[items[n].id].focus(); }
    });
    render(o.items || [], o.active);
    if (parent) parent.appendChild(node);
    return {
      el: node, select,
      value: () => active,
      setItems(list, current) { render(list, current); },
      setCount(id, n) {
        const b = nodes[id];
        if (!b) return;
        let c = b.querySelector('.' + countCls);
        if (!c) { c = el('span', { class: countCls }); b.appendChild(c); }
        c.textContent = String(n);
      },
    };
  }
  /** The segmented view switch of the Aurora sub bar. */
  Aurora.seg = (parent, o) => choice(parent, o || {}, 'seg');
  /** The row of pill tabs (the "project tabs" of the Aurora layout). */
  Aurora.pilltabs = (parent, o) => choice(parent, o || {}, 'pills');

  /* ───────────────────────── shell: the Aurora layout ───────────────────────── */
  const isMac = () => /Mac|iPhone|iPad/.test((root.navigator && (root.navigator.platform || root.navigator.userAgent)) || '');
  const clear = (node) => { while (node.firstChild) node.removeChild(node.firstChild); };

  function railItem(it) {
    const attrs = { class: 'a-rail__item', 'aria-label': it.label, 'data-tip': it.label, 'data-id': it.id };
    let node;
    if (it.theme) node = el('button', Object.assign(attrs, { type: 'button', 'data-theme-toggle': true, 'data-tip': it.label || t('shell.theme') }));
    else if (it.cmdk) node = el('button', Object.assign(attrs, { type: 'button', 'data-cmdk': true }), icon(it.icon || 'search', { size: 20 }));
    else if (it.href) node = el('a', Object.assign(attrs, { href: it.href }, it.external ? { target: '_blank', rel: 'noopener noreferrer' } : null), icon(it.icon || 'dot', { size: 20 }));
    else node = el('button', Object.assign(attrs, { type: 'button' }), icon(it.icon || 'dot', { size: 20 }));
    if (it.onClick) node.addEventListener('click', it.onClick);
    if (it.badge) node.appendChild(el('span', { class: 'a-rail__badge' }, it.badge > 99 ? '99+' : String(it.badge)));
    if (it.active) { node.classList.add('is-active'); node.setAttribute('aria-current', 'page'); }
    return node;
  }

  /**
   * Builds the Aurora layout (a navigation rail down the left; beside it the top bar, the view switch and tabs,
   * the content and the status bar, under a soft glow) and returns handles to fill it.
   * The content goes into `shell.container`.
   */
  function shell(o) {
    o = o || {};
    const mount = o.mount || doc.body;
    if (!doc.body.classList.contains('a-body')) doc.body.classList.add('a-body');
    const brand = o.brand || {};
    const items = {};

    // rail
    const rail = el('nav', { class: 'a-rail', 'aria-label': o.railLabel || t('shell.rail') });
    const mark = isNode(brand.mark) ? brand.mark : icon(brand.mark || 'prism', { size: 22 });
    const logoAttrs = { class: 'a-rail__logo', 'aria-label': brand.name || undefined, 'data-tip': brand.name || undefined };
    rail.appendChild(brand.href ? el('a', Object.assign(logoAttrs, { href: brand.href }), mark) : el('span', logoAttrs, mark));
    const spec = o.rail || [];
    (spec.some((x) => Array.isArray(x) || x === 'spacer') ? spec : [spec]).forEach((entry) => {
      if (entry === 'spacer') { rail.appendChild(el('div', { class: 'a-rail__spacer' })); return; }
      const group = el('div', { class: 'a-rail__group' });
      [].concat(entry).forEach((it) => { const n = railItem(it); if (it.id) items[it.id] = n; group.appendChild(n); });
      rail.appendChild(group);
    });

    // top bar
    const crumbs = el('nav', { class: 'a-crumbs', 'aria-label': t('shell.here') });
    const searchLabel = (o.search && o.search.label) || t('shell.search');
    const search = o.search === false ? null : el('button', { class: 'a-search', type: 'button', 'data-cmdk': true, 'aria-label': searchLabel }, icon('search', { size: 14 }), el('span', searchLabel), el('kbd', { class: 'a-kbd' }, isMac() ? '⌘ K' : 'Ctrl K'));
    const actions = el('div', { class: 'a-topbar__end' });
    const topbar = el('header', { class: 'a-topbar' }, crumbs, el('div', { class: 'a-topbar__fill', 'aria-hidden': 'true' }), search, actions);

    // sub bar: view switch, tab pills, end pills
    const tabsHost = el('div', { class: 'a-subbar__tabs' });
    const subEnd = el('div', { class: 'a-subbar__end' });
    const subbar = el('div', { class: 'a-subbar' }, tabsHost, subEnd);
    const chrome = el('div', { class: 'a-chrome' }, topbar, subbar);

    // content and status bar
    const container = el('div', { class: 'a-container', id: o.containerId || undefined });
    const main = el('main', { class: 'a-main', id: o.mainId || 'main', tabindex: '-1' }, container);
    const stStart = el('div', { class: 'a-statusbar__group' });
    const stEnd = el('div', { class: 'a-statusbar__group' });
    const statusbar = el('footer', { class: 'a-statusbar' }, stStart, el('div', { class: 'a-statusbar__fill' }), stEnd);
    if (o.status === false) statusbar.hidden = true;

    const frame = el('div', { class: 'a-frame' }, chrome, main, statusbar);
    const wrap = el('div', { class: 'a-shell' }, rail, frame);
    const skip = el('a', { class: 'a-skip', href: `#${main.id}` }, o.skipLabel || t('shell.skip'));
    mount.insertBefore(wrap, mount.firstChild);
    mount.insertBefore(skip, wrap);

    let views = null;
    let tabs = null;
    const api = { el: wrap, rail, frame, chrome, topbar, subbar, main, container, statusbar, items };
    Object.defineProperties(api, { views: { get: () => views }, tabs: { get: () => tabs } });

    function fitSubbar() { subbar.hidden = !(views || tabs || subEnd.firstChild); }
    api.setCrumbs = (list) => {
      clear(crumbs);
      const arr = (list || []).filter(Boolean);
      arr.forEach((c, i) => {
        const it = typeof c === 'string' ? { label: c } : c;
        if (i) crumbs.appendChild(icon('chevron-right', { size: 13 }));
        crumbs.appendChild(i === arr.length - 1 ? el('strong', { 'aria-current': 'page' }, it.label) : it.href ? el('a', { href: it.href }, it.label) : el('span', it.label));
      });
    };
    api.setActive = (id) => {
      Object.keys(items).forEach((k) => {
        const on = k === id;
        items[k].classList.toggle('is-active', on);
        if (on) items[k].setAttribute('aria-current', 'page'); else items[k].removeAttribute('aria-current');
      });
    };
    api.setBadge = (id, n) => {
      const node = items[id];
      if (!node) return;
      const old = node.querySelector('.a-rail__badge');
      if (old) old.remove();
      if (n) node.appendChild(el('span', { class: 'a-rail__badge' }, n > 99 ? '99+' : String(n)));
    };
    api.setActions = (nodes) => { clear(actions); [].concat(nodes || []).forEach((n) => append(actions, n)); if (o.theme !== false) actions.appendChild(el('button', { class: 'a-nav-btn', type: 'button', 'data-theme-toggle': true })); syncToggles(); };
    api.setViews = (opts) => {
      if (views) { views.el.remove(); views = null; }
      if (opts && opts.items && opts.items.length) { views = Aurora.seg(null, opts); subbar.insertBefore(views.el, tabsHost); }
      fitSubbar();
      return views;
    };
    api.setTabs = (opts) => {
      clear(tabsHost);
      tabs = opts && opts.items && opts.items.length ? Aurora.pilltabs(tabsHost, opts) : null;
      fitSubbar();
      return tabs;
    };
    api.setSubbarEnd = (nodes) => { clear(subEnd); [].concat(nodes || []).forEach((n) => append(subEnd, n)); fitSubbar(); };
    api.setStatus = (s) => {
      clear(stStart); clear(stEnd);
      const fill = (host, list) => [].concat(list || []).filter((n) => n != null && n !== false).forEach((n) => host.appendChild(isNode(n) ? n : el('span', { class: 'a-statusbar__item' }, String(n))));
      fill(stStart, s && s.start); fill(stEnd, s && s.end);
    };
    api.destroy = () => { wrap.remove(); skip.remove(); };

    api.setCrumbs(o.crumbs || [brand.name || '']);
    api.setActions(o.actions);
    api.setViews(o.views);
    api.setTabs(o.tabs);
    api.setSubbarEnd(o.subbarEnd);
    api.setStatus(o.status || null);
    fitSubbar();
    return api;
  }
  Aurora.shell = shell;

  /* ───────────────────────── init ───────────────────────── */
  let booted = false;
  function init(opts) {
    opts = opts || {};
    const html = doc.documentElement;
    html.classList.add('a-js');
    let stored = null;
    try { stored = root.localStorage.getItem(THEME_KEY); } catch (e) { stored = null; }
    // opts.forceTheme: true makes opts.theme / data-theme win over the visitor's stored choice (e.g. for ?theme= previews)
    theme.set((!opts.forceTheme && stored) || opts.theme || html.getAttribute('data-theme') || 'auto', false);
    if (!booted) {
      booted = true;
      // delegated, so toggles and palette buttons built later (by Aurora.shell or by the app) work too
      doc.addEventListener('click', (e) => {
        const target = e.target && e.target.closest ? e.target : null;
        if (!target) return;
        if (target.closest('[data-theme-toggle]')) theme.toggle();
        else if (target.closest('[data-cmdk]')) cmdk.open();
      });
      doc.addEventListener('aurora:theme', syncToggles);
      if (root.matchMedia) { const mq = root.matchMedia('(prefers-color-scheme: light)'); if (mq.addEventListener) mq.addEventListener('change', () => { if (theme.pref() === 'auto') syncToggles(); }); }
      if (opts.shortcuts !== false) {
        doc.addEventListener('keydown', (e) => {
          if ((e.metaKey || e.ctrlKey) && !e.shiftKey && !e.altKey && String(e.key).toLowerCase() === 'k') { e.preventDefault(); if (cmdk.dlg && cmdk.dlg.open) cmdk.close(); else cmdk.open(); }
        });
      }
      // the top bar gets a hairline once the page has scrolled under it
      const onScroll = () => html.classList.toggle('a-scrolled', (root.scrollY || html.scrollTop || 0) > 4);
      root.addEventListener('scroll', throttle(onScroll, 50), { passive: true });
      onScroll();
    }
    syncToggles();
    reveal(doc);
    return Aurora;
  }
  Aurora.init = init;
})(typeof window !== 'undefined' ? window : globalThis);
