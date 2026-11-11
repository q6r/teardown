/* report-boot.js: starts the single-file report written by `teardown analyze --html`.
 * The report is read from the JSON island (#report-data), whose content the Go side escaped so that
 * no file name or string can close the script element. The page is the same Aurora shell as the
 * dashboard (rail, top bar, sub bar, status bar), with the report sections as #fragment links.
 * Nothing here touches the network. */
(function () {
  'use strict';

  const A = window.Aurora;
  const V = window.TeardownView;
  A.init();

  let report = null;
  try {
    report = JSON.parse(document.getElementById('report-data').textContent);
  } catch (e) { /* the page says so below */ }

  const version = report && report.tool && report.tool.version ? V.vis(report.tool.version) : '';
  const name = report && report.file && report.file.name ? V.vis(report.file.name) : 'Report';
  const shell = A.shell({
    brand: { name: 'teardown', href: '#', mark: 'cpu' },
    rail: [
      [{ id: 'report', label: 'Report', icon: 'file-text', href: '#', active: true }],
      'spacer',
      [{ id: 'palette', label: 'Command palette', icon: 'command', cmdk: true }],
    ],
    crumbs: ['teardown', name],
    status: { start: [`teardown${version ? ' ' + version : ''}`, 'Single-file report, works offline'], end: ['Static analysis only; files are never executed'] },
  });

  if (!report) {
    A.empty(shell.container, { icon: 'alert', title: 'This report could not be read', text: 'The embedded report data is damaged. Run teardown again to produce a new file.' });
    return;
  }

  const copyJSON = A.el('button', { class: 'a-btn a-btn--sm', type: 'button', onclick: () => A.copy(JSON.stringify(report, null, 2), { label: 'Report JSON copied' }) }, A.icon('copy', { size: 15 }), 'Copy JSON');
  const view = V.render(shell.container, report, { actions: [copyJSON] });
  V.dock(shell, view, { anchors: true });
  A.cmdk.register(view.commands.concat([
    { id: 'copy-json', label: 'Copy the report as JSON', group: 'This report', hint: 'clipboard', keywords: 'export', run: () => copyJSON.click() },
    { id: 'theme', label: 'Toggle light / dark theme', group: 'Actions', keywords: 'appearance mode', run: () => A.theme.toggle() },
  ]));
})();
