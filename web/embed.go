// Package web embeds the dashboard served by "teardown serve" and the pieces that
// "teardown analyze --html" inlines into a single-file report: the Aurora UI kit
// (aurora.css, aurora.js, aurora-charts.js), the shared report view
// (report-view.css, report-view.js), the dashboard (index.html, app.css, app.js)
// and the bootstrap of the exported page (report-boot.js).
package web

import (
	"embed"
	"io/fs"
)

//go:embed *.html *.css *.js *.svg
var assets embed.FS

// FS returns the dashboard files; index.html sits at the root of the returned
// file system.
func FS() fs.FS { return assets }
