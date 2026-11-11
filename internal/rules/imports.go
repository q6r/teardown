package rules

import (
	"fmt"
	"slices"
	"strings"

	"github.com/q6r/teardown/internal/report"
)

const (
	apiPresenceLimitation = "API presence alone proves nothing: legitimate software (debuggers, installers, security and remote-support tools, games, browsers) imports the same functions."
	dynamicLimitation     = "Functions resolved at run time (GetProcAddress, dlsym) or hidden by a packer are not in the import table, so a missing cluster proves nothing either."
)

// importIndex answers "which of these APIs does the file import" by canonical name.
type importIndex struct {
	byCanon map[string][]string
	total   int
}

// normalizeAPI folds an imported name into its canonical, comparable form.
func normalizeAPI(name string) string {
	n := strings.ToLower(name)
	if i := strings.IndexByte(n, '@'); i >= 0 {
		n = n[:i]
	}
	n = strings.TrimPrefix(n, "__imp_")
	n = strings.TrimLeft(n, "_")
	if strings.HasPrefix(n, "zw") {
		n = "nt" + n[2:]
	}
	return n
}

func indexImports(imps []report.Import) importIndex {
	ix := importIndex{byCanon: map[string][]string{}}
	for _, lib := range imps {
		ix.total += lib.Count
		for _, fn := range lib.Functions {
			display := fn
			if lib.Library != "" && lib.Library != report.UnspecifiedLibrary {
				display = lib.Library + "!" + fn
			}
			c := normalizeAPI(fn)
			ix.byCanon[c] = append(ix.byCanon[c], display)
			if n := len(c); n > 2 && (c[n-1] == 'a' || c[n-1] == 'w') {
				ix.byCanon[c[:n-1]] = append(ix.byCanon[c[:n-1]], display)
			}
		}
	}
	return ix
}

// match returns the display names (sorted, unique) of every listed API the file imports.
func (ix importIndex) match(names ...[]string) []string {
	var out []string
	for _, group := range names {
		for _, n := range group {
			out = append(out, ix.byCanon[n]...)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func importRules() []rule {
	return []rule{
		{info: Info{IDs: []string{"imports.process-injection"}, Category: report.CategoryImports, Severity: "medium-high",
			Summary: "Imports covering at least two stages of remote memory allocation, writing and thread/APC execution."},
			run: ruleProcessInjection},
		{info: Info{IDs: []string{"imports.keylogging"}, Category: report.CategoryImports, Severity: "medium",
			Summary: "Keyboard hooks or key-state polling combined with window-context APIs."},
			run: ruleKeylogging},
		{info: Info{IDs: []string{"imports.anti-debug"}, Category: report.CategoryImports, Severity: "low-medium",
			Summary: "Two or more debugger-detection APIs."},
			run: ruleAntiDebug},
		{info: Info{IDs: []string{"imports.crypto"}, Category: report.CategoryImports, Severity: "info",
			Summary: "Two or more cryptographic APIs (CryptoAPI, CNG, OpenSSL)."},
			run: ruleCrypto},
		{info: Info{IDs: []string{"imports.networking"}, Category: report.CategoryImports, Severity: "info",
			Summary: "Two or more networking APIs (sockets, WinINet, WinHTTP)."},
			run: ruleNetworking},
		{info: Info{IDs: []string{"imports.download-and-execute"}, Category: report.CategoryImports, Severity: "medium",
			Summary: "URLDownloadToFile-style download APIs together with process-launch APIs."},
			run: ruleDownloadExecute},
		{info: Info{IDs: []string{"imports.service-manipulation"}, Category: report.CategoryImports, Severity: "low",
			Summary: "Service-control-manager APIs that create or reconfigure services."},
			run: ruleServices},
		{info: Info{IDs: []string{"imports.token-privileges"}, Category: report.CategoryImports, Severity: "low",
			Summary: "Access-token and privilege manipulation APIs."},
			run: ruleTokens},
		{info: Info{IDs: []string{"imports.minimal-import-table"}, Category: report.CategoryImports, Severity: "low",
			Summary: "A PE whose import table holds almost nothing but LoadLibrary/GetProcAddress."},
			run: ruleMinimalImports},
		{info: Info{IDs: []string{"imports.reverse-shell-pattern"}, Category: report.CategoryImports, Severity: "medium",
			Summary: "socket + connect + dup2 + exec-family imports in a Unix executable."},
			run: ruleReverseShell},
	}
}

func ruleProcessInjection(in *input) []report.Finding {
	alloc := in.imp.match(apiRemoteAlloc)
	write := in.imp.match(apiRemoteWrite)
	exec := in.imp.match(apiRemoteExec)
	open := in.imp.match(apiOpenProcess)
	stages := 0
	var evidence []string
	for _, s := range []struct {
		label string
		apis  []string
	}{{"allocate or map memory in another process", alloc}, {"write to another process", write}, {"start or hijack a thread there", exec}} {
		if len(s.apis) > 0 {
			stages++
			evidence = append(evidence, s.label+": "+strings.Join(sample(s.apis, 4), ", "))
		}
	}
	if stages < 2 {
		return nil
	}
	if len(open) > 0 {
		evidence = append(evidence, "process handle: "+strings.Join(sample(open, 3), ", "))
	}
	sev, conf := report.SeverityMedium, report.ConfidenceLow
	title := "Imports cover two stages of process injection"
	if stages == 3 {
		sev, conf = report.SeverityHigh, report.ConfidenceMedium
		title = "Imports cover the full process-injection chain (allocate, write, execute)"
	}
	return []report.Finding{{
		ID: "imports.process-injection", Title: title, Severity: sev, Category: report.CategoryImports, Confidence: conf,
		Evidence: evidence,
		Limitations: []string{
			apiPresenceLimitation,
			"Debuggers, profilers, anti-virus and game overlays legitimately use remote memory and thread APIs.",
			dynamicLimitation,
		},
	}}
}

func ruleKeylogging(in *input) []report.Finding {
	hooks := in.imp.match(apiHooks)
	keys := in.imp.match(apiKeys)
	ctx := in.imp.match(apiWindowContext)
	async := in.imp.match([]string{"getasynckeystate"})
	hooksAndKeys := len(hooks) > 0 && len(keys) > 0
	asyncInContext := len(async) > 0 && len(ctx) > 0
	if !hooksAndKeys && !asyncInContext {
		return nil
	}
	var evidence []string
	if len(hooks) > 0 {
		evidence = append(evidence, "hook installation: "+strings.Join(hooks, ", "))
	}
	if len(keys) > 0 {
		evidence = append(evidence, "key state / raw input: "+strings.Join(sample(keys, 4), ", "))
	}
	if len(ctx) > 0 {
		evidence = append(evidence, "window context: "+strings.Join(sample(ctx, 3), ", "))
	}
	return []report.Finding{{
		ID: "imports.keylogging", Title: "Imports resemble keyboard capture", Severity: report.SeverityMedium,
		Category: report.CategoryImports, Confidence: report.ConfidenceLow, Evidence: evidence,
		Limitations: []string{
			apiPresenceLimitation,
			"Input-method editors, accessibility tools, macro/automation utilities and games use these APIs for legitimate hotkeys and overlays.",
			dynamicLimitation,
		},
	}}
}

func ruleAntiDebug(in *input) []report.Finding {
	found := in.imp.match(apiAntiDebug)
	if len(found) < 2 {
		return nil
	}
	sev := report.SeverityLow
	if len(found) >= 4 {
		sev = report.SeverityMedium
	}
	return []report.Finding{{
		ID: "imports.anti-debug", Title: fmt.Sprintf("Imports include %d debugger-detection APIs", len(found)),
		Severity: sev, Category: report.CategoryImports, Confidence: report.ConfidenceLow,
		Evidence: sample(found, 8),
		Limitations: []string{
			apiPresenceLimitation,
			"C runtimes, crash reporters, copy-protection and games routinely call IsDebuggerPresent and friends.",
			dynamicLimitation,
		},
	}}
}

func ruleCrypto(in *input) []report.Finding {
	found := in.imp.match(apiCrypto)
	if len(found) < 2 {
		return nil
	}
	return []report.Finding{{
		ID: "imports.crypto", Title: "Imports cryptographic APIs", Severity: report.SeverityInfo,
		Category: report.CategoryImports, Confidence: report.ConfidenceMedium, Evidence: sample(found, 8),
		Limitations: []string{
			apiPresenceLimitation,
			"Cryptography is used for TLS, hashing, licensing and DRM as often as for ransomware or payload decryption; static imports cannot tell which.",
			"Statically linked crypto code (Go, Rust, bundled OpenSSL) leaves no import trace.",
		},
	}}
}

func ruleNetworking(in *input) []report.Finding {
	found := in.imp.match(apiNetwork)
	if len(found) < 2 {
		return nil
	}
	return []report.Finding{{
		ID: "imports.networking", Title: "Imports networking APIs", Severity: report.SeverityInfo,
		Category: report.CategoryImports, Confidence: report.ConfidenceMedium, Evidence: sample(found, 8),
		Limitations: []string{
			apiPresenceLimitation,
			"Network access says nothing about what is contacted; see the extracted URLs and addresses for candidates.",
		},
	}}
}

func ruleDownloadExecute(in *input) []report.Finding {
	dl := in.imp.match(apiDownload)
	launch := in.imp.match(apiLaunch)
	if len(dl) == 0 || len(launch) == 0 {
		return nil
	}
	return []report.Finding{{
		ID: "imports.download-and-execute", Title: "Imports a file-download API together with process-launch APIs",
		Severity: report.SeverityMedium, Category: report.CategoryImports, Confidence: report.ConfidenceLow,
		Evidence: append([]string{"download: " + strings.Join(dl, ", ")}, "launch: "+strings.Join(sample(launch, 4), ", ")),
		Limitations: []string{
			apiPresenceLimitation,
			"Updaters and installers legitimately download and run files; nothing here shows what is downloaded or whether it is run.",
			dynamicLimitation,
		},
	}}
}

func ruleServices(in *input) []report.Finding {
	found := in.imp.match(apiService)
	install := in.imp.match(apiServiceInstall)
	if len(found) < 3 || len(install) == 0 {
		return nil
	}
	return []report.Finding{{
		ID: "imports.service-manipulation", Title: "Imports APIs that create or reconfigure Windows services",
		Severity: report.SeverityLow, Category: report.CategoryImports, Confidence: report.ConfidenceMedium,
		Evidence: sample(found, 8),
		Limitations: []string{
			apiPresenceLimitation,
			"Installers, drivers' setup programs and administration tools manage services as a matter of course.",
		},
	}}
}

func ruleTokens(in *input) []report.Finding {
	found := in.imp.match(apiToken)
	adjust := in.imp.match([]string{"adjusttokenprivileges"})
	if len(found) < 3 || len(adjust) == 0 {
		return nil
	}
	return []report.Finding{{
		ID: "imports.token-privileges", Title: "Imports access-token and privilege manipulation APIs",
		Severity: report.SeverityLow, Category: report.CategoryImports, Confidence: report.ConfidenceLow,
		Evidence: sample(found, 8),
		Limitations: []string{
			apiPresenceLimitation,
			"Shutdown helpers, backup tools and installers adjust their own token privileges routinely.",
		},
	}}
}

func ruleMinimalImports(in *input) []report.Finding {
	if in.rep.Type.ID != report.TypePE || in.imp.total == 0 || in.imp.total > 8 {
		return nil
	}
	load := in.imp.match(apiLoadLibrary)
	proc := in.imp.match(apiGetProc)
	if len(load) == 0 || len(proc) == 0 {
		return nil
	}
	return []report.Finding{{
		ID: "imports.minimal-import-table", Title: fmt.Sprintf("Import table has only %d functions, including LoadLibrary and GetProcAddress", in.imp.total),
		Severity: report.SeverityLow, Category: report.CategoryImports, Confidence: report.ConfidenceLow,
		Evidence: append(sample(load, 2), sample(proc, 2)...),
		Limitations: []string{
			"Packers and shellcode loaders resolve everything else at run time, which this pattern resembles; so do some minimal launchers and installers.",
			"Go and other non-C toolchains also produce small import tables.",
		},
	}}
}

func ruleReverseShell(in *input) []report.Finding {
	if in.rep.Type.ID != report.TypeELF && in.rep.Type.ID != report.TypeMachO && in.rep.Type.ID != report.TypeMachOFat {
		return nil
	}
	sock, conn := in.imp.match(apiShSocket), in.imp.match(apiShConn)
	dup, exec := in.imp.match(apiShDup), in.imp.match(apiShExec)
	if len(sock) == 0 || len(conn) == 0 || len(dup) == 0 || len(exec) == 0 {
		return nil
	}
	evidence := []string{
		"socket: " + strings.Join(sock, ", "), "connect: " + strings.Join(conn, ", "),
		"descriptor redirection: " + strings.Join(dup, ", "), "exec: " + strings.Join(sample(exec, 3), ", "),
	}
	return []report.Finding{{
		ID: "imports.reverse-shell-pattern", Title: "Imports match the classic reverse-shell call sequence",
		Severity: report.SeverityMedium, Category: report.CategoryImports, Confidence: report.ConfidenceLow,
		Evidence: evidence,
		Limitations: []string{
			apiPresenceLimitation,
			"Network daemons, SSH-like tools and supervisors combine the same calls for legitimate session handling.",
			dynamicLimitation,
		},
	}}
}
