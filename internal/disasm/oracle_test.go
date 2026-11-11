package disasm

// This file is a developer tool, not part of the normal test run. It compares the
// decoder with the disassembler of the Go toolchain: "go tool objdump" prints
// every instruction of a Go executable together with its bytes, and the length
// of each instruction is what a linear sweep depends on. A length mismatch means
// the decoder would lose synchronisation, which is the failure that matters.
//
// To run it, build any Go program for Windows (or any other target) and point the
// test at the executable. From the repository root, in PowerShell:
//
//	$env:CGO_ENABLED = "0"; $env:GOOS = "windows"; $env:GOARCH = "amd64"
//	go build -o $env:TEMP\oracle64.exe cmd/gofmt
//	Remove-Item Env:GOOS, Env:GOARCH
//	$env:TEARDOWN_DISASM_ORACLE = "1"
//	$env:TEARDOWN_DISASM_ORACLE_BIN = "$env:TEMP\oracle64.exe"
//	go test ./internal/disasm -run TestOracle -v -count=1
//
// Use GOARCH=386 and TEARDOWN_DISASM_ORACLE_MODE=32 for 32-bit code. The other
// variables are TEARDOWN_DISASM_ORACLE_MIN (the lowest acceptable length
// agreement in percent, default 99.5) and TEARDOWN_DISASM_ORACLE_SAMPLES (how
// many side-by-side instruction pairs to log, default 40).
//
// The test never executes the binary: go tool objdump only reads it. It reports
// the number of instructions compared, the length agreement, how often the
// decoder fell back to "db", the opcode patterns behind the length mismatches
// and a sweep check (the share of the toolchain's instruction starts that a linear
// sweep from each function's first byte also reports). It also cross-checks the
// operation, the registers and the numeric operands against the toolchain's text
// after normalising the Go assembler spelling; those three numbers are indicative,
// the length agreement is the verdict.

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const (
	oracleEnv     = "TEARDOWN_DISASM_ORACLE"
	oracleBinEnv  = "TEARDOWN_DISASM_ORACLE_BIN"
	oracleModeEnv = "TEARDOWN_DISASM_ORACLE_MODE"
	oracleMinEnv  = "TEARDOWN_DISASM_ORACLE_MIN"
	oracleSampEnv = "TEARDOWN_DISASM_ORACLE_SAMPLES"
	oracleDumpEnv = "TEARDOWN_DISASM_ORACLE_DUMP"
)

// oracleFunc is one function of the executable as printed by go tool objdump.
type oracleFunc struct {
	name  string
	addr  uint64
	code  []byte
	offs  []int    // offset of each instruction in code
	texts []string // the toolchain's text for each instruction
}

// oracleStats accumulates the comparison.
type oracleStats struct {
	compared, lenOK, db     int
	unknown, blind, skipped int
	sweepTotal, sweepHit    int
	guessed, guessedClean   int
	unclean                 []string
	opKnown, opOK           int
	regKnown, regOK         int
	numKnown, numOK         int
	mismatch                map[string]*oracleMismatch
	opDiff                  map[string]int
	regDiff, numDiff        map[string]int
	samples                 []string
	dbBytes                 map[string]int
}

type oracleMismatch struct {
	count   int
	goOp    string
	example string
}

func TestOracle(t *testing.T) {
	if os.Getenv(oracleEnv) != "1" {
		t.Skipf("developer tool: set %s=1 and %s=<Go-built executable> (see the file header)", oracleEnv, oracleBinEnv)
	}
	bin := os.Getenv(oracleBinEnv)
	if bin == "" {
		t.Fatalf("%s is not set", oracleBinEnv)
	}
	mode := Mode64
	if os.Getenv(oracleModeEnv) == "32" {
		mode = Mode32
	}
	minPct := 99.5
	if v := os.Getenv(oracleMinEnv); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			t.Fatalf("%s: %v", oracleMinEnv, err)
		}
		minPct = f
	}
	wantSamples := 40
	if v := os.Getenv(oracleSampEnv); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			t.Fatalf("%s: %v", oracleSampEnv, err)
		}
		wantSamples = n
	}

	cmd := exec.Command("go", "tool", "objdump", bin)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("go tool objdump: %v", err)
	}

	st := &oracleStats{
		mismatch: map[string]*oracleMismatch{}, opDiff: map[string]int{}, regDiff: map[string]int{},
		numDiff: map[string]int{}, dbBytes: map[string]int{},
	}
	seenOps := map[string]int{}
	var cur *oracleFunc
	flush := func() {
		if cur != nil && len(cur.offs) > 0 {
			compareFunc(mode, cur, st, seenOps, wantSamples)
		}
		cur = nil
	}

	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	functions := 0
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "TEXT ") {
			flush()
			name := strings.Fields(line)[1]
			if strings.HasPrefix(name, "go:") {
				continue // the build ID string sits at the start of .text: data, not code
			}
			cur = &oracleFunc{name: name}
			functions++
			continue
		}
		if cur == nil {
			continue
		}
		fields := nonEmpty(strings.Split(line, "\t"))
		if len(fields) < 4 || !strings.HasPrefix(fields[1], "0x") {
			continue
		}
		addr, err := strconv.ParseUint(fields[1][2:], 16, 64)
		if err != nil {
			t.Fatalf("bad address in %q", line)
		}
		raw, err := hexBytes(fields[2])
		if err != nil {
			t.Fatalf("bad bytes in %q: %v", line, err)
		}
		if len(cur.offs) == 0 {
			cur.addr = addr
		} else if addr != cur.addr+uint64(len(cur.code)) {
			// a gap inside a symbol: start a new run so offsets stay contiguous
			flush()
			cur = &oracleFunc{name: cur.name, addr: addr}
		}
		cur.offs = append(cur.offs, len(cur.code))
		cur.code = append(cur.code, raw...)
		cur.texts = append(cur.texts, strings.Join(fields[3:], " "))
	}
	flush()
	if err := sc.Err(); err != nil {
		t.Fatalf("reading objdump output: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("go tool objdump: %v", err)
	}

	pct := func(a, b int) float64 {
		if b == 0 {
			return 0
		}
		return 100 * float64(a) / float64(b)
	}
	t.Logf("binary: %s, mode %d, %d functions", bin, mode, functions)
	t.Logf("instructions compared:      %d", st.compared)
	t.Logf("not compared:               %d instructions the toolchain prints as unknown (?), %d it misreads (VEX or EVEX it does not know), %d that follow either in the same function", st.unknown, st.blind, st.skipped-st.unknown-st.blind)
	t.Logf("length agreement:           %.4f%% (%d of %d)", pct(st.lenOK, st.compared), st.lenOK, st.compared)
	t.Logf("fell back to db:            %.4f%% (%d)", pct(st.db, st.compared), st.db)
	t.Logf("linear sweep sync:          %.4f%% of %d instruction starts (functions without blind spots)", pct(st.sweepHit, st.sweepTotal), st.sweepTotal)
	t.Logf("functions with blind spots: %d, of which %d sweep cleanly (no db, exact end, ends in ret, jmp or trap)", st.guessed, st.guessedClean)
	if len(st.unclean) > 0 {
		t.Logf("not clean:\n  %s", strings.Join(st.unclean, "\n  "))
	}
	t.Logf("operation agreement:        %.3f%% of %d mapped", pct(st.opOK, st.opKnown), st.opKnown)
	t.Logf("register agreement:         %.3f%% of %d", pct(st.regOK, st.regKnown), st.regKnown)
	t.Logf("numeric operand agreement:  %.3f%% of %d", pct(st.numOK, st.numKnown), st.numKnown)

	for _, kind := range []struct {
		title string
		m     map[string]int
	}{{"operation disagreements (Go -> decoder)", st.opDiff}, {"register disagreements", st.regDiff}, {"numeric disagreements", st.numDiff}, {"db fallbacks (first bytes)", st.dbBytes}} {
		if len(kind.m) == 0 {
			continue
		}
		t.Logf("%s, top 12:\n%s", kind.title, topCounts(kind.m, 12))
	}
	if len(st.mismatch) > 0 {
		keys := make([]string, 0, len(st.mismatch))
		for k := range st.mismatch {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if a, b := st.mismatch[keys[i]].count, st.mismatch[keys[j]].count; a != b {
				return a > b
			}
			return keys[i] < keys[j]
		})
		var sb strings.Builder
		for i, k := range keys {
			if i == 10 {
				break
			}
			m := st.mismatch[k]
			fmt.Fprintf(&sb, "  %6d  %-22s go %-8s e.g. %s\n", m.count, k, m.goOp, m.example)
		}
		t.Logf("opcode patterns behind the length mismatches, top 10 of %d:\n%s", len(keys), sb.String())
	}
	if len(st.samples) > 0 {
		t.Logf("side by side (toolchain | decoder):\n%s", strings.Join(st.samples, "\n"))
	}
	if st.compared == 0 {
		t.Fatal("no instructions were compared")
	}
	if got := pct(st.lenOK, st.compared); got < minPct {
		t.Errorf("length agreement %.4f%% is below the %.2f%% target", got, minPct)
	}
}

func nonEmpty(in []string) []string {
	out := in[:0]
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

func hexBytes(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd length")
	}
	b := make([]byte, len(s)/2)
	for i := range b {
		v, err := strconv.ParseUint(s[2*i:2*i+2], 16, 8)
		if err != nil {
			return nil, err
		}
		b[i] = byte(v)
	}
	return b, nil
}

func topCounts(m map[string]int, n int) string {
	type kv struct {
		k string
		v int
	}
	all := make([]kv, 0, len(m))
	for k, v := range m {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].v != all[j].v {
			return all[i].v > all[j].v
		}
		return all[i].k < all[j].k
	})
	var sb strings.Builder
	for i, e := range all {
		if i == n {
			break
		}
		fmt.Fprintf(&sb, "  %6d  %s\n", e.v, e.k)
	}
	return sb.String()
}

// blindSpot reports whether the toolchain's own decoder cannot be trusted for this
// instruction: the bytes start with a VEX or EVEX prefix but the toolchain printed
// something that is not a vector instruction (it does not know every AVX and AVX-512
// instruction, and then reads the prefix as a separate instruction).
func blindSpot(mode Mode, b []byte, text string) bool {
	if len(b) == 0 || (b[0] != 0xc4 && b[0] != 0xc5 && b[0] != 0x62) {
		return false
	}
	if mode == Mode32 && (len(b) < 2 || b[1]&0xc0 != 0xc0) {
		return false
	}
	op := goOpName(text)
	return !strings.HasPrefix(op, "V") && !strings.HasPrefix(op, "K")
}

// compareFunc compares the instructions of one function. The toolchain's output is
// only trusted up to its first blind spot: after an instruction it misreads, its
// instruction boundaries no longer match the real ones, so the rest of the function
// is not compared one by one. Such a function gets a plausibility check instead: a
// linear sweep must consume it exactly, without any db, and end in a ret or jump.
func compareFunc(mode Mode, f *oracleFunc, st *oracleStats, seenOps map[string]int, wantSamples int) {
	n := len(f.offs)
	end := func(i int) int {
		if i+1 < n {
			return f.offs[i+1]
		}
		return len(f.code)
	}
	trusted := n
	for i := 0; i < n; i++ {
		if f.texts[i] == "?" {
			st.unknown++
			trusted = min(trusted, i)
		} else if blindSpot(mode, f.code[f.offs[i]:end(i)], f.texts[i]) {
			st.blind++
			trusted = min(trusted, i)
		}
	}
	st.skipped += n - trusted

	if dump := os.Getenv(oracleDumpEnv); dump != "" && strings.Contains(f.name, dump) {
		dumpFunc(mode, f)
	}

	for i := 0; i < trusted; i++ {
		off := f.offs[i]
		goLen := end(i) - off
		text := f.texts[i]
		in := Decode(mode, f.code[off:], f.addr+uint64(off))
		st.compared++
		if !in.Valid {
			st.db++
			st.dbBytes[hexKey(f.code[off:min(len(f.code), off+4)])+"  go: "+text]++
		}
		if in.Len == goLen {
			st.lenOK++
		} else {
			key := patternKey(mode, f.code[off:end(i)])
			m := st.mismatch[key]
			if m == nil {
				m = &oracleMismatch{goOp: goOpName(text), example: fmt.Sprintf("% x  go: %s  mine: %s (len %d, want %d)", f.code[off:end(i)], text, in.Text, in.Len, goLen)}
				st.mismatch[key] = m
			}
			m.count++
			continue
		}
		compareText(in, text, st)
		if goOp := goOpName(text); len(st.samples) < wantSamples && seenOps[goOp] < 1 {
			seenOps[goOp]++
			st.samples = append(st.samples, fmt.Sprintf("  %-46s | %s", text, in.Text))
		}
	}

	if trusted == n {
		// the sweep: decode from the first byte and see which instruction starts are reported
		starts := make(map[int]bool, n)
		for off := 0; off < len(f.code); {
			in := Decode(mode, f.code[off:], f.addr+uint64(off))
			starts[off] = true
			off += in.Len
		}
		for i := 0; i < n; i++ {
			st.sweepTotal++
			if starts[f.offs[i]] {
				st.sweepHit++
			}
		}
		return
	}

	st.guessed++
	var last Inst
	for off := 0; off < len(f.code); {
		in := Decode(mode, f.code[off:], f.addr+uint64(off))
		if !in.Valid {
			if len(st.unclean) < 8 {
				st.unclean = append(st.unclean, fmt.Sprintf("%s +%#x: % x", f.name, off, f.code[off:min(len(f.code), off+8)]))
			}
			return
		}
		last = in
		off += in.Len
	}
	if last.Flow == FlowRet || last.Flow == FlowJump || last.Flow == FlowTrap {
		st.guessedClean++
	} else if len(st.unclean) < 8 {
		st.unclean = append(st.unclean, fmt.Sprintf("%s ends with %q", f.name, last.Text))
	}
}

// dumpFunc logs the decoder's linear sweep of a function next to the toolchain's text.
func dumpFunc(mode Mode, f *oracleFunc) {
	goText := make(map[int]string, len(f.offs))
	for i, off := range f.offs {
		goText[off] = f.texts[i]
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "sweep of %s:\n", f.name)
	for off := 0; off < len(f.code); {
		in := Decode(mode, f.code[off:], f.addr+uint64(off))
		fmt.Fprintf(&sb, "  %#x  %-28s %-48s | %s\n", in.Addr, hexKey(in.Bytes), in.Text, goText[off])
		off += in.Len
	}
	fmt.Print(sb.String())
}

func hexKey(b []byte) string { return fmt.Sprintf("% x", b) }

// patternKey names the opcode behind an instruction: prefixes and REX are skipped,
// the opcode (with its escape bytes) is kept, and for group opcodes the ModRM reg field.
func patternKey(mode Mode, b []byte) string {
	i := 0
	for i < len(b) {
		switch c := b[i]; {
		case c == 0x66 || c == 0x67 || c == 0xf2 || c == 0xf3 || c == 0xf0 || c == 0x2e || c == 0x36 || c == 0x3e || c == 0x26 || c == 0x64 || c == 0x65:
			i++
			continue
		case mode == Mode64 && c&0xf0 == 0x40:
			i++
			continue
		}
		break
	}
	if i >= len(b) {
		return "prefixes only"
	}
	group := func(at int) string {
		if at < len(b) {
			return fmt.Sprintf(" /%d", b[at]>>3&7)
		}
		return ""
	}
	switch c := b[i]; {
	case c == 0x0f && i+1 < len(b):
		c2 := b[i+1]
		switch {
		case (c2 == 0x38 || c2 == 0x3a) && i+2 < len(b):
			return fmt.Sprintf("0f %02x %02x", c2, b[i+2])
		case c2 == 0x01 || c2 == 0xae || c2 == 0xc7 || c2 == 0xba || (c2 >= 0x71 && c2 <= 0x73):
			return fmt.Sprintf("0f %02x", c2) + group(i+2)
		}
		return fmt.Sprintf("0f %02x", c2)
	case (c == 0xc5 || c == 0xc4) && i+2 < len(b):
		if c == 0xc5 {
			return fmt.Sprintf("vex2 pp%d %02x", b[i+1]&3, b[i+2])
		}
		return fmt.Sprintf("vex3 map%d pp%d %02x", b[i+1]&0x1f, b[i+2]&3, b[min(len(b)-1, i+3)])
	case c == 0x62:
		return "evex"
	case c == 0x80 || c == 0x81 || c == 0x83 || c == 0xc0 || c == 0xc1 || (c >= 0xd0 && c <= 0xd3) || c == 0xf6 || c == 0xf7 || c == 0xfe || c == 0xff || c == 0xc6 || c == 0xc7 || c == 0x8f:
		return fmt.Sprintf("%02x", c) + group(i+1)
	}
	return fmt.Sprintf("%02x", b[i])
}

// goOpName returns the operation of a Go assembler line, skipping prefix words.
func goOpName(text string) string {
	for _, w := range strings.Fields(text) {
		w = strings.TrimSuffix(w, ";")
		switch w {
		case "REP", "REPN", "LOCK", "CS", "DS", "ES", "FS", "GS", "SS", "DATA16", "ADDR16", "REX", "REX.W":
			continue
		}
		return w
	}
	return ""
}

// myOpName returns the mnemonic of the decoder's text without lock, rep and bnd prefixes.
func myOpName(in Inst) string {
	for _, w := range strings.Fields(in.Mnemonic) {
		switch w {
		case "lock", "rep", "repe", "repne", "repz", "repnz", "bnd":
			continue
		}
		return w
	}
	return ""
}

// goAliases maps the spelling of a Go operation to the Intel names it can stand for.
var goAliases = map[string][]string{
	"movzx": {"movzx"}, "movsx": {"movsx", "movsxd"}, "movlqsx": {"movsxd"},
	"movblzx": {"movzx"}, "movwlzx": {"movzx"}, "movbqzx": {"movzx"}, "movwqzx": {"movzx"},
	"movblsx": {"movsx"}, "movwlsx": {"movsx"}, "movbqsx": {"movsx"}, "movwqsx": {"movsx"},
	"movabsq": {"movabs"}, "movsq": {"movs"}, "movsb": {"movs"}, "movsw": {"movs"}, "movsl": {"movs"},
	"stosq": {"stos"}, "stosb": {"stos"}, "stosw": {"stos"}, "stosl": {"stos"},
	"lodsq": {"lods"}, "lodsb": {"lods"}, "lodsw": {"lods"}, "lodsl": {"lods"},
	"scasq": {"scas"}, "scasb": {"scas"}, "scasw": {"scas"}, "scasl": {"scas"},
	"cmpsq": {"cmps"}, "cmpsb": {"cmps"}, "cmpsw": {"cmps"}, "cmpsl": {"cmps"},
	"cltq": {"cdqe"}, "cqo": {"cqo"}, "cdq": {"cdq"}, "cwde": {"cwde"}, "cbw": {"cbw"}, "cwd": {"cwd"},
	"movq": {"mov", "movq", "movd", "movabs"}, "movd": {"movd", "movq"}, "movl": {"mov", "movd"},
	"movss": {"movss"}, "movsd": {"movsd", "movs"}, "movups": {"movups"}, "movsd_xmm": {"movsd"}, "cmpsd_xmm": {"cmpsd"},
	"outsd": {"outs"}, "outsb": {"outs"}, "outsw": {"outs"}, "insd": {"ins"}, "insb": {"ins"}, "insw": {"ins"}, "lodsd": {"lods"},
	"scasd": {"scas"}, "stosd": {"stos"}, "cmpsd": {"cmps", "cmpsd"},
	"xchgl": {"xchg", "nop"}, "xchgq": {"xchg", "nop"}, "nopl": {"nop"}, "nopw": {"nop"}, "nopq": {"nop"},
	"pushq": {"push"}, "popq": {"pop"}, "pushl": {"push"}, "popl": {"pop"}, "pushw": {"push"}, "popw": {"pop"},
	"callq": {"call"}, "retq": {"ret"}, "jmpq": {"jmp"},
	"imul3q": {"imul"}, "imul3l": {"imul"}, "imul3w": {"imul"},
	"int": {"int"}, "int3": {"int3"}, "syscall": {"syscall"},
	"sarl": {"sar"}, "sarq": {"sar"}, "sar": {"sar"},
	"vmovdqu": {"vmovdqu"}, "pushfq": {"pushf"}, "popfq": {"popf"}, "pushfl": {"pushfd"}, "popfl": {"popfd"},
	"leaveq": {"leave"}, "leave": {"leave"}, "jrcxz": {"jrcxz"}, "jecxz": {"jecxz"},
	"xlatb": {"xlatb"}, "fwait": {"fwait"}, "iretq": {"iretq"}, "iretl": {"iretd"},
}

// goCond maps the condition codes of Go's setcc and cmovcc spellings to the Intel ones.
var goCond = map[string]string{
	"eq": "e", "ne": "ne", "lt": "l", "ge": "ge", "le": "le", "gt": "g", "hi": "a", "ls": "be", "cc": "ae", "cs": "b",
	"mi": "s", "pl": "ns", "ps": "p", "pc": "np", "ov": "o", "oc": "no", "o": "o", "no": "no", "b": "b", "ae": "ae", "e": "e",
	"be": "be", "a": "a", "s": "s", "ns": "ns", "p": "p", "np": "np", "l": "l", "g": "g", "z": "e", "nz": "ne", "c": "b", "nc": "ae",
}

// opAgrees reports whether a Go operation and the decoder's mnemonic name the same operation,
// and whether the Go operation could be mapped at all.
func opAgrees(goOp, mine string) (agree, mapped bool) {
	g := strings.ToLower(goOp)
	if g == mine {
		return true, true
	}
	for _, a := range goAliases[g] {
		if a == mine {
			return true, true
		}
	}
	// setcc and cmovcc: SETEQ, CMOVQNE, CMOVLLT, ...
	for _, base := range []string{"set", "cmov"} {
		if rest, ok := strings.CutPrefix(g, base); ok {
			if base == "cmov" && len(rest) > 1 && strings.ContainsAny(rest[:1], "wlq") {
				rest = rest[1:]
			}
			if c, ok := goCond[rest]; ok {
				return base+c == mine, true
			}
		}
	}
	// a size suffix: ADDQ, SHLL, XORB, CMPW, ...
	if len(g) > 1 && strings.ContainsRune("bwlq", rune(g[len(g)-1])) && g[:len(g)-1] == mine {
		return true, true
	}
	// jumps: Go has the same condition names as Intel for the common ones
	if strings.HasPrefix(g, "j") && strings.HasPrefix(mine, "j") {
		if c, ok := goCond[g[1:]]; ok {
			return "j"+c == mine, true
		}
	}
	// vector instructions: Go keeps the Intel names, in upper case
	if strings.HasPrefix(g, "v") && strings.HasPrefix(mine, "v") {
		return g == mine, true
	}
	return false, strings.HasPrefix(g, "j") || len(g) > 1 && mine != "" && strings.HasPrefix(g, mine)
}

var (
	goRegRe  = regexp.MustCompile(`\b(R(?:8|9|1[0-5])[BWDL]?|[ER]?[ABCD]X|[ABCD][LH]|[ER]?[SD]I|[ER]?[SB]P|SIL|DIL|SPL|BPL|X(?:[0-9]|1[0-5])|Y(?:[0-9]|1[0-5]))\b`)
	myRegRe  = regexp.MustCompile(`\b(r(?:8|9|1[0-5])[bwd]?|[er]?[abcd]x|[abcd][lh]|[er]?[sd]i|[er]?[sb]p|sil|dil|spl|bpl|xmm(?:[0-9]|1[0-5])|ymm(?:[0-9]|1[0-5]))\b`)
	hexNumRe = regexp.MustCompile(`-?0x[0-9a-fA-F]+`)
)

// regKey canonicalises a register name to class and number, so that rax, eax, ax,
// al, AX and AL all compare equal.
func regKey(name string) string {
	n := strings.ToLower(name)
	switch {
	case strings.HasPrefix(n, "xmm"), strings.HasPrefix(n, "ymm"):
		return "v" + n[3:]
	case n[0] == 'x' || n[0] == 'y':
		return "v" + n[1:]
	case n[0] == 'r' && len(n) > 1 && n[1] >= '0' && n[1] <= '9':
		return "g" + strings.TrimRight(n[1:], "bwdl")
	}
	order := map[string]string{"a": "0", "c": "1", "d": "2", "b": "3"}
	switch n {
	case "sp", "esp", "rsp", "spl":
		return "g4"
	case "bp", "ebp", "rbp", "bpl":
		return "g5"
	case "si", "esi", "rsi", "sil":
		return "g6"
	case "di", "edi", "rdi", "dil":
		return "g7"
	case "ah":
		return "g4h"
	case "ch":
		return "g5h"
	case "dh":
		return "g6h"
	case "bh":
		return "g7h"
	}
	return "g" + order[strings.TrimLeft(strings.TrimRight(n, "xlh"), "er")]
}

// regSet lists the canonical registers of a text, sorted.
func regSet(re *regexp.Regexp, s string) string {
	var keys []string
	for _, m := range re.FindAllString(s, -1) {
		keys = append(keys, regKey(m))
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

// numbersAgree checks that every hexadecimal number the toolchain printed also
// appears, possibly sign-extended or truncated, in the decoder's text.
func numbersAgree(goText, mine string) bool {
	var have []uint64
	for _, m := range hexNumRe.FindAllString(mine, -1) {
		v, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimPrefix(m, "-"), "0x"), 16, 64)
		if err == nil {
			if strings.HasPrefix(m, "-") {
				v = -v
			}
			have = append(have, v)
		}
	}
	for _, m := range hexNumRe.FindAllString(goText, -1) {
		neg := strings.HasPrefix(m, "-")
		v, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimPrefix(m, "-"), "0x"), 16, 64)
		if err != nil {
			return false
		}
		if neg {
			v = -v
		}
		found := false
		for _, h := range have {
			for _, w := range []uint{8, 16, 32, 64} {
				mask := mask(int(w))
				if h&mask == v&mask || (-h)&mask == v&mask {
					found = true
				}
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// compareText cross-checks the operation, registers and numbers of one instruction
// whose length already agrees.
func compareText(in Inst, text string, st *oracleStats) {
	goOp := goOpName(text)
	if agree, mapped := opAgrees(goOp, myOpName(in)); mapped {
		st.opKnown++
		if agree {
			st.opOK++
		} else {
			st.opDiff[goOp+" -> "+myOpName(in)]++
		}
	}
	// Go lists implicit operands for a few instructions and hides some register operands
	// of others, so only compare when the toolchain printed at least one register
	if strings.Contains(text, "(SB)") || in.Mnemonic == "db" {
		return
	}
	goRegs, myRegs := regSet(goRegRe, text), regSet(myRegRe, in.Operands)
	if goRegs != "" || myRegs != "" {
		st.regKnown++
		if goRegs == myRegs {
			st.regOK++
		} else {
			st.regDiff[fmt.Sprintf("%s | %s", text, in.Text)]++
		}
	}
	if strings.Contains(text, "0x") && in.Mnemonic != "int3" {
		// the decoder spells the implicit shift count of the D0 and D1 forms as 1, not 0x1
		mine := strings.TrimSuffix(in.Text, ", 1")
		if mine != in.Text {
			mine += ", 0x1"
		}
		st.numKnown++
		if numbersAgree(text, mine) {
			st.numOK++
		} else {
			st.numDiff[fmt.Sprintf("%s | %s", text, in.Text)]++
		}
	}
}
