package disasm

// A second developer tool next to oracle_test.go. The Go toolchain ships the
// encoding tests of its assembler (src/cmd/asm/internal/asm/testdata): thousands of
// lines such as
//
//	ADCQ $-249346713, AX                    // 4815674523f1
//	VAESDEC X24, X7, X11                    // 62124508ded8 or 6212c508ded8
//
// that pair an instruction with its machine code (a line may list alternative
// encodings). They were produced by an independent encoder, cover the whole ISA
// including AVX and AVX-512, and are a much wider net than the code the compiler
// emits. The test decodes every listed encoding and checks that the decoder reports
// exactly that many bytes. Nothing is copied into this repository: the files are
// read from the local toolchain.
//
// From the repository root, in PowerShell:
//
//	$goroot = go env GOROOT
//	$env:TEARDOWN_DISASM_ORACLE = "1"
//	$env:TEARDOWN_DISASM_ORACLE_ASM = "$goroot\src\cmd\asm\internal\asm\testdata\amd64enc.s"
//	go test ./internal/disasm -run TestOracleAsm -v -count=1
//
// TEARDOWN_DISASM_ORACLE_ASM may also name a directory (every .s file in it is
// read, for example the avx512enc directory next to amd64enc.s). Set
// TEARDOWN_DISASM_ORACLE_MODE=32 for the 32-bit files. The test fails when the
// length agreement is below TEARDOWN_DISASM_ORACLE_MIN percent (default 99.5).

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const oracleAsmEnv = "TEARDOWN_DISASM_ORACLE_ASM"

type asmStats struct {
	encodings, lenOK, db int
	opKnown, opOK        int
	regKnown, regOK      int
	numKnown, numOK      int
	mismatch             map[string]*oracleMismatch
	missing              map[string]int
	opDiff, regDiff      map[string]int
	numDiff              map[string]int
}

func TestOracleAsm(t *testing.T) {
	if os.Getenv(oracleEnv) != "1" || os.Getenv(oracleAsmEnv) == "" {
		t.Skipf("developer tool: set %s=1 and %s=<assembler encoding test file or directory> (see the file header)", oracleEnv, oracleAsmEnv)
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

	var files []string
	path := os.Getenv(oracleAsmEnv)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.IsDir() {
		files, err = filepath.Glob(filepath.Join(path, "*.s"))
		if err != nil {
			t.Fatal(err)
		}
	} else {
		files = []string{path}
	}
	if len(files) == 0 {
		t.Fatalf("no .s files in %s", path)
	}

	st := &asmStats{
		mismatch: map[string]*oracleMismatch{}, missing: map[string]int{},
		opDiff: map[string]int{}, regDiff: map[string]int{}, numDiff: map[string]int{},
	}
	for _, file := range files {
		if err := checkAsmFile(mode, file, st); err != nil {
			t.Fatal(err)
		}
	}

	pct := 100 * float64(st.lenOK) / float64(max(st.encodings, 1))
	t.Logf("files: %d, mode %d", len(files), mode)
	t.Logf("encodings checked:   %d", st.encodings)
	t.Logf("length agreement:    %.4f%% (%d of %d)", pct, st.lenOK, st.encodings)
	t.Logf("reported as db:      %.4f%% (%d)", 100*float64(st.db)/float64(max(st.encodings, 1)), st.db)
	pctOf := func(a, b int) float64 { return 100 * float64(a) / float64(max(b, 1)) }
	t.Logf("operation agreement: %.3f%% of %d mapped", pctOf(st.opOK, st.opKnown), st.opKnown)
	t.Logf("register agreement:  %.3f%% of %d", pctOf(st.regOK, st.regKnown), st.regKnown)
	t.Logf("numeric agreement:   %.3f%% of %d", pctOf(st.numOK, st.numKnown), st.numKnown)
	for _, kind := range []struct {
		title string
		m     map[string]int
	}{{"instructions the decoder does not know", st.missing}, {"operation disagreements (Go -> decoder)", st.opDiff}, {"register disagreements", st.regDiff}, {"numeric disagreements", st.numDiff}} {
		if len(kind.m) > 0 {
			t.Logf("%s, top 15:\n%s", kind.title, topCounts(kind.m, 15))
		}
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
			if i == 12 {
				break
			}
			m := st.mismatch[k]
			fmt.Fprintf(&sb, "  %6d  %-22s %-10s e.g. %s\n", m.count, k, m.goOp, m.example)
		}
		t.Logf("opcode patterns behind the length mismatches, top 12 of %d:\n%s", len(keys), sb.String())
	}
	if st.encodings == 0 {
		t.Fatal("no encodings found")
	}
	if pct < minPct {
		t.Errorf("length agreement %.4f%% is below the %.2f%% target", pct, minPct)
	}
}

// checkAsmFile reads one assembler test file and decodes every encoding in it.
func checkAsmFile(mode Mode, file string, st *asmStats) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") {
			continue
		}
		code, comment, ok := strings.Cut(line, "//")
		if !ok {
			continue
		}
		code = strings.TrimSpace(code)
		for _, alt := range strings.Split(comment, " or ") {
			raw, err := hexBytes(strings.TrimSpace(alt))
			if err != nil || len(raw) == 0 || len(raw) > MaxInstLen {
				break // not an encoding (a remark), or too long to be one
			}
			st.encodings++
			in := Decode(mode, raw, 0x140001000)
			goOp := goOpName(code)
			if !in.Valid {
				st.db++
				st.missing[fmt.Sprintf("%-14s % x", goOp, raw[:min(len(raw), 5)])]++
			}
			if in.Len == len(raw) && in.Valid {
				st.lenOK++
				compareAsmText(code, in, st)
				continue
			}
			key := patternKey(mode, raw)
			m := st.mismatch[key]
			if m == nil {
				m = &oracleMismatch{goOp: goOp, example: fmt.Sprintf("% x  go: %s  mine: %s (len %d, want %d)", raw, code, in.Text, in.Len, len(raw))}
				st.mismatch[key] = m
			}
			m.count++
		}
	}
	return sc.Err()
}

var (
	goImmRe  = regexp.MustCompile(`\$(-?(?:0x[0-9a-fA-F]+|[0-9]+))`)
	goDispRe = regexp.MustCompile(`(?:^|[ ,])(-?(?:0x[0-9a-fA-F]+|[0-9]+))\(`)
	anyNumRe = regexp.MustCompile(`-?0x[0-9a-fA-F]+|[0-9]+`)
	goSkipRe = regexp.MustCompile(`\((?:PC|SB|FP)\)|[ ,]K[0-7]|[ ,]Z[0-9]|[ ,]M[0-7]|[ ,]F[0-7]|\{`)
)

// parseGoNumber parses a Go assembler integer literal (decimal or hexadecimal, signed).
func parseGoNumber(s string) (uint64, bool) {
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	base := 10
	if rest, ok := strings.CutPrefix(s, "0x"); ok {
		s, base = rest, 16
	}
	v, err := strconv.ParseUint(s, base, 64)
	if err != nil {
		return 0, false
	}
	if neg {
		v = -v
	}
	return v, true
}

// compareAsmText cross-checks the operation, the registers and the numbers of the
// decoder's text against the assembler source line that produced the bytes. Only the
// instructions whose operands the assembler source spells in a comparable way are
// checked; the figures are indicative, the length agreement is the verdict.
func compareAsmText(src string, in Inst, st *asmStats) {
	if goSkipRe.MatchString(src) || in.Mnemonic == "vex" || in.Mnemonic == "evex" {
		return
	}
	goOp := goOpName(src)
	if goOp == "" || strings.ContainsAny(goOp[:1], "JL") && goOp != "LEAL" && goOp != "LEAQ" && goOp != "LEAW" || strings.HasPrefix(goOp, "CALL") || goOp == "XBEGIN" {
		return
	}
	if agree, mapped := opAgrees(goOp, myOpName(in)); mapped {
		st.opKnown++
		if agree {
			st.opOK++
		} else {
			st.opDiff[goOp+" -> "+myOpName(in)]++
		}
	}
	goRegs, myRegs := regSet(goRegRe, src), regSet(myRegRe, in.Operands)
	if goRegs != "" || myRegs != "" {
		st.regKnown++
		if goRegs == myRegs {
			st.regOK++
		} else {
			st.regDiff[src+" | "+in.Text]++
		}
	}
	var want []uint64
	for _, re := range []*regexp.Regexp{goImmRe, goDispRe} {
		for _, m := range re.FindAllStringSubmatch(src, -1) {
			if v, ok := parseGoNumber(m[1]); ok && v != 0 {
				want = append(want, v)
			}
		}
	}
	if len(want) == 0 {
		return
	}
	var have []uint64
	for _, m := range anyNumRe.FindAllString(in.Operands, -1) {
		if v, ok := parseGoNumber(m); ok {
			have = append(have, v)
		}
	}
	st.numKnown++
	for _, v := range want {
		found := false
		for _, h := range have {
			for _, w := range []int{8, 16, 32, 64} {
				if m := mask(w); h&m == v&m || (-h)&m == v&m {
					found = true
				}
			}
		}
		if !found {
			st.numDiff[src+" | "+in.Text]++
			return
		}
	}
	st.numOK++
}
