package xref

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/q6r/teardown/internal/format/pe"
	"github.com/q6r/teardown/internal/limits"
	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/testfixtures"
)

// dropperFixture is an image whose code calls four of its five imports, the
// last one through a thunk. Everything the tests expect about it was worked out
// by hand from the layout the fixture builder documents:
//
//   - the image base is 0x140000000, .text is at RVA 0x1000 (file offset 0x200) and
//     .data at RVA 0x3000;
//   - the import address table starts at RVA 0x20d0, so OpenProcess, VirtualAllocEx,
//     WriteProcessMemory, CreateRemoteThread and ExitProcess are the slots at
//     0x20d0, 0x20d8, 0x20e0, 0x20e8 and 0x20f0;
//   - the code, by offset from .text: "xor eax, eax; ret" (the entry point) and
//     int3 padding up to 0x10; the stub from there: 0x10 sub rsp, 0x58; 0x14 the
//     arguments of OpenProcess and its call at 0x21; 0x2c the arguments of
//     VirtualAllocEx and its call at 0x47; 0x52 those of WriteProcessMemory and its
//     call at 0x72; 0x7d those of CreateRemoteThread and "call 0xb8" at 0xa7; ret at
//     0xb7; the thunk "jmp [slot 0x20e8]" at 0xb8.
func dropperFixture() []byte {
	zero := testfixtures.PEArg{Kind: testfixtures.PEArgZero}
	imm := func(v uint32) testfixtures.PEArg { return testfixtures.PEArg{Kind: testfixtures.PEArgImm, Value: v} }
	res := func(i uint32) testfixtures.PEArg { return testfixtures.PEArg{Kind: testfixtures.PEArgResult, Value: i} }
	return testfixtures.PE(testfixtures.PEOptions{
		Imports: []testfixtures.PEImport{{Library: "KERNEL32.dll", Functions: []string{
			"OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "ExitProcess",
		}}},
		Calls: []testfixtures.PECall{
			{Function: "OpenProcess", Args: []testfixtures.PEArg{imm(0x1fffff), zero, imm(0x1a4)}},
			{Function: "VirtualAllocEx", Args: []testfixtures.PEArg{res(0), zero, imm(0x1000), imm(0x3000), imm(0x40)}},
			{Function: "WriteProcessMemory", Args: []testfixtures.PEArg{res(0), res(1), {Kind: testfixtures.PEArgData}, imm(0x200), zero}},
			{Function: "CreateRemoteThread", Thunk: true, Args: []testfixtures.PEArg{res(0), zero, zero, res(1), zero, zero, zero}},
		},
	})
}

func scan(t *testing.T, data []byte) *Index {
	t.Helper()
	ix, err := Scan(context.Background(), bytes.NewReader(data), int64(len(data)), limits.ForSize(int64(len(data))), Options{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return ix
}

func TestFindsTheCallSitesOfEveryImport(t *testing.T) {
	ix := scan(t, dropperFixture())
	if ix.Arch() != "x86-64" || ix.Imports() != 5 || !ix.Complete() || len(ix.Notes()) != 0 {
		t.Fatalf("arch %q, %d imports, complete %v, notes %v", ix.Arch(), ix.Imports(), ix.Complete(), ix.Notes())
	}
	tests := []struct {
		api  string
		want []Site
	}{
		{"KERNEL32.dll!OpenProcess", []Site{{API: "KERNEL32.dll!OpenProcess", Kind: KindCall, Addr: 0x140001021, Offset: 0x221, Section: ".text"}}},
		{"KERNEL32.dll!VirtualAllocEx", []Site{{API: "KERNEL32.dll!VirtualAllocEx", Kind: KindCall, Addr: 0x140001047, Offset: 0x247, Section: ".text"}}},
		{"KERNEL32.dll!WriteProcessMemory", []Site{{API: "KERNEL32.dll!WriteProcessMemory", Kind: KindCall, Addr: 0x140001072, Offset: 0x272, Section: ".text"}}},
		// The call goes through the thunk, and the thunk is listed last.
		{"KERNEL32.dll!CreateRemoteThread", []Site{
			{API: "KERNEL32.dll!CreateRemoteThread", Kind: KindCallThunk, Addr: 0x1400010a7, Offset: 0x2a7, Section: ".text", Via: 0x1400010b8},
			{API: "KERNEL32.dll!CreateRemoteThread", Kind: KindThunk, Addr: 0x1400010b8, Offset: 0x2b8, Section: ".text"},
		}},
		{"KERNEL32.dll!ExitProcess", nil},
		{"KERNEL32.dll!NoSuchFunction", nil},
	}
	for _, tc := range tests {
		got := ix.Sites(tc.api)
		if !slices.Equal(got, tc.want) {
			t.Errorf("Sites(%q) = %+v\nwant %+v", tc.api, got, tc.want)
		}
		if n := ix.Count(tc.api); n != len(tc.want) {
			t.Errorf("Count(%q) = %d, want %d", tc.api, n, len(tc.want))
		}
	}

	var names []string
	for _, a := range ix.APIs() {
		names = append(names, fmt.Sprintf("%s:%d", a.Function, a.Sites))
	}
	if want := []string{"OpenProcess:1", "VirtualAllocEx:1", "WriteProcessMemory:1", "CreateRemoteThread:2"}; !slices.Equal(names, want) {
		t.Errorf("APIs() = %v, want %v (ExitProcess is imported but never called)", names, want)
	}

	// A bare name, in any case and without the library, finds the same sites; so does
	// the A/W-folded form the rules use.
	for _, name := range []string{"virtualallocex", "VIRTUALALLOCEX", "kernel32.dll!VIRTUALALLOCEX"} {
		if got := ix.Sites(name); len(got) != 1 || got[0].Addr != 0x140001047 {
			t.Errorf("Sites(%q) = %+v", name, got)
		}
	}
	if got := ix.Sites("other.dll!VirtualAllocEx"); got != nil {
		t.Errorf("a different library must not match: %+v", got)
	}
}

func TestBlockShowsTheCallWithItsContext(t *testing.T) {
	ix := scan(t, dropperFixture())
	site := ix.Sites("VirtualAllocEx")[0]
	b := ix.Block(site, DefaultBefore, DefaultAfter)
	if err := b.Validate(); err != nil {
		t.Fatalf("the block is not valid: %v", err)
	}
	if b.Kind != report.CodeKindDisasm || b.Title != "call to KERNEL32.dll!VirtualAllocEx in .text" || b.Section != ".text" || b.Arch != "x86-64" || b.Truncated {
		t.Errorf("block header = %+v", b)
	}
	if b.Address != 0x14000101b || b.Offset != 0x21b {
		t.Errorf("the block starts at address %v, offset %#x", b.Address, b.Offset)
	}
	type line struct {
		addr  uint64
		off   int64
		bytes string
		text  string
		note  string
		hit   bool
	}
	want := []line{
		{0x14000101b, 0x21b, "41 b8 a4 01 00 00", "mov r8d, 0x1a4", "", false},
		{0x140001021, 0x221, "ff 15 a9 10 00 00", "call qword ptr [rip+0x10a9]", "KERNEL32.dll!OpenProcess", false},
		{0x140001027, 0x227, "48 89 44 24 38", "mov qword ptr [rsp+0x38], rax", "", false},
		{0x14000102c, 0x22c, "48 8b 4c 24 38", "mov rcx, qword ptr [rsp+0x38]", "", false},
		{0x140001031, 0x231, "31 d2", "xor edx, edx", "", false},
		{0x140001033, 0x233, "41 b8 00 10 00 00", "mov r8d, 0x1000", "", false},
		{0x140001039, 0x239, "41 b9 00 30 00 00", "mov r9d, 0x3000", "", false},
		{0x14000103f, 0x23f, "c7 44 24 20 40 00 00 00", "mov dword ptr [rsp+0x20], 0x40", "", false},
		{0x140001047, 0x247, "ff 15 8b 10 00 00", "call qword ptr [rip+0x108b]", "KERNEL32.dll!VirtualAllocEx", true},
		{0x14000104d, 0x24d, "48 89 44 24 40", "mov qword ptr [rsp+0x40], rax", "", false},
		{0x140001052, 0x252, "48 8b 4c 24 38", "mov rcx, qword ptr [rsp+0x38]", "", false},
		{0x140001057, 0x257, "48 8b 54 24 40", "mov rdx, qword ptr [rsp+0x40]", "", false},
		{0x14000105c, 0x25c, "4c 8d 05 9d 1f 00 00", "lea r8, [rip+0x1f9d]", "0x140003000 in .data", false},
	}
	var got []line
	for _, l := range b.Lines {
		got = append(got, line{uint64(l.Address), l.Offset, l.Bytes, l.Text, l.Note, l.Highlight})
	}
	if !slices.Equal(got, want) {
		t.Fatalf("lines:\n%+v\nwant:\n%+v", got, want)
	}
	if len(b.Limitations) != 3 || !strings.Contains(b.Limitations[0], "linear sweep") || !strings.Contains(b.Limitations[0], "x86-64") {
		t.Errorf("limitations = %q", b.Limitations)
	}
}

func TestBlockReachesBackOverPaddingAndTheEntryCode(t *testing.T) {
	ix := scan(t, dropperFixture())
	b := ix.Block(ix.Sites("OpenProcess")[0], DefaultBefore, DefaultAfter)
	// Eight instructions precede the first call: four of the int3 padding that follows
	// the entry point's "xor eax, eax; ret", then sub rsp, mov, xor, mov.
	var texts []string
	for _, l := range b.Lines {
		texts = append(texts, l.Text)
	}
	want := []string{
		"int3", "int3", "int3", "int3", "sub rsp, 0x58", "mov ecx, 0x1fffff", "xor edx, edx", "mov r8d, 0x1a4",
		"call qword ptr [rip+0x10a9]", "mov qword ptr [rsp+0x38], rax", "mov rcx, qword ptr [rsp+0x38]", "xor edx, edx", "mov r8d, 0x1000",
	}
	if !slices.Equal(texts, want) || !b.Lines[8].Highlight {
		t.Fatalf("lines = %q", texts)
	}
	if len(b.Limitations) != 3 {
		t.Errorf("limitations = %q: a clean lead-in adds none", b.Limitations)
	}

	// Asking for more than the section holds before the call reaches its first byte.
	b = ix.Block(ix.Sites("OpenProcess")[0], 40, 0)
	if b.Lines[0].Text != "xor eax, eax" || b.Lines[1].Text != "ret" || len(b.Lines) != 2+13+4+1 || b.Address != 0x140001000 || b.Offset != 0x200 {
		t.Errorf("block starts with %q at %v (%d lines)", b.Lines[0].Text, b.Address, len(b.Lines))
	}
}

func TestBlockThroughAThunk(t *testing.T) {
	ix := scan(t, dropperFixture())
	sites := ix.Sites("CreateRemoteThread")
	call := ix.Block(sites[0], 2, 1)
	if err := call.Validate(); err != nil {
		t.Fatal(err)
	}
	if call.Title != "call to KERNEL32.dll!CreateRemoteThread through a thunk in .text" {
		t.Errorf("title = %q", call.Title)
	}
	var hit report.CodeLine
	for _, l := range call.Lines {
		if l.Highlight {
			hit = l
		}
	}
	if hit.Text != "call 0x1400010b8" || hit.Note != "KERNEL32.dll!CreateRemoteThread (through the thunk at 0x1400010b8)" || hit.Bytes != "e8 0c 00 00 00" {
		t.Errorf("call line = %+v", hit)
	}

	stub := ix.Block(sites[1], 1, 1)
	if stub.Title != "import thunk for KERNEL32.dll!CreateRemoteThread in .text" {
		t.Errorf("title = %q", stub.Title)
	}
	if hit := stub.Lines[len(stub.Lines)-2]; hit.Text != "jmp qword ptr [rip+0x102a]" || !hit.Highlight || hit.Note != "KERNEL32.dll!CreateRemoteThread" {
		t.Errorf("thunk line = %+v (lines %+v)", hit, stub.Lines)
	}
}

// patchText overwrites bytes of .text (file offset 0x200 in every fixture).
func patchText(data []byte, at int, code ...byte) []byte {
	out := slices.Clone(data)
	copy(out[0x200+at:], code)
	return out
}

func TestUncalledThunksAndLoadsOfTheSlot(t *testing.T) {
	// Without the call, the thunk is a "jmp [IAT]" that may be a tail call.
	noCall := patchText(dropperFixture(), 0xa7, 0x90, 0x90, 0x90, 0x90, 0x90)
	ix := scan(t, noCall)
	want := []Site{{API: "KERNEL32.dll!CreateRemoteThread", Kind: KindJump, Addr: 0x1400010b8, Offset: 0x2b8, Section: ".text"}}
	if got := ix.Sites("CreateRemoteThread"); !slices.Equal(got, want) {
		t.Errorf("sites = %+v, want %+v", got, want)
	}
	if _, n := ix.CallBlocks("CreateRemoteThread", 6); n != 1 {
		t.Errorf("a tail call counts as a call site: %d", n)
	}

	// A mov rax, [slot] in the padding after the code: a load, shown only when nothing calls the import.
	// WriteProcessMemory is at slot 0x20e0: at RVA 0x1100 the displacement ends at 0x1107, so 0x20e0 - 0x1107 = 0xfd9.
	withLoad := patchText(dropperFixture(), 0x100, 0x48, 0x8b, 0x05, 0xd9, 0x0f, 0x00, 0x00)
	ix = scan(t, withLoad)
	sites := ix.Sites("WriteProcessMemory")
	if len(sites) != 2 || sites[0].Kind != KindCall || sites[1].Kind != KindLoad || sites[1].Addr != 0x140001100 {
		t.Fatalf("sites = %+v", sites)
	}
	blocks, n := ix.CallBlocks("WriteProcessMemory", 6)
	if len(blocks) != 1 || n != 1 || !strings.HasPrefix(blocks[0].Title, "call to ") {
		t.Errorf("CallBlocks must leave the load out when a call exists: %d blocks, %d sites", len(blocks), n)
	}

	loadOnly := patchText(withLoad, 0x72, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90) // the 6-byte call of WriteProcessMemory
	ix = scan(t, loadOnly)
	blocks, n = ix.CallBlocks("WriteProcessMemory", 6)
	if len(blocks) != 1 || n != 1 || blocks[0].Title != "reference to KERNEL32.dll!WriteProcessMemory in .text" {
		t.Errorf("a load is the only evidence: %d blocks, %d sites: %+v", len(blocks), n, blocks)
	}
	if text := blocks[0].Lines[len(blocks[0].Lines)-1].Text; text == "" {
		t.Error("empty line")
	}
}

func TestCallBlocksAreBoundedAndRanked(t *testing.T) {
	ix := scan(t, dropperFixture())
	blocks, n := ix.CallBlocks("KERNEL32.dll!CreateRemoteThread", 6)
	// The import thunk that something calls is not a call site of its own.
	if n != 1 || len(blocks) != 1 || !strings.Contains(blocks[0].Title, "through a thunk") {
		t.Fatalf("%d blocks for %d sites: %+v", len(blocks), n, blocks)
	}
	if blocks, n := ix.CallBlocks("ExitProcess", 6); len(blocks) != 0 || n != 0 {
		t.Errorf("a function nobody calls has no blocks: %d, %d", len(blocks), n)
	}
	if blocks, _ := ix.CallBlocks("OpenProcess", 0); len(blocks) != 0 {
		t.Errorf("limit 0 means no blocks, got %d", len(blocks))
	}
	if blocks, _ := ix.CallBlocks("OpenProcess", -3); len(blocks) != 0 {
		t.Errorf("a negative limit means no blocks, got %d", len(blocks))
	}
}

func TestBlockSaysWhenTheEarlierInstructionsCannotBeRecovered(t *testing.T) {
	// 0x06 is not an instruction in 64-bit mode: every start point before the call fails to decode.
	junk := bytes.Repeat([]byte{0x06}, 0x47-0x3f) // the eight bytes before the call at 0x47
	data := patchText(dropperFixture(), 0x3f, junk...)
	ix := scan(t, data)
	site := ix.Sites("VirtualAllocEx")[0]
	b := ix.Block(site, DefaultBefore, DefaultAfter)
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	if !b.Lines[0].Highlight || b.Lines[0].Address != 0x140001047 {
		t.Errorf("the block must start at the call: %+v", b.Lines[0])
	}
	if last := b.Limitations[len(b.Limitations)-1]; last != leadInLimit {
		t.Errorf("limitations = %q", b.Limitations)
	}
}

func TestPE32AbsoluteCalls(t *testing.T) {
	data := testfixtures.PE(testfixtures.PEOptions{Bits: 32})
	// By hand: PE32 thunks are four bytes wide, so the address table of the default
	// image (one import) is at RVA 0x2060 and its slot at VA 0x402060. .text is at 0x401000.
	code := []byte{
		0xff, 0x15, 0x60, 0x20, 0x40, 0x00, // call dword ptr [0x402060]
		0xc3, // ret
	}
	ix := scan(t, patchText(data, 0, code...))
	if ix.Arch() != "x86" {
		t.Fatalf("arch = %q", ix.Arch())
	}
	sites := ix.Sites("ExitProcess")
	if len(sites) != 1 || sites[0].Kind != KindCall || sites[0].Addr != 0x401000 || sites[0].Offset != 0x200 {
		t.Fatalf("sites = %+v", sites)
	}
	b := ix.Block(sites[0], 1, 1)
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	if b.Arch != "x86" || b.Lines[0].Text != "call dword ptr [0x402060]" || b.Lines[0].Note != "kernel32.dll!ExitProcess" || !b.Lines[0].Highlight {
		t.Errorf("block = %+v", b)
	}
}

func TestUnsupportedAndEmptyImages(t *testing.T) {
	arm := slices.Clone(dropperFixture())
	binary.LittleEndian.PutUint16(arm[testfixtures.PEOffset+4:], 0xaa64)
	if ix, err := Scan(context.Background(), bytes.NewReader(arm), int64(len(arm)), limits.Limits{}, Options{}); !errors.Is(err, ErrUnsupported) || ix != nil {
		t.Errorf("ARM64: index %v, error %v", ix, err)
	}
	if _, err := Scan(context.Background(), bytes.NewReader([]byte("not a pe")), 8, limits.Limits{}, Options{}); err == nil {
		t.Error("a file that is not a PE must be an error")
	}

	// No executable section: nothing to find, and the index says why.
	data := slices.Clone(dropperFixture())
	binary.LittleEndian.PutUint32(data[testfixtures.PESectionHeaderOffset(64, 0)+36:], testfixtures.PESectionRData)
	ix := scan(t, data)
	if len(ix.APIs()) != 0 || len(ix.Notes()) != 1 || !strings.Contains(ix.Notes()[0], "no executable section") {
		t.Errorf("APIs %v, notes %v", ix.APIs(), ix.Notes())
	}

	// No imports at all.
	ix = scan(t, testfixtures.PE(testfixtures.PEOptions{NoImports: true}))
	if ix.Imports() != 0 || len(ix.APIs()) != 0 || len(ix.Notes()) != 1 {
		t.Errorf("imports %d, notes %v", ix.Imports(), ix.Notes())
	}
}

func TestBudgetsAreReportedAsPartial(t *testing.T) {
	data := dropperFixture()
	r := bytes.NewReader(data)
	res, err := pe.Parse(context.Background(), r, int64(len(data)), limits.ForSize(int64(len(data))))
	if err != nil {
		t.Fatal(err)
	}
	// 0x30 bytes cover the first call (0x21) but not the second (0x47).
	ix, err := Find(context.Background(), r, int64(len(data)), res.Layout, Options{MaxSectionBytes: 0x30})
	if err != nil {
		t.Fatal(err)
	}
	if ix.Complete() || len(ix.Sites("OpenProcess")) != 1 || len(ix.Sites("VirtualAllocEx")) != 0 || len(ix.Notes()) == 0 {
		t.Errorf("complete %v, notes %v", ix.Complete(), ix.Notes())
	}
	// Nineteen instructions (the entry code, its 13 int3 of padding, sub, mov, xor, mov) come before the call at 0x21.
	ix, _ = Find(context.Background(), r, int64(len(data)), res.Layout, Options{MaxInstructions: 19})
	if ix.Complete() || len(ix.Sites("OpenProcess")) != 0 || !strings.Contains(strings.Join(ix.Notes(), " "), "19 instructions") {
		t.Errorf("complete %v, notes %v", ix.Complete(), ix.Notes())
	}
	ix, _ = Find(context.Background(), r, int64(len(data)), res.Layout, Options{MaxBytes: 10})
	if ix.Complete() {
		t.Error("a 10-byte budget cannot cover the code")
	}
}

func TestCancelledScan(t *testing.T) {
	data := dropperFixture()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ix, err := Scan(ctx, bytes.NewReader(data), int64(len(data)), limits.Limits{}, Options{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if ix != nil && ix.Complete() {
		t.Error("a cancelled scan must not claim to be complete")
	}

	// Cancelled between the header parse and the sweep: the partial index comes back with the error.
	res, perr := pe.Parse(context.Background(), bytes.NewReader(data), int64(len(data)), limits.Limits{})
	if perr != nil {
		t.Fatal(perr)
	}
	ix, err = Find(ctx, bytes.NewReader(data), int64(len(data)), res.Layout, Options{})
	if !errors.Is(err, context.Canceled) || ix == nil || ix.Complete() || len(ix.APIs()) != 0 {
		t.Errorf("Find with a cancelled context: index %v, err %v", ix, err)
	}
	if notes := strings.Join(ix.Notes(), " "); !strings.Contains(notes, "interrupted") {
		t.Errorf("notes = %q", notes)
	}
}

func TestSiteCapsKeepTheCountExact(t *testing.T) {
	// Many calls to one import: only maxSitesPerAPI are kept, all are counted.
	const calls = maxSitesPerAPI + 40
	var code []byte
	for i := range calls {
		// call qword ptr [rip+disp] in a section of its own at RVA 0x4000; the slot of
		// ExitProcess is at RVA 0x2068.
		next := 0x4000 + 6*(i+1)
		disp := uint32(0x2068 - next)
		code = append(code, 0xff, 0x15, byte(disp), byte(disp>>8), byte(disp>>16), byte(disp>>24))
	}
	ix := scan(t, testfixtures.PE(testfixtures.PEOptions{Sections: []testfixtures.PESection{
		{Name: ".code", Data: code, Characteristics: testfixtures.PESectionCode},
	}}))
	if got := len(ix.Sites("ExitProcess")); got != maxSitesPerAPI {
		t.Errorf("kept %d sites, want the cap of %d", got, maxSitesPerAPI)
	}
	if got := ix.Count("ExitProcess"); got != calls {
		t.Errorf("counted %d sites, want %d", got, calls)
	}
	if !strings.Contains(strings.Join(ix.Notes(), " "), "more call sites exist") {
		t.Errorf("notes = %v", ix.Notes())
	}
	_, n := ix.CallBlocks("ExitProcess", 6)
	if n != calls {
		t.Errorf("CallBlocks counts %d sites, want %d", n, calls)
	}
}
