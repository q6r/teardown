package disasm

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// testAddr is the virtual address the table tests decode at.
const testAddr = 0x1000

// mustHex converts "48 8b 4c 24 08" to bytes.
func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// decodeCase is one hand-verified encoding: the bytes come from the Intel
// architecture manuals (opcode maps and ModRM/SIB tables), the text is the
// expected Intel-syntax rendering. All of them decode at testAddr.
type decodeCase struct {
	hex  string
	want string
}

func runCases(t *testing.T, mode Mode, cases []decodeCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.hex, func(t *testing.T) {
			code := mustHex(t, tc.hex)
			in := Decode(mode, code, testAddr)
			if in.Text != tc.want {
				t.Fatalf("Decode(% x) = %q, want %q", code, in.Text, tc.want)
			}
			if in.Len != len(code) {
				t.Errorf("Decode(% x) Len = %d, want %d", code, in.Len, len(code))
			}
			if !in.Valid {
				t.Errorf("Decode(% x) is not Valid", code)
			}
			checkInvariants(t, code, in)
		})
	}
}

// checkInvariants verifies the structural promises of Inst for any decode result.
func checkInvariants(t testing.TB, code []byte, in Inst) {
	t.Helper()
	if len(code) == 0 {
		if in.Len != 0 {
			t.Fatalf("empty input gave Len %d", in.Len)
		}
		return
	}
	if in.Len < 1 || in.Len > MaxInstLen || in.Len > len(code) {
		t.Fatalf("Decode(% x) Len = %d", code, in.Len)
	}
	if !bytes.Equal(in.Bytes, code[:in.Len]) || len(in.Bytes) != in.Len {
		t.Fatalf("Decode(% x) Bytes = % x", code, in.Bytes)
	}
	want := in.Mnemonic
	if in.Operands != "" {
		want += " " + in.Operands
	}
	if in.Text != want {
		t.Fatalf("Decode(% x) Text %q != Mnemonic %q + Operands %q", code, in.Text, in.Mnemonic, in.Operands)
	}
	for i := 0; i < len(in.Text); i++ {
		if c := in.Text[i]; c < 0x20 || c > 0x7e {
			t.Fatalf("Decode(% x) Text %q holds a non-ASCII or control byte", code, in.Text)
		}
	}
	if in.Mnemonic == "" || in.Text != strings.TrimSpace(in.Text) {
		t.Fatalf("Decode(% x) Text = %q", code, in.Text)
	}
	if in.Valid != (in.Mnemonic != "db") {
		t.Fatalf("Decode(% x) Valid = %v for mnemonic %q", code, in.Valid, in.Mnemonic)
	}
	if !in.Valid && in.Len != 1 {
		t.Fatalf("Decode(% x) invalid but Len = %d", code, in.Len)
	}
}

func TestDecode64OneByte(t *testing.T) {
	runCases(t, Mode64, []decodeCase{
		// no-operand instructions
		{"90", "nop"},
		{"c3", "ret"},
		{"cc", "int3"},
		{"c9", "leave"},
		{"cb", "retf"},
		{"f4", "hlt"},
		{"f1", "int1"},
		{"fc", "cld"},
		{"fd", "std"},
		{"f8", "clc"},
		{"f9", "stc"},
		{"f5", "cmc"},
		{"fa", "cli"},
		{"fb", "sti"},
		{"9b", "fwait"},
		{"9e", "sahf"},
		{"9f", "lahf"},
		{"d7", "xlatb"},
		{"9c", "pushf"},
		{"9d", "popf"},
		{"66 90", "nop"},
		{"f3 90", "pause"},
		{"f3 c3", "repz ret"},
		{"c2 08 00", "ret 0x8"},
		{"ca 10 00", "retf 0x10"},
		{"cd 80", "int 0x80"},
		{"cd 2e", "int 0x2e"},
		{"c8 10 00 00", "enter 0x10, 0x0"},
		{"c6 f8 07", "xabort 0x7"},
		{"c7 f8 00 00 00 00", "xbegin 0x1006"},

		// push and pop
		{"55", "push rbp"},
		{"5d", "pop rbp"},
		{"41 54", "push r12"},
		{"41 5f", "pop r15"},
		{"66 50", "push ax"},
		{"68 00 10 00 00", "push 0x1000"},
		{"6a 01", "push 0x1"},
		{"6a ff", "push 0xffffffffffffffff"},
		{"ff 30", "push qword ptr [rax]"},
		{"8f 00", "pop qword ptr [rax]"},

		// mov
		{"48 89 e5", "mov rbp, rsp"},
		{"89 d8", "mov eax, ebx"},
		{"88 c8", "mov al, cl"},
		{"40 88 f0", "mov al, sil"},
		{"88 e0", "mov al, ah"},
		{"44 88 c0", "mov al, r8b"},
		{"8a 07", "mov al, byte ptr [rdi]"},
		{"66 89 c8", "mov ax, cx"},
		{"4d 89 c8", "mov r8, r9"},
		{"48 8b 4c 24 08", "mov rcx, qword ptr [rsp+0x8]"},
		{"48 89 45 f8", "mov qword ptr [rbp-0x8], rax"},
		{"8b 04 85 00 10 40 00", "mov eax, dword ptr [rax*4+0x401000]"},
		{"8b 44 88 10", "mov eax, dword ptr [rax+rcx*4+0x10]"},
		{"8b 04 24", "mov eax, dword ptr [rsp]"},
		{"41 8b 04 24", "mov eax, dword ptr [r12]"},
		{"41 8b 45 00", "mov eax, dword ptr [r13+0x0]"},
		{"42 8b 04 28", "mov eax, dword ptr [rax+r13*1]"},
		{"8b 80 00 01 00 00", "mov eax, dword ptr [rax+0x100]"},
		{"8b 80 00 ff ff ff", "mov eax, dword ptr [rax-0x100]"},
		{"b8 01 00 00 00", "mov eax, 0x1"},
		{"b0 41", "mov al, 0x41"},
		{"41 b8 00 00 00 80", "mov r8d, 0x80000000"},
		{"66 b8 34 12", "mov ax, 0x1234"},
		{"48 b8 88 77 66 55 44 33 22 11", "movabs rax, 0x1122334455667788"},
		{"48 c7 c0 ff ff ff ff", "mov rax, 0xffffffffffffffff"},
		{"c7 45 fc 00 00 00 00", "mov dword ptr [rbp-0x4], 0x0"},
		{"c6 00 41", "mov byte ptr [rax], 0x41"},
		{"66 c7 00 34 12", "mov word ptr [rax], 0x1234"},
		{"48 c7 00 ff ff ff ff", "mov qword ptr [rax], 0xffffffffffffffff"},
		{"8c d8", "mov eax, ds"},
		{"8e d8", "mov ds, eax"},
		{"8c 18", "mov word ptr [rax], ds"},
		{"64 48 8b 04 25 28 00 00 00", "mov rax, qword ptr fs:[0x28]"},
		{"65 48 8b 04 25 60 00 00 00", "mov rax, qword ptr gs:[0x60]"},
		{"64 8b 00", "mov eax, dword ptr fs:[rax]"},
		{"a0 88 77 66 55 44 33 22 11", "movabs al, byte ptr ds:0x1122334455667788"},
		{"48 a3 88 77 66 55 44 33 22 11", "movabs qword ptr ds:0x1122334455667788, rax"},
		{"67 8b 00", "mov eax, dword ptr [eax]"},
		{"67 48 8b 04 24", "mov rax, qword ptr [esp]"},
		{"48 63 d0", "movsxd rdx, eax"},
		{"4c 63 04 8a", "movsxd r8, dword ptr [rdx+rcx*4]"},
		{"0f b6 c1", "movzx eax, cl"},
		{"0f b6 00", "movzx eax, byte ptr [rax]"},
		{"0f b7 c1", "movzx eax, cx"},
		{"48 0f b7 00", "movzx rax, word ptr [rax]"},
		{"0f be c1", "movsx eax, cl"},
		{"48 0f be c1", "movsx rax, cl"},
		{"0f bf 00", "movsx eax, word ptr [rax]"},
		{"48 0f c3 08", "movnti qword ptr [rax], rcx"},

		// lea
		{"48 8d 0d b7 1f 00 00", "lea rcx, [rip+0x1fb7]"},
		{"48 8b 05 f9 ff ff ff", "mov rax, qword ptr [rip-0x7]"},
		{"8d 04 40", "lea eax, [rax+rax*2]"},
		{"48 8d 04 c5 00 00 00 00", "lea rax, [rax*8+0x0]"},
		{"48 8d 7c 24 10", "lea rdi, [rsp+0x10]"},
		{"8d 74 26 00", "lea esi, [rsi+0x0]"},

		// arithmetic and logic
		{"48 83 ec 28", "sub rsp, 0x28"},
		{"48 83 c4 28", "add rsp, 0x28"},
		{"48 81 ec 00 01 00 00", "sub rsp, 0x100"},
		{"83 e8 01", "sub eax, 0x1"},
		{"83 c0 ff", "add eax, 0xffffffff"},
		{"48 83 e4 f0", "and rsp, 0xfffffffffffffff0"},
		{"66 83 c0 01", "add ax, 0x1"},
		{"66 05 34 12", "add ax, 0x1234"},
		{"80 38 00", "cmp byte ptr [rax], 0x0"},
		{"80 f9 ff", "cmp cl, 0xff"},
		{"01 d8", "add eax, ebx"},
		{"03 45 fc", "add eax, dword ptr [rbp-0x4]"},
		{"04 05", "add al, 0x5"},
		{"05 00 10 00 00", "add eax, 0x1000"},
		{"48 05 00 10 00 00", "add rax, 0x1000"},
		{"48 05 00 00 00 80", "add rax, 0xffffffff80000000"},
		{"09 c8", "or eax, ecx"},
		{"11 d8", "adc eax, ebx"},
		{"19 d8", "sbb eax, ebx"},
		{"21 d8", "and eax, ebx"},
		{"29 d8", "sub eax, ebx"},
		{"31 c0", "xor eax, eax"},
		{"33 c9", "xor ecx, ecx"},
		{"48 31 c0", "xor rax, rax"},
		{"45 31 c0", "xor r8d, r8d"},
		{"39 d8", "cmp eax, ebx"},
		{"3b 05 00 01 00 00", "cmp eax, dword ptr [rip+0x100]"},
		{"3c 41", "cmp al, 0x41"},
		{"3d 00 10 00 00", "cmp eax, 0x1000"},
		{"48 3d 00 10 00 00", "cmp rax, 0x1000"},
		{"83 f8 01", "cmp eax, 0x1"},
		{"48 83 f8 ff", "cmp rax, 0xffffffffffffffff"},
		{"84 c0", "test al, al"},
		{"85 c0", "test eax, eax"},
		{"48 85 c0", "test rax, rax"},
		{"a8 01", "test al, 0x1"},
		{"a9 00 01 00 00", "test eax, 0x100"},
		{"f6 c1 01", "test cl, 0x1"},
		{"f7 c1 00 01 00 00", "test ecx, 0x100"},
		{"f6 00 80", "test byte ptr [rax], 0x80"},
		{"ff c0", "inc eax"},
		{"48 ff c0", "inc rax"},
		{"ff c8", "dec eax"},
		{"fe c0", "inc al"},
		{"fe c8", "dec al"},
		{"ff 00", "inc dword ptr [rax]"},
		{"f7 d8", "neg eax"},
		{"f7 d0", "not eax"},
		{"48 f7 d8", "neg rax"},
		{"f6 d8", "neg al"},
		{"48 f7 e1", "mul rcx"},
		{"f7 e1", "mul ecx"},
		{"f7 f1", "div ecx"},
		{"48 f7 f9", "idiv rcx"},
		{"f7 7d fc", "idiv dword ptr [rbp-0x4]"},
		{"f7 e9", "imul ecx"},
		{"0f af c1", "imul eax, ecx"},
		{"48 0f af c1", "imul rax, rcx"},
		{"6b c0 0c", "imul eax, eax, 0xc"},
		{"6b c0 f4", "imul eax, eax, 0xfffffff4"},
		{"69 c0 e8 03 00 00", "imul eax, eax, 0x3e8"},
		{"48 69 c0 e8 03 00 00", "imul rax, rax, 0x3e8"},
		{"98", "cwde"},
		{"48 98", "cdqe"},
		{"66 98", "cbw"},
		{"99", "cdq"},
		{"48 99", "cqo"},
		{"66 99", "cwd"},
		{"87 d1", "xchg ecx, edx"},
		{"48 87 d1", "xchg rcx, rdx"},
		{"86 c8", "xchg al, cl"},
		{"49 90", "xchg r8, rax"},
		{"91", "xchg ecx, eax"},
		{"48 93", "xchg rbx, rax"},

		// shifts and rotates
		{"d1 e0", "shl eax, 1"},
		{"d1 f8", "sar eax, 1"},
		{"d0 e8", "shr al, 1"},
		{"c1 e0 04", "shl eax, 0x4"},
		{"c1 f8 1f", "sar eax, 0x1f"},
		{"48 c1 e8 3f", "shr rax, 0x3f"},
		{"d3 e0", "shl eax, cl"},
		{"48 d3 ea", "shr rdx, cl"},
		{"d2 e0", "shl al, cl"},
		{"c0 e8 04", "shr al, 0x4"},
		{"c1 c0 08", "rol eax, 0x8"},
		{"d1 c8", "ror eax, 1"},
		{"c1 d0 01", "rcl eax, 0x1"},
		{"c1 d8 01", "rcr eax, 0x1"},
		{"d1 20", "shl dword ptr [rax], 1"},

		// control flow with relative targets, decoded at 0x1000
		{"e8 00 00 00 00", "call 0x1005"},
		{"e8 fb 0f 00 00", "call 0x2000"},
		{"e9 fb ff ff ff", "jmp 0x1000"},
		{"eb fe", "jmp 0x1000"},
		{"eb 7f", "jmp 0x1081"},
		{"74 05", "je 0x1007"},
		{"75 fe", "jne 0x1000"},
		{"72 00", "jb 0x1002"},
		{"73 00", "jae 0x1002"},
		{"76 00", "jbe 0x1002"},
		{"77 00", "ja 0x1002"},
		{"78 00", "js 0x1002"},
		{"79 00", "jns 0x1002"},
		{"7a 00", "jp 0x1002"},
		{"7b 00", "jnp 0x1002"},
		{"7c 00", "jl 0x1002"},
		{"7d 00", "jge 0x1002"},
		{"7e 00", "jle 0x1002"},
		{"7f 00", "jg 0x1002"},
		{"70 00", "jo 0x1002"},
		{"71 00", "jno 0x1002"},
		{"0f 84 10 00 00 00", "je 0x1016"},
		{"0f 85 00 01 00 00", "jne 0x1106"},
		{"0f 8f f0 ff ff ff", "jg 0xff6"},
		{"e3 05", "jrcxz 0x1007"},
		{"67 e3 05", "jecxz 0x1008"},
		{"e2 fe", "loop 0x1000"},
		{"e1 fe", "loope 0x1000"},
		{"e0 fe", "loopne 0x1000"},
		{"f2 e8 00 00 00 00", "bnd call 0x1006"},
		{"f2 c3", "bnd ret"},
		{"3e ff e0", "notrack jmp rax"},
		{"3e ff 20", "notrack jmp qword ptr [rax]"},
		{"3e ff d0", "notrack call rax"},
		{"3e 74 05", "je 0x1008"},
		{"ff d0", "call rax"},
		{"41 ff d4", "call r12"},
		{"ff e0", "jmp rax"},
		{"ff 15 b7 1f 00 00", "call qword ptr [rip+0x1fb7]"},
		{"ff 25 b7 1f 00 00", "jmp qword ptr [rip+0x1fb7]"},
		{"ff 14 25 18 40 40 00", "call qword ptr [0x404018]"},
		{"ff 24 c5 00 10 40 00", "jmp qword ptr [rax*8+0x401000]"},
		{"ff 10", "call qword ptr [rax]"},
		{"ff 18", "call fword ptr [rax]"},
		{"48 ff 18", "call tbyte ptr [rax]"},
		{"ff 28", "jmp fword ptr [rax]"},

		// string instructions
		{"a4", "movs byte ptr [rdi], byte ptr [rsi]"},
		{"48 a5", "movs qword ptr [rdi], qword ptr [rsi]"},
		{"f3 a4", "rep movs byte ptr [rdi], byte ptr [rsi]"},
		{"f3 48 a5", "rep movs qword ptr [rdi], qword ptr [rsi]"},
		{"f3 48 ab", "rep stos qword ptr [rdi], rax"},
		{"f3 aa", "rep stos byte ptr [rdi], al"},
		{"f3 ab", "rep stos dword ptr [rdi], eax"},
		{"f2 ae", "repne scas al, byte ptr [rdi]"},
		{"f3 a6", "repe cmps byte ptr [rsi], byte ptr [rdi]"},
		{"ac", "lods al, byte ptr [rsi]"},
		{"48 ad", "lods rax, qword ptr [rsi]"},
		{"6c", "ins byte ptr [rdi], dx"},
		{"6e", "outs dx, byte ptr [rsi]"},
		{"67 a4", "movs byte ptr [edi], byte ptr [esi]"},
		{"64 ac", "lods al, byte ptr fs:[rsi]"},

		// in and out
		{"e4 60", "in al, 0x60"},
		{"e5 60", "in eax, 0x60"},
		{"e6 80", "out 0x80, al"},
		{"ec", "in al, dx"},
		{"ed", "in eax, dx"},
		{"ee", "out dx, al"},
		{"ef", "out dx, eax"},
		{"66 ef", "out dx, ax"},

		// lock prefix
		{"f0 0f b1 0a", "lock cmpxchg dword ptr [rdx], ecx"},
		{"f0 48 0f c1 01", "lock xadd qword ptr [rcx], rax"},
		{"f0 ff 00", "lock inc dword ptr [rax]"},
		{"f0 83 00 01", "lock add dword ptr [rax], 0x1"},
		{"87 08", "xchg dword ptr [rax], ecx"},
	})
}

func TestDecode64TwoByte(t *testing.T) {
	runCases(t, Mode64, []decodeCase{
		{"0f 05", "syscall"},
		{"0f 34", "sysenter"},
		{"0f a2", "cpuid"},
		{"0f 0b", "ud2"},
		{"0f 31", "rdtsc"},
		{"0f 01 f9", "rdtscp"},
		{"0f 01 d0", "xgetbv"},
		{"0f 01 f8", "swapgs"},
		{"0f 30", "wrmsr"},
		{"0f 32", "rdmsr"},
		{"f3 0f 1e fa", "endbr64"},
		{"f3 0f 1e fb", "endbr32"},
		{"0f ae e8", "lfence"},
		{"0f ae f0", "mfence"},
		{"0f ae f8", "sfence"},
		{"0f 18 08", "prefetcht0 [rax]"},
		{"0f 18 00", "prefetchnta [rax]"},
		{"0f 0d 08", "prefetchw [rax]"},
		{"0f ae 38", "clflush byte ptr [rax]"},
		{"0f ae 10", "ldmxcsr dword ptr [rax]"},
		{"0f ae 18", "stmxcsr dword ptr [rax]"},
		{"0f ae 00", "fxsave [rax]"},
		{"48 0f ae 00", "fxsave64 [rax]"},
		{"0f c7 08", "cmpxchg8b [rax]"},
		{"48 0f c7 08", "cmpxchg16b [rax]"},
		{"0f c7 f0", "rdrand eax"},
		{"0f c7 f8", "rdseed eax"},
		{"48 0f c7 f0", "rdrand rax"},
		{"0f 20 c0", "mov rax, cr0"},
		{"0f 22 d8", "mov cr3, rax"},
		{"44 0f 20 c0", "mov rax, cr8"},
		{"0f 21 c0", "mov rax, dr0"},
		{"0f 1f 00", "nop dword ptr [rax]"},
		{"0f 1f 40 00", "nop dword ptr [rax+0x0]"},
		{"0f 1f 44 00 00", "nop dword ptr [rax+rax*1+0x0]"},
		{"66 0f 1f 44 00 00", "nop word ptr [rax+rax*1+0x0]"},
		{"0f 1f 80 00 00 00 00", "nop dword ptr [rax+0x0]"},
		{"0f 1f 84 00 00 00 00 00", "nop dword ptr [rax+rax*1+0x0]"},
		{"66 0f 1f 84 00 00 00 00 00", "nop word ptr [rax+rax*1+0x0]"},
		{"66 2e 0f 1f 84 00 00 00 00 00", "nop word ptr cs:[rax+rax*1+0x0]"},
		{"66 66 2e 0f 1f 84 00 00 00 00 00", "nop word ptr cs:[rax+rax*1+0x0]"},

		// cmovcc, setcc, bit instructions
		{"0f 94 c0", "sete al"},
		{"0f 9f c0", "setg al"},
		{"0f 95 c1", "setne cl"},
		{"0f 90 00", "seto byte ptr [rax]"},
		{"0f 4f c1", "cmovg eax, ecx"},
		{"48 0f 44 c1", "cmove rax, rcx"},
		{"0f 42 05 00 00 00 00", "cmovb eax, dword ptr [rip+0x0]"},
		{"0f 4d c1", "cmovge eax, ecx"},
		{"0f a3 c8", "bt eax, ecx"},
		{"0f ab c8", "bts eax, ecx"},
		{"0f b3 c8", "btr eax, ecx"},
		{"0f bb c8", "btc eax, ecx"},
		{"0f ba e0 05", "bt eax, 0x5"},
		{"0f ba 28 03", "bts dword ptr [rax], 0x3"},
		{"48 0f ba f0 3f", "btr rax, 0x3f"},
		{"0f ba f8 01", "btc eax, 0x1"},
		{"0f bc c1", "bsf eax, ecx"},
		{"0f bd c1", "bsr eax, ecx"},
		{"f3 0f bc c1", "tzcnt eax, ecx"},
		{"f3 0f bd c1", "lzcnt eax, ecx"},
		{"f3 0f b8 c1", "popcnt eax, ecx"},
		{"f3 48 0f b8 c1", "popcnt rax, rcx"},
		{"0f c8", "bswap eax"},
		{"48 0f c9", "bswap rcx"},
		{"41 0f c8", "bswap r8d"},
		{"0f a4 c2 04", "shld edx, eax, 0x4"},
		{"0f a5 c2", "shld edx, eax, cl"},
		{"0f ac c2 04", "shrd edx, eax, 0x4"},
		{"0f b0 0a", "cmpxchg byte ptr [rdx], cl"},
		{"0f c0 c1", "xadd cl, al"},
		{"0f c1 08", "xadd dword ptr [rax], ecx"},
		{"0f a0", "push fs"},
		{"0f a9", "pop gs"},

		// SSE and SSE2
		{"0f 10 00", "movups xmm0, xmmword ptr [rax]"},
		{"0f 11 08", "movups xmmword ptr [rax], xmm1"},
		{"66 0f 10 00", "movupd xmm0, xmmword ptr [rax]"},
		{"f3 0f 10 05 00 01 00 00", "movss xmm0, dword ptr [rip+0x100]"},
		{"f3 0f 10 c1", "movss xmm0, xmm1"},
		{"f3 0f 11 45 fc", "movss dword ptr [rbp-0x4], xmm0"},
		{"f2 0f 10 45 f8", "movsd xmm0, qword ptr [rbp-0x8]"},
		{"f2 0f 11 01", "movsd qword ptr [rcx], xmm0"},
		{"0f 28 c1", "movaps xmm0, xmm1"},
		{"44 0f 28 c1", "movaps xmm8, xmm1"},
		{"0f 29 00", "movaps xmmword ptr [rax], xmm0"},
		{"66 0f 28 c1", "movapd xmm0, xmm1"},
		{"0f 12 00", "movlps xmm0, qword ptr [rax]"},
		{"0f 12 c1", "movhlps xmm0, xmm1"},
		{"0f 16 c1", "movlhps xmm0, xmm1"},
		{"0f 16 00", "movhps xmm0, qword ptr [rax]"},
		{"66 0f 17 00", "movhpd qword ptr [rax], xmm0"},
		{"66 0f 6f 00", "movdqa xmm0, xmmword ptr [rax]"},
		{"f3 0f 6f 00", "movdqu xmm0, xmmword ptr [rax]"},
		{"f3 0f 7f 01", "movdqu xmmword ptr [rcx], xmm0"},
		{"66 0f 7f 01", "movdqa xmmword ptr [rcx], xmm0"},
		{"0f 6f c1", "movq mm0, mm1"},
		{"0f 7f 00", "movq qword ptr [rax], mm0"},
		{"0f 77", "emms"},
		{"66 0f ef c0", "pxor xmm0, xmm0"},
		{"0f ef c1", "pxor mm0, mm1"},
		{"66 0f eb c1", "por xmm0, xmm1"},
		{"66 0f db c1", "pand xmm0, xmm1"},
		{"66 0f df c1", "pandn xmm0, xmm1"},
		{"0f 57 c0", "xorps xmm0, xmm0"},
		{"66 0f 57 c9", "xorpd xmm1, xmm1"},
		{"0f 54 c1", "andps xmm0, xmm1"},
		{"0f 56 c1", "orps xmm0, xmm1"},
		{"f2 0f 58 c1", "addsd xmm0, xmm1"},
		{"f3 0f 58 c1", "addss xmm0, xmm1"},
		{"0f 58 c1", "addps xmm0, xmm1"},
		{"66 0f 58 c1", "addpd xmm0, xmm1"},
		{"f3 0f 59 c1", "mulss xmm0, xmm1"},
		{"f2 0f 5c 45 f0", "subsd xmm0, qword ptr [rbp-0x10]"},
		{"f2 0f 5e c1", "divsd xmm0, xmm1"},
		{"f2 0f 51 c1", "sqrtsd xmm0, xmm1"},
		{"f3 0f 51 c1", "sqrtss xmm0, xmm1"},
		{"f2 0f 5d c1", "minsd xmm0, xmm1"},
		{"f2 0f 5f c1", "maxsd xmm0, xmm1"},
		{"f2 0f 2a c0", "cvtsi2sd xmm0, eax"},
		{"f2 48 0f 2a c0", "cvtsi2sd xmm0, rax"},
		{"f3 0f 2a c0", "cvtsi2ss xmm0, eax"},
		{"f2 0f 2a 00", "cvtsi2sd xmm0, dword ptr [rax]"},
		{"f2 48 0f 2a 00", "cvtsi2sd xmm0, qword ptr [rax]"},
		{"f2 0f 2c c0", "cvttsd2si eax, xmm0"},
		{"f2 48 0f 2c c0", "cvttsd2si rax, xmm0"},
		{"f3 0f 2c c0", "cvttss2si eax, xmm0"},
		{"f2 0f 2d c0", "cvtsd2si eax, xmm0"},
		{"f3 0f 5a c1", "cvtss2sd xmm0, xmm1"},
		{"f2 0f 5a c1", "cvtsd2ss xmm0, xmm1"},
		{"0f 5a c1", "cvtps2pd xmm0, xmm1"},
		{"66 0f 5a c1", "cvtpd2ps xmm0, xmm1"},
		{"f3 0f e6 c1", "cvtdq2pd xmm0, xmm1"},
		{"0f 5b c1", "cvtdq2ps xmm0, xmm1"},
		{"66 0f 2e c1", "ucomisd xmm0, xmm1"},
		{"0f 2e c1", "ucomiss xmm0, xmm1"},
		{"66 0f 2f c1", "comisd xmm0, xmm1"},
		{"0f 2f 00", "comiss xmm0, dword ptr [rax]"},
		{"66 0f 6e c0", "movd xmm0, eax"},
		{"66 48 0f 6e c0", "movq xmm0, rax"},
		{"66 0f 7e c0", "movd eax, xmm0"},
		{"66 48 0f 7e c0", "movq rax, xmm0"},
		{"0f 6e c0", "movd mm0, eax"},
		{"f3 0f 7e c1", "movq xmm0, xmm1"},
		{"f3 0f 7e 00", "movq xmm0, qword ptr [rax]"},
		{"66 0f d6 00", "movq qword ptr [rax], xmm0"},
		{"66 0f d7 c1", "pmovmskb eax, xmm1"},
		{"0f d7 c1", "pmovmskb eax, mm1"},
		{"0f 50 c1", "movmskps eax, xmm1"},
		{"66 0f 50 c1", "movmskpd eax, xmm1"},
		{"66 0f 70 c0 00", "pshufd xmm0, xmm0, 0x0"},
		{"f2 0f 70 c1 1b", "pshuflw xmm0, xmm1, 0x1b"},
		{"f3 0f 70 c1 1b", "pshufhw xmm0, xmm1, 0x1b"},
		{"0f 70 c1 1b", "pshufw mm0, mm1, 0x1b"},
		{"66 0f 74 c1", "pcmpeqb xmm0, xmm1"},
		{"66 0f 76 c1", "pcmpeqd xmm0, xmm1"},
		{"66 0f 64 c1", "pcmpgtb xmm0, xmm1"},
		{"66 0f fc c1", "paddb xmm0, xmm1"},
		{"66 0f fe c1", "paddd xmm0, xmm1"},
		{"66 0f d4 c1", "paddq xmm0, xmm1"},
		{"66 0f fb c1", "psubq xmm0, xmm1"},
		{"66 0f f4 c1", "pmuludq xmm0, xmm1"},
		{"66 0f 60 c1", "punpcklbw xmm0, xmm1"},
		{"0f 60 c1", "punpcklbw mm0, mm1"},
		{"66 0f 6c c1", "punpcklqdq xmm0, xmm1"},
		{"66 0f 6d c1", "punpckhqdq xmm0, xmm1"},
		{"66 0f 14 c1", "unpcklpd xmm0, xmm1"},
		{"66 0f 67 c1", "packuswb xmm0, xmm1"},
		{"66 0f 73 d8 08", "psrldq xmm0, 0x8"},
		{"66 0f 73 f8 08", "pslldq xmm0, 0x8"},
		{"66 0f 73 d0 08", "psrlq xmm0, 0x8"},
		{"66 0f 72 f0 04", "pslld xmm0, 0x4"},
		{"66 0f 71 d0 04", "psrlw xmm0, 0x4"},
		{"0f 71 d0 04", "psrlw mm0, 0x4"},
		{"66 0f d1 c1", "psrlw xmm0, xmm1"},
		{"66 0f c6 c1 4e", "shufpd xmm0, xmm1, 0x4e"},
		{"0f c6 c1 4e", "shufps xmm0, xmm1, 0x4e"},
		{"0f c2 c1 01", "cmpps xmm0, xmm1, 0x1"},
		{"f2 0f c2 c1 00", "cmpsd xmm0, xmm1, 0x0"},
		{"66 0f c4 c0 02", "pinsrw xmm0, eax, 0x2"},
		{"66 0f c5 c1 02", "pextrw eax, xmm1, 0x2"},
		{"f2 0f f0 00", "lddqu xmm0, xmmword ptr [rax]"},
		{"66 0f e7 00", "movntdq xmmword ptr [rax], xmm0"},
		{"0f 2b 00", "movntps xmmword ptr [rax], xmm0"},
		{"66 0f f7 c1", "maskmovdqu xmm0, xmm1"},
		{"66 0f 7c c1", "haddpd xmm0, xmm1"},
		{"f2 0f 7c c1", "haddps xmm0, xmm1"},
		{"f2 0f 12 c1", "movddup xmm0, xmm1"},
		{"f3 0f 16 c1", "movshdup xmm0, xmm1"},
		{"66 0f e6 c1", "cvttpd2dq xmm0, xmm1"},
		{"f3 0f 5b c1", "cvttps2dq xmm0, xmm1"},
		{"66 0f 5b c1", "cvtps2dq xmm0, xmm1"},
		{"66 41 0f 6f c0", "movdqa xmm0, xmm8"},
		{"66 45 0f ef c0", "pxor xmm8, xmm8"},
		{"66 0f 2a c1", "cvtpi2pd xmm0, mm1"},

		// three-byte maps
		{"66 0f 38 00 c1", "pshufb xmm0, xmm1"},
		{"0f 38 00 c1", "pshufb mm0, mm1"},
		{"66 0f 38 17 c1", "ptest xmm0, xmm1"},
		{"66 0f 38 1c c1", "pabsb xmm0, xmm1"},
		{"66 0f 38 10 c1", "pblendvb xmm0, xmm1, xmm0"},
		{"66 0f 38 20 c1", "pmovsxbw xmm0, xmm1"},
		{"66 0f 38 31 00", "pmovzxbd xmm0, dword ptr [rax]"},
		{"66 0f 38 29 c1", "pcmpeqq xmm0, xmm1"},
		{"66 0f 38 37 c1", "pcmpgtq xmm0, xmm1"},
		{"66 0f 38 3d c1", "pmaxsd xmm0, xmm1"},
		{"66 0f 38 40 c1", "pmulld xmm0, xmm1"},
		{"66 0f 38 dc c1", "aesenc xmm0, xmm1"},
		{"66 0f 38 dd c1", "aesenclast xmm0, xmm1"},
		{"66 0f 38 de c1", "aesdec xmm0, xmm1"},
		{"66 0f 38 db c1", "aesimc xmm0, xmm1"},
		{"66 0f 3a df c1 01", "aeskeygenassist xmm0, xmm1, 0x1"},
		{"66 0f 3a 44 c1 00", "pclmulqdq xmm0, xmm1, 0x0"},
		{"66 0f 3a 0f c1 08", "palignr xmm0, xmm1, 0x8"},
		{"0f 3a 0f c1 08", "palignr mm0, mm1, 0x8"},
		{"66 0f 3a 63 c1 0c", "pcmpistri xmm0, xmm1, 0xc"},
		{"66 0f 3a 61 c1 0c", "pcmpestri xmm0, xmm1, 0xc"},
		{"66 0f 3a 0b c1 09", "roundsd xmm0, xmm1, 0x9"},
		{"66 0f 3a 16 c0 01", "pextrd eax, xmm0, 0x1"},
		{"66 48 0f 3a 16 c0 01", "pextrq rax, xmm0, 0x1"},
		{"66 0f 3a 22 c0 01", "pinsrd xmm0, eax, 0x1"},
		{"66 0f 3a 14 c0 01", "pextrb eax, xmm0, 0x1"},
		{"66 0f 3a 14 00 01", "pextrb byte ptr [rax], xmm0, 0x1"},
		{"66 0f 3a 15 00 01", "pextrw word ptr [rax], xmm0, 0x1"},
		{"66 0f 3a 20 c0 01", "pinsrb xmm0, eax, 0x1"},
		{"66 0f 3a 20 00 01", "pinsrb xmm0, byte ptr [rax], 0x1"},
		{"f2 0f 38 f0 c1", "crc32 eax, cl"},
		{"f2 0f 38 f1 c1", "crc32 eax, ecx"},
		{"f2 48 0f 38 f1 c1", "crc32 rax, rcx"},
		{"66 f2 0f 38 f1 c1", "crc32 eax, cx"},
		{"0f 38 f0 00", "movbe eax, dword ptr [rax]"},
		{"0f 38 f1 00", "movbe dword ptr [rax], eax"},
		{"66 0f 38 f6 c1", "adcx eax, ecx"},
		{"f3 0f 38 f6 c1", "adox eax, ecx"},
		{"0f 38 c8 c1", "sha1nexte xmm0, xmm1"},
		{"0f 38 cb c1", "sha256rnds2 xmm0, xmm1, xmm0"},
		{"0f 3a cc c1 03", "sha1rnds4 xmm0, xmm1, 0x3"},
		{"66 0f 38 2a 00", "movntdqa xmm0, xmmword ptr [rax]"},
	})
}

func TestDecode64VEX(t *testing.T) {
	runCases(t, Mode64, []decodeCase{
		{"c5 f8 77", "vzeroupper"},
		{"c5 fc 77", "vzeroall"},
		{"c5 fd 6f 00", "vmovdqa ymm0, ymmword ptr [rax]"},
		{"c5 f9 6f 00", "vmovdqa xmm0, xmmword ptr [rax]"},
		{"c5 fe 6f 00", "vmovdqu ymm0, ymmword ptr [rax]"},
		{"c5 fe 7f 01", "vmovdqu ymmword ptr [rcx], ymm0"},
		{"c5 fc 10 00", "vmovups ymm0, ymmword ptr [rax]"},
		{"c5 fc 28 c1", "vmovaps ymm0, ymm1"},
		{"c5 fd 74 c1", "vpcmpeqb ymm0, ymm0, ymm1"},
		{"c5 f1 74 c2", "vpcmpeqb xmm0, xmm1, xmm2"},
		{"c5 fd d7 c0", "vpmovmskb eax, ymm0"},
		{"c5 f9 ef c0", "vpxor xmm0, xmm0, xmm0"},
		{"c5 fd eb c1", "vpor ymm0, ymm0, ymm1"},
		{"c5 fd db c1", "vpand ymm0, ymm0, ymm1"},
		{"c5 f8 57 c0", "vxorps xmm0, xmm0, xmm0"},
		{"c5 fb 10 45 f8", "vmovsd xmm0, qword ptr [rbp-0x8]"},
		{"c5 fb 58 c1", "vaddsd xmm0, xmm0, xmm1"},
		{"c5 f9 70 c1 1b", "vpshufd xmm0, xmm1, 0x1b"},
		{"c5 f9 73 d9 08", "vpsrldq xmm0, xmm1, 0x8"},
		{"c5 f9 6e c0", "vmovd xmm0, eax"},
		{"c4 e1 f9 6e c0", "vmovq xmm0, rax"},
		{"c4 e2 7d 78 c0", "vpbroadcastb ymm0, xmm0"},
		{"c4 e2 7d 58 00", "vpbroadcastd ymm0, dword ptr [rax]"},
		{"c4 e2 7d 36 c1", "vpermd ymm0, ymm0, ymm1"},
		{"c4 e3 7d 39 c1 01", "vextracti128 xmm1, ymm0, 0x1"},
		{"c4 e3 7d 38 c1 01", "vinserti128 ymm0, ymm0, xmm1, 0x1"},
		{"c4 e3 7d 46 c1 31", "vperm2i128 ymm0, ymm0, ymm1, 0x31"},
		{"c4 e2 f9 b9 c1", "vfmadd231sd xmm0, xmm0, xmm1"},
		{"c4 e2 79 b8 c1", "vfmadd231ps xmm0, xmm0, xmm1"},
		{"c4 e2 78 f2 c1", "andn eax, eax, ecx"},
		{"c4 e2 78 f7 c1", "bextr eax, ecx, eax"},
		{"c4 e2 79 f7 c1", "shlx eax, ecx, eax"},
		{"c4 e3 7b f0 c1 05", "rorx eax, ecx, 0x5"},
		{"c4 e2 78 f3 c9", "blsr eax, ecx"},
		{"c4 e2 f8 f5 c1", "bzhi rax, rcx, rax"},
		{"c5 fd 6f 05 00 01 00 00", "vmovdqa ymm0, ymmword ptr [rip+0x100]"},
		{"c4 41 7d 6f c1", "vmovdqa ymm8, ymm9"},
		{"c4 e3 7d 4c c1 20", "vpblendvb ymm0, ymm0, ymm1, ymm2"},
		{"c5 f8 5f c1", "vmaxps xmm0, xmm0, xmm1"},
		// not modelled: reported generically with the right length
		{"c4 e2 7d 50 00", "vex 0f38.66.50"},
		{"c4 e3 7d 7f c1 01", "vex 0f3a.66.7f"},
		{"62 f1 7c 48 10 00", "evex 0f.np.10"},
		{"62 f2 7d 48 78 c0", "evex 0f38.66.78"},
		{"62 f3 7d 48 3e c1 00", "evex 0f3a.66.3e"},
	})
}

func TestDecode32(t *testing.T) {
	runCases(t, Mode32, []decodeCase{
		{"55", "push ebp"},
		{"5d", "pop ebp"},
		{"89 e5", "mov ebp, esp"},
		{"83 ec 10", "sub esp, 0x10"},
		{"8b 45 08", "mov eax, dword ptr [ebp+0x8]"},
		{"c3", "ret"},
		{"c9", "leave"},
		{"40", "inc eax"},
		{"4f", "dec edi"},
		{"66 40", "inc ax"},
		{"48", "dec eax"},
		{"e8 00 00 00 00", "call 0x1005"},
		{"e9 fb ff ff ff", "jmp 0x1000"},
		{"eb 05", "jmp 0x1007"},
		{"66 eb 05", "jmp 0x1008"},
		{"ff 15 00 30 40 00", "call dword ptr [0x403000]"},
		{"ff 25 00 30 40 00", "jmp dword ptr [0x403000]"},
		{"ff 10", "call dword ptr [eax]"},
		{"ff d0", "call eax"},
		{"ff 14 85 00 30 40 00", "call dword ptr [eax*4+0x403000]"},
		{"a1 00 30 40 00", "mov eax, dword ptr ds:0x403000"},
		{"a3 00 30 40 00", "mov dword ptr ds:0x403000, eax"},
		{"b8 00 30 40 00", "mov eax, 0x403000"},
		{"68 00 30 40 00", "push 0x403000"},
		{"6a ff", "push 0xffffffff"},
		{"8d 04 40", "lea eax, [eax+eax*2]"},
		{"8b 05 00 30 40 00", "mov eax, dword ptr [0x403000]"},
		{"8b 04 25 00 30 40 00", "mov eax, dword ptr [0x403000]"},
		{"64 a1 18 00 00 00", "mov eax, dword ptr fs:0x18"},
		{"64 8b 0d 00 00 00 00", "mov ecx, dword ptr fs:[0x0]"},
		{"60", "pushad"},
		{"61", "popad"},
		{"66 60", "pushaw"},
		{"06", "push es"},
		{"07", "pop es"},
		{"1e", "push ds"},
		{"27", "daa"},
		{"2f", "das"},
		{"37", "aaa"},
		{"3f", "aas"},
		{"d4 0a", "aam 0xa"},
		{"d5 0a", "aad 0xa"},
		{"ce", "into"},
		{"c4 00", "les eax, fword ptr [eax]"},
		{"c5 00", "lds eax, fword ptr [eax]"},
		{"62 00", "bound eax, [eax]"},
		{"63 c8", "arpl ax, cx"},
		{"9a 00 10 00 00 23 00", "call 0x23:0x1000"},
		{"ea 00 10 00 00 23 00", "jmp 0x23:0x1000"},
		{"66 b8 34 12", "mov ax, 0x1234"},
		{"66 83 c0 01", "add ax, 0x1"},
		{"66 05 34 12", "add ax, 0x1234"},
		{"66 c7 00 34 12", "mov word ptr [eax], 0x1234"},
		{"67 8b 00", "mov eax, dword ptr [bx+si]"},
		{"67 8b 40 02", "mov eax, dword ptr [bx+si+0x2]"},
		{"67 8b 46 02", "mov eax, dword ptr [bp+0x2]"},
		{"67 8b 06 34 12", "mov eax, dword ptr [0x1234]"},
		{"67 8b 86 34 12", "mov eax, dword ptr [bp+0x1234]"},
		{"67 8b 07", "mov eax, dword ptr [bx]"},
		{"e3 00", "jecxz 0x1002"},
		{"67 e3 00", "jcxz 0x1003"},
		{"0f 84 00 00 00 00", "je 0x1006"},
		{"0f 05", "syscall"},
		{"0f a2", "cpuid"},
		{"0f 1f 44 00 00", "nop dword ptr [eax+eax*1+0x0]"},
		{"0f b6 c1", "movzx eax, cl"},
		{"0f b6 c5", "movzx eax, ch"},
		{"88 e0", "mov al, ah"},
		{"f3 a5", "rep movs dword ptr [edi], dword ptr [esi]"},
		{"66 f3 a5", "rep movs word ptr [edi], word ptr [esi]"},
		{"f3 ab", "rep stos dword ptr [edi], eax"},
		{"0f 28 c1", "movaps xmm0, xmm1"},
		{"66 0f ef c0", "pxor xmm0, xmm0"},
		{"f3 0f 7e c1", "movq xmm0, xmm1"},
		{"c5 f8 77", "vzeroupper"},
		{"c5 fd 6f 00", "vmovdqa ymm0, ymmword ptr [eax]"},
		{"c4 e2 7d 78 c0", "vpbroadcastb ymm0, xmm0"},
		{"62 f1 7c 48 10 00", "evex 0f.np.10"},
		{"0f 20 c0", "mov eax, cr0"},
		{"0f 22 d8", "mov cr3, eax"},
		{"f0 0f b1 0a", "lock cmpxchg dword ptr [edx], ecx"},
		{"cf", "iretd"},
		{"66 cf", "iretw"},
		{"9c", "pushfd"},
		{"66 9c", "pushfw"},
		{"9d", "popfd"},
		{"ff 30", "push dword ptr [eax]"},
		{"66 ff 30", "push word ptr [eax]"},
		{"0f 01 d0", "xgetbv"},
	})
}

func TestDecodeX87(t *testing.T) {
	registerForms := []decodeCase{
		{"d9 ee", "fldz"},
		{"d9 e8", "fld1"},
		{"d9 eb", "fldpi"},
		{"d9 e0", "fchs"},
		{"d9 e1", "fabs"},
		{"d9 fa", "fsqrt"},
		{"d9 c0", "fld st(0)"},
		{"d9 c9", "fxch st(1)"},
		{"d9 d0", "fnop"},
		{"d8 c1", "fadd st, st(1)"},
		{"d8 c9", "fmul st, st(1)"},
		{"d8 d1", "fcom st(1)"},
		{"d8 e1", "fsub st, st(1)"},
		{"d8 f9", "fdivr st, st(1)"},
		{"dc c1", "fadd st(1), st"},
		{"dc e9", "fsub st(1), st"},
		{"dc e1", "fsubr st(1), st"},
		{"de c1", "faddp st(1), st"},
		{"de c9", "fmulp st(1), st"},
		{"de e9", "fsubp st(1), st"},
		{"de f9", "fdivp st(1), st"},
		{"de d9", "fcompp"},
		{"da e9", "fucompp"},
		{"dd d8", "fstp st(0)"},
		{"dd d9", "fstp st(1)"},
		{"dd c0", "ffree st(0)"},
		{"db e3", "fninit"},
		{"db e2", "fnclex"},
		{"db e9", "fucomi st, st(1)"},
		{"db f1", "fcomi st, st(1)"},
		{"df e9", "fucomip st, st(1)"},
		{"df f1", "fcomip st, st(1)"},
		{"df e0", "fnstsw ax"},
		{"da c1", "fcmovb st, st(1)"},
		{"db c1", "fcmovnb st, st(1)"},
	}
	memoryForms := []decodeCase{
		{"d9 00", "fld dword ptr [rax]"},
		{"d9 18", "fstp dword ptr [rax]"},
		{"d9 28", "fldcw word ptr [rax]"},
		{"d9 38", "fnstcw word ptr [rax]"},
		{"dd 00", "fld qword ptr [rax]"},
		{"dd 18", "fstp qword ptr [rax]"},
		{"db 28", "fld tbyte ptr [rax]"},
		{"db 38", "fstp tbyte ptr [rax]"},
		{"db 00", "fild dword ptr [rax]"},
		{"df 28", "fild qword ptr [rax]"},
		{"df 00", "fild word ptr [rax]"},
		{"df 38", "fistp qword ptr [rax]"},
		{"d8 00", "fadd dword ptr [rax]"},
		{"dc 08", "fmul qword ptr [rax]"},
		{"da 00", "fiadd dword ptr [rax]"},
		{"de 08", "fimul word ptr [rax]"},
		{"dd 38", "fnstsw word ptr [rax]"},
		{"d9 30", "fnstenv [rax]"},
	}
	t.Run("64", func(t *testing.T) { runCases(t, Mode64, append(registerForms, memoryForms...)) })
	t.Run("32", func(t *testing.T) {
		runCases(t, Mode32, append([]decodeCase{
			{"d9 05 00 30 40 00", "fld dword ptr [0x403000]"},
			{"db 2d 00 20 40 00", "fld tbyte ptr [0x402000]"},
			{"d9 5d fc", "fstp dword ptr [ebp-0x4]"},
			{"dd 45 f8", "fld qword ptr [ebp-0x8]"},
			{"d9 00", "fld dword ptr [eax]"},
		}, registerForms...))
	})
}

// TestDecodeInvalid covers bytes that are not an instruction: truncation, the
// 15-byte limit, opcodes that do not exist and opcodes that are invalid in a mode.
func TestDecodeInvalid(t *testing.T) {
	type tc struct {
		mode Mode
		hex  string
		want string
	}
	cases := []tc{
		// truncated at the end of the input
		{Mode64, "48 8b", "db 0x48"},
		{Mode64, "48", "db 0x48"},
		{Mode64, "e8 00 00", "db 0xe8"},
		{Mode64, "e8", "db 0xe8"},
		{Mode64, "0f", "db 0x0f"},
		{Mode64, "0f 38", "db 0x0f"},
		{Mode64, "0f 3a 0f c1", "db 0x0f"},
		{Mode64, "ff 15 b7 1f", "db 0xff"},
		{Mode64, "8b 84 24 00", "db 0x8b"},
		{Mode64, "48 b8 88 77 66 55 44 33 22", "db 0x48"},
		{Mode64, "c7 45 fc 00 00 00", "db 0xc7"},
		{Mode64, "c5", "db 0xc5"},
		{Mode64, "c5 f8", "db 0xc5"},
		{Mode64, "c4 e2 7d", "db 0xc4"},
		{Mode64, "62 f1 7c", "db 0x62"},
		{Mode32, "ff 15 00 30 40", "db 0xff"},
		{Mode32, "67 8b 06 34", "db 0x67"},
		// prefix-only input
		{Mode64, "66", "db 0x66"},
		{Mode64, "f3", "db 0xf3"},
		{Mode64, "f0", "db 0xf0"},
		{Mode64, "2e 66 67", "db 0x2e"},
		{Mode64, "66 66 66 66", "db 0x66"},
		// invalid in 64-bit mode
		{Mode64, "06", "db 0x06"},
		{Mode64, "07", "db 0x07"},
		{Mode64, "0e", "db 0x0e"},
		{Mode64, "16", "db 0x16"},
		{Mode64, "1f", "db 0x1f"},
		{Mode64, "27", "db 0x27"},
		{Mode64, "2f", "db 0x2f"},
		{Mode64, "37", "db 0x37"},
		{Mode64, "3f", "db 0x3f"},
		{Mode64, "60", "db 0x60"},
		{Mode64, "61", "db 0x61"},
		{Mode64, "82 c0 01", "db 0x82"},
		{Mode64, "9a 00 00 00 00 00 00", "db 0x9a"},
		{Mode64, "ce", "db 0xce"},
		{Mode64, "d4 0a", "db 0xd4"},
		{Mode64, "d5 0a", "db 0xd5"},
		{Mode64, "d6", "db 0xd6"},
		{Mode64, "ea 00 00 00 00 00 00", "db 0xea"},
		// opcodes that are not instructions
		{Mode64, "0f 04", "db 0x0f"},
		{Mode64, "0f 0a", "db 0x0f"},
		{Mode64, "0f 24 c0", "db 0x0f"},
		{Mode64, "0f 36", "db 0x0f"},
		{Mode64, "0f 38 ff c0", "db 0x0f"},
		{Mode64, "0f 3a ff c0 00", "db 0x0f"},
		{Mode64, "0f 7a c0", "db 0x0f"},
		{Mode64, "0f 0f c0 00", "db 0x0f"},
		{Mode64, "8f c8", "db 0x8f"},
		{Mode64, "c6 c8 00", "db 0xc6"},
		{Mode64, "fe d0", "db 0xfe"},
		{Mode64, "ff f8", "db 0xff"},
		{Mode64, "8d c0", "db 0x8d"},
		{Mode64, "8e f0", "db 0x8e"},
		{Mode64, "0f 01 c0", "db 0x0f"},
		{Mode64, "d9 d1", "db 0xd9"},
		{Mode64, "db e4", "db 0xdb"},
		{Mode64, "0f c7 c8", "db 0x0f"},
		{Mode64, "0f b8 c1", "db 0x0f"},
		{Mode64, "66 0f 10", "db 0x66"},
		{Mode64, "0f 13 c1", "db 0x0f"},
		{Mode64, "0f ae c0", "db 0x0f"},
		// VEX and EVEX prefixed by something that is undefined
		{Mode64, "66 c5 f8 77", "db 0x66"},
		{Mode64, "48 c5 f8 77", "db 0x48"},
		{Mode64, "f3 c5 f8 77", "db 0xf3"},
		{Mode64, "c4 e0 7d 78 c0", "db 0xc4"},
		{Mode64, "62 00 00 00 00 00", "db 0x62"},
		{Mode64, "62 f1 78 48 10 00", "db 0x62"},
	}
	for _, c := range cases {
		code := mustHex(t, c.hex)
		in := Decode(c.mode, code, testAddr)
		if in.Text != c.want {
			t.Errorf("Decode(%d, % x) = %q (len %d), want %q", c.mode, code, in.Text, in.Len, c.want)
			continue
		}
		checkInvariants(t, code, in)
		if strings.HasPrefix(c.want, "db ") && (in.Valid || in.Len != 1) {
			t.Errorf("Decode(%d, % x): db fallback must be invalid with Len 1: %+v", c.mode, code, in)
		}
	}

	if in := Decode(Mode64, nil, testAddr); in.Len != 0 || in.Text != "" || in.Valid {
		t.Errorf("Decode(nil) = %+v, want the zero Inst", in)
	}
	if in := Decode(Mode64, []byte{}, testAddr); in.Len != 0 || in.Text != "" {
		t.Errorf("Decode(empty) = %+v, want the zero Inst", in)
	}
}

func TestDecodeFifteenByteLimit(t *testing.T) {
	// fourteen prefixes and a nop are exactly fifteen bytes: valid
	code := append(bytes.Repeat([]byte{0x66}, 14), 0x90)
	in := Decode(Mode64, code, testAddr)
	if !in.Valid || in.Len != 15 || in.Text != "nop" {
		t.Errorf("14 prefixes + nop = %+v", in)
	}
	// one more prefix makes it sixteen: invalid, and decoding resumes at the next byte
	code = append(bytes.Repeat([]byte{0x66}, 15), 0x90)
	in = Decode(Mode64, code, testAddr)
	if in.Valid || in.Len != 1 || in.Text != "db 0x66" {
		t.Errorf("15 prefixes + nop = %+v", in)
	}
	// a long instruction whose operand would end past byte fifteen
	code = append(bytes.Repeat([]byte{0x2e}, 8), mustHex(t, "64 48 8b 04 25 28 00 00 00")...)
	in = Decode(Mode64, code, testAddr)
	if in.Valid || in.Len != 1 {
		t.Errorf("17-byte instruction = %+v", in)
	}
	// exactly fifteen: ten segment prefixes and a five-byte instruction (mov eax, imm32)
	code = append(bytes.Repeat([]byte{0x2e}, 10), mustHex(t, "b8 01 00 00 00")...)
	in = Decode(Mode64, code, testAddr)
	if !in.Valid || in.Len != 15 || in.Text != "mov eax, 0x1" {
		t.Errorf("15-byte instruction = %+v", in)
	}
	// extra input after the instruction is never consumed
	code = append(code, 0x90, 0x90)
	if in = Decode(Mode64, code, testAddr); in.Len != 15 {
		t.Errorf("Len = %d with trailing bytes", in.Len)
	}
}

func TestInstFields(t *testing.T) {
	t.Run("indirect call through the IAT", func(t *testing.T) {
		in := Decode(Mode64, mustHex(t, "ff 15 b7 1f 00 00"), 0x140001042)
		if in.Flow != FlowCall || !in.Indirect || in.HasTarget || !in.HasRipRef || in.HasAbsRef {
			t.Errorf("flags wrong: %+v", in)
		}
		if want := uint64(0x140001042 + 6 + 0x1fb7); in.RipRef != want {
			t.Errorf("RipRef = %#x, want %#x", in.RipRef, want)
		}
		if in.Text != "call qword ptr [rip+0x1fb7]" || in.Mnemonic != "call" || in.Operands != "qword ptr [rip+0x1fb7]" {
			t.Errorf("text wrong: %+v", in)
		}
	})
	t.Run("rip-relative lea counts the whole instruction", func(t *testing.T) {
		in := Decode(Mode64, mustHex(t, "48 8d 0d b7 1f 00 00"), 0x140001000)
		if !in.HasRipRef || in.RipRef != 0x140001000+7+0x1fb7 || in.Flow != FlowNone {
			t.Errorf("%+v", in)
		}
	})
	t.Run("rip-relative with an immediate after the displacement", func(t *testing.T) {
		// cmp dword ptr [rip+0x10], 0x5: the target is relative to the end of the immediate
		in := Decode(Mode64, mustHex(t, "83 3d 10 00 00 00 05"), 0x1000)
		if !in.HasRipRef || in.RipRef != 0x1000+7+0x10 || in.Text != "cmp dword ptr [rip+0x10], 0x5" {
			t.Errorf("%+v", in)
		}
	})
	t.Run("negative rip displacement", func(t *testing.T) {
		in := Decode(Mode64, mustHex(t, "48 8b 05 f9 ff ff ff"), 0x1000)
		if !in.HasRipRef || in.RipRef != 0x1000 {
			t.Errorf("%+v", in)
		}
	})
	t.Run("address-size prefix truncates the rip target", func(t *testing.T) {
		in := Decode(Mode64, mustHex(t, "67 8b 05 00 00 00 00"), 0x1_0000_1000)
		if !in.HasRipRef || in.RipRef != 0x1007 || in.Text != "mov eax, dword ptr [eip+0x0]" {
			t.Errorf("%+v", in)
		}
	})
	t.Run("direct call", func(t *testing.T) {
		in := Decode(Mode64, mustHex(t, "e8 fb 0f 00 00"), 0x1000)
		if in.Flow != FlowCall || in.Indirect || !in.HasTarget || in.Target != 0x2000 || in.HasRipRef {
			t.Errorf("%+v", in)
		}
	})
	t.Run("backward jump wraps at 64 bits", func(t *testing.T) {
		in := Decode(Mode64, mustHex(t, "e9 00 00 00 80"), 0x10)
		if !in.HasTarget || in.Target != 0x10+5-0x80000000+(1<<64) {
			t.Errorf("target %#x", in.Target)
		}
	})
	t.Run("32-bit targets wrap at 32 bits", func(t *testing.T) {
		in := Decode(Mode32, mustHex(t, "e9 00 00 00 80"), 0x10)
		if !in.HasTarget || in.Target != 0x80000015 {
			t.Errorf("target %#x", in.Target)
		}
		in = Decode(Mode32, mustHex(t, "e9 f0 ff ff ff"), 0x4)
		if !in.HasTarget || in.Target != 0xfffffff9 {
			t.Errorf("target %#x", in.Target)
		}
	})
	t.Run("indirect jump through a register", func(t *testing.T) {
		in := Decode(Mode64, mustHex(t, "ff e0"), 0x1000)
		if in.Flow != FlowJump || !in.Indirect || in.HasTarget || in.HasRipRef {
			t.Errorf("%+v", in)
		}
	})
	t.Run("jmp thunk through the IAT", func(t *testing.T) {
		in := Decode(Mode64, mustHex(t, "ff 25 b7 1f 00 00"), 0x1000)
		if in.Flow != FlowJump || !in.Indirect || !in.HasRipRef || in.RipRef != 0x1006+0x1fb7 {
			t.Errorf("%+v", in)
		}
	})
	t.Run("conditional jump", func(t *testing.T) {
		in := Decode(Mode64, mustHex(t, "74 05"), 0x1000)
		if in.Flow != FlowCondJump || !in.HasTarget || in.Target != 0x1007 || in.Indirect {
			t.Errorf("%+v", in)
		}
		in = Decode(Mode64, mustHex(t, "0f 85 00 01 00 00"), 0x1000)
		if in.Flow != FlowCondJump || in.Target != 0x1106 {
			t.Errorf("%+v", in)
		}
		in = Decode(Mode64, mustHex(t, "e2 fe"), 0x1000)
		if in.Flow != FlowCondJump || in.Target != 0x1000 {
			t.Errorf("%+v", in)
		}
	})
	t.Run("absolute operand in 32-bit mode", func(t *testing.T) {
		in := Decode(Mode32, mustHex(t, "ff 15 00 30 40 00"), 0x1000)
		if in.Flow != FlowCall || !in.Indirect || !in.HasAbsRef || in.AbsRef != 0x403000 || in.HasRipRef {
			t.Errorf("%+v", in)
		}
		in = Decode(Mode32, mustHex(t, "a1 00 30 40 00"), 0x1000)
		if !in.HasAbsRef || in.AbsRef != 0x403000 {
			t.Errorf("moffs: %+v", in)
		}
	})
	t.Run("absolute operand through SIB in 64-bit mode", func(t *testing.T) {
		in := Decode(Mode64, mustHex(t, "ff 14 25 18 40 40 00"), 0x1000)
		if !in.HasAbsRef || in.AbsRef != 0x404018 || in.HasRipRef {
			t.Errorf("%+v", in)
		}
	})
	t.Run("segment-relative offsets are not addresses", func(t *testing.T) {
		in := Decode(Mode64, mustHex(t, "64 48 8b 04 25 28 00 00 00"), 0x1000)
		if in.HasAbsRef || in.HasRipRef {
			t.Errorf("%+v", in)
		}
	})
	t.Run("no reference for register-based memory", func(t *testing.T) {
		in := Decode(Mode64, mustHex(t, "ff 10"), 0x1000)
		if in.HasAbsRef || in.HasRipRef || !in.Indirect {
			t.Errorf("%+v", in)
		}
	})
	t.Run("flow classes", func(t *testing.T) {
		for _, c := range []struct {
			hex  string
			flow Flow
		}{
			{"c3", FlowRet}, {"c2 04 00", FlowRet}, {"cb", FlowRet}, {"cf", FlowRet}, {"f3 c3", FlowRet},
			{"cc", FlowTrap}, {"cd 2e", FlowTrap}, {"0f 0b", FlowTrap}, {"f4", FlowTrap},
			{"90", FlowNone}, {"0f 05", FlowNone}, {"48 89 e5", FlowNone},
			{"ff d0", FlowCall}, {"ff e0", FlowJump}, {"eb 00", FlowJump}, {"e3 00", FlowCondJump},
		} {
			if in := Decode(Mode64, mustHex(t, c.hex), 0); in.Flow != c.flow {
				t.Errorf("%s: Flow = %v, want %v", c.hex, in.Flow, c.flow)
			}
		}
	})
	t.Run("Bytes is a capacity-limited sub-slice of the input", func(t *testing.T) {
		code := mustHex(t, "48 89 e5 90 90")
		in := Decode(Mode64, code, 0)
		if len(in.Bytes) != 3 || cap(in.Bytes) != 3 || &in.Bytes[0] != &code[0] {
			t.Errorf("Bytes %v len %d cap %d", in.Bytes, len(in.Bytes), cap(in.Bytes))
		}
	})
	t.Run("an unknown mode decodes as 64-bit", func(t *testing.T) {
		if in := Decode(Mode(0), mustHex(t, "48 89 e5"), 0); in.Text != "mov rbp, rsp" {
			t.Errorf("%+v", in)
		}
	})
	t.Run("Flow strings", func(t *testing.T) {
		for f, want := range map[Flow]string{FlowNone: "none", FlowCall: "call", FlowJump: "jump", FlowCondJump: "condjump", FlowRet: "ret", FlowTrap: "trap", Flow(99): "unknown"} {
			if f.String() != want {
				t.Errorf("Flow(%d) = %q, want %q", f, f.String(), want)
			}
		}
	})
}

func TestDecodeAll(t *testing.T) {
	prologue := mustHex(t, "55 48 89 e5 48 83 ec 20 31 c0 e8 00 00 00 00 c9 c3")
	insts := DecodeAll(Mode64, prologue, 0x1000, 0)
	want := []string{"push rbp", "mov rbp, rsp", "sub rsp, 0x20", "xor eax, eax", "call 0x100f", "leave", "ret"}
	if len(insts) != len(want) {
		t.Fatalf("got %d instructions, want %d: %v", len(insts), len(want), insts)
	}
	addr := uint64(0x1000)
	total := 0
	for i, in := range insts {
		if in.Text != want[i] || in.Addr != addr {
			t.Errorf("instruction %d = %q at %#x, want %q at %#x", i, in.Text, in.Addr, want[i], addr)
		}
		addr += uint64(in.Len)
		total += in.Len
	}
	if total != len(prologue) {
		t.Errorf("instructions cover %d of %d bytes", total, len(prologue))
	}

	if got := DecodeAll(Mode64, prologue, 0x1000, 3); len(got) != 3 || got[2].Text != "sub rsp, 0x20" {
		t.Errorf("max 3 gave %v", got)
	}
	if got := DecodeAll(Mode64, nil, 0, 0); len(got) != 0 {
		t.Errorf("nil input gave %v", got)
	}
	if got := DecodeAll(Mode64, prologue, 0, -5); len(got) != len(want) {
		t.Errorf("negative max gave %d instructions", len(got))
	}

	// resynchronisation: an invalid byte becomes db and decoding goes on
	mixed := mustHex(t, "90 06 90 e8 00 90 c3")
	got := DecodeAll(Mode64, mixed, 0, 0)
	var texts []string
	for _, in := range got {
		texts = append(texts, in.Text)
	}
	// e8 00 90 c3 is a call cut short by the end of the input, and so is 00 90 c3
	if want := "nop; db 0x06; nop; db 0xe8; db 0x00; nop; ret"; strings.Join(texts, "; ") != want {
		t.Errorf("mixed = %v, want %s", texts, want)
	}

	// the hard cap bounds the result whatever max says
	big := bytes.Repeat([]byte{0x90}, MaxInstructions+100)
	if got := DecodeAll(Mode64, big, 0, 0); len(got) != MaxInstructions {
		t.Errorf("default cap: %d instructions", len(got))
	}
	if got := DecodeAll(Mode64, big, 0, 1<<30); len(got) != MaxInstructions {
		t.Errorf("explicit huge max: %d instructions", len(got))
	}
}
