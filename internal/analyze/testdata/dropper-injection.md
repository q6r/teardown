# teardown report: `dropper.bin`

> Static analysis only; the file was never executed.

| | |
|---|---|
| Type | PE32+ executable for Windows (x86-64, console) (high confidence) |
| Tags | `64-bit` `exe` `x86-64` |
| Size | 18.8 KiB (19,200 bytes) |
| Risk | **14/100 low** |
| Entropy | 0.00 of 8.00 bits per byte |
| Generated | 2026-11-10 12:00:00Z by teardown 0.2.0 in 0 ms |

## Findings (1)

### [HIGH] `imports.process-injection`: Imports cover the full process-injection chain (allocate, write, execute)

Confidence: **medium** · category: imports

Evidence:

- allocate or map memory in another process: KERNEL32.dll!VirtualAllocEx
- write to another process: KERNEL32.dll!WriteProcessMemory
- start or hijack a thread there: KERNEL32.dll!CreateRemoteThread
- process handle: KERNEL32.dll!OpenProcess
- code: 4 call sites in .text (see the code blocks)

Code:

#### Code: call to KERNEL32.dll!VirtualAllocEx in .text

.text · 0x1400010bd · x86-64

```asm
  0x1400010bd  41 b8 a4 01 00 00        mov r8d, 0x1a4
  0x1400010c3  ff 15 ef 10 00 00        call qword ptr [rip+0x10ef]  ; KERNEL32.dll!OpenProcess
  0x1400010c9  48 89 44 24 48           mov qword ptr [rsp+0x48], rax
  0x1400010ce  48 8b 4c 24 48           mov rcx, qword ptr [rsp+0x48]
  0x1400010d3  31 d2                    xor edx, edx
  0x1400010d5  41 b8 00 10 00 00        mov r8d, 0x1000
  0x1400010db  41 b9 00 30 00 00        mov r9d, 0x3000
  0x1400010e1  c7 44 24 20 40 00 00 00  mov dword ptr [rsp+0x20], 0x40
> 0x1400010e9  ff 15 b1 10 00 00        call qword ptr [rip+0x10b1]  ; KERNEL32.dll!VirtualAllocEx
  0x1400010ef  48 89 44 24 50           mov qword ptr [rsp+0x50], rax
  0x1400010f4  48 8b 4c 24 48           mov rcx, qword ptr [rsp+0x48]
  0x1400010f9  48 8b 54 24 50           mov rdx, qword ptr [rsp+0x50]
  0x1400010fe  4c 8d 05 fb 1e 00 00     lea r8, [rip+0x1efb]  ; 0x140003000 in .data
```

#### Code: call to KERNEL32.dll!WriteProcessMemory in .text

.text · 0x1400010e1 · x86-64

```asm
  0x1400010e1  c7 44 24 20 40 00 00 00     mov dword ptr [rsp+0x20], 0x40
  0x1400010e9  ff 15 b1 10 00 00           call qword ptr [rip+0x10b1]  ; KERNEL32.dll!VirtualAllocEx
  0x1400010ef  48 89 44 24 50              mov qword ptr [rsp+0x50], rax
  0x1400010f4  48 8b 4c 24 48              mov rcx, qword ptr [rsp+0x48]
  0x1400010f9  48 8b 54 24 50              mov rdx, qword ptr [rsp+0x50]
  0x1400010fe  4c 8d 05 fb 1e 00 00        lea r8, [rip+0x1efb]  ; 0x140003000 in .data
  0x140001105  41 b9 00 02 00 00           mov r9d, 0x200
  0x14000110b  48 c7 44 24 20 00 00 00 00  mov qword ptr [rsp+0x20], 0x0
> 0x140001114  ff 15 8e 10 00 00           call qword ptr [rip+0x108e]  ; KERNEL32.dll!WriteProcessMemory
  0x14000111a  48 8b 4c 24 48              mov rcx, qword ptr [rsp+0x48]
  0x14000111f  31 d2                       xor edx, edx
  0x140001121  45 31 c0                    xor r8d, r8d
  0x140001124  4c 8b 4c 24 50              mov r9, qword ptr [rsp+0x50]
```

#### Code: call to KERNEL32.dll!CreateRemoteThread in .text

.text · 0x140001114 · x86-64

```asm
  0x140001114  ff 15 8e 10 00 00           call qword ptr [rip+0x108e]  ; KERNEL32.dll!WriteProcessMemory
  0x14000111a  48 8b 4c 24 48              mov rcx, qword ptr [rsp+0x48]
  0x14000111f  31 d2                       xor edx, edx
  0x140001121  45 31 c0                    xor r8d, r8d
  0x140001124  4c 8b 4c 24 50              mov r9, qword ptr [rsp+0x50]
  0x140001129  48 c7 44 24 20 00 00 00 00  mov qword ptr [rsp+0x20], 0x0
  0x140001132  48 c7 44 24 28 00 00 00 00  mov qword ptr [rsp+0x28], 0x0
  0x14000113b  48 c7 44 24 30 00 00 00 00  mov qword ptr [rsp+0x30], 0x0
> 0x140001144  ff 15 66 10 00 00           call qword ptr [rip+0x1066]  ; KERNEL32.dll!CreateRemoteThread
  0x14000114a  48 8b 4c 24 40              mov rcx, qword ptr [rsp+0x40]
  0x14000114f  48 8d 15 ba 1e 00 00        lea rdx, [rip+0x1eba]  ; 0x140003010 in .data
  0x140001156  ff 15 34 10 00 00           call qword ptr [rip+0x1034]  ; KERNEL32.dll!GetProcAddress
  0x14000115c  31 c9                       xor ecx, ecx
```

#### Code: call to KERNEL32.dll!OpenProcess in .text

.text · 0x140001095 · x86-64

```asm
  0x140001095  48 c7 44 24 20 00 00 00 00  mov qword ptr [rsp+0x20], 0x0
  0x14000109e  ff 15 1c 13 00 00           call qword ptr [rip+0x131c]  ; URLMON.dll!URLDownloadToFileA
  0x1400010a4  48 8d 0d 55 1f 00 00        lea rcx, [rip+0x1f55]  ; 0x140003000 in .data
  0x1400010ab  ff 15 e7 10 00 00           call qword ptr [rip+0x10e7]  ; KERNEL32.dll!LoadLibraryA
  0x1400010b1  48 89 44 24 40              mov qword ptr [rsp+0x40], rax
  0x1400010b6  b9 ff ff 1f 00              mov ecx, 0x1fffff
  0x1400010bb  31 d2                       xor edx, edx
  0x1400010bd  41 b8 a4 01 00 00           mov r8d, 0x1a4
> 0x1400010c3  ff 15 ef 10 00 00           call qword ptr [rip+0x10ef]  ; KERNEL32.dll!OpenProcess
  0x1400010c9  48 89 44 24 48              mov qword ptr [rsp+0x48], rax
  0x1400010ce  48 8b 4c 24 48              mov rcx, qword ptr [rsp+0x48]
  0x1400010d3  31 d2                       xor edx, edx
  0x1400010d5  41 b8 00 10 00 00           mov r8d, 0x1000
```

Limitations of the code shown:

- x86-64 code decoded as a linear sweep (ARM64 and other instruction sets are not supported): data inside a code section can be read as instructions, and one wrong byte shifts what follows.
- Only calls through the import table and import thunks are found: functions resolved at run time are invisible, and packed or protected code hides its real calls.
- A view of the code, not a decompiler, an emulator or a verdict: nothing was executed, and the code shows what is called, not why.

Limitations:

- API presence alone proves nothing: legitimate software (debuggers, installers, security and remote-support tools, games, browsers) imports the same functions.
- Debuggers, profilers, anti-virus and game overlays legitimately use remote memory and thread APIs.
- Functions resolved at run time (GetProcAddress, dlsym) or hidden by a packer are not in the import table, so a missing cluster proves nothing either.

## Risk basis

- +14  imports.process-injection (high severity, medium confidence)

## Hashes

| Algorithm | Digest |
|---|---|
| MD5 | `` |
| SHA-1 | `` |
| SHA-256 | `` |

## Strings

0 strings found (minimum length 0).

## Limitations

- Static analysis only; the file was never executed.
