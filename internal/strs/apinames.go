package strs

import (
	"strings"
	"sync"
)

// Groups of API names, reported as the kind of an "api" string. Each list is
// sorted in byte order and no name appears twice across all lists (a test
// enforces both). Names that exist in ANSI and wide variants are listed once
// without the trailing A or W; the lookup tolerates the suffix.
const (
	groupProcess     = "process"
	groupAntiDebug   = "antidebug"
	groupKeylog      = "keylog"
	groupSurveil     = "surveil"
	groupCrypto      = "crypto"
	groupNetwork     = "network"
	groupService     = "service"
	groupRegistry    = "registry"
	groupFile        = "file"
	groupLoader      = "loader"
	groupExec        = "exec"
	groupPrivilege   = "privilege"
	groupNative      = "native"
	groupSystem      = "system"
	groupCOM         = "com"
	groupCompression = "compression"
)

var apiProcess = []string{
	"CreateProcess", "CreateProcessAsUser", "CreateProcessInternal", "CreateProcessWithLogon",
	"CreateProcessWithToken", "CreateRemoteThread", "CreateRemoteThreadEx", "CreateThread",
	"CreateToolhelp32Snapshot", "EnumProcessModules", "EnumProcesses", "GetModuleFileNameEx",
	"GetThreadContext", "HeapCreate", "MapViewOfFile", "MapViewOfFileEx", "Module32First",
	"Module32Next", "OpenProcess", "OpenThread", "Process32First", "Process32Next", "QueueUserAPC",
	"ReadProcessMemory", "ResumeThread", "SetThreadContext", "SuspendThread", "TerminateProcess",
	"TerminateThread", "Thread32First", "Thread32Next", "UnmapViewOfFile", "VirtualAlloc",
	"VirtualAllocEx", "VirtualAllocExNuma", "VirtualFree", "VirtualFreeEx", "VirtualProtect",
	"VirtualProtectEx", "VirtualQuery", "VirtualQueryEx", "Wow64GetThreadContext",
	"Wow64SetThreadContext", "Wow64SuspendThread", "WriteProcessMemory", "memfd_create", "mprotect",
	"process_vm_readv", "process_vm_writev",
}

var apiAntiDebug = []string{
	"AddVectoredExceptionHandler", "CheckRemoteDebuggerPresent", "ContinueDebugEvent",
	"DebugActiveProcess", "DebugActiveProcessStop", "DebugBreak", "IsDebuggerPresent",
	"NtQueryInformationProcess", "NtSetInformationThread", "OutputDebugString",
	"RtlAddVectoredExceptionHandler", "SetUnhandledExceptionFilter", "UnhandledExceptionFilter",
	"WaitForDebugEvent", "ZwQueryInformationProcess", "ZwSetInformationThread", "ptrace",
}

var apiKeylog = []string{
	"BlockInput", "CallNextHookEx", "GetAsyncKeyState", "GetKeyNameText", "GetKeyState",
	"GetKeyboardState", "GetRawInputData", "MapVirtualKey", "RegisterRawInputDevices", "SendInput",
	"SetWinEventHook", "SetWindowsHookEx", "UnhookWindowsHookEx", "keybd_event", "mouse_event",
}

var apiSurveil = []string{
	"AddClipboardFormatListener", "BitBlt", "CreateCompatibleBitmap", "CreateCompatibleDC",
	"GetClipboardData", "GetDC", "GetDesktopWindow", "GetForegroundWindow", "GetWindowDC",
	"GetWindowText", "OpenClipboard", "PrintWindow", "SetClipboardData", "SetClipboardViewer",
	"StretchBlt", "capGetDriverDescription", "mciSendString", "waveInOpen", "waveInStart",
}

// apiCrypto lists exact crypto names; the BCrypt*, NCrypt*, Crypt* and the
// OpenSSL-style families are matched by prefix (see apiPrefixes).
var apiCrypto = []string{
	"3DES", "AES", "AES-128-CBC", "AES-128-CTR", "AES-128-ECB", "AES-128-GCM", "AES-192-CBC",
	"AES-256-CBC", "AES-256-CTR", "AES-256-ECB", "AES-256-GCM", "AES128", "AES256", "Argon2",
	"Argon2id", "BLAKE2b", "BLAKE2s", "Blowfish", "BoringSSL", "Botan", "BouncyCastle", "Camellia",
	"CertCloseStore", "CertEnumCertificatesInStore", "CertFindCertificateInStore",
	"CertFreeCertificateContext", "CertGetCertificateChain", "CertOpenStore", "CertOpenSystemStore",
	"CertVerifyCertificateChainPolicy", "ChaCha20", "ChaCha20-Poly1305", "Crypto++", "CryptoPP",
	"Curve25519", "DES-EDE3", "ECDH", "ECDHE", "ECDSA", "Ed25519", "GnuTLS", "HMAC", "HMAC-SHA256",
	"LibreSSL", "MD2", "MD4", "MD5", "OpenSSL", "PBKDF2", "Poly1305", "RC2", "RC4", "RC5",
	"RIPEMD160", "RSA", "RSA-OAEP", "RtlGenRandom", "SHA-1", "SHA-256", "SHA-384", "SHA-512",
	"SHA1", "SHA224", "SHA256", "SHA3-256", "SHA384", "SHA512", "Salsa20", "Serpent",
	"SystemFunction032", "SystemFunction036", "Twofish", "X25519", "XSalsa20", "arc4random",
	"arc4random_buf", "bcrypt", "crypt", "crypt_r", "getentropy", "getrandom", "libcrypto",
	"libgcrypt", "libsodium", "libssl", "mbedTLS", "prime256v1", "scrypt", "secp256k1",
	"secp256r1", "wolfSSL",
}

var apiNetwork = []string{
	"DnsQuery", "DnsQueryEx", "DnsQuery_A", "DnsQuery_W", "FtpGetFile", "FtpOpenFile", "FtpPutFile",
	"GetAdaptersAddresses", "GetAdaptersInfo", "GetExtendedTcpTable", "GetExtendedUdpTable",
	"GetIpNetTable", "GetTcpTable", "GetUdpTable", "HttpAddRequestHeaders", "HttpEndRequest",
	"HttpOpenRequest", "HttpQueryInfo", "HttpSendRequest", "HttpSendRequestEx", "IcmpCreateFile",
	"IcmpSendEcho", "NetLocalGroupAddMembers", "NetServerEnum", "NetShareEnum", "NetUserAdd",
	"NetUserEnum", "NetUserGetInfo", "ObtainUserAgentString", "TransmitFile",
	"URLDownloadToCacheFile", "URLDownloadToFile", "URLOpenBlockingStream", "URLOpenStream",
	"WNetAddConnection2", "WNetAddConnection3", "WNetEnumResource", "WNetOpenEnum", "accept",
	"closesocket", "connect", "freeaddrinfo", "getaddrinfo", "gethostbyaddr", "gethostbyname",
	"gethostname", "getnameinfo", "getpeername", "getsockname", "getsockopt", "inet_addr",
	"inet_ntoa", "inet_ntop", "inet_pton", "ioctlsocket", "listen", "recvfrom", "sendto",
	"setsockopt", "socket",
}

var apiService = []string{
	"ChangeServiceConfig", "ChangeServiceConfig2", "CloseServiceHandle", "ControlService",
	"CreateService", "DeleteService", "EnumServicesStatus", "EnumServicesStatusEx",
	"LockServiceDatabase", "NotifyServiceStatusChange", "OpenSCManager", "OpenService",
	"QueryServiceConfig", "QueryServiceStatus", "QueryServiceStatusEx", "RegisterServiceCtrlHandler",
	"RegisterServiceCtrlHandlerEx", "SetServiceStatus", "StartService", "StartServiceCtrlDispatcher",
}

var apiRegistry = []string{
	"RegCloseKey", "RegConnectRegistry", "RegCreateKey", "RegCreateKeyEx", "RegDeleteKey",
	"RegDeleteKeyEx", "RegDeleteKeyValue", "RegDeleteValue", "RegEnumKey", "RegEnumKeyEx",
	"RegEnumValue", "RegFlushKey", "RegGetValue", "RegLoadKey", "RegNotifyChangeKeyValue",
	"RegOpenKey", "RegOpenKeyEx", "RegQueryInfoKey", "RegQueryValue", "RegQueryValueEx",
	"RegRestoreKey", "RegSaveKey", "RegSetKeyValue", "RegSetValue", "RegSetValueEx", "SHDeleteKey",
	"SHDeleteValue", "SHEnumKeyEx", "SHGetValue", "SHSetValue",
}

var apiFile = []string{
	"CopyFile", "CopyFileEx", "CreateDirectory", "CreateFile", "CreateHardLink",
	"CreateSymbolicLink", "DeleteFile", "DeviceIoControl", "FindClose", "FindFirstFile",
	"FindFirstFileEx", "FindNextFile", "FlushFileBuffers", "GetDiskFreeSpace", "GetDriveType",
	"GetFileAttributes", "GetFileSize", "GetFileSizeEx", "GetLogicalDriveStrings",
	"GetLogicalDrives", "GetSystemDirectory", "GetSystemWow64Directory", "GetTempFileName",
	"GetTempPath", "GetVolumeInformation", "GetWindowsDirectory", "MoveFile", "MoveFileEx",
	"ReadFile", "RemoveDirectory", "ReplaceFile", "SHFileOperation", "SHGetFolderPath",
	"SHGetSpecialFolderPath", "SetFileAttributes", "SetFilePointer", "SetFilePointerEx",
	"WriteFile", "opendir", "readdir", "readlink", "realpath", "unlink",
}

var apiLoader = []string{
	"AddDllDirectory", "FindResource", "FindResourceEx", "FreeLibrary", "GetModuleFileName",
	"GetModuleHandle", "GetModuleHandleEx", "GetProcAddress", "LdrGetDllHandle",
	"LdrGetProcedureAddress", "LdrLoadDll", "LdrUnloadDll", "LoadLibrary", "LoadLibraryEx",
	"LoadResource", "LockResource", "SetDefaultDllDirectories", "SetDllDirectory", "SizeofResource",
	"dladdr", "dlclose", "dlerror", "dlopen", "dlsym",
}

var apiExec = []string{
	"ExitWindowsEx", "InitiateSystemShutdown", "ShellExecute", "ShellExecuteEx", "WinExec",
	"_popen", "_wsystem", "chroot", "execl", "execle", "execlp", "execv", "execve", "execvp",
	"execvpe", "popen", "posix_spawn", "posix_spawnp", "prctl", "seteuid", "setgid", "setresuid",
	"setreuid", "setuid", "syscall", "system", "unshare", "vfork",
}

var apiPrivilege = []string{
	"AdjustTokenPrivileges", "CheckTokenMembership", "DuplicateToken", "DuplicateTokenEx",
	"GetTokenInformation", "ImpersonateLoggedOnUser", "ImpersonateNamedPipeClient",
	"ImpersonateSelf", "IsUserAnAdmin", "LogonUser", "LogonUserEx", "LookupPrivilegeValue",
	"OpenProcessToken", "OpenThreadToken", "RevertToSelf", "SeAssignPrimaryTokenPrivilege",
	"SeBackupPrivilege", "SeCreateTokenPrivilege", "SeDebugPrivilege", "SeImpersonatePrivilege",
	"SeLoadDriverPrivilege", "SeRestorePrivilege", "SeShutdownPrivilege", "SeTakeOwnershipPrivilege",
	"SeTcbPrivilege", "SetThreadToken", "SetTokenInformation",
}

var apiNative = []string{
	"NtAdjustPrivilegesToken", "NtAllocateVirtualMemory", "NtClose", "NtCreateFile", "NtCreateKey",
	"NtCreateMutant", "NtCreateProcess", "NtCreateProcessEx", "NtCreateSection", "NtCreateThread",
	"NtCreateThreadEx", "NtCreateUserProcess", "NtDelayExecution", "NtDeleteKey", "NtDeleteValueKey",
	"NtDeviceIoControlFile", "NtDuplicateObject", "NtEnumerateKey", "NtFreeVirtualMemory",
	"NtGetContextThread", "NtLoadDriver", "NtMapViewOfSection", "NtOpenFile", "NtOpenKey",
	"NtOpenProcess", "NtOpenProcessToken", "NtOpenThread", "NtOpenThreadToken",
	"NtProtectVirtualMemory", "NtQueryInformationThread", "NtQueryObject",
	"NtQuerySystemInformation", "NtQueryValueKey", "NtQueryVirtualMemory", "NtQueueApcThread",
	"NtRaiseHardError", "NtReadFile", "NtReadVirtualMemory", "NtResumeProcess", "NtResumeThread",
	"NtSetContextThread", "NtSetInformationProcess", "NtSetSystemInformation", "NtSetValueKey",
	"NtShutdownSystem", "NtSuspendProcess", "NtSuspendThread", "NtTerminateProcess",
	"NtUnloadDriver", "NtUnmapViewOfSection", "NtWriteFile", "NtWriteVirtualMemory",
	"RtlAdjustPrivilege", "RtlCompressBuffer", "RtlCopyMemory", "RtlCreateProcessParameters",
	"RtlCreateProcessParametersEx", "RtlCreateUserThread", "RtlDecompressBuffer",
	"RtlExitUserThread", "RtlGetVersion", "RtlInitUnicodeString", "RtlMoveMemory",
	"RtlSetProcessIsCritical", "RtlSetThreadIsCritical", "RtlZeroMemory", "ZwAllocateVirtualMemory",
	"ZwClose", "ZwCreateFile", "ZwCreateSection", "ZwCreateThreadEx", "ZwLoadDriver",
	"ZwMapViewOfSection", "ZwOpenProcess", "ZwProtectVirtualMemory", "ZwQuerySystemInformation",
	"ZwReadVirtualMemory", "ZwSetValueKey", "ZwTerminateProcess", "ZwUnloadDriver",
	"ZwUnmapViewOfSection", "ZwWriteVirtualMemory",
}

var apiSystem = []string{
	"CloseHandle", "ConnectNamedPipe", "CreateEvent", "CreateMailslot", "CreateMutex",
	"CreateNamedPipe", "DuplicateHandle", "EnumDisplayDevices", "EnumWindows", "ExitProcess",
	"FindWindow", "FindWindowEx", "FormatMessage", "GetCommandLine", "GetComputerName",
	"GetCurrentProcess", "GetCurrentProcessId", "GetCurrentThread", "GetCurrentThreadId",
	"GetCursorPos", "GetEnvironmentVariable", "GetKeyboardLayout", "GetLastError", "GetLocaleInfo",
	"GetNativeSystemInfo", "GetStartupInfo", "GetSystemInfo", "GetSystemMetrics", "GetSystemTime",
	"GetTickCount", "GetTimeZoneInformation", "GetUserDefaultLangID", "GetUserName", "GetVersion",
	"GetVersionEx", "GetWindowThreadProcessId", "GlobalMemoryStatusEx", "MessageBox", "OpenMutex",
	"QueryPerformanceCounter", "SetEnvironmentVariable", "SetLastError", "WaitForMultipleObjects",
	"WaitForSingleObject", "getenv", "getpwnam", "getpwuid", "setenv", "uname",
}

var apiCOM = []string{
	"CLSIDFromProgID", "CLSIDFromString", "CoCreateGuid", "CoCreateInstance", "CoCreateInstanceEx",
	"CoGetObject", "CoInitialize", "CoInitializeEx", "CoInitializeSecurity", "CoSetProxyBlanket",
	"CoUninitialize", "IActiveScript", "IPersistFile", "IShellLink", "IWbemLocator", "IWbemServices",
	"OleInitialize", "StringFromGUID2", "SysAllocString", "SysFreeString", "VariantClear",
	"VariantInit",
}

var apiCompression = []string{
	"BZ2_bzCompress", "BZ2_bzDecompress", "LZ4_decompress_safe", "ZSTD_decompress", "deflateInit2_",
	"deflateInit_", "inflateInit2_", "inflateInit_", "uncompress",
}

// apiGroups pairs each group with its sorted name list.
var apiGroups = []struct {
	group string
	names []string
}{
	{groupProcess, apiProcess},
	{groupAntiDebug, apiAntiDebug},
	{groupKeylog, apiKeylog},
	{groupSurveil, apiSurveil},
	{groupCrypto, apiCrypto},
	{groupNetwork, apiNetwork},
	{groupService, apiService},
	{groupRegistry, apiRegistry},
	{groupFile, apiFile},
	{groupLoader, apiLoader},
	{groupExec, apiExec},
	{groupPrivilege, apiPrivilege},
	{groupNative, apiNative},
	{groupSystem, apiSystem},
	{groupCOM, apiCOM},
	{groupCompression, apiCompression},
}

// apiPrefixes match whole families of names. When upper is set the character
// after the prefix must be an upper-case letter (CryptEncrypt yes, Cryptography no).
var apiPrefixes = []struct {
	prefix string
	group  string
	upper  bool
}{
	{"BCrypt", groupCrypto, true}, {"NCrypt", groupCrypto, true}, {"Crypt", groupCrypto, true},
	{"EVP_", groupCrypto, false}, {"RSA_", groupCrypto, false}, {"AES_", groupCrypto, false},
	{"DES_", groupCrypto, false}, {"SHA1_", groupCrypto, false}, {"SHA256_", groupCrypto, false},
	{"SHA512_", groupCrypto, false}, {"MD5_", groupCrypto, false}, {"HMAC_", groupCrypto, false},
	{"BN_", groupCrypto, false}, {"EC_", groupCrypto, false}, {"ECDSA_", groupCrypto, false},
	{"ECDH_", groupCrypto, false}, {"DH_", groupCrypto, false}, {"DSA_", groupCrypto, false},
	{"X509_", groupCrypto, false}, {"PEM_", groupCrypto, false}, {"PKCS7_", groupCrypto, false},
	{"PKCS12_", groupCrypto, false}, {"SSL_", groupCrypto, false}, {"TLS_", groupCrypto, false},
	{"BIO_", groupCrypto, false}, {"OPENSSL_", groupCrypto, false}, {"CRYPTO_", groupCrypto, false},
	{"RAND_", groupCrypto, false}, {"mbedtls_", groupCrypto, false}, {"wolfSSL_", groupCrypto, false},
	{"gnutls_", groupCrypto, false}, {"gcry_", groupCrypto, false}, {"sodium_", groupCrypto, false},
	{"crypto_", groupCrypto, false},
	{"curl_", groupNetwork, false}, {"WSA", groupNetwork, true}, {"WinHttp", groupNetwork, true},
	{"Internet", groupNetwork, true},
}

const (
	minAPILen = 3
	maxAPILen = 64
)

// apiIndex returns the name-to-group map, built once on first use.
var apiIndex = sync.OnceValue(func() map[string]string {
	n := 0
	for _, g := range apiGroups {
		n += len(g.names)
	}
	index := make(map[string]string, n)
	for _, g := range apiGroups {
		for _, name := range g.names {
			index[name] = g.group
		}
	}
	return index
})

// apiGroup reports whether s is a well-known Win32, native, POSIX or crypto API
// (or algorithm, or library) name and returns its group. Matching is exact and
// case-sensitive; a trailing A or W (ANSI/wide variant) and a leading
// underscore (C and Mach-O symbol decoration) are tolerated, and a few families
// are matched by prefix. s must consist of letters, digits, '_', '-' and '+'.
func apiGroup(s string) (string, bool) {
	if len(s) < minAPILen || len(s) > maxAPILen {
		return "", false
	}
	index := apiIndex()
	if g, ok := index[s]; ok {
		return g, true
	}
	if s[0] == '_' && len(s) > minAPILen {
		if g, ok := index[s[1:]]; ok {
			return g, true
		}
	}
	if last := s[len(s)-1]; last == 'A' || last == 'W' {
		if g, ok := index[s[:len(s)-1]]; ok {
			return g, true
		}
	}
	for _, p := range apiPrefixes {
		if len(s) > len(p.prefix) && strings.HasPrefix(s, p.prefix) {
			if !p.upper || (s[len(p.prefix)] >= 'A' && s[len(p.prefix)] <= 'Z') {
				return p.group, true
			}
		}
	}
	return "", false
}
