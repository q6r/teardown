package rules

// Canonical API names used by the import-cluster rules. Names are lower-case,
// without the ANSI/wide suffix (A/W) and with the Zw* spelling folded into Nt*
// (see normalizeAPI). Every table is exercised by TestAPITablesAreCanonical.
var (
	// Process injection / hollowing: three stages plus the handle needed.
	apiRemoteAlloc = []string{
		"ntallocatevirtualmemory", "ntmapviewofsection", "ntprotectvirtualmemory",
		"ntunmapviewofsection", "virtualallocex", "virtualprotectex",
	}
	apiRemoteWrite = []string{"ntwritevirtualmemory", "process_vm_writev", "writeprocessmemory"}
	apiRemoteExec  = []string{
		"createremotethread", "createremotethreadex", "ntcreatethreadex", "ntqueueapcthread",
		"ntqueueapcthreadex", "ntsetcontextthread", "ptrace", "queueuserapc", "rtlcreateuserthread",
		"setthreadcontext",
	}
	apiOpenProcess = []string{"ntopenprocess", "openprocess"}

	// Keylogging / input capture.
	apiHooks = []string{"setwindowshookex"}
	apiKeys  = []string{
		"getasynckeystate", "getkeyboardstate", "getkeystate", "getrawinputdata",
		"registerrawinputdevices",
	}
	apiWindowContext = []string{"getforegroundwindow", "getwindowtext", "getwindowtextlength"}

	// Anti-debugging and anti-analysis.
	apiAntiDebug = []string{
		"checkremotedebuggerpresent", "dbgbreakpoint", "dbguiremotebreakin", "isdebuggerpresent",
		"ntqueryinformationprocess", "ntquerysysteminformation", "ntsetinformationthread",
		"outputdebugstring", "ptrace",
	}

	// Cryptography.
	apiCrypto = []string{
		"aes_decrypt", "aes_encrypt", "bcryptdecrypt", "bcryptencrypt", "bcryptgeneratesymmetrickey",
		"bcryptopenalgorithmprovider", "cryptacquirecontext", "cryptdecrypt", "cryptderivekey",
		"cryptencrypt", "cryptgenkey", "crypthashdata", "cryptimportkey", "cryptprotectdata",
		"cryptunprotectdata", "evp_cipherinit_ex", "evp_decryptinit_ex", "evp_encryptinit_ex",
		"ncryptdecrypt", "ncryptencrypt", "rsa_private_decrypt", "rsa_public_encrypt",
	}

	// Networking.
	apiNetwork = []string{
		"accept", "bind", "connect", "getaddrinfo", "gethostbyname", "httpopenrequest",
		"httpsendrequest", "internetconnect", "internetopen", "internetopenurl", "internetreadfile",
		"listen", "recv", "send", "socket", "urldownloadtocachefile", "urldownloadtofile",
		"winhttpconnect", "winhttpopen", "winhttpreaddata", "winhttpsendrequest", "wsastartup",
	}
	apiDownload = []string{"urldownloadtocachefile", "urldownloadtofile"}
	apiLaunch   = []string{
		"createprocess", "createprocessasuser", "createprocesswithlogon", "createprocesswithtoken",
		"shellexecute", "shellexecuteex", "winexec",
	}

	// Services.
	apiService = []string{
		"changeserviceconfig", "changeserviceconfig2", "controlservice", "createservice",
		"deleteservice", "openscmanager", "openservice", "startservice",
	}
	apiServiceInstall = []string{"changeserviceconfig", "changeserviceconfig2", "createservice"}

	// Privilege and token manipulation.
	apiToken = []string{
		"adjusttokenprivileges", "duplicatetokenex", "impersonateloggedonuser", "lookupprivilegevalue",
		"openprocesstoken", "setthreadtoken",
	}

	// Dynamic loading (for the minimal import table heuristic).
	apiLoadLibrary = []string{"loadlibrary", "loadlibraryex"}
	apiGetProc     = []string{"getprocaddress"}

	// Reverse-shell building blocks on Unix-likes.
	apiShSocket = []string{"socket"}
	apiShConn   = []string{"connect"}
	apiShDup    = []string{"dup2", "dup3"}
	apiShExec   = []string{"execl", "execle", "execlp", "execv", "execve", "execvp", "popen", "system"}
)
