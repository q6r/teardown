package report

// Content type identifiers (Type.ID). Package sniff produces them and package
// analyze dispatches on them.
const (
	TypePE          = "pe"
	TypeDOS         = "dos"
	TypeELF         = "elf"
	TypeMachO       = "macho"
	TypeMachOFat    = "macho-fat"
	TypeClass       = "class"
	TypeDex         = "dex"
	TypeWasm        = "wasm"
	TypePyc         = "pyc"
	TypeLua         = "luac"
	TypeZip         = "zip"
	TypeJar         = "jar"
	TypeAPK         = "apk"
	TypeAAB         = "aab"
	TypeDocx        = "docx"
	TypeXlsx        = "xlsx"
	TypePptx        = "pptx"
	TypeODF         = "odf"
	TypeEPUB        = "epub"
	TypeNupkg       = "nupkg"
	TypeWheel       = "wheel"
	TypeVSIX        = "vsix"
	TypeAsar        = "asar"
	TypePDF         = "pdf"
	TypeRTF         = "rtf"
	TypeOLE         = "ole"
	TypeSQLite      = "sqlite"
	TypeGzip        = "gzip"
	TypeBzip2       = "bzip2"
	TypeXz          = "xz"
	TypeZstd        = "zstd"
	Type7z          = "7z"
	TypeRar         = "rar"
	TypeTar         = "tar"
	TypePNG         = "png"
	TypeJPEG        = "jpeg"
	TypeGIF         = "gif"
	TypeWebP        = "webp"
	TypeGGUF        = "gguf"
	TypeSafetensors = "safetensors"
	TypeScript      = "script"
	TypeText        = "text"
	TypeData        = "data"
)

// Type families (Type.Family).
const (
	FamilyExecutable = "executable"
	FamilyBytecode   = "bytecode"
	FamilyArchive    = "archive"
	FamilyPackage    = "package"
	FamilyDocument   = "document"
	FamilyImage      = "image"
	FamilyDatabase   = "database"
	FamilyModel      = "model"
	FamilyScript     = "script"
	FamilyText       = "text"
	FamilyData       = "data"
)

// String classification categories (StringItem.Category, Strings.ByCategory keys).
const (
	CatURL       = "url"
	CatDomain    = "domain"
	CatIP        = "ip"
	CatEmail     = "email"
	CatPath      = "path"
	CatRegistry  = "registry"
	CatCommand   = "command"
	CatBase64    = "base64"
	CatHex       = "hex"
	CatAPI       = "api"
	CatUserAgent = "useragent"
	CatSecret    = "secret"
	CatPlain     = "plain"
)

// StringCategories lists every category in display order (most specific first).
func StringCategories() []string {
	return []string{
		CatSecret, CatURL, CatEmail, CatIP, CatRegistry, CatCommand, CatUserAgent,
		CatPath, CatDomain, CatAPI, CatBase64, CatHex, CatPlain,
	}
}

// Hardening identifiers (Hardening.ID). Parsers emit the ones that make sense
// for their format and the rules engine turns disabled ones into findings.
const (
	// HardenASLR is PE DYNAMIC_BASE (address space layout randomisation).
	HardenASLR = "aslr"
	// HardenHighEntropyVA is PE HIGH_ENTROPY_VA (64-bit ASLR).
	HardenHighEntropyVA = "high-entropy-va"
	// HardenDEP is PE NX_COMPAT (data execution prevention).
	HardenDEP = "dep"
	// HardenCFG is PE GUARD_CF (control flow guard).
	HardenCFG = "cfg"
	// HardenSEH is PE structured exception handling safety (NO_SEH / SafeSEH).
	HardenSEH = "seh"
	// HardenForceIntegrity is PE FORCE_INTEGRITY (signature enforced at load).
	HardenForceIntegrity = "force-integrity"
	// HardenSigned is the presence of an Authenticode signature or macOS code signature.
	HardenSigned = "signed"
	// HardenPIE is a position independent executable (ELF ET_DYN, Mach-O MH_PIE).
	HardenPIE = "pie"
	// HardenNX is a non-executable stack (ELF PT_GNU_STACK without X).
	HardenNX = "nx"
	// HardenRELRO is ELF relocation read-only (partial or full).
	HardenRELRO = "relro"
	// HardenCanary is stack-smashing protection (__stack_chk_fail imported).
	HardenCanary = "canary"
	// HardenFortify is glibc _FORTIFY_SOURCE (__*_chk imports).
	HardenFortify = "fortify"
	// HardenEncrypted is Mach-O LC_ENCRYPTION_INFO (App Store DRM).
	HardenEncrypted = "encrypted"
)
