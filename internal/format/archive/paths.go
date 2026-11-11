package archive

import "strings"

// unsafePath reports whether extracting an entry with this raw name could write
// outside the extraction root (the "zip-slip" class of bugs): a NUL byte, an
// absolute path (POSIX, drive letter or UNC), or any parent-directory segment.
// Both '/' and '\' count as separators because extractors differ in which they
// honour. Any ".." segment is flagged, even one that happens to normalise to a
// location inside the root, because legitimate archives never contain it.
func unsafePath(raw string) bool {
	if strings.IndexByte(raw, 0) >= 0 {
		return true
	}
	p := strings.ReplaceAll(raw, `\`, "/")
	if strings.HasPrefix(p, "/") {
		return true
	}
	if len(p) >= 2 && p[1] == ':' && (p[0]|0x20 >= 'a' && p[0]|0x20 <= 'z') {
		return true
	}
	for seg := range strings.SplitSeq(p, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

// nestedExts are extensions of entries that are archives, installers or
// executables in their own right. Native libraries (.so), bytecode (.dex,
// .class) and similar members of normal packages are deliberately absent.
var nestedExts = map[string]bool{
	".zip": true, ".jar": true, ".war": true, ".ear": true, ".aar": true, ".apk": true, ".aab": true,
	".apkm": true, ".xapk": true, ".7z": true, ".rar": true, ".gz": true, ".tgz": true, ".bz2": true,
	".tbz2": true, ".xz": true, ".zst": true, ".tar": true, ".cab": true, ".msi": true, ".msix": true,
	".appx": true, ".exe": true, ".dll": true, ".sys": true, ".scr": true,
}

// benignExts are extensions of members that are not worth a magic-number
// check: text, markup, media, fonts and the typical contents of packages.
var benignExts = map[string]bool{
	".xml": true, ".txt": true, ".json": true, ".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".webp": true, ".svg": true, ".html": true, ".htm": true, ".css": true, ".js": true, ".mjs": true,
	".md": true, ".properties": true, ".mf": true, ".sf": true, ".rsa": true, ".dsa": true, ".ec": true,
	".so": true, ".dex": true, ".arsc": true, ".pb": true, ".ttf": true, ".otf": true, ".woff": true,
	".woff2": true, ".ico": true, ".kotlin_module": true, ".version": true, ".yml": true, ".yaml": true,
	".csv": true, ".java": true, ".kt": true, ".ogg": true, ".mp3": true, ".wav": true, ".mp4": true,
	".webm": true, ".pdf": true, ".rels": true, ".proto": true, ".sql": true, ".ts": true, ".map": true,
	".tsx": true, ".jsx": true, ".dylib": true, ".pyc": true, ".py": true, ".rb": true, ".lua": true,
}

// containerMagics are the leading bytes of archives, installers and executables.
var containerMagics = [][]byte{
	{'P', 'K', 3, 4},
	{'P', 'K', 5, 6},
	{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C},
	{'R', 'a', 'r', '!'},
	{0x1F, 0x8B},
	{'B', 'Z', 'h'},
	{0xFD, '7', 'z', 'X', 'Z', 0},
	{0x28, 0xB5, 0x2F, 0xFD},
	{'M', 'Z'},
	{0x7F, 'E', 'L', 'F'},
	{'M', 'S', 'C', 'F'},
	{0xD0, 0xCF, 0x11, 0xE0},
	{0xCF, 0xFA, 0xED, 0xFE},
	{0xCE, 0xFA, 0xED, 0xFE},
	{0xFE, 0xED, 0xFA, 0xCF},
	{0xFE, 0xED, 0xFA, 0xCE},
}

// looksLikeContainer reports whether b starts with the magic number of an
// archive, installer or executable.
func looksLikeContainer(b []byte) bool {
	for _, m := range containerMagics {
		if len(b) >= len(m) && string(b[:len(m)]) == string(m) {
			return true
		}
	}
	return false
}
