package macho

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/q6r/teardown/internal/binio"
	"github.com/q6r/teardown/internal/limits"
)

// Load command numbers the parser understands.
const (
	lcSegment        = 0x1
	lcSymtab         = 0x2
	lcDysymtab       = 0xb
	lcLoadDylib      = 0xc
	lcIDDylib        = 0xd
	lcLazyLoadDylib  = 0x20
	lcUUID           = 0x1b
	lcCodeSignature  = 0x1d
	lcSegment64      = 0x19
	lcEncryptionInfo = 0x21
	lcVersionMinMac  = 0x24
	lcVersionMinIOS  = 0x25
	lcVersionMinTV   = 0x2f
	lcVersionMinWat  = 0x30
	lcEncryption64   = 0x2c
	lcBuildVersion   = 0x32
	lcLoadWeakDylib  = 0x80000018
	lcRPath          = 0x8000001c
	lcReexportDylib  = 0x8000001f
	lcLoadUpward     = 0x80000023
	lcMain           = 0x80000028
)

// Parser limits independent of the caller's [limits.Limits].
const (
	maxName    = 1024
	maxSymbols = 4 << 20 // symbol table entries scanned
	maxStored  = 100000  // imported / exported names stored
	nlistChunk = 4096    // nlist entries read per I/O call
)

type section struct {
	name     string // "SEGMENT,section"
	segment  string
	addr     uint64
	size     uint64
	offset   uint32 // relative to the slice
	flags    uint32
	zerofill bool
}

type segment struct {
	name       string
	vmaddr     uint64
	vmsize     uint64
	fileoff    uint64
	filesize   uint64
	maxprot    uint32
	initprot   uint32
	nsects     uint32
	sections   []section
	sectionCap bool // section list truncated at lim.MaxList
}

// thin is one parsed (single-architecture) Mach-O image.
type thin struct {
	// base and size locate the slice inside the file.
	base, size int64

	is64    bool
	big     bool
	order   binary.ByteOrder
	cpu     uint32
	subcpu  uint32
	typ     uint32
	flags   uint32
	ncmds   uint32
	cmdsize uint32

	loadCommands int
	segments     []segment
	dylibs       []string // LC_LOAD_DYLIB-family names in command order (ordinal = index+1)
	rpaths       []string
	installName  string
	uuid         string
	signed       bool
	hasEncCmd    bool
	cryptID      uint32
	platform     string
	minOS        string
	sdk          string
	entryOffset  *uint64

	symoff, nsyms, stroff, strsize uint32
	haveSymtab                     bool

	notes []string
}

func (t *thin) note(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if len(t.notes) < 25 {
		for _, n := range t.notes {
			if n == msg {
				return
			}
		}
		t.notes = append(t.notes, msg)
	}
}

var (
	errNotMachO = errors.New("not a Mach-O file")
)

// parseThin decodes the Mach-O image occupying [base, base+size) of r.
func parseThin(ctx context.Context, r io.ReaderAt, base, size int64, lim limits.Limits) (*thin, error) {
	t := &thin{base: base, size: size}
	sr := io.NewSectionReader(r, base, size)
	head, err := binio.ReadUpTo(sr, size, 0, 32)
	if err != nil {
		return nil, fmt.Errorf("reading the Mach-O header: %w", err)
	}
	if len(head) < 4 {
		return nil, fmt.Errorf("%w: only %d bytes, a Mach-O header needs at least 28", errNotMachO, len(head))
	}
	switch binary.LittleEndian.Uint32(head) {
	case 0xfeedface:
		t.order = binary.LittleEndian
	case 0xfeedfacf:
		t.order, t.is64 = binary.LittleEndian, true
	case 0xcefaedfe:
		t.order, t.big = binary.BigEndian, true
	case 0xcffaedfe:
		t.order, t.big, t.is64 = binary.BigEndian, true, true
	default:
		return nil, fmt.Errorf("%w: bad magic number %#08x (want feedface or feedfacf)", errNotMachO, binary.BigEndian.Uint32(head))
	}
	hdrLen := 28
	if t.is64 {
		hdrLen = 32
	}
	if len(head) < hdrLen {
		return nil, fmt.Errorf("truncated Mach-O header: need %d bytes, have %d", hdrLen, len(head))
	}
	c := binio.NewCursor(head, t.order)
	c.Skip(4)
	t.cpu, t.subcpu, t.typ = c.U32(), c.U32(), c.U32()
	t.ncmds, t.cmdsize, t.flags = c.U32(), c.U32(), c.U32()

	t.readLoadCommands(ctx, sr, int64(hdrLen), lim)
	return t, nil
}

func (t *thin) readLoadCommands(ctx context.Context, r io.ReaderAt, hdrLen int64, lim limits.Limits) {
	avail := max(t.size-hdrLen, 0)
	want := int64(t.cmdsize)
	if want > avail {
		t.note("the load commands need %d bytes but only %d follow the header; the file is probably truncated", want, avail)
		want = avail
	}
	if want > lim.MaxMeta {
		t.note("the load command area is %d bytes; only the first %d are read", want, lim.MaxMeta)
		want = lim.MaxMeta
	}
	raw, err := binio.ReadAt(r, t.size, hdrLen, want)
	if err != nil {
		t.note("the load commands could not be read: %v", err)
		return
	}
	ncmds := uint64(t.ncmds)
	if byLen := uint64(len(raw)) / 8; ncmds > byLen {
		t.note("the header declares %d load commands but the load command area holds at most %d", ncmds, byLen)
		ncmds = byLen
	}
	pos := 0
	sections := 0
	for i := uint64(0); i < ncmds; i++ {
		if i%256 == 0 && ctx.Err() != nil {
			return
		}
		if pos+8 > len(raw) {
			break
		}
		cmd := t.order.Uint32(raw[pos:])
		size := int(t.order.Uint32(raw[pos+4:]))
		if size < 8 || size > len(raw)-pos {
			t.note("load command %d (%#x) has an invalid size of %d bytes; the remaining commands were ignored", i, cmd, size)
			return
		}
		t.loadCommands++
		t.decode(cmd, raw[pos:pos+size], lim, &sections)
		pos += size
	}
}

// decode interprets one load command (cmd points at its first byte).
func (t *thin) decode(cmd uint32, b []byte, lim limits.Limits, sections *int) {
	c := binio.NewCursor(b, t.order)
	c.Skip(8)
	switch cmd {
	case lcSegment, lcSegment64:
		t.decodeSegment(cmd == lcSegment64, c, lim, sections)
	case lcSymtab:
		t.symoff, t.nsyms, t.stroff, t.strsize = c.U32(), c.U32(), c.U32(), c.U32()
		t.haveSymtab = c.Err() == nil
	case lcLoadDylib, lcLoadWeakDylib, lcReexportDylib, lcLazyLoadDylib, lcLoadUpward:
		if name, ok := t.dylibName(b); ok && len(t.dylibs) < lim.MaxList {
			t.dylibs = append(t.dylibs, name)
		}
	case lcIDDylib:
		if name, ok := t.dylibName(b); ok {
			t.installName = name
		}
	case lcRPath:
		off := c.U32()
		if s, ok := lcString(b, off); ok && len(t.rpaths) < lim.MaxList {
			t.rpaths = append(t.rpaths, s)
		}
	case lcUUID:
		if raw := c.Bytes(16); raw != nil {
			t.uuid = formatUUID(raw)
		}
	case lcCodeSignature:
		t.signed = true
	case lcEncryptionInfo, lcEncryption64:
		c.Skip(8) // cryptoff, cryptsize
		if id := c.U32(); c.Err() == nil {
			t.hasEncCmd, t.cryptID = true, id
		}
	case lcBuildVersion:
		platform, minos, sdk := c.U32(), c.U32(), c.U32()
		if c.Err() == nil {
			t.platform, t.minOS, t.sdk = platformName(platform), versionString(minos), versionString(sdk)
		}
	case lcVersionMinMac, lcVersionMinIOS, lcVersionMinTV, lcVersionMinWat:
		version, sdk := c.U32(), c.U32()
		if c.Err() == nil {
			t.platform = map[uint32]string{lcVersionMinMac: "macos", lcVersionMinIOS: "ios", lcVersionMinTV: "tvos", lcVersionMinWat: "watchos"}[cmd]
			t.minOS, t.sdk = versionString(version), versionString(sdk)
		}
	case lcMain:
		if off := c.U64(); c.Err() == nil {
			t.entryOffset = &off
		}
	}
}

func (t *thin) decodeSegment(is64 bool, c *binio.Cursor, lim limits.Limits, sections *int) {
	var s segment
	s.name = binio.FixedString(c.Bytes(16))
	if is64 {
		s.vmaddr, s.vmsize, s.fileoff, s.filesize = c.U64(), c.U64(), c.U64(), c.U64()
	} else {
		s.vmaddr, s.vmsize, s.fileoff, s.filesize = uint64(c.U32()), uint64(c.U32()), uint64(c.U32()), uint64(c.U32())
	}
	s.maxprot, s.initprot, s.nsects = c.U32(), c.U32(), c.U32()
	c.Skip(4) // flags
	if c.Err() != nil {
		t.note("a segment load command is too short to hold a segment header")
		return
	}
	secSize := 68
	if is64 {
		secSize = 80
	}
	n := uint64(s.nsects)
	if fit := uint64(c.Remaining() / secSize); n > fit {
		t.note("segment %s declares %d sections but its command holds only %d", s.name, n, fit)
		n = fit
	}
	for range n {
		var sec section
		sec.name = binio.FixedString(c.Bytes(16))
		sec.segment = binio.FixedString(c.Bytes(16))
		if is64 {
			sec.addr, sec.size = c.U64(), c.U64()
		} else {
			sec.addr, sec.size = uint64(c.U32()), uint64(c.U32())
		}
		sec.offset = c.U32()
		c.Skip(12) // align, reloff, nreloc
		sec.flags = c.U32()
		c.Skip(8) // reserved1, reserved2
		if is64 {
			c.Skip(4) // reserved3
		}
		if c.Err() != nil {
			break
		}
		// Section types 0x1, 0xc and 0x12 occupy memory but no file space.
		switch sec.flags & 0xff {
		case 0x1, 0xc, 0x12:
			sec.zerofill = true
		}
		sec.name = sec.segment + "," + sec.name
		if *sections >= lim.MaxList {
			s.sectionCap = true
			continue
		}
		*sections++
		s.sections = append(s.sections, sec)
	}
	t.segments = append(t.segments, s)
}

// dylibName extracts the install name of a dylib_command.
func (t *thin) dylibName(b []byte) (string, bool) {
	if len(b) < 16 {
		return "", false
	}
	return lcString(b, t.order.Uint32(b[8:]))
}

// lcString reads the NUL-terminated lc_str at the given offset of a load command.
func lcString(b []byte, off uint32) (string, bool) {
	if off < 8 || uint64(off) >= uint64(len(b)) {
		return "", false
	}
	rest := b[off:]
	if i := indexNUL(rest); i >= 0 {
		rest = rest[:i]
	}
	return binio.Printable(string(rest), maxName), true
}

func indexNUL(b []byte) int {
	for i, v := range b {
		if v == 0 {
			return i
		}
	}
	return -1
}

func formatUUID(b []byte) string {
	h := strings.ToUpper(fmt.Sprintf("%x", b))
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
