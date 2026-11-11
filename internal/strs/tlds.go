package strs

import (
	"strings"
	"sync"
)

// tldList is the allow-list of top-level domains accepted by the domain and
// email matchers. It is deliberately conservative: TLDs that collide with
// common file extensions are left out so that file names are not mistaken for
// host names. Excluded on purpose: ai am app as cc cf cr in la md mk mm mp
// pl pm ps py rs sc sh so st zip mov (and of course dll, exe, bat, sys, ...).
// The private-use names (local, internal, lan, corp, home, intranet,
// localdomain) and "onion" are included because they matter for triage.
const tldList = `
com net org edu gov mil int info biz name pro mobi asia tel travel jobs coop aero museum arpa
xyz top site online club cloud tech store shop link live icu vip work click dev io co me tv us ws
tk ml ga gq nu to fm gg sx ly pw su space website fun bid win download review trade party stream
science accountant loan men racing date faith cricket kim lol wang ren red blue pink black mom
host press rocks ninja guru social network systems solutions services digital email group global
world life today news media agency company center support zone expert cash money bank finance
exchange market trading
ru cn jp kr br de fr es it nl be at ch se no dk fi ie pt gr tr ua cz sk hu ro bg hr si lt lv ee
by kz uz ge az il ir iq sa ae eg ng za ke gh ma tn dz au nz ca mx ar cl pe ve uy bo ec pa cu pr
jm hk tw sg my th vn ph id pk bd lk np kh mn uk eu is li lu mt cy mc
onion local internal lan corp home intranet localdomain
`

// tlds returns the allow-list as a set. It is built once on first use.
var tlds = sync.OnceValue(func() map[string]struct{} {
	fields := strings.Fields(tldList)
	set := make(map[string]struct{}, len(fields))
	for _, f := range fields {
		set[f] = struct{}{}
	}
	return set
})

// tldAllowed reports whether the lower-case label is an allowed TLD.
func tldAllowed(label string) bool {
	_, ok := tlds()[label]
	return ok
}
