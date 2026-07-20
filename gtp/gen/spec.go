package main

import (
	"regexp"
	"strings"
)

// Presence classes from the spec grammar tables. Only M changes
// generated-code behaviour (an encode-time and decode-time mandatory
// check); every other class maps to "optional", since the conditions
// are prose the generator cannot evaluate.
const (
	M = "M"
	C = "C"
	O = "O"
)

// specData holds the extracted description of each protocol. The
// generated spec_<proto>.go files (written by the `fetch` sub-command,
// see emit.go) register into it from their init(); the render
// sub-command reads it back and resolves it into a Model. Keeping the
// facts as compiled-in Go — rather than a side file the render step must
// parse — means an ordinary build has no extra input format to read.
var specData = map[string]*Spec{}

// Spec is one protocol's machine-extracted description: the IE registry
// and the message grammars, as read from the 3GPP spec tables by the
// `fetch` sub-command (see extract.go). Nothing here is hand-curated —
// regenerate spec_<proto>.go with `go run . fetch <proto> <version>` to
// move to a newer release.
type Spec struct {
	Protocol string // "gtp1" | "gtp2"; also the C prefix
	Doc      string // e.g. "3GPP TS 29.274"
	Release  string // e.g. "17.6.0", decoded from the version

	IEs      []*IE
	Messages []*Message
}

// IE is one registry entry (TS 29.274 Table 8.1-1 / TS 29.060 Table 37).
type IE struct {
	Name     string // canonical spec name; the enum stem source
	CName    string // C enum stem, derived from Name
	Type     uint16 // IE type value
	FixedLen int    // gtp1: > 0 marks a TV IE with this value length
	Comment  string
}

// Message is one message grammar (a spec §7.x table).
type Message struct {
	Name    string // "Create Session Request"
	Short   string // C name stem, e.g. "create_session_request"
	Type    uint16 // message type value
	Section string // spec subclause, for the comment
	NoTeid  bool   // gtp2: header without TEID (echo/version)
	Comment string
	Rows    []*Row
}

// Row is one IE occurrence within a message, in wire order. Repeated
// occurrences of one IE type are separate rows distinguished (gtp2) by
// Instance or (gtp1) by their order of appearance.
type Row struct {
	IE       string // registry name (join key)
	Field    string // C field name, derived from the row's display name
	Presence string // M|C|O
	Instance int    // gtp2; default 0
	Comment  string
}

var nonIdent = regexp.MustCompile(`[^A-Za-z0-9]+`)

// cStem joins a name's alphanumeric words with underscores, upper-cased:
// "Serving Network" -> "SERVING_NETWORK", "F-TEID" -> "FTEID". A leading
// digit is escaped so the result is a legal C identifier.
func cStem(name string) string {
	name = strings.ReplaceAll(name, "-", "") // F-TEID -> FTEID
	var out []string
	for _, p := range nonIdent.Split(name, -1) {
		if p != "" {
			out = append(out, strings.ToUpper(p))
		}
	}
	s := strings.Join(out, "_")
	if s != "" && s[0] >= '0' && s[0] <= '9' {
		s = "_" + s // "3GPP..." -> "_3GPP..."
	}
	return s
}

// dropTrailingParen removes a trailing "(abbreviation)":
// "Recovery (Restart Counter)" -> "Recovery". A mid-string parenthetical
// like "H(e)NB ..." is left in place.
func dropTrailingParen(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, ")") {
		if i := strings.LastIndexByte(s, '('); i > 0 {
			return strings.TrimSpace(s[:i])
		}
	}
	return s
}

// deriveCName turns a spec IE/message name into an upper-snake C enum
// stem: "Recovery (Restart Counter)" -> "RECOVERY".
func deriveCName(name string) string { return cStem(dropTrailingParen(name)) }

// deriveField is the lower-cased C struct field name for a grammar row,
// taken from its descriptive name. Any remaining parentheses (e.g. the
// "(e)" in "H(e)NB Local IP Address") become word separators.
func deriveField(name string) string {
	name = strings.NewReplacer("(", " ", ")", " ").Replace(dropTrailingParen(name))
	return strings.ToLower(cStem(name))
}
