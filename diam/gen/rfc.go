package main

// AVP, command and Enumerated-value extraction from the IETF RFCs that
// define the base protocol and the applications 3GPP builds on. RFCs are
// immutable once published, so pinning one is just naming its number.
//
// Three regular constructs carry everything needed:
//
//   - Per-AVP prose, e.g. RFC 6733 §8.7: "The Auth-Request-Type AVP
//     (AVP Code 274) is of type Enumerated and ...". This is the
//     primary source because it carries name, code and type together.
//     The §4.5-style flag tables cannot play that role: RFC 7155's
//     table has neither a Code nor a Data Type column.
//   - The AVP flag tables, which supply the M bit, keyed by AVP name.
//     Names wrap across lines in the fixed-width layout
//     ("CC-Service-" / "  Specific-Units") and are rejoined.
//   - The command-code table (RFC 6733 §3.1 and friends), in either the
//     fixed-width or the pipe-delimited layout.
//
// Enumerated values are written "AUTHENTICATE_ONLY 1" — value last and
// unparenthesised, unlike any of the three 3GPP dialects.

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// rfcSource is one pinned RFC.
type rfcSource struct {
	num int    // 6733
	app string // application the AVPs are attributed to
	// commandApp labels the commands this RFC defines; empty skips its
	// command table entirely (RFC 7155's table restates RFC 6733's).
	commandApp string
}

func (r *rfcSource) file() string { return fmt.Sprintf("rfc%d.txt", r.num) }

// rfcName matches an AVP name as the prose spells it. RFC 4006 writes
// some of them with spaces where the registry hyphenates ("The Check
// Balance Result AVP (AVP Code 422)"), so up to five space-separated
// words are accepted and rejoined with hyphens by hyphenate(). Every
// word must start upper-case or with a digit, which keeps the match from
// running through the lower-case connectives of an ordinary sentence.
const rfcName = `([A-Za-z0-9][A-Za-z0-9\-]*(?:\s+[A-Z0-9][A-Za-z0-9\-]*){0,4})`

var (
	// "The Auth-Request-Type AVP (AVP Code 274) is of type Enumerated".
	// RFC 4006 also writes "is type of Enumerated" (§8.4), and a
	// bracketed citation may sit between the code and the type ("The
	// Framed-IP-Address AVP (AVP Code 8) [RFC2865] is of type
	// OctetString", RFC 7155 §4.4.10.5.1). The sentence may wrap, so
	// runs of whitespace stand in for single spaces throughout.
	rfcAvpRe = regexp.MustCompile(
		`(?s)The\s+` + rfcName + `\s+AVP\s+\(AVP\s+Code\s+(\d+)\)` +
			`(?:\s*\[[^\]]*\])?(?:,|\s)+is\s+(?:of\s+type|type\s+of)\s+([A-Za-z0-9]+)`)
	// The same statement with the code after the type, which RFC 4006
	// uses for about a third of its AVPs: "The User-Equipment-Info-Type
	// AVP is of type Enumerated  (AVP Code 459)".
	rfcAvpAltRe = regexp.MustCompile(
		`(?s)The\s+` + rfcName + `\s+AVP\s+is\s+(?:of\s+type|type\s+of)\s+` +
			`([A-Za-z0-9]+)\s*\(AVP\s+Code\s+(\d+)\)`)
	// A flag-table data line: name, optional code, optional section,
	// optional type, then the pipe-delimited flag columns. The type
	// column often abuts the first pipe with no space at all
	// ("OctetString| M  |  V  |" in RFC 6733 §4.5), so no separator is
	// required before it.
	rfcFlagRowRe = regexp.MustCompile(
		`^\s{2,}(\S[^|]*?)\s*\|([^|]*)\|`)
	// Where an AVP name ends in a flag-table row: the first whitespace
	// followed by a digit, which starts the code or section column.
	rfcNameCutRe = regexp.MustCompile(`\s+\d.*$`)
	// A wrapped-name continuation line inside a flag table: indented
	// text, then only empty flag cells.
	rfcFlagContRe = regexp.MustCompile(`^\s{4,}(\S[^|]*?)\s*\|[\s|]*$`)
	// An RFC section heading at column 0: "8.7.  Auth-Request-Type AVP".
	rfcHeadingRe = regexp.MustCompile(`^(\d+(?:\.\d+)*)\.\s+(\S.*)$`)
	// "AUTHENTICATE_ONLY 1" — an Enumerated value, value last.
	rfcEnumRe = regexp.MustCompile(`^\s{2,}([A-Z][A-Z0-9_]{1,60})\s+(\d{1,10})\s*$`)
	// A command row, either "Abort-Session-Request  ASR  274  8.5.1" or
	// "| AA-Request | AAR | 265 | Section 3.1 |".
	rfcCmdRe = regexp.MustCompile(
		`^\s*\|?\s*([A-Za-z][A-Za-z0-9\-]*)\s*\|?\s+([A-Z]{3})\s*\|?\s+(\d{3})\b`)
	// The continuation of a wrapped command name: a bare word.
	rfcWordRe = regexp.MustCompile(`^\s*\|?\s*([A-Za-z][A-Za-z0-9\-]*)\s*\|?\s*$`)
	// Page furniture that interrupts tables.
	rfcNoiseRe = regexp.MustCompile(`(?i)^\s*(RFC\s+\d+|.*\[Page\s+\d+\]\s*)$`)
)

// joinWrapped appends a continuation fragment to a wrapped name. Every
// wrap in these tables breaks after a hyphen ("CC-Service-" +
// "Specific-Units"), so a plain concatenation is right; a fragment that
// does not follow a hyphen gets one inserted.
func joinWrapped(head, tail string) string {
	head, tail = strings.TrimSpace(head), strings.TrimSpace(tail)
	if head == "" {
		return tail
	}
	if strings.HasSuffix(head, "-") || strings.HasPrefix(tail, "-") {
		return head + tail
	}
	return head + "-" + tail
}

// rfcMandatory reads the flag tables and returns the AVP names whose
// first flag column asserts M. Column layouts differ per RFC (RFC 6733
// has MUST/MUST NOT, RFC 4006 adds MAY/SHOULD NOT/Encr), but the first
// column is MUST in all of them.
func rfcMandatory(lines []string) map[string]bool {
	must := map[string]bool{}
	prev := ""
	for _, ln := range lines {
		if rfcNoiseRe.MatchString(ln) {
			continue
		}
		if m := rfcFlagContRe.FindStringSubmatch(ln); m != nil && prev != "" {
			// A continuation carries no flags; move the entry's key.
			joined := joinWrapped(prev, m[1])
			if must[prev] {
				delete(must, prev)
				must[joined] = true
			}
			prev = joined
			continue
		}
		m := rfcFlagRowRe.FindStringSubmatch(ln)
		if m == nil {
			continue
		}
		head, flags := strings.TrimSpace(m[1]), m[2]
		// Strip the trailing code/section/type columns off the name. The
		// cut is at the first whitespace-then-digit, which is where the
		// AVP code (RFC 6733 §4.5) or the section number (RFC 7155
		// §4.2.1) begins. Column alignment cannot be used: the gap is
		// one space in "Destination-Host 293" and thirteen in
		// "Class             25".
		name := strings.TrimSpace(rfcNameCutRe.ReplaceAllString(head, ""))
		if name == "" || strings.EqualFold(name, "Attribute Name") {
			continue
		}
		if strings.Contains(strings.ToUpper(flags), "M") {
			must[name] = true
		}
		prev = name
	}
	return must
}

// rfcCommands reads a command-code table into pair entries: the
// "-Request"/"-Answer" suffix is dropped so one entry covers both, which
// is the convention the generated DIAM_CMD_* constants follow.
func rfcCommands(lines []string, appName string) []*Command {
	seen := map[uint32]bool{}
	var out []*Command
	for i, ln := range lines {
		m := rfcCmdRe.FindStringSubmatch(ln)
		if m == nil {
			continue
		}
		name, code := m[1], uint32(atoiSafe(m[3]))
		if code < 256 {
			continue
		}
		// Rejoin a name wrapped onto the following line.
		if strings.HasSuffix(name, "-") {
			for _, nxt := range lines[i+1:] {
				if strings.TrimSpace(nxt) == "" || rfcNoiseRe.MatchString(nxt) {
					continue
				}
				if w := rfcWordRe.FindStringSubmatch(nxt); w != nil {
					name = joinWrapped(name, w[1])
				}
				break
			}
		}
		name = strings.TrimSuffix(reqAnsSuffixRe.ReplaceAllString(name, ""), "-")
		if name == "" || seen[code] {
			continue
		}
		seen[code] = true
		out = append(out, &Command{Name: name, Code: code, App: appName})
	}
	return out
}

// extractRFC reads one RFC's AVPs (with Enumerated values) and, when the
// source asks for them, its command codes.
func extractRFC(src *rfcSource, raw []byte, warn func(string, ...any)) ([]*AVP, []*Command, error) {
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	lines := strings.Split(text, "\n")

	must := rfcMandatory(lines)

	// One linear pass: a type sentence opens an AVP's definition and the
	// Enumerated lines that follow belong to it until the next sentence.
	// Section boundaries are deliberately not used as the delimiter —
	// RFC 6733 states the Result-Code AVP in §7.1 but lists its values in
	// the child subclauses §7.1.1..§7.1.5, so anything keyed on the
	// subclause loses them.
	blob := strings.Join(dropNoise(lines), "\n")
	hits := rfcDefs(blob)

	byName := map[string]*AVP{}
	var out []*AVP
	for hi, h := range hits {
		name, code := h.name, h.code
		typName, ok := typeVocab[typeKey(h.typ)]
		if !ok {
			warn("RFC %d: avp %s (code %d): unknown type %q; skipped",
				src.num, name, code, h.typ)
			continue
		}
		if prev, dup := byName[name]; dup {
			if prev.Code != code {
				warn("RFC %d: avp %s: also defined at code %d, keeping %d",
					src.num, name, code, prev.Code)
			}
			continue
		}
		a := &AVP{
			Name: name, Code: code, Type: typName,
			Mandatory: must[name], App: src.app,
			Src: fmt.Sprintf("RFC %d", src.num),
		}
		// Enumerated values between this sentence and the next one.
		// Result-Code is an Unsigned32 whose values RFC 6733 still
		// enumerates (§7.1), so the integer types are swept too.
		switch typName {
		case "Enumerated", "Unsigned32", "Integer32":
			end := len(blob)
			if hi+1 < len(hits) {
				end = hits[hi+1].start
			}
			a.Enums = rfcEnums(blob[h.end:end])
		}
		byName[name] = a
		out = append(out, a)
	}

	var cmds []*Command
	if src.commandApp != "" {
		cmds = rfcCommands(lines, src.commandApp)
	}
	if len(out) == 0 {
		return nil, nil, fmt.Errorf("RFC %d: no AVP definitions found", src.num)
	}
	return out, cmds, nil
}

// rfcDef is one "The X AVP ... is of type T" statement and where it sits.
type rfcDef struct {
	start, end int
	name, typ  string
	code       uint32
}

// rfcDefs finds every AVP definition statement, in either word order,
// ordered by position so the text between one and the next bounds that
// AVP's Enumerated values.
func rfcDefs(blob string) []*rfcDef {
	var out []*rfcDef
	add := func(m []int, nameG, typeG, codeG int) {
		out = append(out, &rfcDef{
			start: m[0], end: m[1],
			name: hyphenate(blob[m[2*nameG]:m[2*nameG+1]]),
			typ:  blob[m[2*typeG]:m[2*typeG+1]],
			code: uint32(atoiSafe(blob[m[2*codeG]:m[2*codeG+1]])),
		})
	}
	for _, m := range rfcAvpRe.FindAllStringSubmatchIndex(blob, -1) {
		add(m, 1, 3, 2)
	}
	for _, m := range rfcAvpAltRe.FindAllStringSubmatchIndex(blob, -1) {
		add(m, 1, 2, 3)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].start < out[j].start })
	return out
}

// hyphenate rejoins a name the prose wrote with spaces or across a line
// wrap: "Check Balance Result" -> "Check-Balance-Result". No Diameter AVP
// name contains a space, so this is always the intended spelling.
func hyphenate(s string) string {
	return strings.Join(strings.Fields(s), "-")
}

// dropNoise removes the page furniture that splits a definition across
// a page break.
func dropNoise(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, ln := range lines {
		if rfcNoiseRe.MatchString(ln) {
			continue
		}
		out = append(out, ln)
	}
	return out
}

// rfcEnums reads "NAME value" Enumerated lines out of one AVP's prose.
func rfcEnums(blob string) []*Enum {
	var out []*Enum
	seen := map[string]bool{}
	for _, ln := range strings.Split(blob, "\n") {
		m := rfcEnumRe.FindStringSubmatch(ln)
		if m == nil {
			continue
		}
		v, err := strconv.ParseInt(m[2], 10, 64)
		if err != nil {
			continue
		}
		cname := deriveCName(m[1])
		if cname == "" || seen[cname] {
			continue
		}
		seen[cname] = true
		out = append(out, &Enum{Name: m[1], CName: cname, Value: v})
	}
	return out
}
