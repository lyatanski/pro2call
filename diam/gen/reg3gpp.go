package main

// AVP extraction from the 3GPP specifications.
//
// Registry tables. Every 29-series Diameter spec carries its AVPs in a
// table whose header names an "AVP Code" and a "Value Type" column, e.g.
// TS 29.229 Table 6.3.0.1:
//
//	Attribute Name | AVP Code | Clause defined | Value Type | Must | May | ...
//	Public-Identity|      601 |         6.3.2 |  UTF8String |    M, V |  |
//
// Columns are located by content rather than by header index. Header
// index would be the obvious choice and works for five of the six
// specs, but TS 32.299 Table 7.2.0.1 (the 500-odd charging AVPs) merges
// its header cells differently from its data rows: even after gridSpan
// expansion the header reports 38 columns and "Value Type" lands on an
// index that is blank in 40% of the data rows. Anchoring on the values
// themselves — the first bare integer is the code, the first cell in the
// RFC 6733 type vocabulary is the type, the first flag-ish cell after it
// is the Must column — reads all six tables with one rule.
//
// The M bit comes from that Must column. The V bit — which decides
// whether a code lands in 3GPP vendor space or IETF space, and so must
// not be guessed — is read from the flag columns in three steps:
//
//	V in Must              a vendor AVP ("M, V" in TS 29.229)
//	V in a later column    an IETF AVP the spec only reuses; this is how
//	                       TS 32.299 Table 7.1.0.1 marks
//	                       Accounting-Input-Octets (code 363) as
//	                       Must=M, Must-not=V
//	V stated nowhere       the registry's own scope decides, which is
//	                       what its title asserts ("3GPP specific AVPs").
//	                       TS 32.299 Table 7.2.0.1 truncates the flag
//	                       columns for 3GPP-OC-Rating-Group and others.
//
// Getting this wrong does not fail loudly — it files a 3GPP AVP under
// vendor 0, where it collides with whatever IETF AVP holds that code.
//
// Enumerated values live in the AVP's own subclause, in three dialects
// across the specs (see enumsFromSection).

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// typeVocab maps a normalised Value Type cell to a canonical RFC 6733
// type. The aliases are the spellings the specs and RFCs actually use.
var typeVocab = map[string]string{
	"octetstring":      "OctetString",
	"octectstring":     "OctetString", // TS 32.299 typo, kept deliberately
	"integer32":        "Integer32",
	"integer64":        "Integer64",
	"unsigned32":       "Unsigned32",
	"unsigned64":       "Unsigned64",
	"float32":          "Float32",
	"float64":          "Float64",
	"grouped":          "Grouped",
	"enumerated":       "Enumerated",
	"utf8string":       "UTF8String",
	"diameteridentity": "DiameterIdentity",
	"diamident":        "DiameterIdentity", // RFC 6733 §4.5 spelling
	"diameteruri":      "DiameterURI",
	"diamuri":          "DiameterURI",
	"address":          "Address",
	"time":             "Time",
	"ipfilterrule":     "IPFilterRule",
	"qosfilterrule":    "QoSFilterRule",
}

var (
	intRe = regexp.MustCompile(`^\d+$`)
	// Separator between a value and its name in the value-first enum
	// dialect: a tab column or a run of spaces.
	enumPairSep = regexp.MustCompile(`\t|\s{2,}`)
	referRe     = regexp.MustCompile(`(?i)^refer\s*\[\d+\]$`)
	// A footnote marker some registry rows carry in the name cell, e.g.
	// "Sponsored-Connectivity-Data (NOTE 4)" in TS 29.214 Table 5.3.0.1.
	noteSuffixRe = regexp.MustCompile(`(?i)\s*\(note[^)]*\)\s*$`)
	// The request/answer half of a command name, dropped so one entry
	// covers the pair. TS 29.338 §6.3.2.2 separates it with a space
	// ("MO-Forward-Short-Message Request") where §5.3.2.2 uses a hyphen.
	reqAnsSuffixRe = regexp.MustCompile(`[-\s]+(?:Request|Answer)$`)
	// A flag-rules cell: "M, V", "V", "M,V", "-". The period is there
	// because TS 29.212 Table 5.3.0.1 writes "M.V" for QoS-Information
	// and QoS-Upgrade; rejecting that cell loses the vendor bit and
	// files those AVPs under vendor 0.
	flagsRe = regexp.MustCompile(`^[MVP,.\-/ ]+$`)
	// A bare clause reference, which may sit between the name and the
	// code. Anything else there means the row is not a registry entry.
	clauseRefRe = regexp.MustCompile(`^[\d.a-z]+$`)
	nonAlnum    = regexp.MustCompile(`[^a-z0-9]+`)
)

// normCell folds a cell to a comparison key: lower-case, runs of
// non-alphanumerics collapsed to one space.
func normCell(s string) string {
	return strings.Trim(nonAlnum.ReplaceAllString(strings.ToLower(s), " "), " ")
}

// typeKey strips a Value Type cell down to its vocabulary key,
// discarding any note reference: "Value Type (NOTE 2)" -> "valuetype",
// "Unsigned32" -> "unsigned32".
func typeKey(s string) string {
	if i := strings.IndexByte(s, '('); i >= 0 {
		s = s[:i]
	}
	return nonAlnum.ReplaceAllString(strings.ToLower(s), "")
}

func atoiSafe(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// isRegistryTable reports whether a table is an AVP registry: its
// header names both an AVP code and a value type column.
func isRegistryTable(t *table) bool {
	var b strings.Builder
	for i, r := range t.rows {
		if i == 4 {
			break
		}
		b.WriteString(normCell(strings.Join(r, "|")))
		b.WriteByte(' ')
	}
	h := b.String()
	return strings.Contains(h, "avp code") && strings.Contains(h, "value type") &&
		(strings.Contains(h, "attribute name") || strings.Contains(h, "avp name"))
}

// regRow is one parsed registry row. must is the "Must" flag cell; rest
// holds the flag cells after it (May / Should not / Must not), which is
// where a spec states that the V bit must *not* be set.
type regRow struct {
	name  string
	code  uint32
	typ   string
	must  string
	rest  []string
	refer string // non-empty when the type defers to another spec
}

// parseRegRow reads one registry row by anchoring on cell content.
// Returns nil for header, note and continuation rows.
func parseRegRow(r []string) *regRow {
	i := 0
	for i < len(r) && strings.TrimSpace(r[i]) == "" {
		i++
	}
	if i >= len(r) {
		return nil
	}
	name := noteSuffixRe.ReplaceAllString(strings.TrimSpace(r[i]), "")
	i++

	// The code: the first bare integer. Anything else non-numeric before
	// it means this is not a data row.
	var code uint32
	found := false
	for ; i < len(r); i++ {
		c := strings.TrimSpace(r[i])
		if c == "" {
			continue
		}
		if intRe.MatchString(c) {
			code = uint32(atoiSafe(c))
			i++
			found = true
			break
		}
		// A clause reference ("6.3.2") may precede the code in some
		// layouts; anything richer than that is prose.
		if !clauseRefRe.MatchString(strings.ToLower(c)) {
			return nil
		}
	}
	if !found {
		return nil
	}

	// The type: the first cell in the vocabulary. A "refer [207]" cell
	// means the defining spec is elsewhere.
	typ := ""
	for ; i < len(r); i++ {
		c := strings.TrimSpace(r[i])
		if c == "" {
			continue
		}
		if k, ok := typeVocab[typeKey(c)]; ok {
			typ = k
			i++
			break
		}
		if referRe.MatchString(c) {
			return &regRow{name: name, code: code, refer: c}
		}
	}
	if typ == "" {
		return nil
	}

	// The flag columns: the first non-empty flag-ish cell after the type
	// is "Must", and the flag-ish cells following it are May / Should
	// not / Must not.
	must := ""
	var rest []string
	for ; i < len(r); i++ {
		c := strings.TrimSpace(r[i])
		if c == "" {
			continue
		}
		if !flagsRe.MatchString(c) {
			break
		}
		if must == "" {
			must = c
		} else {
			rest = append(rest, c)
		}
	}
	return &regRow{name: name, code: code, typ: typ, must: must, rest: rest}
}

// hasFlag reports whether a flag cell asserts a bit. The cell has
// already been matched against flagsRe, so it holds nothing but flag
// letters and separators, and testing for the letter is enough: the
// separator is variously ", ", ",", "." and sometimes absent altogether
// ("VM" for Target-IP-Address in TS 32.299 Table 7.2.0.1).
func hasFlag(cell string, f byte) bool {
	return strings.IndexByte(strings.ToUpper(cell), f) >= 0
}

func anyHasFlag(cells []string, f byte) bool {
	for _, c := range cells {
		if hasFlag(c, f) {
			return true
		}
	}
	return false
}

var skipName = regexp.MustCompile(`^(reserved|void|spare|attribute name|avp name|note)\b`)

// enum dialects. All three appear as standalone paragraphs inside the
// AVP's subclause:
//
//	REGISTRATION (0)          TS 29.229 / 29.212 / 29.214 / 29.329
//	-SM_DELIVER (0)           TS 29.338, as a bulleted list
//	0<tab>ORIGINATING_ROLE    TS 32.299, value first
//
// The 32.299 form also packs several values into one paragraph
// ("0\tS-CSCF\t1\tP-CSCF\t..."), so that dialect is scanned repeatedly
// across the paragraph rather than anchored to its start.
var (
	// "REGISTRATION (0)", "-<tab>ONLY_IMSI_REQUESTED (0)," — the leading
	// bullet and the trailing list punctuation are both optional, and
	// some names are spaced rather than underscored ("NETWORK_REQUEST
	// NOT SUPPORTED (0)" in TS 29.212 §5.3.24).
	// The name may start with a digit — TS 29.212 §5.3.27 defines
	// IP-CAN-Type values "3GPP-GPRS (0)", "3GPP-EPS (5)", "3GPP-5GS (8)"
	// — so a leading letter must not be required.
	enumNameFirst = regexp.MustCompile(`^-?\s*([A-Za-z0-9][A-Za-z0-9_\-/. ]{0,60}?)\s*\((\d+)\)\s*[,.;]?$`)
	// "The X AVP is of type Enumerated". Both the leading "The" and the
	// AVP code are optional. The specs and RFCs phrase the type three
	// ways — "is of type T", "is of type of T" (TS 29.212 §5.3.23) and
	// "is type of T" (RFC 4006 §8.4) — so all three are accepted.
	// The name may also be spaced where the registry hyphenates it
	// ("The Pre-emption Vulnerability AVP", TS 29.212 §5.3.47), which is
	// why lookups against this map go through normCell.
	typeSentence = regexp.MustCompile(
		`(?s)^(?:The\s+)?([A-Za-z0-9][A-Za-z0-9\- ]*?)\s+AVP\s*(?:\(AVP\s+code\s+(\d+)\))?` +
			`.{0,160}?\bis\s+(?:of\s+type|type\s+of)(?:\s+of)?\s+([A-Za-z0-9]+)`)
)

// enumValueFirst reads the TS 32.299 dialect, where the value leads and
// a single paragraph may hold a whole list:
//
//	"0\tS-CSCF\t1\tP-CSCF\t2\tI-CSCF\t3\tMRFC"   §7.2.113
//	"0    SGSN"                                  §7.2.198
//
// That spec aligns these lists with tabs in some subclauses and with
// runs of spaces in others, so either separates a pair. Tokens are
// walked rather than matched with one regexp because RE2 has no
// lookahead to bound each pair. A paragraph that does not start with an
// integer is prose and yields nothing.
func enumValueFirst(p string) [][2]string {
	var clean []string
	for _, t := range enumPairSep.Split(p, -1) {
		if t = strings.TrimSpace(t); t != "" {
			clean = append(clean, t)
		}
	}
	if len(clean) < 2 || !intRe.MatchString(clean[0]) {
		return nil
	}
	var out [][2]string
	for i := 0; i+1 < len(clean); i++ {
		if !intRe.MatchString(clean[i]) || intRe.MatchString(clean[i+1]) {
			continue
		}
		out = append(out, [2]string{clean[i], clean[i+1]})
		i++ // the name is consumed
	}
	return out
}

// enumsFromSection reads the Enumerated values a subclause defines,
// keyed by the AVP name its type sentence names. A subclause may
// document more than one AVP (TS 32.299 §7.2.177 covers Role-Of-Node,
// Role-Of-ProSe-Function and Route-Header-Received), so values are
// attributed to the most recent type sentence rather than to the
// heading.
func enumsFromSection(s *section, warn func(string, ...any)) map[string][]*Enum {
	out := map[string][]*Enum{}
	curAVP, curEnum := "", false
	seen := map[string]map[string]bool{}

	add := func(name string, val int64) {
		if !curEnum || curAVP == "" {
			return
		}
		cname := deriveCName(name)
		if cname == "" {
			return
		}
		if seen[curAVP] == nil {
			seen[curAVP] = map[string]bool{}
		}
		if seen[curAVP][cname] {
			return
		}
		seen[curAVP][cname] = true
		out[curAVP] = append(out[curAVP], &Enum{Name: name, CName: cname, Value: val})
	}

	for _, p := range s.body {
		if m := typeSentence.FindStringSubmatch(p); m != nil {
			curAVP = normCell(m[1])
			// Enumerated is the normal carrier, but the specs also
			// enumerate values for Unsigned32/Integer32 AVPs
			// (Experimental-Result-Code, Result-Code).
			switch strings.ToLower(m[3]) {
			case "enumerated", "unsigned32", "integer32":
				curEnum = true
			default:
				curEnum = false
			}
			continue
		}
		if !curEnum {
			continue
		}
		if m := enumNameFirst.FindStringSubmatch(p); m != nil {
			v, err := strconv.ParseInt(m[2], 10, 64)
			if err != nil {
				warn("§%s %s: enum %q has bad value %q", s.num, curAVP, m[1], m[2])
				continue
			}
			add(strings.TrimSpace(m[1]), v)
			continue
		}
		for _, pair := range enumValueFirst(p) {
			v, err := strconv.ParseInt(pair[0], 10, 64)
			if err != nil {
				continue
			}
			add(pair[1], v)
		}
	}
	return out
}

// specSource is one pinned specification and the registries to take
// from it. sections maps a subclause prefix to the application the
// registry under it belongs to; a nil value selects a registry that is
// deliberately skipped (another interface documented in the same spec).
type specSource struct {
	num string // "29.229"
	ver string // 3GPP version code, "j00"
	// primaryApp labels command codes, whose table sits outside the AVP
	// subclauses the sections map covers.
	primaryApp string
	sections   map[string]*string
	// enumSections limits the enum sweep to the subclauses that define
	// AVPs; empty means the whole document.
	enumSections []string
}

func app(name string) *string { return &name }

// file is the .docx name inside specs/: "29229-j00.docx".
func (s *specSource) file() string {
	return fmt.Sprintf("%s-%s.docx", strings.Replace(s.num, ".", "", 1), s.ver)
}

// release renders the pinned version as a dotted release. Each
// character of a 3GPP version code is one field, 0-9 then a-z for
// 10-35: "j00" -> "19.0.0", "j30" -> "19.3.0".
func (s *specSource) release() string {
	parts := make([]string, 0, len(s.ver))
	for _, r := range s.ver {
		switch {
		case r >= '0' && r <= '9':
			parts = append(parts, strconv.Itoa(int(r-'0')))
		case r >= 'a' && r <= 'z':
			parts = append(parts, strconv.Itoa(10+int(r-'a')))
		default:
			return s.ver
		}
	}
	return strings.Join(parts, ".")
}

// appFor resolves the subclause a registry table sits in to an
// application, following the longest matching prefix. ok is false when
// no rule covers the table at all — that is a spec layout change and is
// reported rather than silently dropped.
func (s *specSource) appFor(sec string) (name string, selected, ok bool) {
	best := ""
	var val *string
	for pfx, a := range s.sections {
		if sec != pfx && !strings.HasPrefix(sec, pfx+".") {
			continue
		}
		if len(pfx) > len(best) {
			best, val = pfx, a
		}
	}
	if best == "" {
		return "", false, false
	}
	if val == nil {
		return "", false, true
	}
	return *val, true, true
}

// isCommandTable reports whether a table is a command-code registry,
// e.g. TS 29.229 Table 6.1.1 "Command-Code values":
//
//	Command-Name | Abbreviation | Code | Clause
//	User-Authorization-Request | UAR | 300 | 6.1.1
func isCommandTable(t *table) bool {
	var b strings.Builder
	for i, r := range t.rows {
		if i == 3 {
			break
		}
		b.WriteString(normCell(strings.Join(r, "|")))
		b.WriteByte(' ')
	}
	h := b.String()
	return strings.Contains(h, "command name") && strings.Contains(h, "code")
}

// commandsFromTable reads a command-code table. The "-Request"/"-Answer"
// suffix is dropped so one entry covers the pair, matching the
// DIAM_CMD_* convention.
func commandsFromTable(t *table, appName string) []*Command {
	var out []*Command
	seen := map[uint32]bool{}
	for _, r := range t.rows {
		var name string
		var code uint32
		found := false
		for _, c := range r {
			c = strings.TrimSpace(c)
			if c == "" {
				continue
			}
			if name == "" {
				if skipName.MatchString(normCell(c)) || normCell(c) == "command name" {
					break
				}
				name = c
				continue
			}
			if intRe.MatchString(c) {
				code = uint32(atoiSafe(c))
				found = true
				break
			}
		}
		if !found || code < 256 {
			continue
		}
		name = reqAnsSuffixRe.ReplaceAllString(name, "")
		if name == "" || seen[code] {
			continue
		}
		seen[code] = true
		out = append(out, &Command{Name: name, Code: code, App: appName})
	}
	return out
}

// extract3GPP reads one spec's registries, command codes and Enumerated
// values.
func extract3GPP(src *specSource, raw []byte, warn func(string, ...any)) ([]*AVP, []*Command, error) {
	doc, err := parseDocx(src.file(), raw)
	if err != nil {
		return nil, nil, err
	}

	// Enumerated values first, so the registry rows can pick them up.
	enums := map[string][]*Enum{}
	for _, s := range doc.sections {
		if len(src.enumSections) > 0 {
			want := false
			for _, pfx := range src.enumSections {
				if s.num == pfx || strings.HasPrefix(s.num, pfx+".") {
					want = true
					break
				}
			}
			if !want {
				continue
			}
		}
		for name, vals := range enumsFromSection(s, warn) {
			if _, dup := enums[name]; !dup {
				enums[name] = vals
			}
		}
	}

	var out []*AVP
	var cmds []*Command
	nreg := 0
	for _, t := range doc.tables {
		if isCommandTable(t) {
			if a, selected, ok := src.appFor(t.section); ok && selected {
				cmds = append(cmds, commandsFromTable(t, a)...)
			} else if !ok {
				// Command tables sit outside the AVP subclauses (TS
				// 29.229 §6.1 vs §6.3), so fall back to the spec's
				// primary application rather than dropping them.
				cmds = append(cmds, commandsFromTable(t, src.primaryApp)...)
			}
			continue
		}
		if !isRegistryTable(t) {
			continue
		}
		appName, selected, ok := src.appFor(t.section)
		if !ok {
			warn("TS %s: registry table in §%s (caption %q) matches no section rule; skipped",
				src.num, t.section, t.caption)
			continue
		}
		if !selected {
			continue
		}
		nreg++
		for _, r := range t.rows {
			row := parseRegRow(r)
			if row == nil {
				continue
			}
			if skipName.MatchString(normCell(row.name)) {
				continue
			}
			if row.refer != "" {
				// The row exists but the type is defined in a spec that
				// is not pinned here (mostly the TS 29.061 GPRS
				// charging AVPs). Emitting a guessed type would be
				// worse than leaving the AVP out.
				warn("TS %s: avp %s (code %d): type %q defers to another spec; skipped",
					src.num, row.name, row.code, row.refer)
				continue
			}
			// Which registry the code belongs to. "V" in the Must column
			// says vendor space; "V" in one of the later columns (Must
			// not) says IETF space, which is how TS 32.299 Table 7.1.0.1
			// marks the IETF AVPs charging reuses. When the row states
			// neither — TS 32.299 Table 7.2.0.1 truncates the flag
			// columns for 3GPP-OC-Rating-Group and its neighbours — the
			// registry's own scope decides, which is exactly what its
			// title asserts ("3GPP specific AVPs").
			vendorID := uint32(0)
			vendor := ""
			switch {
			case hasFlag(row.must, 'V'):
				vendorID, vendor = 10415, "3GPP"
			case anyHasFlag(row.rest, 'V'):
				// explicitly not a vendor AVP
			case appName != "Base":
				vendorID, vendor = 10415, "3GPP"
			}
			a := &AVP{
				Name:      row.name,
				Code:      row.code,
				Vendor:    vendor,
				VendorID:  vendorID,
				Type:      row.typ,
				Mandatory: hasFlag(row.must, 'M'),
				App:       appName,
				Src:       "TS " + src.num,
			}
			// Keyed on the normalised name: the prose that carries the
			// values does not always spell the AVP exactly as the
			// registry row does.
			if vals, ok := enums[normCell(row.name)]; ok {
				a.Enums = vals
			}
			out = append(out, a)
		}
	}
	if nreg == 0 {
		return nil, nil, fmt.Errorf("TS %s: no registry table found", src.num)
	}
	return out, cmds, nil
}
