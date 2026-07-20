package main

// Spec extraction: turn the relevant tables into a *Spec.
// A .docx is a ZIP whose word/document.xml holds the body;
// Tables (<w:tbl>) carry the IE registry and the per-message
// grammars, and each table's caption lives in the paragraph
// just before it. Nothing here is hand-curated: field names
// are derived from the spec's own descriptive names, IE/message
// types come straight from the registry tables.

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"html"
	"os"
	"regexp"
	"strconv"
	"strings"
	"io"
)

// ---- docx table model ----

type table struct {
	id      string     // caption id, e.g. "8.1-1" or "37"
	title   string     // caption title text
	section string     // enclosing heading number, e.g. "7.3.1"
	rows    [][]string // cell text, row-major
}

type tableSet struct {
	all  []table
	byID map[string]*table
}

func (ts *tableSet) id(id string) *table { return ts.byID[id] }

// XML shapes (WordprocessingML). Struct tags use local names, which
// encoding/xml matches regardless of the w: namespace prefix.
type xPStyle struct {
	Val string `xml:"val,attr"`
}
type xP struct {
	Style *xPStyle `xml:"pPr>pStyle"`
	Inner string   `xml:",innerxml"`
}
type xTc struct {
	Ps []xP `xml:"p"`
}
type xTr struct {
	Tcs []xTc `xml:"tc"`
}
type xTbl struct {
	Trs []xTr `xml:"tr"`
}

var (
	captionRe = regexp.MustCompile(`^Table\s+([0-9][0-9A-Za-z.\-]*)\s*:\s*(.*)$`)
	headingRe = regexp.MustCompile(`^(\d+(?:\.\d+)*)\b`)
)

// wtRe matches a <w:t> text run (but not <w:tab>/<w:tbl>).
var wtRe = regexp.MustCompile(`(?s)<w:t(?: [^>]*)?>(.*?)</w:t>`)

// pText is all of a paragraph's text, gathering every <w:t> at any depth
// (runs are sometimes nested in <w:hyperlink>/<w:ins>/<w:smartTag>).
func pText(p *xP) string {
	var b strings.Builder
	for _, m := range wtRe.FindAllStringSubmatch(p.Inner, -1) {
		b.WriteString(m[1])
	}
	return strings.TrimSpace(html.UnescapeString(b.String()))
}

func cellText(tc *xTc) string {
	parts := make([]string, 0, len(tc.Ps))
	for i := range tc.Ps {
		if t := pText(&tc.Ps[i]); t != "" {
			parts = append(parts, t)
		}
	}
	return strings.Join(parts, " ")
}

func tableRows(t *xTbl) [][]string {
	rows := make([][]string, 0, len(t.Trs))
	for i := range t.Trs {
		cells := make([]string, 0, len(t.Trs[i].Tcs))
		for j := range t.Trs[i].Tcs {
			cells = append(cells, cellText(&t.Trs[i].Tcs[j]))
		}
		rows = append(rows, cells)
	}
	return rows
}

// parseTables walks the body in document order, associating each table
// with the caption paragraph preceding it and the most recent heading.
func parseTables(doc []byte) (*tableSet, error) {
	dec := xml.NewDecoder(bytes.NewReader(doc))
	ts := &tableSet{byID: map[string]*table{}}
	var capID, capTitle, section string
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "p":
			var p xP
			if err := dec.DecodeElement(&p, &se); err != nil {
				return nil, err
			}
			txt := pText(&p)
			if txt == "" {
				continue
			}
			if m := captionRe.FindStringSubmatch(txt); m != nil {
				capID, capTitle = m[1], strings.TrimSpace(m[2])
			}
			if p.Style != nil && strings.HasPrefix(p.Style.Val, "Heading") {
				if m := headingRe.FindStringSubmatch(txt); m != nil {
					section = m[1]
				}
			}
		case "tbl":
			var t xTbl
			if err := dec.DecodeElement(&t, &se); err != nil {
				return nil, err
			}
			ts.all = append(ts.all, table{id: capID, title: capTitle, section: section, rows: tableRows(&t)})
			capID, capTitle = "", "" // caption applies to one table only
		}
	}
	for i := range ts.all {
		if id := ts.all[i].id; id != "" {
			if _, dup := ts.byID[id]; !dup {
				ts.byID[id] = &ts.all[i]
			}
		}
	}
	return ts, nil
}

// ---- shared helpers ----

var (
	nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)
	refRe    = regexp.MustCompile(`\d+\.\d+(?:\.\d+)*`)
)

// norm folds a name to a comparison key: lower-case, every run of
// non-alphanumerics collapsed to one space. So "IP-Address", "IP Address"
// and "F-TEID"/"F TEID" all compare equal.
func norm(s string) string {
	return strings.Trim(nonAlnum.ReplaceAllString(strings.ToLower(s), " "), " ")
}

// sectionRef pulls the "7.7.32" out of a cell that may also carry the IE
// name, e.g. "GSN Address 7.7.32".
func sectionRef(s string) string { return refRe.FindString(s) }

// parenAbbrev returns the parenthetical of "Long Name (ABBR)" -> "ABBR".
func parenAbbrev(s string) string {
	if i := strings.LastIndexByte(s, '('); i >= 0 {
		if j := strings.IndexByte(s[i:], ')'); j > 0 {
			return strings.TrimSpace(s[i+1 : i+j])
		}
	}
	return ""
}

// dropParen returns "Long Name (ABBR)" -> "Long Name".
func dropParen(s string) string {
	if i := strings.IndexByte(s, '('); i > 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

func atoiSafe(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// singleType parses a registry type cell that must be one integer;
// ranges ("4 to 34", "6-7") and non-numeric cells yield ok=false.
func singleType(s string) (uint16, bool) {
	s = strings.TrimSpace(s)
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > 0xffff {
		return 0, false
	}
	return uint16(n), true
}

func presence(p string) string {
	p = strings.ToUpper(strings.TrimSpace(p))
	switch {
	case strings.HasPrefix(p, "M"):
		return M
	case strings.HasPrefix(p, "C"):
		return C
	default:
		return O
	}
}

// headerRow finds the index of the row that contains all of want (as
// normalized substrings) — the grammar/registry column header.
func headerRow(rows [][]string, want ...string) int {
	for i, r := range rows {
		joined := norm(strings.Join(r, "|"))
		ok := true
		for _, w := range want {
			if !strings.Contains(joined, w) {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}

func colIndex(header []string, want string) int {
	for i, c := range header {
		if strings.Contains(norm(c), want) {
			return i
		}
	}
	return -1
}

func cell(row []string, i int) string {
	if i >= 0 && i < len(row) {
		return strings.TrimSpace(row[i])
	}
	return ""
}

// uniqueFields disambiguates repeated derived field names within one
// message (e.g. the four gtp1 "GSN Address" rows): field, field_2, ...
func uniqueFields(rows []*Row) {
	seen := map[string]int{}
	for _, r := range rows {
		if r.Field == "" {
			r.Field = "field"
		}
		n := seen[r.Field]
		seen[r.Field]++
		if n > 0 {
			r.Field = fmt.Sprintf("%s_%d", r.Field, n+1)
		}
	}
}

// uniqueCNames disambiguates colliding IE enum stems in the registry.
func uniqueCNames(ies []*IE) {
	seen := map[string]int{}
	for _, ie := range ies {
		n := seen[ie.CName]
		seen[ie.CName]++
		if n > 0 {
			ie.CName = fmt.Sprintf("%s_%d", ie.CName, n+1)
		}
	}
}

var grammarTitleRe = regexp.MustCompile(`(?i)^Information Elements?\s+in\s+(?:an?\s+|the\s+)?(.+?)\.?$`)

// ---- GTPv2 (TS 29.274) ----

func extractGTP2(ts *tableSet, ver string) (*Spec, error) {
	reg := ts.id("8.1-1")
	if reg == nil {
		return nil, fmt.Errorf("IE registry Table 8.1-1 not found")
	}
	ies, lookup := gtp2Registry(reg)

	mtt := ts.id("6.1-1")
	if mtt == nil {
		return nil, fmt.Errorf("message-type Table 6.1-1 not found")
	}
	names, byName := messageTypes(mtt, "message type", "message")

	spec := &Spec{IEs: ies}
	used := map[uint16]bool{}
	for i := range ts.all {
		t := &ts.all[i]
		m := grammarTitleRe.FindStringSubmatch(t.title)
		if m == nil {
			continue
		}
		mt, ok := matchMessage(m[1], names, byName)
		if !ok {
			continue // a grouped-IE sub-table or an unlisted message
		}
		if used[mt.typ] {
			fmt.Fprintf(os.Stderr, "gtp2: %q: message type %d already has a grammar; skipping\n", t.title, mt.typ)
			continue
		}
		used[mt.typ] = true
		msg := &Message{
			Name:    mt.name,
			Short:   deriveField(mt.name),
			Type:    mt.typ,
			Section: strings.SplitN(t.id, "-", 2)[0],
			NoTeid:  mt.typ <= 3, // Echo Req/Rsp, Version Not Supported carry no TEID
			Rows:    gtp2Rows(t, lookup),
		}
		spec.Messages = append(spec.Messages, msg)
	}
	if len(spec.Messages) == 0 {
		return nil, fmt.Errorf("no GTPv2 message grammars extracted")
	}
	return spec, nil
}

func gtp2Registry(reg *table) ([]*IE, map[string]*IE) {
	var ies []*IE
	lookup := map[string]*IE{}
	add := func(key string, ie *IE) {
		if key = norm(key); key != "" {
			if _, ok := lookup[key]; !ok {
				lookup[key] = ie
			}
		}
	}
	for _, r := range reg.rows[1:] {
		typ, ok := singleType(cell(r, 0))
		if !ok {
			continue
		}
		name := cell(r, 1)
		if name == "" || strings.HasPrefix(name, "Reserved") || strings.HasPrefix(name, "Spare") {
			continue
		}
		ie := &IE{Name: name, Type: typ, CName: deriveCName(name), Comment: cell(r, 2)}
		ies = append(ies, ie)
		add(name, ie)
		add(dropParen(name), ie)
		add(parenAbbrev(name), ie)
	}
	return ies, lookup
}

func gtp2Rows(t *table, lookup map[string]*IE) []*Row {
	h := headerRow(t.rows, "ie type")
	if h < 0 {
		return nil
	}
	nameCol := 0
	pCol := colIndex(t.rows[h], "p")
	ieCol := colIndex(t.rows[h], "ie type")
	insCol := colIndex(t.rows[h], "ins")

	var rows []*Row
	for _, r := range t.rows[h+1:] {
		ieName := cell(r, ieCol)
		if ieName == "" {
			continue // continuation condition line for the row above
		}
		ie := lookup[norm(ieName)]
		if ie == nil {
			ie = lookup[norm(dropParen(ieName))]
		}
		if ie == nil {
			// fall back to the abbreviation, robust against a mismatch
			// (or typo) in the registry's long name.
			ie = lookup[norm(parenAbbrev(ieName))]
		}
		if ie == nil {
			fmt.Fprintf(os.Stderr, "gtp2: %q: unknown IE %q; skipping row\n", t.title, ieName)
			continue
		}
		disp := cell(r, nameCol)
		if disp == "" {
			disp = ie.Name
		}
		rows = append(rows, &Row{
			IE:       ie.Name,
			Field:    deriveField(disp),
			Presence: presence(cell(r, pCol)),
			Instance: atoiSafe(cell(r, insCol)),
		})
	}
	uniqueFields(rows)
	return rows
}

// ---- GTPv1 (TS 29.060) ----

func extractGTP1(ts *tableSet, ver string) (*Spec, error) {
	reg := ts.id("37")
	if reg == nil {
		return nil, fmt.Errorf("IE registry Table 37 not found")
	}
	ies, byRef, byName := gtp1Registry(reg)

	mtt := ts.id("1")
	if mtt == nil {
		return nil, fmt.Errorf("message Table 1 not found")
	}
	names, byMsg := messageTypes(mtt, "message", "message")

	spec := &Spec{IEs: ies}
	used := map[uint16]bool{}
	for i := range ts.all {
		t := &ts.all[i]
		m := grammarTitleRe.FindStringSubmatch(t.title)
		if m == nil {
			continue
		}
		mt, ok := matchMessage(m[1], names, byMsg)
		if !ok {
			continue
		}
		if used[mt.typ] {
			fmt.Fprintf(os.Stderr, "gtp1: %q: message type %d already has a grammar; skipping\n", t.title, mt.typ)
			continue
		}
		used[mt.typ] = true
		sec := mt.section
		if !headingRe.MatchString(sec) || !strings.Contains(sec, ".") {
			sec = t.section
		}
		msg := &Message{
			Name:    mt.name,
			Short:   deriveField(mt.name),
			Type:    mt.typ,
			Section: sec,
			Rows:    gtp1Rows(t, byRef, byName),
		}
		spec.Messages = append(spec.Messages, msg)
	}
	if len(spec.Messages) == 0 {
		return nil, fmt.Errorf("no GTPv1 message grammars extracted")
	}
	return spec, nil
}

func gtp1Registry(reg *table) (ies []*IE, byRef, byName map[string]*IE) {
	byRef = map[string]*IE{}
	byName = map[string]*IE{}
	for _, r := range reg.rows[1:] {
		typ, ok := singleType(cell(r, 0))
		if !ok {
			continue
		}
		format := strings.ToUpper(cell(r, 1))
		name := cell(r, 2)
		if name == "" || strings.HasPrefix(name, "Reserved") || strings.HasPrefix(name, "Spare") {
			continue
		}
		ref := sectionRef(cell(r, 3))
		ie := &IE{Name: name, Type: typ, CName: deriveCName(name)}
		if ref != "" {
			ie.Comment = "§" + ref
		}
		if format == "TV" {
			ie.FixedLen = atoiSafe(cell(r, 5))
		}
		ies = append(ies, ie)
		if k := norm(ref); k != "" {
			byRef[k] = ie
		}
		for _, key := range []string{name, dropParen(name), parenAbbrev(name)} {
			if k := norm(key); k != "" {
				if _, dup := byName[k]; !dup {
					byName[k] = ie
				}
			}
		}
	}
	uniqueCNames(ies)
	return ies, byRef, byName
}

func gtp1Rows(t *table, byRef, byName map[string]*IE) []*Row {
	h := headerRow(t.rows, "presence")
	if h < 0 {
		h = 0
	}
	nameCol := 0
	pCol := colIndex(t.rows[h], "presence")
	refCol := colIndex(t.rows[h], "reference")

	var rows []*Row
	for _, r := range t.rows[h+1:] {
		name := cell(r, nameCol)
		if name == "" || strings.HasPrefix(name, "NOTE") {
			continue
		}
		ref := sectionRef(cell(r, refCol))
		ie := byRef[norm(ref)]
		if ie == nil {
			ie = byName[norm(name)]
		}
		if ie == nil {
			ie = byName[norm(dropParen(name))]
		}
		if ie == nil {
			fmt.Fprintf(os.Stderr, "gtp1: %q: unknown IE %q (ref %q); skipping row\n", t.title, name, ref)
			continue
		}
		rows = append(rows, &Row{
			IE:       ie.Name,
			Field:    deriveField(name),
			Presence: presence(cell(r, pCol)),
		})
	}
	uniqueFields(rows)
	return rows
}

// ---- message-type registry (shared) ----

type msgType struct {
	name    string
	typ     uint16
	section string
}

// messageTypes reads a message-type registry table (gtp2 Table 6.1-1 /
// gtp1 Table 1) into an ordered list plus a normalized-name index. The
// third column, when it is a subclause reference, is kept as the section.
func messageTypes(t *table, headerKey, _ string) ([]msgType, map[string]*msgType) {
	h := headerRow(t.rows, headerKey)
	if h < 0 {
		h = 0
	}
	var list []msgType
	for _, r := range t.rows[h+1:] {
		typ, ok := singleType(cell(r, 0))
		if !ok {
			continue
		}
		name := cell(r, 1)
		if name == "" || strings.HasPrefix(name, "Reserved") || strings.HasPrefix(name, "For future") {
			continue
		}
		sec := cell(r, 2)
		if !strings.Contains(sec, ".") {
			sec = ""
		}
		list = append(list, msgType{name: name, typ: typ, section: sec})
	}
	byName := make(map[string]*msgType, len(list))
	for i := range list {
		if k := norm(list[i].name); k != "" {
			if _, dup := byName[k]; !dup {
				byName[k] = &list[i]
			}
		}
	}
	return list, byName
}

// matchMessage resolves a grammar-table title's subject to a registered
// message: exact normalized name first, else the longest registered name
// that is a substring of the title (handles gtp1's "SGSN-Initiated
// Update PDP Context Request" -> "Update PDP Context Request").
func matchMessage(title string, list []msgType, byName map[string]*msgType) (*msgType, bool) {
	if mt, ok := byName[norm(title)]; ok {
		return mt, true
	}
	nt := norm(title)
	var best *msgType
	for i := range list {
		n := norm(list[i].name)
		if strings.Contains(nt, n) && (best == nil || len(n) > len(norm(best.name))) {
			best = &list[i]
		}
	}
	return best, best != nil
}
