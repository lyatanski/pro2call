package main

// WordprocessingML reading for the 3GPP specifications under specs/.
// A .docx is a ZIP whose word/document.xml holds the body; the
// registry tables (<w:tbl>) carry the AVP codes, types and flag rules,
// and the Enumerated values live in the body text of the AVP's own
// subclause.
//
// Two details differ from gtp/gen's reader and matter here:
//
//   - Tabs and line breaks are kept as separators. TS 32.299 writes its
//     Enumerated values as "0<tab>ORIGINATING_ROLE"; dropping the tab
//     (as gtp/gen deliberately does) glues a whole value list into one
//     unparseable run: "0S-CSCF1P-CSCF2I-CSCF3MRFC".
//   - Horizontally merged cells are expanded via <w:gridSpan>, so every
//     row of a table has the same column count. The registry tables put
//     their column labels in merged header cells ("AVP Flag rules"
//     spanning Must/May/Should not/Must not), and without expansion the
//     header indices do not line up with the data rows.

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// section is one numbered subclause: its heading plus the body
// paragraphs up to the next heading.
type section struct {
	num   string // "6.3.24"
	title string // "User-Authorization-Type AVP"
	body  []string
}

// table is one <w:tbl> with the caption id preceding it (when any) and
// the subclause it sits in.
type table struct {
	caption string     // "6.3.0.1", "" when the table has no caption
	section string     // enclosing subclause number
	rows    [][]string // cell text, row-major, gridSpan-expanded
}

// document is one parsed .docx.
type document struct {
	tables   []*table
	sections []*section
}

// findSection returns the subclause with the given number.
func (d *document) findSection(num string) *section {
	for _, s := range d.sections {
		if s.num == num {
			return s
		}
	}
	return nil
}

// XML shapes. Struct tags use local names, which encoding/xml matches
// regardless of the w: namespace prefix.
// xVal is any WordprocessingML element carrying only a w:val attribute
// (<w:pStyle w:val="Heading3"/>, <w:gridSpan w:val="4"/>).
type xVal struct {
	Val string `xml:"val,attr"`
}
type xPara struct {
	Style *xVal  `xml:"pPr>pStyle"`
	Inner string `xml:",innerxml"`
}
type xCell struct {
	GridSpan *xVal   `xml:"tcPr>gridSpan"`
	Paras    []xPara `xml:"p"`
	Inner    string  `xml:",innerxml"`
}
type xRow struct {
	Cells []xCell `xml:"tc"`
}
type xTable struct {
	Rows []xRow `xml:"tr"`
}

var (
	// A <w:t> text run. Kept deliberately narrow so it does not match
	// <w:tab> or a nested <w:tbl>.
	runRe = regexp.MustCompile(`(?s)<w:t(?: [^>]*)?>(.*?)</w:t>`)
	// Separators that carry meaning inside a paragraph: a tab column
	// and a soft line break both delimit fields in the spec tables.
	sepRe = regexp.MustCompile(`<w:(?:tab|br)\b[^>]*/?>`)

	captionRe = regexp.MustCompile(`^Table\s+([0-9][0-9A-Za-z.\-]*)\s*:`)
	// A subclause heading: "6.3.24 User-Authorization-Type AVP". The
	// number may carry a release letter ("5a.3.1" in TS 29.212).
	headingRe = regexp.MustCompile(`^(\d+[0-9a-z]*(?:\.\d+)*)\s*(.*)$`)
)

// paraText is all of a paragraph's text with tabs and breaks preserved
// as "\t". Runs are sometimes nested in <w:hyperlink>/<w:ins>, so every
// <w:t> at any depth is gathered.
func paraText(inner string) string {
	// Mark the separators first so they survive the run extraction.
	marked := sepRe.ReplaceAllString(inner, "<w:t>\t</w:t>")
	var b strings.Builder
	for _, m := range runRe.FindAllStringSubmatch(marked, -1) {
		b.WriteString(m[1])
	}
	// Word writes non-breaking spaces into the spec tables ("NOTE 2");
	// fold them so column labels compare as plain text.
	s := strings.ReplaceAll(unescapeXML(b.String()), " ", " ")
	return strings.TrimSpace(s)
}

// unescapeXML resolves the five predefined entities. &amp; is resolved
// last so "&amp;lt;" yields "&lt;" rather than "<".
func unescapeXML(s string) string {
	if !strings.ContainsRune(s, '&') {
		return s
	}
	for _, r := range [][2]string{{"&lt;", "<"}, {"&gt;", ">"}, {"&quot;", `"`},
		{"&apos;", "'"}, {"&amp;", "&"}} {
		s = strings.ReplaceAll(s, r[0], r[1])
	}
	return s
}

// cellText joins a cell's paragraphs with a space.
func cellText(c *xCell) string {
	parts := make([]string, 0, len(c.Paras))
	for i := range c.Paras {
		if t := paraText(c.Paras[i].Inner); t != "" {
			parts = append(parts, t)
		}
	}
	if len(parts) == 0 {
		// A cell whose runs are not wrapped in <w:p> children we
		// decoded; fall back to the whole cell body.
		return paraText(c.Inner)
	}
	return strings.Join(parts, " ")
}

// rowCells returns one row's text with horizontal merges expanded, so
// the row has one entry per grid column.
func rowCells(r *xRow) []string {
	out := make([]string, 0, len(r.Cells))
	for i := range r.Cells {
		out = append(out, cellText(&r.Cells[i]))
		span := 1
		if gs := r.Cells[i].GridSpan; gs != nil {
			if n := atoiSafe(gs.Val); n > 1 {
				span = n
			}
		}
		for j := 1; j < span; j++ {
			out = append(out, "")
		}
	}
	return out
}

// parseDocx reads one .docx into tables and subclauses.
func parseDocx(name string, raw []byte) (*document, error) {
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	var body []byte
	for _, f := range zr.File {
		if f.Name == "word/document.xml" {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			body, err = io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			break
		}
	}
	if body == nil {
		return nil, fmt.Errorf("%s: no word/document.xml", name)
	}

	doc := &document{}
	dec := xml.NewDecoder(bytes.NewReader(body))
	var caption string
	var cur *section
	inBody := false
	for {
		tok, err := dec.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "body":
			inBody = true
		case "p":
			if !inBody {
				continue
			}
			var p xPara
			if err := dec.DecodeElement(&p, &se); err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			txt := paraText(p.Inner)
			if txt == "" {
				continue
			}
			style := ""
			if p.Style != nil {
				style = p.Style.Val
			}
			if m := captionRe.FindStringSubmatch(txt); m != nil {
				caption = m[1]
			}
			switch {
			case strings.HasPrefix(style, "Heading"):
				if m := headingRe.FindStringSubmatch(txt); m != nil {
					cur = &section{num: m[1], title: strings.TrimSpace(m[2])}
					doc.sections = append(doc.sections, cur)
				}
			case strings.HasPrefix(style, "TOC"):
				// table of contents; the same headings appear again in
				// the body, so ignore these entirely.
			case cur != nil:
				cur.body = append(cur.body, txt)
			}
		case "tbl":
			if !inBody {
				continue
			}
			var t xTable
			if err := dec.DecodeElement(&t, &se); err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			rows := make([][]string, 0, len(t.Rows))
			for i := range t.Rows {
				rows = append(rows, rowCells(&t.Rows[i]))
			}
			sec := ""
			if cur != nil {
				sec = cur.num
			}
			doc.tables = append(doc.tables, &table{caption: caption, section: sec, rows: rows})
			caption = "" // a caption applies to one table only
		}
	}
	return doc, nil
}
