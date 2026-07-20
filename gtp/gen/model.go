package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Model is the fully resolved view of a Spec that templates render from.
// Every IE is a zero-copy "view" (opaque value bytes); the generator no
// longer curates typed scalars, sub-structs, grouped structs or masks —
// the wire value of each IE is exposed verbatim and the caller decodes
// it. The registry join, enum names, decode-dispatch grouping and the
// mandatory-check expressions are precomputed here so the templates stay
// declarative.
type Model struct {
	Spec *Spec
	P    string // C prefix, lower: "gtp2"
	U    string // C prefix, upper: "GTP2"

	Messages []*Msg

	// gtp1 self-contained enums (gtp2 borrows its IE/MT namespace from
	// the hand-written base headers, so it emits raw values instead).
	IEs   []*IE     // registry, sorted by type (IE enum + TV table)
	MTs   []MT      // message-type enum entries, deduplicated by value
	TVLen []TVEntry // fixed value lengths for TV IEs

	ies map[string]*IE
}

type MT struct {
	Enum string
	Val  uint16
}

type TVEntry struct {
	Type  uint16
	Len   int
	CName string
}

// Msg is one message.
type Msg struct {
	M       *Message
	Stem    string // create_session_request
	CType   string // gtp2_create_session_request_t
	MTEnum  string // "GTP1_MT_ECHO_REQUEST" (gtp1) or the raw value "32" (gtp2)
	NoTeid  bool
	Flds    []*Fld
	Cases   []*DecCase
	EncPre  []string // encode preconditions: C conditions yielding E_MISSING
	DecMiss string   // decode-time missing-mandatory condition ("" if none)
	OccVars []string // gtp1: occurrence-counter variable names
}

// Fld is one IE occurrence resolved against the registry. P/U/V are baked
// in so template blocks can reference the C prefix and the enclosing
// struct variable ("m" in message functions, rebound to "out" in the
// decode case bodies via the withvar helper) without extra context.
type Fld struct {
	IE *IE

	P, U, V string // c prefix lower/upper; enclosing variable name
	W       string // wbuf expression: "&w" in messages

	Field    string
	IEEnum   string // "GTP1_IE_FTEID" (gtp1) or the raw value "87" (gtp2)
	IEName   string // registry name, for a comment next to a raw value
	Kind     string // always "view"
	Presence string
	M        bool // mandatory
	Instance int
	TV       bool // gtp1: TV-format IE
	FixedLen int  // gtp1 TV value length
	Comment  string
}

// DecCase groups the message fields that share one wire IE type: the body
// of one case label in the decode switch.
type DecCase struct {
	IEEnum string
	IEName string
	Flds   []*Fld // spec/table order
	OccVar string // gtp1: occurrence counter variable ("" if single)
	DV     string // decode output variable: always "out"
}

// build resolves a Spec into a Model.
func build(spec *Spec) (*Model, error) {
	m := &Model{
		Spec: spec,
		P:    spec.Protocol,
		U:    strings.ToUpper(spec.Protocol),
		ies:  make(map[string]*IE, len(spec.IEs)),
	}
	for _, ie := range spec.IEs {
		if ie.CName == "" {
			ie.CName = deriveCName(ie.Name)
		}
		m.ies[ie.Name] = ie
	}

	for _, im := range spec.Messages {
		msg := &Msg{
			M:      im,
			Stem:   im.Short,
			CType:  fmt.Sprintf("%s_%s_t", m.P, im.Short),
			MTEnum: m.mtEnum(im),
			NoTeid: im.NoTeid,
		}
		for _, r := range im.Rows {
			f, err := m.buildFld(r)
			if err != nil {
				return nil, fmt.Errorf("message %s: %w", im.Name, err)
			}
			msg.Flds = append(msg.Flds, f)
		}
		msg.Cases = m.buildCases(msg.Flds, spec.Protocol == "gtp1")
		msg.EncPre = encPre(msg.Flds)
		msg.DecMiss = decMiss(msg.Flds, "out")
		for _, c := range msg.Cases {
			if c.OccVar != "" {
				msg.OccVars = append(msg.OccVars, c.OccVar)
			}
		}
		m.Messages = append(m.Messages, msg)
	}

	// gtp1: registry-wide artifacts (self-contained IE / MT enums + the
	// TV-length table the iterator needs to skip unknown TV IEs).
	if spec.Protocol == "gtp1" {
		m.IEs = append(m.IEs, spec.IEs...)
		sort.Slice(m.IEs, func(i, j int) bool { return m.IEs[i].Type < m.IEs[j].Type })
		for _, ie := range m.IEs {
			if ie.FixedLen > 0 && ie.Type < 128 {
				m.TVLen = append(m.TVLen, TVEntry{ie.Type, ie.FixedLen, ie.CName})
			}
		}
		seen := map[uint16]bool{}
		for _, msg := range m.Messages {
			if !seen[msg.M.Type] {
				seen[msg.M.Type] = true
				m.MTs = append(m.MTs, MT{msg.MTEnum, msg.M.Type})
			}
		}
	}
	return m, nil
}

// ieEnum returns the C reference for an IE's wire type: a self-contained
// enum name for gtp1, the raw numeric value for gtp2 (whose IE namespace
// is owned by the hand-written base header).
func (m *Model) ieEnum(ie *IE) string {
	if m.P == "gtp1" {
		return fmt.Sprintf("%s_IE_%s", m.U, ie.CName)
	}
	return strconv.Itoa(int(ie.Type))
}

func (m *Model) mtEnum(msg *Message) string {
	if m.P == "gtp1" {
		return fmt.Sprintf("%s_MT_%s", m.U, deriveCName(msg.Name))
	}
	return strconv.Itoa(int(msg.Type))
}

func (m *Model) buildFld(r *Row) (*Fld, error) {
	ie := m.ies[r.IE]
	if ie == nil {
		return nil, fmt.Errorf("field %s: unknown ie %q", r.Field, r.IE)
	}
	return &Fld{
		IE:       ie,
		P:        m.P,
		U:        m.U,
		V:        "m",
		W:        "&w",
		Field:    r.Field,
		IEEnum:   m.ieEnum(ie),
		IEName:   ie.Name,
		Kind:     "view",
		Presence: r.Presence,
		M:        r.Presence == M,
		Instance: r.Instance,
		TV:       ie.FixedLen > 0,
		FixedLen: ie.FixedLen,
		Comment:  r.Comment,
	}, nil
}

// buildCases groups fields by wire IE type in first-appearance order. The
// decode case bodies write to "out". ordered (gtp1) resolves repeated
// same-type IEs by their order of appearance.
func (m *Model) buildCases(flds []*Fld, ordered bool) []*DecCase {
	var cases []*DecCase
	byEnum := map[string]*DecCase{}
	for _, f := range flds {
		c := byEnum[f.IEEnum]
		if c == nil {
			c = &DecCase{IEEnum: f.IEEnum, IEName: f.IEName, DV: "out"}
			byEnum[f.IEEnum] = c
			cases = append(cases, c)
		}
		c.Flds = append(c.Flds, f)
	}
	if ordered { // gtp1: same-type fields resolved by occurrence order
		for _, c := range cases {
			if len(c.Flds) > 1 {
				c.OccVar = "occ_" + c.Flds[0].Field
			}
		}
	}
	return cases
}

// encPre returns encode-time precondition C expressions that yield
// E_MISSING when a mandatory IE view is absent.
func encPre(flds []*Fld) []string {
	var out []string
	for _, f := range flds {
		if f.M {
			out = append(out, fmt.Sprintf("!m->%s.data", f.Field))
		}
	}
	return out
}

// decMiss returns the decode-time missing-mandatory condition over the
// given output variable name.
func decMiss(flds []*Fld, v string) string {
	var terms []string
	for _, f := range flds {
		if f.M {
			terms = append(terms, fmt.Sprintf("!%s->%s.data", v, f.Field))
		}
	}
	return strings.Join(terms, " || ")
}
