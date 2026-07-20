package main

import (
	"fmt"
	"sort"
)

// Model is the fully resolved view of a Spec that templates render
// from. Everything join-like (vendor resolution, sort order for the
// binary searches, flag expressions) is precomputed here so the
// templates stay declarative.
type Model struct {
	Spec *Spec
	P    string // C prefix, lower: "diam"
	U    string // C prefix, upper: "DIAM"

	Types   []TypeEntry
	Vendors []VendorEntry
	Apps    []AppEntry
	Cmds    []CmdEntry
	Avps    []AvpEntry  // sorted by (vendor id, code) — dict table order
	Enums   []EnumGroup // AVPs with Enumerated value constants
	Values  []ValueName // flat (vendor, code, value) -> name, sorted
}

type TypeEntry struct {
	Enum    string // DIAM_TYPE_UTF8_STRING
	Name    string // "UTF8String"
	Comment string
}

type VendorEntry struct {
	Enum string // DIAM_VENDOR_3GPP
	ID   uint32
	Name string
}

type AppEntry struct {
	Enum    string // DIAM_APP_CX
	ID      uint32
	Name    string
	Comment string
}

type CmdEntry struct {
	Enum    string // DIAM_CMD_USER_AUTHORIZATION
	Code    uint32
	Name    string
	Comment string // owning app
}

type AvpEntry struct {
	Enum       string // DIAM_AVP_PUBLIC_IDENTITY
	Code       uint32
	VendorExpr string // "DIAM_VENDOR_3GPP" or "0"
	VendorID   uint32
	TypeEnum   string // DIAM_TYPE_UTF8_STRING
	FlagsExpr  string // default flags: "DIAM_AVP_F_..." composition or "0"
	Name       string
	Comment    string
}

type EnumGroup struct {
	AvpEnum string // DIAM_AVP_CC_REQUEST_TYPE
	AvpName string // "CC-Request-Type"
	Consts  []EnumConst
}

type EnumConst struct {
	Name  string // DIAM_CC_REQUEST_TYPE_INITIAL_REQUEST
	Value int64
	Wire  string // dictionary value name, for the name table
}

type ValueName struct {
	VendorID   uint32
	VendorExpr string
	Code       uint32
	Value      int64
	Name       string
}

// build resolves a Spec into a Model.
func build(spec *Spec) (*Model, error) {
	m := &Model{Spec: spec, P: "diam", U: "DIAM"}

	for _, t := range Types {
		m.Types = append(m.Types, TypeEntry{
			Enum: fmt.Sprintf("%s_TYPE_%s", m.U, typeEnum(t)),
			Name: t,
		})
	}

	vendorExpr := map[string]string{}
	for _, v := range spec.Vendors {
		e := VendorEntry{
			Enum: fmt.Sprintf("%s_VENDOR_%s", m.U, deriveCName(v.Name)),
			ID:   v.ID,
			Name: v.Name,
		}
		vendorExpr[v.Name] = e.Enum
		m.Vendors = append(m.Vendors, e)
	}

	for _, a := range spec.Apps {
		m.Apps = append(m.Apps, AppEntry{
			Enum:    fmt.Sprintf("%s_APP_%s", m.U, a.CName),
			ID:      a.ID,
			Name:    a.Name,
			Comment: a.Comment,
		})
	}

	for _, c := range spec.Commands {
		m.Cmds = append(m.Cmds, CmdEntry{
			Enum:    fmt.Sprintf("%s_CMD_%s", m.U, deriveCName(c.Name)),
			Code:    c.Code,
			Name:    c.Name,
			Comment: c.App,
		})
	}

	for _, a := range spec.AVPs {
		e := AvpEntry{
			Enum:       fmt.Sprintf("%s_AVP_%s", m.U, a.CName),
			Code:       a.Code,
			VendorID:   a.VendorID,
			VendorExpr: "0",
			TypeEnum:   fmt.Sprintf("%s_TYPE_%s", m.U, typeEnum(a.Type)),
			Name:       a.Name,
		}
		if a.App != "" && a.App != "Base" {
			e.Comment = a.App
		}
		if a.Vendor != "" {
			e.VendorExpr = vendorExpr[a.Vendor]
			if e.VendorExpr == "" {
				return nil, fmt.Errorf("avp %s: unknown vendor %q", a.Name, a.Vendor)
			}
		}
		switch {
		case a.Mandatory && a.Vendor != "":
			e.FlagsExpr = fmt.Sprintf("%s_AVP_F_VENDOR | %s_AVP_F_MANDATORY", m.U, m.U)
		case a.Mandatory:
			e.FlagsExpr = fmt.Sprintf("%s_AVP_F_MANDATORY", m.U)
		case a.Vendor != "":
			e.FlagsExpr = fmt.Sprintf("%s_AVP_F_VENDOR", m.U)
		default:
			e.FlagsExpr = "0"
		}
		m.Avps = append(m.Avps, e)

		if len(a.Enums) > 0 {
			g := EnumGroup{AvpEnum: e.Enum, AvpName: a.Name}
			for _, en := range a.Enums {
				// Enumerated is Integer32 on the wire (RFC 6733 §4.3);
				// specs occasionally write values as unsigned
				// (Media-Type OTHER = 0xFFFFFFFF), so fold into the
				// int32 domain the C constants and lookups live in.
				v := en.Value
				if v > 0x7FFFFFFF && v <= 0xFFFFFFFF {
					v = int64(int32(uint32(v)))
				}
				g.Consts = append(g.Consts, EnumConst{
					Name:  fmt.Sprintf("%s_%s_%s", m.U, a.CName, en.CName),
					Value: v,
					Wire:  en.Name,
				})
				m.Values = append(m.Values, ValueName{
					VendorID:   e.VendorID,
					VendorExpr: e.VendorExpr,
					Code:       e.Code,
					Value:      v,
					Name:       en.Name,
				})
			}
			m.Enums = append(m.Enums, g)
		}
	}

	// Dict tables are binary-searched: order by (vendor id, code) and
	// the value table additionally by value.
	sort.SliceStable(m.Avps, func(i, j int) bool {
		if m.Avps[i].VendorID != m.Avps[j].VendorID {
			return m.Avps[i].VendorID < m.Avps[j].VendorID
		}
		return m.Avps[i].Code < m.Avps[j].Code
	})
	sort.SliceStable(m.Values, func(i, j int) bool {
		if m.Values[i].VendorID != m.Values[j].VendorID {
			return m.Values[i].VendorID < m.Values[j].VendorID
		}
		if m.Values[i].Code != m.Values[j].Code {
			return m.Values[i].Code < m.Values[j].Code
		}
		return m.Values[i].Value < m.Values[j].Value
	})
	sort.SliceStable(m.Cmds, func(i, j int) bool { return m.Cmds[i].Code < m.Cmds[j].Code })
	sort.SliceStable(m.Apps, func(i, j int) bool { return m.Apps[i].ID < m.Apps[j].ID })

	return m, nil
}
