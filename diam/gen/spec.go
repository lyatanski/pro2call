package main

import (
	"regexp"
	"strings"
)

// Spec is the resolved Diameter profile the templates render: the AVP
// registry, application ids and command codes extracted from the
// dictionary files, plus the curation applied in curate() (main.go).
type Spec struct {
	Doc     string // "RFC 6733; 3GPP TS 29.229, ..."
	Release string // dictionary snapshot tag

	Vendors  []*Vendor
	Apps     []*App
	Commands []*Command
	AVPs     []*AVP
}

// Vendor is one SMI enterprise number referenced by vendor AVPs.
type Vendor struct {
	Name string // "3GPP"
	ID   uint32 // 10415
}

// App is one Diameter application id.
type App struct {
	Name    string // "Cx"
	CName   string // C enum stem; derived from Name if empty
	ID      uint32 // 16777216
	Comment string
}

// Command is one command code (one entry covers the request/answer pair).
type Command struct {
	Name string // "User-Authorization"
	Code uint32 // 300
	App  string // owning app name, informative
}

// Enum is one Enumerated value.
type Enum struct {
	Name  string
	CName string
	Value int64
}

// AVP is one registry entry, keyed by (code, vendor).
type AVP struct {
	Name      string
	CName     string
	Code      uint32
	Vendor    string // vendor Name; "" = standard
	VendorID  uint32
	Type      string // one of Types
	Mandatory bool   // spec says the M bit must be set
	App       string // defining app, informative
	Enums     []*Enum
}

// Types is the canonical AVP data-type set (RFC 6733 §4.2/§4.3). The
// order is meaningful: it defines the diam_avp_type_t enum values.
var Types = []string{
	"OctetString",
	"Integer32",
	"Integer64",
	"Unsigned32",
	"Unsigned64",
	"Float32",
	"Float64",
	"Grouped",
	"Enumerated",
	"UTF8String",
	"DiameterIdentity",
	"DiameterURI",
	"Address",
	"Time",
	"IPFilterRule",
	"QoSFilterRule",
}

// typeEnum maps a canonical type name to its C enum stem:
// "UTF8String" -> "UTF8_STRING" (rendered as DIAM_TYPE_UTF8_STRING).
func typeEnum(t string) string {
	switch t {
	case "OctetString":
		return "OCTET_STRING"
	case "UTF8String":
		return "UTF8_STRING"
	case "DiameterIdentity":
		return "IDENTITY"
	case "DiameterURI":
		return "URI"
	case "IPFilterRule":
		return "IP_FILTER_RULE"
	case "QoSFilterRule":
		return "QOS_FILTER_RULE"
	default:
		return strings.ToUpper(t)
	}
}

var nonIdent = regexp.MustCompile(`[^A-Za-z0-9]+`)

// deriveCName turns a dictionary name into an upper-snake C enum stem:
// "CC-Request-Type" -> "CC_REQUEST_TYPE", "3GPP-RAT-Type" -> "3GPP_RAT_TYPE"
// (always used behind a DIAM_ prefix, so a leading digit is fine).
func deriveCName(name string) string {
	var out []string
	for _, p := range nonIdent.Split(name, -1) {
		if p != "" {
			out = append(out, strings.ToUpper(p))
		}
	}
	return strings.Join(out, "_")
}
