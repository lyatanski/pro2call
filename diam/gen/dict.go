// Dictionary extraction: parses the machine-readable Diameter
// dictionary files maintained by the Wireshark project
// (resources/protocols/diameter), which transcribe the AVP registries
// of RFC 6733 and the 3GPP application specs (TS 29.229 Cx, TS 29.214
// Rx, TS 32.299 Ro/Rf, ...), committed under dict/.
//
// The 3GPP/ETSI spec documents themselves are .docx prose whose AVP
// tables do not carry the data type in a mechanically reliable form;
// the dictionary files are the standards' registries already
// transcribed field by field, so extraction stays a parse, not an
// interpretation. Provenance per AVP is the enclosing <application>
// (or the base registry) and is recorded in the AVP's App field.
package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Friendly names for well-known application ids; the dictionary's own
// name attribute is used for anything not listed. Base accounting (3)
// has no <application> element and is synthesized when selected.
var appNames = map[uint32]string{
	0:        "Base",
	3:        "Base-Accounting",
	4:        "Credit-Control",
	16777216: "Cx",
	16777217: "Sh",
	16777236: "Rx",
}

type xEnum struct {
	Name string
	Code int64
}

type xAvp struct {
	Name      string
	Code      uint32
	VendorKey string
	Mandatory bool
	Type      string
	Enums     []xEnum
}

type xCmd struct {
	Name string
	Code uint32
}

type xApp struct {
	ID   uint32
	Name string
	Key  string // "base" or decimal id
	Cmds []xCmd
	Avps []xAvp
}

type doc struct {
	vendors map[string]uint32 // dictionary key -> enterprise id
	vnames  map[string]string // dictionary key -> display name
	apps    []*xApp
}

// Wireshark type-name aliases -> canonical RFC 6733 types.
var typeAlias = map[string]string{
	"IPAddress":              "Address",
	"AppId":                  "Unsigned32",
	"VendorId":               "Unsigned32",
	"Integer":                "Integer32",
	"OctetStringOrUTF8":      "OctetString",
	"MIPRegistrationRequest": "OctetString",
}

func canonType(t string, warn func(string, ...any), avp string) string {
	if a, ok := typeAlias[t]; ok {
		return a
	}
	for _, k := range Types {
		if k == t {
			return t
		}
	}
	warn("avp %s: unknown type %q, using OctetString", avp, t)
	return "OctetString"
}

// The dictionary files use a DTD with custom entities to stitch the
// per-vendor files together; encoding/xml resolves neither, so strip
// the DOCTYPE block and any non-predefined entity references before
// parsing. Each input file is parsed on its own.
var entityRe = regexp.MustCompile(`&(?:[A-Za-z][A-Za-z0-9_.-]*);`)

func clean(b []byte) []byte {
	if i := bytes.Index(b, []byte("<!DOCTYPE")); i >= 0 {
		end := bytes.Index(b[i:], []byte("]>"))
		n := 2
		if end < 0 {
			end = bytes.IndexByte(b[i:], '>')
			n = 1
		}
		if end >= 0 {
			b = append(append([]byte{}, b[:i]...), b[i+end+n:]...)
		}
	}
	return entityRe.ReplaceAllFunc(b, func(m []byte) []byte {
		switch string(m) {
		case "&amp;", "&lt;", "&gt;", "&quot;", "&apos;":
			return m
		}
		return nil
	})
}

func attr(e xml.StartElement, name string) string {
	for _, a := range e.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

func parseDict(name string, raw []byte, d *doc, warn func(string, ...any)) error {
	// Files like TGPP.xml hold several top-level <application> elements
	// (they are DTD fragments, not standalone documents), so walk
	// tokens instead of unmarshalling one root.
	dec := xml.NewDecoder(bytes.NewReader(clean(raw)))
	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("%s: %w", name, err)
		}
		e, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch e.Name.Local {
		case "dictionary":
			// container; descend by continuing the token loop
		case "vendor":
			key := attr(e, "vendor-id")
			if code, err := strconv.ParseUint(attr(e, "code"), 10, 32); err == nil {
				d.vendors[key] = uint32(code)
				d.vnames[key] = attr(e, "name")
			}
			dec.Skip()
		case "base":
			if err := parseApp(dec, e, 0, "Base", d, warn); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		case "application":
			id64, err := strconv.ParseUint(attr(e, "id"), 10, 32)
			if err != nil {
				warn("%s: application with bad id %q skipped", name, attr(e, "id"))
				dec.Skip()
				continue
			}
			appName := appNames[uint32(id64)]
			if appName == "" {
				appName = strings.TrimPrefix(attr(e, "name"), "3GPP ")
			}
			if err := parseApp(dec, e, uint32(id64), appName, d, warn); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		default:
			dec.Skip()
		}
	}
}

func parseApp(dec *xml.Decoder, start xml.StartElement, id uint32,
	name string, d *doc, warn func(string, ...any)) error {

	key := "base"
	if id != 0 {
		key = strconv.FormatUint(uint64(id), 10)
	}
	var app *xApp
	for _, a := range d.apps {
		if a.Key == key {
			app = a
			break
		}
	}
	if app == nil {
		app = &xApp{ID: id, Name: name, Key: key}
		d.apps = append(d.apps, app)
	}

	for {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		switch e := tok.(type) {
		case xml.EndElement:
			if e.Name.Local == start.Name.Local {
				return nil
			}
		case xml.StartElement:
			switch e.Name.Local {
			case "command":
				if code, err := strconv.ParseUint(attr(e, "code"), 10, 32); err == nil {
					app.Cmds = append(app.Cmds, xCmd{attr(e, "name"), uint32(code)})
				} else {
					warn("command %q: bad code %q", attr(e, "name"), attr(e, "code"))
				}
				dec.Skip()
			case "vendor":
				vkey := attr(e, "vendor-id")
				if code, err := strconv.ParseUint(attr(e, "code"), 10, 32); err == nil {
					d.vendors[vkey] = uint32(code)
					d.vnames[vkey] = attr(e, "name")
				}
				dec.Skip()
			case "avp":
				avp, err := parseAvp(dec, e, warn)
				if err != nil {
					return err
				}
				if avp != nil {
					app.Avps = append(app.Avps, *avp)
				}
			default:
				dec.Skip()
			}
		}
	}
}

func parseAvp(dec *xml.Decoder, start xml.StartElement,
	warn func(string, ...any)) (*xAvp, error) {

	name := attr(start, "name")
	code64, err := strconv.ParseUint(attr(start, "code"), 10, 32)
	if err != nil {
		warn("avp %q: bad code %q, skipped", name, attr(start, "code"))
		dec.Skip()
		return nil, nil
	}
	avp := &xAvp{
		Name:      name,
		Code:      uint32(code64),
		VendorKey: attr(start, "vendor-id"),
		Mandatory: attr(start, "mandatory") == "must",
	}
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch e := tok.(type) {
		case xml.EndElement:
			if e.Name.Local == start.Name.Local {
				return avp, nil
			}
		case xml.StartElement:
			switch e.Name.Local {
			case "type":
				avp.Type = attr(e, "type-name")
				dec.Skip()
			case "grouped":
				avp.Type = "Grouped"
				dec.Skip()
			case "enum":
				v, err := strconv.ParseInt(attr(e, "code"), 0, 64)
				if err != nil {
					warn("avp %s: enum %q has bad code %q", name,
						attr(e, "name"), attr(e, "code"))
				} else {
					avp.Enums = append(avp.Enums, xEnum{attr(e, "name"), v})
				}
				dec.Skip()
			default:
				dec.Skip()
			}
		}
	}
}

// extract parses the embedded dictionary files and assembles the
// selected profile.
func extract(dicts map[string][]byte, order []string, selectApps,
	enumAVPs []string, warn func(string, ...any)) (*Spec, error) {

	d := &doc{vendors: map[string]uint32{}, vnames: map[string]string{}}
	d.vendors["None"] = 0
	for _, name := range order {
		if err := parseDict(name, dicts[name], d, warn); err != nil {
			return nil, err
		}
	}

	selected := func(key string) bool {
		for _, s := range selectApps {
			if s == key {
				return true
			}
		}
		return false
	}
	keepEnums := func(avp string) bool {
		for _, s := range enumAVPs {
			if s == avp {
				return true
			}
		}
		return false
	}

	res := &Spec{}

	// Synthesize selected well-known apps that have no element of their
	// own (base accounting), so their id constants are still emitted.
	for _, s := range selectApps {
		if id, err := strconv.ParseUint(s, 10, 32); err == nil {
			found := false
			for _, a := range d.apps {
				if a.Key == s {
					found = true
					break
				}
			}
			if !found {
				if name := appNames[uint32(id)]; name != "" {
					d.apps = append(d.apps, &xApp{ID: uint32(id), Name: name, Key: s})
				} else {
					warn("selected app %s not found in the dictionaries", s)
				}
			}
		}
	}

	sort.Slice(d.apps, func(i, j int) bool { return d.apps[i].ID < d.apps[j].ID })

	type avpKey struct {
		vendor uint32
		code   uint32
	}
	seenAvp := map[avpKey]string{}
	seenCmd := map[uint32]string{}
	seenCName := map[string]bool{}
	vendorUsed := map[string]bool{}

	appCNames := map[string]bool{}
	for _, app := range d.apps {
		if !selected(app.Key) {
			continue
		}
		a := &App{Name: app.Name, ID: app.ID, CName: deriveCName(app.Name)}
		if appCNames[a.CName] {
			a.CName = fmt.Sprintf("%s_%d", a.CName, a.ID)
			warn("app %s (id %d): name reused, C name %s", a.Name, a.ID, a.CName)
		}
		appCNames[a.CName] = true
		res.Apps = append(res.Apps, a)

		for _, c := range app.Cmds {
			if other, dup := seenCmd[c.Code]; dup {
				if other != c.Name {
					warn("command code %d: %q also defined as %q, keeping first",
						c.Code, other, c.Name)
				}
				continue
			}
			seenCmd[c.Code] = c.Name
			res.Commands = append(res.Commands, &Command{
				Name: c.Name, Code: c.Code, App: app.Name,
			})
		}

		for i := range app.Avps {
			av := &app.Avps[i]
			if av.Name == "Reserved" {
				continue // registry placeholder rows
			}
			vid, ok := d.vendors[av.VendorKey]
			if av.VendorKey != "" && !ok {
				warn("avp %s: unknown vendor key %q, skipped", av.Name, av.VendorKey)
				continue
			}
			k := avpKey{vid, av.Code}
			if other, dup := seenAvp[k]; dup {
				if other != av.Name {
					warn("avp code %d vendor %d: %q also defined as %q, keeping first",
						av.Code, vid, other, av.Name)
				}
				continue
			}
			seenAvp[k] = av.Name

			var vendor string
			if vid != 0 {
				vendor = d.vnames[av.VendorKey]
				if vendor == "" {
					vendor = av.VendorKey
				}
				vendorUsed[vendor] = true
			}
			out := &AVP{
				Name:      av.Name,
				Code:      av.Code,
				Vendor:    vendor,
				VendorID:  vid,
				Type:      canonType(av.Type, warn, av.Name),
				Mandatory: av.Mandatory,
				App:       app.Name,
			}
			// Distinct AVPs occasionally share a name across vendors
			// (or the base file repeats a vendor AVP under another
			// code); keep C names unique by suffixing the code.
			out.CName = deriveCName(out.Name)
			if seenCName[out.CName] {
				out.CName = fmt.Sprintf("%s_%d", out.CName, out.Code)
				warn("avp %s (code %d, vendor %q): name reused, C name %s",
					out.Name, out.Code, vendor, out.CName)
			}
			seenCName[out.CName] = true
			if len(av.Enums) > 0 {
				if out.Type != "Enumerated" && out.Type != "Unsigned32" &&
					out.Type != "Integer32" {
					warn("avp %s: enums on type %s", av.Name, out.Type)
				}
				if keepEnums(av.Name) {
					seenEnum := map[string]int64{}
					for _, e := range av.Enums {
						cname := deriveCName(e.Name)
						if prev, dup := seenEnum[cname]; dup {
							if prev != e.Code {
								warn("avp %s: enum name %q reused for %d and %d, keeping first",
									av.Name, e.Name, prev, e.Code)
							}
							continue
						}
						seenEnum[cname] = e.Code
						out.Enums = append(out.Enums,
							&Enum{Name: e.Name, CName: cname, Value: e.Code})
					}
				}
			}
			res.AVPs = append(res.AVPs, out)
		}
	}

	// Vendors actually referenced, by id.
	for key, name := range d.vnames {
		if vendorUsed[name] {
			res.Vendors = append(res.Vendors, &Vendor{Name: name, ID: d.vendors[key]})
		}
	}
	sort.Slice(res.Vendors, func(i, j int) bool { return res.Vendors[i].ID < res.Vendors[j].ID })

	sort.Slice(res.Commands, func(i, j int) bool { return res.Commands[i].Code < res.Commands[j].Code })
	sort.Slice(res.AVPs, func(i, j int) bool {
		vi, vj := res.AVPs[i].Vendor, res.AVPs[j].Vendor
		if vi != vj {
			return vi < vj
		}
		return res.AVPs[i].Code < res.AVPs[j].Code
	})
	return res, nil
}
