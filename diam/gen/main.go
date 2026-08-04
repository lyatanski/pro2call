// diamgen renders the Diameter dictionary layer (application ids,
// command codes, AVP registry with types/flags/names, curated
// Enumerated values) for RFC 6733 base + 3GPP Cx / Sh / Rx / Gx /
// S6c / SGd / Ro / Rf:
//
//	go run . <out-dir>   -> <out-dir>/{inc/diam_dict.h,src/diam_dict.c}
//	go run . -diff       -> registry diff against the Wireshark dictionaries
//
// The AVP data is extracted from the specifications themselves, pinned
// under specs/: the 3GPP .docx releases (see reg3gpp.go) and the IETF
// RFCs (see rfc.go). Each source names one exact release, so the
// generated dictionary is attributable to a 3GPP release rather than to
// a third party's snapshot of one. What to keep and how to label it is
// the curation block below; the C syntax lives in templates/.
//
// The Wireshark dictionary files under dict/ are retained solely as a
// cross-check: -diff reports every AVP the two sources disagree about
// (see diff.go), and diff_test.go fails when a difference appears that
// is not already accounted for.
package main

import (
	"bytes"
	"embed"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
)

//go:embed specs dict templates
var files embed.FS

// ---- Sources ----

// The 3GPP specifications, each pinned to one version code. sections
// maps an AVP-registry subclause to the application it defines; a nil
// value marks a registry that belongs to an interface outside this
// profile and is skipped deliberately, so that a genuinely new registry
// still shows up as a warning rather than being silently dropped.
var specSources = []*specSource{
	{num: "29.229", ver: "j00", primaryApp: "Cx",
		sections: map[string]*string{"6.3": app("Cx")}, enumSections: []string{"6.3"}},
	{num: "29.329", ver: "j10", primaryApp: "Sh",
		sections: map[string]*string{
			"6.3": app("Sh"),
			// §8.3 restates the Sh AVPs used for subscription
			// notification; the registry itself is §6.3.
			"8.3": nil,
		}, enumSections: []string{"6.3"}},
	{num: "29.214", ver: "j30", primaryApp: "Rx",
		sections: map[string]*string{"5.3": app("Rx")}, enumSections: []string{"5.3"}},
	{num: "29.212", ver: "j10", primaryApp: "Gx",
		sections: map[string]*string{
			"5.3": app("Gx"),
			// Gxx, Sd and St are documented in the same spec but are
			// not part of this profile.
			"5a.3": nil, "5b.3": nil, "5c.3": nil, "5c.6": nil,
		}, enumSections: []string{"5.3"}},
	{num: "29.338", ver: "j30", primaryApp: "SGd",
		sections: map[string]*string{
			// The short-message AVPs are defined once under S6c (§5.3)
			// and reused verbatim by SGd (§6.3), TS 29.338 §6.3.
			"5.3": app("S6c"), "6.3": app("SGd"),
		}, enumSections: []string{"5.3", "6.3"}},
	{num: "32.299", ver: "j00", primaryApp: "Ro",
		sections: map[string]*string{
			// §7.1 is the IETF AVPs charging reuses (vendor id 0), §7.2
			// the 3GPP charging AVPs. Both Ro (online, RFC 4006) and Rf
			// (offline, base accounting) draw on them.
			"7.1": app("Base"), "7.2": app("Ro"),
		}, enumSections: []string{"7.1", "7.2"}},
}

// The IETF RFCs. RFC 7155's command table restates RFC 6733's, so only
// its AA command is taken (via extraCommands) and its own table skipped.
var rfcSources = []*rfcSource{
	{num: 6733, app: "Base", commandApp: "Base"},
	{num: 4006, app: "Credit-Control", commandApp: "Credit-Control"},
	// RFC 7155 is the NAS application in its own right; it is pinned
	// because Rx reuses its AA command and its access AVPs.
	{num: 7155, app: "NASREQ"},
}

// ---- Curation ----

const specDoc = "RFC 6733 base and the 3GPP Cx / Sh / Rx / Gx / S6c / SGd / Ro / Rf"

// Application ids. These are assigned identifiers rather than bulk
// registry data — a handful of numbers, each named by its own spec — so
// they are stated here with that spec beside them.
var apps = []*App{
	{Name: "Base", ID: 0, Comment: "RFC 6733 base protocol"},
	{Name: "Base-Accounting", ID: 3,
		Comment: "RFC 6733 accounting; Rf offline charging (TS 32.299) runs here"},
	{Name: "Credit-Control", ID: 4,
		Comment: "RFC 4006 DCCA; Ro online charging (TS 32.299) runs here"},
	{Name: "Cx", ID: 16777216, Comment: "IMS CSCF-HSS interface, TS 29.229"},
	{Name: "Sh", ID: 16777217, Comment: "IP-SM-GW/AS-HSS interface, TS 29.328/29.329"},
	{Name: "Rx", ID: 16777236, Comment: "AF-PCRF interface, TS 29.214"},
	{Name: "Gx", ID: 16777238, Comment: "PCEF-PCRF policy and charging control, TS 29.212"},
	{Name: "S6c", ID: 16777312, Comment: "SMSC-HSS routing info, TS 29.338"},
	{Name: "SGd", ID: 16777313, Comment: "SMS over Diameter, TS 29.338"},
}

// C-name overrides for AVPs whose spec names collide. Two applications
// each define a "User-Data" (Cx code 606, TS 29.229 §6.3.4; Sh code 702,
// TS 29.329 §6.3.4) and TS 29.212 and TS 32.299 each define a
// "3GPP-PS-Data-Off-Status" (Gx 2847, Ro 4406). Suffixing the loser with
// its code would work but makes the constant depend on which source is
// read first; naming both by interface is stable and is what the
// Wireshark dictionaries settled on too.
var cnameOverride = map[[2]uint32]string{
	{606, 10415}:  "CX_USER_DATA",
	{702, 10415}:  "SH_USER_DATA",
	{2847, 10415}: "3GPP_PS_DATA_OFF_STATUS_GX",
}

// Commands a selected application uses that its own spec does not
// tabulate: AA (RFC 7155) is reused by Rx (TS 29.214 §5.6), and RFC
// 7155's own command table only restates the base ones.
var extraCommands = []*Command{
	{Name: "AA", Code: 265, App: "Rx"},
}

// AVPs whose Enumerated values become C constants and name-table
// entries — the ones scripts actually dispatch on. Extracting every
// Enumerated value in the profile would emit tens of thousands of
// constants for no gain.
var enumAVPs = []string{
	"Result-Code", "Termination-Cause", "Disconnect-Cause",
	"Redirect-Host-Usage", "Session-Server-Failover", "Auth-Session-State",
	"Auth-Request-Type", "Re-Auth-Request-Type", "Accounting-Record-Type",
	"Accounting-Realtime-Required", "CC-Request-Type", "CC-Session-Failover",
	"CC-Unit-Type", "Check-Balance-Result", "Credit-Control-Failure-Handling",
	"Direct-Debiting-Failure-Handling", "Final-Unit-Action",
	"Multiple-Services-Indicator", "Requested-Action", "Subscription-Id-Type",
	"Tariff-Change-Usage", "User-Equipment-Info-Type", "Redirect-Address-Type",
	"User-Authorization-Type", "Server-Assignment-Type", "Reason-Code",
	"Originating-Request", "Media-Type", "Flow-Status", "Flow-Usage",
	"Specific-Action", "Abort-Cause", "AF-Signalling-Protocol",
	"Service-Info-Status", "Node-Functionality", "Role-Of-Node",
	"Reporting-Reason", "Experimental-Result-Code",
	// Gx (TS 29.212): what a PCEF sends in a CCR and dispatches on in a
	// CCA / RAR.
	"IP-CAN-Type", "RAT-Type", "Bearer-Usage", "Bearer-Operation",
	"Bearer-Control-Mode", "Network-Request-Support", "QoS-Class-Identifier",
	"Event-Trigger", "PCC-Rule-Status", "Rule-Failure-Code",
	"Pre-emption-Capability", "Pre-emption-Vulnerability", "Metering-Method",
	"Reporting-Level", "Online", "Offline", "Session-Release-Cause",
	// SGd/S6c (TS 29.338) and Sh (TS 29.328): what an IP-SM-GW sets in
	// an OFR/TFR and dispatches on in the answer. SM-Delivery-Outcome
	// itself is Grouped (TS 29.338 §5.3.3.14); the value that reports
	// the outcome is SM-Delivery-Cause.
	"SM-Delivery-Cause",
	"SM-Enumerated-Delivery-Failure-Cause", "SM-RP-MTI",
	"SM-Delivery-Not-Intended", "Serving-Node-Type",
	"User-Data-Already-Available", "Alert-Reason",
	"Data-Reference", "Subs-Req-Type",
}

// AVPs a covered application uses that none of the pinned specs define.
// Alert-Reason belongs to TS 29.272 (S6a/S6d) §7.3.83, which is not
// pinned here — pinning a 4 MB spec for one AVP would drag several
// hundred out-of-profile AVPs in with it — but the SMS emulators read it
// off an Alert-Service-Centre-Request. TS 29.272's own registry row
// spells the type "Enumerate"; the value is Enumerated.
var extraAVPs = []*AVP{
	{Name: "Alert-Reason", Code: 1434, Vendor: "3GPP", VendorID: 10415,
		Type: "Enumerated", Mandatory: true, App: "SGd", Enums: []*Enum{
			{Name: "UE_PRESENT", Value: 0},
			{Name: "UE_MEMORY_AVAILABLE", Value: 1},
		}},
}

// Enumerated values the specs do not state in a form the extraction can
// attach to an AVP. Experimental-Result-Code is an Unsigned32 whose
// values the 3GPP specs list per interface in prose that names no AVP;
// RFC 6733 §8.15 defines Termination-Cause but delegates its values to
// the IANA registry. Both are stated here with their source.
var extraEnums = map[string][]*Enum{
	// TS 29.229 §6.2
	"Experimental-Result-Code": {
		{Name: "DIAMETER_FIRST_REGISTRATION", Value: 2001},
		{Name: "DIAMETER_SUBSEQUENT_REGISTRATION", Value: 2002},
		{Name: "DIAMETER_UNREGISTERED_SERVICE", Value: 2003},
		{Name: "DIAMETER_SUCCESS_SERVER_NAME_NOT_STORED", Value: 2004},
		{Name: "DIAMETER_ERROR_USER_UNKNOWN", Value: 5001},
		{Name: "DIAMETER_ERROR_IDENTITIES_DONT_MATCH", Value: 5002},
		{Name: "DIAMETER_ERROR_IDENTITY_NOT_REGISTERED", Value: 5003},
		{Name: "DIAMETER_ERROR_ROAMING_NOT_ALLOWED", Value: 5004},
		{Name: "DIAMETER_ERROR_IDENTITY_ALREADY_REGISTERED", Value: 5005},
		{Name: "DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED", Value: 5006},
		{Name: "DIAMETER_ERROR_IN_ASSIGNMENT_TYPE", Value: 5007},
		{Name: "DIAMETER_ERROR_TOO_MUCH_DATA", Value: 5008},
		{Name: "DIAMETER_ERROR_NOT_SUPPORTED_USER_DATA", Value: 5009},
	},
	// IANA "Termination-Cause AVP Values" registry, per RFC 6733 §8.15.
	"Termination-Cause": {
		{Name: "DIAMETER_LOGOUT", Value: 1},
		{Name: "DIAMETER_SERVICE_NOT_PROVIDED", Value: 2},
		{Name: "DIAMETER_BAD_ANSWER", Value: 3},
		{Name: "DIAMETER_ADMINISTRATIVE", Value: 4},
		{Name: "DIAMETER_LINK_BROKEN", Value: 5},
		{Name: "DIAMETER_AUTH_EXPIRED", Value: 6},
		{Name: "DIAMETER_USER_MOVED", Value: 7},
		{Name: "DIAMETER_SESSION_TIMEOUT", Value: 8},
	},
}

// ---- Generation ----

func main() {
	diff := flag.Bool("diff", false,
		"report the registry diff against the Wireshark dictionaries and exit")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: diamgen [-diff] <out-dir>")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *diff {
		if err := runDiff(os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "diamgen:", err)
			os.Exit(1)
		}
		return
	}
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(flag.Arg(0)); err != nil {
		fmt.Fprintln(os.Stderr, "diamgen:", err)
		os.Exit(1)
	}
}

// warnf is the extraction warning sink.
func warnf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "  warn: "+format+"\n", a...)
}

// buildSpec extracts the profile from the pinned specifications.
func buildSpec(warn func(string, ...any)) (*Spec, error) {
	spec := &Spec{Doc: specDoc}

	var releases []string
	var avps []*AVP
	var cmds []*Command

	// The RFCs are read first because a (code, vendor) is claimed by the
	// first source that defines it, and in IETF space the RFC is the
	// definition while a 3GPP spec only records its use. TS 32.299
	// Table 7.1.0.1 ("Use Of IETF Diameter AVPs") lists
	// Acct-Multi-Session-Id as Unsigned32 where RFC 6733 §9.8.5 defines
	// it as UTF8String; reading the RFCs first keeps the definition.
	// Nothing in 3GPP vendor space is affected — the RFCs define none of
	// it — so the 29-series still owns every V-flagged AVP.
	for _, src := range rfcSources {
		raw, err := files.ReadFile("specs/" + src.file())
		if err != nil {
			return nil, err
		}
		a, c, err := extractRFC(src, raw, warn)
		if err != nil {
			return nil, err
		}
		avps = append(avps, a...)
		cmds = append(cmds, c...)
		releases = append(releases, fmt.Sprintf("RFC %d", src.num))
	}
	for _, src := range specSources {
		raw, err := files.ReadFile("specs/" + src.file())
		if err != nil {
			return nil, err
		}
		a, c, err := extract3GPP(src, raw, warn)
		if err != nil {
			return nil, err
		}
		avps = append(avps, a...)
		cmds = append(cmds, c...)
		releases = append(releases, fmt.Sprintf("TS %s v%s", src.num, src.release()))
	}
	// Hand-added AVPs go last so they yield to the specs: if a pinned
	// release starts defining one, the extracted row wins and the
	// duplicate is reported rather than emitted twice.
	for _, a := range extraAVPs {
		dup := false
		for _, have := range avps {
			if have.Code == a.Code && have.VendorID == a.VendorID {
				warn("avp %s (code %d): now defined by %s, drop it from extraAVPs",
					a.Name, a.Code, have.App)
				dup = true
				break
			}
		}
		if !dup {
			avps = append(avps, a)
		}
	}
	spec.Sources = releases

	spec.Apps = apps
	for _, a := range spec.Apps {
		if a.CName == "" {
			a.CName = deriveCName(a.Name)
		}
	}
	spec.Vendors = []*Vendor{{Name: "3GPP", ID: 10415}}

	// Commands, keyed by code. Sources are consulted in order, so the
	// spec that owns a code claims it.
	cmds = append(cmds, extraCommands...)
	seenCmd := map[uint32]*Command{}
	for _, c := range cmds {
		if prev, dup := seenCmd[c.Code]; dup {
			if prev.Name != c.Name {
				warn("command code %d: %q also extracted as %q, keeping first",
					c.Code, prev.Name, c.Name)
			}
			continue
		}
		seenCmd[c.Code] = c
		spec.Commands = append(spec.Commands, c)
	}

	// AVPs, keyed by (code, vendor). Sources are consulted in order, so
	// the defining spec wins over a later one that reuses the AVP.
	keep := map[string]bool{}
	for _, n := range enumAVPs {
		keep[n] = true
	}
	type key struct{ code, vendor uint32 }
	seen := map[key]*AVP{}
	cnames := map[string]bool{}
	for _, a := range avps {
		k := key{a.Code, a.VendorID}
		if prev, dup := seen[k]; dup {
			switch {
			case prev.Name != a.Name:
				warn("avp code %d vendor %d: %q (%s) also defined as %q by %s, keeping first",
					a.Code, a.VendorID, prev.Name, prev.Src, a.Name, a.Src)
			case prev.Type != a.Type:
				warn("avp %s (code %d vendor %d): %s says %s, %s says %s, keeping %s",
					a.Name, a.Code, a.VendorID, prev.Src, prev.Type, a.Src, a.Type, prev.Type)
			}
			if len(prev.Enums) == 0 && len(a.Enums) > 0 && keep[a.Name] {
				prev.Enums = a.Enums
			}
			continue
		}
		if !keep[a.Name] {
			a.Enums = nil
		}
		if vals, ok := extraEnums[a.Name]; ok && keep[a.Name] {
			a.Enums = mergeEnums(a.Enums, vals)
		}
		// Distinct AVPs occasionally share a name across applications or
		// vendors. Curated names come first; anything else falls back to
		// a code suffix and is reported, so a new collision is visible
		// rather than quietly order-dependent.
		a.CName = deriveCName(a.Name)
		if over, ok := cnameOverride[[2]uint32{a.Code, a.VendorID}]; ok {
			a.CName = over
		} else if cnames[a.CName] {
			a.CName = fmt.Sprintf("%s_%d", a.CName, a.Code)
			warn("avp %s (code %d, vendor %d): name reused, C name %s; "+
				"consider a cnameOverride entry", a.Name, a.Code, a.VendorID, a.CName)
		}
		cnames[a.CName] = true
		seen[k] = a
		spec.AVPs = append(spec.AVPs, a)
	}

	// Every enum value needs a C name. Extraction derives one as it goes;
	// the curated tables above state only the wire name, so fill in
	// anything still empty rather than emitting DIAM_<AVP>_ twice.
	for _, a := range spec.AVPs {
		for _, e := range a.Enums {
			if e.CName == "" {
				e.CName = deriveCName(e.Name)
			}
		}
	}

	for _, n := range enumAVPs {
		found := false
		for _, a := range spec.AVPs {
			if a.Name == n && len(a.Enums) > 0 {
				found = true
				break
			}
		}
		if !found {
			warn("enum avp %s: no Enumerated values extracted", n)
		}
	}

	sort.SliceStable(spec.Commands, func(i, j int) bool {
		return spec.Commands[i].Code < spec.Commands[j].Code
	})
	sort.SliceStable(spec.AVPs, func(i, j int) bool {
		if spec.AVPs[i].VendorID != spec.AVPs[j].VendorID {
			return spec.AVPs[i].VendorID < spec.AVPs[j].VendorID
		}
		return spec.AVPs[i].Code < spec.AVPs[j].Code
	})
	return spec, nil
}

// mergeEnums adds the curated values that extraction did not find,
// leaving any it did alone.
func mergeEnums(have, add []*Enum) []*Enum {
	seen := map[int64]bool{}
	for _, e := range have {
		seen[e.Value] = true
	}
	for _, e := range add {
		if seen[e.Value] {
			continue
		}
		if e.CName == "" {
			e.CName = deriveCName(e.Name)
		}
		have = append(have, e)
	}
	return have
}

func run(outDir string) error {
	spec, err := buildSpec(warnf)
	if err != nil {
		return err
	}
	model, err := build(spec)
	if err != nil {
		return err
	}

	root := template.New("diamgen")
	root.Funcs(template.FuncMap{
		// C string literal escaping for dictionary names.
		"cstr": func(s string) string {
			s = strings.ReplaceAll(s, `\`, `\\`)
			return strings.ReplaceAll(s, `"`, `\"`)
		},
	})
	if _, err := root.ParseFS(files, "templates/*.tmpl"); err != nil {
		return err
	}

	for _, out := range []struct{ tmpl, rel string }{
		{"diam_dict_h.tmpl", filepath.Join("inc", "diam_dict.h")},
		{"diam_dict_c.tmpl", filepath.Join("src", "diam_dict.c")},
	} {
		var b bytes.Buffer
		if err := root.ExecuteTemplate(&b, out.tmpl, model); err != nil {
			return fmt.Errorf("render %s: %w", out.tmpl, err)
		}
		path := filepath.Join(outDir, out.rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		src := append(bytes.TrimRight(b.Bytes(), "\n"), '\n')
		if err := os.WriteFile(path, src, 0o644); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "wrote", path)
	}
	fmt.Fprintf(os.Stderr, "%d AVPs, %d commands, %d applications\n",
		len(spec.AVPs), len(spec.Commands), len(spec.Apps))
	return nil
}
