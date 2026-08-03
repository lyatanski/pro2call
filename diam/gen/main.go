// diamgen renders the Diameter dictionary layer (application ids,
// command codes, AVP registry with types/flags/names, curated
// Enumerated values) for RFC 6733 base + 3GPP Cx / Rx / Ro / Rf:
//
//	go run . <out-dir>   -> <out-dir>/{inc/diam_dict.h,src/diam_dict.c}
//
// The AVP data comes from the Wireshark project's dictionary files
// committed under dict/ (see dict.go); what to keep and how to label
// it is the curation block below. The C syntax lives in templates/.
package main

import (
	"bytes"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

//go:embed dict templates
var files embed.FS

// ---- Curation over the dictionary registries ----

const (
	specDoc = "RFC 6733; 3GPP TS 29.229 (Cx), TS 29.212 (Gx), TS 29.214 (Rx), " +
		"TS 32.299 (Ro/Rf), TS 29.328/29.329 (Sh), TS 29.338 (S6c/SGd)"
	specRelease = "wireshark master 2026-07" // dict/ snapshot tag
)

// Parse order; later files cannot redefine an (app, code, vendor) the
// earlier ones already claimed.
var dictOrder = []string{"dictionary.xml", "chargecontrol.xml", "TGPP.xml"}

// Applications to keep: "base" for the RFC 6733 registry (which also
// carries the TS 32.299 charging AVPs in the dictionary) or a decimal
// application id. Gq is selected because the dictionaries define the
// 500-series media AVPs that Rx reuses (TS 29.214 §5.3) under the Gq
// application; S6c the same way for SGd, which is a bare <application>
// element with no registry of its own — the short-message AVPs
// (SM-RP-UI, SC-Address, TFR-Flags, ...) are defined once under S6c and
// reused verbatim by SGd (TS 29.338 §6.3).
var selectApps = []string{"base", "3", "4", "16777216", "16777217", "16777222",
	"16777236", "16777238", "16777312", "16777313"}

var appComments = map[string]string{
	"Base":            "RFC 6733 base protocol",
	"Base-Accounting": "RFC 6733 accounting; Rf offline charging (TS 32.299) runs here",
	"Credit-Control":  "RFC 4006 DCCA; Ro online charging (TS 32.299) runs here",
	"Cx":              "IMS CSCF-HSS interface, TS 29.229",
	"Sh":              "IP-SM-GW/AS-HSS interface, TS 29.328/29.329",
	"Gq":              "TS 29.209; defines the media AVPs Rx reuses",
	"Rx":              "AF-PCRF interface, TS 29.214",
	"Gx":              "PCEF-PCRF policy and charging control, TS 29.212",
	"S6c":             "SMSC-HSS routing info; also the SGd AVP registry, TS 29.338",
	"SGd":             "SMS over Diameter, TS 29.338",
}

// Commands the selected applications use but the dictionaries define
// elsewhere: AA (RFC 7155) is reused by Rx (TS 29.214 §5.6) while the
// dictionaries keep it in their NASREQ file.
var extraCommands = []*Command{
	{Name: "AA", Code: 265, App: "Rx"},
}

// AVPs a selected application uses that the dictionary snapshot is
// missing outright. TS 29.338 §6.3.20 defines OFR-Flags at 3328, in the
// 3324..3328 run the Wireshark dictionary skips; an MO-Forward-Short-
// Message-Request that cannot carry it has no way to say the message
// was submitted over S6as6d. Same escape hatch as extraCommands.
var extraAVPs = []*AVP{
	{Name: "OFR-Flags", Code: 3328, Vendor: "3GPP", VendorID: 10415,
		Type: "Unsigned32", Mandatory: false, App: "S6c"},
}

// Provenance fixups for commands the dictionaries do extract, but into
// the wrong registry. The TS 29.338 commands sit in dictionary.xml's
// <base> command list, so they come out labelled "Base"; this only
// rewrites the comment the generated header carries beside each code,
// never the code itself. Appending them to extraCommands instead would
// emit the same DIAM_CMD_* constant twice.
var commandApp = map[uint32]string{
	8388645: "SGd", // MO-Forward-Short-Message
	8388646: "SGd", // MT-Forward-Short-Message
	8388647: "S6c", // Send-Routing-Info-for-SM
	8388648: "SGd", // Alert-Service-Centre
	8388649: "SGd", // Report-SM-Delivery-Status
}

// AVPs whose Enumerated values become C constants + name-table entries
// — the ones scripts actually dispatch on.
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
	// an OFR/TFR and dispatches on in the answer.
	"SM-Delivery-Outcome", "SM-Delivery-Cause",
	"SM-Enumerated-Delivery-Failure-Cause", "SM-RP-MTI",
	"SM-Delivery-Not-Intended", "Serving-Node-Type",
	"User-Data-Already-Available", "Alert-Reason",
	"Data-Reference", "Subs-Req-Type",
}

// ---- Generation ----

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: diamgen <out-dir>")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "diamgen:", err)
		os.Exit(1)
	}
}

func run(outDir string) error {
	warn := func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, "  warn: "+format+"\n", a...)
	}
	dicts := map[string][]byte{}
	for _, name := range dictOrder {
		b, err := files.ReadFile("dict/" + name)
		if err != nil {
			return err
		}
		dicts[name] = b
	}
	spec, err := extract(dicts, dictOrder, selectApps, enumAVPs, warn)
	if err != nil {
		return err
	}

	// curation: labels and out-of-profile commands
	spec.Doc, spec.Release = specDoc, specRelease
	for _, a := range spec.Apps {
		a.Comment = appComments[a.Name]
	}
	spec.Commands = append(spec.Commands, extraCommands...)
	for _, c := range spec.Commands {
		if app, ok := commandApp[c.Code]; ok {
			c.App = app
		}
	}
	// Hand-added AVPs yield to the dictionary: a later snapshot that
	// fills the gap must not produce the constant twice. build() sorts
	// the registry, so appending out of code order is fine.
	for _, a := range extraAVPs {
		dup := false
		for _, have := range spec.AVPs {
			if have.Code == a.Code && have.VendorID == a.VendorID {
				dup = true
				warn("avp %s (code %d): now in the dictionary, drop it from extraAVPs",
					a.Name, a.Code)
				break
			}
		}
		if !dup {
			a.CName = deriveCName(a.Name)
			spec.AVPs = append(spec.AVPs, a)
		}
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
	return nil
}
