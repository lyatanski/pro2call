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
	specDoc     = "RFC 6733; 3GPP TS 29.229 (Cx), TS 29.214 (Rx), TS 32.299 (Ro/Rf)"
	specRelease = "wireshark master 2026-07" // dict/ snapshot tag
)

// Parse order; later files cannot redefine an (app, code, vendor) the
// earlier ones already claimed.
var dictOrder = []string{"dictionary.xml", "chargecontrol.xml", "TGPP.xml"}

// Applications to keep: "base" for the RFC 6733 registry (which also
// carries the TS 32.299 charging AVPs in the dictionary) or a decimal
// application id. Gq is selected because the dictionaries define the
// 500-series media AVPs that Rx reuses (TS 29.214 §5.3) under the Gq
// application.
var selectApps = []string{"base", "3", "4", "16777216", "16777222", "16777236"}

var appComments = map[string]string{
	"Base":            "RFC 6733 base protocol",
	"Base-Accounting": "RFC 6733 accounting; Rf offline charging (TS 32.299) runs here",
	"Credit-Control":  "RFC 4006 DCCA; Ro online charging (TS 32.299) runs here",
	"Cx":              "IMS CSCF-HSS interface, TS 29.229",
	"Gq":              "TS 29.209; defines the media AVPs Rx reuses",
	"Rx":              "AF-PCRF interface, TS 29.214",
}

// Commands the selected applications use but the dictionaries define
// elsewhere: AA (RFC 7155) is reused by Rx (TS 29.214 §5.6) while the
// dictionaries keep it in their NASREQ file.
var extraCommands = []*Command{
	{Name: "AA", Code: 265, App: "Rx"},
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
