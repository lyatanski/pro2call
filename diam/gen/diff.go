package main

// Cross-check of the spec-derived registry against the Wireshark
// Diameter dictionary files under dict/.
//
// The dictionaries used to be the generator's input; they are kept as an
// independent transcription of the same standards. `go run . -diff`
// prints every disagreement, and diff_test.go compares that report
// against the reviewed baseline in testdata/wireshark.diff, so a new
// disagreement — an extraction bug, or a real change in a spec — fails
// the build instead of passing silently.
//
// Differences fall into four kinds:
//
//	RENAME   both define (code, vendor) but under different names. Mostly
//	         Wireshark disambiguating with a 3GPP- prefix the specs do
//	         not use ("3GPP-SIP-Authenticate" vs "SIP-Authenticate").
//	TYPE     the data type or the M bit disagree.
//	SPEC     the specs define an AVP the dictionaries lack.
//	DICT     the dictionaries define one the pinned specs do not. Most of
//	         these are Wireshark's <base> registry, which is a grab-bag
//	         holding AVPs from specs outside this profile (S6a, T6a, 5G).

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// Wireshark dictionary parse order and the applications to take from
// it — the selection the generator used when these files were the
// input. Retained so the diff compares like with like.
var (
	dictOrder  = []string{"dictionary.xml", "chargecontrol.xml", "TGPP.xml"}
	selectApps = []string{"base", "3", "4", "16777216", "16777217", "16777222",
		"16777236", "16777238", "16777312", "16777313"}
)

// diffEntry is one disagreement.
type diffEntry struct {
	kind   string // RENAME | TYPE | SPEC | DICT
	code   uint32
	vendor uint32
	text   string
}

// runDiff writes the cross-check report.
func runDiff(w io.Writer) error {
	// The spec side, with warnings suppressed: they are the generator's
	// business, and keeping them out makes the report reproducible.
	quiet := func(string, ...any) {}
	spec, err := buildSpec(quiet)
	if err != nil {
		return err
	}

	dicts := map[string][]byte{}
	for _, name := range dictOrder {
		b, err := files.ReadFile("dict/" + name)
		if err != nil {
			return err
		}
		dicts[name] = b
	}
	ws, err := extract(dicts, dictOrder, selectApps, enumAVPs, quiet)
	if err != nil {
		return err
	}

	type key struct{ code, vendor uint32 }
	specBy := map[key]*AVP{}
	for _, a := range spec.AVPs {
		specBy[key{a.Code, a.VendorID}] = a
	}
	wsBy := map[key]*AVP{}
	for _, a := range ws.AVPs {
		wsBy[key{a.Code, a.VendorID}] = a
	}

	var out []diffEntry
	for k, sa := range specBy {
		wa, ok := wsBy[k]
		if !ok {
			out = append(out, diffEntry{"SPEC", k.code, k.vendor,
				fmt.Sprintf("%s (%s, %s, %s)", sa.Name, sa.Type, sa.App, sa.Src)})
			continue
		}
		if !sameName(sa.Name, wa.Name) {
			out = append(out, diffEntry{"RENAME", k.code, k.vendor,
				fmt.Sprintf("%s says %q, dict says %q", sa.Src, sa.Name, wa.Name)})
		}
		if sa.Type != wa.Type {
			out = append(out, diffEntry{"TYPE", k.code, k.vendor,
				fmt.Sprintf("%s: %s says %s, dict says %s", sa.Name, sa.Src, sa.Type, wa.Type)})
		}
		if sa.Mandatory != wa.Mandatory {
			out = append(out, diffEntry{"TYPE", k.code, k.vendor,
				fmt.Sprintf("%s: %s says M=%v, dict says M=%v",
					sa.Name, sa.Src, sa.Mandatory, wa.Mandatory)})
		}
	}
	for k, wa := range wsBy {
		if _, ok := specBy[k]; !ok {
			out = append(out, diffEntry{"DICT", k.code, k.vendor,
				fmt.Sprintf("%s (%s, %s)", wa.Name, wa.Type, wa.App)})
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].kind != out[j].kind {
			return out[i].kind < out[j].kind
		}
		if out[i].vendor != out[j].vendor {
			return out[i].vendor < out[j].vendor
		}
		if out[i].code != out[j].code {
			return out[i].code < out[j].code
		}
		return out[i].text < out[j].text
	})

	counts := map[string]int{}
	for _, e := range out {
		counts[e.kind]++
	}
	fmt.Fprintf(w, "# spec-derived vs Wireshark dictionary cross-check\n")
	fmt.Fprintf(w, "# spec: %d AVPs   dict: %d AVPs\n", len(spec.AVPs), len(ws.AVPs))
	fmt.Fprintf(w, "# RENAME=%d TYPE=%d SPEC=%d DICT=%d\n",
		counts["RENAME"], counts["TYPE"], counts["SPEC"], counts["DICT"])
	for _, e := range out {
		fmt.Fprintf(w, "%-6s %5d/%-5d %s\n", e.kind, e.code, e.vendor, e.text)
	}
	return nil
}

// sameName compares two dictionary names ignoring the spelling
// differences that carry no meaning: case, separator runs, and the
// 3GPP- prefix Wireshark adds to disambiguate its flat namespace.
func sameName(a, b string) bool {
	norm := func(s string) string {
		s = strings.TrimPrefix(s, "3GPP-")
		return strings.ReplaceAll(normCell(s), " ", "")
	}
	return norm(a) == norm(b)
}
