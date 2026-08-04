package main

// The Wireshark cross-check, as a test.
//
// testdata/wireshark.diff is the reviewed record of every point on which
// the spec-derived registry and the Wireshark Diameter dictionaries
// disagree. Regenerating the dictionary from a newer spec release, or
// changing the extraction, moves lines in that report; the test fails and
// prints them, so each one is looked at before it is accepted.
//
// A failure is not by itself a bug. It means one of:
//
//	an extraction change   — check the report is what you intended
//	a newer pinned spec    — the release genuinely changed the registry
//	a newer dict/ snapshot — Wireshark caught up, or drifted
//
// Once the change is understood, refresh the baseline:
//
//	go test -run TestWiresharkDiff -update

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata/wireshark.diff")

const baselinePath = "testdata/wireshark.diff"

func TestWiresharkDiff(t *testing.T) {
	var got bytes.Buffer
	if err := runDiff(&got); err != nil {
		t.Fatalf("runDiff: %v", err)
	}

	if *update {
		if err := os.WriteFile(baselinePath, got.Bytes(), 0o644); err != nil {
			t.Fatalf("write baseline: %v", err)
		}
		t.Logf("wrote %s", baselinePath)
		return
	}

	want, err := os.ReadFile(baselinePath)
	if err != nil {
		t.Fatalf("read baseline (run with -update to create it): %v", err)
	}
	if bytes.Equal(got.Bytes(), want) {
		return
	}

	added, removed := lineDiff(string(want), got.String())
	t.Errorf("the spec/dictionary cross-check changed: %d new, %d resolved.\n"+
		"Review the lines below, then re-run with -update to accept them.",
		len(added), len(removed))
	for _, l := range added {
		t.Errorf("  new:      %s", l)
	}
	for _, l := range removed {
		t.Errorf("  resolved: %s", l)
	}
}

// lineDiff reports the lines present in only one of the two reports. The
// report is sorted, so a set difference is enough and reads better than a
// positional diff.
func lineDiff(want, got string) (added, removed []string) {
	set := func(s string) map[string]bool {
		m := map[string]bool{}
		for _, l := range strings.Split(s, "\n") {
			if l = strings.TrimRight(l, "\r"); l != "" {
				m[l] = true
			}
		}
		return m
	}
	w, g := set(want), set(got)
	for _, l := range strings.Split(got, "\n") {
		if l != "" && !w[l] {
			added = append(added, l)
		}
	}
	for _, l := range strings.Split(want, "\n") {
		if l != "" && !g[l] {
			removed = append(removed, l)
		}
	}
	return added, removed
}

// TestGeneratesCleanly renders the dictionary into a temporary directory
// and compiles nothing — it only asserts that extraction reports no
// warning it is not meant to. The one accepted warning is the
// Acct-Multi-Session-Id type conflict between RFC 6733 and TS 32.299,
// which buildSpec resolves in the RFC's favour.
func TestGeneratesCleanly(t *testing.T) {
	var warnings []string
	spec, err := buildSpec(func(format string, a ...any) {
		warnings = append(warnings, fmt.Sprintf(format, a...))
	})
	if err != nil {
		t.Fatalf("buildSpec: %v", err)
	}
	if len(spec.AVPs) < 900 {
		t.Errorf("only %d AVPs extracted; expected at least 900", len(spec.AVPs))
	}
	if len(spec.Commands) < 25 {
		t.Errorf("only %d commands extracted; expected at least 25", len(spec.Commands))
	}
	for _, w := range warnings {
		switch {
		case strings.Contains(w, "defers to another spec"):
			// Rows whose type lives in a spec that is not pinned; the
			// generator reports and skips them by design.
		case strings.Contains(w, "Acct-Multi-Session-Id"):
			// Known, resolved in RFC 6733's favour.
		default:
			t.Errorf("unexpected extraction warning: %s", w)
		}
	}
}

// TestEnumAVPsResolve asserts every AVP named in enumAVPs came out with
// values. A silent miss here is how a dispatch constant disappears.
func TestEnumAVPsResolve(t *testing.T) {
	spec, err := buildSpec(func(string, ...any) {})
	if err != nil {
		t.Fatalf("buildSpec: %v", err)
	}
	have := map[string]int{}
	for _, a := range spec.AVPs {
		if len(a.Enums) > 0 {
			have[a.Name] = len(a.Enums)
		}
	}
	for _, n := range enumAVPs {
		if have[n] == 0 {
			t.Errorf("enum avp %s: no Enumerated values", n)
		}
	}
}

// TestRenders asserts the templates still execute; a template error is
// otherwise only seen at build time.
func TestRenders(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir); err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, rel := range []string{"inc/diam_dict.h", "src/diam_dict.c"} {
		b, err := os.ReadFile(dir + "/" + rel)
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if len(b) < 1000 {
			t.Errorf("%s is only %d bytes", rel, len(b))
		}
	}
}
