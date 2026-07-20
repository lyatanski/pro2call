// renders the GTP control-plane typed message layers from the
// protocol descriptions extracted from the 3GPP specifications.
// The C syntax lives entirely in templates/.
package main

import (
	"flag"
	"bytes"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"text/template"
	"archive/zip"
	"net/http"
	"io"
	"strings"
)

//go:embed templates
var templates embed.FS

// protoConfig names everything release-specific for one protocol: the
// spec number, the default 3GPP version code, and the extractor that
// reads that spec's table layout. This is the only place a spec/URL is
// named — bump defaultVer (or pass a version to `fetch`) to retarget.
type protoConfig struct {
	proto      string
	specNum    string // "29.274"
	defaultVer string // 3GPP version code, e.g. "h60" (Rel-17 v6.0.0)
	extract    func(ts *tableSet, ver string) (*Spec, error)
}

var protos = map[string]*protoConfig{
	"gtp1": {proto: "gtp1", specNum: "29.060", defaultVer: "j00", extract: extractGTP1},
	"gtp2": {proto: "gtp2", specNum: "29.274", defaultVer: "j00", extract: extractGTP2},
}

// fileStem is the spec number without the dot: "29.274" -> "29274".
func (c *protoConfig) fileStem() string { return strings.Replace(c.specNum, ".", "", 1) }

// series is the leading number: "29.274" -> "29".
func (c *protoConfig) series() string {
	if i := strings.IndexByte(c.specNum, '.'); i > 0 {
		return c.specNum[:i]
	}
	return c.specNum
}

// zipURL is the 3GPP archive location of one version's ZIP.
func (c *protoConfig) zipURL(ver string) string {
	return fmt.Sprintf("https://www.3gpp.org/ftp/Specs/archive/%s_series/%s/%s-%s.zip",
		c.series(), c.specNum, c.fileStem(), ver)
}

// docxName is the document inside that ZIP: "29274-h60.docx".
func (c *protoConfig) docxName(ver string) string {
	return fmt.Sprintf("%s-%s.docx", c.fileStem(), ver)
}

// decodeVersion turns a 3GPP version code into a dotted release. Each
// character is one version field, base-36-ish: 0-9 then a-z for 10-35.
// "h60" -> "17.6.0", "h40" -> "17.4.0".
func decodeVersion(ver string) string {
	var parts []string
	for _, r := range ver {
		switch {
		case r >= '0' && r <= '9':
			parts = append(parts, fmt.Sprintf("%d", r-'0'))
		case r >= 'a' && r <= 'z':
			parts = append(parts, fmt.Sprintf("%d", 10+(r-'a')))
		default:
			return ver // unrecognised; keep as-is
		}
	}
	return strings.Join(parts, ".")
}

func main() {
	fetch := flag.Bool("fetch", false, "download the spec from 3gpp")
	version := flag.Int("version", 2, "GTP-C version")
	release := flag.String("release", "j00", "verdion to download")
	out := flag.String("out", "out", "output location")
	flag.Parse()

	var doc []byte
	v := fmt.Sprintf("gtp%d", *version)
	if *fetch {
		zipData, err := httpGet(protos[v].zipURL(*release))
		if err != nil {
			fmt.Fprintln(os.Stderr, "gtpgen:", err)
			os.Exit(1)
		}

		doc, err = docXML(zipData, protos[v].docxName(*release))
		if err != nil {
			fmt.Fprintln(os.Stderr, "gtpgen:", err)
			os.Exit(1)
		}

		if err = os.WriteFile(fmt.Sprintf("%s-%s.docx", protos[v].fileStem(), *release), doc, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "gtpgen:", err)
			os.Exit(1)
		}
	} else {
		var err error
		doc, err = os.ReadFile(fmt.Sprintf("%s-%s.docx", protos[v].fileStem(), *release))
		if err != nil {
			fmt.Fprintln(os.Stderr, "gtpgen:", err)
			os.Exit(1)
		}
	}

	err := doParse(doc, protos[v], *release, *out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gtpgen:", err)
		os.Exit(1)
	}
}

// ---- download ----
func httpGet(url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// 3GPP's CDN rejects the default Go user agent.
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) gtpgen")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

// docXML extracts word/document.xml from the named .docx inside the spec
// ZIP (a ZIP within a ZIP).
func docXML(zipData []byte, docxName string) ([]byte, error) {
	outer, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, err
	}
	docx, err := readZipEntry(outer, docxName)
	if err != nil {
		// fall back to the first .docx present
		for _, f := range outer.File {
			if strings.HasSuffix(f.Name, ".docx") {
				if docx, err = readFile(f); err == nil {
					break
				}
			}
		}
		if docx == nil {
			return nil, fmt.Errorf("no %s in spec ZIP", docxName)
		}
	}
	inner, err := zip.NewReader(bytes.NewReader(docx), int64(len(docx)))
	if err != nil {
		return nil, err
	}
	return readZipEntry(inner, "word/document.xml")
}

func readZipEntry(z *zip.Reader, name string) ([]byte, error) {
	for _, f := range z.File {
		if f.Name == name {
			return readFile(f)
		}
	}
	return nil, fmt.Errorf("%s not found in archive", name)
}

func readFile(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func doParse(doc []byte, cfg *protoConfig, ver string, outDir string) error {
	ts, err := parseTables(doc)
	if err != nil {
		return err
	}

	spec, err := cfg.extract(ts, ver)
	if err != nil {
		return err
	}
	spec.Protocol = cfg.proto
	spec.Doc = cfg.specNum
	spec.Release = decodeVersion(ver)

	err = render(spec, outDir)
	if err != nil {
		return err
	}
	return nil
}

func render(spec *Spec, outDir string) error {
	model, err := build(spec)
	if err != nil {
		return err
	}

	root := template.New("gtpgen")
	root.Funcs(template.FuncMap{
		// dynamic dispatch: {{include (printf "%s_dec_%s" .P .Kind) .}}
		"include": func(name string, data any) (string, error) {
			t := root.Lookup(name)
			if t == nil {
				return "", fmt.Errorf("no template %q", name)
			}
			var b bytes.Buffer
			err := t.Execute(&b, data)
			return b.String(), err
		},
		// withvar re-binds the struct variable a field block renders
		// against ("m" in message functions, "out" in decode case bodies).
		"withvar": func(f *Fld, v string) *Fld {
			c := *f
			c.V = v
			return &c
		},
	})
	if _, err := root.ParseFS(templates, "templates/*.tmpl"); err != nil {
		return err
	}

	for _, out := range []struct{ tmpl, rel string }{
		{spec.Protocol + "_msg_h.tmpl", filepath.Join("inc", spec.Protocol+"_msg.h")},
		{spec.Protocol + "_msg_c.tmpl", filepath.Join("src", spec.Protocol+"_msg.c")},
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

