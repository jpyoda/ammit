// Package normalize undoes packaging and encoding tricks before analysis.
//
// Every trick in this file maps to a real bypass of existing scanners:
//
//   - whitespace inflation pushes a payload past an LLM's context window
//     (Trail of Bits, "The sorry state of skill distribution", 2026);
//   - precompiled Python bytecode hides logic from source scanners (same);
//   - instructions hidden inside an Office document's XML (same);
//   - password-protected archives defeat antivirus (ClawHavoc, 2026);
//   - zero-width, bidi and Unicode "tag" characters hide text from humans;
//   - base64 blobs that are decoded and executed at runtime.
//
// The normalizer never executes anything. It records what it saw as notes
// (the structural analyzer turns them into findings) and adds derived files
// containing the decoded content so every analyzer can see it.
package normalize

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/jpyoda/ammit/internal/collect"
	"github.com/jpyoda/ammit/internal/ir"
)

// Thresholds.
const (
	whitespaceRun    = 2000 // whitespace characters in a row
	blankLineRun     = 300  // consecutive blank lines
	minB64           = 60   // minimum base64 blob length worth decoding
	maxDerivedB64    = 50
	minStringLen     = 6
	maxCompressRatio = 200
)

// Normalize expands archives and decodes hidden content in place.
func Normalize(a *ir.Artifact, lim collect.Limits) {
	n := &normalizer{a: a, lim: lim}
	for _, f := range a.Files {
		n.total += int64(len(f.Raw))
	}
	// a.Files grows while we iterate: extracted files are normalized too.
	for i := 0; i < len(a.Files); i++ {
		n.file(a.Files[i], depth(a.Files[i].Path))
	}
	a.ComputeHash()
}

type normalizer struct {
	a     *ir.Artifact
	lim   collect.Limits
	total int64
	b64   int
}

func depth(p string) int { return strings.Count(p, "!/") }

func (n *normalizer) file(f *ir.File, d int) {
	switch f.Kind {
	case ir.FileArchive, ir.FileDocument:
		if d >= n.lim.MaxDepth {
			f.AddNote("archive-depth", 0, fmt.Sprintf("nested archive deeper than %d levels was not expanded", n.lim.MaxDepth))
			return
		}
		n.expand(f)
	case ir.FileCompiled:
		f.AddNote("compiled-code", 0, "compiled code cannot be reviewed as source")
		n.strings(f)
	case ir.FileBinary:
		if len(f.Raw) > 0 {
			if collect.IsExecutable(f.Raw) {
				f.AddNote("executable", 0, "bundled native executable")
			} else {
				f.AddNote("binary", 0, "unrecognized binary file")
			}
			n.strings(f)
		}
	}
	if f.Kind.IsText() {
		n.text(f)
	}
}

// ---------------------------------------------------------------- archives

func (n *normalizer) budget(size uint64) bool {
	if len(n.a.Files) >= n.lim.MaxFiles {
		return false
	}
	return n.total+int64(size) <= n.lim.MaxTotalBytes
}

func (n *normalizer) child(parent *ir.File, name string, data []byte) *ir.File {
	c := &ir.File{Path: parent.Path + "!/" + strings.TrimPrefix(path.Clean("/"+name), "/"), Parent: parent.Path, Raw: data}
	c.Kind = collect.Classify(name, data)
	if c.Kind.IsText() {
		c.Text = string(data)
	}
	n.total += int64(len(data))
	n.a.Add(c)
	return c
}

func (n *normalizer) expand(f *ir.File) {
	if bytes.HasPrefix(f.Raw, []byte{0x1f, 0x8b}) {
		n.expandGzip(f)
		return
	}
	zr, err := zip.NewReader(bytes.NewReader(f.Raw), int64(len(f.Raw)))
	if err != nil {
		f.AddNote("archive-unreadable", 0, "could not open archive: "+err.Error())
		return
	}
	var docText strings.Builder
	for _, zf := range zr.File {
		if zf.FileInfo().IsDir() {
			continue
		}
		if zf.Flags&0x1 != 0 {
			f.AddNote("encrypted-archive", 0, "password-protected entry "+zf.Name+" cannot be inspected")
			continue
		}
		if zf.CompressedSize64 > 0 && zf.UncompressedSize64/zf.CompressedSize64 > maxCompressRatio && zf.UncompressedSize64 > 1<<20 {
			f.AddNote("archive-bomb", 0, "entry "+zf.Name+" has a suspicious compression ratio and was skipped")
			continue
		}
		if !n.budget(zf.UncompressedSize64) {
			f.AddNote("archive-limit", 0, "archive not fully expanded: size or file limit reached")
			return
		}
		rc, err := zf.Open()
		if err != nil {
			f.AddNote("archive-unreadable", 0, zf.Name+": "+err.Error())
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(rc, n.lim.MaxFileBytes))
		rc.Close()
		if f.Kind == ir.FileDocument && isDocumentXML(zf.Name) {
			docText.WriteString(xmlText(data))
			docText.WriteString("\n")
			continue
		}
		n.child(f, zf.Name, data)
	}
	if docText.Len() > 0 {
		c := n.child(f, "document-text.txt", []byte(docText.String()))
		c.Derived = true
		c.Kind = ir.FileText
	}
}

func (n *normalizer) expandGzip(f *ir.File) {
	gz, err := gzip.NewReader(bytes.NewReader(f.Raw))
	if err != nil {
		f.AddNote("archive-unreadable", 0, err.Error())
		return
	}
	data, err := io.ReadAll(io.LimitReader(gz, n.lim.MaxFileBytes))
	if err != nil {
		f.AddNote("archive-unreadable", 0, err.Error())
		return
	}
	tr := tar.NewReader(bytes.NewReader(data))
	isTar := false
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		isTar = true
		if h.Typeflag != tar.TypeReg {
			if h.Typeflag == tar.TypeSymlink || h.Typeflag == tar.TypeLink {
				f.AddNote("symlink", 0, fmt.Sprintf("archive link %s -> %s (not followed)", h.Name, h.Linkname))
			}
			continue
		}
		if !n.budget(uint64(h.Size)) {
			f.AddNote("archive-limit", 0, "archive not fully expanded: size or file limit reached")
			return
		}
		body, _ := io.ReadAll(io.LimitReader(tr, n.lim.MaxFileBytes))
		n.child(f, h.Name, body)
	}
	if !isTar && n.budget(uint64(len(data))) {
		n.child(f, strings.TrimSuffix(path.Base(f.Path), ".gz"), data)
	}
}

func isDocumentXML(name string) bool {
	return strings.HasSuffix(name, ".xml") && (strings.HasPrefix(name, "word/") || strings.HasPrefix(name, "ppt/slides/") ||
		strings.HasPrefix(name, "ppt/notesSlides/") || strings.HasPrefix(name, "xl/") || name == "content.xml" || strings.HasPrefix(name, "docProps/"))
}

var tagRe = regexp.MustCompile(`<[^>]*>`)

func xmlText(b []byte) string {
	s := tagRe.ReplaceAllString(string(b), " ")
	r := strings.NewReplacer("&lt;", "<", "&gt;", ">", "&amp;", "&", "&quot;", `"`, "&apos;", "'")
	return strings.Join(strings.Fields(r.Replace(s)), " ")
}

// ---------------------------------------------------------- compiled files

// strings extracts printable runs, like the Unix strings tool. CPython keeps
// string constants verbatim in .pyc files, so URLs, shell commands and
// "os.environ" survive compilation and are visible to rules this way.
func (n *normalizer) strings(f *ir.File) {
	var out strings.Builder
	var cur []byte
	flush := func() {
		if len(cur) >= minStringLen {
			out.Write(cur)
			out.WriteByte('\n')
		}
		cur = cur[:0]
	}
	for _, b := range f.Raw {
		if b >= 0x20 && b < 0x7f || b == '\t' {
			cur = append(cur, b)
		} else {
			flush()
		}
	}
	flush()
	if out.Len() == 0 {
		return
	}
	c := &ir.File{Path: f.Path + "#strings", Parent: f.Path, Derived: true, Kind: ir.FileText, Raw: []byte(out.String())}
	c.Text = out.String()
	n.a.Add(c)
}

// -------------------------------------------------------------------- text

var (
	b64Re     = regexp.MustCompile(`[A-Za-z0-9+/]{` + fmt.Sprint(minB64) + `,}={0,2}`)
	commentRe = regexp.MustCompile(`(?s)<!--(.*?)-->`)
)

func (n *normalizer) text(f *ir.File) {
	// Invisible characters: record them, decode tag-smuggled text, strip
	// them so "cu​rl" matches rules for "curl".
	clean, hidden := stripInvisible(f)
	if hidden != "" {
		c := &ir.File{Path: f.Path + "#hidden-tag-text", Parent: f.Path, Derived: true, Kind: ir.FileText, Raw: []byte(hidden)}
		c.Text = hidden
		n.a.Add(c)
	}
	f.Text = clean

	n.whitespace(f)

	if f.Kind == ir.FileMarkdown {
		for _, m := range commentRe.FindAllStringSubmatchIndex(f.Text, -1) {
			body := strings.TrimSpace(f.Text[m[2]:m[3]])
			if len(body) >= 40 {
				f.AddNote("hidden-comment", lineAt(f.Text, m[0]), "HTML comment hidden from rendered view: "+clip(body, 80))
			}
		}
	}

	for _, m := range b64Re.FindAllStringIndex(f.Text, -1) {
		if n.b64 >= maxDerivedB64 {
			break
		}
		blob := f.Text[m[0]:m[1]]
		dec, err := base64.StdEncoding.DecodeString(padB64(blob))
		if err != nil || !printable(dec) {
			continue
		}
		n.b64++
		line := lineAt(f.Text, m[0])
		f.AddNote("base64-text", line, "base64 blob decodes to text: "+clip(string(dec), 80))
		c := &ir.File{Path: fmt.Sprintf("%s#base64@L%d", f.Path, line), Parent: f.Path, Derived: true, Kind: ir.FileScript, Raw: dec}
		c.Text = string(dec)
		n.a.Add(c)
	}
}

func padB64(s string) string {
	s = strings.TrimRight(s, "=")
	for len(s)%4 != 0 {
		s += "="
	}
	return s
}

func printable(b []byte) bool {
	if len(b) == 0 || !utf8.Valid(b) {
		return false
	}
	bad := 0
	for _, r := range string(b) {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			bad++
		}
	}
	return bad*20 < len(b)
}

func (n *normalizer) whitespace(f *ir.File) {
	run, blank, line := 0, 0, 1
	reported := false
	lineStart := true
	for _, r := range f.Text {
		if r == '\n' {
			line++
			if lineStart {
				blank++
			}
			lineStart = true
		} else if r != ' ' && r != '\t' && r != '\r' {
			if !reported && (run >= whitespaceRun || blank >= blankLineRun) {
				f.AddNote("whitespace-inflation", line, fmt.Sprintf("%d whitespace characters (%d blank lines) precede content at this line", run, blank))
				reported = true
			}
			run, blank = 0, 0
			lineStart = false
			continue
		}
		run++
	}
}

func stripInvisible(f *ir.File) (string, string) {
	var out, tags strings.Builder
	zw, bidi, tagCount := 0, 0, 0
	firstLine := 0
	line := 1
	for i, r := range f.Text {
		if r == '\n' {
			line++
		}
		switch {
		case r >= 0xE0000 && r <= 0xE007F:
			tagCount++
			if r >= 0xE0020 && r <= 0xE007E {
				tags.WriteRune(r - 0xE0000)
			}
		case r == 0x200B || r == 0x200C || r == 0x200D || r == 0x2060 || r == 0x2061 || r == 0x2062 || r == 0x2063 || r == 0x2064 || r == 0x180E || (r == 0xFEFF && i > 0):
			zw++
		case (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069):
			bidi++
		default:
			out.WriteRune(r)
			continue
		}
		if firstLine == 0 {
			firstLine = line
		}
	}
	if tagCount > 0 {
		f.AddNote("unicode-tags", firstLine, fmt.Sprintf("%d invisible Unicode tag characters (ASCII smuggling); hidden text: %s", tagCount, clip(tags.String(), 80)))
	}
	if bidi > 0 {
		f.AddNote("unicode-bidi", firstLine, fmt.Sprintf("%d bidirectional control characters can make text display differently than it reads", bidi))
	}
	if zw > 0 {
		f.AddNote("unicode-zero-width", firstLine, fmt.Sprintf("%d zero-width characters removed before analysis", zw))
	}
	return out.String(), tags.String()
}

func lineAt(s string, off int) int {
	if off > len(s) {
		off = len(s)
	}
	return strings.Count(s[:off], "\n") + 1
}

func clip(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
