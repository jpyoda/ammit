package analyzer

import (
	"context"
	"path"
	"strings"

	"github.com/jpyoda/ammit/internal/finding"
	"github.com/jpyoda/ammit/internal/ir"
	"github.com/jpyoda/ammit/internal/surface"
)

// Structural turns normalizer and collector notes into findings. These are
// signs of evasion or of content that could not be fully analyzed.
type Structural struct{}

func (Structural) Name() string { return "structural" }

type noteRule struct {
	id, title, category string
	sev                 finding.Severity
	conf                float64
	fix                 string
}

var noteRules = map[string]noteRule{
	"whitespace-inflation": {"AMT-EVADE-001", "Whitespace inflation", "evasion", finding.High, 0.8,
		"Large runs of whitespace push content past scanner and LLM context limits. Inspect the content after the whitespace."},
	"unicode-tags": {"AMT-EVADE-002", "Hidden text in Unicode tag characters", "evasion", finding.High, 0.9,
		"Invisible tag characters encode text a human cannot see but a model can read. Remove them and review the hidden text."},
	"unicode-bidi": {"AMT-EVADE-003", "Bidirectional control characters", "evasion", finding.Medium, 0.6,
		"Bidi controls can make code or text display differently from how it is read."},
	"unicode-zero-width": {"AMT-EVADE-004", "Zero-width characters", "evasion", finding.Medium, 0.5,
		"Zero-width characters can split keywords to dodge pattern matching."},
	"encrypted-archive": {"AMT-EVADE-005", "Password-protected archive", "evasion", finding.High, 0.85,
		"Encrypted archives cannot be scanned and are a known malware delivery trick (ClawHavoc)."},
	"compiled-code": {"AMT-EVADE-006", "Compiled code without reviewable source", "evasion", finding.High, 0.7,
		"Bytecode hides logic from source review. Require the source and rebuild it yourself."},
	"executable": {"AMT-EXEC-010", "Bundled executable", "execution", finding.Medium, 0.6,
		"Native executables run with the agent's permissions and cannot be reviewed as source."},
	"binary": {"AMT-EXEC-011", "Unrecognized binary file", "execution", finding.Low, 0.3,
		"A binary file of unknown type. Its printable strings were scanned."},
	"hidden-comment": {"AMT-INJECT-010", "Hidden markdown comment", "prompt-injection", finding.Low, 0.4,
		"HTML comments are invisible when rendered but visible to the model. Review their content."},
	"base64-text": {"AMT-EVADE-007", "Encoded text blob", "evasion", finding.Info, 0.3,
		"A base64 blob decodes to readable text; the decoded content is scanned as well."},
	"archive-bomb":       {"AMT-LIMIT-001", "Suspicious compression ratio", "evasion", finding.Medium, 0.6, ""},
	"archive-depth":      {"AMT-LIMIT-002", "Deeply nested archive not expanded", "incomplete", finding.Medium, 0.5, ""},
	"archive-limit":      {"AMT-LIMIT-003", "Archive not fully expanded", "incomplete", finding.Medium, 0.5, ""},
	"archive-unreadable": {"AMT-LIMIT-004", "Unreadable archive", "incomplete", finding.Medium, 0.5, ""},
	"truncated":          {"AMT-LIMIT-005", "File only partly analyzed", "incomplete", finding.Medium, 0.5, ""},
	"symlink": {"AMT-FS-001", "Symlink in add-on", "filesystem", finding.Medium, 0.5,
		"Symlinks can point outside the add-on, for example at credentials. They were not followed."},
	"limit":      {"AMT-LIMIT-006", "Add-on not fully analyzed", "incomplete", finding.Medium, 0.5, ""},
	"unreadable": {"AMT-LIMIT-007", "Unreadable path", "incomplete", finding.Low, 0.4, ""},
}

func (Structural) Analyze(_ context.Context, a *ir.Artifact) ([]finding.Finding, error) {
	var out []finding.Finding
	mk := func(code, msg, file, loc string, line int) {
		r, ok := noteRules[code]
		if !ok {
			return
		}
		f := finding.Finding{RuleID: r.id, Title: r.title, Severity: r.sev, Category: r.category, Message: msg,
			File: file, Line: line, Confidence: r.conf, Remediation: r.fix}
		if loc != file {
			f.Location = loc
		}
		out = append(out, f)
	}
	for _, n := range a.Notes {
		mk(n.Code, n.Message, "", "", 0)
	}
	for _, f := range a.Files {
		for _, n := range f.Notes {
			code := n.Code
			// Compiled code next to its own source is less suspicious.
			if code == "compiled-code" && hasSource(a, f) {
				out = append(out, finding.Finding{RuleID: "AMT-EVADE-006", Title: "Compiled code shipped with source",
					Severity: finding.Low, Category: "evasion", Message: n.Message + "; a matching source file exists but may differ",
					File: a.Origin(f), Confidence: 0.3, Remediation: "Delete bytecode and let the interpreter rebuild it from the reviewed source."})
				continue
			}
			before := len(out)
			mk(code, n.Message, a.Origin(f), f.Path, n.Line)
			for i := before; i < len(out); i++ {
				out[i].Surface = surface.Of(f.Path, f.Kind)
			}
		}
	}
	return out, nil
}

func hasSource(a *ir.Artifact, f *ir.File) bool {
	if !strings.HasSuffix(f.Path, ".pyc") {
		return false
	}
	base := strings.TrimSuffix(path.Base(f.Path), ".pyc")
	if i := strings.Index(base, "."); i > 0 { // module.cpython-312.pyc
		base = base[:i]
	}
	for _, o := range a.Files {
		if path.Base(o.Path) == base+".py" {
			return true
		}
	}
	return false
}
