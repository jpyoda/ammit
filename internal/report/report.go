// Package report computes verdicts and renders results.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/jpyoda/ammit/internal/analyzer"
	"github.com/jpyoda/ammit/internal/finding"
	"github.com/jpyoda/ammit/internal/ir"
)

// Verdict is the overall outcome: block (high or critical), review (medium,
// or an incomplete scan), notes (only low or info), no-findings. There is
// deliberately no "safe" verdict:
// a scan can only fail to find problems, never prove their absence.
type Verdict string

const (
	VerdictBlock      Verdict = "block"
	VerdictReview     Verdict = "review"
	VerdictNotes      Verdict = "notes"
	VerdictNoFindings Verdict = "no-findings"
)

// Report is the result of scanning one artifact.
type Report struct {
	Tool       string            `json:"tool"`
	Version    string            `json:"version"`
	Artifact   ArtifactSummary   `json:"artifact"`
	Verdict    Verdict           `json:"verdict"`
	Summary    map[string]int    `json:"summary"`
	Findings   []finding.Finding `json:"findings"`
	References []ir.Reference    `json:"references,omitempty"`
	Errors     []string          `json:"errors,omitempty"`
	Disclaimer string            `json:"disclaimer"`
}

// ArtifactSummary describes what was scanned.
type ArtifactSummary struct {
	Name   string  `json:"name"`
	Root   string  `json:"root"`
	Kind   ir.Kind `json:"kind"`
	SHA256 string  `json:"sha256"`
	Files  int     `json:"files"`
}

const disclaimer = "ammit reports what it found. No findings is not proof of safety: review add-ons from untrusted sources yourself."

// Build deduplicates findings, sorts them and decides the verdict.
func Build(version string, a *ir.Artifact, res analyzer.Result) *Report {
	seen := map[string]bool{}
	var fs []finding.Finding
	for _, f := range res.Findings {
		if seen[f.Key()] {
			continue
		}
		seen[f.Key()] = true
		fs = append(fs, f)
	}
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity != fs[j].Severity {
			return fs[i].Severity > fs[j].Severity
		}
		if fs[i].File != fs[j].File {
			return fs[i].File < fs[j].File
		}
		return fs[i].Line < fs[j].Line
	})
	n := 0
	for _, f := range a.Files {
		if !f.Derived {
			n++
		}
	}
	r := &Report{Tool: "ammit", Version: version, Findings: fs, References: a.References, Errors: res.Errors,
		Summary:    map[string]int{},
		Artifact:   ArtifactSummary{Name: a.Name, Root: a.Root, Kind: a.Kind, SHA256: a.SHA256, Files: n},
		Disclaimer: disclaimer}
	if r.Findings == nil {
		r.Findings = []finding.Finding{}
	}
	max := finding.Severity(-1)
	for _, f := range fs {
		r.Summary[f.Severity.String()]++
		if f.Severity > max {
			max = f.Severity
		}
	}
	switch {
	case max >= finding.High:
		r.Verdict = VerdictBlock
	case max >= finding.Medium || len(res.Errors) > 0:
		// Fail closed: an analyzer error means the scan is incomplete.
		r.Verdict = VerdictReview
	case max >= finding.Info:
		// Only low or informational findings: worth reading, not a gate.
		r.Verdict = VerdictNotes
	default:
		r.Verdict = VerdictNoFindings
	}
	return r
}

// MaxSeverity returns the highest severity in the report, or -1.
func (r *Report) MaxSeverity() finding.Severity {
	max := finding.Severity(-1)
	for _, f := range r.Findings {
		if f.Severity > max {
			max = f.Severity
		}
	}
	return max
}

// JSON writes reports as JSON (one object, or an array for several).
func JSON(w io.Writer, rs []*Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if len(rs) == 1 {
		return enc.Encode(rs[0])
	}
	return enc.Encode(rs)
}

// Text writes a human-readable report.
func Text(w io.Writer, rs []*Report, color bool) {
	c := func(code, s string) string {
		if !color {
			return s
		}
		return "\x1b[" + code + "m" + s + "\x1b[0m"
	}
	sevColor := map[finding.Severity]string{finding.Critical: "1;31", finding.High: "31", finding.Medium: "33", finding.Low: "36", finding.Info: "2"}
	for i, r := range rs {
		if i > 0 {
			fmt.Fprintln(w)
		}
		verdict := strings.ToUpper(string(r.Verdict))
		vc := map[Verdict]string{VerdictBlock: "1;31", VerdictReview: "1;33", VerdictNotes: "1;36", VerdictNoFindings: "1;32"}[r.Verdict]
		fmt.Fprintf(w, "%s  %s (%s, %d files)\n", c(vc, verdict), r.Artifact.Name, r.Artifact.Kind, r.Artifact.Files)
		fmt.Fprintf(w, "    %s\n", c("2", r.Artifact.Root))
		for _, f := range r.Findings {
			loc := f.File
			inner := f.Location != "" && f.Location != f.File
			switch {
			case inner && f.Line > 0:
				loc = fmt.Sprintf("%s (in %s:%d)", f.File, f.Location, f.Line)
			case inner:
				loc = fmt.Sprintf("%s (in %s)", f.File, f.Location)
			case f.Line > 0:
				loc = fmt.Sprintf("%s:%d", f.File, f.Line)
			}
			fmt.Fprintf(w, "  %-8s %s %s\n", c(sevColor[f.Severity], strings.ToUpper(f.Severity.String())), c("1", f.Title), c("2", "["+f.RuleID+"]"))
			if f.Surface != "" && f.Surface != "code" && f.Surface != "instructions" {
				loc += " [" + f.Surface + "]"
			}
			if loc != "" {
				fmt.Fprintf(w, "           %s\n", loc)
			}
			if f.DemotedFrom != "" {
				fmt.Fprintf(w, "           %s\n", c("2", "demoted from "+f.DemotedFrom+": "+f.DemotedWhy))
			}
			if f.Evidence != "" {
				fmt.Fprintf(w, "           %s\n", c("2", "> "+f.Evidence))
			}
		}
		for _, e := range r.Errors {
			fmt.Fprintf(w, "  %s %s\n", c("1;33", "ERROR   "), e)
		}
		if len(r.Findings) > 0 {
			var parts []string
			for _, s := range []string{"critical", "high", "medium", "low", "info"} {
				if n := r.Summary[s]; n > 0 {
					parts = append(parts, fmt.Sprintf("%d %s", n, s))
				}
			}
			fmt.Fprintf(w, "  %s\n", strings.Join(parts, ", "))
		}
		if urls := countRefs(r.References); urls > 0 {
			fmt.Fprintf(w, "  %s\n", c("2", fmt.Sprintf("%d external references recorded (see --format json)", urls)))
		}
	}
	fmt.Fprintf(w, "\n%s\n", c("2", disclaimer))
}

func countRefs(rs []ir.Reference) int { return len(rs) }
