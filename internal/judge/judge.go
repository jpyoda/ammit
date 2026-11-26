package judge

import (
	"context"
	"fmt"
	"strings"

	"github.com/jpyoda/ammit/internal/finding"
	"github.com/jpyoda/ammit/internal/ir"
	"github.com/jpyoda/ammit/internal/redact"
	"github.com/jpyoda/ammit/internal/surface"
)

// Asker is anything that can answer a prompt: the API client, or a fake in tests.
type Asker interface {
	Ask(ctx context.Context, p Prompt) (*Answer, Usage, error)
}

// Options configure a judgment.
type Options struct {
	Runs   int // independent runs; high and critical findings need agreement (default 2)
	Budget int // characters of content per request (default DefaultBudget)
}

// Stats describe what the judge did, for logs and cost tracking.
type Stats struct {
	Runs       int   `json:"runs"`
	Usage      Usage `json:"usage"`
	Dropped    int   `json:"dropped_unverified"`
	Redactions int   `json:"redactions"`
	Files      int   `json:"files_sent"`
	Omitted    int   `json:"files_omitted"`
	Chars      int   `json:"chars_sent"`
}

const minQuote = 8

// Judge runs the model and turns verified answers into findings.
func Judge(ctx context.Context, ask Asker, a *ir.Artifact, static []finding.Finding, o Options) ([]finding.Finding, Stats, error) {
	if o.Runs <= 0 {
		o.Runs = 2
	}
	p := Build(a, static, o.Budget)
	st := Stats{Runs: o.Runs, Redactions: p.Redactions, Files: len(p.Files), Omitted: len(p.Omitted), Chars: p.Chars}

	// The text each included file was sent as, for verifying quotes.
	sent := map[string]string{}
	for _, path := range p.Files {
		f := a.File(path)
		t, _ := redact.Text(condense(f.Text))
		sent[path] = t
	}

	type key struct{ category, file string }
	type seen struct {
		f     finding.Finding
		runs  map[int]bool
		sevs  []finding.Severity
		quote string
	}
	merged := map[key]*seen{}
	var order []key
	manip := map[string]finding.Finding{}

	for run := 0; run < o.Runs; run++ {
		ans, u, err := ask.Ask(ctx, p)
		st.Usage.InputTokens += u.InputTokens
		st.Usage.OutputTokens += u.OutputTokens
		st.Usage.CacheReadTokens += u.CacheReadTokens
		st.Usage.CacheCreationTokens += u.CacheCreationTokens
		if err != nil {
			return nil, st, err // fail closed: the scan becomes "review"
		}
		for _, mf := range ans.Findings {
			path, ok := verify(sent, mf.File, mf.Quote)
			if !ok {
				st.Dropped++
				continue
			}
			sev, err := finding.ParseSeverity(mf.Severity)
			if err != nil || sev == finding.Info {
				st.Dropped++
				continue
			}
			cat := mf.Category
			if _, ok := ruleIDs[cat]; !ok {
				cat = "other"
			}
			k := key{cat, path}
			s := merged[k]
			if s == nil {
				s = &seen{runs: map[int]bool{}, quote: mf.Quote, f: toFinding(a, path, cat, mf.Reason, mf.Quote)}
				merged[k] = s
				order = append(order, k)
			}
			if !s.runs[run] {
				s.runs[run] = true
				s.sevs = append(s.sevs, sev)
			}
		}
		for _, m := range ans.ManipulationAttempts {
			path, ok := verify(sent, m.File, m.Quote)
			if !ok {
				st.Dropped++
				continue
			}
			mk := path + "\x00" + strings.Join(strings.Fields(m.Quote), " ")
			if _, dup := manip[mk]; dup {
				continue
			}
			f := toFinding(a, path, "prompt-injection", "Text in the add-on addresses the reviewer or scanner to influence its verdict.", m.Quote)
			f.RuleID, f.Title, f.Severity, f.Confidence = "AMT-JUDGE-MANIP", "Attempt to manipulate the reviewer", finding.High, 0.8
			manip[mk] = f
		}
	}

	var out []finding.Finding
	for _, k := range order {
		s := merged[k]
		f := s.f
		// Lowest severity any agreeing run gave: the conservative reading.
		sev := s.sevs[0]
		for _, v := range s.sevs[1:] {
			if v < sev {
				sev = v
			}
		}
		agreed := len(s.runs) >= min(2, o.Runs)
		if sev >= finding.High && !agreed {
			f.Severity = finding.Medium
			f.Confidence = 0.4
			f.Message += fmt.Sprintf(" (reported as %s by %d of %d runs; needs agreement to count as %s)", maxSev(s.sevs), len(s.runs), o.Runs, maxSev(s.sevs))
		} else {
			f.Severity = sev
			if agreed {
				f.Confidence = 0.7
			}
		}
		out = append(out, f)
	}
	for _, f := range manip {
		out = append(out, f)
	}
	if n := countText(p.Omitted); n > 0 {
		out = append(out, finding.Finding{RuleID: "AMT-JUDGE-INCOMPLETE", Title: "LLM judge did not see every file",
			Severity: finding.Medium, Category: "incomplete", Analyzer: "judge", Confidence: 1,
			Message: fmt.Sprintf("%d text files were over the judge's size budget and were not reviewed: %s", n, strings.Join(p.Omitted, "; "))})
	}
	return out, st, nil
}

func maxSev(s []finding.Severity) finding.Severity {
	m := s[0]
	for _, v := range s {
		if v > m {
			m = v
		}
	}
	return m
}

func countText(omitted []string) int {
	n := 0
	for _, o := range omitted {
		if strings.HasSuffix(o, "(over the size budget)") {
			n++
		}
	}
	return n
}

// verify checks that quote appears in the named file as it was sent,
// ignoring differences in whitespace. It returns the file's real path.
func verify(sent map[string]string, file, quote string) (string, bool) {
	q := strings.Join(strings.Fields(quote), " ")
	if len(q) < minQuote {
		return "", false
	}
	path := file
	if _, ok := sent[path]; !ok {
		// Accept a unique suffix match ("SKILL.md" for "helper/SKILL.md").
		path = ""
		for p := range sent {
			if p == file || strings.HasSuffix(p, "/"+file) {
				if path != "" {
					return "", false
				}
				path = p
			}
		}
		if path == "" {
			return "", false
		}
	}
	text := strings.Join(strings.Fields(sent[path]), " ")
	if q == redact.Mask || !strings.Contains(text, q) {
		return "", false
	}
	return path, true
}

var titles = map[string]string{
	"execution": "Runs code the add-on shouldn't", "exfiltration": "Sends data out", "credential-access": "Reaches for credentials",
	"prompt-injection": "Hijacks the agent", "oversight": "Weakens user oversight", "supply-chain": "Risky package source",
	"persistence": "Persists beyond its task", "deception": "Behavior doesn't match its stated purpose", "other": "Other concern",
}

func toFinding(a *ir.Artifact, path, category, reason, quote string) finding.Finding {
	f := a.File(path)
	origin := path
	s := ""
	if f != nil {
		origin = a.Origin(f)
		s = surface.Of(path, f.Kind)
	}
	fd := finding.Finding{RuleID: ruleIDs[category], Title: "LLM judge: " + titles[category], Category: category,
		Message: reason, File: origin, Evidence: finding.Clip(quote, 160), Analyzer: "judge", Confidence: 0.5, Surface: s}
	if origin != path {
		fd.Location = path
	}
	return fd
}
