// Package finding defines analyzer output.
package finding

import (
	"fmt"
	"strings"
)

// Severity of a finding.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var sevNames = []string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < 0 || int(s) >= len(sevNames) {
		return "unknown"
	}
	return sevNames[s]
}

// ParseSeverity parses a severity name.
func ParseSeverity(s string) (Severity, error) {
	for i, n := range sevNames {
		if strings.EqualFold(s, n) {
			return Severity(i), nil
		}
	}
	return Info, fmt.Errorf("unknown severity %q (want one of %s)", s, strings.Join(sevNames, ", "))
}

// MarshalText makes severities render as names in JSON.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText parses severity names from JSON.
func (s *Severity) UnmarshalText(b []byte) error {
	v, err := ParseSeverity(string(b))
	*s = v
	return err
}

// Finding is one issue an analyzer reports.
type Finding struct {
	RuleID   string   `json:"rule_id"`
	Title    string   `json:"title"`
	Severity Severity `json:"severity"`
	Category string   `json:"category"`
	Message  string   `json:"message"`
	// File is the real file the finding belongs to; Location is the logical
	// path where it was seen (an archive member or derived file), if
	// different.
	File     string `json:"file,omitempty"`
	Location string `json:"location,omitempty"`
	Line     int    `json:"line,omitempty"`
	Evidence string `json:"evidence,omitempty"`
	Analyzer string `json:"analyzer"`
	// Confidence in [0,1]: how sure the analyzer is this is a real problem.
	Confidence  float64 `json:"confidence"`
	Remediation string  `json:"remediation,omitempty"`
	// Surface says where the finding sits: code, instructions, config,
	// docs, tests or comments (see internal/surface).
	Surface string `json:"surface,omitempty"`
	// DemotedFrom is the original severity when context lowered it.
	DemotedFrom string `json:"demoted_from,omitempty"`
	DemotedWhy  string `json:"demoted_why,omitempty"`
}

// Demote lowers severity one step and records why. Info stays info.
func (f *Finding) Demote(why string) {
	if f.Severity == Info {
		return
	}
	f.DemotedFrom = f.Severity.String()
	f.DemotedWhy = why
	f.Severity--
}

// Key identifies duplicate findings.
func (f Finding) Key() string {
	return fmt.Sprintf("%s|%s|%s|%d", f.RuleID, f.File, f.Location, f.Line)
}
