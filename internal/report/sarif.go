package report

import (
	"encoding/json"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jpyoda/ammit/internal/finding"
)

// SARIF writes reports as a SARIF 2.1.0 log, which GitHub code scanning
// and most security dashboards ingest.
func SARIF(w io.Writer, rs []*Report, baseDir string) error {
	type msg struct {
		Text string `json:"text"`
	}
	type region struct {
		StartLine int `json:"startLine,omitempty"`
	}
	type artifactLoc struct {
		URI string `json:"uri"`
	}
	type physLoc struct {
		ArtifactLocation artifactLoc `json:"artifactLocation"`
		Region           *region     `json:"region,omitempty"`
	}
	type location struct {
		PhysicalLocation physLoc `json:"physicalLocation"`
	}
	type result struct {
		RuleID              string            `json:"ruleId"`
		Level               string            `json:"level"`
		Message             msg               `json:"message"`
		Locations           []location        `json:"locations,omitempty"`
		PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
		Properties          map[string]any    `json:"properties,omitempty"`
	}
	type rule struct {
		ID               string         `json:"id"`
		Name             string         `json:"name"`
		ShortDescription msg            `json:"shortDescription"`
		Help             *msg           `json:"help,omitempty"`
		Properties       map[string]any `json:"properties,omitempty"`
	}

	rules := map[string]rule{}
	var results []result
	for _, r := range rs {
		for _, f := range r.Findings {
			if _, ok := rules[f.RuleID]; !ok {
				ru := rule{ID: f.RuleID, Name: f.Title, ShortDescription: msg{f.Title},
					Properties: map[string]any{"tags": []string{"security", f.Category}, "security-severity": securitySeverity(f.Severity)}}
				if f.Remediation != "" {
					ru.Help = &msg{f.Remediation}
				}
				rules[f.RuleID] = ru
			}
			text := f.Message
			if f.Evidence != "" {
				text += "\nEvidence: " + f.Evidence
			}
			if f.Location != "" && f.Location != f.File {
				text += "\nFound in: " + f.Location
			}
			res := result{RuleID: f.RuleID, Level: level(f.Severity), Message: msg{text},
				PartialFingerprints: map[string]string{"ammit/v1": f.Key()},
				Properties:          map[string]any{"severity": f.Severity.String(), "confidence": f.Confidence, "artifact": r.Artifact.Name}}
			uri := relURI(baseDir, r.Artifact.Root, f.File)
			if uri != "" {
				l := location{PhysicalLocation: physLoc{ArtifactLocation: artifactLoc{URI: uri}}}
				if f.Line > 0 && (f.Location == "" || f.Location == f.File) {
					l.PhysicalLocation.Region = &region{StartLine: f.Line}
				}
				res.Locations = []location{l}
			}
			results = append(results, res)
		}
	}
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	ruleList := make([]rule, 0, len(ids))
	for _, id := range ids {
		ruleList = append(ruleList, rules[id])
	}
	if results == nil {
		results = []result{}
	}
	version := "dev"
	if len(rs) > 0 {
		version = rs[0].Version
	}
	log := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name": "ammit", "version": version, "informationUri": "https://github.com/jpyoda/ammit", "rules": ruleList}},
			"results": results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func level(s finding.Severity) string {
	switch {
	case s >= finding.High:
		return "error"
	case s == finding.Medium:
		return "warning"
	default:
		return "note"
	}
}

func securitySeverity(s finding.Severity) string {
	return map[finding.Severity]string{finding.Critical: "9.5", finding.High: "8.0", finding.Medium: "5.5", finding.Low: "3.0", finding.Info: "0.0"}[s]
}

// relURI makes a file path relative to baseDir for SARIF consumers.
func relURI(baseDir, root, file string) string {
	if file == "" {
		return ""
	}
	full := file
	if root != "" {
		if strings.HasSuffix(root, file) || filepath.Base(root) == file {
			full = root // single-file artifact
		} else {
			full = filepath.Join(root, filepath.FromSlash(file))
		}
	}
	if baseDir != "" {
		if rel, err := filepath.Rel(baseDir, full); err == nil && !strings.HasPrefix(rel, "..") {
			return filepath.ToSlash(rel)
		}
	}
	return filepath.ToSlash(full)
}
