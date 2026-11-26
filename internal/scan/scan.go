// Package scan wires the pipeline together:
// collect -> normalize -> extract references -> analyze -> report.
package scan

import (
	"context"

	"github.com/jpyoda/ammit/internal/analyzer"
	"github.com/jpyoda/ammit/internal/collect"
	"github.com/jpyoda/ammit/internal/ir"
	"github.com/jpyoda/ammit/internal/normalize"
	"github.com/jpyoda/ammit/internal/refs"
	"github.com/jpyoda/ammit/internal/report"
	"github.com/jpyoda/ammit/internal/rules"
)

// Options configure a scan.
type Options struct {
	Version string
	Rules   *rules.Set
	Plugins []analyzer.Plugin
	Limits  collect.Limits
}

// Prepare loads and normalizes an add-on without analyzing it.
func Prepare(path string, lim collect.Limits) (*ir.Artifact, error) {
	a, err := collect.Load(path, lim)
	if err != nil {
		return nil, err
	}
	normalize.Normalize(a, lim)
	refs.Extract(a)
	return a, nil
}

// Path scans one add-on on disk.
func Path(ctx context.Context, path string, o Options) (*report.Report, error) {
	if o.Limits.MaxFiles == 0 {
		o.Limits = collect.DefaultLimits
	}
	a, err := Prepare(path, o.Limits)
	if err != nil {
		return nil, err
	}
	return Artifact(ctx, a, o), nil
}

// Artifact analyzes an already prepared artifact.
func Artifact(ctx context.Context, a *ir.Artifact, o Options) *report.Report {
	as := []analyzer.Analyzer{analyzer.Structural{}, analyzer.References{}}
	if o.Rules != nil {
		as = append(as, rules.Analyzer{Set: o.Rules})
	}
	for _, p := range o.Plugins {
		as = append(as, p)
	}
	res := analyzer.Run(ctx, a, as)
	return report.Build(o.Version, a, res)
}
