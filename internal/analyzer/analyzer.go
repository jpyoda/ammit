// Package analyzer defines the analyzer interface and runs analyzers.
package analyzer

import (
	"context"
	"fmt"
	"sync"

	"github.com/jpyoda/ammit/internal/finding"
	"github.com/jpyoda/ammit/internal/ir"
)

// Analyzer inspects an artifact and reports findings.
type Analyzer interface {
	Name() string
	Analyze(ctx context.Context, a *ir.Artifact) ([]finding.Finding, error)
}

// Result is the combined output of running analyzers.
type Result struct {
	Findings []finding.Finding
	// Errors lists analyzers that failed. A failed analyzer makes the scan
	// incomplete, and an incomplete scan can never report "no findings".
	Errors []string
}

// Run executes analyzers in parallel. Errors and panics are captured as
// analyzer errors rather than silently dropped: ammit fails closed.
func Run(ctx context.Context, a *ir.Artifact, as []Analyzer) Result {
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		res Result
	)
	for _, an := range as {
		wg.Add(1)
		go func(an Analyzer) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					mu.Lock()
					res.Errors = append(res.Errors, fmt.Sprintf("%s: panic: %v", an.Name(), r))
					mu.Unlock()
				}
			}()
			fs, err := an.Analyze(ctx, a)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", an.Name(), err))
			}
			for i := range fs {
				if fs[i].Analyzer == "" {
					fs[i].Analyzer = an.Name()
				}
			}
			res.Findings = append(res.Findings, fs...)
		}(an)
	}
	wg.Wait()
	return res
}
