// Command ammit-judge is ammit's LLM judge, an analyzer plugin that asks a
// Claude model whether an add-on's instructions and code match what it says
// it is for.
//
// It speaks ammit's plugin protocol (docs/plugins.md) on stdin and stdout.
// Usually you don't run it directly:
//
//	ammit scan --judge ./my-skill
//
// To see exactly what would be sent to the API, without calling it:
//
//	ammit scan --dump-ir ./my-skill | ammit-judge --preview
//
// It needs ANTHROPIC_API_KEY. ANTHROPIC_BASE_URL points it at a proxy.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/jpyoda/ammit/internal/finding"
	"github.com/jpyoda/ammit/internal/ir"
	"github.com/jpyoda/ammit/internal/judge"
)

type request struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  struct {
		Artifact *ir.Artifact      `json:"artifact"`
		Findings []finding.Finding `json:"findings"`
	} `json:"params"`
}

func main() {
	model := flag.String("model", judge.DefaultModel, "Claude model ID")
	runs := flag.Int("runs", 2, "independent runs; high and critical findings need agreement")
	budget := flag.Int("budget", judge.DefaultBudget, "characters of add-on content sent per request")
	preview := flag.Bool("preview", false, "print the prompt that would be sent and exit without calling the API")
	flag.Parse()

	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 512<<20))
	if err != nil {
		fail(0, err)
	}
	var req request
	if err := json.Unmarshal(raw, &req); err != nil {
		fail(0, fmt.Errorf("invalid request: %v", err))
	}
	if req.Params.Artifact == nil {
		// --preview also accepts a bare IR from `ammit scan --dump-ir`.
		var a ir.Artifact
		if err := json.Unmarshal(raw, &a); err != nil || len(a.Files) == 0 {
			fail(req.ID, fmt.Errorf("no artifact in the request"))
		}
		req.Params.Artifact = &a
		req.Method = "analyze"
	}
	if req.Method != "analyze" {
		fail(req.ID, fmt.Errorf("unknown method %q", req.Method))
	}

	if *preview {
		p := judge.Build(req.Params.Artifact, req.Params.Findings, *budget)
		fmt.Printf("# model: %s, runs: %d\n# files sent: %d, omitted: %d, characters: %d, secrets masked: %d\n\n",
			*model, *runs, len(p.Files), len(p.Omitted), p.Chars, p.Redactions)
		fmt.Printf("## system\n\n%s\n\n## user\n\n%s\n", judge.System, p.User)
		return
	}

	client, err := judge.NewClientFromEnv(*model)
	if err != nil {
		fail(req.ID, err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	fs, st, err := judge.Judge(ctx, client, req.Params.Artifact, req.Params.Findings, judge.Options{Runs: *runs, Budget: *budget})
	stats, _ := json.Marshal(map[string]any{"model": *model, "stats": st})
	fmt.Fprintln(os.Stderr, string(stats))
	if err != nil {
		fail(req.ID, err)
	}
	if fs == nil {
		fs = []finding.Finding{}
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{
		"jsonrpc": "2.0", "id": req.ID,
		"result": map[string]any{"findings": fs, "stats": st, "model": *model},
	})
}

func fail(id int, err error) {
	json.NewEncoder(os.Stdout).Encode(map[string]any{
		"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": -32000, "message": err.Error()},
	})
	os.Exit(0) // the error travels in the response; ammit turns it into a review verdict
}
