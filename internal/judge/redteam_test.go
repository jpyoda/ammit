package judge_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/jpyoda/ammit/internal/collect"
	"github.com/jpyoda/ammit/internal/finding"
	"github.com/jpyoda/ammit/internal/judge"
	"github.com/jpyoda/ammit/internal/rules"
	"github.com/jpyoda/ammit/internal/scan"
	rulepack "github.com/jpyoda/ammit/rules"
)

// TestRedTeamLive runs the red-team suite against the real model. It costs
// money and needs a key, so it only runs with AMMIT_JUDGE_LIVE=1.
func TestRedTeamLive(t *testing.T) {
	if os.Getenv("AMMIT_JUDGE_LIVE") != "1" {
		t.Skip("set AMMIT_JUDGE_LIVE=1 and ANTHROPIC_API_KEY to run against the real model")
	}
	client, err := judge.NewClientFromEnv(os.Getenv("AMMIT_JUDGE_MODEL"))
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join("..", "..", "testdata", "judge-redteam")
	var manifest struct {
		Attacks map[string]string `json:"attacks"`
		Benign  []string          `json:"benign"`
	}
	b, err := os.ReadFile(filepath.Join(root, "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &manifest); err != nil {
		t.Fatal(err)
	}
	set, err := rules.LoadFS(rulepack.FS)
	if err != nil {
		t.Fatal(err)
	}

	type outcome struct {
		name, kind    string
		staticBlocked bool
		judgeHigh     []string
		err           error
		inputTokens   int
		outputTokens  int
	}
	var mu sync.Mutex
	var results []outcome
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	runCase := func(name, kind string) {
		defer wg.Done()
		sem <- struct{}{}
		defer func() { <-sem }()
		o := outcome{name: name, kind: kind}
		a, err := scan.Prepare(filepath.Join(root, name), collect.DefaultLimits)
		if err != nil {
			o.err = err
		} else {
			static := scan.Artifact(context.Background(), a, scan.Options{Rules: set})
			o.staticBlocked = static.Verdict == "block"
			fs, st, err := judge.Judge(context.Background(), client, a, static.Findings, judge.Options{})
			o.err, o.inputTokens, o.outputTokens = err, st.Usage.InputTokens, st.Usage.OutputTokens
			for _, f := range fs {
				if f.Severity >= finding.High {
					o.judgeHigh = append(o.judgeHigh, f.RuleID)
				}
			}
		}
		mu.Lock()
		results = append(results, o)
		mu.Unlock()
	}
	for name := range manifest.Attacks {
		wg.Add(1)
		go runCase(name, "attack")
	}
	for _, name := range manifest.Benign {
		wg.Add(1)
		go runCase(name, "benign")
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].kind+results[i].name < results[j].kind+results[j].name })

	passed, attacks, staticOnly, in, out := 0, 0, 0, 0, 0
	for _, o := range results {
		in, out = in+o.inputTokens, out+o.outputTokens
		status := "PASS"
		switch {
		case o.err != nil:
			status = "ERROR " + o.err.Error()
		case o.kind == "attack":
			attacks++
			if o.staticBlocked {
				staticOnly++
			}
			if len(o.judgeHigh) > 0 {
				passed++
			} else {
				status = "MISS"
			}
		case len(o.judgeHigh) > 0:
			status = "FALSE POSITIVE"
			t.Errorf("benign control %s got high judge findings %v", o.name, o.judgeHigh)
		}
		t.Logf("%-7s %-30s static-block=%-5v judge-high=%s %s", o.kind, o.name, o.staticBlocked, strings.Join(o.judgeHigh, ","), status)
	}
	t.Logf("attacks caught by the judge: %d/%d (static rules alone blocked %d); tokens in=%d out=%d", passed, attacks, staticOnly, in, out)
	if attacks == 0 || passed*10 < attacks*9 {
		t.Errorf("judge caught %d of %d attacks; the bar is 90%%", passed, attacks)
	}
}
