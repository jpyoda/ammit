package analyzer_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/jpyoda/ammit/internal/analyzer"
	"github.com/jpyoda/ammit/internal/finding"
	"github.com/jpyoda/ammit/internal/ir"
)

// TestHelperPlugin is not a real test: the plugin tests re-run the test
// binary as a fake plugin process.
func TestHelperPlugin(t *testing.T) {
	mode := os.Getenv("AMMIT_FAKE_PLUGIN")
	if mode == "" {
		return
	}
	in, _ := io.ReadAll(os.Stdin)
	var req struct {
		Method string `json:"method"`
		Params struct {
			Artifact ir.Artifact `json:"artifact"`
		} `json:"params"`
	}
	json.Unmarshal(in, &req)
	switch mode {
	case "ok":
		fmt.Printf(`{"jsonrpc":"2.0","id":1,"result":{"findings":[{"rule_id":"PLUG-1","title":"seen %s","severity":"medium","category":"test","message":"m","confidence":0.5}]}}`, req.Params.Artifact.Name)
	case "error":
		fmt.Print(`{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"model unavailable"}}`)
	case "garbage":
		fmt.Print("not json")
	case "hang":
		time.Sleep(10 * time.Second)
	}
	os.Exit(0)
}

func plugin(t *testing.T, mode string, timeout time.Duration) analyzer.Plugin {
	t.Setenv("AMMIT_FAKE_PLUGIN", mode)
	return analyzer.Plugin{Path: os.Args[0], Args: []string{"-test.run=TestHelperPlugin"}, Timeout: timeout}
}

func TestPluginOK(t *testing.T) {
	a := ir.New("my-skill", "/tmp/my-skill")
	fs, err := plugin(t, "ok", 0).Analyze(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Title != "seen my-skill" || fs[0].Severity.String() != "medium" {
		t.Errorf("unexpected findings: %+v", fs)
	}
}

func TestPluginFailuresAreErrors(t *testing.T) {
	for _, mode := range []string{"error", "garbage", "hang"} {
		t.Run(mode, func(t *testing.T) {
			_, err := plugin(t, mode, 2*time.Second).Analyze(context.Background(), ir.New("x", "x"))
			if err == nil {
				t.Error("expected an error")
			}
		})
	}
}

// A failing analyzer must surface as an error, never as a clean result.
func TestRunFailsClosed(t *testing.T) {
	res := analyzer.Run(context.Background(), ir.New("x", "x"), []analyzer.Analyzer{panicky{}})
	if len(res.Errors) != 1 {
		t.Errorf("panic not captured: %+v", res)
	}
}

type panicky struct{}

func (panicky) Name() string { return "panicky" }
func (panicky) Analyze(context.Context, *ir.Artifact) ([]finding.Finding, error) {
	panic("boom")
}
