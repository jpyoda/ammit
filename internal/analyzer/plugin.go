package analyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/jpyoda/ammit/internal/textutil"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/jpyoda/ammit/internal/finding"
	"github.com/jpyoda/ammit/internal/ir"
)

// Plugin runs an out-of-process analyzer. ammit writes one JSON-RPC 2.0
// request to the plugin's stdin and reads one response from its stdout:
//
//	-> {"jsonrpc":"2.0","id":1,"method":"analyze","params":{"artifact":{...IR...},"findings":[...]}}
//	<- {"jsonrpc":"2.0","id":1,"result":{"findings":[...]}}
//
// Plugins can be written in any language (the LLM judge and the Python
// bytecode decompiler are planned as plugins). See docs/plugins.md.
type Plugin struct {
	Path    string
	Args    []string
	Timeout time.Duration
	// Static holds the built-in analyzers' findings, sent to the plugin as
	// context. Plugins run after the built-in analyzers.
	Static []finding.Finding
}

func (p Plugin) Name() string { return "plugin:" + filepath.Base(p.Path) }

type rpcRequest struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      int       `json:"id"`
	Method  string    `json:"method"`
	Params  rpcParams `json:"params"`
}

type rpcParams struct {
	Artifact *ir.Artifact      `json:"artifact"`
	Findings []finding.Finding `json:"findings,omitempty"`
}

type rpcResponse struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Result  *struct {
		Findings []finding.Finding `json:"findings"`
	} `json:"result"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

const maxPluginOutput = 16 << 20

func (p Plugin) Analyze(ctx context.Context, a *ir.Artifact) ([]finding.Finding, error) {
	timeout := p.Timeout
	if timeout == 0 {
		timeout = 120 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: 1, Method: "analyze", Params: rpcParams{Artifact: a, Findings: p.Static}})
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, p.Path, p.Args...)
	cmd.Stdin = bytes.NewReader(req)
	var stdout, stderr limitedBuffer
	stdout.max, stderr.max = maxPluginOutput, 64<<10
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("plugin failed: %v: %s", err, textutil.Clip(stderr.String(), 300))
	}
	if stdout.overflow {
		return nil, fmt.Errorf("plugin output exceeded %d bytes", maxPluginOutput)
	}
	var resp rpcResponse
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return nil, fmt.Errorf("plugin returned invalid JSON: %v", err)
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("plugin error %d: %s", resp.Error.Code, resp.Error.Message)
	}
	if resp.Result == nil {
		return nil, fmt.Errorf("plugin returned no result")
	}
	return resp.Result.Findings, nil
}

type limitedBuffer struct {
	bytes.Buffer
	max      int
	overflow bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.max {
		b.overflow = true
		return len(p), nil
	}
	return b.Buffer.Write(p)
}
