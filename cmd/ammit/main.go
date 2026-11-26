// Command ammit scans AI agent add-ons (skills, plugins, MCP server
// configurations, subagents, hooks and instruction files) for malicious or
// risky behavior.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/jpyoda/ammit/internal/analyzer"
	"github.com/jpyoda/ammit/internal/collect"
	"github.com/jpyoda/ammit/internal/discover"
	"github.com/jpyoda/ammit/internal/finding"
	"github.com/jpyoda/ammit/internal/report"
	"github.com/jpyoda/ammit/internal/rules"
	"github.com/jpyoda/ammit/internal/scan"
	rulepack "github.com/jpyoda/ammit/rules"
)

// version is set at build time with -ldflags "-X main.version=v0.1.0".
var version = "dev"

const usage = `ammit weighs AI agent add-ons before you trust them.

Usage:
  ammit scan [flags] PATH...      scan skills, plugins, MCP configs or instruction files
  ammit discover [flags]          find add-ons installed on this machine (and scan them)
  ammit rules [flags]             list detection rules
  ammit version                   print the version

Exit codes: 0 no findings at or above --fail-on, 1 findings at or above
--fail-on, 2 usage or runtime error.

Run "ammit <command> -h" for a command's flags.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	switch args[0] {
	case "scan":
		return cmdScan(ctx, args[1:], stdout, stderr)
	case "discover":
		return cmdDiscover(ctx, args[1:], stdout, stderr)
	case "rules":
		return cmdRules(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "ammit", version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprintf(stderr, "ammit: unknown command %q\n\n%s", args[0], usage)
	return 2
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

type common struct {
	format, output, failOn, rulesDir, baseDir, color string
	noDefault                                        bool
	plugins                                          multiFlag
	pluginTimeout                                    time.Duration
	judge                                            bool
	judgeModel                                       string
	judgeRuns                                        int
}

func (c *common) register(fs *flag.FlagSet) {
	fs.StringVar(&c.format, "format", "text", "output format: text, json or sarif")
	fs.StringVar(&c.output, "output", "", "write the report to this file instead of stdout")
	fs.StringVar(&c.failOn, "fail-on", "high", "exit 1 when a finding is at or above this severity (critical, high, medium, low, info, none)")
	fs.StringVar(&c.rulesDir, "rules", "", "directory of extra JSON rule packs (same IDs override defaults)")
	fs.BoolVar(&c.noDefault, "no-default-rules", false, "do not load the built-in rules")
	fs.Var(&c.plugins, "plugin", "run an external analyzer plugin (repeatable); see docs/plugins.md")
	fs.DurationVar(&c.pluginTimeout, "plugin-timeout", 2*time.Minute, "timeout per plugin run")
	fs.StringVar(&c.baseDir, "base-dir", "", "make SARIF paths relative to this directory (default: current directory)")
	fs.StringVar(&c.color, "color", "auto", "color text output: auto, always or never")
	fs.BoolVar(&c.judge, "judge", false, "also ask the LLM judge (ammit-judge; needs ANTHROPIC_API_KEY; sends redacted add-on text to Anthropic)")
	fs.StringVar(&c.judgeModel, "judge-model", "claude-sonnet-5-5", "Claude model for --judge")
	fs.IntVar(&c.judgeRuns, "judge-runs", 2, "independent judge runs; high findings need agreement")
}

// findJudge locates ammit-judge next to this binary, then on PATH.
func findJudge() (string, error) {
	name := "ammit-judge"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if self, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(self), name)
		if _, err := os.Stat(cand); err == nil {
			return cand, nil
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("--judge needs the ammit-judge binary next to ammit or on PATH (go install github.com/jpyoda/ammit/cmd/ammit-judge@latest)")
}

func loadRules(c *common) (*rules.Set, error) {
	set := &rules.Set{}
	if !c.noDefault {
		d, err := rules.LoadFS(rulepack.FS)
		if err != nil {
			return nil, fmt.Errorf("built-in rules: %w", err)
		}
		set = d
	}
	if c.rulesDir != "" {
		extra, err := rules.LoadDir(c.rulesDir)
		if err != nil {
			return nil, err
		}
		set.Merge(extra)
	}
	return set, nil
}

func (c *common) options() (scan.Options, error) {
	set, err := loadRules(c)
	if err != nil {
		return scan.Options{}, err
	}
	o := scan.Options{Version: version, Rules: set, Limits: collect.DefaultLimits}
	for _, p := range c.plugins {
		parts := strings.Fields(p)
		o.Plugins = append(o.Plugins, analyzer.Plugin{Path: parts[0], Args: parts[1:], Timeout: c.pluginTimeout})
	}
	if c.judge {
		if os.Getenv("ANTHROPIC_API_KEY") == "" {
			return o, fmt.Errorf("--judge needs ANTHROPIC_API_KEY (nothing is sent without it)")
		}
		path, err := findJudge()
		if err != nil {
			return o, err
		}
		timeout := c.pluginTimeout
		if timeout < 10*time.Minute {
			timeout = 10 * time.Minute
		}
		o.Plugins = append(o.Plugins, analyzer.Plugin{Path: path, Timeout: timeout,
			Args: []string{"--model", c.judgeModel, "--runs", fmt.Sprint(c.judgeRuns)}})
	}
	return o, nil
}

func (c *common) write(rs []*report.Report, stdout io.Writer) error {
	w := stdout
	if c.output != "" {
		f, err := os.Create(c.output)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	switch c.format {
	case "json":
		return report.JSON(w, rs)
	case "sarif":
		base := c.baseDir
		if base == "" {
			base, _ = os.Getwd()
		}
		return report.SARIF(w, rs, base)
	case "text":
		color := c.color == "always" || (c.color == "auto" && c.output == "" && isTerminal(stdout))
		report.Text(w, rs, color)
		return nil
	}
	return fmt.Errorf("unknown format %q", c.format)
}

func (c *common) exitCode(rs []*report.Report) (int, error) {
	if c.failOn == "none" {
		return 0, nil
	}
	th, err := finding.ParseSeverity(c.failOn)
	if err != nil {
		return 2, err
	}
	for _, r := range rs {
		if r.MaxSeverity() >= th {
			return 1, nil
		}
	}
	return 0, nil
}

func cmdScan(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c common
	c.register(fs)
	dumpIR := fs.Bool("dump-ir", false, "print the normalized intermediate representation as JSON and exit")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: ammit scan [flags] PATH...\n\nPATH can be a directory, an archive (.zip, .skill, .tar.gz) or a single file.\n\nFlags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return 2
	}
	if *dumpIR {
		for _, p := range fs.Args() {
			a, err := scan.Prepare(p, collect.DefaultLimits)
			if err != nil {
				fmt.Fprintf(stderr, "ammit: %s: %v\n", p, err)
				return 2
			}
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(a); err != nil {
				fmt.Fprintln(stderr, "ammit:", err)
				return 2
			}
		}
		return 0
	}
	o, err := c.options()
	if err != nil {
		fmt.Fprintln(stderr, "ammit:", err)
		return 2
	}
	var rs []*report.Report
	for _, p := range fs.Args() {
		r, err := scan.Path(ctx, p, o)
		if err != nil {
			fmt.Fprintf(stderr, "ammit: %s: %v\n", p, err)
			return 2
		}
		rs = append(rs, r)
	}
	return finish(&c, rs, stdout, stderr)
}

func finish(c *common, rs []*report.Report, stdout, stderr io.Writer) int {
	if err := c.write(rs, stdout); err != nil {
		fmt.Fprintln(stderr, "ammit:", err)
		return 2
	}
	code, err := c.exitCode(rs)
	if err != nil {
		fmt.Fprintln(stderr, "ammit:", err)
	}
	return code
}

func cmdDiscover(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("discover", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c common
	c.register(fs)
	home, _ := os.UserHomeDir()
	homeDir := fs.String("home", home, "home directory to inspect (empty to skip)")
	project := fs.String("project", "", "also inspect this project directory")
	doScan := fs.Bool("scan", false, "scan every add-on found")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: ammit discover [flags]\n\nLists agent add-ons at well-known locations without running anything.\nWith --scan, scans each one. Designed to run from MDM or osquery.\n\nFlags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	items := discover.Find(*homeDir, *project)
	if !*doScan {
		if c.format == "json" {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			if items == nil {
				items = []discover.Item{}
			}
			_ = enc.Encode(items)
			return 0
		}
		if len(items) == 0 {
			fmt.Fprintln(stdout, "No agent add-ons found at known locations.")
			return 0
		}
		for _, it := range items {
			fmt.Fprintf(stdout, "%-15s %-13s %s\n", it.Agent, it.What, it.Path)
		}
		return 0
	}
	o, err := c.options()
	if err != nil {
		fmt.Fprintln(stderr, "ammit:", err)
		return 2
	}
	var rs []*report.Report
	for _, it := range items {
		r, err := scan.Path(ctx, it.Path, o)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return 2
			}
			fmt.Fprintf(stderr, "ammit: %s: %v\n", it.Path, err)
			continue
		}
		r.Artifact.Name = it.Agent + ":" + it.What + ":" + r.Artifact.Name
		rs = append(rs, r)
	}
	if len(rs) == 0 {
		fmt.Fprintln(stderr, "ammit: no add-ons found at known locations")
	}
	return finish(&c, rs, stdout, stderr)
}

func cmdRules(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rules", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c common
	fs.StringVar(&c.rulesDir, "rules", "", "directory of extra JSON rule packs")
	fs.BoolVar(&c.noDefault, "no-default-rules", false, "do not load the built-in rules")
	asJSON := fs.Bool("json", false, "print rules as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	set, err := loadRules(&c)
	if err != nil {
		fmt.Fprintln(stderr, "ammit:", err)
		return 2
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(set.Rules)
		return 0
	}
	for _, r := range set.Rules {
		fmt.Fprintf(stdout, "%-16s %-9s %-22s %s\n", r.ID, r.Severity, r.Category, r.Title)
	}
	fmt.Fprintf(stdout, "\n%d pattern rules. Structural checks (evasion, archives, encodings) are built in: see docs/rules.md.\n", len(set.Rules))
	return 0
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0 && os.Getenv("NO_COLOR") == ""
}
