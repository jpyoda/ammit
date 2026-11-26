package rules

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	rulepack "github.com/jpyoda/ammit/rules"
)

func TestPrefilterExtraction(t *testing.T) {
	cases := map[string][]string{
		`\bcurl\s+\S+\s*\|\s*sh`:        {"curl"},
		`(wget|curl)\b[^\n]*\|\s*bash`:  {"bash"},
		`\b(npx|bunx|uvx)\s+`:           {"npx", "bunx", "uvx"},
		`[a-z]+`:                        nil,
		`(a|c)x`:                        nil, // single letters are too weak to filter on
		`(xattr\s+-c|spctl\s+--master)`: {"xattr", "--master"},
	}
	for pat, want := range cases {
		got := buildPrefilter(pat, false)
		if (got == nil) != (want == nil) {
			t.Errorf("%s: got %v, want %v", pat, got, want)
			continue
		}
		for _, w := range want {
			found := false
			for _, g := range got {
				if g == fold(w) || strings.Contains(fold(w), g) {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: got %v, missing %q", pat, got, w)
			}
		}
	}
}

// The prefilter must never skip text its regex matches. Checked for every
// default pattern against every fixture plus case and fold tricks.
func TestPrefilterNeverSkipsAMatch(t *testing.T) {
	set, err := LoadFS(rulepack.FS)
	if err != nil {
		t.Fatal(err)
	}
	var texts []string
	filepath.WalkDir(filepath.Join("..", "..", "testdata"), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if b, err := os.ReadFile(p); err == nil {
				s := string(b)
				texts = append(texts, s, strings.ToUpper(s),
					strings.NewReplacer("s", "ſ", "k", "K").Replace(s)) // long s, Kelvin sign
			}
		}
		return nil
	})
	if len(texts) < 30 {
		t.Fatalf("only %d texts found", len(texts))
	}
	checked := 0
	for _, r := range set.Rules {
		for i, re := range r.compiled {
			for _, s := range texts {
				view := fold(s)
				if r.CaseSensitive {
					view = s
				}
				if re.MatchString(s) {
					checked++
					if !r.filters[i].pass(view) {
						t.Errorf("%s pattern %d: prefilter %v skipped a matching text", r.ID, i, r.filters[i])
					}
				}
			}
		}
	}
	if checked < 50 {
		t.Errorf("only %d matches exercised; test is too weak", checked)
	}
}

func TestEveryDefaultPatternIsFiltered(t *testing.T) {
	set, _ := LoadFS(rulepack.FS)
	unfiltered := 0
	for _, r := range set.Rules {
		for i, f := range r.filters {
			if f == nil {
				unfiltered++
				t.Logf("%s pattern %d has no prefilter: %s", r.ID, i, r.Patterns[i])
			}
		}
	}
	if unfiltered > 0 {
		t.Errorf("%d patterns run without a prefilter", unfiltered)
	}
}
