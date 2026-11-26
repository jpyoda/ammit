package rules_test

import (
	"regexp"
	"testing"
	"testing/fstest"

	"github.com/jpyoda/ammit/internal/finding"
	"github.com/jpyoda/ammit/internal/rules"
	rulepack "github.com/jpyoda/ammit/rules"
)

var idRe = regexp.MustCompile(`^AMT-[A-Z]+-\d{3}$`)

func TestDefaultPackIsValid(t *testing.T) {
	set, err := rules.LoadFS(rulepack.FS)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Rules) < 20 {
		t.Fatalf("expected at least 20 default rules, got %d", len(set.Rules))
	}
	for _, r := range set.Rules {
		if !idRe.MatchString(r.ID) {
			t.Errorf("rule id %q does not match AMT-CATEGORY-NNN", r.ID)
		}
		if r.Description == "" || r.Category == "" {
			t.Errorf("%s: description and category are required", r.ID)
		}
		if r.Severity < finding.Info || r.Severity > finding.Critical {
			t.Errorf("%s: bad severity", r.ID)
		}
	}
}

func TestLoadRejectsBadRules(t *testing.T) {
	cases := map[string]string{
		"duplicate":     `{"name":"x","rules":[{"id":"A","title":"t","severity":"low","patterns":["a"]},{"id":"A","title":"t","severity":"low","patterns":["b"]}]}`,
		"bad regex":     `{"name":"x","rules":[{"id":"A","title":"t","severity":"low","patterns":["("]}]}`,
		"no patterns":   `{"name":"x","rules":[{"id":"A","title":"t","severity":"low","patterns":[]}]}`,
		"bad severity":  `{"name":"x","rules":[{"id":"A","title":"t","severity":"urgent","patterns":["a"]}]}`,
		"unknown field": `{"name":"x","rules":[{"id":"A","title":"t","severity":"low","patterns":["a"],"typo":1}]}`,
		"lookahead":     `{"name":"x","rules":[{"id":"A","title":"t","severity":"low","patterns":["a(?!b)"]}]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := rules.LoadFS(fstest.MapFS{"p.json": {Data: []byte(body)}})
			if err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestMergeOverrides(t *testing.T) {
	base, _ := rules.LoadFS(fstest.MapFS{"a.json": {Data: []byte(`{"name":"a","rules":[{"id":"X","title":"old","severity":"low","patterns":["a"]}]}`)}})
	over, _ := rules.LoadFS(fstest.MapFS{"b.json": {Data: []byte(`{"name":"b","rules":[{"id":"X","title":"new","severity":"high","patterns":["a"]},{"id":"Y","title":"y","severity":"low","patterns":["b"]}]}`)}})
	base.Merge(over)
	if len(base.Rules) != 2 || base.Rules[0].Title != "new" {
		t.Errorf("merge did not override: %+v", base.Rules)
	}
}
