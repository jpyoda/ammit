package rules

import (
	"regexp/syntax"
	"strings"
	"unicode"
)

// A prefilter is a set of literals, at least one of which must appear in any
// text the pattern can match. Running strings.Contains for a few literals is
// far cheaper than the regex, so files without any of them are skipped. A nil
// prefilter means "always run the regex".
//
// Literals and text are both compared in case-folded form (each rune mapped
// to the smallest rune in its Unicode fold orbit), the same equivalence the
// regex uses for (?i): "ſ" folds with "s", "K" (Kelvin) with "k".
type prefilter []string

const minLiteral = 2

func buildPrefilter(pattern string, caseSensitive bool) prefilter {
	flags := syntax.Perl
	if !caseSensitive {
		flags |= syntax.FoldCase
	}
	re, err := syntax.Parse(pattern, flags)
	if err != nil {
		return nil
	}
	lits := required(re.Simplify())
	if lits == nil {
		return nil
	}
	out := make(prefilter, 0, len(lits))
	seen := map[string]bool{}
	for _, l := range lits {
		if !caseSensitive {
			l = fold(l)
		}
		if !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	return out
}

// required returns literals one of which every match must contain, or nil
// when it can't tell. It is conservative: nil is always safe.
func required(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		if len(re.Rune) >= minLiteral {
			return []string{string(re.Rune)}
		}
	case syntax.OpCapture:
		return required(re.Sub[0])
	case syntax.OpPlus:
		return required(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return required(re.Sub[0])
		}
	case syntax.OpAlternate:
		var all []string
		for _, s := range re.Sub {
			l := required(s)
			if l == nil {
				return nil
			}
			all = append(all, l...)
		}
		return all
	case syntax.OpConcat:
		// Every child must match, so any child's literals will do. Prefer
		// the smallest set; then the one with the longest shortest literal.
		var best []string
		for _, s := range re.Sub {
			l := required(s)
			if l == nil {
				continue
			}
			if best == nil || len(l) < len(best) || (len(l) == len(best) && shortest(l) > shortest(best)) {
				best = l
			}
		}
		return best
	}
	return nil
}

func shortest(ls []string) int {
	m := len(ls[0])
	for _, l := range ls {
		if len(l) < m {
			m = len(l)
		}
	}
	return m
}

func foldRune(r rune) rune {
	min := r
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		if f < min {
			min = f
		}
	}
	return min
}

// fold maps text to its case-folded form for prefilter comparisons.
func fold(s string) string { return strings.Map(foldRune, s) }

// pass reports whether the regex needs to run on text (folded when the
// rule is case-insensitive).
func (p prefilter) pass(text string) bool {
	if p == nil {
		return true
	}
	for _, l := range p {
		if strings.Contains(text, l) {
			return true
		}
	}
	return false
}
