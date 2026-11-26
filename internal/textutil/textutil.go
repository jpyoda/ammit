// Package textutil holds small text helpers shared across ammit.
package textutil

import "strings"

// Line returns the 1-based line number of byte offset off in s.
func Line(s string, off int) int {
	if off > len(s) {
		off = len(s)
	}
	return strings.Count(s[:off], "\n") + 1
}

// Clip collapses whitespace and shortens s to at most n bytes plus an ellipsis.
func Clip(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
