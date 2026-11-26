package textutil

import "testing"

func TestLineAndClip(t *testing.T) {
	if Line("a\nb\nc", 2) != 2 || Line("abc", 0) != 1 || Line("a\n", 99) != 2 {
		t.Error("Line")
	}
	if Clip("  a   b ", 10) != "a b" || Clip("abcdef", 3) != "abc…" {
		t.Error("Clip")
	}
}
