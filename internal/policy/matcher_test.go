package policy

import (
	"regexp"
	"strings"
	"testing"
)

func TestCatalogueLookupHasNoPerCallAllocations(t *testing.T) {
	if _, ok := LookupTool("get_activity"); !ok {
		t.Fatal("missing known action")
	}
	if n := testing.AllocsPerRun(20, func() { LookupTool("get_activity") }); n != 0 {
		t.Fatalf("lookup reconstructs the catalogue: %.0f allocations per call", n)
	}
}
func TestCatalogueCopiesCannotChangeAuthority(t *testing.T) {
	a := Actions()
	a[0].Name = "garmin:injected"
	a[0].Tool = "injected"
	if _, ok := LookupTool("injected"); ok {
		t.Fatal("caller changed internal catalogue")
	}
	if Actions()[0].Name == "garmin:injected" {
		t.Fatal("catalogue shares mutable storage")
	}
}
func referenceGlob(pattern, value string) bool {
	if len(pattern) > 256 {
		return false
	}
	var b strings.Builder
	b.WriteString("(?s)^")
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteByte('$')
	return regexp.MustCompile(b.String()).MatchString(value)
}
func FuzzGlobMatchesReference(f *testing.F) {
	for _, s := range [][2]string{{"*", "a/b\nc"}, {"*", "*abc"}, {"AI: ?*", "AI: żółw"}, {"a*b?c", "abbc"}, {"a[*]", "a[x]"}, {"a**?", "ab"}, {"", ""}} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, p, v string) {
		if len(v) > 512 {
			return
		}
		if match(p, v) != referenceGlob(p, v) {
			t.Fatalf("glob differs from documented semantics: %q %q", p, v)
		}
	})
}
